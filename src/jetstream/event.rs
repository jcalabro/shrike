//! The public event value model and the proposal-0015 live-frame parser.
//!
//! An [`Event`] is the normalized, transport-independent unit both the archive
//! and the live tail produce. Its `seq` is the Jetstream cursor and its `did`
//! and `time_us` come from the envelope; the payload carries the kind-specific
//! detail. Identity, account, and sync payloads wrap the upstream
//! `com.atproto.sync.subscribeRepos` event, which carries its *own* relay `seq`
//! and `time` — those are never the cursor and must never be persisted or
//! deduplicated on. Only the Jetstream [`Event::seq`] advances the cursor.
//!
//! [`parse_live_frame`] maps one proposal-0015 wire frame to either an
//! [`Event`], an advisory [`Info`], a skip (unknown forward-compatible
//! `$type`), or a terminal [`Error`]. It enforces the lexicon `required` fields
//! that the generated decoders do not: a frame with a non-positive `seq`, an
//! unparseable `time`, or a missing required field is rejected rather than
//! delivered as a zero-valued event that would corrupt the dedup cursor.

use serde_json::{Map, Value};

use super::error::{Error, Result, truncate_on_char_boundary};
use super::filter::Kind;
use super::json_cbor::record_json_to_dag_cbor;
use super::record::Record;
use super::time::rfc3339_to_micros;
use crate::api::com::atproto::{
    SyncSubscribeReposAccount, SyncSubscribeReposIdentity, SyncSubscribeReposSync,
};
use crate::syntax::{Did, Nsid, RecordKey, Tid};

/// The proposal-0015 payload `$type`s carried inside a `message` envelope.
const TYPE_COMMIT: &str = "network.bsky.jetstream.subscribeEvents#commit";
const TYPE_IDENTITY: &str = "network.bsky.jetstream.subscribeEvents#identity";
const TYPE_ACCOUNT: &str = "network.bsky.jetstream.subscribeEvents#account";
const TYPE_SYNC: &str = "network.bsky.jetstream.subscribeEvents#sync";
const TYPE_INFO: &str = "network.bsky.jetstream.subscribeEvents#info";

/// A commit operation. Segment kind 7 (`create-resync`) is folded into
/// [`Operation::Create`], matching the Go client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    /// A newly created record.
    Create,
    /// An updated record.
    Update,
    /// A deleted record (no record body or CID).
    Delete,
}

/// A record mutation.
#[derive(Debug, Clone)]
pub struct Commit {
    /// Whether the record was created, updated, or deleted.
    pub operation: Operation,
    /// The record's collection NSID.
    pub collection: Nsid,
    /// The record key.
    pub rkey: RecordKey,
    /// The repo revision of the commit that produced this operation.
    pub rev: Tid,
    /// The record body. `None` for deletes; `Some` for creates and updates.
    pub record: Option<Record>,
}

/// The kind-specific detail of an [`Event`].
///
/// Identity/account/sync variants hold the upstream
/// `com.atproto.sync.subscribeRepos` event verbatim; consume its fields for
/// detail but never its `seq`/`time` as a cursor.
#[derive(Debug, Clone)]
pub enum EventPayload {
    /// A record mutation.
    Commit(Commit),
    /// An identity change.
    Identity(SyncSubscribeReposIdentity),
    /// An account status change.
    Account(SyncSubscribeReposAccount),
    /// A repo sync marker.
    Sync(SyncSubscribeReposSync),
}

/// A normalized Jetstream event.
#[derive(Debug, Clone)]
pub struct Event {
    /// The Jetstream sequence — the stream cursor. Always `>= 1`.
    pub seq: u64,
    /// The repo the event concerns.
    pub did: Did,
    /// The event's display time in Unix microseconds (indexed time when a
    /// timestamp import overrode witnessed time, otherwise witnessed time).
    pub time_us: i64,
    /// The kind-specific detail.
    pub payload: EventPayload,
}

impl Event {
    /// The event's [`Kind`].
    pub fn kind(&self) -> Kind {
        match self.payload {
            EventPayload::Commit(_) => Kind::Commit,
            EventPayload::Identity(_) => Kind::Identity,
            EventPayload::Account(_) => Kind::Account,
            EventPayload::Sync(_) => Kind::Sync,
        }
    }
}

/// An advisory `#info` frame (e.g. `OutdatedCursor`). It carries no `seq` and
/// never advances the cursor. Delivered rather than logged-and-dropped because a
/// clamped-timestamp resume implies a gap the consumer may care about.
#[derive(Debug, Clone)]
pub struct Info {
    /// The advisory name, e.g. `OutdatedCursor`.
    pub name: String,
    /// An optional human-readable message, bounded in length.
    pub message: Option<String>,
}

/// A batch of ordered events handed to the consumer. Owns its events and reports
/// the highest sequence through [`Batch::last_cursor`] so progress can be
/// persisted after processing.
#[derive(Debug, Clone, Default)]
pub struct Batch {
    events: Vec<Event>,
}

impl Batch {
    /// Build a batch from events already ordered by ascending sequence.
    pub fn new(events: Vec<Event>) -> Batch {
        Batch { events }
    }

    /// The events in the batch, in ascending sequence order.
    pub fn events(&self) -> &[Event] {
        &self.events
    }

    /// Consume the batch, yielding its events.
    pub fn into_events(self) -> Vec<Event> {
        self.events
    }

    /// The number of events in the batch.
    pub fn len(&self) -> usize {
        self.events.len()
    }

    /// Whether the batch is empty.
    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// The highest sequence in the batch — the cursor to persist after
    /// processing — or `None` if the batch is empty. Events are ordered, so this
    /// is the last event's sequence.
    pub fn last_cursor(&self) -> Option<u64> {
        self.events.last().map(|e| e.seq)
    }
}

/// A stream delivery: a batch of events or a seq-less advisory. An [`Info`] is
/// never folded into a [`Batch`] and never advances the cursor.
#[derive(Debug, Clone)]
pub enum Delivery {
    /// A batch of ordered events.
    Batch(Batch),
    /// An advisory `#info` frame.
    Info(Info),
}

/// A cheap, copyable snapshot of engine progress. Not a metrics registry.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Stats {
    /// Archive plan pages processed.
    pub pages: u64,
    /// The pinned sealed-tip sequence `S`.
    pub sealed_tip_seq: u64,
    /// The sequence the plan has covered so far.
    pub planned_through_seq: u64,
    /// The residual gap between coverage and the sealed tip.
    pub residual_gap: u64,
    /// Events delivered to the consumer.
    pub delivered_events: u64,
    /// The last processed (deduplicated) sequence.
    pub last_processed_seq: u64,
}

/// The result of parsing one accepted live frame.
#[derive(Debug, Clone)]
pub enum LiveFrame {
    /// A commit, identity, account, or sync event.
    Event(Event),
    /// An advisory `#info` frame.
    Info(Info),
}

/// Parse one proposal-0015 live frame (already-decompressed JSON text).
///
/// Returns `Ok(Some(_))` for an accepted event or info frame, `Ok(None)` for a
/// frame that is well-formed but carries an unknown (forward-compatible)
/// envelope or payload `$type`, and `Err` for a terminal `error` frame, a frame
/// from a non-v2 endpoint (no envelope `$type`), or a malformed event.
pub fn parse_live_frame(bytes: &[u8]) -> Result<Option<LiveFrame>> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| Error::InvalidFrame("frame is not JSON"))?;
    parse_live_value(&value)
}

/// Parse one proposal-0015 live frame from already-parsed JSON.
pub fn parse_live_value(value: &Value) -> Result<Option<LiveFrame>> {
    let obj = value
        .as_object()
        .ok_or(Error::InvalidFrame("frame is not a JSON object"))?;

    // A missing envelope `$type` most likely means a legacy v1 endpoint.
    let envelope_type = obj
        .get("$type")
        .and_then(Value::as_str)
        .ok_or(Error::InvalidFrame("frame has no envelope $type"))?;

    match envelope_type {
        "error" => Err(parse_error_frame(obj)),
        "message" => {
            let payload = obj
                .get("payload")
                .and_then(Value::as_object)
                .ok_or(Error::MalformedEvent("message frame has no payload object"))?;
            parse_payload(payload)
        }
        // Unknown non-empty envelope $type: skip for forward compatibility.
        _ => Ok(None),
    }
}

/// Build a terminal [`Error::Protocol`] from an `error` envelope frame.
fn parse_error_frame(obj: &Map<String, Value>) -> Error {
    let name = obj.get("error").and_then(Value::as_str).unwrap_or("Error");
    let message = obj.get("message").and_then(Value::as_str);
    Error::protocol(name, message)
}

/// Dispatch a `message` payload by its exact `$type`.
fn parse_payload(payload: &Map<String, Value>) -> Result<Option<LiveFrame>> {
    let payload_type = payload
        .get("$type")
        .and_then(Value::as_str)
        .ok_or(Error::MalformedEvent("payload has no $type"))?;

    match payload_type {
        TYPE_COMMIT => Ok(Some(LiveFrame::Event(parse_commit_event(payload)?))),
        TYPE_IDENTITY | TYPE_ACCOUNT | TYPE_SYNC => Ok(Some(LiveFrame::Event(parse_did_event(
            payload_type,
            payload,
        )?))),
        TYPE_INFO => Ok(Some(LiveFrame::Info(parse_info(payload)?))),
        // Unknown non-empty payload $type: skip for forward compatibility.
        _ => Ok(None),
    }
}

/// Parse a `#commit` payload. The record's dag-json is canonicalized to DAG-CBOR
/// once here; deletes carry no record or CID.
fn parse_commit_event(payload: &Map<String, Value>) -> Result<Event> {
    let seq = required_seq(payload)?;
    let did = required_did(payload)?;
    let time_us = required_time_us(payload)?;

    let operation = match payload.get("operation").and_then(Value::as_str) {
        Some("create") => Operation::Create,
        Some("update") => Operation::Update,
        Some("delete") => Operation::Delete,
        _ => return Err(Error::MalformedEvent("commit operation missing or invalid")),
    };

    let collection = Nsid::try_from(required_str(payload, "collection")?)
        .map_err(|_| Error::MalformedEvent("commit collection is not a valid NSID"))?;
    let rkey = RecordKey::try_from(required_str(payload, "rkey")?)
        .map_err(|_| Error::MalformedEvent("commit rkey is not a valid record key"))?;
    let rev = Tid::try_from(required_str(payload, "rev")?)
        .map_err(|_| Error::MalformedEvent("commit rev is not a valid TID"))?;

    let record = match operation {
        Operation::Delete => None,
        Operation::Create | Operation::Update => {
            let record_json = payload
                .get("record")
                .ok_or(Error::MalformedEvent("create/update commit has no record"))?;
            let cbor = record_json_to_dag_cbor(record_json)?;
            let cid_hint = payload.get("cid").and_then(Value::as_str);
            Some(Record::from_wire(cbor, cid_hint)?)
        }
    };

    Ok(Event {
        seq,
        did,
        time_us,
        payload: EventPayload::Commit(Commit {
            operation,
            collection,
            rkey,
            rev,
            record,
        }),
    })
}

/// Parse an identity/account/sync payload. The upstream event is deserialized
/// with the generated type; the Jetstream envelope `seq`/`did`/`time` come from
/// the payload's top level.
fn parse_did_event(payload_type: &str, payload: &Map<String, Value>) -> Result<Event> {
    let seq = required_seq(payload)?;
    let did = required_did(payload)?;
    let time_us = required_time_us(payload)?;

    // Deserialize the nested upstream event from its named field.
    let nested = |key: &str| -> Result<Value> {
        payload
            .get(key)
            .cloned()
            .ok_or(Error::MalformedEvent("event missing its upstream body"))
    };

    let payload = match payload_type {
        TYPE_IDENTITY => {
            let upstream: SyncSubscribeReposIdentity = serde_json::from_value(nested("identity")?)
                .map_err(|_| Error::MalformedEvent("invalid identity body"))?;
            EventPayload::Identity(upstream)
        }
        TYPE_ACCOUNT => {
            let upstream: SyncSubscribeReposAccount = serde_json::from_value(nested("account")?)
                .map_err(|_| Error::MalformedEvent("invalid account body"))?;
            EventPayload::Account(upstream)
        }
        TYPE_SYNC => {
            let upstream: SyncSubscribeReposSync = serde_json::from_value(nested("sync")?)
                .map_err(|_| Error::MalformedEvent("invalid sync body"))?;
            EventPayload::Sync(upstream)
        }
        // Only the three DID-level types reach this function.
        _ => return Err(Error::MalformedEvent("unexpected payload type")),
    };

    Ok(Event {
        seq,
        did,
        time_us,
        payload,
    })
}

/// Parse an `#info` payload into an advisory, bounding the message length.
fn parse_info(payload: &Map<String, Value>) -> Result<Info> {
    let mut name = required_str(payload, "name")?.to_owned();
    truncate_on_char_boundary(&mut name, super::error::MAX_PROTOCOL_MESSAGE_LEN);
    let message = payload.get("message").and_then(Value::as_str).map(|m| {
        let mut m = m.to_owned();
        truncate_on_char_boundary(&mut m, super::error::MAX_PROTOCOL_MESSAGE_LEN);
        m
    });
    Ok(Info { name, message })
}

/// Extract a required string field.
fn required_str<'a>(payload: &'a Map<String, Value>, key: &'static str) -> Result<&'a str> {
    payload
        .get(key)
        .and_then(Value::as_str)
        .ok_or(Error::MalformedEvent(
            "event missing a required string field",
        ))
}

/// Extract and validate the Jetstream envelope `seq` (must be `>= 1`).
fn required_seq(payload: &Map<String, Value>) -> Result<u64> {
    let seq = payload
        .get("seq")
        .and_then(Value::as_i64)
        .ok_or(Error::MalformedEvent("event missing seq"))?;
    if seq <= 0 {
        return Err(Error::MalformedEvent("event seq must be positive"));
    }
    Ok(seq as u64)
}

/// Extract and validate the envelope `did`.
fn required_did(payload: &Map<String, Value>) -> Result<Did> {
    Did::try_from(required_str(payload, "did")?)
        .map_err(|_| Error::MalformedEvent("event did is not a valid DID"))
}

/// Extract and convert the envelope `time` to Unix microseconds.
fn required_time_us(payload: &Map<String, Value>) -> Result<i64> {
    rfc3339_to_micros(required_str(payload, "time")?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const TIME: &str = "2024-01-01T00:00:00.000000Z";
    const REV: &str = "3l3qo2vutsw2b";
    const RKEY: &str = "3l3qo2vuowo2b";

    fn commit_frame(operation: &str, with_record: bool) -> Value {
        let mut payload = serde_json::json!({
            "$type": TYPE_COMMIT,
            "seq": 42,
            "did": DID,
            "time": TIME,
            "operation": operation,
            "collection": "app.bsky.feed.post",
            "rkey": RKEY,
            "rev": REV,
        });
        if with_record {
            payload["record"] = serde_json::json!({"$type": "app.bsky.feed.post", "text": "hi"});
            payload["cid"] =
                serde_json::json!("bafyreib2rxk3rw6wzqevqwqv6c5jx5rzq7z6z6z6z6z6z6z6z6z6z6z6z");
        }
        serde_json::json!({"$type": "message", "payload": payload})
    }

    #[test]
    fn parses_create_commit_with_record() {
        // No cid hint so the CID is computed from the canonicalized record.
        let mut frame = commit_frame("create", true);
        frame["payload"].as_object_mut().unwrap().remove("cid");
        let parsed = parse_live_value(&frame).unwrap().unwrap();
        let LiveFrame::Event(event) = parsed else {
            panic!("expected event");
        };
        assert_eq!(event.seq, 42);
        assert_eq!(event.did.as_str(), DID);
        assert_eq!(event.time_us, 1_704_067_200_000_000);
        assert_eq!(event.kind(), Kind::Commit);
        let EventPayload::Commit(commit) = event.payload else {
            panic!("expected commit");
        };
        assert_eq!(commit.operation, Operation::Create);
        assert_eq!(commit.collection.as_str(), "app.bsky.feed.post");
        let record = commit.record.expect("create has a record");
        // The record round-trips back to its logical JSON.
        assert_eq!(
            record.to_json().unwrap(),
            serde_json::json!({"$type": "app.bsky.feed.post", "text": "hi"})
        );
    }

    #[test]
    fn delete_commit_has_no_record() {
        let frame = commit_frame("delete", false);
        let LiveFrame::Event(event) = parse_live_value(&frame).unwrap().unwrap() else {
            panic!("expected event");
        };
        let EventPayload::Commit(commit) = event.payload else {
            panic!("expected commit");
        };
        assert_eq!(commit.operation, Operation::Delete);
        assert!(commit.record.is_none());
    }

    #[test]
    fn missing_envelope_type_is_invalid_frame() {
        let frame = serde_json::json!({"payload": {"$type": TYPE_INFO, "name": "x"}});
        assert!(matches!(
            parse_live_value(&frame),
            Err(Error::InvalidFrame(_))
        ));
    }

    #[test]
    fn error_frame_is_terminal_protocol_error() {
        let frame = serde_json::json!({
            "$type": "error",
            "error": "ConsumerTooSlow",
            "message": "you are too slow",
        });
        match parse_live_value(&frame) {
            Err(Error::Protocol { name, message }) => {
                assert_eq!(name, "ConsumerTooSlow");
                assert_eq!(message.as_deref(), Some("you are too slow"));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
    }

    #[test]
    fn info_frame_parses_and_does_not_advance_cursor() {
        let frame = serde_json::json!({
            "$type": "message",
            "payload": {"$type": TYPE_INFO, "name": "OutdatedCursor", "message": "clamped"},
        });
        let LiveFrame::Info(info) = parse_live_value(&frame).unwrap().unwrap() else {
            panic!("expected info");
        };
        assert_eq!(info.name, "OutdatedCursor");
        assert_eq!(info.message.as_deref(), Some("clamped"));
    }

    #[test]
    fn unknown_payload_type_is_skipped() {
        let frame = serde_json::json!({
            "$type": "message",
            "payload": {"$type": "network.bsky.jetstream.subscribeEvents#future"},
        });
        assert!(parse_live_value(&frame).unwrap().is_none());
    }

    #[test]
    fn unknown_envelope_type_is_skipped() {
        let frame = serde_json::json!({"$type": "future", "payload": {}});
        assert!(parse_live_value(&frame).unwrap().is_none());
    }

    #[test]
    fn non_positive_seq_is_rejected() {
        let mut frame = commit_frame("create", true);
        frame["payload"]["seq"] = serde_json::json!(0);
        assert!(matches!(
            parse_live_value(&frame),
            Err(Error::MalformedEvent(_))
        ));
    }

    #[test]
    fn unparseable_time_is_rejected() {
        let mut frame = commit_frame("create", true);
        frame["payload"]["time"] = serde_json::json!("not a time");
        assert!(matches!(
            parse_live_value(&frame),
            Err(Error::InvalidTimestamp(_))
        ));
    }

    #[test]
    fn missing_required_commit_field_is_rejected() {
        let mut frame = commit_frame("create", true);
        frame["payload"]
            .as_object_mut()
            .unwrap()
            .remove("collection");
        assert!(matches!(
            parse_live_value(&frame),
            Err(Error::MalformedEvent(_))
        ));
    }

    #[test]
    fn create_without_record_is_rejected() {
        let frame = commit_frame("create", false);
        assert!(matches!(
            parse_live_value(&frame),
            Err(Error::MalformedEvent(_))
        ));
    }

    #[test]
    fn parses_identity_event_using_envelope_seq() {
        let frame = serde_json::json!({
            "$type": "message",
            "payload": {
                "$type": TYPE_IDENTITY,
                "seq": 100,
                "did": DID,
                "time": TIME,
                "identity": {
                    // Upstream relay seq differs from the Jetstream seq.
                    "seq": 999,
                    "did": DID,
                    "handle": "alice.test",
                    "time": TIME,
                },
            },
        });
        let LiveFrame::Event(event) = parse_live_value(&frame).unwrap().unwrap() else {
            panic!("expected event");
        };
        // The Jetstream envelope seq is the cursor, not the relay's 999.
        assert_eq!(event.seq, 100);
        assert_eq!(event.kind(), Kind::Identity);
        let EventPayload::Identity(identity) = event.payload else {
            panic!("expected identity");
        };
        assert_eq!(identity.seq, 999);
        assert_eq!(
            identity.handle.as_ref().map(|h| h.as_str()),
            Some("alice.test")
        );
    }

    #[test]
    fn parses_account_event() {
        let frame = serde_json::json!({
            "$type": "message",
            "payload": {
                "$type": TYPE_ACCOUNT,
                "seq": 7,
                "did": DID,
                "time": TIME,
                "account": {"seq": 7, "did": DID, "active": true, "time": TIME},
            },
        });
        let LiveFrame::Event(event) = parse_live_value(&frame).unwrap().unwrap() else {
            panic!("expected event");
        };
        assert_eq!(event.kind(), Kind::Account);
        let EventPayload::Account(account) = event.payload else {
            panic!("expected account");
        };
        assert!(account.active);
    }

    #[test]
    fn batch_last_cursor_is_highest_seq() {
        let make = |seq: u64| Event {
            seq,
            did: Did::try_from(DID).unwrap(),
            time_us: 0,
            payload: EventPayload::Commit(Commit {
                operation: Operation::Delete,
                collection: Nsid::try_from("app.bsky.feed.post").unwrap(),
                rkey: RecordKey::try_from(RKEY).unwrap(),
                rev: Tid::try_from(REV).unwrap(),
                record: None,
            }),
        };
        let batch = Batch::new(vec![make(1), make(5), make(9)]);
        assert_eq!(batch.last_cursor(), Some(9));
        assert_eq!(batch.len(), 3);
        assert_eq!(Batch::default().last_cursor(), None);
    }
}
