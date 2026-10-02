//! AT Protocol event streaming — firehose, labels, and Jetstream.
//!
//! # Overview
//!
//! Provides types and parsing for AT Protocol event streams:
//!
//! - **Firehose / label streams**: CBOR-framed binary WebSocket messages
//!   (`com.atproto.sync.subscribeRepos`, `com.atproto.label.subscribeLabels`).
//! - **Jetstream**: JSON WebSocket messages served by the community Jetstream
//!   relay (a lighter-weight alternative to the raw firehose).
//!
//! The [`Client`] type manages WebSocket connections with automatic
//! reconnection and exponential backoff.
//!
//! Events are delivered in batches for efficient bulk processing. The
//! [`Config`] fields `batch_size` and `batch_timeout` control batching
//! behavior (defaults: 50 events, 500ms). Each yield from
//! [`Client::subscribe`] or [`Client::jetstream`] delivers a `Vec` of 1 to
//! `batch_size` events. Batches flush when full, when the timeout elapses,
//! or when an error is encountered — in which case the partial batch is
//! yielded first, followed by the error.

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub mod client;
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[path = "client_wasm.rs"]
pub mod client;
pub mod event;
pub mod jetstream;
#[cfg(feature = "sync")]
pub mod parallel;
pub mod reconnect;

#[cfg(feature = "sync")]
pub use crate::sync::raw::parse_raw_sync_frame;
pub use client::{Client, Config};
pub use event::{Event, Label, Operation};
pub use jetstream::{JetstreamCommit, JetstreamEvent, parse_jetstream_message};
pub use reconnect::BackoffPolicy;

use thiserror::Error;

/// Errors produced by the streaming client and frame parsers.
#[derive(Debug, Error)]
pub enum StreamError {
    #[error("JSON parse error: {0}")]
    ParseJson(String),
    #[error("CBOR parse error: {0}")]
    ParseCbor(String),
    #[error("WebSocket error: {0}")]
    WebSocket(String),
    #[error("unknown event type: {0}")]
    UnknownType(String),
    /// A relay-originated error frame (`op == -1`). Carries the structured
    /// `error` name and optional human-readable `message` so a persistent
    /// upstream failure (e.g. `FutureCursor`, `ConsumerTooSlow`) surfaces to the
    /// consumer instead of being silently skipped into a reconnect loop.
    #[error("relay error frame: {error}{}", .message.as_ref().map(|m| format!(": {m}")).unwrap_or_default())]
    RelayError {
        error: String,
        message: Option<String>,
    },
    #[cfg(feature = "sync")]
    #[error("verifier error: {0}")]
    Verifier(#[source] Box<crate::sync::VerifierError>),
    #[cfg(feature = "sync")]
    #[error("per-DID verify queue overflow for {did}: dropped event at seq {seq}")]
    QueueOverflow { did: String, seq: i64 },
}

impl From<crate::cbor::CborError> for StreamError {
    fn from(e: crate::cbor::CborError) -> Self {
        StreamError::ParseCbor(e.to_string())
    }
}

#[cfg(feature = "sync")]
impl From<crate::sync::VerifierError> for StreamError {
    fn from(err: crate::sync::VerifierError) -> Self {
        Self::Verifier(Box::new(err))
    }
}

// ---------------------------------------------------------------------------
// Firehose frame parsing
// ---------------------------------------------------------------------------

/// Parse a single firehose CBOR frame into an [`Event`].
///
/// A firehose frame consists of two consecutive CBOR values:
/// 1. A header map `{op: int, t: string}` — `op=1` means a regular message,
///    `op=-1` means an error frame. `t` is the type discriminant
///    (e.g. `"#commit"`, `"#identity"`, `"#account"`, `"#labels"`).
/// 2. A body map whose shape depends on `t`.
///
/// # Errors
///
/// Returns [`StreamError`] if the frame is malformed, the type is unknown,
/// or required fields are missing.
pub fn parse_firehose_frame(data: &[u8]) -> Result<Event, StreamError> {
    use crate::cbor::Decoder;
    use crate::syntax::{Did, Handle, Tid};

    // Decode the header map.
    let mut dec = Decoder::new(data);
    let header = dec
        .decode()
        .map_err(|e| StreamError::ParseCbor(format!("header: {e}")))?;

    let (op, type_tag) = extract_frame_header(header)?;

    // op=-1 is an error frame. Decode its body `{error, message}` and surface
    // the structured error name/message rather than dropping it (which would
    // turn a persistent relay error into a silent reconnect loop).
    if op == -1 {
        let body = dec
            .decode()
            .map_err(|e| StreamError::ParseCbor(format!("error frame body: {e}")))?;
        let (error, message) = extract_error_frame_body(body);
        return Err(StreamError::RelayError { error, message });
    }
    if op != 1 {
        // Unknown op codes are forward-compat: surface as a skippable
        // UnknownType (the consumer continues) rather than a fatal parse error
        // that would trigger a reconnect loop.
        return Err(StreamError::UnknownType(format!("unknown frame op: {op}")));
    }

    // Decode the body map.
    let body = dec
        .decode()
        .map_err(|e| StreamError::ParseCbor(format!("body: {e}")))?;

    // A firehose frame is exactly a (header, body) pair; reject trailing bytes
    // rather than silently ignoring them (matches shrike's strict cbor::decode
    // no-trailing-data invariant).
    if !dec.is_empty() {
        return Err(StreamError::ParseCbor(
            "trailing data after frame body".into(),
        ));
    }

    match type_tag {
        "#commit" => {
            let fields = require_map(&body, "#commit")?;
            let did_str = require_text(fields, "repo").or_else(|_| require_text(fields, "did"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let rev_str = require_text(fields, "rev")?;
            let rev = Tid::try_from(rev_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid rev TID: {e}")))?;
            let seq = require_int(fields, "seq")?;

            // Operations reference their records' blocks by CID.
            let blocks = parse_commit_blocks(fields)?;
            let operations = parse_commit_ops(fields, &blocks)?;
            Ok(Event::Commit {
                did,
                rev,
                seq,
                operations,
            })
        }
        "#identity" => {
            let fields = require_map(&body, "#identity")?;
            let did_str = require_text(fields, "did").or_else(|_| require_text(fields, "repo"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let seq = require_int(fields, "seq")?;
            let handle = optional_text(fields, "handle").and_then(|h| Handle::try_from(h).ok());
            Ok(Event::Identity { did, seq, handle })
        }
        "#account" => {
            let fields = require_map(&body, "#account")?;
            let did_str = require_text(fields, "did").or_else(|_| require_text(fields, "repo"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let seq = require_int(fields, "seq")?;
            let active = optional_bool(fields, "active").unwrap_or(false);
            Ok(Event::Account { did, seq, active })
        }
        "#labels" => {
            let fields = require_map(&body, "#labels")?;
            let seq = require_int(fields, "seq")?;
            let labels = parse_labels(fields)?;
            Ok(Event::Labels { seq, labels })
        }
        "#info" | "#sync" => {
            // Forward-compat: skip info and sync frames.
            Err(StreamError::UnknownType(type_tag.to_owned()))
        }
        other => Err(StreamError::UnknownType(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn extract_frame_header<'a>(header: crate::cbor::Value<'a>) -> Result<(i64, &'a str), StreamError> {
    use crate::cbor::Value;

    let entries = match header {
        Value::Map(m) => m,
        _ => {
            return Err(StreamError::ParseCbor(
                "frame header must be a CBOR map".into(),
            ));
        }
    };

    let mut op: Option<i64> = None;
    let mut t: Option<&str> = None;

    for (key, val) in entries {
        match key {
            "op" => {
                op = Some(match val {
                    Value::Unsigned(n) => i64::try_from(n)
                        .map_err(|_| StreamError::ParseCbor("op overflow".into()))?,
                    Value::Signed(n) => n,
                    _ => return Err(StreamError::ParseCbor("op must be an integer".into())),
                });
            }
            "t" => {
                t = Some(match val {
                    Value::Text(s) => s,
                    _ => return Err(StreamError::ParseCbor("t must be a text string".into())),
                });
            }
            _ => {}
        }
    }

    let op = op.ok_or_else(|| StreamError::ParseCbor("missing op in frame header".into()))?;
    let t = t.ok_or_else(|| StreamError::ParseCbor("missing t in frame header".into()))?;
    Ok((op, t))
}

/// Extract the `{error, message?}` body of an `op == -1` error frame. A
/// missing/non-text `error` defaults to `"Unknown"` (matching the TS reference
/// `ErrorFrame.fromError`); `message` is optional.
fn extract_error_frame_body(body: crate::cbor::Value<'_>) -> (String, Option<String>) {
    use crate::cbor::Value;

    let Value::Map(entries) = body else {
        return ("Unknown".to_owned(), None);
    };

    let mut error: Option<String> = None;
    let mut message: Option<String> = None;
    for (key, val) in entries {
        match (key, val) {
            ("error", Value::Text(s)) => error = Some(s.to_owned()),
            ("message", Value::Text(s)) => message = Some(s.to_owned()),
            _ => {}
        }
    }
    (error.unwrap_or_else(|| "Unknown".to_owned()), message)
}

type Fields<'a> = Vec<(&'a str, crate::cbor::Value<'a>)>;

fn require_map<'v, 'a>(
    val: &'v crate::cbor::Value<'a>,
    context: &str,
) -> Result<&'v Fields<'a>, StreamError> {
    match val {
        crate::cbor::Value::Map(m) => Ok(m),
        _ => Err(StreamError::ParseCbor(format!(
            "{context} body must be a CBOR map"
        ))),
    }
}

fn require_text<'a>(fields: &'a Fields<'_>, key: &str) -> Result<&'a str, StreamError> {
    for (k, v) in fields {
        if *k == key {
            return match v {
                crate::cbor::Value::Text(s) => Ok(s),
                _ => Err(StreamError::ParseCbor(format!(
                    "field {key:?} must be a text string"
                ))),
            };
        }
    }
    Err(StreamError::ParseCbor(format!("missing field {key:?}")))
}

fn require_int(fields: &Fields<'_>, key: &str) -> Result<i64, StreamError> {
    for (k, v) in fields {
        if *k == key {
            return match v {
                crate::cbor::Value::Unsigned(n) => i64::try_from(*n)
                    .map_err(|_| StreamError::ParseCbor(format!("field {key:?} overflows i64"))),
                crate::cbor::Value::Signed(n) => Ok(*n),
                _ => Err(StreamError::ParseCbor(format!(
                    "field {key:?} must be an integer"
                ))),
            };
        }
    }
    Err(StreamError::ParseCbor(format!("missing field {key:?}")))
}

fn optional_text<'a>(fields: &'a Fields<'_>, key: &str) -> Option<&'a str> {
    fields.iter().find_map(|(k, v)| match v {
        crate::cbor::Value::Text(s) if *k == key => Some(*s),
        _ => None,
    })
}

fn optional_bool(fields: &Fields<'_>, key: &str) -> Option<bool> {
    for (k, v) in fields {
        if *k == key
            && let crate::cbor::Value::Bool(b) = v
        {
            return Some(*b);
        }
    }
    None
}

/// Decode the `blocks` field from a `#commit` body as a CAR file, checking
/// every block against its CID.
fn parse_commit_blocks<'a>(fields: &Fields<'a>) -> Result<CommitBlocks<'a>, StreamError> {
    let Some(car) = extract_bytes(fields, "blocks") else {
        // blocks field may be absent; return empty index.
        return Ok(CommitBlocks::Few(Vec::new()));
    };

    let (_roots, blocks) = crate::car::read_slice(car)
        .map_err(|e| StreamError::ParseCbor(format!("failed to decode commit blocks CAR: {e}")))?;

    for block in &blocks {
        // Verify the block content hashes to its declared CID. The CAR reader
        // does not verify CID-to-content, so without this check a malicious or
        // buggy relay could ship a block labeled CID X whose bytes hash to Y,
        // and we would emit those bytes as the authentic record for X — silent
        // data corruption from untrusted network input. Both atmos (every
        // Next()) and the atproto TS reference (verifyIncomingCarBlocks) verify
        // by default.
        let computed = crate::cbor::Cid::compute(block.cid.codec(), block.data);
        if computed != block.cid {
            return Err(StreamError::ParseCbor(format!(
                "commit block CID mismatch: declared {}, content hashes to {}",
                block.cid, computed
            )));
        }
    }
    Ok(CommitBlocks::new(blocks))
}

/// A commit's verified blocks, borrowed from the frame, for finding records
/// by CID.
///
/// Commits usually carry a handful of blocks, which a scan searches faster
/// than an index would. More are hashed, so that a frame with many ops and
/// many blocks is not quadratic.
enum CommitBlocks<'a> {
    Few(Vec<crate::car::BlockRef<'a>>),
    Many(crate::cbor::cid::CidMap<&'a [u8]>),
}

impl<'a> CommitBlocks<'a> {
    /// The most blocks searched by scanning.
    const SCAN_MAX: usize = 32;

    fn new(blocks: Vec<crate::car::BlockRef<'a>>) -> Self {
        if blocks.len() <= Self::SCAN_MAX {
            return CommitBlocks::Few(blocks);
        }
        // A block that appears twice passed the hash check both times, so
        // either copy holds the same bytes.
        CommitBlocks::Many(blocks.into_iter().map(|b| (b.cid, b.data)).collect())
    }

    /// The data of the block with this CID.
    fn get(&self, cid: &crate::cbor::Cid) -> Option<&'a [u8]> {
        match self {
            CommitBlocks::Few(blocks) => blocks.iter().find(|b| b.cid == *cid).map(|b| b.data),
            CommitBlocks::Many(index) => index.get(cid).copied(),
        }
    }
}

/// Parse the `ops` array from a `#commit` body.
///
/// The firehose wire format uses:
/// - `action`: "create" | "update" | "delete"
/// - `path`: "collection/rkey" (combined, split on first `/`)
/// - `cid`: CBOR CID link (for create/update, absent for delete)
///
/// Record data is NOT in the ops — it's looked up from the `blocks` CAR
/// data via the CID.
fn parse_commit_ops(
    fields: &Fields<'_>,
    blocks: &CommitBlocks<'_>,
) -> Result<Vec<event::Operation>, StreamError> {
    use crate::cbor::Value;
    use crate::syntax::{Nsid, RecordKey};

    let ops_val = fields.iter().find(|(k, _)| *k == "ops").map(|(_, v)| v);

    let Some(ops_val) = ops_val else {
        // ops array may be absent on older protocol versions; return empty.
        return Ok(vec![]);
    };

    let arr = match ops_val {
        Value::Array(a) => a,
        _ => return Err(StreamError::ParseCbor("commit ops must be an array".into())),
    };

    let mut ops = Vec::with_capacity(arr.len());
    for item in arr {
        let item_fields = require_map(item, "op entry")?;
        let action = require_text(item_fields, "action")?;

        // path is "collection/rkey" — split on first '/'
        let path = require_text(item_fields, "path")?;
        let (collection_str, rkey_str) = path
            .split_once('/')
            .ok_or_else(|| StreamError::ParseCbor(format!("op path missing '/': {path:?}")))?;

        let collection = Nsid::try_from(collection_str)
            .map_err(|e| StreamError::ParseCbor(format!("invalid collection: {e}")))?;
        let rkey = RecordKey::try_from(rkey_str)
            .map_err(|e| StreamError::ParseCbor(format!("invalid rkey: {e}")))?;

        let op = match action {
            "create" | "update" => {
                // CID is optional — may be a CBOR CID or null.
                let cid = extract_cid_optional(item_fields, "cid").ok_or_else(|| {
                    StreamError::ParseCbor(format!("missing cid for {action} op"))
                })?;

                // Look up record data from the blocks CAR by CID. A create/update
                // op whose record block is absent from the CAR is malformed —
                // error rather than silently emitting an empty record.
                let record = blocks
                    .get(&cid)
                    .ok_or_else(|| {
                        StreamError::ParseCbor(format!(
                            "{action} op references CID {cid} absent from commit blocks"
                        ))
                    })?
                    .to_vec();

                if action == "create" {
                    event::Operation::Create {
                        collection,
                        rkey,
                        cid,
                        record,
                    }
                } else {
                    event::Operation::Update {
                        collection,
                        rkey,
                        cid,
                        record,
                    }
                }
            }
            "delete" => event::Operation::Delete { collection, rkey },
            other => {
                return Err(StreamError::ParseCbor(format!(
                    "unknown op action: {other:?}"
                )));
            }
        };
        ops.push(op);
    }
    Ok(ops)
}

fn extract_cid_optional(fields: &Fields<'_>, key: &str) -> Option<crate::cbor::Cid> {
    for (k, v) in fields {
        if *k == key {
            return match v {
                crate::cbor::Value::Cid(c) => Some(*c),
                _ => None,
            };
        }
    }
    None
}

fn extract_bytes<'a>(fields: &Fields<'a>, key: &str) -> Option<&'a [u8]> {
    for (k, v) in fields {
        if *k == key
            && let crate::cbor::Value::Bytes(b) = v
        {
            return Some(*b);
        }
    }
    None
}

/// Parse the `labels` array from a `#labels` body.
fn parse_labels(fields: &Fields<'_>) -> Result<Vec<event::Label>, StreamError> {
    use crate::cbor::Value;
    use crate::syntax::Did;

    let labels_val = fields.iter().find(|(k, _)| *k == "labels").map(|(_, v)| v);

    let Some(labels_val) = labels_val else {
        return Ok(vec![]);
    };

    let arr = match labels_val {
        Value::Array(a) => a,
        _ => return Err(StreamError::ParseCbor("labels must be an array".into())),
    };

    let mut labels = Vec::with_capacity(arr.len());
    for item in arr {
        let item_fields = require_map(item, "label entry")?;
        let src_str = require_text(item_fields, "src")?;
        let uri = require_text(item_fields, "uri")?.to_owned();
        let val = require_text(item_fields, "val")?.to_owned();
        let neg = optional_bool(item_fields, "neg").unwrap_or(false);
        let src = Did::try_from(src_str)
            .map_err(|e| StreamError::ParseCbor(format!("invalid label src DID: {e}")))?;
        labels.push(event::Label { src, uri, val, neg });
    }
    Ok(labels)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use crate::cbor::{Cid, Codec};
    use crate::streaming::*;
    use crate::syntax::{Did, Nsid, RecordKey, Tid};
    use proptest::prelude::*;
    use proptest::sample::Index;

    // --- Jetstream parsing tests ---

    #[test]
    fn parse_jetstream_commit_create() {
        let json = r#"{
            "did": "did:plc:test123456789abcdefghij",
            "time_us": 1700000000000000,
            "kind": "commit",
            "commit": {
                "operation": "create",
                "collection": "app.bsky.feed.post",
                "rkey": "abc123",
                "cid": "bafyreihffx5a2e4gzlcbsuaamgoxwaqlodtip3r5ln4vpqwlpz6ji7ydnm",
                "record": {"text": "hello", "$type": "app.bsky.feed.post", "createdAt": "2024-01-01T00:00:00Z"}
            }
        }"#;
        let event = parse_jetstream_message(json).unwrap();
        match event {
            JetstreamEvent::Commit {
                did,
                collection,
                operation,
                ..
            } => {
                assert_eq!(did.as_str(), "did:plc:test123456789abcdefghij");
                assert_eq!(collection.as_str(), "app.bsky.feed.post");
                assert!(matches!(operation, JetstreamCommit::Create { .. }));
            }
            _ => panic!("expected commit"),
        }
    }

    #[test]
    fn parse_jetstream_commit_delete() {
        let json = r#"{
            "did": "did:plc:test123456789abcdefghij",
            "time_us": 1700000000000000,
            "kind": "commit",
            "commit": {
                "operation": "delete",
                "collection": "app.bsky.feed.post",
                "rkey": "abc123"
            }
        }"#;
        let event = parse_jetstream_message(json).unwrap();
        match event {
            JetstreamEvent::Commit { operation, .. } => {
                assert!(matches!(operation, JetstreamCommit::Delete));
            }
            _ => panic!("expected commit"),
        }
    }

    #[test]
    fn parse_jetstream_identity() {
        let json = r#"{
            "did": "did:plc:test123456789abcdefghij",
            "time_us": 1700000000000000,
            "kind": "identity"
        }"#;
        let event = parse_jetstream_message(json).unwrap();
        assert!(matches!(event, JetstreamEvent::Identity { .. }));
    }

    #[test]
    fn parse_jetstream_account() {
        let json = r#"{
            "did": "did:plc:test123456789abcdefghij",
            "time_us": 1700000000000000,
            "kind": "account",
            "account": {
                "active": true
            }
        }"#;
        let event = parse_jetstream_message(json).unwrap();
        match event {
            JetstreamEvent::Account { active, .. } => assert!(active),
            _ => panic!("expected account"),
        }
    }

    // --- Event type pattern-match test ---

    #[test]
    fn event_commit_pattern_match() {
        let event = Event::Commit {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            rev: Tid::new(1_700_000_000_000_000, 0).unwrap(),
            seq: 42,
            operations: vec![Operation::Create {
                collection: Nsid::try_from("app.bsky.feed.post").unwrap(),
                rkey: RecordKey::try_from("abc").unwrap(),
                cid: Cid::compute(Codec::Raw, b"test"),
                record: vec![],
            }],
        };
        match &event {
            Event::Commit {
                did, operations, ..
            } => {
                assert_eq!(did.as_str(), "did:plc:test123456789abcdefghij");
                assert_eq!(operations.len(), 1);
            }
            _ => panic!("expected Commit"),
        }
    }

    // --- Firehose frame parsing test ---

    #[test]
    fn parse_firehose_commit_frame() {
        // Build a minimal firehose #commit frame:
        // Header: {op: 1, t: "#commit"}
        // Body: {blocks: <CAR bytes>, ops: [{action: "create", path: "app.bsky.feed.post/abc", cid: <CID>}], repo: "did:plc:...", rev: "2222222222222", seq: 1}
        use crate::cbor::Encoder;

        let record_data = b"fake record data";
        let record_cid = Cid::compute(Codec::Drisl, record_data);

        // Build a minimal CAR containing the record block
        let block = crate::car::Block {
            cid: record_cid,
            data: record_data.to_vec(),
        };
        let car_bytes = crate::car::write_all(&[record_cid], std::slice::from_ref(&block)).unwrap();

        // Encode the full frame: header + body
        let mut frame = Vec::new();
        {
            let mut enc = Encoder::new(&mut frame);
            // Header map — CBOR canonical key order: "t"(1) < "op"(2)
            enc.encode_map_header(2).unwrap();
            enc.encode_text("t").unwrap();
            enc.encode_text("#commit").unwrap();
            enc.encode_text("op").unwrap();
            enc.encode_u64(1).unwrap();

            // Body map — CBOR canonical key order by encoded length:
            // "ops"(3), "rev"(3), "seq"(3), "repo"(4), "blocks"(6)
            enc.encode_map_header(5).unwrap();
            enc.encode_text("ops").unwrap();
            enc.encode_array_header(1).unwrap();
            // op entry: "cid"(3), "path"(4), "action"(6)
            enc.encode_map_header(3).unwrap();
            enc.encode_text("cid").unwrap();
            enc.encode_cid(&record_cid).unwrap();
            enc.encode_text("path").unwrap();
            enc.encode_text("app.bsky.feed.post/abc").unwrap();
            enc.encode_text("action").unwrap();
            enc.encode_text("create").unwrap();
            enc.encode_text("rev").unwrap();
            enc.encode_text("2222222222222").unwrap();
            enc.encode_text("seq").unwrap();
            enc.encode_u64(1).unwrap();
            enc.encode_text("repo").unwrap();
            enc.encode_text("did:plc:test123456789abcdefghij").unwrap();
            enc.encode_text("blocks").unwrap();
            enc.encode_bytes(&car_bytes).unwrap();
        }

        let event = parse_firehose_frame(&frame).unwrap();
        match event {
            Event::Commit {
                did,
                seq,
                operations,
                ..
            } => {
                assert_eq!(did.as_str(), "did:plc:test123456789abcdefghij");
                assert_eq!(seq, 1);
                assert_eq!(operations.len(), 1);
                match &operations[0] {
                    Operation::Create {
                        collection,
                        rkey,
                        cid,
                        record,
                    } => {
                        assert_eq!(collection.as_str(), "app.bsky.feed.post");
                        assert_eq!(rkey.as_str(), "abc");
                        assert_eq!(cid, &record_cid);
                        assert_eq!(record, record_data);
                    }
                    _ => panic!("expected Create operation"),
                }
            }
            _ => panic!("expected Commit event"),
        }
    }

    /// Build a #commit frame whose single create op references `op_cid`, with a
    /// blocks CAR containing one block `(block_cid, block_data)`. Lets tests
    /// stage CID/content mismatches and missing blocks.
    fn build_commit_frame(op_cid: &Cid, block_cid: &Cid, block_data: &[u8]) -> Vec<u8> {
        use crate::cbor::Encoder;
        let block = crate::car::Block {
            cid: *block_cid,
            data: block_data.to_vec(),
        };
        let car_bytes = crate::car::write_all(&[*block_cid], std::slice::from_ref(&block)).unwrap();
        let mut frame = Vec::new();
        let mut enc = Encoder::new(&mut frame);
        enc.encode_map_header(2).unwrap();
        enc.encode_text("t").unwrap();
        enc.encode_text("#commit").unwrap();
        enc.encode_text("op").unwrap();
        enc.encode_u64(1).unwrap();
        enc.encode_map_header(5).unwrap();
        enc.encode_text("ops").unwrap();
        enc.encode_array_header(1).unwrap();
        enc.encode_map_header(3).unwrap();
        enc.encode_text("cid").unwrap();
        enc.encode_cid(op_cid).unwrap();
        enc.encode_text("path").unwrap();
        enc.encode_text("app.bsky.feed.post/abc").unwrap();
        enc.encode_text("action").unwrap();
        enc.encode_text("create").unwrap();
        enc.encode_text("rev").unwrap();
        enc.encode_text("2222222222222").unwrap();
        enc.encode_text("seq").unwrap();
        enc.encode_u64(1).unwrap();
        enc.encode_text("repo").unwrap();
        enc.encode_text("did:plc:test123456789abcdefghij").unwrap();
        enc.encode_text("blocks").unwrap();
        enc.encode_bytes(&car_bytes).unwrap();
        frame
    }

    #[test]
    fn firehose_rejects_forged_block_cid() {
        // A block labeled with a CID that does NOT hash to its content must be
        // rejected, not emitted as the authentic record. Regression test for
        // H5 (firehose block CID verification).
        let real_data = b"authentic record";
        let real_cid = Cid::compute(Codec::Drisl, real_data);
        let forged_data = b"forged record bytes";
        // Frame claims the block is `real_cid` but ships `forged_data`.
        let frame = build_commit_frame(&real_cid, &real_cid, forged_data);
        let result = parse_firehose_frame(&frame);
        assert!(
            result.is_err(),
            "forged block (CID/content mismatch) must be rejected, got {result:?}"
        );
    }

    #[test]
    fn firehose_rejects_missing_op_block() {
        // A create op referencing a CID absent from the blocks CAR must error,
        // not emit an empty record. Regression test for H5.
        let present_data = b"present block";
        let present_cid = Cid::compute(Codec::Drisl, present_data);
        let missing_cid = Cid::compute(Codec::Drisl, b"some other record");
        // The op references `missing_cid`, but the CAR only contains present_cid.
        let frame = build_commit_frame(&missing_cid, &present_cid, present_data);
        let result = parse_firehose_frame(&frame);
        assert!(
            result.is_err(),
            "op referencing an absent block must be rejected, got {result:?}"
        );
    }

    #[test]
    fn firehose_accepts_valid_block() {
        // Positive control: a well-formed frame still parses.
        let data = b"valid record data";
        let cid = Cid::compute(Codec::Drisl, data);
        let frame = build_commit_frame(&cid, &cid, data);
        let event = parse_firehose_frame(&frame).expect("valid frame must parse");
        match event {
            Event::Commit { operations, .. } => {
                assert_eq!(operations.len(), 1);
                match &operations[0] {
                    Operation::Create { record, .. } => assert_eq!(record, data),
                    _ => panic!("expected Create"),
                }
            }
            _ => panic!("expected Commit"),
        }
    }

    #[test]
    fn firehose_unknown_op_is_skippable() {
        // L20: an unknown op code must surface as UnknownType (which the
        // consumer skips) rather than a fatal ParseCbor (reconnect loop).
        use crate::cbor::Encoder;
        let mut frame = Vec::new();
        let mut enc = Encoder::new(&mut frame);
        // Header {t:"#weird", op:99}, then an empty body map.
        enc.encode_map_header(2).unwrap();
        enc.encode_text("t").unwrap();
        enc.encode_text("#weird").unwrap();
        enc.encode_text("op").unwrap();
        enc.encode_u64(99).unwrap();
        enc.encode_map_header(0).unwrap();
        match parse_firehose_frame(&frame) {
            Err(StreamError::UnknownType(_)) => {}
            other => panic!("unknown op must be UnknownType (skippable), got {other:?}"),
        }
    }

    #[test]
    fn firehose_error_frame_surfaces_name_and_message() {
        // L21: an op=-1 error frame must surface the relay's structured error
        // name and message as a RelayError, not be silently skipped.
        use crate::cbor::Encoder;
        let mut frame = Vec::new();
        let mut enc = Encoder::new(&mut frame);
        // Header {op:-1, t:"#error"}.
        enc.encode_map_header(2).unwrap();
        enc.encode_text("t").unwrap();
        enc.encode_text("#error").unwrap();
        enc.encode_text("op").unwrap();
        enc.encode_i64(-1).unwrap();
        // Body {error:"FutureCursor", message:"cursor in the future"}.
        enc.encode_map_header(2).unwrap();
        enc.encode_text("error").unwrap();
        enc.encode_text("FutureCursor").unwrap();
        enc.encode_text("message").unwrap();
        enc.encode_text("cursor in the future").unwrap();

        match parse_firehose_frame(&frame) {
            Err(StreamError::RelayError { error, message }) => {
                assert_eq!(error, "FutureCursor");
                assert_eq!(message.as_deref(), Some("cursor in the future"));
            }
            other => panic!("error frame must be RelayError, got {other:?}"),
        }
    }

    #[test]
    fn firehose_error_frame_without_message_defaults_error_name() {
        // L21: a message-less error frame still surfaces the error name; a
        // missing error name defaults to "Unknown".
        use crate::cbor::Encoder;
        let mut frame = Vec::new();
        let mut enc = Encoder::new(&mut frame);
        enc.encode_map_header(2).unwrap();
        enc.encode_text("t").unwrap();
        enc.encode_text("#error").unwrap();
        enc.encode_text("op").unwrap();
        enc.encode_i64(-1).unwrap();
        // Body with only an error name, no message.
        enc.encode_map_header(1).unwrap();
        enc.encode_text("error").unwrap();
        enc.encode_text("ConsumerTooSlow").unwrap();

        match parse_firehose_frame(&frame) {
            Err(StreamError::RelayError { error, message }) => {
                assert_eq!(error, "ConsumerTooSlow");
                assert_eq!(message, None);
            }
            other => panic!("error frame must be RelayError, got {other:?}"),
        }
    }

    #[test]
    fn firehose_rejects_trailing_frame_data() {
        // L24: trailing bytes after the (header, body) pair must be rejected.
        let data = b"valid record data";
        let cid = Cid::compute(Codec::Drisl, data);
        let mut frame = build_commit_frame(&cid, &cid, data);
        frame.push(0x00); // stray trailing byte
        assert!(
            parse_firehose_frame(&frame).is_err(),
            "trailing data after frame body must be rejected"
        );
    }

    /// A frame of type `t` with this body.
    fn frame(t: &str, body: crate::cbor::Value<'_>) -> Vec<u8> {
        use crate::cbor::{Value, encode_value};
        let header = Value::Map(vec![("t", Value::Text(t)), ("op", Value::Unsigned(1))]);
        let mut frame = encode_value(&header).unwrap();
        frame.extend(encode_value(&body).unwrap());
        frame
    }

    fn op(
        action: &'static str,
        path: &'static str,
        cid: Option<Cid>,
    ) -> crate::cbor::Value<'static> {
        use crate::cbor::Value;
        let mut op = vec![("action", Value::Text(action)), ("path", Value::Text(path))];
        op.extend(cid.map(|c| ("cid", Value::Cid(c))));
        Value::Map(op)
    }

    /// A `#commit` frame with these ops and, unless `None`, a blocks CAR
    /// holding these blocks in this order.
    fn commit_frame(
        ops: Vec<crate::cbor::Value<'_>>,
        blocks: Option<&[(Cid, Vec<u8>)]>,
    ) -> Vec<u8> {
        use crate::cbor::Value;
        let car = blocks.map(|blocks| {
            let blocks: Vec<_> = blocks
                .iter()
                .map(|(cid, data)| crate::car::Block {
                    cid: *cid,
                    data: data.clone(),
                })
                .collect();
            crate::car::write_all(&[], &blocks).unwrap()
        });
        let mut body = vec![
            ("ops", Value::Array(ops)),
            ("rev", Value::Text("2222222222222")),
            ("seq", Value::Unsigned(1)),
            ("repo", Value::Text("did:plc:test123456789abcdefghij")),
        ];
        body.extend(car.as_deref().map(|car| ("blocks", Value::Bytes(car))));
        frame("#commit", Value::Map(body))
    }

    fn block(codec: Codec, data: &[u8]) -> (Cid, Vec<u8>) {
        (Cid::compute(codec, data), data.to_vec())
    }

    /// Blocks no op references, like a commit's MST nodes: few enough to be
    /// scanned, or enough to be indexed.
    fn fillers(n: usize) -> Vec<(Cid, Vec<u8>)> {
        (0..n)
            .map(|i| block(Codec::Drisl, format!("node {i}").as_bytes()))
            .collect()
    }

    fn commit_ops(frame: &[u8]) -> Vec<Operation> {
        match parse_firehose_frame(frame) {
            Ok(Event::Commit { operations, .. }) => operations,
            other => panic!("expected a commit, got {other:?}"),
        }
    }

    fn parse_error(frame: &[u8]) -> String {
        match parse_firehose_frame(frame) {
            Err(e) => e.to_string(),
            Ok(event) => panic!("expected an error, got {event:?}"),
        }
    }

    /// An op as comparable fields: action, collection, rkey, CID, record.
    type OpFields = (&'static str, String, String, Option<Cid>, Vec<u8>);

    fn op_fields(op: Operation) -> OpFields {
        match op {
            Operation::Create {
                collection,
                rkey,
                cid,
                record,
            } => (
                "create",
                collection.to_string(),
                rkey.to_string(),
                Some(cid),
                record,
            ),
            Operation::Update {
                collection,
                rkey,
                cid,
                record,
            } => (
                "update",
                collection.to_string(),
                rkey.to_string(),
                Some(cid),
                record,
            ),
            Operation::Delete { collection, rkey } => (
                "delete",
                collection.to_string(),
                rkey.to_string(),
                None,
                vec![],
            ),
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn firehose_ops_get_their_own_records() {
        let (a_cid, a) = block(Codec::Drisl, b"record a");
        let (b_cid, b) = block(Codec::Raw, b"record b");
        for n in [0, 3, 40] {
            let mut blocks = fillers(n);
            blocks.insert(n / 2, (b_cid, b.clone()));
            blocks.push((a_cid, a.clone()));
            // A repeated block is harmless.
            blocks.insert(0, (a_cid, a.clone()));
            let frame = commit_frame(
                vec![
                    op("update", "app.bsky.feed.post/b", Some(b_cid)),
                    op("delete", "app.bsky.feed.like/c", None),
                    op("create", "app.bsky.feed.post/a", Some(a_cid)),
                    // Identical records share a block.
                    op("create", "app.bsky.graph.follow/d", Some(a_cid)),
                ],
                Some(&blocks),
            );
            let got: Vec<_> = commit_ops(&frame).into_iter().map(op_fields).collect();
            let want = |action, collection: &str, rkey: &str, cid, record: &[u8]| {
                (action, collection.into(), rkey.into(), cid, record.to_vec())
            };
            let want = vec![
                want("update", "app.bsky.feed.post", "b", Some(b_cid), &b),
                want("delete", "app.bsky.feed.like", "c", None, b""),
                want("create", "app.bsky.feed.post", "a", Some(a_cid), &a),
                want("create", "app.bsky.graph.follow", "d", Some(a_cid), &a),
            ];
            assert_eq!(got, want, "{n} filler blocks");
        }
    }

    #[test]
    fn firehose_missing_record_names_the_op_and_cid() {
        let (cid, data) = block(Codec::Drisl, b"record");
        // The same bytes under the other codec are a different block.
        let raw = Cid::compute(Codec::Raw, &data);
        for n in [0, 40] {
            let mut blocks = fillers(n);
            blocks.push((raw, data.clone()));
            for action in ["create", "update"] {
                let frame = commit_frame(
                    vec![op(action, "app.bsky.feed.post/a", Some(cid))],
                    Some(&blocks),
                );
                assert_eq!(
                    parse_error(&frame),
                    format!(
                        "CBOR parse error: {action} op references CID {cid} absent from commit blocks"
                    ),
                    "{n} filler blocks"
                );
            }
        }
    }

    #[test]
    fn firehose_verifies_every_block() {
        // A forged block is rejected even when no op references it, and the
        // first forged block in the CAR is the one reported.
        let (real, _) = block(Codec::Drisl, b"authentic");
        let forged = b"forged".to_vec();
        let (other, _) = block(Codec::Raw, b"other");
        for n in [0, 40] {
            let mut blocks = fillers(n);
            blocks.push((real, forged.clone()));
            blocks.push((other, b"also forged".to_vec()));
            let frame = commit_frame(
                vec![op("delete", "app.bsky.feed.post/a", None)],
                Some(&blocks),
            );
            assert_eq!(
                parse_error(&frame),
                format!(
                    "CBOR parse error: commit block CID mismatch: declared {real}, content hashes to {}",
                    Cid::compute(Codec::Drisl, &forged)
                ),
                "{n} filler blocks"
            );
        }
    }

    #[test]
    fn firehose_commit_without_blocks() {
        let (cid, _) = block(Codec::Drisl, b"record");
        // An absent blocks field and a CAR of no blocks hold nothing to find.
        for blocks in [None, Some(&[][..])] {
            let delete = commit_frame(vec![op("delete", "app.bsky.feed.post/a", None)], blocks);
            assert!(matches!(
                commit_ops(&delete)[..],
                [Operation::Delete { .. }]
            ));
            let create = commit_frame(
                vec![op("create", "app.bsky.feed.post/a", Some(cid))],
                blocks,
            );
            assert!(parse_error(&create).contains("absent from commit blocks"));
        }
        assert!(commit_ops(&commit_frame(vec![], Some(&[]))).is_empty());
    }

    #[test]
    fn firehose_create_needs_a_cid_link() {
        use crate::cbor::Value;
        let (cid, data) = block(Codec::Drisl, b"record");
        let blocks = [(cid, data)];
        let null_cid = Value::Map(vec![
            ("cid", Value::Null),
            ("path", Value::Text("app.bsky.feed.post/a")),
            ("action", Value::Text("create")),
        ]);
        for op in [op("create", "app.bsky.feed.post/a", None), null_cid] {
            assert_eq!(
                parse_error(&commit_frame(vec![op], Some(&blocks))),
                "CBOR parse error: missing cid for create op"
            );
        }
    }

    #[test]
    fn firehose_labels_and_identity() {
        use crate::cbor::Value;
        let label = |val, neg: Option<bool>| {
            let mut fields = vec![
                ("src", Value::Text("did:plc:test123456789abcdefghij")),
                ("uri", Value::Text("at://did:plc:test123456789abcdefghij")),
                ("val", Value::Text(val)),
            ];
            fields.extend(neg.map(|n| ("neg", Value::Bool(n))));
            Value::Map(fields)
        };
        let labels = Value::Array(vec![label("spam", None), label("nudity", Some(true))]);
        let body = Value::Map(vec![("seq", Value::Unsigned(9)), ("labels", labels)]);
        match parse_firehose_frame(&frame("#labels", body)).unwrap() {
            Event::Labels { seq: 9, labels } => {
                let got: Vec<_> = labels.iter().map(|l| (l.val.as_str(), l.neg)).collect();
                assert_eq!(got, [("spam", false), ("nudity", true)]);
                assert_eq!(labels[0].src.as_str(), "did:plc:test123456789abcdefghij");
                assert_eq!(labels[0].uri, "at://did:plc:test123456789abcdefghij");
            }
            other => panic!("expected labels, got {other:?}"),
        }
        let body = Value::Map(vec![
            ("seq", Value::Unsigned(9)),
            ("labels", Value::Array(vec![Value::Null])),
        ]);
        assert_eq!(
            parse_error(&frame("#labels", body)),
            "CBOR parse error: label entry body must be a CBOR map"
        );

        // A missing, non-text or invalid handle is no handle.
        for (handle, want) in [
            (
                Some(Value::Text("alice.bsky.social")),
                Some("alice.bsky.social"),
            ),
            (Some(Value::Text("-bad-")), None),
            (Some(Value::Unsigned(1)), None),
            (None, None),
        ] {
            let mut body = vec![
                ("did", Value::Text("did:plc:test123456789abcdefghij")),
                ("seq", Value::Unsigned(3)),
            ];
            body.extend(handle.map(|h| ("handle", h)));
            match parse_firehose_frame(&frame("#identity", Value::Map(body))).unwrap() {
                Event::Identity { handle, .. } => {
                    assert_eq!(handle.as_ref().map(|h| h.as_str()), want);
                }
                other => panic!("expected identity, got {other:?}"),
            }
        }
    }

    #[test]
    fn firehose_info_and_sync_are_skippable() {
        use crate::cbor::Value;
        for t in ["#info", "#sync", "#future"] {
            match parse_firehose_frame(&frame(t, Value::Map(vec![]))) {
                Err(StreamError::UnknownType(got)) => assert_eq!(got, t),
                other => panic!("{t} must be UnknownType, got {other:?}"),
            }
        }
    }

    proptest! {
        /// Commits of several records, with unreferenced, repeated and forged
        /// blocks in any order, against a model: the first forged block fails
        /// the frame, then the first op whose record is absent, and otherwise
        /// every op gets the bytes of the block its CID names.
        #[test]
        fn prop_commit_matches_model(
            // Short records collide, so that ops share blocks and some bytes
            // appear under both codecs.
            records in prop::collection::vec(
                (any::<bool>(), prop::collection::vec(0u8..4, 0..3)),
                1..6,
            ),
            present in prop::collection::vec(any::<bool>(), 6),
            extra in 0usize..40,
            repeats in prop::collection::vec(any::<Index>(), 0..3),
            forge in prop::option::weighted(0.2, prop::collection::vec(any::<Index>(), 1..3)),
            ops in prop::collection::vec((0usize..3, any::<Index>()), 0..8),
            order in any::<u64>(),
        ) {
            const PATHS: [&str; 8] = [
                "app.bsky.feed.post/a",
                "app.bsky.feed.post/b",
                "app.bsky.feed.like/c",
                "app.bsky.feed.like/d",
                "app.bsky.graph.follow/e",
                "app.bsky.graph.follow/f",
                "app.bsky.feed.repost/g",
                "app.bsky.feed.repost/h",
            ];
            let records: Vec<_> = records
                .iter()
                .map(|(raw, r)| block(if *raw { Codec::Raw } else { Codec::Drisl }, r))
                .collect();
            let mut blocks = fillers(extra);
            for (record, present) in records.iter().zip(present) {
                if present {
                    blocks.push(record.clone());
                }
            }
            for r in &repeats {
                if !blocks.is_empty() {
                    blocks.push(blocks[r.index(blocks.len())].clone());
                }
            }
            let mut state = order;
            for i in (1..blocks.len()).rev() {
                state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
                blocks.swap(i, (state >> 33) as usize % (i + 1));
            }
            for at in forge.iter().flatten() {
                if !blocks.is_empty() {
                    let i = at.index(blocks.len());
                    blocks[i].1.push(0xff);
                }
            }
            let ops: Vec<_> = ops
                .iter()
                .zip(PATHS)
                .map(|((action, record), path)| {
                    let action = ["create", "update", "delete"][*action];
                    (action, path, records[record.index(records.len())].0)
                })
                .collect();
            let ops_cbor = ops
                .iter()
                .map(|&(action, path, cid)| op(action, path, (action != "delete").then_some(cid)));
            let frame = commit_frame(ops_cbor.collect(), Some(&blocks));

            let forged = blocks.iter().find(|(cid, data)| Cid::compute(cid.codec(), data) != *cid);
            let want: Result<Vec<OpFields>, String> = match forged {
                Some((cid, data)) => Err(format!(
                    "CBOR parse error: commit block CID mismatch: declared {cid}, \
                     content hashes to {}",
                    Cid::compute(cid.codec(), data)
                )),
                None => ops
                    .iter()
                    .map(|&(action, path, cid)| {
                        let (collection, rkey) = path.split_once('/').unwrap();
                        let (collection, rkey) = (collection.to_owned(), rkey.to_owned());
                        if action == "delete" {
                            return Ok((action, collection, rkey, None, vec![]));
                        }
                        match blocks.iter().find(|(c, _)| *c == cid) {
                            Some((_, data)) => {
                                Ok((action, collection, rkey, Some(cid), data.clone()))
                            }
                            None => Err(format!(
                                "CBOR parse error: {action} op references CID {cid} \
                                 absent from commit blocks"
                            )),
                        }
                    })
                    .collect(),
            };
            let got = match parse_firehose_frame(&frame) {
                Ok(Event::Commit { operations, .. }) => {
                    Ok(operations.into_iter().map(op_fields).collect())
                }
                Ok(other) => panic!("expected a commit, got {other:?}"),
                Err(e) => Err(e.to_string()),
            };
            prop_assert_eq!(got, want);
        }
    }

    // --- Config / Client construction tests ---

    #[test]
    fn config_struct_literal() {
        let cfg = Config {
            url: "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos".into(),
            cursor: Some(12345),
            ..Config::default()
        };
        assert_eq!(
            cfg.url,
            "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
        );
        assert_eq!(cfg.cursor, Some(12345));
    }

    #[test]
    fn client_cursor_none_when_unset() {
        let client = Client::new(Config {
            url: "wss://example.com/subscribe".into(),
            ..Config::default()
        });
        assert!(client.cursor().is_none());
    }

    #[test]
    fn client_cursor_returns_value_when_set() {
        let client = Client::new(Config {
            url: "wss://example.com/subscribe".into(),
            cursor: Some(999),
            ..Config::default()
        });
        assert_eq!(client.cursor(), Some(999));
    }

    // --- Jetstream error cases ---

    #[test]
    fn parse_jetstream_unknown_kind() {
        let json = r#"{"did":"did:plc:test123456789abcdefghij","time_us":1,"kind":"unknown"}"#;
        assert!(parse_jetstream_message(json).is_err());
    }

    #[test]
    fn parse_jetstream_invalid_did() {
        let json = r#"{"did":"not-a-did","time_us":1,"kind":"identity"}"#;
        assert!(parse_jetstream_message(json).is_err());
    }

    #[test]
    fn parse_jetstream_commit_update() {
        let json = r#"{
            "did": "did:plc:test123456789abcdefghij",
            "time_us": 1700000000000000,
            "kind": "commit",
            "commit": {
                "operation": "update",
                "collection": "app.bsky.feed.post",
                "rkey": "abc123",
                "cid": "bafyreihffx5a2e4gzlcbsuaamgoxwaqlodtip3r5ln4vpqwlpz6ji7ydnm",
                "record": {"text": "updated"}
            }
        }"#;
        let event = parse_jetstream_message(json).unwrap();
        match event {
            JetstreamEvent::Commit { operation, .. } => {
                assert!(matches!(operation, JetstreamCommit::Update { .. }));
            }
            _ => panic!("expected commit"),
        }
    }
}
