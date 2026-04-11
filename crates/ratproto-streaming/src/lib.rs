//! AT Protocol event streaming — firehose, labels, and Jetstream.
//!
//! # Overview
//!
//! This crate provides types and parsing for AT Protocol event streams:
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

pub mod client;
pub mod event;
pub mod jetstream;
pub mod reconnect;

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
}

impl From<ratproto_cbor::CborError> for StreamError {
    fn from(e: ratproto_cbor::CborError) -> Self {
        StreamError::ParseCbor(e.to_string())
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
    use ratproto_cbor::Decoder;
    use ratproto_syntax::{Did, Handle, Tid};

    // Decode the header map.
    let mut dec = Decoder::new(data);
    let header = dec
        .decode()
        .map_err(|e| StreamError::ParseCbor(format!("header: {e}")))?;

    let (op, type_tag) = extract_frame_header(header)?;

    // op=-1 is an error frame; skip it (yield as Unknown).
    if op == -1 {
        return Err(StreamError::UnknownType("error frame".into()));
    }
    if op != 1 {
        return Err(StreamError::ParseCbor(format!("unknown frame op: {op}")));
    }

    // Decode the body map.
    let body = dec
        .decode()
        .map_err(|e| StreamError::ParseCbor(format!("body: {e}")))?;

    match type_tag.as_str() {
        "#commit" => {
            let fields = require_map(body, "#commit")?;
            let did_str =
                require_text(&fields, "repo").or_else(|_| require_text(&fields, "did"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let rev_str = require_text(&fields, "rev")?;
            let rev = Tid::try_from(rev_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid rev TID: {e}")))?;
            let seq = require_int(&fields, "seq")?;

            // Decode the CAR-encoded blocks to build a CID→data index.
            // Operations reference blocks by CID for create/update records.
            let block_index = parse_commit_blocks(&fields)?;
            let operations = parse_commit_ops(&fields, &block_index)?;
            Ok(Event::Commit {
                did,
                rev,
                seq,
                operations,
            })
        }
        "#identity" => {
            let fields = require_map(body, "#identity")?;
            let did_str =
                require_text(&fields, "did").or_else(|_| require_text(&fields, "repo"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let seq = require_int(&fields, "seq")?;
            let handle = optional_text(&fields, "handle").and_then(|h| Handle::try_from(h).ok());
            Ok(Event::Identity { did, seq, handle })
        }
        "#account" => {
            let fields = require_map(body, "#account")?;
            let did_str =
                require_text(&fields, "did").or_else(|_| require_text(&fields, "repo"))?;
            let did = Did::try_from(did_str)
                .map_err(|e| StreamError::ParseCbor(format!("invalid DID: {e}")))?;
            let seq = require_int(&fields, "seq")?;
            let active = optional_bool(&fields, "active").unwrap_or(false);
            Ok(Event::Account { did, seq, active })
        }
        "#labels" => {
            let fields = require_map(body, "#labels")?;
            let seq = require_int(&fields, "seq")?;
            let labels = parse_labels(&fields)?;
            Ok(Event::Labels { seq, labels })
        }
        "#info" | "#sync" => {
            // Forward-compat: skip info and sync frames.
            Err(StreamError::UnknownType(type_tag))
        }
        other => Err(StreamError::UnknownType(other.to_string())),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn extract_frame_header(header: ratproto_cbor::Value<'_>) -> Result<(i64, String), StreamError> {
    use ratproto_cbor::Value;

    let entries = match header {
        Value::Map(m) => m,
        _ => {
            return Err(StreamError::ParseCbor(
                "frame header must be a CBOR map".into(),
            ));
        }
    };

    let mut op: Option<i64> = None;
    let mut t: Option<String> = None;

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
                    Value::Text(s) => s.to_owned(),
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

type Fields<'a> = Vec<(&'a str, ratproto_cbor::Value<'a>)>;

fn require_map<'a>(
    val: ratproto_cbor::Value<'a>,
    context: &str,
) -> Result<Fields<'a>, StreamError> {
    match val {
        ratproto_cbor::Value::Map(m) => Ok(m),
        _ => Err(StreamError::ParseCbor(format!(
            "{context} body must be a CBOR map"
        ))),
    }
}

fn require_text<'a>(fields: &'a Fields<'_>, key: &str) -> Result<&'a str, StreamError> {
    for (k, v) in fields {
        if *k == key {
            return match v {
                ratproto_cbor::Value::Text(s) => Ok(s),
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
                ratproto_cbor::Value::Unsigned(n) => i64::try_from(*n)
                    .map_err(|_| StreamError::ParseCbor(format!("field {key:?} overflows i64"))),
                ratproto_cbor::Value::Signed(n) => Ok(*n),
                _ => Err(StreamError::ParseCbor(format!(
                    "field {key:?} must be an integer"
                ))),
            };
        }
    }
    Err(StreamError::ParseCbor(format!("missing field {key:?}")))
}

fn optional_text<'a>(fields: &'a Fields<'_>, key: &str) -> Option<&'a str> {
    require_text(fields, key).ok()
}

fn optional_bool(fields: &Fields<'_>, key: &str) -> Option<bool> {
    for (k, v) in fields {
        if *k == key
            && let ratproto_cbor::Value::Bool(b) = v
        {
            return Some(*b);
        }
    }
    None
}

/// Decode the `blocks` field from a `#commit` body as a CAR file.
///
/// Returns a CID→data mapping for looking up record bytes by CID.
fn parse_commit_blocks(
    fields: &Fields<'_>,
) -> Result<std::collections::HashMap<String, Vec<u8>>, StreamError> {
    use std::collections::HashMap;

    let blocks_bytes = extract_bytes(fields, "blocks");

    let Some(blocks_bytes) = blocks_bytes else {
        // blocks field may be absent; return empty index.
        return Ok(HashMap::new());
    };

    let (_roots, blocks) = ratproto_car::read_all(&blocks_bytes[..])
        .map_err(|e| StreamError::ParseCbor(format!("failed to decode commit blocks CAR: {e}")))?;

    let mut index = HashMap::with_capacity(blocks.len());
    for block in blocks {
        index.insert(block.cid.to_string(), block.data);
    }
    Ok(index)
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
    block_index: &std::collections::HashMap<String, Vec<u8>>,
) -> Result<Vec<event::Operation>, StreamError> {
    use ratproto_cbor::Value;
    use ratproto_syntax::{Nsid, RecordKey};

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
        let item_fields = require_map(item.clone(), "op entry")?;
        let action = require_text(&item_fields, "action")?;

        // path is "collection/rkey" — split on first '/'
        let path = require_text(&item_fields, "path")?;
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
                let cid = extract_cid_optional(&item_fields, "cid").ok_or_else(|| {
                    StreamError::ParseCbor(format!("missing cid for {action} op"))
                })?;

                // Look up record data from the blocks CAR by CID.
                let cid_str = cid.to_string();
                let record = block_index.get(&cid_str).cloned().unwrap_or_default();

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

fn extract_cid_optional(fields: &Fields<'_>, key: &str) -> Option<ratproto_cbor::Cid> {
    for (k, v) in fields {
        if *k == key {
            return match v {
                ratproto_cbor::Value::Cid(c) => Some(*c),
                _ => None,
            };
        }
    }
    None
}

fn extract_bytes(fields: &Fields<'_>, key: &str) -> Option<Vec<u8>> {
    for (k, v) in fields {
        if *k == key
            && let ratproto_cbor::Value::Bytes(b) = v
        {
            return Some(b.to_vec());
        }
    }
    None
}

/// Parse the `labels` array from a `#labels` body.
fn parse_labels(fields: &Fields<'_>) -> Result<Vec<event::Label>, StreamError> {
    use ratproto_cbor::Value;
    use ratproto_syntax::Did;

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
        let item_fields = require_map(item.clone(), "label entry")?;
        let src_str = require_text(&item_fields, "src")?;
        let uri = require_text(&item_fields, "uri")?.to_owned();
        let val = require_text(&item_fields, "val")?.to_owned();
        let neg = optional_bool(&item_fields, "neg").unwrap_or(false);
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
    use super::*;
    use ratproto_cbor::{Cid, Codec};
    use ratproto_syntax::{Did, Nsid, RecordKey, Tid};

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
            rev: Tid::new(1_700_000_000_000_000, 0),
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
        use ratproto_cbor::Encoder;

        let record_data = b"fake record data";
        let record_cid = Cid::compute(Codec::Drisl, record_data);

        // Build a minimal CAR containing the record block
        let block = ratproto_car::Block {
            cid: record_cid,
            data: record_data.to_vec(),
        };
        let car_bytes =
            ratproto_car::write_all(&[record_cid], std::slice::from_ref(&block)).unwrap();

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
