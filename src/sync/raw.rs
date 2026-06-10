//! Raw AT Protocol Sync 1.1 firehose event parsing.
//!
//! These types intentionally avoid generated `api` types so sync verification
//! can operate with only the sync, streaming, CBOR, CAR, and syntax layers.

use crate::cbor::Cid;
use crate::syntax::{Did, Handle, Tid};

#[derive(Debug, thiserror::Error)]
pub enum RawSyncError {
    #[error("CBOR parse error: {0}")]
    ParseCbor(String),
    #[error("unknown event type: {0}")]
    UnknownType(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RawSyncEvent {
    Commit(RawCommit),
    Sync(RawSync),
    Account(RawAccount),
    Identity(RawIdentity),
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawCommit {
    pub repo: Did,
    pub rev: Tid,
    pub seq: i64,
    pub time: String,
    pub since: Option<Tid>,
    pub commit: Cid,
    pub blocks: Vec<u8>,
    pub ops: Vec<RawRepoOp>,
    pub blobs: Vec<Cid>,
    pub prev_data: Option<Cid>,
    pub too_big: bool,
    pub rebase: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawRepoOp {
    pub action: String,
    pub path: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawSync {
    pub did: Did,
    pub rev: String,
    pub seq: i64,
    pub time: String,
    pub blocks: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawAccount {
    pub did: Did,
    pub seq: i64,
    pub time: String,
    pub active: bool,
    pub status: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawIdentity {
    pub did: Did,
    pub seq: i64,
    pub time: String,
    pub handle: Option<Handle>,
}

impl RawSyncEvent {
    pub fn into_commit(self) -> Option<RawCommit> {
        match self {
            Self::Commit(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_sync(self) -> Option<RawSync> {
        match self {
            Self::Sync(v) => Some(v),
            _ => None,
        }
    }

    pub fn into_account(self) -> Option<RawAccount> {
        match self {
            Self::Account(v) => Some(v),
            _ => None,
        }
    }
}

type Fields<'a> = Vec<(&'a str, crate::cbor::Value<'a>)>;

/// Parse a raw Sync 1.1 firehose frame.
///
/// A frame is exactly two consecutive CBOR values: the frame header and the
/// event body. Unknown fields are ignored, but known fields are type-checked so
/// malformed byte/link fields do not silently degrade into absent data.
pub fn parse_raw_sync_frame(data: &[u8]) -> Result<RawSyncEvent, RawSyncError> {
    use crate::cbor::Decoder;

    let mut dec = Decoder::new(data);
    let header = dec
        .decode()
        .map_err(|e| RawSyncError::ParseCbor(format!("header: {e}")))?;
    let (op, type_tag) = extract_frame_header(header)?;

    if op != 1 {
        return Err(RawSyncError::ParseCbor(format!("unknown frame op: {op}")));
    }

    let body = dec
        .decode()
        .map_err(|e| RawSyncError::ParseCbor(format!("body: {e}")))?;

    if !dec.is_empty() {
        return Err(RawSyncError::ParseCbor(format!(
            "trailing data after raw sync frame at byte {}",
            dec.position()
        )));
    }

    match type_tag.as_str() {
        "#commit" => parse_commit(body).map(RawSyncEvent::Commit),
        "#sync" => parse_sync(body).map(RawSyncEvent::Sync),
        "#account" => parse_account(body).map(RawSyncEvent::Account),
        "#identity" => parse_identity(body).map(RawSyncEvent::Identity),
        "#info" => {
            let _fields = require_map(body, "#info")?;
            Ok(RawSyncEvent::Info)
        }
        other => Err(RawSyncError::UnknownType(other.to_owned())),
    }
}

fn extract_frame_header(header: crate::cbor::Value<'_>) -> Result<(i64, String), RawSyncError> {
    use crate::cbor::Value;

    let fields = match header {
        Value::Map(fields) => fields,
        _ => {
            return Err(RawSyncError::ParseCbor(
                "frame header must be a CBOR map".into(),
            ));
        }
    };

    let op = require_int(&fields, "op")?;
    let t = require_text(&fields, "t")?.to_owned();
    Ok((op, t))
}

fn parse_commit(body: crate::cbor::Value<'_>) -> Result<RawCommit, RawSyncError> {
    let fields = require_map(body, "#commit")?;
    let repo = parse_did(require_text(&fields, "repo")?, "repo")?;
    let rev = Tid::try_from(require_text(&fields, "rev")?)
        .map_err(|e| RawSyncError::ParseCbor(format!("invalid rev TID: {e}")))?;

    Ok(RawCommit {
        repo,
        rev,
        seq: require_int(&fields, "seq")?,
        time: require_text(&fields, "time")?.to_owned(),
        since: optional_tid(&fields, "since")?,
        commit: require_cid(&fields, "commit")?,
        blocks: require_bytes(&fields, "blocks")?.to_vec(),
        ops: parse_repo_ops(&fields)?,
        blobs: parse_blobs(&fields)?,
        prev_data: optional_cid(&fields, "prevData")?,
        too_big: require_bool(&fields, "tooBig")?,
        rebase: require_bool(&fields, "rebase")?,
    })
}

fn parse_sync(body: crate::cbor::Value<'_>) -> Result<RawSync, RawSyncError> {
    let fields = require_map(body, "#sync")?;
    Ok(RawSync {
        did: parse_did(require_text(&fields, "did")?, "did")?,
        rev: require_text(&fields, "rev")?.to_owned(),
        seq: require_int(&fields, "seq")?,
        time: require_text(&fields, "time")?.to_owned(),
        blocks: require_bytes(&fields, "blocks")?.to_vec(),
    })
}

fn parse_account(body: crate::cbor::Value<'_>) -> Result<RawAccount, RawSyncError> {
    let fields = require_map(body, "#account")?;
    Ok(RawAccount {
        did: parse_did(require_text(&fields, "did")?, "did")?,
        seq: require_int(&fields, "seq")?,
        time: require_text(&fields, "time")?.to_owned(),
        active: require_bool(&fields, "active")?,
        status: optional_text(&fields, "status")?.map(ToOwned::to_owned),
    })
}

fn parse_identity(body: crate::cbor::Value<'_>) -> Result<RawIdentity, RawSyncError> {
    let fields = require_map(body, "#identity")?;
    let handle = optional_text(&fields, "handle")?
        .map(Handle::try_from)
        .transpose()
        .map_err(|e| RawSyncError::ParseCbor(format!("invalid handle: {e}")))?;

    Ok(RawIdentity {
        did: parse_did(require_text(&fields, "did")?, "did")?,
        seq: require_int(&fields, "seq")?,
        time: require_text(&fields, "time")?.to_owned(),
        handle,
    })
}

fn parse_repo_ops(fields: &Fields<'_>) -> Result<Vec<RawRepoOp>, RawSyncError> {
    use crate::cbor::Value;

    let Some(value) = field_value(fields, "ops") else {
        return Ok(Vec::new());
    };

    let Value::Array(items) = value else {
        return Err(RawSyncError::ParseCbor(
            "field \"ops\" must be an array".into(),
        ));
    };

    let mut ops = Vec::with_capacity(items.len());
    for item in items {
        let Value::Map(item_fields) = item else {
            return Err(RawSyncError::ParseCbor(
                "repo op body must be a CBOR map".into(),
            ));
        };
        ops.push(RawRepoOp {
            action: require_text(item_fields, "action")?.to_owned(),
            path: require_text(item_fields, "path")?.to_owned(),
            cid: optional_cid(item_fields, "cid")?,
            prev: optional_cid(item_fields, "prev")?,
        });
    }
    Ok(ops)
}

fn parse_blobs(fields: &Fields<'_>) -> Result<Vec<Cid>, RawSyncError> {
    use crate::cbor::Value;

    let Some(value) = field_value(fields, "blobs") else {
        return Ok(Vec::new());
    };

    let Value::Array(items) = value else {
        return Err(RawSyncError::ParseCbor(
            "field \"blobs\" must be an array".into(),
        ));
    };

    let mut blobs = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::Cid(cid) => blobs.push(*cid),
            _ => {
                return Err(RawSyncError::ParseCbor(
                    "field \"blobs\" entries must be CIDs".into(),
                ));
            }
        }
    }
    Ok(blobs)
}

fn require_map<'a>(
    value: crate::cbor::Value<'a>,
    context: &str,
) -> Result<Fields<'a>, RawSyncError> {
    match value {
        crate::cbor::Value::Map(fields) => Ok(fields),
        _ => Err(RawSyncError::ParseCbor(format!(
            "{context} body must be a CBOR map"
        ))),
    }
}

fn field_value<'a>(fields: &'a Fields<'_>, key: &str) -> Option<&'a crate::cbor::Value<'a>> {
    fields.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
}

fn require_text<'a>(fields: &'a Fields<'_>, key: &str) -> Result<&'a str, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Text(value)) => Ok(value),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be a text string"
        ))),
        None => Err(RawSyncError::ParseCbor(format!("missing field {key:?}"))),
    }
}

fn optional_text<'a>(fields: &'a Fields<'_>, key: &str) -> Result<Option<&'a str>, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Text(value)) => Ok(Some(value)),
        Some(crate::cbor::Value::Null) | None => Ok(None),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be a text string"
        ))),
    }
}

fn require_int(fields: &Fields<'_>, key: &str) -> Result<i64, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Unsigned(value)) => i64::try_from(*value)
            .map_err(|_| RawSyncError::ParseCbor(format!("field {key:?} overflows i64"))),
        Some(crate::cbor::Value::Signed(value)) => Ok(*value),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be an integer"
        ))),
        None => Err(RawSyncError::ParseCbor(format!("missing field {key:?}"))),
    }
}

fn require_bool(fields: &Fields<'_>, key: &str) -> Result<bool, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Bool(value)) => Ok(*value),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be a boolean"
        ))),
        None => Err(RawSyncError::ParseCbor(format!("missing field {key:?}"))),
    }
}

fn require_bytes<'a>(fields: &'a Fields<'_>, key: &str) -> Result<&'a [u8], RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Bytes(value)) => Ok(value),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be bytes"
        ))),
        None => Err(RawSyncError::ParseCbor(format!("missing field {key:?}"))),
    }
}

fn require_cid(fields: &Fields<'_>, key: &str) -> Result<Cid, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Cid(value)) => Ok(*value),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be a CID"
        ))),
        None => Err(RawSyncError::ParseCbor(format!("missing field {key:?}"))),
    }
}

fn optional_cid(fields: &Fields<'_>, key: &str) -> Result<Option<Cid>, RawSyncError> {
    match field_value(fields, key) {
        Some(crate::cbor::Value::Cid(value)) => Ok(Some(*value)),
        Some(crate::cbor::Value::Null) | None => Ok(None),
        Some(_) => Err(RawSyncError::ParseCbor(format!(
            "field {key:?} must be a CID"
        ))),
    }
}

fn optional_tid(fields: &Fields<'_>, key: &str) -> Result<Option<Tid>, RawSyncError> {
    optional_text(fields, key)?
        .map(Tid::try_from)
        .transpose()
        .map_err(|e| RawSyncError::ParseCbor(format!("invalid {key} TID: {e}")))
}

fn parse_did(value: &str, key: &str) -> Result<Did, RawSyncError> {
    Did::try_from(value).map_err(|e| RawSyncError::ParseCbor(format!("invalid {key} DID: {e}")))
}
