use serde::Deserialize;
use shrike_cbor::Cid;
use shrike_syntax::{Did, Nsid, RecordKey};

use crate::StreamError;

/// Jetstream event (JSON protocol — separate from CBOR firehose).
#[derive(Debug)]
pub enum JetstreamEvent {
    Commit {
        did: Did,
        time_us: i64,
        collection: Nsid,
        rkey: RecordKey,
        operation: JetstreamCommit,
    },
    Identity {
        did: Did,
        time_us: i64,
    },
    Account {
        did: Did,
        time_us: i64,
        active: bool,
    },
}

/// The commit operation for a Jetstream commit event.
#[derive(Debug)]
pub enum JetstreamCommit {
    Create { cid: Cid, record: serde_json::Value },
    Update { cid: Cid, record: serde_json::Value },
    Delete,
}

// ---------------------------------------------------------------------------
// Internal serde types for JSON parsing
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct RawJetstreamEvent {
    pub did: String,
    pub time_us: i64,
    pub kind: String,
    pub commit: Option<RawCommit>,
    pub account: Option<RawAccount>,
}

#[derive(Deserialize)]
pub(crate) struct RawCommit {
    pub operation: String,
    pub collection: String,
    pub rkey: String,
    pub cid: Option<String>,
    pub record: Option<serde_json::Value>,
}

#[derive(Deserialize)]
pub(crate) struct RawAccount {
    pub active: bool,
}

// ---------------------------------------------------------------------------
// Parsing
// ---------------------------------------------------------------------------

/// Parse a single Jetstream JSON message into a [`JetstreamEvent`].
pub fn parse_jetstream_message(json: &str) -> Result<JetstreamEvent, StreamError> {
    let raw: RawJetstreamEvent =
        serde_json::from_str(json).map_err(|e| StreamError::ParseJson(e.to_string()))?;

    let did = Did::try_from(raw.did.as_str())
        .map_err(|e| StreamError::ParseJson(format!("invalid DID: {e}")))?;

    match raw.kind.as_str() {
        "commit" => {
            let commit = raw
                .commit
                .ok_or_else(|| StreamError::ParseJson("commit kind missing commit field".into()))?;

            let collection = Nsid::try_from(commit.collection.as_str())
                .map_err(|e| StreamError::ParseJson(format!("invalid collection NSID: {e}")))?;

            let rkey = RecordKey::try_from(commit.rkey.as_str())
                .map_err(|e| StreamError::ParseJson(format!("invalid rkey: {e}")))?;

            let operation = match commit.operation.as_str() {
                "create" => {
                    let cid_str = commit.cid.ok_or_else(|| {
                        StreamError::ParseJson("create commit missing cid".into())
                    })?;
                    let cid = cid_str
                        .parse::<Cid>()
                        .map_err(|e| StreamError::ParseJson(format!("invalid CID: {e}")))?;
                    let record = commit.record.ok_or_else(|| {
                        StreamError::ParseJson("create commit missing record".into())
                    })?;
                    JetstreamCommit::Create { cid, record }
                }
                "update" => {
                    let cid_str = commit.cid.ok_or_else(|| {
                        StreamError::ParseJson("update commit missing cid".into())
                    })?;
                    let cid = cid_str
                        .parse::<Cid>()
                        .map_err(|e| StreamError::ParseJson(format!("invalid CID: {e}")))?;
                    let record = commit.record.ok_or_else(|| {
                        StreamError::ParseJson("update commit missing record".into())
                    })?;
                    JetstreamCommit::Update { cid, record }
                }
                "delete" => JetstreamCommit::Delete,
                other => {
                    return Err(StreamError::ParseJson(format!(
                        "unknown commit operation: {other:?}"
                    )));
                }
            };

            Ok(JetstreamEvent::Commit {
                did,
                time_us: raw.time_us,
                collection,
                rkey,
                operation,
            })
        }
        "identity" => Ok(JetstreamEvent::Identity {
            did,
            time_us: raw.time_us,
        }),
        "account" => {
            let account = raw.account.ok_or_else(|| {
                StreamError::ParseJson("account kind missing account field".into())
            })?;
            Ok(JetstreamEvent::Account {
                did,
                time_us: raw.time_us,
                active: account.active,
            })
        }
        other => Err(StreamError::ParseJson(format!(
            "unknown event kind: {other:?}"
        ))),
    }
}
