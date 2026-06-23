use crate::cbor::Cid;
use crate::syntax::{Did, Nsid, RecordKey};
use serde::Deserialize;

use crate::streaming::StreamError;

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
    // `did`/`time_us`/`kind` are absent on server *error* frames, which carry a
    // top-level `{error, message}` instead — so they are optional here and the
    // error shape is detected before requiring them.
    #[serde(default)]
    pub did: Option<String>,
    #[serde(default)]
    pub time_us: Option<i64>,
    #[serde(default)]
    pub kind: Option<String>,
    pub commit: Option<RawCommit>,
    pub account: Option<RawAccount>,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub message: Option<String>,
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

    // A server error frame carries a top-level `error` (and optional `message`)
    // and no `did`/`kind`. Surface it as a structured RelayError before
    // requiring the data-frame fields — otherwise it deserializes into an
    // opaque "missing field did". Matches the Jetstream reference, which checks
    // the error field first.
    if let Some(error) = raw.error {
        return Err(StreamError::RelayError {
            error,
            message: raw.message,
        });
    }

    let did_str = raw
        .did
        .ok_or_else(|| StreamError::ParseJson("event missing did field".into()))?;
    let did = Did::try_from(did_str.as_str())
        .map_err(|e| StreamError::ParseJson(format!("invalid DID: {e}")))?;
    let time_us = raw
        .time_us
        .ok_or_else(|| StreamError::ParseJson("event missing time_us field".into()))?;
    let kind = raw
        .kind
        .ok_or_else(|| StreamError::ParseJson("event missing kind field".into()))?;

    match kind.as_str() {
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
                time_us,
                collection,
                rkey,
                operation,
            })
        }
        "identity" => Ok(JetstreamEvent::Identity { did, time_us }),
        "account" => {
            let account = raw.account.ok_or_else(|| {
                StreamError::ParseJson("account kind missing account field".into())
            })?;
            Ok(JetstreamEvent::Account {
                did,
                time_us,
                active: account.active,
            })
        }
        other => Err(StreamError::ParseJson(format!(
            "unknown event kind: {other:?}"
        ))),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn jetstream_error_frame_surfaces_code_and_message() {
        // L23: a server error frame carries top-level {error, message} and no
        // did/kind. It must surface as a structured RelayError, not the opaque
        // "missing field did".
        let json = r#"{"error":"FutureCursor","message":"cursor is in the future"}"#;
        match parse_jetstream_message(json) {
            Err(StreamError::RelayError { error, message }) => {
                assert_eq!(error, "FutureCursor");
                assert_eq!(message.as_deref(), Some("cursor is in the future"));
            }
            other => panic!("error frame must be RelayError, got {other:?}"),
        }
    }

    #[test]
    fn jetstream_error_frame_without_message() {
        let json = r#"{"error":"ConsumerTooSlow"}"#;
        match parse_jetstream_message(json) {
            Err(StreamError::RelayError { error, message }) => {
                assert_eq!(error, "ConsumerTooSlow");
                assert_eq!(message, None);
            }
            other => panic!("error frame must be RelayError, got {other:?}"),
        }
    }

    #[test]
    fn jetstream_missing_did_on_data_frame_is_distinct_error() {
        // A non-error frame that genuinely lacks `did` must still be a clear
        // ParseJson error (not silently treated as an error frame).
        let json = r#"{"kind":"identity","time_us":1}"#;
        match parse_jetstream_message(json) {
            Err(StreamError::ParseJson(msg)) => assert!(msg.contains("did")),
            other => panic!("expected ParseJson about did, got {other:?}"),
        }
    }

    #[test]
    fn jetstream_valid_identity_frame_still_parses() {
        // Positive control: a well-formed identity frame is unaffected.
        let json = r#"{"did":"did:plc:7iza6de2dwap2sbkpav7c6c6","time_us":1700000000000000,"kind":"identity"}"#;
        match parse_jetstream_message(json).unwrap() {
            JetstreamEvent::Identity { did, time_us } => {
                assert_eq!(did.as_str(), "did:plc:7iza6de2dwap2sbkpav7c6c6");
                assert_eq!(time_us, 1_700_000_000_000_000);
            }
            other => panic!("expected Identity, got {other:?}"),
        }
    }
}
