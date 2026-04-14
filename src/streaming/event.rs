use crate::cbor::Cid;
use crate::syntax::{Did, Handle, Nsid, RecordKey, Tid};

/// A single event from the firehose or label stream (DRISL/CBOR protocol).
#[derive(Debug)]
pub enum Event {
    Commit {
        did: Did,
        rev: Tid,
        seq: i64,
        operations: Vec<Operation>,
    },
    Identity {
        did: Did,
        seq: i64,
        handle: Option<Handle>,
    },
    Account {
        did: Did,
        seq: i64,
        active: bool,
    },
    Labels {
        seq: i64,
        labels: Vec<Label>,
    },
}

/// A single mutation within a commit.
#[derive(Debug)]
pub enum Operation {
    Create {
        collection: Nsid,
        rkey: RecordKey,
        cid: Cid,
        record: Vec<u8>,
    },
    Update {
        collection: Nsid,
        rkey: RecordKey,
        cid: Cid,
        record: Vec<u8>,
    },
    Delete {
        collection: Nsid,
        rkey: RecordKey,
    },
}

/// A moderation label from a firehose labels event.
#[derive(Debug)]
pub struct Label {
    /// DID of the labeler that issued this label.
    pub src: Did,
    /// AT URI of the labeled content.
    pub uri: String,
    /// Label value (e.g., "spam", "nudity").
    pub val: String,
    /// If true, this negates (removes) a previously applied label.
    pub neg: bool,
}
