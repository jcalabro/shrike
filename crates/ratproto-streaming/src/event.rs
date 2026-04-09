use ratproto_cbor::Cid;
use ratproto_syntax::{Did, Handle, Nsid, RecordKey, Tid};

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

/// A moderation label.
#[derive(Debug)]
pub struct Label {
    pub src: Did,
    pub uri: String,
    pub val: String,
    pub neg: bool,
}
