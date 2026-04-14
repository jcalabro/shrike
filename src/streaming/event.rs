use crate::cbor::Cid;
use crate::syntax::{Did, Handle, Nsid, RecordKey, Tid};

/// A single event from the firehose or label stream (DRISL/CBOR protocol).
#[derive(Debug)]
pub enum Event {
    /// A repository commit containing one or more record mutations.
    Commit {
        /// DID of the repository owner.
        did: Did,
        /// Revision TID of this commit.
        rev: Tid,
        /// Monotonic sequence number on this stream.
        seq: i64,
        /// Record mutations included in this commit.
        operations: Vec<Operation>,
    },
    /// A DID identity update (e.g., handle change or key rotation).
    Identity {
        /// DID that was updated.
        did: Did,
        /// Monotonic sequence number on this stream.
        seq: i64,
        /// New handle, if the identity has one.
        handle: Option<Handle>,
    },
    /// An account status change (activation or deactivation).
    Account {
        /// DID of the account.
        did: Did,
        /// Monotonic sequence number on this stream.
        seq: i64,
        /// Whether the account is currently active.
        active: bool,
    },
    /// A batch of moderation labels.
    Labels {
        /// Monotonic sequence number on this stream.
        seq: i64,
        /// The labels emitted in this event.
        labels: Vec<Label>,
    },
}

/// A single mutation within a commit.
#[derive(Debug)]
pub enum Operation {
    /// A new record was created.
    Create {
        /// Collection NSID (e.g., "app.bsky.feed.post").
        collection: Nsid,
        /// Record key within the collection.
        rkey: RecordKey,
        /// Content hash of the record data.
        cid: Cid,
        /// Raw DRISL-encoded record bytes.
        record: Vec<u8>,
    },
    /// An existing record was updated.
    Update {
        /// Collection NSID.
        collection: Nsid,
        /// Record key within the collection.
        rkey: RecordKey,
        /// Content hash of the new record data.
        cid: Cid,
        /// Raw DRISL-encoded record bytes.
        record: Vec<u8>,
    },
    /// A record was deleted.
    Delete {
        /// Collection NSID.
        collection: Nsid,
        /// Record key of the deleted record.
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
