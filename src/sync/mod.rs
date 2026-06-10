//! AT Protocol repository sync and commit verification.
//!
//! [`SyncClient`] downloads full repositories via `com.atproto.sync.getRepo`
//! and [`verify_blocks`] checks that every block's CID matches its data.

pub mod client;
pub mod error;
pub mod invert;
pub mod raw;
pub mod resync;
pub mod state;
pub mod verifier;
pub mod verify;

pub use client::SyncClient;
pub use error::VerifierError;
pub use invert::{
    CarBlockStore, DecodedCommitCar, check_op_cids, decode_commit_car, decode_sync_commit,
    find_duplicate_path, invert_commit, invert_decoded_commit,
};
pub use raw::{RawAccount, RawCommit, RawIdentity, RawRepoOp, RawSync, RawSyncError, RawSyncEvent};
pub use resync::{
    DEFAULT_MAX_REPO_BLOCK_BYTES, DEFAULT_MAX_REPO_BLOCKS, DEFAULT_MAX_REPO_CAR_BYTES,
    DEFAULT_MAX_REPO_RECORDS, RepoLoadLimits, ResyncEvent,
};
pub use state::{
    ChainState, HostingState, MemStateStore, StateStore, StateStoreError, StateStoreOperation,
};
pub use verifier::{
    DEFAULT_FUTURE_REV_TOLERANCE, DEFAULT_RESYNC_BURST, DEFAULT_RESYNC_LIMIT_PER_SECOND,
    DEFAULT_RESYNC_LIMITER_CAPACITY, HostingPolicy, IdentityResolver, LegacyCommitPolicy,
    MAX_COMMIT_BLOCKS_BYTES, MAX_COMMIT_OPS, ResyncRateLimit, SyncRepoSource,
    VERIFIER_LOCK_STRIPES, Verifier, VerifierOp, VerifierOptions, VerifierPolicy, VerifierStats,
};
pub use verify::verify_blocks;

use crate::cbor::Cid;
use crate::repo::Commit;
use crate::syntax::{Nsid, RecordKey};

/// Errors produced by the sync client and verifier.
#[derive(Debug, thiserror::Error)]
pub enum SyncError {
    #[error("sync failed: {0}")]
    Sync(String),
    #[error("verification failed: {0}")]
    Verification(String),
    #[error("verifier error: {0}")]
    Verifier(#[source] Box<crate::sync::error::VerifierError>),
    #[error("state store error: {0}")]
    StateStore(#[from] crate::sync::state::StateStoreError),
    #[error("XRPC error: {0}")]
    Xrpc(#[from] crate::xrpc::Error),
    #[error("CAR error: {0}")]
    Car(#[from] crate::car::CarError),
    #[error("CBOR error: {0}")]
    Cbor(#[from] crate::cbor::CborError),
    #[error("repo error: {0}")]
    Repo(#[from] crate::repo::RepoError),
    #[error("identity error: {0}")]
    Identity(#[from] crate::identity::IdentityError),
}

impl From<crate::sync::error::VerifierError> for SyncError {
    fn from(err: crate::sync::error::VerifierError) -> Self {
        Self::Verifier(Box::new(err))
    }
}

/// A fully downloaded repository, including its commit and all CAR blocks.
pub struct DownloadedRepo {
    /// DID of the repository owner.
    pub did: crate::syntax::Did,
    /// The signed commit at the head of the repository.
    pub commit: Commit,
    /// All blocks from the CAR file (MST nodes, records, commit).
    pub blocks: Vec<crate::car::Block>,
}

/// A single record extracted from a downloaded repository.
pub struct Record {
    /// Collection NSID (e.g., "app.bsky.feed.post").
    pub collection: Nsid,
    /// Record key within the collection.
    pub rkey: RecordKey,
    /// Content hash of the record data.
    pub cid: Cid,
    /// Raw DRISL-encoded record bytes.
    pub data: Vec<u8>,
}

/// An entry returned from `listRepos`.
pub struct RepoEntry {
    /// DID of the repository owner.
    pub did: crate::syntax::Did,
    /// CID of the current head commit.
    pub head: Cid,
}
