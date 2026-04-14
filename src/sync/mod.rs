//! AT Protocol repository sync and commit verification.
//!
//! This crate provides a [`client::SyncClient`] for downloading full repositories
//! via `com.atproto.sync.getRepo` and a [`verify`] module for verifying block CIDs.

pub mod client;
pub mod verify;

pub use client::SyncClient;
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
