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
    pub did: crate::syntax::Did,
    pub commit: Commit,
    pub blocks: Vec<crate::car::Block>,
}

/// A single record extracted from a downloaded repository.
pub struct Record {
    pub collection: Nsid,
    pub rkey: RecordKey,
    pub cid: Cid,
    pub data: Vec<u8>,
}

/// An entry returned from `listRepos`.
pub struct RepoEntry {
    pub did: crate::syntax::Did,
    pub head: Cid,
}
