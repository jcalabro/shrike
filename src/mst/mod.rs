//! Merkle Search Tree implementation for AT Protocol repositories.
//!
//! An MST is a hybrid structure combining a Merkle tree and a search tree,
//! providing both cryptographic integrity and efficient key-based lookups.
//! AT Protocol uses MSTs to store repository records with deterministic
//! ordering and content addressing.
//!
//! DetachedTree is the sans-IO core: it provides insert, get, remove, and
//! walk operations, reads nodes it has not decoded yet from a BlockSource
//! the caller supplies, and hands back new and retired node blocks from
//! `flush` instead of writing them. Its `missing_blocks` method lets callers
//! with asynchronous storage prefetch every node an operation needs.
//!
//! Tree wraps a DetachedTree around a synchronous BlockStore, loading nodes
//! from it on demand and writing new nodes back when the root CID is
//! computed. Use MemBlockStore for in-memory trees or implement BlockStore
//! for persistent storage.
//!
//! The diff function compares two trees and returns added, updated, and
//! removed entries.

pub mod block_store;
pub mod diff;
pub mod height;
pub mod node;
pub mod tree;

pub use block_store::{BlockSource, BlockStore, MemBlockStore, NoBlocks};
pub use diff::{Diff, diff};
pub use height::height_for_key;
pub use tree::{DetachedTree, Tree, TreeWrite};

use thiserror::Error;

/// Errors produced by MST operations.
#[derive(Debug, Error)]
pub enum MstError {
    /// A required block was not found in the block store.
    #[error("block not found: {0}")]
    BlockNotFound(String),
    /// A node's structure or data is malformed.
    #[error("invalid node: {0}")]
    InvalidNode(String),
    /// Failed to encode or decode CBOR data for a node.
    #[error("CBOR error: {0}")]
    Cbor(String),
    /// An unexpected internal error.
    #[error("internal error: {0}")]
    Internal(String),
}
