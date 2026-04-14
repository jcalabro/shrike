//! Merkle Search Tree implementation for AT Protocol repositories.
//!
//! An MST is a hybrid structure combining a Merkle tree and a search tree,
//! providing both cryptographic integrity and efficient key-based lookups.
//! AT Protocol uses MSTs to store repository records with deterministic
//! ordering and content addressing.
//!
//! The Tree type provides insert, get, remove, and list operations. All
//! mutations produce a new root CID. The diff function compares two trees
//! and returns added, updated, and removed entries.
//!
//! BlockStore manages the content-addressed blocks that make up the tree.
//! Use MemBlockStore for in-memory trees or implement BlockStore for
//! persistent storage.

pub mod block_store;
pub mod diff;
pub mod height;
pub mod node;
pub mod tree;

pub use block_store::{BlockStore, MemBlockStore};
pub use diff::{Diff, diff};
pub use height::height_for_key;
pub use tree::Tree;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum MstError {
    #[error("block not found: {0}")]
    BlockNotFound(String),
    #[error("invalid node: {0}")]
    InvalidNode(String),
    #[error("CBOR error: {0}")]
    Cbor(String),
    #[error("internal error: {0}")]
    Internal(String),
}
