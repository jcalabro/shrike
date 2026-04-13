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
