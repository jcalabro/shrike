use std::cell::RefCell;
use std::collections::HashMap;

use shrike_cbor::Cid;

use crate::MstError;

/// Pluggable block storage for MST persistence.
pub trait BlockStore {
    /// Retrieve a block by its CID. Returns an error if not found.
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError>;
    /// Store a block at the given CID.
    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError>;
    /// Check whether a block exists.
    fn has_block(&self, cid: &Cid) -> Result<bool, MstError>;
}

/// Simple in-memory block store for testing.
///
/// Uses interior mutability via `RefCell` so that `put_block` can work through
/// a shared reference (required by the `BlockStore` trait which takes `&self`).
pub struct MemBlockStore {
    blocks: RefCell<HashMap<Cid, Vec<u8>>>,
}

impl MemBlockStore {
    pub fn new() -> Self {
        MemBlockStore {
            blocks: RefCell::new(HashMap::new()),
        }
    }
}

impl Default for MemBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl BlockStore for MemBlockStore {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
        self.blocks
            .borrow()
            .get(cid)
            .cloned()
            .ok_or_else(|| MstError::BlockNotFound(cid.to_string()))
    }

    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
        self.blocks.borrow_mut().insert(cid, data);
        Ok(())
    }

    fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
        Ok(self.blocks.borrow().contains_key(cid))
    }
}
