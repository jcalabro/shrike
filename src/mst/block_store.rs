use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::BuildHasher;

use crate::cbor::Cid;

use crate::mst::MstError;

/// Pluggable block storage for MST persistence.
pub trait BlockStore {
    /// Retrieve a block by its CID. Returns an error if not found.
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError>;
    /// Store a block at the given CID.
    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError>;
    /// Check whether a block exists.
    fn has_block(&self, cid: &Cid) -> Result<bool, MstError>;
}

/// Synchronous, read-only block lookup for [`DetachedTree`].
///
/// Unlike [`BlockStore::get_block`], an absent block is `Ok(None)` rather
/// than an error, so a tree can report which blocks it still needs.
/// Implementations typically wrap blocks the caller has already fetched.
///
/// [`DetachedTree`]: crate::mst::DetachedTree
pub trait BlockSource {
    /// Return the block with the given CID, or `None` if it is not
    /// available.
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError>;
}

impl<S: BuildHasher> BlockSource for HashMap<Cid, Vec<u8>, S> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        Ok(self.get(cid).map(|data| Cow::Borrowed(data.as_slice())))
    }
}

impl BlockSource for MemBlockStore {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        Ok(self.blocks.borrow().get(cid).cloned().map(Cow::Owned))
    }
}

/// A [`BlockSource`] with no blocks, for operations on a tree whose needed
/// nodes are already loaded.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoBlocks;

impl BlockSource for NoBlocks {
    fn read_block(&self, _cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        Ok(None)
    }
}

/// Simple in-memory block store backed by a `HashMap`.
///
/// Uses interior mutability via `RefCell` so that `put_block` can work through
/// a shared reference (required by the `BlockStore` trait which takes `&self`).
/// Suitable for testing and short-lived repositories.
pub struct MemBlockStore {
    blocks: RefCell<HashMap<Cid, Vec<u8>>>,
}

impl MemBlockStore {
    /// Create an empty in-memory block store.
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
