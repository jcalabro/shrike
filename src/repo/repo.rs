use std::rc::Rc;

use crate::cbor::{Cid, Codec};
use crate::crypto::SigningKey;
use crate::mst::{BlockStore, MemBlockStore, MstError, Tree};
use crate::syntax::{Did, Nsid, RecordKey, TidClock};

use crate::repo::RepoError;
use crate::repo::commit::Commit;

/// Wrapper around `Rc<MemBlockStore>` that implements `BlockStore`.
///
/// This allows the `Tree` and the `Repo` to share the same underlying store
/// (the tree needs `Box<dyn BlockStore>` ownership, but we also need to
/// store record and commit blocks outside the tree).
struct SharedStore(Rc<MemBlockStore>);

impl BlockStore for SharedStore {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
        self.0.get_block(cid)
    }

    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
        self.0.put_block(cid, data)
    }

    fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
        self.0.has_block(cid)
    }
}

/// In-memory AT Protocol repository.
///
/// Records are organized in a Merkle Search Tree and wrapped in signed commits.
pub struct Repo {
    did: Did,
    clock: TidClock,
    store: Rc<MemBlockStore>,
    tree: Tree,
    prev_commit: Option<Cid>,
}

impl Repo {
    /// Create a new empty repository for the given DID.
    pub fn new(did: Did, clock: TidClock) -> Self {
        let store = Rc::new(MemBlockStore::new());
        let tree = Tree::new(Box::new(SharedStore(Rc::clone(&store))));
        Repo {
            did,
            clock,
            store,
            tree,
            prev_commit: None,
        }
    }

    /// Read a record's raw DRISL bytes and CID.
    ///
    /// Returns `Ok(None)` if the record does not exist.
    #[inline]
    pub fn get(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
    ) -> Result<Option<(Cid, Vec<u8>)>, RepoError> {
        let key = mst_key(collection, rkey);
        let cid = match self.tree.get(&key)? {
            Some(c) => c,
            None => return Ok(None),
        };
        let data = self.store.get_block(&cid)?;
        Ok(Some((cid, data)))
    }

    /// Create a new record. Fails if the record key already exists.
    #[inline]
    pub fn create(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        record: &[u8],
    ) -> Result<Cid, RepoError> {
        let key = mst_key(collection, rkey);

        // Check that the key doesn't already exist.
        if self.tree.get(&key)?.is_some() {
            return Err(RepoError::RecordExists(key));
        }

        let cid = Cid::compute(Codec::Drisl, record);
        self.store.put_block(cid, record.to_vec())?;
        self.tree.insert(key, cid)?;
        Ok(cid)
    }

    /// Update an existing record. Fails if the record key does not exist.
    pub fn update(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        record: &[u8],
    ) -> Result<Cid, RepoError> {
        let key = mst_key(collection, rkey);

        // Check that the key exists.
        if self.tree.get(&key)?.is_none() {
            return Err(RepoError::RecordNotFound(key));
        }

        let cid = Cid::compute(Codec::Drisl, record);
        self.store.put_block(cid, record.to_vec())?;
        self.tree.insert(key, cid)?;
        Ok(cid)
    }

    /// Delete a record.
    pub fn delete(&mut self, collection: &Nsid, rkey: &RecordKey) -> Result<(), RepoError> {
        let key = mst_key(collection, rkey);
        self.tree.remove(&key)?;
        Ok(())
    }

    /// Sign and produce a commit for the current repository state.
    pub fn commit(&mut self, key: &dyn SigningKey) -> Result<Commit, RepoError> {
        let root_cid = self.tree.root_cid()?;
        let rev = self.clock.next();

        let mut commit = Commit {
            did: self.did.clone(),
            version: 3,
            rev,
            prev: self.prev_commit,
            data: root_cid,
            sig: None,
        };

        commit.sign(key)?;

        // Store the commit block.
        let commit_data = commit.to_cbor()?;
        let commit_cid = Cid::compute(Codec::Drisl, &commit_data);
        self.store.put_block(commit_cid, commit_data)?;
        self.prev_commit = Some(commit_cid);

        Ok(commit)
    }

    /// List all records in a collection, returned as (record_key, cid) pairs.
    pub fn list(&mut self, collection: &Nsid) -> Result<Vec<(RecordKey, Cid)>, RepoError> {
        let col_str = collection.as_str();
        // Pre-compute prefix length: "{collection}/" — avoids format! + String alloc
        let prefix_len = col_str.len() + 1; // +1 for '/'
        let mut results = Vec::new();

        self.tree.walk(|key, cid| {
            // Fast prefix check: verify length, then collection match, then '/' separator
            if key.len() > prefix_len
                && key.as_bytes()[col_str.len()] == b'/'
                && key.as_bytes()[..col_str.len()] == *col_str.as_bytes()
            {
                let rkey = RecordKey::try_from(&key[prefix_len..])
                    .map_err(|e| MstError::Internal(format!("invalid record key in MST: {e}")))?;
                results.push((rkey, cid));
            }
            Ok(())
        })?;

        Ok(results)
    }
}

/// Build the MST key from collection and record key: `{collection}/{rkey}`.
///
/// Uses direct string concatenation instead of `format!` to avoid the
/// formatting machinery overhead.
#[inline]
fn mst_key(collection: &Nsid, rkey: &RecordKey) -> String {
    let col = collection.as_str();
    let rk = rkey.as_str();
    let mut key = String::with_capacity(col.len() + 1 + rk.len());
    key.push_str(col);
    key.push('/');
    key.push_str(rk);
    key
}
