use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::car::{Block, SliceReader};
use crate::cbor::cid::{CidMap, FastHashState};
use crate::cbor::{Cid, Codec};
use crate::crypto::SigningKey;
use crate::mst::{BlockSource, DetachedTree, MstError};
use crate::syntax::{Did, Nsid, RecordKey, TidClock};

use crate::repo::RepoError;
use crate::repo::commit::Commit;
use crate::repo::proof::{ProofError, proof_car};
use crate::repo::store::{CommitData, MemRepoStore, RecordAction, RecordOp, RepoStore, WriteOp};

/// An AT Protocol repository.
///
/// Records are organized in a Merkle Search Tree and wrapped in signed
/// commits. Writes are staged in memory; [`commit`](Self::commit) signs
/// them and persists them to the [`RepoStore`] in one
/// [`apply_commit`](RepoStore::apply_commit) call. Reads see staged writes;
/// proofs and exports reflect the last commit.
pub struct Repo<S: RepoStore = MemRepoStore> {
    did: Did,
    clock: TidClock,
    store: S,
    tree: DetachedTree,
    /// Record blocks written since the last commit.
    records: HashMap<Cid, Vec<u8>>,
    /// Records changed since the last commit, by MST key.
    staged: BTreeMap<String, Staged>,
    /// MST changes flushed from the tree but not yet accepted by the store.
    unsaved: Unsaved,
    head: Option<Head>,
}

// A repository can move between threads and be held across `.await` points.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Repo>();
};

struct Staged {
    collection: Nsid,
    rkey: RecordKey,
    /// The record's CID at the last commit.
    prev: Option<Cid>,
    /// The record's CID now.
    cid: Option<Cid>,
}

#[derive(Default)]
struct Unsaved {
    nodes: BTreeMap<Cid, Vec<u8>>,
    retired: BTreeSet<Cid>,
}

struct Head {
    cid: Cid,
    commit: Commit,
}

impl Repo<MemRepoStore> {
    /// Create a new, empty, in-memory repository for the given DID.
    pub fn new(did: Did, clock: TidClock) -> Self {
        Self::empty(MemRepoStore::new(), did, clock)
    }

    /// Load a repository from a CAR file into memory. See
    /// [`import_car`](Self::import_car).
    pub fn load_car(car: &[u8]) -> Result<Self, RepoError> {
        Self::import_car(MemRepoStore::new(), car)
    }
}

impl<S: RepoStore> Repo<S> {
    /// Create a new, empty repository for `did` in `store`, which must not
    /// hold a repository already.
    pub fn init(store: S, did: Did, clock: TidClock) -> Result<Self, RepoError> {
        if store.head().map_err(storage)?.is_some() {
            return Err(RepoError::StoreNotEmpty);
        }
        Ok(Self::empty(store, did, clock))
    }

    /// Open the repository at `store`'s head commit.
    pub fn open(store: S) -> Result<Self, RepoError> {
        let cid = store.head().map_err(storage)?.ok_or(RepoError::NoCommit)?;
        let bytes = store
            .get_block(&cid)
            .map_err(storage)?
            .ok_or(RepoError::MissingBlock(cid))?;
        let commit = Commit::from_cbor(&bytes)?;
        let clock =
            TidClock::new(commit.rev.clock_id()).map_err(|e| RepoError::Commit(e.to_string()))?;
        clock.observe(commit.rev);
        Ok(Repo {
            did: commit.did.clone(),
            clock,
            store,
            tree: DetachedTree::load(commit.data),
            records: HashMap::new(),
            staged: BTreeMap::new(),
            unsaved: Unsaved::default(),
            head: Some(Head { cid, commit }),
        })
    }

    /// Load a repository from a CAR file, such as `com.atproto.sync.getRepo`
    /// returns, into `store`, which must not hold a repository already.
    ///
    /// Every block is checked against its CID and the repository must be
    /// complete: every MST node and record its commit references must be in
    /// the CAR. Only those blocks are stored. The commit signature is not
    /// checked; verify [`head`](Self::head) against the account's key.
    pub fn import_car(mut store: S, car: &[u8]) -> Result<Self, RepoError> {
        if store.head().map_err(storage)?.is_some() {
            return Err(RepoError::StoreNotEmpty);
        }
        let reader = SliceReader::new(car)?;
        let root = match reader.roots() {
            [root] => *root,
            roots => return Err(RepoError::RootCount(roots.len())),
        };
        // Blocks stay in `car` until the reachable ones are copied out.
        let mut blocks = CidMap::default();
        for block in reader {
            let block = block?;
            if Cid::compute(block.cid.codec(), block.data) != block.cid {
                return Err(RepoError::CidMismatch(block.cid));
            }
            blocks.entry(block.cid).or_insert(block.data);
        }

        if root.codec() != Codec::Drisl {
            return Err(RepoError::Commit(format!("commit {root} is not DRISL")));
        }
        let commit_bytes = blocks
            .remove(&root)
            .ok_or(RepoError::MissingBlock(root))?
            .to_vec();
        let commit = Commit::from_cbor(&commit_bytes)?;
        let mut new_blocks: BTreeMap<Cid, Vec<u8>> = reachable_blocks(&blocks, commit.data)?
            .into_iter()
            .collect();
        drop(blocks);
        new_blocks.insert(root, commit_bytes);

        store
            .apply_commit(&CommitData {
                cid: root,
                commit,
                since: None,
                prev: None,
                prev_data: None,
                new_blocks,
                relevant_blocks: BTreeMap::new(),
                removed_cids: Vec::new(),
                ops: Vec::new(),
            })
            .map_err(storage)?;
        Self::open(store)
    }

    fn empty(store: S, did: Did, clock: TidClock) -> Self {
        Repo {
            did,
            clock,
            store,
            tree: DetachedTree::new(),
            records: HashMap::new(),
            staged: BTreeMap::new(),
            unsaved: Unsaved::default(),
            head: None,
        }
    }

    /// The repository's DID.
    pub fn did(&self) -> &Did {
        &self.did
    }

    /// The last commit, or `None` if nothing has been committed.
    pub fn head(&self) -> Option<&Commit> {
        self.head.as_ref().map(|h| &h.commit)
    }

    /// CID of the last commit block.
    pub fn head_cid(&self) -> Option<Cid> {
        self.head.as_ref().map(|h| h.cid)
    }

    /// The backing store.
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Consume the repository, returning its store. Staged writes are lost.
    pub fn into_store(self) -> S {
        self.store
    }

    /// Whether there are writes since the last commit.
    pub fn has_staged_writes(&self) -> bool {
        !self.staged.is_empty()
    }

    /// Read a record's raw DRISL bytes and CID.
    ///
    /// Returns `Ok(None)` if the record does not exist.
    pub fn get(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
    ) -> Result<Option<(Cid, Vec<u8>)>, RepoError> {
        let key = mst_key(collection, rkey);
        let Some(cid) = self.tree.get(&StoreSource(&self.store), &key)? else {
            return Ok(None);
        };
        let data = match self.records.get(&cid) {
            Some(data) => data.clone(),
            None => self
                .store
                .get_block(&cid)
                .map_err(storage)?
                .ok_or(RepoError::MissingBlock(cid))?,
        };
        Ok(Some((cid, data)))
    }

    /// Create a new record. Fails if the record key already exists.
    pub fn create(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        record: &[u8],
    ) -> Result<Cid, RepoError> {
        let key = mst_key(collection, rkey);
        if self.tree.get(&StoreSource(&self.store), &key)?.is_some() {
            return Err(RepoError::RecordExists(key));
        }
        self.put(collection, rkey, key, record)
    }

    /// Update an existing record. Fails if the record key does not exist.
    pub fn update(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        record: &[u8],
    ) -> Result<Cid, RepoError> {
        let key = mst_key(collection, rkey);
        if self.tree.get(&StoreSource(&self.store), &key)?.is_none() {
            return Err(RepoError::RecordNotFound(key));
        }
        self.put(collection, rkey, key, record)
    }

    /// Delete a record. Fails if the record key does not exist.
    pub fn delete(&mut self, collection: &Nsid, rkey: &RecordKey) -> Result<(), RepoError> {
        let key = mst_key(collection, rkey);
        let src = StoreSource(&self.store);
        match self.tree.remove(&src, &key)? {
            None => Err(RepoError::RecordNotFound(key)),
            Some(prev) => {
                self.stage(collection, rkey, key, Some(prev), None);
                Ok(())
            }
        }
    }

    fn put(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        key: String,
        record: &[u8],
    ) -> Result<Cid, RepoError> {
        let cid = Cid::compute(Codec::Drisl, record);
        let src = StoreSource(&self.store);
        let prev = self.tree.insert(&src, key.clone(), cid)?;
        self.records.insert(cid, record.to_vec());
        self.stage(collection, rkey, key, prev, Some(cid));
        Ok(cid)
    }

    /// Record a key's new value, and its value at the last commit the first
    /// time it changes.
    fn stage(
        &mut self,
        collection: &Nsid,
        rkey: &RecordKey,
        key: String,
        prev: Option<Cid>,
        cid: Option<Cid>,
    ) {
        self.staged
            .entry(key)
            .or_insert_with(|| Staged {
                collection: collection.clone(),
                rkey: rkey.clone(),
                prev,
                cid,
            })
            .cid = cid;
    }

    /// Apply a batch of writes and commit them, together with any writes
    /// already staged.
    ///
    /// The batch is checked in order before anything changes: if any write
    /// is invalid (creating a record that exists, or updating or deleting
    /// one that does not, counting earlier writes in the batch), none are
    /// applied.
    pub fn apply_writes(
        &mut self,
        writes: &[WriteOp],
        key: &dyn SigningKey,
    ) -> Result<CommitData, RepoError> {
        let keys: Vec<String> = writes
            .iter()
            .map(|w| {
                let (c, r) = w.path();
                mst_key(c, r)
            })
            .collect();

        // Load every node the batch touches, so applying it reads nothing.
        let (deleted, written): (Vec<_>, Vec<_>) = writes
            .iter()
            .zip(&keys)
            .partition(|(w, _)| matches!(w, WriteOp::Delete { .. }));
        let src = StoreSource(&self.store);
        let mut missing = self
            .tree
            .missing_blocks(&src, written.iter().map(|(_, k)| k.as_str()))?;
        missing.extend(
            self.tree
                .missing_blocks_for_remove(&src, deleted.iter().map(|(_, k)| k.as_str()))?,
        );
        if let Some(cid) = missing.first() {
            return Err(RepoError::MissingBlock(*cid));
        }

        let mut exists: HashMap<&str, bool> = HashMap::new();
        for (write, key) in writes.iter().zip(&keys) {
            let present = match exists.get(key.as_str()) {
                Some(&present) => present,
                None => self.tree.get(&StoreSource(&self.store), key)?.is_some(),
            };
            let after = match write {
                WriteOp::Create { .. } if present => {
                    return Err(RepoError::RecordExists(key.clone()));
                }
                WriteOp::Update { .. } | WriteOp::Delete { .. } if !present => {
                    return Err(RepoError::RecordNotFound(key.clone()));
                }
                WriteOp::Create { .. } | WriteOp::Update { .. } => true,
                WriteOp::Delete { .. } => false,
            };
            exists.insert(key, after);
        }

        for write in writes {
            match write {
                WriteOp::Create {
                    collection,
                    rkey,
                    record,
                }
                | WriteOp::Update {
                    collection,
                    rkey,
                    record,
                } => {
                    self.put(collection, rkey, mst_key(collection, rkey), record)?;
                }
                WriteOp::Delete { collection, rkey } => self.delete(collection, rkey)?,
            }
        }
        self.commit(key)
    }

    /// Sign the staged writes into a new commit and persist it.
    ///
    /// A commit with no staged writes re-signs the current tree under a new
    /// revision. If signing or the store fails, the writes stay staged and
    /// a later commit includes them.
    pub fn commit(&mut self, key: &dyn SigningKey) -> Result<CommitData, RepoError> {
        let write = self.tree.flush()?;
        for (cid, data) in write.new_blocks {
            if !self.unsaved.retired.remove(&cid) {
                self.unsaved.nodes.insert(cid, data);
            }
        }
        for cid in write.retired {
            if self.unsaved.nodes.remove(&cid).is_none() {
                self.unsaved.retired.insert(cid);
            }
        }

        let mut ops = Vec::new();
        let mut leaves = BTreeMap::new();
        let src = Overlay {
            blocks: &self.unsaved.nodes,
            store: &self.store,
        };
        let proof_nodes = self
            .tree
            .covering_proof(&src, self.staged.keys().map(String::as_str))?;
        for staged in self.staged.values() {
            let cid = staged.cid;
            let action = match (staged.prev, cid) {
                (prev, cid) if prev == cid => continue,
                (None, _) => RecordAction::Create,
                (_, None) => RecordAction::Delete,
                (Some(_), Some(_)) => RecordAction::Update,
            };
            if let Some(cid) = cid {
                let data = self.records.get(&cid).ok_or_else(|| {
                    RepoError::Commit(format!("staged record block {cid} is missing"))
                })?;
                leaves.insert(cid, data.clone());
            }
            ops.push(RecordOp {
                action,
                collection: staged.collection.clone(),
                rkey: staged.rkey.clone(),
                cid,
                prev: staged.prev,
            });
        }

        let mut relevant_blocks = leaves.clone();
        for cid in proof_nodes {
            let data = src
                .read_block(&cid)?
                .ok_or(RepoError::MissingBlock(cid))?
                .into_owned();
            relevant_blocks.insert(cid, data);
        }

        let since = self.head.as_ref().map(|h| h.commit.rev);
        if let Some(since) = since {
            self.clock.observe(since);
        }
        let rev = self.clock.next();
        if let Some(since) = since.filter(|since| rev <= *since) {
            return Err(RepoError::Commit(format!(
                "clock cannot produce a revision after {since}"
            )));
        }
        let signed = Commit::create_signed(self.did.clone(), rev, write.root, key)?;

        let mut new_blocks = self.unsaved.nodes.clone();
        new_blocks.extend(leaves);
        new_blocks.insert(signed.cid, signed.bytes.clone());
        relevant_blocks.insert(signed.cid, signed.bytes);
        let mut removed_cids: Vec<Cid> = self.unsaved.retired.iter().copied().collect();
        if let Some(head) = &self.head {
            removed_cids.push(head.cid);
        }

        let data = CommitData {
            cid: signed.cid,
            commit: signed.commit,
            since,
            prev: self.head.as_ref().map(|h| h.cid),
            prev_data: self.head.as_ref().map(|h| h.commit.data),
            new_blocks,
            relevant_blocks,
            removed_cids,
            ops,
        };
        self.store.apply_commit(&data).map_err(storage)?;

        self.records.clear();
        self.staged.clear();
        self.unsaved = Unsaved::default();
        self.head = Some(Head {
            cid: data.cid,
            commit: data.commit.clone(),
        });
        Ok(data)
    }

    /// Build a record proof CAR for `collection/rkey` at the last commit,
    /// as `com.atproto.sync.getRecord` serves it. See
    /// [`crate::repo::proof`].
    pub fn record_proof(&self, collection: &Nsid, rkey: &RecordKey) -> Result<Vec<u8>, ProofError> {
        self.records_proof(&[(collection.clone(), rkey.clone())])
    }

    /// Build one proof CAR for several records at the last commit. See
    /// [`record_proofs_car`](crate::repo::record_proofs_car).
    pub fn records_proof(&self, paths: &[(Nsid, RecordKey)]) -> Result<Vec<u8>, ProofError> {
        let head = self.head.as_ref().ok_or(ProofError::NoCommit)?;
        let src = StoreSource(&self.store);
        let commit = src
            .read_block(&head.cid)?
            .ok_or(ProofError::MissingBlock(head.cid))?;
        // Until there are writes since the commit, the tree in memory is
        // the commit's, and the nodes it has loaded need no decoding.
        let fresh;
        let tree = if self.tree.root_cid() == Some(head.commit.data) {
            &self.tree
        } else {
            fresh = DetachedTree::load(head.commit.data);
            &fresh
        };
        proof_car(&src, tree, &head.cid, &commit, paths)
    }

    /// Export the last commit as a full-repository CAR file, as
    /// `com.atproto.sync.getRepo` serves it.
    ///
    /// The commit block comes first, then the tree in key order: each MST
    /// node before its contents and each record right after its entry.
    pub fn export_car(&self) -> Result<Vec<u8>, RepoError> {
        let head = self.head.as_ref().ok_or(RepoError::NoCommit)?;
        let src = StoreSource(&self.store);
        let commit = src
            .read_block(&head.cid)?
            .ok_or(RepoError::MissingBlock(head.cid))?
            .into_owned();
        let mut blocks = vec![Block {
            cid: head.cid,
            data: commit,
        }];
        blocks.extend(
            reachable_blocks(&src, head.commit.data)?
                .into_iter()
                .map(|(cid, data)| Block { cid, data }),
        );
        Ok(crate::car::write_all(&[head.cid], &blocks)?)
    }

    /// List all records in a collection, returned as (record_key, cid) pairs.
    pub fn list(&mut self, collection: &Nsid) -> Result<Vec<(RecordKey, Cid)>, RepoError> {
        let col_str = collection.as_str();
        // Pre-compute prefix length: "{collection}/" — avoids format! + String alloc
        let prefix_len = col_str.len() + 1; // +1 for '/'
        let mut results = Vec::new();

        let src = StoreSource(&self.store);
        self.tree.walk(&src, |key, cid| {
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

/// Every block reachable from the MST at `root`, in key order, failing if
/// any is missing: each node before its contents, each record right after
/// its entry, each block once.
fn reachable_blocks(src: &dyn BlockSource, root: Cid) -> Result<Vec<(Cid, Vec<u8>)>, RepoError> {
    let recorder = Recorder::new(src);
    let mut leaves: HashSet<Cid, FastHashState> = HashSet::default();
    let mut leaf_err = None;
    DetachedTree::load(root)
        .walk(&recorder, |_, cid| {
            if !leaves.insert(cid) {
                return Ok(());
            }
            match src.read_block(&cid)? {
                Some(data) => recorder.seen.borrow_mut().push((cid, data.into_owned())),
                None => {
                    leaf_err = Some(RepoError::MissingBlock(cid));
                    return Err(MstError::BlockNotFound(cid.to_string()));
                }
            }
            Ok(())
        })
        .map_err(|e| leaf_err.take().unwrap_or_else(|| e.into()))?;
    Ok(recorder.seen.into_inner())
}

/// Build the MST key from collection and record key: `{collection}/{rkey}`.
///
/// Uses direct string concatenation instead of `format!` to avoid the
/// formatting machinery overhead.
#[inline]
pub(crate) fn mst_key(collection: &Nsid, rkey: &RecordKey) -> String {
    let col = collection.as_str();
    let rk = rkey.as_str();
    let mut key = String::with_capacity(col.len() + 1 + rk.len());
    key.push_str(col);
    key.push('/');
    key.push_str(rk);
    key
}

fn storage(e: impl std::error::Error + Send + Sync + 'static) -> RepoError {
    RepoError::Storage(Box::new(e))
}

/// Reads a [`RepoStore`] as a [`BlockSource`].
struct StoreSource<'a, S: ?Sized>(&'a S);

impl<S: RepoStore + ?Sized> BlockSource for StoreSource<'_, S> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        self.0
            .borrow_block(cid)
            .map_err(|e| MstError::Storage(Box::new(e)))
    }
}

/// Unsaved MST nodes layered over a store.
struct Overlay<'a, S> {
    blocks: &'a BTreeMap<Cid, Vec<u8>>,
    store: &'a S,
}

impl<S: RepoStore> BlockSource for Overlay<'_, S> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        match self.blocks.get(cid) {
            Some(data) => Ok(Some(Cow::Borrowed(data))),
            None => self
                .store
                .borrow_block(cid)
                .map_err(|e| MstError::Storage(Box::new(e))),
        }
    }
}

/// A [`BlockSource`] that remembers every block it hands out, in order.
pub(crate) struct Recorder<'a> {
    src: &'a dyn BlockSource,
    pub(crate) seen: RefCell<Vec<(Cid, Vec<u8>)>>,
}

impl<'a> Recorder<'a> {
    pub(crate) fn new(src: &'a dyn BlockSource) -> Self {
        Recorder {
            src,
            seen: RefCell::new(Vec::new()),
        }
    }
}

impl BlockSource for Recorder<'_> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        let Some(data) = self.src.read_block(cid)? else {
            return Ok(None);
        };
        self.seen.borrow_mut().push((*cid, data.to_vec()));
        Ok(Some(data))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::car::read_all;
    use crate::crypto::P256SigningKey;
    use crate::repo::proof::record_proofs_car;

    fn did() -> Did {
        Did::try_from("did:plc:storestorestorestorestor").unwrap()
    }

    fn col() -> Nsid {
        Nsid::try_from("com.example.record").unwrap()
    }

    fn rk(i: usize) -> RecordKey {
        RecordKey::try_from(format!("r{i:04}").as_str()).unwrap()
    }

    /// DRISL `{"n": i}`.
    fn record(i: u16) -> Vec<u8> {
        let mut v = b"\xa1\x61n\x19".to_vec();
        v.extend_from_slice(&i.to_be_bytes());
        v
    }

    fn create(i: usize, v: u16) -> WriteOp {
        WriteOp::Create {
            collection: col(),
            rkey: rk(i),
            record: record(v),
        }
    }

    fn contents<S: RepoStore>(repo: &mut Repo<S>) -> Vec<(RecordKey, Vec<u8>)> {
        repo.list(&col())
            .unwrap()
            .into_iter()
            .map(|(k, _)| {
                let data = repo.get(&col(), &k).unwrap().unwrap().1;
                (k, data)
            })
            .collect()
    }

    fn export_cids<S: RepoStore>(repo: &Repo<S>) -> BTreeSet<Cid> {
        read_all(&repo.export_car().unwrap()[..])
            .unwrap()
            .1
            .into_iter()
            .map(|b| b.cid)
            .collect()
    }

    #[test]
    fn reopens_from_store() {
        let key = P256SigningKey::generate();
        let mut store = MemRepoStore::new();
        let mut repo = Repo::init(&mut store, did(), TidClock::new(3).unwrap()).unwrap();
        repo.apply_writes(
            &(0..50).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        let first = repo.head().unwrap().clone();
        let want = contents(&mut repo);
        drop(repo);

        let mut repo = Repo::open(&mut store).unwrap();
        assert_eq!(repo.did(), &did());
        assert_eq!(repo.head().unwrap().rev, first.rev);
        assert_eq!(contents(&mut repo), want);

        // Later revisions sort after the stored one, even with a clock that
        // starts behind it.
        let c = repo.commit(&key).unwrap();
        assert!(c.rev() > first.rev);
        assert_eq!(c.since, Some(first.rev));
        assert!(c.ops.is_empty());
        assert_eq!(c.commit.data, first.data);
    }

    #[test]
    fn store_must_match_constructor() {
        let key = P256SigningKey::generate();
        assert!(matches!(
            Repo::open(MemRepoStore::new()),
            Err(RepoError::NoCommit)
        ));
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.commit(&key).unwrap();
        let car = repo.export_car().unwrap();
        let store = repo.into_store();
        assert!(matches!(
            Repo::init(store.clone(), did(), TidClock::new(0).unwrap()),
            Err(RepoError::StoreNotEmpty)
        ));
        assert!(matches!(
            Repo::import_car(store, &car),
            Err(RepoError::StoreNotEmpty)
        ));
    }

    #[test]
    fn store_holds_only_live_blocks_and_retired_records() {
        // Replaced MST nodes and commits are deleted; record blocks are
        // never deleted, so the store holds exactly the live tree plus the
        // records that were replaced or deleted.
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.apply_writes(
            &(0..100).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        assert_eq!(repo.store().len(), export_cids(&repo).len());

        let mut writes = Vec::new();
        for i in 0..30 {
            writes.push(WriteOp::Delete {
                collection: col(),
                rkey: rk(i),
            });
        }
        for i in 30..50 {
            writes.push(WriteOp::Update {
                collection: col(),
                rkey: rk(i),
                record: record(1000 + i as u16),
            });
        }
        let c = repo.apply_writes(&writes, &key).unwrap();
        assert_eq!(c.ops.len(), 50);
        assert_eq!(repo.store().len(), export_cids(&repo).len() + 50);
    }

    #[test]
    fn shared_record_block_survives_deleting_one_copy() {
        // Regression test: the reference implementation lists a deleted
        // record's block as removed even when another key still uses it.
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.apply_writes(&[create(1, 7), create(2, 7)], &key)
            .unwrap();
        let c = repo
            .apply_writes(
                &[WriteOp::Delete {
                    collection: col(),
                    rkey: rk(1),
                }],
                &key,
            )
            .unwrap();
        let shared = Cid::compute(Codec::Drisl, &record(7));
        assert!(!c.removed_cids.contains(&shared));
        assert_eq!(repo.get(&col(), &rk(2)).unwrap().unwrap().1, record(7));
        Repo::load_car(&repo.export_car().unwrap()).unwrap();
    }

    #[test]
    fn invalid_batch_changes_nothing() {
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.apply_writes(&[create(1, 1), create(2, 2)], &key)
            .unwrap();
        repo.create(&col(), &rk(3), &record(3)).unwrap();
        let head = repo.head_cid();
        let before = contents(&mut repo);

        let bad: [&[WriteOp]; 4] = [
            &[create(4, 4), create(1, 9)],
            &[
                WriteOp::Delete {
                    collection: col(),
                    rkey: rk(2),
                },
                WriteOp::Update {
                    collection: col(),
                    rkey: rk(2),
                    record: record(9),
                },
            ],
            &[WriteOp::Delete {
                collection: col(),
                rkey: rk(9),
            }],
            &[create(5, 5), create(5, 6)],
        ];
        for writes in bad {
            assert!(repo.apply_writes(writes, &key).is_err());
            assert_eq!(repo.head_cid(), head);
            assert_eq!(contents(&mut repo), before);
        }

        // Sequences that are only valid in order are accepted.
        let c = repo
            .apply_writes(
                &[
                    WriteOp::Delete {
                        collection: col(),
                        rkey: rk(1),
                    },
                    create(1, 11),
                    create(6, 6),
                    WriteOp::Update {
                        collection: col(),
                        rkey: rk(6),
                        record: record(66),
                    },
                ],
                &key,
            )
            .unwrap();
        // The staged create of r0003 is committed with the batch.
        let ops: Vec<(String, RecordAction)> = c.ops.iter().map(|o| (o.path(), o.action)).collect();
        assert_eq!(
            ops,
            [
                ("com.example.record/r0001".into(), RecordAction::Update),
                ("com.example.record/r0003".into(), RecordAction::Create),
                ("com.example.record/r0006".into(), RecordAction::Create),
            ]
        );
        assert_eq!(repo.get(&col(), &rk(6)).unwrap().unwrap().1, record(66));
    }

    /// A store whose next `apply_commit` fails when armed.
    #[derive(Default)]
    struct Flaky {
        inner: MemRepoStore,
        fail_next: bool,
        fail_reads: bool,
    }

    #[derive(Debug, thiserror::Error)]
    #[error("flaky store")]
    struct FlakyError;

    impl RepoStore for Flaky {
        type Error = FlakyError;
        fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, FlakyError> {
            if self.fail_reads {
                return Err(FlakyError);
            }
            Ok(self.inner.get_block(cid).unwrap_or_default())
        }
        fn head(&self) -> Result<Option<Cid>, FlakyError> {
            Ok(self.inner.head().unwrap_or_default())
        }
        fn apply_commit(&mut self, commit: &CommitData) -> Result<(), FlakyError> {
            if std::mem::take(&mut self.fail_next) {
                return Err(FlakyError);
            }
            let _ = self.inner.apply_commit(commit);
            Ok(())
        }
    }

    #[test]
    fn failed_commit_keeps_writes_staged() {
        let key = P256SigningKey::generate();
        let mut store = Flaky::default();
        let mut repo = Repo::init(&mut store, did(), TidClock::new(0).unwrap()).unwrap();
        repo.apply_writes(
            &(0..60).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        let head = repo.head_cid();

        // Fail a commit, then change the same part of the tree again before
        // retrying: nodes new in the failed attempt are already obsolete.
        for i in 60..80 {
            repo.create(&col(), &rk(i), &record(i as u16)).unwrap();
        }
        repo.store.fail_next = true;
        assert!(matches!(repo.commit(&key), Err(RepoError::Storage(_))));
        assert_eq!(repo.head_cid(), head);
        assert!(repo.has_staged_writes());
        for i in (0..10).chain(70..80) {
            repo.delete(&col(), &rk(i)).unwrap();
        }
        for i in 80..90 {
            repo.create(&col(), &rk(i), &record(i as u16)).unwrap();
        }
        let c = repo.commit(&key).unwrap();
        assert_eq!(c.prev, head);
        let want = contents(&mut repo);
        drop(repo);

        // The store holds a complete tree and no stale MST nodes.
        let mut repo = Repo::open(&mut store).unwrap();
        assert_eq!(contents(&mut repo), want);
        let live = export_cids(&repo);
        let records: BTreeSet<Cid> = (0..90)
            .map(|i| Cid::compute(Codec::Drisl, &record(i)))
            .collect();
        for (cid, _) in store.inner.iter() {
            assert!(
                live.contains(cid) || records.contains(cid),
                "stale block {cid}"
            );
        }
    }

    #[test]
    fn storage_read_errors_surface() {
        let key = P256SigningKey::generate();
        let mut store = Flaky::default();
        let mut repo = Repo::init(&mut store, did(), TidClock::new(0).unwrap()).unwrap();
        repo.apply_writes(
            &(0..20).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        drop(repo);
        let mut repo = Repo::open(&mut store).unwrap();
        repo.store.fail_reads = true;
        assert!(matches!(
            repo.get(&col(), &rk(1)),
            Err(RepoError::Storage(_))
        ));
        assert!(matches!(
            repo.create(&col(), &rk(99), &record(1)),
            Err(RepoError::Storage(_))
        ));
        assert!(matches!(
            repo.apply_writes(&[create(98, 1)], &key),
            Err(RepoError::Storage(_))
        ));
        assert!(matches!(repo.export_car(), Err(RepoError::Storage(_))));
        repo.store.fail_reads = false;
        assert!(!repo.has_staged_writes());
        assert_eq!(contents(&mut repo).len(), 20);
    }

    fn rewrite(car: &[u8], edit: impl FnOnce(&mut Vec<Cid>, &mut Vec<Block>)) -> Vec<u8> {
        let (mut roots, mut blocks) = read_all(car).unwrap();
        edit(&mut roots, &mut blocks);
        crate::car::write_all(&roots, &blocks).unwrap()
    }

    /// Regression test: a CAR whose MST links blocks from several places,
    /// or nests far deeper than any MST, made `load_car` take exponential
    /// time or overflow the stack. Both now fail promptly.
    #[test]
    fn load_car_rejects_hostile_trees() {
        use crate::mst::node::{EntryData, NodeData, encode_node_data};
        let value = Cid::compute(Codec::Drisl, b"\xa0");
        let mut blocks = vec![Block {
            cid: value,
            data: b"\xa0".to_vec(),
        }];
        let mut put = |left: Option<Cid>, key: Option<String>, right: Option<Cid>| {
            let entries = key
                .map(|k| EntryData {
                    prefix_len: 0,
                    key_suffix: k.into_bytes(),
                    value,
                    right,
                })
                .into_iter()
                .collect();
            let data = encode_node_data(&NodeData { left, entries }).unwrap();
            let cid = Cid::compute(Codec::Drisl, &data);
            blocks.push(Block { cid, data });
            cid
        };
        // Each level's two nodes both link both nodes of the level below.
        let mut level = [0, 1].map(|j| put(None, Some(format!("com.example.lvl0/{j}")), None));
        for i in 1..40 {
            let [a, b] = level;
            level = [(a, b, 0), (b, a, 1)]
                .map(|(l, r, j)| put(Some(l), Some(format!("com.example.lvl{i}/{j}")), Some(r)));
        }
        let diamond = level[0];
        let mut chain = put(None, Some("com.example.record/a".into()), None);
        for _ in 0..100_000 {
            chain = put(Some(chain), None, None);
        }

        let key = P256SigningKey::generate();
        for data in [diamond, chain] {
            let commit =
                Commit::create_signed(did(), TidClock::new(0).unwrap().next(), data, &key).unwrap();
            let mut car_blocks = vec![Block {
                cid: commit.cid,
                data: commit.bytes,
            }];
            car_blocks.extend(blocks.iter().cloned());
            let car = crate::car::write_all(&[commit.cid], &car_blocks).unwrap();
            assert!(matches!(
                Repo::load_car(&car),
                Err(RepoError::Mst(MstError::InvalidNode(_)))
            ));
        }
    }

    #[test]
    fn load_car_checks_the_car() {
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.apply_writes(
            &(0..40).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        let car = repo.export_car().unwrap();
        let n = read_all(&car[..]).unwrap().1.len();

        // Unreferenced and duplicate blocks are dropped.
        let padded = rewrite(&car, |_, blocks| {
            blocks.push(blocks[3].clone());
            let junk = b"junk".to_vec();
            blocks.push(Block {
                cid: Cid::compute(Codec::Raw, &junk),
                data: junk,
            });
        });
        let mut loaded = Repo::load_car(&padded).unwrap();
        assert_eq!(loaded.store().len(), n);
        assert_eq!(contents(&mut loaded), contents(&mut repo));
        assert_eq!(loaded.export_car().unwrap(), car);

        // Every missing block is caught up front.
        for i in 0..n {
            let bad = rewrite(&car, |_, blocks| {
                blocks.remove(i);
            });
            assert!(Repo::load_car(&bad).is_err(), "block {i} removed");
        }
        let tampered = rewrite(&car, |_, blocks| {
            let last = blocks[5].data.len() - 1;
            blocks[5].data[last] ^= 1;
        });
        assert!(matches!(
            Repo::load_car(&tampered),
            Err(RepoError::CidMismatch(_))
        ));
        let raw_root = rewrite(&car, |roots, blocks| {
            let cid = Cid::compute(Codec::Raw, &blocks[0].data);
            blocks[0].cid = cid;
            roots[0] = cid;
        });
        assert!(matches!(
            Repo::load_car(&raw_root),
            Err(RepoError::Commit(_))
        ));
        let two_roots = rewrite(&car, |roots, _| roots.push(roots[0]));
        assert!(matches!(
            Repo::load_car(&two_roots),
            Err(RepoError::RootCount(2))
        ));
        assert!(Repo::load_car(&car[..car.len() - 1]).is_err());
    }

    #[test]
    fn loaded_repo_is_writable() {
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        repo.apply_writes(
            &(0..40).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        let mut loaded = Repo::load_car(&repo.export_car().unwrap()).unwrap();
        let writes = [
            create(100, 100),
            WriteOp::Delete {
                collection: col(),
                rkey: rk(5),
            },
        ];
        let a = repo.apply_writes(&writes, &key).unwrap();
        let b = loaded.apply_writes(&writes, &key).unwrap();
        assert_eq!(a.commit.data, b.commit.data);
        assert_eq!(a.ops, b.ops);
        assert_eq!(a.removed_cids.len(), b.removed_cids.len());
        assert_eq!(contents(&mut repo), contents(&mut loaded));
    }

    #[test]
    fn first_commit_data() {
        let key = P256SigningKey::generate();
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        let empty = repo.commit(&key).unwrap();
        assert_eq!(empty.since, None);
        assert_eq!(empty.prev, None);
        assert!(empty.removed_cids.is_empty());
        // The empty tree's root node and the commit.
        assert_eq!(empty.new_blocks.len(), 2);

        let c = repo.apply_writes(&[create(1, 1)], &key).unwrap();
        assert_eq!(c.prev, Some(empty.cid));
        assert_eq!(c.prev_data, Some(empty.commit.data));
        // The empty root node and the previous commit are gone.
        assert_eq!(c.removed_cids.len(), 2);
        assert!(c.removed_cids.contains(&empty.commit.data));
        assert_eq!(c.relevant_blocks.len(), 3);
        let car = c.relevant_car().unwrap();
        let (roots, blocks) = read_all(&car[..]).unwrap();
        assert_eq!(roots, [c.cid]);
        assert_eq!(blocks.len(), 3);
    }

    // --- record proofs from the tree in memory ---

    /// `record_proofs_car` before proofs could come from a loaded tree:
    /// the commit, the nodes `get` reads from a fresh tree in the order
    /// read, then the records.
    fn proofs_car_by_get(
        src: &dyn BlockSource,
        commit_cid: &Cid,
        paths: &[(Nsid, RecordKey)],
    ) -> Result<Vec<u8>, ProofError> {
        let read = |cid: &Cid| -> Result<Vec<u8>, ProofError> {
            src.read_block(cid)?
                .map(Cow::into_owned)
                .ok_or(ProofError::MissingBlock(*cid))
        };
        let commit_bytes = read(commit_cid)?;
        let commit = Commit::from_cbor(&commit_bytes).map_err(ProofError::InvalidCommit)?;
        let recorder = Recorder::new(src);
        let mut tree = DetachedTree::load(commit.data);
        let mut found = Vec::new();
        for (collection, rkey) in paths {
            found.extend(tree.get(&recorder, &mst_key(collection, rkey))?);
        }
        let mut blocks = vec![Block {
            cid: *commit_cid,
            data: commit_bytes,
        }];
        let mut seen = HashSet::from([*commit_cid]);
        for (cid, data) in recorder.seen.into_inner() {
            if seen.insert(cid) {
                blocks.push(Block { cid, data });
            }
        }
        for cid in found {
            if seen.insert(cid) {
                blocks.push(Block {
                    data: read(&cid)?,
                    cid,
                });
            }
        }
        Ok(crate::car::write_all(&[*commit_cid], &blocks)?)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(32))]

        /// `records_proof` uses the tree in memory while it is the last
        /// commit's, and falls back to reading the commit's tree when there
        /// are writes since. Either way the proof must be the CAR the commit
        /// alone yields, byte for byte: what `record_proofs_car` builds and
        /// what it built before.
        #[test]
        fn proofs_match_proofs_from_the_commit(
            ops in proptest::collection::vec((0u8..8, 0usize..120, 0u16..40), 1..80),
            queries in proptest::collection::vec(
                proptest::collection::vec(0usize..140, 1..6),
                1..4,
            ),
        ) {
            let key = P256SigningKey::generate();
            let queries: Vec<Vec<(Nsid, RecordKey)>> = queries
                .iter()
                .map(|q| q.iter().map(|&i| (col(), rk(i))).collect())
                .collect();
            let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
            for (op, i, v) in ops {
                match op {
                    0..=2 => drop(repo.create(&col(), &rk(i), &record(v))),
                    3 => drop(repo.update(&col(), &rk(i), &record(v))),
                    4 => drop(repo.delete(&col(), &rk(i))),
                    5 | 6 => drop(repo.commit(&key).unwrap()),
                    // Reopening drops staged writes and the loaded nodes.
                    _ if repo.head().is_some() => repo = Repo::open(repo.into_store()).unwrap(),
                    _ => {}
                }
                let Some(head) = repo.head_cid() else {
                    continue;
                };
                let src = StoreSource(&repo.store);
                for paths in &queries {
                    let got = repo.records_proof(paths).unwrap();
                    proptest::prop_assert_eq!(&got, &record_proofs_car(&src, &head, paths).unwrap());
                    proptest::prop_assert_eq!(&got, &proofs_car_by_get(&src, &head, paths).unwrap());
                }
            }
        }
    }

    /// A failed commit leaves the tree flushed past the head, which proofs
    /// must not use. `Flaky` also leaves `borrow_block` to its default,
    /// which copies.
    #[test]
    fn proofs_after_a_failed_commit_are_of_the_head() {
        let key = P256SigningKey::generate();
        let mut repo = Repo::init(Flaky::default(), did(), TidClock::new(0).unwrap()).unwrap();
        repo.apply_writes(
            &(0..60).map(|i| create(i, i as u16)).collect::<Vec<_>>(),
            &key,
        )
        .unwrap();
        let head = repo.head_cid().unwrap();
        let paths = [0, 7, 59, 60, 7].map(|i| (col(), rk(i)));
        let proof = repo.records_proof(&paths).unwrap();
        assert_eq!(
            proof,
            proofs_car_by_get(&StoreSource(&repo.store), &head, &paths).unwrap()
        );

        repo.update(&col(), &rk(7), &record(700)).unwrap();
        repo.create(&col(), &rk(60), &record(60)).unwrap();
        assert_eq!(repo.records_proof(&paths).unwrap(), proof);
        repo.store.fail_next = true;
        assert!(repo.commit(&key).is_err());
        assert_eq!(repo.head_cid(), Some(head));
        assert_eq!(repo.records_proof(&paths).unwrap(), proof);

        repo.store.fail_reads = true;
        assert!(matches!(
            repo.records_proof(&paths),
            Err(ProofError::Mst(MstError::Storage(_)))
        ));
        repo.store.fail_reads = false;
        let head = repo.commit(&key).unwrap().cid;
        assert_eq!(
            repo.records_proof(&paths).unwrap(),
            record_proofs_car(&StoreSource(&repo.store), &head, &paths).unwrap()
        );
    }
}
