//! Pluggable repository storage.
//!
//! A [`Repo`](crate::repo::Repo) keeps writes in memory until they are
//! committed, then hands the store one [`CommitData`] to persist. A store
//! therefore needs only three operations: read a block, report the current
//! commit, and apply a commit. [`MemRepoStore`] is the in-memory
//! implementation and a template for persistent ones.

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::convert::Infallible;

use crate::car::{Block, CarError};
use crate::cbor::Cid;
use crate::cbor::cid::CidMap;
use crate::repo::commit::Commit;
use crate::syntax::{Nsid, RecordKey, Tid};

/// Content-addressed block storage for one repository.
///
/// Blocks are immutable: a CID always names the same bytes, so a store
/// never needs to overwrite one. Only one [`Repo`](crate::repo::Repo) may
/// write to a store at a time. A `Repo` takes ownership of its store, and
/// `&mut S` is a store too, so a caller can keep it:
///
/// ```
/// use shrike::repo::{MemRepoStore, Repo, RepoStore, WriteOp};
/// use shrike::syntax::{Did, Nsid, RecordKey, TidClock};
/// use shrike::crypto::P256SigningKey;
///
/// let key = P256SigningKey::generate();
/// let mut store = MemRepoStore::new();
/// let did = Did::try_from("did:plc:test123456789abcdefghij")?;
/// let mut repo = Repo::init(&mut store, did, TidClock::new(0)?)?;
/// repo.apply_writes(
///     &[WriteOp::Create {
///         collection: Nsid::try_from("app.bsky.feed.post")?,
///         rkey: RecordKey::try_from("abc123")?,
///         record: b"\xa1\x64text\x65hello".to_vec(),
///     }],
///     &key,
/// )?;
/// let head = repo.head_cid();
/// drop(repo);
///
/// assert_eq!(store.head()?, head);
/// Repo::open(&mut store)?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
pub trait RepoStore {
    /// The store's error type.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Return the block with the given CID, or `None` if the store does not
    /// have it.
    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error>;

    /// [`get_block`](Self::get_block), borrowing the block if the store
    /// holds it in memory. The default copies it out with `get_block`.
    fn borrow_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, Self::Error> {
        Ok(self.get_block(cid)?.map(Cow::Owned))
    }

    /// Return the CID of the current commit, or `None` if nothing has been
    /// committed.
    fn head(&self) -> Result<Option<Cid>, Self::Error>;

    /// Persist a commit: store `commit.new_blocks`, delete
    /// `commit.removed_cids`, and make `commit.cid` the head.
    ///
    /// This should be atomic. A store that cannot make it atomic must at
    /// least write the new blocks before moving the head, and move the head
    /// before deleting anything, so a crash leaves only garbage behind.
    /// `commit.prev` is the head this commit was built on; comparing it with
    /// the stored head detects a concurrent writer.
    fn apply_commit(&mut self, commit: &CommitData) -> Result<(), Self::Error>;
}

impl<S: RepoStore + ?Sized> RepoStore for &mut S {
    type Error = S::Error;

    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Self::Error> {
        (**self).get_block(cid)
    }

    fn borrow_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, Self::Error> {
        (**self).borrow_block(cid)
    }

    fn head(&self) -> Result<Option<Cid>, Self::Error> {
        (**self).head()
    }

    fn apply_commit(&mut self, commit: &CommitData) -> Result<(), Self::Error> {
        (**self).apply_commit(commit)
    }
}

/// An in-memory [`RepoStore`].
#[derive(Debug, Clone, Default)]
pub struct MemRepoStore {
    blocks: CidMap<Vec<u8>>,
    head: Option<Cid>,
}

impl MemRepoStore {
    /// Create an empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of blocks held.
    pub fn len(&self) -> usize {
        self.blocks.len()
    }

    /// Whether the store holds no blocks.
    pub fn is_empty(&self) -> bool {
        self.blocks.is_empty()
    }

    /// Iterate over the stored blocks, in no particular order.
    pub fn iter(&self) -> impl Iterator<Item = (&Cid, &[u8])> {
        self.blocks.iter().map(|(cid, data)| (cid, data.as_slice()))
    }
}

impl RepoStore for MemRepoStore {
    type Error = Infallible;

    fn get_block(&self, cid: &Cid) -> Result<Option<Vec<u8>>, Infallible> {
        Ok(self.blocks.get(cid).cloned())
    }

    fn borrow_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, Infallible> {
        Ok(self
            .blocks
            .get(cid)
            .map(|data| Cow::Borrowed(data.as_slice())))
    }

    fn head(&self) -> Result<Option<Cid>, Infallible> {
        Ok(self.head)
    }

    fn apply_commit(&mut self, commit: &CommitData) -> Result<(), Infallible> {
        for cid in &commit.removed_cids {
            self.blocks.remove(cid);
        }
        for (cid, data) in &commit.new_blocks {
            self.blocks.insert(*cid, data.clone());
        }
        self.head = Some(commit.cid);
        Ok(())
    }
}

/// Everything a commit changed, as a store persists it and as
/// `com.atproto.sync.subscribeRepos` publishes it.
#[derive(Debug, Clone)]
pub struct CommitData {
    /// CID of the new commit block.
    pub cid: Cid,
    /// The new signed commit.
    pub commit: Commit,
    /// Revision of the previous commit, or `None` for the first.
    pub since: Option<Tid>,
    /// CID of the previous commit block, or `None` for the first.
    pub prev: Option<Cid>,
    /// MST root of the previous commit (the firehose's `prevData`).
    pub prev_data: Option<Cid>,
    /// Blocks the store does not have yet: new MST nodes, new record
    /// blocks, and the commit block.
    pub new_blocks: BTreeMap<Cid, Vec<u8>>,
    /// The blocks a consumer needs to verify and invert this commit against
    /// the previous one: the commit, a covering proof of every changed key,
    /// and the new record blocks. This is the firehose `blocks` field.
    pub relevant_blocks: BTreeMap<Cid, Vec<u8>>,
    /// Blocks the new commit no longer references: replaced MST nodes and
    /// the previous commit block.
    ///
    /// Unlike the reference implementation, this never lists record blocks.
    /// Identical records under different keys share a block, so a commit
    /// cannot tell when a record block stops being referenced; deleting one
    /// could destroy a record that is still in the repository.
    pub removed_cids: Vec<Cid>,
    /// The records this commit changed, sorted by path.
    pub ops: Vec<RecordOp>,
}

impl CommitData {
    /// The commit's revision.
    pub fn rev(&self) -> Tid {
        self.commit.rev
    }

    /// A CAR of [`relevant_blocks`](Self::relevant_blocks) rooted at the
    /// commit, as the firehose carries it.
    pub fn relevant_car(&self) -> Result<Vec<u8>, CarError> {
        let blocks: Vec<Block> = self
            .relevant_blocks
            .iter()
            .map(|(cid, data)| Block {
                cid: *cid,
                data: data.clone(),
            })
            .collect();
        crate::car::write_all(&[self.cid], &blocks)
    }
}

/// What a commit did to one record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordAction {
    Create,
    Update,
    Delete,
}

impl RecordAction {
    /// The action's name in `com.atproto.sync.subscribeRepos#repoOp`.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordAction::Create => "create",
            RecordAction::Update => "update",
            RecordAction::Delete => "delete",
        }
    }
}

/// One record a commit changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordOp {
    pub action: RecordAction,
    pub collection: Nsid,
    pub rkey: RecordKey,
    /// The record's new CID; `None` for a delete.
    pub cid: Option<Cid>,
    /// The record's CID before the commit; `None` for a create.
    pub prev: Option<Cid>,
}

impl RecordOp {
    /// The record's path, `collection/rkey`.
    pub fn path(&self) -> String {
        crate::repo::repo::mst_key(&self.collection, &self.rkey)
    }
}

/// One write in a [`Repo::apply_writes`](crate::repo::Repo::apply_writes)
/// batch. Records are DRISL bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WriteOp {
    /// Create a record that must not exist yet.
    Create {
        collection: Nsid,
        rkey: RecordKey,
        record: Vec<u8>,
    },
    /// Replace a record that must exist.
    Update {
        collection: Nsid,
        rkey: RecordKey,
        record: Vec<u8>,
    },
    /// Delete a record that must exist.
    Delete { collection: Nsid, rkey: RecordKey },
}

impl WriteOp {
    pub(crate) fn path(&self) -> (&Nsid, &RecordKey) {
        match self {
            WriteOp::Create {
                collection, rkey, ..
            }
            | WriteOp::Update {
                collection, rkey, ..
            }
            | WriteOp::Delete { collection, rkey } => (collection, rkey),
        }
    }
}
