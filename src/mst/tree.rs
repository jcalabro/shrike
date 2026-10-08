use std::borrow::Cow;
use std::collections::hash_map::Entry as MapEntry;

use crate::cbor::cid::CidMap;
use crate::cbor::{Cid, Codec};

use crate::mst::MstError;
use crate::mst::block_store::{BlockSource, BlockStore, NoBlocks};
use crate::mst::height::height_for_key;
use crate::mst::node::{self, EntryData, NodeData, decode_node_data, encode_node_data};

/// How many levels below the root a node may load. Each level down a tree
/// is one height lower and keys have heights 0 to 128, so no tree built by
/// the MST rules is deeper; a deeper one could overflow the stack.
const MAX_DEPTH: usize = 128;

/// Where a node sits in the tree: how many levels below the root, and the
/// keys its position allows, those strictly between `lo` and `hi` (`None`
/// is unbounded). A node loads only if its keys fit, so a loaded tree is
/// in key order across nodes as well as within them.
#[derive(Clone, Copy)]
struct Place<'a> {
    depth: usize,
    lo: Option<&'a str>,
    hi: Option<&'a str>,
}

impl Place<'_> {
    const ROOT: Place<'static> = Place {
        depth: 0,
        lo: None,
        hi: None,
    };

    /// Whether `key` is in the range this place allows.
    fn admits(&self, key: &str) -> bool {
        self.lo.is_none_or(|lo| lo < key) && self.hi.is_none_or(|hi| key < hi)
    }
}

/// A subtree's slot in its parent: the node there, if any, and its place.
type Child<'n> = (Option<&'n mut Node>, Place<'n>);

/// An in-memory MST entry: a key/value pair with optional right subtree.
struct Entry {
    key: String,
    val: Cid,
    right: Option<Box<Node>>,
}

/// An in-memory MST node.
///
/// A node is either loaded (its entries and child links are materialized)
/// or an unloaded stub that knows only its CID and the height its parent
/// implies. Stubs are decoded from a [`BlockSource`] on demand.
struct Node {
    left: Option<Box<Node>>,
    entries: Vec<Entry>,
    /// The node's CID, or `None` if it changed since the last flush (or was
    /// never written).
    cid: Option<Cid>,
    height: u8,
    loaded: bool,
}

impl Node {
    /// A new node that has not been persisted.
    fn fresh(height: u8, left: Option<Box<Node>>, entries: Vec<Entry>) -> Node {
        Node {
            left,
            entries,
            cid: None,
            height,
            loaded: true,
        }
    }

    /// A persisted node that has not been decoded yet.
    fn stub(cid: Cid, height: u8) -> Node {
        Node {
            left: None,
            entries: Vec::new(),
            cid: Some(cid),
            height,
            loaded: false,
        }
    }

    /// Note that the node is about to change, releasing its CID.
    fn touch(&mut self, released: &mut Vec<Cid>) {
        released.extend(self.cid.take());
    }

    /// Drop the node, releasing its CID.
    fn discard(self, released: &mut Vec<Cid>) {
        released.extend(self.cid);
    }
}

/// AT Protocol Merkle Search Tree that owns no block storage.
///
/// `DetachedTree` is the sans-IO core of the MST. It never reads or writes
/// storage on its own:
///
/// - Methods that may need a node the tree has not decoded yet take a
///   [`BlockSource`] and read from it synchronously. Callers backed by async
///   storage call [`missing_blocks`](Self::missing_blocks) in a loop,
///   fetching each batch it reports (one round trip per tree level) until it
///   reports nothing; operations on those keys then need no further blocks.
/// - [`flush`](Self::flush) returns the new node blocks to persist and the
///   CIDs of node blocks the tree no longer references, instead of writing
///   them anywhere.
///
/// Nodes are checked as they load: one whose keys fall outside the range
/// its place in the tree allows, one more than 128 levels below the root,
/// or one linking a block the tree already links elsewhere fails with
/// [`MstError::InvalidNode`]. No tree built by the MST rules has any of
/// these, and a hostile one could otherwise answer lookups inconsistently,
/// overflow the stack, or describe a tree exponentially larger than its
/// blocks.
///
/// Mutations are failure-safe: `insert` and `remove` load every node they
/// will touch before restructuring anything, so a missing or malformed block
/// fails the call and leaves the tree as it was. If a mutation or flush
/// fails after it began changing nodes, which only a bug can cause, the tree
/// refuses all further use rather than report a wrong root.
///
/// The type is `Send` and `Sync`, so it can be held across `.await` points
/// and inside storage transaction closures.
pub struct DetachedTree {
    root: Option<Box<Node>>,
    /// How many nodes in memory carry each CID: stubs, loaded nodes, and
    /// nodes an earlier flush wrote. Every one of these blocks is persisted.
    /// Loading rejects a block linked twice, so each count is one.
    refs: CidMap<u32>,
    /// CIDs that nodes gave up since the last flush, by changing or being
    /// dropped. `flush` retires those no node carries any more, so it costs
    /// time in proportion to what changed, not to the size of the tree.
    released: Vec<Cid>,
    /// The empty-tree node, if the last flush wrote it as the root.
    empty_root: Option<Cid>,
    /// Set when a mutation or flush failed partway through changing nodes.
    poisoned: bool,
}

// DetachedTree must stay usable across `.await` points and in storage
// transaction closures.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<DetachedTree>();
};

/// The output of [`DetachedTree::flush`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TreeWrite {
    /// The tree's root CID.
    pub root: Cid,
    /// Node blocks to persist: the nodes changed since the previous flush,
    /// minus any block the tree already knows is persisted.
    pub new_blocks: Vec<(Cid, Vec<u8>)>,
    /// Persisted node blocks this tree no longer references, sorted.
    pub retired: Vec<Cid>,
}

impl Default for DetachedTree {
    fn default() -> Self {
        Self::new()
    }
}

impl DetachedTree {
    /// Create an empty tree.
    pub fn new() -> Self {
        DetachedTree {
            root: None,
            refs: CidMap::default(),
            released: Vec::new(),
            empty_root: None,
            poisoned: false,
        }
    }

    /// Open the tree rooted at `root`. Nothing is read until a method needs
    /// a node.
    pub fn load(root: Cid) -> Self {
        let mut tree = Self::new();
        tree.root = Some(Box::new(Node::stub(root, 0)));
        tree.refs.insert(root, 1);
        tree
    }

    /// Report the blocks `src` lacks that a get or insert of any of `keys`
    /// needs: the nodes on each key's search path.
    ///
    /// Loads every node on those paths that `src` can supply and returns the
    /// CIDs of the first unavailable node on each path, sorted and
    /// deduplicated. What lies below an unavailable node is unknown until it
    /// is supplied, so callers loop: fetch the reported blocks, make them
    /// visible through `src`, and call again until the result is empty. Each
    /// round descends at least one tree level.
    ///
    /// A remove needs more; use
    /// [`missing_blocks_for_remove`](Self::missing_blocks_for_remove) for
    /// keys that will be removed.
    pub fn missing_blocks<'k>(
        &mut self,
        src: &dyn BlockSource,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Vec<Cid>, MstError> {
        self.missing(src, keys, Visit::Lookup)
    }

    /// Like [`missing_blocks`](Self::missing_blocks), for a remove of any of
    /// `keys`: each key's search path, plus the two subtrees beside the key
    /// that removing it merges.
    pub fn missing_blocks_for_remove<'k>(
        &mut self,
        src: &dyn BlockSource,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Vec<Cid>, MstError> {
        self.missing(src, keys, Visit::Remove)
    }

    fn missing<'k>(
        &mut self,
        src: &dyn BlockSource,
        keys: impl IntoIterator<Item = &'k str>,
        visit: Visit,
    ) -> Result<Vec<Cid>, MstError> {
        self.check_usable()?;
        let mut missing = Vec::new();
        if let Some(root) = self.root.as_deref_mut() {
            let mut ld = Loader {
                src,
                refs: &mut self.refs,
            };
            for key in keys {
                visit_key_path(&mut ld, root, key, visit, true, Place::ROOT, &mut missing)?;
            }
        }
        missing.sort_unstable();
        missing.dedup();
        Ok(missing)
    }

    /// Look up a key and return its value CID, or `None` if not found.
    pub fn get(&mut self, src: &dyn BlockSource, key: &str) -> Result<Option<Cid>, MstError> {
        self.check_usable()?;
        match self.root.as_deref_mut() {
            None => Ok(None),
            Some(root) => {
                let mut ld = Loader {
                    src,
                    refs: &mut self.refs,
                };
                get_node(&mut ld, root, key, Place::ROOT)
            }
        }
    }

    /// Insert or update a key/value pair, returning the value it replaced.
    ///
    /// Fails with [`MstError::InvalidKey`] if `key` is not a valid MST key
    /// (see [`is_valid_key`]), and with [`MstError::BlockNotFound`] if `src`
    /// lacks a node on the key's path, leaving the tree unchanged.
    pub fn insert(
        &mut self,
        src: &dyn BlockSource,
        key: String,
        val: Cid,
    ) -> Result<Option<Cid>, MstError> {
        self.check_usable()?;
        if !is_valid_key(&key) {
            return Err(MstError::InvalidKey(key));
        }
        let prev = self.load_key_path(src, &key, Visit::Lookup)?;
        if prev == Some(val) {
            return Ok(prev);
        }
        if prev.is_some() {
            // An update leaves the tree's shape alone. Placing the key by
            // its height instead would duplicate it in a tree where it
            // sits at another level.
            let updated = match self.root.as_deref_mut() {
                Some(root) => update_node(root, &key, val, &mut self.released),
                None => Err(MstError::Internal("updated key is not in the tree".into())),
            };
            return updated.map(|()| prev).map_err(|e| self.poison(e));
        }
        let height = height_for_key(&key);
        let root = self.root.take();
        if root.is_none() {
            // The tree stops being empty: the empty-tree node goes.
            self.released.extend(self.empty_root.take());
        }
        match insert_node(root, key, val, height, &mut self.released) {
            Ok(root) => {
                self.root = Some(root);
                Ok(prev)
            }
            Err(e) => Err(self.poison(e)),
        }
    }

    /// Remove a key from the tree, returning the removed value CID.
    ///
    /// Fails with [`MstError::BlockNotFound`] if `src` lacks a node the
    /// removal touches, leaving the tree unchanged.
    pub fn remove(&mut self, src: &dyn BlockSource, key: &str) -> Result<Option<Cid>, MstError> {
        self.check_usable()?;
        if self.load_key_path(src, key, Visit::Remove)?.is_none() {
            return Ok(None);
        }
        let Some(root) = self.root.take() else {
            return Ok(None);
        };
        match remove_from_root(root, key, &mut self.released) {
            Ok((root, removed)) => {
                self.root = root;
                Ok(removed)
            }
            Err(e) => Err(self.poison(e)),
        }
    }

    /// Serialize the nodes changed since the previous flush.
    ///
    /// Returns the root CID, the node blocks to persist, and the persisted
    /// node blocks the tree no longer references. The caller is responsible
    /// for storing `new_blocks`: the next flush reports only changes made
    /// after this one. Whether retired blocks can be deleted depends on
    /// whether anything else (an older commit, another tree) still needs
    /// them.
    pub fn flush(&mut self) -> Result<TreeWrite, MstError> {
        self.check_usable()?;
        let mut written = Vec::new();
        let root = match self.root.as_deref_mut() {
            None => {
                // The empty-tree node is rewritten each time; release the
                // previous copy so the two cancel out.
                self.released.extend(self.empty_root.take());
                empty_node_block().map(|(cid, data)| {
                    written.push((cid, data));
                    cid
                })
            }
            Some(root) => write_node(root, &mut written, &mut Vec::new()),
        };
        let root = root.map_err(|e| self.poison(e))?;
        if self.root.is_none() {
            self.empty_root = Some(root);
        }
        self.settle(written, root).map_err(|e| self.poison(e))
    }

    /// Count the nodes `flush` just wrote and retire the CIDs released
    /// since the last flush that no node carries any more.
    ///
    /// A written node whose CID already has a count (one that was released
    /// and then rebuilt identically, such as after an insert and a remove
    /// of the same key) is persisted already, so it is neither new nor
    /// retired.
    fn settle(&mut self, written: Vec<(Cid, Vec<u8>)>, root: Cid) -> Result<TreeWrite, MstError> {
        for cid in &self.released {
            match self.refs.get_mut(cid) {
                Some(count) if *count > 0 => *count -= 1,
                _ => {
                    return Err(MstError::Internal(format!(
                        "MST node {cid} released more often than it was held"
                    )));
                }
            }
        }
        self.refs.reserve(written.len());
        let mut new_blocks = written;
        new_blocks.retain(|(cid, _)| match self.refs.entry(*cid) {
            MapEntry::Occupied(mut count) => {
                *count.get_mut() += 1;
                false
            }
            MapEntry::Vacant(slot) => {
                slot.insert(1);
                true
            }
        });
        let mut retired = Vec::new();
        for cid in self.released.drain(..) {
            if self.refs.get(&cid) == Some(&0) {
                self.refs.remove(&cid);
                retired.push(cid);
            }
        }
        retired.sort_unstable();
        Ok(TreeWrite {
            root,
            new_blocks,
            retired,
        })
    }

    /// The root's CID, or `None` if the root has changes since the tree was
    /// loaded or last flushed.
    pub(crate) fn root_cid(&self) -> Option<Cid> {
        match &self.root {
            Some(root) => root.cid,
            None => self.empty_root,
        }
    }

    /// Append the CIDs of the nodes on `key`'s search path to `path`, root
    /// first, and return the key's value. These are the nodes a record proof
    /// for `key` carries.
    ///
    /// Nodes the tree has not loaded are read from `src` and decoded without
    /// being kept, so a proof needs only shared access. Fails if the path
    /// runs through a node changed since the tree was loaded or last
    /// flushed, which has no CID yet.
    pub fn search_path(
        &self,
        src: &dyn BlockSource,
        key: &str,
        path: &mut Vec<Cid>,
    ) -> Result<Option<Cid>, MstError> {
        self.check_usable()?;
        let unflushed = || MstError::Internal("the tree has changes since its last flush".into());
        let Some(mut n) = self.root.as_deref() else {
            path.push(self.empty_root.ok_or_else(unflushed)?);
            return Ok(None);
        };
        let mut at = Place::ROOT;
        loop {
            let cid = n.cid.ok_or_else(unflushed)?;
            if !n.loaded {
                return search_blocks(src, cid, key, at, path);
            }
            path.push(cid);
            let i = match n.entries.binary_search_by(|e| e.key.as_str().cmp(key)) {
                Ok(i) => return Ok(Some(n.entries[i].val)),
                Err(i) => i,
            };
            let (child, lo) = match i.checked_sub(1) {
                None => (n.left.as_deref(), at.lo),
                Some(j) => (
                    n.entries[j].right.as_deref(),
                    Some(n.entries[j].key.as_str()),
                ),
            };
            at = Place {
                depth: at.depth + 1,
                lo,
                hi: n.entries.get(i).map_or(at.hi, |e| Some(&e.key)),
            };
            match child {
                Some(child) => n = child,
                None => return Ok(None),
            }
        }
    }

    /// Collect all key/value pairs in sorted order into a Vec.
    pub fn entries(&mut self, src: &dyn BlockSource) -> Result<Vec<(String, Cid)>, MstError> {
        let mut result = Vec::new();
        self.walk(src, |key, val| {
            result.push((key.to_owned(), val));
            Ok(())
        })?;
        Ok(result)
    }

    /// Walk the tree in sorted order, calling `f` for each entry.
    pub fn walk<F>(&mut self, src: &dyn BlockSource, mut f: F) -> Result<(), MstError>
    where
        F: FnMut(&str, Cid) -> Result<(), MstError>,
    {
        self.check_usable()?;
        if let Some(root) = self.root.as_deref_mut() {
            let mut ld = Loader {
                src,
                refs: &mut self.refs,
            };
            walk_node(&mut ld, root, &mut f, Place::ROOT)?;
        }
        Ok(())
    }

    /// Walk the entries reachable through blocks `src` has, in sorted order,
    /// skipping every subtree whose node is unavailable. The root must be
    /// available. This is how a partial tree, such as a proof, is listed.
    pub fn walk_reachable<F>(&mut self, src: &dyn BlockSource, mut f: F) -> Result<(), MstError>
    where
        F: FnMut(&str, Cid) -> Result<(), MstError>,
    {
        self.check_usable()?;
        if let Some(root) = self.root.as_deref_mut() {
            let mut ld = Loader {
                src,
                refs: &mut self.refs,
            };
            ld.ensure_loaded(root, Place::ROOT)?;
            walk_reachable_node(&mut ld, root, &mut f, Place::ROOT)?;
        }
        Ok(())
    }

    /// Return the CIDs of the nodes in the covering proofs for `keys`: for
    /// each key, the nodes that prove its value and its neighbours on
    /// either side. They are what a consumer needs to undo an insert or
    /// remove of those keys with no other blocks, as
    /// `com.atproto.sync.subscribeRepos` commits require. This is the union
    /// of the reference implementation's `getCoveringProof` for each key,
    /// node for node. The result is sorted.
    ///
    /// The tree must have no changes since its last [`flush`](Self::flush).
    pub fn covering_proof<'k>(
        &mut self,
        src: &dyn BlockSource,
        keys: impl IntoIterator<Item = &'k str>,
    ) -> Result<Vec<Cid>, MstError> {
        self.check_usable()?;
        let mut keys: Vec<&str> = keys.into_iter().collect();
        keys.sort_unstable();
        keys.dedup();
        let mut out = Vec::new();
        if keys.is_empty() {
            return Ok(out);
        }
        match self.root.as_deref_mut() {
            None => out.push(empty_node_block()?.0),
            Some(root) => {
                let mut ld = Loader {
                    src,
                    refs: &mut self.refs,
                };
                for step in [key_step, left_sib_step, right_sib_step] {
                    proof_pass(&mut ld, root, &keys, step, Place::ROOT, &mut out)?;
                }
            }
        }
        out.sort_unstable();
        out.dedup();
        Ok(out)
    }

    /// Load every node an insert or remove (per `visit`) of `key` touches,
    /// and return the key's current value.
    fn load_key_path(
        &mut self,
        src: &dyn BlockSource,
        key: &str,
        visit: Visit,
    ) -> Result<Option<Cid>, MstError> {
        let Some(root) = self.root.as_deref_mut() else {
            return Ok(None);
        };
        let mut ld = Loader {
            src,
            refs: &mut self.refs,
        };
        let mut missing = Vec::new();
        visit_key_path(&mut ld, root, key, visit, true, Place::ROOT, &mut missing)?;
        if let Some(cid) = missing.first() {
            return Err(MstError::BlockNotFound(cid.to_string()));
        }
        // Everything on the path is loaded now, so the lookup reads nothing.
        ld.src = &NoBlocks;
        get_node(&mut ld, root, key, Place::ROOT)
    }

    fn check_usable(&self) -> Result<(), MstError> {
        if self.poisoned {
            return Err(MstError::Internal(
                "tree is unusable: an earlier mutation failed partway through".into(),
            ));
        }
        Ok(())
    }

    fn poison(&mut self, e: MstError) -> MstError {
        self.poisoned = true;
        self.root = None;
        e
    }
}

/// Decodes stubs from a block source, counting the child stubs each one
/// links to.
struct Loader<'a> {
    src: &'a dyn BlockSource,
    refs: &'a mut CidMap<u32>,
}

impl Loader<'_> {
    /// Decode `n`, which sits at `at`, if it is a stub. Returns the CID of
    /// its block if the source does not have it.
    ///
    /// Rejects a node whose keys do not fit its place, a node deeper than
    /// [`MAX_DEPTH`], which bounds the recursion of every traversal, and a
    /// node linking a block the tree already links elsewhere. No MST links
    /// one block twice, and allowing it would let a few blocks describe a
    /// tree exponentially larger than themselves.
    fn load(&mut self, n: &mut Node, at: Place<'_>) -> Result<Option<Cid>, MstError> {
        if n.loaded {
            return Ok(None);
        }
        let cid = n
            .cid
            .ok_or_else(|| MstError::Internal("unloaded MST node has no CID".into()))?;
        if at.depth > MAX_DEPTH {
            return Err(too_deep(cid));
        }
        let Some(data) = self.src.read_block(&cid)? else {
            return Ok(Some(cid));
        };
        let nd = decode_node_data(&data)?;
        let children = || {
            nd.left
                .iter()
                .chain(nd.entries.iter().filter_map(|e| e.right.as_ref()))
        };
        let mut linked = 0;
        let mut result = Ok(());
        for child in children() {
            let count = self.refs.entry(*child).or_insert(0);
            if *count > 0 {
                result = Err(MstError::InvalidNode(format!(
                    "node {child} is linked from more than one place"
                )));
                break;
            }
            *count = 1;
            linked += 1;
        }
        if result.is_ok() {
            result = populate_node(n, &nd, at);
        }
        if result.is_err() {
            // Nothing linked these before; forget them again.
            for child in children().take(linked) {
                self.refs.remove(child);
            }
        }
        result.map(|()| None)
    }

    fn ensure_loaded(&mut self, n: &mut Node, at: Place<'_>) -> Result<(), MstError> {
        match self.load(n, at)? {
            None => Ok(()),
            Some(cid) => Err(MstError::BlockNotFound(cid.to_string())),
        }
    }
}

/// Fail unless `n` is loaded. Mutations call this where they used to load
/// on demand: everything they touch is loaded before they start.
fn require_loaded(n: &Node) -> Result<(), MstError> {
    if n.loaded {
        return Ok(());
    }
    Err(MstError::Internal(
        "MST mutation reached a node that was not loaded first".into(),
    ))
}

/// Which operation a [`visit_key_path`] loads nodes for.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Visit {
    /// A get or insert, which follows only the key's search path.
    Lookup,
    /// A remove, which also merges the subtrees beside the key.
    Remove,
}

/// Load the nodes below `n`, which sits at `at`, that a get, insert, or
/// remove of `key` touches, collecting the CIDs of stubs the source cannot
/// supply. `top` is set while no node above `n` has an entry, so that `n`
/// is on the chain of nodes `trim_top` walks.
///
/// A get, an update of an existing key, and a new key's split all follow
/// the search path alone; an update leaves the tree's shape unchanged.
/// A remove also loads what merging the subtrees on either side of the
/// removed entry reads (see [`visit_merge`]).
fn visit_key_path(
    ld: &mut Loader<'_>,
    n: &mut Node,
    key: &str,
    visit: Visit,
    top: bool,
    at: Place<'_>,
    missing: &mut Vec<Cid>,
) -> Result<(), MstError> {
    if let Some(cid) = ld.load(n, at)? {
        missing.push(cid);
        return Ok(());
    }
    match n.entries.binary_search_by(|e| e.key.as_str().cmp(key)) {
        Ok(_) if visit == Visit::Lookup => {}
        Ok(i) => {
            // Removing the root chain's only entry empties the node, so
            // the chain continues into what the merge leaves.
            let chain = top && n.entries.len() == 1;
            let (left, right) = neighbours(n, i, at);
            visit_merge(ld, left, right, chain, missing)?;
        }
        Err(i) => {
            let top = top && n.entries.is_empty();
            if let (Some(child), at) = child_at(n, i, at) {
                visit_key_path(ld, child, key, visit, top, at, missing)?;
            }
        }
    }
    Ok(())
}

/// Load the nodes `merge_nodes` reads to merge `left` and `right`, the
/// subtrees on either side of a removed entry: both sides of each level
/// while both have a node there, down their facing edges. Where only one
/// side has a node, the merge re-links it without reading it. `chain` is
/// set while the merged level is on the chain of nodes `trim_top` walks,
/// which it then continues down.
///
/// This follows the tree's links as the merge does rather than searching
/// for the removed key, so it loads exactly what the merge needs.
fn visit_merge(
    ld: &mut Loader<'_>,
    (left, left_at): Child<'_>,
    (right, right_at): Child<'_>,
    chain: bool,
    missing: &mut Vec<Cid>,
) -> Result<(), MstError> {
    match (left, right) {
        (Some(left), Some(right)) => {
            let absent = [ld.load(left, left_at)?, ld.load(right, right_at)?];
            if absent.iter().any(Option::is_some) {
                missing.extend(absent.into_iter().flatten());
                return Ok(());
            }
            let chain = chain && left.entries.is_empty() && right.entries.is_empty();
            let last = left.entries.len();
            let left_edge = child_at(left, last, left_at);
            let right_edge = child_at(right, 0, right_at);
            visit_merge(ld, left_edge, right_edge, chain, missing)
        }
        (Some(child), None) => visit_root_chain(ld, child, left_at, chain, missing),
        (None, Some(child)) => visit_root_chain(ld, child, right_at, chain, missing),
        (None, None) => Ok(()),
    }
}

/// If `chain` is set, load the nodes `trim_top` inspects when `n`, at
/// `at`, is left as the root's only subtree: down through nodes with no
/// entries to the first with some.
fn visit_root_chain(
    ld: &mut Loader<'_>,
    n: &mut Node,
    at: Place<'_>,
    chain: bool,
    missing: &mut Vec<Cid>,
) -> Result<(), MstError> {
    if !chain {
        return Ok(());
    }
    if let Some(cid) = ld.load(n, at)? {
        // trim_top accepts an unread height-0 node as the root.
        if n.height > 0 {
            missing.push(cid);
        }
        return Ok(());
    }
    let chain = n.entries.is_empty();
    match child_at(n, 0, at) {
        (Some(left), at) => visit_root_chain(ld, left, at, chain, missing),
        (None, _) => Ok(()),
    }
}

/// The subtrees on either side of `entries[i]`, and their places, given
/// `n`'s place `at`.
fn neighbours<'n>(n: &'n mut Node, i: usize, at: Place<'n>) -> (Child<'n>, Child<'n>) {
    let depth = at.depth + 1;
    let (before, rest) = n.entries.split_at_mut(i);
    let Some((Entry { key, right, .. }, after)) = rest.split_first_mut() else {
        return ((None, at), (None, at));
    };
    let key = Some(key.as_str());
    let left = match before.last_mut() {
        Some(Entry { key: lo, right, .. }) => (
            right.as_deref_mut(),
            Place {
                depth,
                lo: Some(lo),
                hi: key,
            },
        ),
        None => (
            n.left.as_deref_mut(),
            Place {
                depth,
                lo: at.lo,
                hi: key,
            },
        ),
    };
    let right = (
        right.as_deref_mut(),
        Place {
            depth,
            lo: key,
            hi: after.first().map_or(at.hi, |e| Some(&e.key)),
        },
    );
    (left, right)
}

/// The subtree between `entries[i - 1]` and `entries[i]` (`left` when
/// `i == 0`), and its place, given `n`'s place `at`.
fn child_at<'n>(n: &'n mut Node, i: usize, at: Place<'n>) -> Child<'n> {
    let depth = at.depth + 1;
    let i = i.min(n.entries.len());
    let (before, after) = n.entries.split_at_mut(i);
    let hi = after.first().map_or(at.hi, |e| Some(&e.key));
    match before.last_mut() {
        Some(Entry { key, right, .. }) => (
            right.as_deref_mut(),
            Place {
                depth,
                lo: Some(key),
                hi,
            },
        ),
        None => (
            n.left.as_deref_mut(),
            Place {
                depth,
                lo: at.lo,
                hi,
            },
        ),
    }
}

fn get_node<'n>(
    ld: &mut Loader<'_>,
    mut n: &'n mut Node,
    key: &str,
    mut at: Place<'n>,
) -> Result<Option<Cid>, MstError> {
    loop {
        ld.ensure_loaded(n, at)?;
        // Nodes hold a few entries, so a scan that stops at the first key
        // not below `key` beats a binary search.
        let mut i = n.entries.len();
        for (j, e) in n.entries.iter().enumerate() {
            match key.cmp(&e.key) {
                std::cmp::Ordering::Less => {
                    i = j;
                    break;
                }
                std::cmp::Ordering::Equal => return Ok(Some(e.val)),
                std::cmp::Ordering::Greater => {}
            }
        }
        match child_at(n, i, at) {
            (Some(child), child_at) => (n, at) = (child, child_at),
            (None, _) => return Ok(None),
        }
    }
}

// The mutations below take `released`, the tree's list of CIDs given up
// since the last flush: each node they change or drop adds its CID there
// (see `Node::touch` and `Node::discard`).

fn insert_node(
    n: Option<Box<Node>>,
    key: String,
    val: Cid,
    height: u8,
    released: &mut Vec<Cid>,
) -> Result<Box<Node>, MstError> {
    let Some(n) = n else {
        return Ok(Box::new(Node::fresh(
            height,
            None,
            vec![Entry {
                key,
                val,
                right: None,
            }],
        )));
    };

    require_loaded(&n)?;

    if height > n.height {
        // Step up one level, wrapping the current node as a child.
        let child_height = n.height;
        let parent = Box::new(Node::fresh(child_height + 1, Some(n), Vec::new()));
        return insert_node(Some(parent), key, val, height, released);
    }

    if height < n.height {
        return insert_below(n, key, val, height, released);
    }

    // Same height: insert into this node's entries.
    insert_at_level(n, key, val, released)
}

/// Set the value of `key`, which is in the tree, changing each node on its
/// search path.
fn update_node(n: &mut Node, key: &str, val: Cid, released: &mut Vec<Cid>) -> Result<(), MstError> {
    require_loaded(n)?;
    n.touch(released);
    match n.entries.binary_search_by(|e| e.key.as_str().cmp(key)) {
        Ok(i) => {
            n.entries[i].val = val;
            Ok(())
        }
        Err(i) => match child_at(n, i, Place::ROOT).0 {
            Some(child) => update_node(child, key, val, released),
            None => Err(MstError::Internal("updated key is not in the tree".into())),
        },
    }
}

/// Insert a key into a subtree of `n` (key height < n.height).
fn insert_below(
    mut n: Box<Node>,
    key: String,
    val: Cid,
    height: u8,
    released: &mut Vec<Cid>,
) -> Result<Box<Node>, MstError> {
    let idx = find_child_index(&n, &key);

    let child = if idx == 0 {
        n.left.take()
    } else {
        n.entries[idx - 1].right.take()
    };

    // If no child exists and we're exactly one level above, create leaf directly.
    if child.is_none() && n.height - 1 == height {
        let new_child = Box::new(Node::fresh(
            height,
            None,
            vec![Entry {
                key,
                val,
                right: None,
            }],
        ));
        n.touch(released);
        if idx == 0 {
            n.left = Some(new_child);
        } else {
            n.entries[idx - 1].right = Some(new_child);
        }
        return Ok(n);
    }

    let child = match child {
        Some(c) => c,
        None => Box::new(Node::fresh(n.height - 1, None, Vec::new())),
    };

    let new_child = insert_node(Some(child), key, val, height, released)?;

    n.touch(released);
    if idx == 0 {
        n.left = Some(new_child);
    } else {
        n.entries[idx - 1].right = Some(new_child);
    }
    Ok(n)
}

/// Insert a key at the same height level as `n`.
fn insert_at_level(
    mut n: Box<Node>,
    key: String,
    val: Cid,
    released: &mut Vec<Cid>,
) -> Result<Box<Node>, MstError> {
    // Binary search for insertion point.
    let i = n
        .entries
        .binary_search_by(|e| e.key.as_str().cmp(&key))
        .unwrap_or_else(|x| x);

    // Check for update of existing key.
    if i < n.entries.len() && n.entries[i].key == key {
        n.entries[i].val = val;
        n.touch(released);
        return Ok(n);
    }

    // Split the child between entries[i-1] and entries[i].
    let child_to_split = if i == 0 {
        n.left.take()
    } else {
        n.entries[i - 1].right.take()
    };

    let (left, right) = split_node(child_to_split, &key, released)?;

    let new_entry = Entry {
        key,
        val,
        right: right.map(Box::new),
    };

    n.entries.insert(i, new_entry);

    // Update left pointer or previous entry's right.
    if i == 0 {
        n.left = left.map(Box::new);
    } else {
        n.entries[i - 1].right = left.map(Box::new);
    }

    n.touch(released);
    Ok(n)
}

/// Split a node at key, returning (left, right) subtrees.
/// Left contains everything < key, right contains everything > key.
fn split_node(
    n: Option<Box<Node>>,
    key: &str,
    released: &mut Vec<Cid>,
) -> Result<(Option<Node>, Option<Node>), MstError> {
    let Some(mut n) = n else {
        return Ok((None, None));
    };

    require_loaded(&n)?;
    // Every branch below changes `n` or replaces it.
    n.touch(released);

    // Binary search for split point: first entry with key >= key.
    let split_idx = match n.entries.binary_search_by(|e| e.key.as_str().cmp(key)) {
        Ok(i) => Some(i),
        Err(i) => {
            if i < n.entries.len() {
                Some(i)
            } else {
                None
            }
        }
    };

    match split_idx {
        None => {
            // All entries < key. The rightmost child may still need splitting.
            let last_child = if let Some(last) = n.entries.last_mut() {
                last.right.take()
            } else {
                n.left.take()
            };
            let (child_left, child_right) = split_node(last_child, key, released)?;
            if let Some(last) = n.entries.last_mut() {
                last.right = child_left.map(Box::new);
            } else {
                n.left = child_left.map(Box::new);
            }
            let right_node =
                child_right.map(|cr| Node::fresh(n.height, Some(Box::new(cr)), Vec::new()));
            Ok((trim_node(*n), trim_node_opt(right_node)))
        }
        Some(0) => {
            // All entries >= key. The left child may still need splitting.
            let left_child = n.left.take();
            let (child_left, child_right) = split_node(left_child, key, released)?;
            n.left = child_right.map(Box::new);
            let left_node =
                child_left.map(|cl| Node::fresh(n.height, Some(Box::new(cl)), Vec::new()));
            Ok((trim_node_opt(left_node), trim_node(*n)))
        }
        Some(split_i) => {
            // Split in the middle.
            let right_entries: Vec<Entry> = n.entries.drain(split_i..).collect();
            let left_entries = std::mem::take(&mut n.entries);

            let mut left_node = Node::fresh(n.height, n.left.take(), left_entries);

            // The child between the two halves needs recursive splitting.
            // split_i > 0 guarantees left_entries is non-empty.
            let last = left_node
                .entries
                .last_mut()
                .ok_or_else(|| MstError::Internal("split produced empty left".into()))?;
            let mid_child = last.right.take();
            let (mid_left, mid_right) = split_node(mid_child, key, released)?;
            let last = left_node
                .entries
                .last_mut()
                .ok_or_else(|| MstError::Internal("split produced empty left".into()))?;
            last.right = mid_left.map(Box::new);

            let right_node = Node::fresh(n.height, mid_right.map(Box::new), right_entries);

            Ok((trim_node(left_node), trim_node(right_node)))
        }
    }
}

/// Remove `key` below `root`, then collapse the root chain it may leave.
fn remove_from_root(
    root: Box<Node>,
    key: &str,
    released: &mut Vec<Cid>,
) -> Result<(Option<Box<Node>>, Option<Cid>), MstError> {
    let (root, removed) = remove_node(root, key, released)?;
    Ok((trim_top(root, released)?, removed))
}

fn remove_node(
    mut n: Box<Node>,
    key: &str,
    released: &mut Vec<Cid>,
) -> Result<(Option<Box<Node>>, Option<Cid>), MstError> {
    require_loaded(&n)?;

    // Search for the key in entries.
    for i in 0..n.entries.len() {
        if key == n.entries[i].key {
            let removed_val = n.entries[i].val;

            // Merge left and right children around this entry.
            let left_child = if i == 0 {
                n.left.take()
            } else {
                n.entries[i - 1].right.take()
            };
            let right_child = n.entries[i].right.take();

            let merged = merge_nodes(left_child, right_child, released)?;

            n.entries.remove(i);

            if i == 0 {
                n.left = merged;
            } else {
                n.entries[i - 1].right = merged;
            }
            n.touch(released);

            return Ok((prune_empty(n, released), Some(removed_val)));
        }

        if key < n.entries[i].key.as_str() {
            // Descend into left child.
            let child = if i == 0 {
                n.left.take()
            } else {
                n.entries[i - 1].right.take()
            };
            if let Some(child) = child {
                let (new_child, removed) = remove_node(child, key, released)?;
                if removed.is_some() {
                    n.touch(released);
                }
                if i == 0 {
                    n.left = new_child;
                } else {
                    n.entries[i - 1].right = new_child;
                }
                return Ok((prune_empty(n, released), removed));
            }
            return Ok((Some(n), None));
        }
    }

    // Key > all entries, descend into rightmost child.
    if !n.entries.is_empty() {
        let last = n.entries.len() - 1;
        let child = n.entries[last].right.take();
        if let Some(child) = child {
            let (new_child, removed) = remove_node(child, key, released)?;
            if removed.is_some() {
                n.touch(released);
            }
            n.entries[last].right = new_child;
            return Ok((prune_empty(n, released), removed));
        }
    } else if let Some(left) = n.left.take() {
        let (new_child, removed) = remove_node(left, key, released)?;
        if removed.is_some() {
            n.touch(released);
        }
        n.left = new_child;
        return Ok((prune_empty(n, released), removed));
    }
    Ok((Some(n), None))
}

/// Merge two sibling subtrees back together.
fn merge_nodes(
    left: Option<Box<Node>>,
    right: Option<Box<Node>>,
    released: &mut Vec<Cid>,
) -> Result<Option<Box<Node>>, MstError> {
    let (mut left, mut right) = match (left, right) {
        (None, r) => return Ok(r),
        (l, None) => return Ok(l),
        (Some(l), Some(r)) => (l, r),
    };

    require_loaded(&left)?;
    require_loaded(&right)?;

    // Merge the rightmost child of left with the left child of right.
    let left_right_child = if let Some(last) = left.entries.last_mut() {
        last.right.take()
    } else {
        left.left.take()
    };

    let merged = merge_nodes(left_right_child, right.left.take(), released)?;

    if let Some(last) = left.entries.last_mut() {
        last.right = merged;
    } else {
        left.left = merged;
    }

    // Append right's entries to left.
    left.entries.append(&mut right.entries);
    left.touch(released);
    right.discard(released);

    Ok(Some(left))
}

/// Encode the empty-tree node: no entries and no subtree.
fn empty_node_block() -> Result<(Cid, Vec<u8>), MstError> {
    let nd = NodeData {
        left: None,
        entries: vec![],
    };
    let data = encode_node_data(&nd)?;
    Ok((Cid::compute(Codec::Drisl, &data), data))
}

/// Recursively encode changed nodes into `out`. Returns the node's CID.
///
/// Each block is encoded in `scratch`, which grows to the largest node and
/// is then reused, and copied out at its exact size.
fn write_node(
    n: &mut Node,
    out: &mut Vec<(Cid, Vec<u8>)>,
    scratch: &mut Vec<u8>,
) -> Result<Cid, MstError> {
    if let Some(cid) = n.cid {
        return Ok(cid);
    }
    require_loaded(n)?;

    // Recursively write children first.
    if let Some(left) = &mut n.left {
        write_node(left, out, scratch)?;
    }
    for entry in &mut n.entries {
        if let Some(right) = &mut entry.right {
            write_node(right, out, scratch)?;
        }
    }

    scratch.clear();
    encode_node(n, scratch)?;
    let cid = Cid::compute(Codec::Drisl, scratch);
    out.push((cid, scratch.to_vec()));
    n.cid = Some(cid);
    Ok(cid)
}

/// Append an in-memory node's block to `buf`: the encoding of the
/// `NodeData` it stands for, with each key's suffix borrowed from the key.
fn encode_node(n: &Node, buf: &mut Vec<u8>) -> Result<(), MstError> {
    let left = match &n.left {
        Some(left) => Some(left.cid.ok_or_else(|| {
            MstError::Internal("left node CID not computed; call write_node first".into())
        })?),
        None => None,
    };

    node::start_node(buf, n.entries.len());
    let mut prev_key: &str = "";
    for e in &n.entries {
        let right = match &e.right {
            Some(right) => Some(right.cid.ok_or_else(|| {
                MstError::Internal("right node CID not computed; call write_node first".into())
            })?),
            None => None,
        };
        let prefix_len = shared_prefix_len(prev_key, &e.key);
        let suffix = &e.key.as_bytes()[prefix_len..];
        node::put_entry(buf, prefix_len, suffix, &e.val, right.as_ref());
        prev_key = &e.key;
    }
    node::finish_node(buf, left.as_ref());
    Ok(())
}

fn walk_node<F>(ld: &mut Loader<'_>, n: &mut Node, f: &mut F, at: Place<'_>) -> Result<(), MstError>
where
    F: FnMut(&str, Cid) -> Result<(), MstError>,
{
    ld.ensure_loaded(n, at)?;
    for i in 0..=n.entries.len() {
        if let Some(e) = i.checked_sub(1).and_then(|j| n.entries.get(j)) {
            f(&e.key, e.val)?;
        }
        if let (Some(child), at) = child_at(n, i, at) {
            walk_node(ld, child, f, at)?;
        }
    }
    Ok(())
}

fn walk_reachable_node<F>(
    ld: &mut Loader<'_>,
    n: &mut Node,
    f: &mut F,
    at: Place<'_>,
) -> Result<(), MstError>
where
    F: FnMut(&str, Cid) -> Result<(), MstError>,
{
    for i in 0..=n.entries.len() {
        if let Some(e) = i.checked_sub(1).and_then(|j| n.entries.get(j)) {
            f(&e.key, e.val)?;
        }
        if let (Some(child), at) = child_at(n, i, at)
            && ld.load(child, at)?.is_none()
        {
            walk_reachable_node(ld, child, f, at)?;
        }
    }
    Ok(())
}

/// A position in a node, in the reference implementation's flattened view
/// of it: the left subtree, then each entry followed by its right subtree.
/// Absent subtrees take no position.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Slot {
    Left,
    Leaf(usize),
    Right(usize),
}

/// The subtree at `slot`, or `None` if it holds an entry, and its place,
/// given `n`'s place `at`.
fn slot_subtree<'n>(n: &'n mut Node, slot: Slot, at: Place<'n>) -> Child<'n> {
    match slot {
        Slot::Left => child_at(n, 0, at),
        Slot::Right(i) => child_at(n, i + 1, at),
        Slot::Leaf(_) => (None, at),
    }
}

/// Index of the first entry whose key is at least `key`, or the entry
/// count if there is none. Its slot is `findGtOrEqualLeafIndex`.
fn gte_entry(n: &Node, key: &str) -> usize {
    n.entries.partition_point(|e| e.key.as_str() < key)
}

/// The slot just before entry `i`, or the last slot when `i` is the entry
/// count.
fn slot_before(n: &Node, i: usize) -> Option<Slot> {
    match i.checked_sub(1) {
        None => n.left.is_some().then_some(Slot::Left),
        Some(j) if n.entries.get(j)?.right.is_some() => Some(Slot::Right(j)),
        Some(j) => Some(Slot::Leaf(j)),
    }
}

/// The slot just after entry `i`.
fn slot_after(n: &Node, i: usize) -> Option<Slot> {
    if n.entries.get(i)?.right.is_some() {
        Some(Slot::Right(i))
    } else {
        (i + 1 < n.entries.len()).then_some(Slot::Leaf(i + 1))
    }
}

/// One covering-proof rule at a loaded node, for one key: whether the node
/// is in the proof, and the slot the rule continues into. The rule only
/// descends if that slot is a subtree.
type ProofStep = fn(&Node, &str) -> (bool, Option<Slot>);

/// `proofForKey`: the search path down to `key`, omitting the nodes below
/// the last one that could hold it.
fn key_step(n: &Node, key: &str) -> (bool, Option<Slot>) {
    let i = gte_entry(n, key);
    if n.entries.get(i).is_some_and(|e| e.key == key) {
        return (true, None);
    }
    let next = slot_before(n, i);
    (matches!(next, Some(Slot::Left | Slot::Right(_))), next)
}

/// `proofForLeftSib`: the path down the subtree just left of `key`.
fn left_sib_step(n: &Node, key: &str) -> (bool, Option<Slot>) {
    (true, slot_before(n, gte_entry(n, key)))
}

/// `proofForRightSib`: the path down to the entry just right of `key`.
fn right_sib_step(n: &Node, key: &str) -> (bool, Option<Slot>) {
    let i = gte_entry(n, key);
    let found = if i < n.entries.len() {
        Some(Slot::Leaf(i))
    } else {
        slot_before(n, i)
    };
    let next = match found {
        Some(Slot::Leaf(j)) if n.entries[j].key == key => slot_after(n, j),
        Some(Slot::Leaf(_)) => slot_before(n, i),
        subtree => subtree,
    };
    (true, next)
}

/// Apply `step` for every key in `keys` (sorted) from `n` down, adding the
/// nodes it selects to `out`. Each node is visited once: the slot a step
/// picks never moves left as the key grows, so keys that continue into the
/// same subtree form a run.
fn proof_pass(
    ld: &mut Loader<'_>,
    n: &mut Node,
    keys: &[&str],
    step: ProofStep,
    at: Place<'_>,
    out: &mut Vec<Cid>,
) -> Result<(), MstError> {
    ld.ensure_loaded(n, at)?;
    let mut included = false;
    let mut runs: Vec<(Slot, usize, usize)> = Vec::new();
    for (k, key) in keys.iter().enumerate() {
        let (include, next) = step(n, key);
        included |= include;
        match (next, runs.last_mut()) {
            (Some(slot @ (Slot::Left | Slot::Right(_))), Some((last, _, end))) if *last == slot => {
                *end = k + 1;
            }
            (Some(slot @ (Slot::Left | Slot::Right(_))), _) => runs.push((slot, k, k + 1)),
            _ => {}
        }
    }
    if included {
        match n.cid {
            Some(cid) => out.push(cid),
            None => {
                return Err(MstError::Internal(
                    "covering proof needs a flushed tree".into(),
                ));
            }
        }
    }
    for (slot, start, end) in runs {
        if let (Some(child), at) = slot_subtree(n, slot, at) {
            proof_pass(ld, child, &keys[start..end], step, at, out)?;
        }
    }
    Ok(())
}

/// AT Protocol Merkle Search Tree backed by a [`BlockStore`].
///
/// A wrapper around [`DetachedTree`] for synchronous stores: nodes load
/// from the store on demand, and `root_cid` writes new node blocks back to
/// it. All operations (including reads like `get` and `walk`) take
/// `&mut self` because they may load nodes. Use `DetachedTree` directly for
/// asynchronous storage or when the tree must be `Send`.
pub struct Tree {
    inner: DetachedTree,
    store: Box<dyn BlockStore>,
    /// Flushed blocks the store has not accepted yet.
    unsaved: Vec<(Cid, Vec<u8>)>,
}

impl Tree {
    /// Create a new empty MST backed by the given store.
    pub fn new(store: Box<dyn BlockStore>) -> Self {
        Tree {
            inner: DetachedTree::new(),
            store,
            unsaved: Vec::new(),
        }
    }

    /// Load an MST from a root CID using the given store.
    /// Child nodes are loaded lazily on first access.
    pub fn load(store: Box<dyn BlockStore>, root: Cid) -> Self {
        Tree {
            inner: DetachedTree::load(root),
            store,
            unsaved: Vec::new(),
        }
    }

    /// Look up a key and return its value CID, or `None` if not found.
    pub fn get(&mut self, key: &str) -> Result<Option<Cid>, MstError> {
        self.inner.get(&StoreSource(&*self.store), key)
    }

    /// Insert or update a key/value pair. Fails with [`MstError::InvalidKey`]
    /// if `key` is not a valid MST key (see [`is_valid_key`]).
    pub fn insert(&mut self, key: String, cid: Cid) -> Result<(), MstError> {
        self.inner
            .insert(&StoreSource(&*self.store), key, cid)
            .map(|_| ())
    }

    /// Remove a key from the tree. Returns the removed value CID, or `None`.
    pub fn remove(&mut self, key: &str) -> Result<Option<Cid>, MstError> {
        self.inner.remove(&StoreSource(&*self.store), key)
    }

    /// Compute and return the root CID of the tree.
    /// Writes new node blocks to the block store.
    pub fn root_cid(&mut self) -> Result<Cid, MstError> {
        let write = self.inner.flush()?;
        self.unsaved.extend(write.new_blocks);
        // Put a copy so a block the store rejects is retried on the next call
        // instead of being lost.
        while let Some((cid, data)) = self.unsaved.last() {
            self.store.put_block(*cid, data.clone())?;
            self.unsaved.pop();
        }
        Ok(write.root)
    }

    /// Collect all key/value pairs in sorted order into a Vec.
    pub fn entries(&mut self) -> Result<Vec<(String, Cid)>, MstError> {
        self.inner.entries(&StoreSource(&*self.store))
    }

    /// Walk the tree in sorted order, calling `f` for each entry.
    pub fn walk<F>(&mut self, f: F) -> Result<(), MstError>
    where
        F: FnMut(&str, Cid) -> Result<(), MstError>,
    {
        self.inner.walk(&StoreSource(&*self.store), f)
    }
}

/// Reads a [`BlockStore`] as a [`BlockSource`], mapping its not-found
/// error to an absent block.
struct StoreSource<'a>(&'a dyn BlockStore);

impl BlockSource for StoreSource<'_> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        match self.0.get_block(cid) {
            Ok(data) => Ok(Some(Cow::Owned(data))),
            Err(MstError::BlockNotFound(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Collapse an empty-passthrough root chain after a remove.
///
/// When `remove` deletes the last entry from a multi-level root it leaves
/// behind a non-`None`, entries-empty node whose only useful state lives
/// on its left child. This walks down that chain until it finds a node
/// with real entries (or runs out of nodes).
///
/// Each candidate must be loaded before we test its emptiness: an unloaded
/// stub has no entries and no left child in memory even when its CID
/// points at a real subtree. Treating one as empty would replace the root
/// with `None` and silently drop every record below the removed key.
fn trim_top(
    mut n: Option<Box<Node>>,
    released: &mut Vec<Cid>,
) -> Result<Option<Box<Node>>, MstError> {
    while let Some(mut node) = n {
        // A height-0 node has no subtrees, so it can only appear as a child
        // if it has entries: it is the root as it stands. Accepting it
        // unread lets a partial tree, such as a commit proof, be inverted.
        if !node.loaded && node.height == 0 {
            return Ok(Some(node));
        }
        require_loaded(&node)?;
        if !node.entries.is_empty() {
            return Ok(Some(node));
        }
        n = node.left.take();
        node.discard(released);
    }
    Ok(None)
}

/// Drop a node left with no entries and no subtree by a remove.
///
/// A node with no entries but a left subtree is a canonical height filler
/// and must stay: only the root chain is trimmed (see `trim_top`). A node
/// with neither holds nothing, and the reference implementations remove it,
/// cascading up through any intermediates it leaves empty in turn.
fn prune_empty(n: Box<Node>, released: &mut Vec<Cid>) -> Option<Box<Node>> {
    if n.loaded && n.entries.is_empty() && n.left.is_none() {
        n.discard(released);
        None
    } else {
        Some(n)
    }
}

/// Populate a node's in-memory fields from decoded `NodeData`.
///
/// Leaves `n` untouched if the data is malformed.
///
/// Height handling is subtle. In the canonical MST every parent-child edge
/// spans exactly one level, but on-disk node blocks do not record their
/// height — it is recomputed from a key. For nodes with at least one
/// entry that's straightforward (`height_for_key(entries[0])`). For
/// empty-entries intermediates — the height-fillers the canonical shape
/// requires whenever a parent and its only descendant span >1 level —
/// there is no key to hash, so we rely on the parent having seeded
/// `n.height` when it created the stub. After we know this node's own
/// height we propagate `height - 1` down into each newly-created child stub
/// so the chain stays correct as later loads walk further. atproto/indigo
/// handles the same case via a post-load `ensureHeights` walk; we propagate
/// eagerly during the lazy load instead.
fn populate_node(n: &mut Node, nd: &NodeData, at: Place<'_>) -> Result<(), MstError> {
    let mut entries: Vec<Entry> = Vec::with_capacity(nd.entries.len());
    for_each_key(nd, |_, ed, key| {
        entries.push(Entry {
            key: key.to_owned(),
            val: ed.value,
            right: ed.right.map(|cid| Box::new(Node::stub(cid, 0))),
        });
    })?;
    // Entries are in order, so checking the ends checks them all.
    for e in entries.first().into_iter().chain(entries.last()) {
        if !at.admits(&e.key) {
            return Err(out_of_place(&e.key));
        }
    }

    // Derive height from entries when we have one; otherwise preserve the
    // parent-seeded height for empty intermediates.
    let height = match entries.first() {
        Some(first) => height_for_key(&first.key),
        None => n.height,
    };

    // Child stubs need their height now, because n.height was not known when
    // the entries were built. This is what keeps empty intermediates
    // loadable: when a later load reaches such a child and finds its entries
    // empty, the height seeded here is the only signal it has.
    let child_height = height.saturating_sub(1);
    for entry in &mut entries {
        if let Some(right) = &mut entry.right {
            right.height = child_height;
        }
    }

    n.left = nd.left.map(|cid| Box::new(Node::stub(cid, child_height)));
    n.entries = entries;
    n.height = height;
    n.loaded = true;
    Ok(())
}

fn too_deep(cid: Cid) -> MstError {
    MstError::InvalidNode(format!(
        "node {cid} is more than {MAX_DEPTH} levels below the root"
    ))
}

fn out_of_place(key: &str) -> MstError {
    MstError::InvalidNode(format!(
        "key {key:?} is outside the range its place in the tree allows"
    ))
}

/// Rebuild each entry's full key from the node's prefix compression and call
/// `f` with the entry's index, the entry and its key, in order.
fn for_each_key(nd: &NodeData, mut f: impl FnMut(usize, &EntryData, &str)) -> Result<(), MstError> {
    let (mut key, mut prev) = (Vec::new(), Vec::new());
    for (i, ed) in nd.entries.iter().enumerate() {
        // The prefix length must not exceed the previous key's length. For the
        // first entry this means prefix_len must be 0 (full key). Without this
        // guard a malformed/hostile node block would silently reconstruct the
        // WRONG key — silent corruption of a content-addressed structure.
        // Reject instead. (atmos mst.go:886-888)
        let Some(prefix) = prev.get(..ed.prefix_len) else {
            return Err(MstError::InvalidNode(format!(
                "entry prefix length {} exceeds previous key length {}",
                ed.prefix_len,
                prev.len()
            )));
        };
        key.clear();
        key.extend_from_slice(prefix);
        key.extend_from_slice(&ed.key_suffix);
        let text = std::str::from_utf8(&key)
            .map_err(|_| MstError::InvalidNode("key is not valid UTF-8".into()))?;
        if !is_valid_key(text) {
            return Err(MstError::InvalidNode(format!("invalid MST key {text:?}")));
        }

        // Entries within a node must be in strictly ascending key order; the
        // whole tree's get/diff/binary-search logic relies on it. A block whose
        // entries are out of order (malformed or hostile) must be rejected, not
        // loaded as-is. (atmos mst.go:894-896)
        if i > 0 && key <= prev {
            return Err(MstError::InvalidNode(format!(
                "entry key {text:?} is not greater than previous key {:?}",
                String::from_utf8_lossy(&prev)
            )));
        }
        f(i, ed, text);
        std::mem::swap(&mut key, &mut prev);
    }
    Ok(())
}

/// [`DetachedTree::search_path`] from a node the tree has not loaded,
/// which sits at `at`, decoding each block on the way without keeping it.
fn search_blocks(
    src: &dyn BlockSource,
    mut cid: Cid,
    key: &str,
    at: Place<'_>,
    path: &mut Vec<Cid>,
) -> Result<Option<Cid>, MstError> {
    let mut depth = at.depth;
    let (mut lo, mut hi) = (at.lo.map(str::to_owned), at.hi.map(str::to_owned));
    loop {
        if depth > MAX_DEPTH {
            return Err(too_deep(cid));
        }
        let data = src
            .read_block(&cid)?
            .ok_or_else(|| MstError::BlockNotFound(cid.to_string()))?;
        path.push(cid);
        let nd = decode_node_data(&data)?;
        let place = Place {
            depth,
            lo: lo.as_deref(),
            hi: hi.as_deref(),
        };
        let last = nd.entries.len().saturating_sub(1);
        let mut misplaced = None;
        // The first entry at or after `key` and whether it is `key`, and the
        // keys either side of the subtree before it.
        let mut at = None;
        let (mut below, mut above) = (None, None);
        for_each_key(&nd, |i, _, k| {
            if (i == 0 || i == last) && !place.admits(k) {
                misplaced.get_or_insert_with(|| out_of_place(k));
            }
            if at.is_none() && key <= k {
                at = Some((i, key == k));
                above = Some(k.to_owned());
            } else if at.is_none() {
                let below = below.get_or_insert_with(String::new);
                below.clear();
                below.push_str(k);
            }
        })?;
        if let Some(e) = misplaced {
            return Err(e);
        }
        let child = match at {
            Some((i, true)) => return Ok(nd.entries.get(i).map(|e| e.value)),
            Some((0, false)) => nd.left,
            Some((i, false)) => nd.entries.get(i - 1).and_then(|e| e.right),
            None => nd.entries.last().map_or(nd.left, |e| e.right),
        };
        match child {
            Some(next) => cid = next,
            None => return Ok(None),
        }
        lo = below.or(lo);
        hi = above.or(hi);
        depth += 1;
    }
}

/// Whether `key` is a valid MST key, as the reference implementation
/// requires of every key it inserts or loads: a collection and a record key
/// separated by one `/`, neither empty, using only ASCII letters, digits and
/// `_~-:.`, and at most 1024 bytes in all.
pub fn is_valid_key(key: &str) -> bool {
    let bytes = key.as_bytes();
    let Some(slash) = bytes.iter().position(|&b| b == b'/') else {
        return false;
    };
    let allowed = |b: &u8| b.is_ascii_alphanumeric() || b"_~-:.".contains(b);
    bytes.len() as u64 <= node::MAX_KEY_LEN
        && slash > 0
        && slash + 1 < bytes.len()
        && bytes[..slash].iter().all(allowed)
        && bytes[slash + 1..].iter().all(allowed)
}

/// Find the entry index where key would be found.
/// Returns 0 if key < all entries (meaning use n.left).
/// Returns i if key should be in the subtree after entries[i-1].
fn find_child_index(n: &Node, key: &str) -> usize {
    n.entries
        .binary_search_by(|e| e.key.as_str().cmp(key))
        .unwrap_or_else(|x| x)
}

/// Return the length in bytes of the common prefix between two strings.
#[inline]
fn shared_prefix_len(a: &str, b: &str) -> usize {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // Keys share long prefixes, so compare eight bytes at a time: the first
    // byte that differs is the lowest set byte of the words' difference.
    let mut len = 0;
    for (x, y) in a.as_chunks::<8>().0.iter().zip(b.as_chunks::<8>().0) {
        let diff = u64::from_le_bytes(*x) ^ u64::from_le_bytes(*y);
        if diff != 0 {
            return len + diff.trailing_zeros() as usize / 8;
        }
        len += 8;
    }
    let rest = a[len..].iter().zip(&b[len..]);
    len + rest.take_while(|(x, y)| x == y).count()
}

/// Remove completely empty nodes (no entries and no children). Split calls
/// this only on nodes it has already released or built.
fn trim_node(n: Node) -> Option<Node> {
    if n.loaded && n.entries.is_empty() && n.left.is_none() {
        None
    } else {
        Some(n)
    }
}

fn trim_node_opt(n: Option<Node>) -> Option<Node> {
    n.and_then(trim_node)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use std::collections::HashSet;
    use std::rc::Rc;

    use super::*;
    use crate::cbor::Codec;
    use crate::mst::block_store::MemBlockStore;
    use crate::mst::node::tests::reference_encode_node_data;

    /// Test-only adapter so the same `MemBlockStore` can back two `Tree`
    /// handles. The production `Tree` takes `Box<dyn BlockStore>` (owned),
    /// which makes it awkward to "persist into store, then reload from
    /// store" within a single test. Wrapping in `Rc` gives us cheap
    /// shared ownership without adding a Clone bound to `BlockStore`.
    impl BlockStore for Rc<MemBlockStore> {
        fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
            (**self).get_block(cid)
        }
        fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
            (**self).put_block(cid, data)
        }
        fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
            (**self).has_block(cid)
        }
    }

    fn test_value_cid() -> Cid {
        "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"
            .parse()
            .unwrap()
    }

    fn build_tree_from_keys(keys: &[&str]) -> Tree {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val = test_value_cid();
        for &k in keys {
            tree.insert(k.to_string(), val).unwrap();
        }
        tree
    }

    // --- Hardening: malformed node blocks must error on load, never silently
    // reconstruct wrong keys (content-addressed integrity). Mirrors atmos
    // hardening_test.go C2 series. ---

    /// Store a hand-built NodeData as the root block and return a Tree whose
    /// first access will load (and validate) it.
    fn tree_from_node_data(nd: &NodeData) -> Tree {
        use crate::cbor::{Cid, Codec};
        let data = encode_node_data(nd).unwrap();
        let cid = Cid::compute(Codec::Drisl, &data);
        let store = MemBlockStore::new();
        store.put_block(cid, data).unwrap();
        Tree::load(Box::new(store), cid)
    }

    #[test]
    fn load_rejects_nonzero_first_entry_prefix() {
        // First entry must carry the full key (prefix_len 0). A non-zero first
        // prefix would be silently swallowed by Vec::truncate on an empty
        // buffer, reconstructing a wrong (too-short) key.
        let nd = NodeData {
            left: None,
            entries: vec![EntryData {
                prefix_len: 5,
                key_suffix: b"key".to_vec(),
                value: test_value_cid(),
                right: None,
            }],
        };
        let mut tree = tree_from_node_data(&nd);
        assert!(
            tree.entries().is_err(),
            "non-zero first-entry prefix must be rejected"
        );
    }

    #[test]
    fn load_rejects_prefix_exceeding_previous_key() {
        // Second entry's prefix_len (99) exceeds the previous key length (2).
        let nd = NodeData {
            left: None,
            entries: vec![
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"ab".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
                EntryData {
                    prefix_len: 99,
                    key_suffix: b"x".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
            ],
        };
        let mut tree = tree_from_node_data(&nd);
        assert!(
            tree.entries().is_err(),
            "prefix length exceeding previous key must be rejected"
        );
    }

    #[test]
    fn load_rejects_out_of_order_entries() {
        // Entries must be strictly ascending; "zzz/aaa" then "aaa/bbb" is
        // descending and must be rejected, not loaded with a broken sort order.
        let nd = NodeData {
            left: None,
            entries: vec![
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"zzz/aaa".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"aaa/bbb".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
            ],
        };
        let mut tree = tree_from_node_data(&nd);
        assert!(
            tree.entries().is_err(),
            "out-of-order entries must be rejected"
        );
    }

    #[test]
    fn load_rejects_duplicate_keys() {
        // Equal adjacent keys are not strictly ascending → rejected.
        let nd = NodeData {
            left: None,
            entries: vec![
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"dup".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"dup".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
            ],
        };
        let mut tree = tree_from_node_data(&nd);
        assert!(tree.entries().is_err(), "duplicate keys must be rejected");
    }

    #[test]
    fn load_accepts_valid_prefix_compressed_node() {
        // Positive control: a well-formed prefix-compressed node loads and
        // reconstructs the two expected full keys.
        let nd = NodeData {
            left: None,
            entries: vec![
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"app.bsky.feed.post/aaa".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
                EntryData {
                    prefix_len: 19, // shares "app.bsky.feed.post/"
                    key_suffix: b"bbb".to_vec(),
                    value: test_value_cid(),
                    right: None,
                },
            ],
        };
        let mut tree = tree_from_node_data(&nd);
        let entries = tree.entries().expect("valid node must load");
        let keys: Vec<&str> = entries.iter().map(|(k, _)| k.as_str()).collect();
        assert_eq!(
            keys,
            vec!["app.bsky.feed.post/aaa", "app.bsky.feed.post/bbb"]
        );
    }

    #[test]
    fn empty_tree_has_deterministic_root() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let cid1 = tree.root_cid().unwrap();
        let store2 = MemBlockStore::new();
        let mut tree2 = Tree::new(Box::new(store2));
        let cid2 = tree2.root_cid().unwrap();
        assert_eq!(cid1, cid2);
    }

    #[test]
    fn empty_tree_root_cid_interop() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let cid = tree.root_cid().unwrap();
        assert_eq!(
            cid.to_string(),
            "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
        );
    }

    #[test]
    fn single_entry_root_cid_interop() {
        let mut tree = build_tree_from_keys(&["com.example.record/3jqfcqzm3fo2j"]);
        let cid = tree.root_cid().unwrap();
        assert_eq!(
            cid.to_string(),
            "bafyreibj4lsc3aqnrvphp5xmrnfoorvru4wynt6lwidqbm2623a6tatzdu"
        );
    }

    #[test]
    fn single_entry_layer2_root_cid_interop() {
        let mut tree = build_tree_from_keys(&["com.example.record/3jqfcqzm3fx2j"]);
        let cid = tree.root_cid().unwrap();
        assert_eq!(
            cid.to_string(),
            "bafyreih7wfei65pxzhauoibu3ls7jgmkju4bspy4t2ha2qdjnzqvoy33ai"
        );
    }

    #[test]
    fn five_entries_root_cid_interop() {
        let mut tree = build_tree_from_keys(&[
            "com.example.record/3jqfcqzm3fp2j",
            "com.example.record/3jqfcqzm3fr2j",
            "com.example.record/3jqfcqzm3fs2j",
            "com.example.record/3jqfcqzm3ft2j",
            "com.example.record/3jqfcqzm4fc2j",
        ]);
        let cid = tree.root_cid().unwrap();
        assert_eq!(
            cid.to_string(),
            "bafyreicmahysq4n6wfuxo522m6dpiy7z7qzym3dzs756t5n7nfdgccwq7m"
        );
    }

    #[test]
    fn edge_case_trim_top_on_delete() {
        let val = test_value_cid();
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for k in [
            "com.example.record/3jqfcqzm3fn2j",
            "com.example.record/3jqfcqzm3fo2j",
            "com.example.record/3jqfcqzm3fp2j",
            "com.example.record/3jqfcqzm3fs2j",
            "com.example.record/3jqfcqzm3ft2j",
            "com.example.record/3jqfcqzm3fu2j",
        ] {
            tree.insert(k.to_string(), val).unwrap();
        }

        let cid_before = tree.root_cid().unwrap();
        assert_eq!(
            cid_before.to_string(),
            "bafyreifnqrwbk6ffmyaz5qtujqrzf5qmxf7cbxvgzktl4e3gabuxbtatv4"
        );

        tree.remove("com.example.record/3jqfcqzm3fs2j").unwrap();

        let cid_after = tree.root_cid().unwrap();
        assert_eq!(
            cid_after.to_string(),
            "bafyreie4kjuxbwkhzg2i5dljaswcroeih4dgiqq6pazcmunwt2byd725vi"
        );
    }

    #[test]
    fn edge_case_insertion_splits_two_layers_down() {
        let val = test_value_cid();
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for k in [
            "com.example.record/3jqfcqzm3fo2j",
            "com.example.record/3jqfcqzm3fp2j",
            "com.example.record/3jqfcqzm3fr2j",
            "com.example.record/3jqfcqzm3fs2j",
            "com.example.record/3jqfcqzm3ft2j",
            "com.example.record/3jqfcqzm3fz2j",
            "com.example.record/3jqfcqzm4fc2j",
            "com.example.record/3jqfcqzm4fd2j",
            "com.example.record/3jqfcqzm4ff2j",
            "com.example.record/3jqfcqzm4fg2j",
            "com.example.record/3jqfcqzm4fh2j",
        ] {
            tree.insert(k.to_string(), val).unwrap();
        }

        let cid_before = tree.root_cid().unwrap();
        assert_eq!(
            cid_before.to_string(),
            "bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem"
        );

        tree.insert("com.example.record/3jqfcqzm3fx2j".to_string(), val)
            .unwrap();

        let cid_after = tree.root_cid().unwrap();
        assert_eq!(
            cid_after.to_string(),
            "bafyreid2x5eqs4w4qxvc5jiwda4cien3gw2q6cshofxwnvv7iucrmfohpm"
        );

        tree.remove("com.example.record/3jqfcqzm3fx2j").unwrap();

        let cid_final = tree.root_cid().unwrap();
        assert_eq!(
            cid_final.to_string(),
            "bafyreiettyludka6fpgp33stwxfuwhkzlur6chs4d2v4nkmq2j3ogpdjem"
        );
    }

    #[test]
    fn edge_case_new_layers_two_higher() {
        let val = test_value_cid();
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for k in [
            "com.example.record/3jqfcqzm3ft2j",
            "com.example.record/3jqfcqzm3fz2j",
        ] {
            tree.insert(k.to_string(), val).unwrap();
        }

        let cid_before = tree.root_cid().unwrap();
        assert_eq!(
            cid_before.to_string(),
            "bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky"
        );

        tree.insert("com.example.record/3jqfcqzm3fx2j".to_string(), val)
            .unwrap();

        let cid_after = tree.root_cid().unwrap();
        assert_eq!(
            cid_after.to_string(),
            "bafyreiavxaxdz7o7rbvr3zg2liox2yww46t7g6hkehx4i4h3lwudly7dhy"
        );

        tree.remove("com.example.record/3jqfcqzm3fx2j").unwrap();

        let cid_again = tree.root_cid().unwrap();
        assert_eq!(
            cid_again.to_string(),
            "bafyreidfcktqnfmykz2ps3dbul35pepleq7kvv526g47xahuz3rqtptmky"
        );

        tree.insert("com.example.record/3jqfcqzm3fx2j".to_string(), val)
            .unwrap();
        tree.insert("com.example.record/3jqfcqzm4fd2j".to_string(), val)
            .unwrap();

        let cid_both = tree.root_cid().unwrap();
        assert_eq!(
            cid_both.to_string(),
            "bafyreig4jv3vuajbsybhyvb7gggvpwh2zszwfyttjrj6qwvcsp24h6popu"
        );
    }

    #[test]
    fn insert_and_get() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val_cid = Cid::compute(Codec::Raw, b"value");
        tree.insert("app.bsky.feed.post/abc".to_string(), val_cid)
            .unwrap();
        assert_eq!(tree.get("app.bsky.feed.post/abc").unwrap(), Some(val_cid));
        assert_eq!(tree.get("nonexistent").unwrap(), None);
    }

    #[test]
    fn insert_and_remove() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let cid = Cid::compute(Codec::Raw, b"v");
        tree.insert("col/key".to_string(), cid).unwrap();
        let removed = tree.remove("col/key").unwrap();
        assert_eq!(removed, Some(cid));
        assert_eq!(tree.get("col/key").unwrap(), None);
    }

    #[test]
    fn insert_update() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val1 = Cid::compute(Codec::Drisl, b"v1");
        let val2 = Cid::compute(Codec::Drisl, b"v2");
        tree.insert("col/key".to_string(), val1).unwrap();
        assert_eq!(tree.get("col/key").unwrap(), Some(val1));
        tree.insert("col/key".to_string(), val2).unwrap();
        assert_eq!(tree.get("col/key").unwrap(), Some(val2));
    }

    #[test]
    fn entries_sorted() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for key in ["col/c", "col/a", "col/b"] {
            tree.insert(key.to_string(), Cid::compute(Codec::Raw, key.as_bytes()))
                .unwrap();
        }
        let entries = tree.entries().unwrap();
        assert_eq!(entries[0].0, "col/a");
        assert_eq!(entries[1].0, "col/b");
        assert_eq!(entries[2].0, "col/c");
    }

    #[test]
    fn root_cid_deterministic_regardless_of_insertion_order() {
        let keys: Vec<(&str, &[u8])> = vec![("col/a", b"va"), ("col/b", b"vb"), ("col/c", b"vc")];

        let store1 = MemBlockStore::new();
        let mut t1 = Tree::new(Box::new(store1));
        for &(k, v) in &keys {
            t1.insert(k.to_string(), Cid::compute(Codec::Raw, v))
                .unwrap();
        }

        let store2 = MemBlockStore::new();
        let mut t2 = Tree::new(Box::new(store2));
        for &(k, v) in keys.iter().rev() {
            t2.insert(k.to_string(), Cid::compute(Codec::Raw, v))
                .unwrap();
        }

        assert_eq!(t1.root_cid().unwrap(), t2.root_cid().unwrap());
    }

    #[test]
    fn remove_all_keys() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val = Cid::compute(Codec::Drisl, b"val");
        for key in ["col/a", "col/b", "col/c"] {
            tree.insert(key.to_string(), val).unwrap();
        }
        for key in ["col/a", "col/b", "col/c"] {
            tree.remove(key).unwrap();
        }
        let cid = tree.root_cid().unwrap();
        assert_eq!(
            cid.to_string(),
            "bafyreie5737gdxlw5i64vzichcalba3z2v5n6icifvx5xytvske7mr3hpm"
        );
    }

    #[test]
    fn remove_nonexistent() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val = Cid::compute(Codec::Drisl, b"val");
        tree.insert("col/a".to_string(), val).unwrap();
        let removed = tree.remove("nonexistent").unwrap();
        assert!(removed.is_none());
        assert!(tree.get("col/a").unwrap().is_some());
    }

    #[test]
    fn get_from_empty_tree() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        assert_eq!(tree.get("anything").unwrap(), None);
    }

    #[test]
    fn write_and_load() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val = Cid::compute(Codec::Drisl, b"val");
        for key in ["col/a", "col/b", "col/c"] {
            tree.insert(key.to_string(), val).unwrap();
        }
        let root_cid = tree.root_cid().unwrap();

        // Walk to verify entries are correct
        let entries = tree.entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "col/a");
        assert_eq!(entries[1].0, "col/b");
        assert_eq!(entries[2].0, "col/c");

        // Verify root CID is stable
        let root_cid2 = tree.root_cid().unwrap();
        assert_eq!(root_cid, root_cid2);
    }

    #[test]
    fn many_inserts_and_removes() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        // Insert 100 keys
        for i in 0..100u32 {
            let key = format!("app.bsky.feed.post/{i:05}");
            tree.insert(key, Cid::compute(Codec::Raw, &i.to_be_bytes()))
                .unwrap();
        }
        // Verify all exist
        for i in 0..100u32 {
            let key = format!("app.bsky.feed.post/{i:05}");
            assert!(tree.get(&key).unwrap().is_some(), "key {key} should exist");
        }
        // Remove even keys
        for i in (0..100u32).step_by(2) {
            let key = format!("app.bsky.feed.post/{i:05}");
            assert!(tree.remove(&key).unwrap().is_some());
        }
        // Verify odd keys still exist, even keys gone
        for i in 0..100u32 {
            let key = format!("app.bsky.feed.post/{i:05}");
            if i % 2 == 0 {
                assert!(
                    tree.get(&key).unwrap().is_none(),
                    "even key {key} should be gone"
                );
            } else {
                assert!(
                    tree.get(&key).unwrap().is_some(),
                    "odd key {key} should exist"
                );
            }
        }
    }

    #[test]
    fn shared_prefix_len_tests() {
        assert_eq!(shared_prefix_len("", ""), 0);
        assert_eq!(shared_prefix_len("", "abc"), 0);
        assert_eq!(shared_prefix_len("abc", ""), 0);
        assert_eq!(shared_prefix_len("abc", "abc"), 3);
        assert_eq!(shared_prefix_len("abc", "abd"), 2);
        assert_eq!(shared_prefix_len("abcdef", "abcxyz"), 3);
        assert_eq!(shared_prefix_len("hello", "hello world"), 5);
        // The reference implementation's countPrefixLen vectors.
        assert_eq!(shared_prefix_len("ab", "abc"), 2);
        assert_eq!(shared_prefix_len("abc", "ab"), 2);
        assert_eq!(shared_prefix_len("abcde", "abc"), 3);
        assert_eq!(shared_prefix_len("abc", "abcde"), 3);
        assert_eq!(shared_prefix_len("abcde", "abc1"), 3);
        assert_eq!(shared_prefix_len("abcde", "abb"), 2);
        assert_eq!(shared_prefix_len("abcde", "qbb"), 0);
        assert_eq!(shared_prefix_len("", "asdf"), 0);
        assert_eq!(shared_prefix_len("abc", "abc\x00"), 3);
        assert_eq!(shared_prefix_len("abc\x00", "abc"), 3);
        // Either side of each eight-byte word compared at once.
        let long = "abcdefghijklmnopqrstuvwxyz";
        for len in 0..=long.len() {
            for diff in 0..len {
                let mut other = long[..len].to_owned();
                other.replace_range(diff..=diff, "_");
                assert_eq!(shared_prefix_len(&long[..len], &other), diff);
            }
            assert_eq!(shared_prefix_len(&long[..len], long), len);
        }
        // A shared prefix can end inside a multi-byte character.
        assert_eq!(shared_prefix_len("aaaaaaaé", "aaaaaaaè"), 8);
    }

    // --- Security tests ---

    #[test]
    fn populate_node_rejects_invalid_utf8_key() {
        // Build a NodeData with invalid UTF-8 in key_suffix, persist it,
        // then try to load it. The populate_node call should return an error.
        let cid = Cid::compute(Codec::Drisl, b"test");
        let nd = crate::mst::node::NodeData {
            left: None,
            entries: vec![crate::mst::node::EntryData {
                prefix_len: 0,
                key_suffix: vec![0xFF, 0xFE], // invalid UTF-8
                value: cid,
                right: None,
            }],
        };
        let data = crate::mst::node::encode_node_data(&nd).unwrap();
        let node_cid = Cid::compute(crate::cbor::Codec::Drisl, &data);

        let store = MemBlockStore::new();
        store.put_block(node_cid, data).unwrap();

        let mut tree = Tree::load(Box::new(store), node_cid);
        let result = tree.entries();
        assert!(result.is_err(), "should reject invalid UTF-8 in key");
    }

    #[test]
    fn empty_tree_walk_is_noop() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let entries = tree.entries().unwrap();
        assert!(entries.is_empty());
        let mut count = 0;
        tree.walk(|_, _| {
            count += 1;
            Ok(())
        })
        .unwrap();
        assert_eq!(count, 0);
    }

    /// Build a tree from `keys`, persist its blocks to `store`, return root CID.
    /// Mirrors the atmos test pattern of "stage to disk, then reload".
    fn stage_tree_to_store(store: Rc<MemBlockStore>, keys: &[&str]) -> Cid {
        let mut tree = Tree::new(Box::new(store));
        let val = test_value_cid();
        for &k in keys {
            tree.insert(k.to_string(), val).unwrap();
        }
        tree.root_cid().unwrap()
    }

    /// Compute the canonical root CID for a key set, building from scratch
    /// in a fresh store. The MST is canonical, so this is the single
    /// acceptable root for any tree containing exactly these keys.
    fn canonical_root_for(keys: &[&str]) -> Cid {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val = test_value_cid();
        for &k in keys {
            tree.insert(k.to_string(), val).unwrap();
        }
        tree.root_cid().unwrap()
    }

    /// Regression test for the empty-intermediate height bug. ported from
    /// atmos commit 015c597 ("fix MST height bug").
    ///
    /// `populate_node` derives a node's height from its first entry's key.
    /// For an empty-entries intermediate (the height-filler the canonical
    /// MST shape requires when a parent and its only descendant span >1
    /// level), there is no such key, and the node was left at height 0.
    /// Subsequent inserts traversing that intermediate then misread it as
    /// height 0 and built a non-canonical tower of synthetic intermediates.
    ///
    /// Trigger requires (a) a height gap >1 between a node and its
    /// descendants and (b) a lazy reload, so the tree is reconstructed
    /// from blocks rather than mutated in place. The height-4 root key
    /// below sits over height-0 leaves, forcing empty intermediates at
    /// heights 3, 2, 1; the test reloads and inserts a second leaf via a
    /// path that necessarily traverses one of them.
    #[test]
    fn lazy_load_empty_intermediate_height() {
        // Heights chosen via height_for_key on these literal strings.
        let root_key = "com.example.record/0000057"; // height 4
        let leaf_key1 = "com.example.record/0000000"; // height 0
        let leaf_key2 = "com.example.record/0000001"; // height 0
        assert_eq!(
            height_for_key(root_key),
            4,
            "fixture height drifted; pick another height-4 key",
        );
        assert_eq!(height_for_key(leaf_key1), 0);
        assert_eq!(height_for_key(leaf_key2), 0);

        let store = Rc::new(MemBlockStore::new());
        let root = stage_tree_to_store(Rc::clone(&store), &[root_key, leaf_key1]);

        // Lazy reload: Tree::load only stubs the root; descendants are
        // fetched on demand via ensure_loaded.
        let mut reloaded = Tree::load(Box::new(Rc::clone(&store)), root);
        reloaded
            .insert(leaf_key2.to_string(), test_value_cid())
            .unwrap();
        let got = reloaded.root_cid().unwrap();

        let want = canonical_root_for(&[root_key, leaf_key1, leaf_key2]);
        assert_eq!(
            got, want,
            "lazy-load + insert produced a non-canonical root \
             (likely an empty-entries intermediate node lost its height during ensure_loaded)",
        );
    }

    /// Regression test for the trim-top-loop bug. Ported from atmos commit
    /// a5d22b3 ("fix MST remove bug").
    ///
    /// `Tree::remove`'s top-trim loop collapses empty-passthrough roots
    /// onto their left child. When the left child was an unloaded stub
    /// (entries empty + left None at the in-memory level, but a real
    /// subtree on disk under `cid`), the loop's "stop when left is None"
    /// check fired immediately and replaced the root with `None`, dropping
    /// every record below the removed key. Fix: ensure_loaded the
    /// candidate before testing its emptiness.
    ///
    /// Trigger: a 2-record tree shaped (height-2 root entry, height-1 left
    /// subtree), removed via the height-2 entry after a lazy reload.
    #[test]
    fn lazy_load_remove_trims_through_unloaded_stub() {
        // Heights chosen via height_for_key on these literal strings.
        let root_key = "col.lection/0000019"; // height 2 (will be removed)
        let leaf_key = "col.lection/0000005"; // height 1 (lone survivor)
        assert_eq!(
            height_for_key(root_key),
            2,
            "fixture height drifted; pick another height-2 key",
        );
        assert_eq!(
            height_for_key(leaf_key),
            1,
            "fixture height drifted; pick another height-1 key",
        );
        assert!(leaf_key < root_key, "leaf must sort before root");

        let store = Rc::new(MemBlockStore::new());
        let root = stage_tree_to_store(Rc::clone(&store), &[root_key, leaf_key]);

        let mut reloaded = Tree::load(Box::new(Rc::clone(&store)), root);
        let removed = reloaded.remove(root_key).unwrap();
        assert!(
            removed.is_some(),
            "remove returned None; the root entry should have been found",
        );
        let got = reloaded.root_cid().unwrap();

        let want = canonical_root_for(&[leaf_key]);
        assert_eq!(
            got, want,
            "lazy-load + remove produced an empty-or-wrong root \
             (likely the trim-top loop walked through an unloaded stub)",
        );

        // Sanity: leaf_key must still be retrievable.
        let val = reloaded.get(leaf_key).unwrap();
        assert_eq!(val, Some(test_value_cid()), "leaf was dropped by trim loop");
    }

    /// Regression test: removing the only entry of a non-root node must
    /// leave an empty intermediate node in place, not splice the node's
    /// left child directly into the parent.
    ///
    /// The canonical MST (and every other implementation) keeps a node with
    /// no entries but a subtree as a height filler; only the root chain is
    /// trimmed. Splicing the child up broke the one-level-per-edge shape and
    /// produced a root CID that disagreed with a fresh build of the same
    /// key set.
    ///
    /// Shape: a height-2 root entry over a lone height-1 entry, which has a
    /// height-0 leaf to its left. Removing the height-1 entry empties the
    /// middle node while it still has a child.
    #[test]
    fn remove_keeps_empty_intermediate_node() {
        let root_key = "com.example.record/0000027"; // height 2
        let mid_key = "com.example.record/0000023"; // height 1 (removed)
        let leaf_key = "com.example.record/0000020"; // height 0
        assert_eq!(height_for_key(root_key), 2, "fixture height drifted");
        assert_eq!(height_for_key(mid_key), 1, "fixture height drifted");
        assert_eq!(height_for_key(leaf_key), 0, "fixture height drifted");

        let mut tree = build_tree_from_keys(&[root_key, mid_key, leaf_key]);
        tree.root_cid().unwrap();
        assert_eq!(tree.remove(mid_key).unwrap(), Some(test_value_cid()));

        assert_eq!(
            tree.root_cid().unwrap(),
            canonical_root_for(&[root_key, leaf_key]),
            "remove spliced a child over an emptied intermediate node",
        );
    }

    /// Regression test: a remove that empties a subtree must also drop the
    /// empty intermediate nodes above it, not leave childless empty nodes
    /// behind.
    ///
    /// Shape: a height-2 root entry whose only left descendant is a
    /// height-0 leaf, reached through an empty height-1 intermediate.
    /// Removing the leaf empties the intermediate, which then holds nothing
    /// and must go too.
    #[test]
    fn remove_prunes_emptied_intermediate_chain() {
        let root_key = "com.example.record/0000002"; // height 2
        let leaf_key = "com.example.record/0000000"; // height 0 (removed)
        assert_eq!(height_for_key(root_key), 2, "fixture height drifted");
        assert_eq!(height_for_key(leaf_key), 0, "fixture height drifted");

        let mut tree = build_tree_from_keys(&[root_key, leaf_key]);
        tree.root_cid().unwrap();
        assert_eq!(tree.remove(leaf_key).unwrap(), Some(test_value_cid()));

        assert_eq!(
            tree.root_cid().unwrap(),
            canonical_root_for(&[root_key]),
            "remove left an empty, childless intermediate node in the tree",
        );
    }

    // --- DetachedTree: sans-IO loading, failure safety, flush bookkeeping. ---

    /// A block source that can pretend blocks are missing. It also serves
    /// the legacy `Tree` (through `Rc`), whose store reports hidden blocks
    /// as not found.
    #[derive(Default)]
    struct HidingStore {
        blocks: std::collections::HashMap<Cid, Vec<u8>>,
        hidden: std::cell::RefCell<HashSet<Cid>>,
    }

    impl BlockSource for HidingStore {
        fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
            if self.hidden.borrow().contains(cid) {
                return Ok(None);
            }
            self.blocks.read_block(cid)
        }
    }

    impl BlockStore for Rc<HidingStore> {
        fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
            match self.read_block(cid)? {
                Some(data) => Ok(data.into_owned()),
                None => Err(MstError::BlockNotFound(cid.to_string())),
            }
        }
        fn put_block(&self, _cid: Cid, _data: Vec<u8>) -> Result<(), MstError> {
            Err(MstError::Internal("read-only test store".into()))
        }
        fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
            Ok(self.read_block(cid)?.is_some())
        }
    }

    fn record_key(i: usize) -> String {
        format!("com.example.record/{i:07}")
    }

    /// Build a tree from scratch and flush it. The MST is canonical, so the
    /// result is the only acceptable root and block set for these entries.
    fn canonical_write(entries: &std::collections::BTreeMap<String, Cid>) -> TreeWrite {
        let mut tree = DetachedTree::new();
        for (k, v) in entries {
            tree.insert(&NoBlocks, k.clone(), *v).unwrap();
        }
        tree.flush().unwrap()
    }

    enum Op {
        Insert(String, Cid),
        Remove(String),
    }

    impl Op {
        fn apply(&self, tree: &mut DetachedTree, src: &dyn BlockSource) -> Result<(), MstError> {
            match self {
                Op::Insert(k, v) => tree.insert(src, k.clone(), *v).map(|_| ()),
                Op::Remove(k) => tree.remove(src, k).map(|_| ()),
            }
        }

        fn apply_to_model(&self, model: &mut std::collections::BTreeMap<String, Cid>) {
            match self {
                Op::Insert(k, v) => {
                    model.insert(k.clone(), *v);
                }
                Op::Remove(k) => {
                    model.remove(k);
                }
            }
        }
    }

    /// Regression test: a mutation that needs a block the source lacks must
    /// fail without changing the tree. The store-backed tree used to detach
    /// its root before restructuring, so a missing block partway through a
    /// remove or insert dropped the whole tree and the next `root_cid`
    /// silently returned the empty-tree CID.
    ///
    /// Tries every (operation, hidden node) pair on a multi-level tree.
    #[test]
    fn detached_mutation_with_missing_block_leaves_tree_unchanged() {
        let base: std::collections::BTreeMap<String, Cid> = (0..80)
            .map(|i| (record_key(i * 2), test_value_cid()))
            .collect();
        let base_write = canonical_write(&base);
        let store = HidingStore {
            blocks: base_write.new_blocks.iter().cloned().collect(),
            ..Default::default()
        };
        let other_val = Cid::compute(Codec::Drisl, b"other");

        let mut ops = Vec::new();
        for i in (0..160).step_by(7) {
            // Even keys exist (remove / update), odd keys are new (insert).
            if i % 2 == 0 {
                ops.push(Op::Remove(record_key(i)));
                ops.push(Op::Insert(record_key(i), other_val));
            } else {
                ops.push(Op::Insert(record_key(i), test_value_cid()));
            }
        }

        let mut failures = 0;
        for op in &ops {
            let mut expected = base.clone();
            op.apply_to_model(&mut expected);
            let expected_root = canonical_write(&expected).root;

            for (hidden, _) in &base_write.new_blocks {
                if *hidden == base_write.root {
                    continue;
                }
                store.hidden.borrow_mut().insert(*hidden);
                let mut tree = DetachedTree::load(base_write.root);
                let result = op.apply(&mut tree, &store);
                store.hidden.borrow_mut().clear();

                if let Err(e) = result {
                    failures += 1;
                    assert!(
                        matches!(&e, MstError::BlockNotFound(cid) if *cid == hidden.to_string()),
                        "unexpected error: {e}"
                    );
                    let unchanged = tree.flush().unwrap();
                    assert_eq!(
                        unchanged.root, base_write.root,
                        "failed op changed the root"
                    );
                    assert!(unchanged.new_blocks.is_empty());
                    assert!(unchanged.retired.is_empty());
                    op.apply(&mut tree, &store).unwrap();
                }
                assert_eq!(tree.flush().unwrap().root, expected_root);
            }
        }
        assert!(
            failures >= ops.len(),
            "only {failures} ops hit a hidden block"
        );
    }

    /// The store-backed wrapper keeps its root when a remove fails on a
    /// missing block (the original symptom of the bug above).
    #[test]
    fn tree_remove_with_missing_block_keeps_root() {
        let base: std::collections::BTreeMap<String, Cid> =
            (0..80).map(|i| (record_key(i), test_value_cid())).collect();
        let base_write = canonical_write(&base);
        let store = Rc::new(HidingStore {
            blocks: base_write.new_blocks.iter().cloned().collect(),
            ..Default::default()
        });

        let mut failures = 0;
        for (hidden, _) in &base_write.new_blocks {
            if *hidden == base_write.root {
                continue;
            }
            store.hidden.borrow_mut().insert(*hidden);
            let mut tree = Tree::load(Box::new(Rc::clone(&store)), base_write.root);
            if tree.remove(&record_key(27)).is_err() {
                failures += 1;
                assert_eq!(tree.root_cid().unwrap(), base_write.root);
            }
            store.hidden.borrow_mut().clear();
        }
        assert!(failures > 0, "no hidden block affected the remove");
    }

    /// `missing_blocks` and `missing_blocks_for_remove` prefetch everything
    /// the operations need, one tree level per round, after which they run
    /// against a source with no blocks at all.
    #[test]
    fn missing_blocks_prefetch_rounds() {
        let base: std::collections::BTreeMap<String, Cid> = (0..200)
            .map(|i| (record_key(i * 2), test_value_cid()))
            .collect();
        let base_write = canonical_write(&base);
        let all: std::collections::HashMap<Cid, Vec<u8>> =
            base_write.new_blocks.iter().cloned().collect();
        let root_height = (0..200)
            .map(|i| height_for_key(&record_key(i * 2)))
            .max()
            .unwrap();

        let ops = [
            Op::Remove(record_key(54)),
            Op::Remove(record_key(114)),
            Op::Insert(record_key(301), test_value_cid()),
        ];
        let removed = [record_key(54), record_key(114)];
        let inserted = [record_key(301)];

        let mut tree = DetachedTree::load(base_write.root);
        let mut fetched = std::collections::HashMap::new();
        let mut rounds = 0;
        loop {
            let mut missing = tree
                .missing_blocks_for_remove(&fetched, removed.iter().map(String::as_str))
                .unwrap();
            missing.extend(
                tree.missing_blocks(&fetched, inserted.iter().map(String::as_str))
                    .unwrap(),
            );
            if missing.is_empty() {
                break;
            }
            rounds += 1;
            for cid in missing {
                fetched.insert(cid, all[&cid].clone());
            }
        }
        assert!(rounds >= 1 && rounds <= usize::from(root_height) + 1);
        assert!(fetched.len() < all.len(), "prefetch loaded the whole tree");

        let mut expected = base.clone();
        for op in &ops {
            op.apply(&mut tree, &NoBlocks).unwrap();
            op.apply_to_model(&mut expected);
        }
        assert_eq!(tree.flush().unwrap().root, canonical_write(&expected).root);
    }

    /// Inserting the value a key already has is a no-op that reports it.
    #[test]
    fn detached_insert_same_value_is_noop() {
        let mut tree = DetachedTree::new();
        assert_eq!(
            tree.insert(&NoBlocks, record_key(1), test_value_cid())
                .unwrap(),
            None
        );
        let first = tree.flush().unwrap();
        assert_eq!(
            tree.insert(&NoBlocks, record_key(1), test_value_cid())
                .unwrap(),
            Some(test_value_cid())
        );
        let second = tree.flush().unwrap();
        assert_eq!(second.root, first.root);
        assert!(second.new_blocks.is_empty());
        assert!(second.retired.is_empty());
    }

    /// The first `n` record keys after `after` (by index) at `height`.
    fn keys_at(height: u8, after: usize, n: usize) -> Vec<(usize, String)> {
        (after + 1..)
            .map(|i| (i, record_key(i)))
            .filter(|(_, k)| height_for_key(k) == height)
            .take(n)
            .collect()
    }

    fn write_of(keys: &[String]) -> TreeWrite {
        let val = Cid::compute(Codec::Drisl, b"v");
        canonical_write(&keys.iter().map(|k| (k.clone(), val)).collect())
    }

    /// The root of a tree of `keys` and a store holding its blocks.
    fn partial(keys: &[String]) -> (Cid, HidingStore) {
        let write = write_of(keys);
        let store = HidingStore {
            blocks: write.new_blocks.into_iter().collect(),
            ..Default::default()
        };
        (write.root, store)
    }

    fn canonical_root(keys: &[String]) -> Cid {
        write_of(keys).root
    }

    /// The CID of the subtree right of `key` in the node `cid`.
    fn right_of(store: &HidingStore, cid: Cid, key: &str) -> Cid {
        let nd = decode_node_data(&store.blocks[&cid]).unwrap();
        let mut prev = Vec::new();
        for e in &nd.entries {
            prev.truncate(e.prefix_len);
            prev.extend_from_slice(&e.key_suffix);
            if prev == key.as_bytes() {
                return e.right.unwrap();
            }
        }
        panic!("{key} not in node");
    }

    #[test]
    fn removing_root_entry_promotes_unread_height_zero_subtree() {
        // Root [a] at height 1 over an unread height-0 node [b, c]: removing
        // a makes that node the root without reading it, as a commit proof
        // that omits it requires.
        let (ia, a) = keys_at(1, 0, 1).remove(0);
        let low: Vec<String> = keys_at(0, ia, 2).into_iter().map(|(_, k)| k).collect();
        let (root, store) = partial(&[a.clone(), low[0].clone(), low[1].clone()]);
        let child = right_of(&store, root, &a);
        store.hidden.borrow_mut().insert(child);

        let mut tree = DetachedTree::load(root);
        assert_eq!(
            tree.missing_blocks_for_remove(&store, [a.as_str()])
                .unwrap(),
            []
        );
        assert!(tree.remove(&store, &a).unwrap().is_some());
        let write = tree.flush().unwrap();
        assert_eq!(write.root, child);
        assert_eq!(write.root, canonical_root(&low));
        assert!(write.new_blocks.is_empty());
    }

    #[test]
    fn removing_root_entry_reads_higher_subtrees() {
        // Root [a] at height 2 over a height-1 filler over [b, c]. The filler
        // must be read: only its block shows it has no entries of its own.
        let (ia, a) = keys_at(2, 0, 1).remove(0);
        let low: Vec<String> = keys_at(0, ia, 2).into_iter().map(|(_, k)| k).collect();
        let (root, store) = partial(&[a.clone(), low[0].clone(), low[1].clone()]);
        let filler = right_of(&store, root, &a);

        store.hidden.borrow_mut().insert(filler);
        let mut tree = DetachedTree::load(root);
        assert_eq!(
            tree.missing_blocks_for_remove(&store, [a.as_str()])
                .unwrap(),
            [filler]
        );
        assert!(matches!(
            tree.remove(&store, &a),
            Err(MstError::BlockNotFound(_))
        ));
        assert_eq!(tree.flush().unwrap().root, root);

        // With the filler readable, the height-0 node below it may stay
        // unread.
        store.hidden.borrow_mut().clear();
        let leaf_node = {
            let nd = decode_node_data(&store.blocks[&filler]).unwrap();
            assert!(nd.entries.is_empty());
            nd.left.unwrap()
        };
        store.hidden.borrow_mut().insert(leaf_node);
        let mut tree = DetachedTree::load(root);
        assert!(tree.remove(&store, &a).unwrap().is_some());
        assert_eq!(tree.flush().unwrap().root, canonical_root(&low));
    }

    #[test]
    fn lone_neighbour_of_removed_key_is_not_read() {
        // Removing a non-root key with a subtree on only one side re-links
        // that subtree as is.
        for height in [1, 2] {
            let (ia, a) = keys_at(height, 0, 1).remove(0);
            let (ib, b) = keys_at(height, ia, 1).remove(0);
            let low: Vec<String> = keys_at(0, ib, 3).into_iter().map(|(_, k)| k).collect();
            let mut keys = vec![a.clone(), b.clone()];
            keys.extend(low.iter().cloned());
            let (root, store) = partial(&keys);
            // b's right subtree holds the low keys; a has no subtrees.
            let sub = right_of(&store, root, &b);
            store.hidden.borrow_mut().insert(sub);

            let mut tree = DetachedTree::load(root);
            assert!(tree.remove(&store, &b).unwrap().is_some());
            let mut rest = vec![a.clone()];
            rest.extend(low.iter().cloned());
            assert_eq!(
                tree.flush().unwrap().root,
                canonical_root(&rest),
                "height {height}"
            );
        }
    }

    /// A tree of `low` height-0 keys and `high` height-1 keys interleaved,
    /// and a height-1 key with a height-0 subtree on both sides.
    fn two_level_tree(low: usize, high: usize) -> (Vec<String>, String) {
        let mut keys: Vec<String> = keys_at(0, 0, low).into_iter().map(|(_, k)| k).collect();
        let highs: Vec<String> = keys_at(1, 0, high).into_iter().map(|(_, k)| k).collect();
        keys.extend(highs.iter().cloned());
        keys.sort();
        let flanked = highs
            .iter()
            .find(|h| {
                let i = keys.binary_search(h).unwrap();
                i > 0
                    && i + 1 < keys.len()
                    && height_for_key(&keys[i - 1]) == 0
                    && height_for_key(&keys[i + 1]) == 0
            })
            .expect("no height-1 key with subtrees on both sides")
            .clone();
        (keys, flanked)
    }

    /// Regression test: undoing an update (inserting a key's previous
    /// value) needs only the root-to-key path the update rewrote, which is
    /// all an indigo-style producer ships for an update op. The insert used
    /// to load the subtrees on both sides of the key, as a remove does, and
    /// failed with `BlockNotFound` on a commit that carried just the path.
    #[test]
    fn update_inverts_with_only_the_key_path() {
        let (keys, key) = two_level_tree(60, 3);
        let old = Cid::compute(Codec::Drisl, b"v");
        let new = Cid::compute(Codec::Drisl, b"new");
        let base = write_of(&keys);
        let all: std::collections::HashMap<Cid, Vec<u8>> =
            base.new_blocks.iter().cloned().collect();

        let mut tree = DetachedTree::load(base.root);
        assert_eq!(tree.insert(&all, key.clone(), new).unwrap(), Some(old));
        let update = tree.flush().unwrap();
        // The key is in the root: the update rewrote only that node.
        assert_eq!(update.new_blocks.len(), 1);
        let path: std::collections::HashMap<Cid, Vec<u8>> = update.new_blocks.into_iter().collect();

        let mut inv = DetachedTree::load(update.root);
        assert_eq!(inv.missing_blocks(&path, [key.as_str()]).unwrap(), []);
        assert_eq!(inv.get(&path, &key).unwrap(), Some(new));
        assert_eq!(inv.insert(&path, key.clone(), old).unwrap(), Some(new));
        assert_eq!(inv.flush().unwrap().root, base.root);

        // A remove of the same key still needs both neighbours, and fails
        // cleanly without them.
        let mut inv = DetachedTree::load(update.root);
        assert_eq!(
            inv.missing_blocks_for_remove(&path, [key.as_str()])
                .unwrap()
                .len(),
            2
        );
        assert!(matches!(
            inv.remove(&path, &key),
            Err(MstError::BlockNotFound(_))
        ));
        assert_eq!(inv.flush().unwrap().root, update.root);
    }

    /// Every key of a multi-level tree can be updated and the update undone
    /// from the blocks the update wrote alone.
    #[test]
    fn every_update_inverts_from_its_own_new_blocks() {
        let base: std::collections::BTreeMap<String, Cid> = (0..300)
            .map(|i| (record_key(i), test_value_cid()))
            .collect();
        let base_write = canonical_write(&base);
        let all: std::collections::HashMap<Cid, Vec<u8>> =
            base_write.new_blocks.iter().cloned().collect();
        let new = Cid::compute(Codec::Drisl, b"new");

        for key in base.keys() {
            let mut tree = DetachedTree::load(base_write.root);
            tree.insert(&all, key.clone(), new).unwrap();
            let update = tree.flush().unwrap();
            let path: std::collections::HashMap<Cid, Vec<u8>> =
                update.new_blocks.into_iter().collect();

            let mut inv = DetachedTree::load(update.root);
            assert_eq!(inv.missing_blocks(&path, [key.as_str()]).unwrap(), []);
            inv.insert(&NoBlocks, key.clone(), test_value_cid())
                .unwrap_or_else(|e| panic!("{key}: {e}"));
            assert_eq!(inv.flush().unwrap().root, base_write.root, "{key}");
        }
    }

    // --- flush bookkeeping: `retired` and `new_blocks` without a tree walk ---

    /// Every CID in memory, stubs included: what the tree references.
    fn in_memory_cids(tree: &DetachedTree) -> HashSet<Cid> {
        fn visit(n: &Node, out: &mut HashSet<Cid>) {
            out.extend(n.cid);
            if let Some(left) = &n.left {
                visit(left, out);
            }
            for e in &n.entries {
                if let Some(right) = &e.right {
                    visit(right, out);
                }
            }
        }
        let mut out = HashSet::new();
        if let Some(root) = &tree.root {
            visit(root, &mut out);
        }
        out
    }

    /// One step of [`flush_matches_whole_tree_bookkeeping`].
    #[derive(Debug, Clone)]
    enum Step {
        Insert(usize, u8),
        Remove(usize),
        Flush,
        Reload,
    }

    fn step_strategy(keys: usize) -> impl proptest::strategy::Strategy<Value = Step> {
        use proptest::prelude::*;
        prop_oneof![
            6 => (0..keys, 0u8..3).prop_map(|(k, v)| Step::Insert(k, v)),
            3 => (0..keys).prop_map(Step::Remove),
            2 => Just(Step::Flush),
            1 => Just(Step::Reload),
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// Regression test for the O(tree) flush: `flush` used to collect
        /// every CID in memory and diff it against everything persisted.
        /// It now settles only the CIDs that changed, and must report
        /// exactly what that walk would have: as retired, every block the
        /// tree held since the last flush and no longer references; as new,
        /// every referenced block it did not hold.
        #[test]
        fn flush_matches_whole_tree_bookkeeping(
            base in 0usize..300,
            steps in proptest::collection::vec(step_strategy(400), 1..120),
        ) {
            let base: std::collections::BTreeMap<String, Cid> =
                (0..base).map(|i| (record_key(i), test_value_cid())).collect();
            let base_write = canonical_write(&base);
            let mut store: std::collections::HashMap<Cid, Vec<u8>> =
                base_write.new_blocks.iter().cloned().collect();
            let mut model = base;
            let mut tree = DetachedTree::load(base_write.root);
            // CIDs the tree held since its last flush, and the blocks it
            // referenced at that flush.
            let mut held: HashSet<Cid> = [base_write.root].into();
            let empty = empty_node_block().unwrap().0;

            let flush = |tree: &mut DetachedTree,
                             held: &mut HashSet<Cid>,
                             store: &mut std::collections::HashMap<Cid, Vec<u8>>,
                             model: &std::collections::BTreeMap<String, Cid>| {
                let write = tree.flush().unwrap();
                let mut now = in_memory_cids(tree);
                if tree.root.is_none() {
                    now.insert(empty);
                }
                let mut retired: Vec<Cid> = held.difference(&now).copied().collect();
                retired.sort_unstable();
                assert_eq!(write.retired, retired);
                let new: HashSet<Cid> = write.new_blocks.iter().map(|(c, _)| *c).collect();
                assert_eq!(new.len(), write.new_blocks.len(), "duplicate new block");
                assert_eq!(new, now.difference(held).copied().collect::<HashSet<_>>());
                for (cid, data) in &write.new_blocks {
                    assert_eq!(*cid, Cid::compute(Codec::Drisl, data));
                    store.insert(*cid, data.clone());
                }
                assert_eq!(write.root, canonical_write(model).root);
                *held = now;
            };

            for step in steps {
                match step {
                    Step::Insert(k, v) => {
                        let key = record_key(k);
                        tree.missing_blocks(&store, [key.as_str()]).unwrap();
                        held.extend(in_memory_cids(&tree));
                        let val = Cid::compute(Codec::Drisl, &[v]);
                        tree.insert(&store, key.clone(), val).unwrap();
                        model.insert(key, val);
                    }
                    Step::Remove(k) => {
                        let key = record_key(k);
                        tree.missing_blocks_for_remove(&store, [key.as_str()]).unwrap();
                        held.extend(in_memory_cids(&tree));
                        tree.remove(&store, &key).unwrap();
                        model.remove(&key);
                    }
                    Step::Flush => flush(&mut tree, &mut held, &mut store, &model),
                    Step::Reload => {
                        flush(&mut tree, &mut held, &mut store, &model);
                        let root = tree.flush().unwrap().root;
                        tree = DetachedTree::load(root);
                        held = [root].into();
                    }
                }
                held.extend(in_memory_cids(&tree));
            }
            flush(&mut tree, &mut held, &mut store, &model);
        }
    }

    /// A node's block as it used to be encoded, through `NodeData` and
    /// `Encoder`: the oracle for `encode_node`.
    fn reference_node_block(n: &Node) -> Vec<u8> {
        let mut entries = Vec::new();
        let mut prev: &[u8] = b"";
        for e in &n.entries {
            let key = e.key.as_bytes();
            let prefix_len = prev.iter().zip(key).take_while(|(a, b)| a == b).count();
            entries.push(EntryData {
                prefix_len,
                key_suffix: key[prefix_len..].to_vec(),
                value: e.val,
                right: e.right.as_ref().map(|r| r.cid.unwrap()),
            });
            prev = key;
        }
        let left = n.left.as_ref().map(|l| l.cid.unwrap());
        reference_encode_node_data(&NodeData { left, entries })
    }

    /// Keys that share long prefixes and reach heights 2 and 3 (so trees
    /// have nodes with no entries, only a left subtree).
    fn node_key() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::*;
        prop_oneof![
            (0usize..2000).prop_map(record_key),
            "c/[a-z]{1,6}",
            "x/x{0,40}[ab]{1,3}",
            "app\\.bsky\\.feed\\.(post|like)/3k[a-z2-7]{0,11}",
        ]
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(512))]

        /// `flush` encodes each node straight from memory, exactly as
        /// building its `NodeData` and encoding that would.
        #[test]
        fn node_blocks_match_reference_encoding(
            keys in proptest::collection::vec(node_key(), 0..80),
            removes in proptest::collection::vec(proptest::prelude::any::<proptest::sample::Index>(), 0..20),
        ) {
            let mut tree = DetachedTree::new();
            for key in &keys {
                let val = Cid::compute(Codec::Raw, key.as_bytes());
                tree.insert(&NoBlocks, key.clone(), val).unwrap();
            }
            if !keys.is_empty() {
                for i in removes {
                    tree.remove(&NoBlocks, &keys[i.index(keys.len())]).unwrap();
                }
            }
            let write = tree.flush().unwrap();
            let blocks: std::collections::HashMap<Cid, Vec<u8>> =
                write.new_blocks.into_iter().collect();

            fn check(n: &Node, blocks: &std::collections::HashMap<Cid, Vec<u8>>) -> usize {
                let want = reference_node_block(n);
                let mut got = vec![0xaa];
                encode_node(n, &mut got).unwrap();
                assert_eq!(got[1..], want);
                let cid = Cid::compute(Codec::Drisl, &want);
                assert_eq!(n.cid, Some(cid));
                assert_eq!(blocks.get(&cid), Some(&want));
                let below = n.entries.iter().filter_map(|e| e.right.as_deref());
                1 + n.left.as_deref().into_iter().chain(below).map(|c| check(c, blocks)).sum::<usize>()
            }
            let nodes = match tree.root.as_deref() {
                Some(root) => check(root, &blocks),
                None => {
                    let empty = reference_encode_node_data(&NodeData { left: None, entries: vec![] });
                    assert_eq!(write.root, Cid::compute(Codec::Drisl, &empty));
                    assert_eq!(blocks.get(&write.root), Some(&empty));
                    1
                }
            };
            proptest::prop_assert_eq!(nodes, blocks.len());
        }

        #[test]
        fn shared_prefix_len_matches_bytewise(
            (a, b) in proptest::strategy::Strategy::prop_map(
                ("[aé]{0,20}", "[aéè]{0,10}", "[aéè]{0,10}"),
                |(prefix, x, y)| (prefix.clone() + &x, prefix + &y),
            ),
        ) {
            let want = a.bytes().zip(b.bytes()).take_while(|(x, y)| x == y).count();
            proptest::prop_assert_eq!(shared_prefix_len(&a, &b), want);
        }
    }

    /// Encode a node of `entries` (key, right subtree) and `left` into
    /// `blocks`, with every value `test_value_cid()`, and return its CID.
    fn put_node(
        blocks: &mut std::collections::HashMap<Cid, Vec<u8>>,
        left: Option<Cid>,
        entries: &[(&str, Option<Cid>)],
    ) -> Cid {
        let mut prev = "";
        let entries = entries
            .iter()
            .map(|&(key, right)| {
                let p = shared_prefix_len(prev, key);
                prev = key;
                EntryData {
                    prefix_len: p,
                    key_suffix: key.as_bytes()[p..].to_vec(),
                    value: test_value_cid(),
                    right,
                }
            })
            .collect();
        let data = encode_node_data(&NodeData { left, entries }).unwrap();
        let cid = Cid::compute(Codec::Drisl, &data);
        blocks.insert(cid, data);
        cid
    }

    /// Every operation that reads `key`'s part of the tree, each on a fresh
    /// load of `root`, with what it returned.
    fn every_op(
        root: Cid,
        src: &dyn BlockSource,
        key: &str,
    ) -> Vec<(&'static str, Result<(), MstError>)> {
        let fresh = || DetachedTree::load(root);
        vec![
            ("get", fresh().get(src, key).map(drop)),
            (
                "insert",
                fresh().insert(src, key.into(), test_value_cid()).map(drop),
            ),
            ("remove", fresh().remove(src, key).map(drop)),
            ("entries", fresh().entries(src).map(drop)),
            ("walk_reachable", fresh().walk_reachable(src, |_, _| Ok(()))),
            (
                "missing_blocks",
                fresh().missing_blocks(src, [key]).map(drop),
            ),
            (
                "missing_blocks_for_remove",
                fresh().missing_blocks_for_remove(src, [key]).map(drop),
            ),
            (
                "covering_proof",
                fresh().covering_proof(src, [key]).map(drop),
            ),
            (
                "search_path",
                fresh().search_path(src, key, &mut Vec::new()).map(drop),
            ),
        ]
    }

    /// The reference implementation's "MST Interop Allowable Keys" cases.
    #[test]
    fn valid_keys_match_reference() {
        let long = format!("coll/{}", "a".repeat(1019));
        assert_eq!(long.len(), 1024);
        for key in [
            "coll/3jui7kd54zh2y",
            "coll/self",
            "coll/example.com",
            "com.example/rkey",
            "coll/~1.2-3_",
            "coll/dHJ1ZQ",
            "coll/pre:fix",
            "coll/_",
            &long,
        ] {
            assert!(is_valid_key(key), "{key:?} should be valid");
        }
        let too_long = format!("{long}a");
        for key in [
            "",
            "asdf",
            "nested/collection/asdf",
            "coll/",
            "/rkey",
            "coll/jalapeñoA",
            "coll/coöperative",
            "coll/abc💩",
            "coll/key$",
            "coll/key%",
            "coll/key(",
            "coll/key)",
            "coll/key+",
            "coll/key=",
            "coll/@handle",
            "coll/any space",
            "coll/#extra",
            "coll/any+space",
            "coll/number[3]",
            "coll/number(3)",
            "coll/dHJ1ZQ==",
            "coll/\"quote\"",
            &too_long,
        ] {
            assert!(!is_valid_key(key), "{key:?} should be invalid");
        }
    }

    /// Inserting an invalid key fails and changes nothing, as in the
    /// reference implementation.
    #[test]
    fn insert_rejects_invalid_keys() {
        let mut tree = DetachedTree::new();
        tree.insert(&NoBlocks, "coll/a".into(), test_value_cid())
            .unwrap();
        let before = tree.flush().unwrap().root;
        for key in ["", "a", "coll/", "coll/a b", "coll/a/b", "coll/é"] {
            assert!(
                matches!(
                    tree.insert(&NoBlocks, key.into(), test_value_cid()),
                    Err(MstError::InvalidKey(k)) if k == key
                ),
                "{key:?}"
            );
        }
        assert_eq!(tree.flush().unwrap().root, before);

        let mut tree = Tree::new(Box::new(MemBlockStore::new()));
        assert!(matches!(
            tree.insert("a".into(), test_value_cid()),
            Err(MstError::InvalidKey(_))
        ));
        assert!(tree.entries().unwrap().is_empty());
    }

    /// A node holding a key the reference implementation would reject does
    /// not load, on any path that reads it.
    #[test]
    fn nodes_with_invalid_keys_are_rejected() {
        for bad in ["a", "coll/a b", "coll/a/b", "coll/é"] {
            let mut blocks = std::collections::HashMap::new();
            let root = put_node(&mut blocks, None, &[(bad, None)]);
            for (op, result) in every_op(root, &blocks, "coll/z") {
                assert!(
                    matches!(&result, Err(MstError::InvalidNode(e)) if e.contains("invalid MST key")),
                    "{bad:?} {op}: {result:?}"
                );
            }
        }
    }

    /// Regression test: a tree that links one block from two places was
    /// accepted, so a handful of blocks could describe a tree exponentially
    /// larger, and listing one took exponential time. The reference
    /// implementation rejects shared subtrees (`mst-dag.test.ts`); so does
    /// loading here. A subtree with keys cannot fit two places in key order
    /// (the diamond below fails that check first); one without keys, a
    /// chain of empty nodes, can, and is rejected as linked twice.
    #[test]
    fn shared_subtrees_are_rejected() {
        let val = test_value_cid();
        // Two nodes per level, each linking both nodes of the level below:
        // 80 blocks describing 2^40 entries.
        let mut blocks = std::collections::HashMap::new();
        let mut level: Vec<Cid> = (0..2)
            .map(|j| {
                put_node(
                    &mut blocks,
                    None,
                    &[(&format!("com.example.lvl0/{j}"), None)],
                )
            })
            .collect();
        for i in 1..40 {
            level = (0..2)
                .map(|j| {
                    let key = format!("com.example.lvl{i}/{j}");
                    put_node(
                        &mut blocks,
                        Some(level[j]),
                        &[(&key, Some(level[(j + 1) % 2]))],
                    )
                })
                .collect();
        }
        let diamond = level[0];
        // One wide node whose entries all link one chain of empty nodes.
        let mut chain = put_node(&mut blocks, None, &[]);
        for _ in 0..50 {
            chain = put_node(&mut blocks, Some(chain), &[]);
        }
        let wide: Vec<String> = (0..50)
            .map(|i| format!("com.example.wide/{i:06}"))
            .collect();
        let entries: Vec<(&str, Option<Cid>)> =
            wide.iter().map(|k| (k.as_str(), Some(chain))).collect();
        let shared_chain = put_node(&mut blocks, None, &entries);
        // One node linking the same leaf on both sides of its entry.
        let leaf = put_node(&mut blocks, None, &[("com.example.a/1", None)]);
        let twice = put_node(&mut blocks, Some(leaf), &[("com.example.m/1", Some(leaf))]);

        for (op, result) in every_op(diamond, &blocks, "com.example.zzz/z") {
            assert!(
                matches!(result, Err(MstError::InvalidNode(_))),
                "{op}: {result:?}"
            );
        }
        for root in [shared_chain, twice] {
            for (op, result) in every_op(root, &blocks, "com.example.wide/000001") {
                if matches!(op, "get" | "search_path" | "missing_blocks" | "insert") {
                    // These follow one path, which never meets a block twice
                    // (and stops at the key).
                    continue;
                }
                assert!(
                    matches!(&result, Err(MstError::InvalidNode(e)) if e.contains("more than one place")),
                    "{op} on {root}: {result:?}"
                );
            }
        }

        // A failed load changes nothing, and the rest of the tree stays
        // usable.
        let outer = put_node(
            &mut blocks,
            None,
            &[("com.example.a/0", Some(shared_chain))],
        );
        let mut tree = DetachedTree::load(outer);
        assert!(tree.entries(&blocks).is_err());
        assert!(tree.entries(&blocks).is_err());
        assert_eq!(tree.get(&blocks, "com.example.a/0").unwrap(), Some(val));
        assert_eq!(tree.flush().unwrap().root, outer);
    }

    /// Regression test: every traversal recursed once per level with no
    /// bound, so a long chain of empty nodes overflowed the stack and
    /// aborted the process (a few thousand levels sufficed). No MST is
    /// deeper than `MAX_DEPTH` levels below its root.
    #[test]
    fn trees_deeper_than_any_mst_are_rejected() {
        let mut blocks = std::collections::HashMap::new();
        let bottom = "com.example.bottom/a";
        let mut chain = put_node(&mut blocks, None, &[(bottom, None)]);
        let mut at_limit = None;
        for depth in 1..=100_000 {
            chain = put_node(&mut blocks, Some(chain), &[]);
            if depth == MAX_DEPTH {
                at_limit = Some(chain);
            }
        }
        for (op, result) in every_op(chain, &blocks, bottom) {
            assert!(
                matches!(&result, Err(MstError::InvalidNode(e)) if e.contains("levels below the root")),
                "{op}: {result:?}"
            );
        }

        // A chain just as deep as an MST can be loads, and every operation
        // works on it.
        let at_limit = at_limit.unwrap();
        for (op, result) in every_op(at_limit, &blocks, bottom) {
            assert!(result.is_ok(), "{op}: {result:?}");
        }
        let mut tree = DetachedTree::load(at_limit);
        assert_eq!(tree.get(&blocks, bottom).unwrap(), Some(test_value_cid()));
        tree.insert(&blocks, "com.example.top/a".into(), test_value_cid())
            .unwrap();
        tree.remove(&blocks, bottom).unwrap();
        tree.flush().unwrap();
    }

    /// Regression test (the counterpart of atmos#15): removing the only
    /// entry of the topmost node holding one, below a root with no entries,
    /// left `trim_top` a subtree that was never loaded. The remove failed
    /// with an internal error and the tree became unusable, even with every
    /// block available.
    #[test]
    fn remove_below_entryless_root_loads_what_the_trim_reads() {
        let (_, k) = keys_at(2, 0, 1).remove(0);
        let (_, after) = keys_at(1, 0, 10).into_iter().find(|(_, a)| *a > k).unwrap();
        let mut blocks = std::collections::HashMap::new();
        let subtree = put_node(&mut blocks, None, &[(&after, None)]);
        let node = put_node(&mut blocks, None, &[(&k, Some(subtree))]);
        let root = put_node(&mut blocks, Some(node), &[]);

        let mut tree = DetachedTree::load(root);
        assert_eq!(tree.remove(&blocks, &k).unwrap(), Some(test_value_cid()));
        assert_eq!(tree.flush().unwrap().root, subtree);

        // Without the subtree the remove fails, changing nothing.
        let store = HidingStore {
            blocks,
            ..Default::default()
        };
        store.hidden.borrow_mut().insert(subtree);
        let mut tree = DetachedTree::load(root);
        assert_eq!(
            tree.missing_blocks_for_remove(&store, [k.as_str()])
                .unwrap(),
            [subtree]
        );
        assert!(matches!(
            tree.remove(&store, &k),
            Err(MstError::BlockNotFound(_))
        ));
        assert_eq!(tree.get(&store, &k).unwrap(), Some(test_value_cid()));
        assert_eq!(tree.flush().unwrap().root, root);
    }

    /// Regression test: a remove loaded the subtrees beside the removed key
    /// all the way down their facing edges, past the level where one side
    /// ends and the merge re-links the other without reading it, so it
    /// failed on blocks it never needed. Mirrors atmos
    /// TestRemoveOnPartialTreeLoadsOnlyWhatItNeeds.
    #[test]
    fn remove_reads_only_the_levels_the_merge_joins() {
        let (i, left) = keys_at(2, 0, 1).remove(0);
        let (i, top) = keys_at(3, i, 1).remove(0);
        let (_, tail) = keys_at(0, i, 1).remove(0);
        let keys = [left.clone(), top.clone(), tail.clone()];
        let (root, store) = partial(&keys);
        // Right of `top`: an empty height-2 node, then an empty height-1
        // node, then `tail`. The merge joins `left`'s node with the first
        // and re-links the second unread.
        let right = right_of(&store, root, &top);
        let below = decode_node_data(&store.blocks[&right])
            .unwrap()
            .left
            .unwrap();
        store.hidden.borrow_mut().insert(below);

        let mut tree = DetachedTree::load(root);
        assert!(
            tree.missing_blocks_for_remove(&store, [top.as_str()])
                .unwrap()
                .is_empty()
        );
        assert!(tree.remove(&store, &top).unwrap().is_some());
        assert_eq!(tree.flush().unwrap().root, canonical_root(&[left, tail]));
    }

    /// Regression test: updating a key that sits at another level than its
    /// height, as a tree built elsewhere may have it, placed the key by its
    /// height like a new one. That split the tree around the old entry,
    /// duplicating the key, or reached unloaded nodes and failed
    /// internally. An update now leaves the tree's shape alone, as the
    /// reference implementation's does.
    #[test]
    fn update_leaves_a_misplaced_key_in_place() {
        let (i, low) = keys_at(0, 0, 1).remove(0);
        let (_, high) = keys_at(1, i, 1).remove(0);
        let mut blocks = std::collections::HashMap::new();
        // `high` belongs a level up, but sits beside `low`.
        let root = put_node(&mut blocks, None, &[(&low, None), (&high, None)]);

        let new = Cid::compute(Codec::Drisl, b"new");
        let mut tree = DetachedTree::load(root);
        assert_eq!(
            tree.insert(&blocks, high.clone(), new).unwrap(),
            Some(test_value_cid())
        );
        assert_eq!(
            tree.entries(&NoBlocks).unwrap(),
            [(low.clone(), test_value_cid()), (high.clone(), new)]
        );
        let mut want = NodeData {
            left: None,
            entries: decode_node_data(&blocks[&root]).unwrap().entries,
        };
        want.entries[1].value = new;
        let want = Cid::compute(Codec::Drisl, &encode_node_data(&want).unwrap());
        assert_eq!(tree.flush().unwrap().root, want);
    }

    /// Regression test: only the order of keys within a node was checked,
    /// so a subtree holding keys outside the range its place allows loaded.
    /// Lookups then missed keys the tree held, and merging such a subtree
    /// on a remove built nodes whose keys were out of order, which this
    /// tree then wrote and refused to read back.
    #[test]
    fn subtrees_holding_keys_outside_their_place_are_rejected() {
        let mut blocks = std::collections::HashMap::new();
        // Right of "m", but holding "a".
        let stray = put_node(&mut blocks, None, &[("com.example.a/1", None)]);
        let root = put_node(&mut blocks, None, &[("com.example.m/1", Some(stray))]);

        for (op, result) in every_op(root, &blocks, "com.example.z/1") {
            if matches!(op, "get" | "missing_blocks" | "search_path") {
                assert!(
                    matches!(&result, Err(MstError::InvalidNode(e)) if e.contains("outside the range")),
                    "{op}: {result:?}"
                );
            }
        }
        // A remove that reads the stray subtree fails, changing nothing.
        let mut tree = DetachedTree::load(root);
        assert!(matches!(
            tree.remove(&blocks, "com.example.m/1"),
            Err(MstError::InvalidNode(_))
        ));
        assert_eq!(
            tree.get(&blocks, "com.example.m/1").unwrap(),
            Some(test_value_cid())
        );
        assert_eq!(tree.flush().unwrap().root, root);
    }

    /// Flushing an unchanged tree, or one changed and changed back, writes
    /// and retires nothing.
    #[test]
    fn flush_of_restored_tree_is_empty() {
        let base: std::collections::BTreeMap<String, Cid> = (0..200)
            .map(|i| (record_key(i * 2), test_value_cid()))
            .collect();
        let mut tree = DetachedTree::new();
        for (k, v) in &base {
            tree.insert(&NoBlocks, k.clone(), *v).unwrap();
        }
        let first = tree.flush().unwrap();
        let again = tree.flush().unwrap();
        assert_eq!(again.root, first.root);
        assert!(again.new_blocks.is_empty() && again.retired.is_empty());

        let other = Cid::compute(Codec::Drisl, b"other");
        // Add an odd key and update its even neighbour, then undo both.
        for i in (0..200).step_by(17) {
            tree.insert(&NoBlocks, record_key(2 * i + 1), other)
                .unwrap();
            tree.insert(&NoBlocks, record_key(2 * i), other).unwrap();
        }
        for i in (0..200).step_by(17) {
            tree.remove(&NoBlocks, &record_key(2 * i + 1)).unwrap();
            tree.insert(&NoBlocks, record_key(2 * i), test_value_cid())
                .unwrap();
        }
        let restored = tree.flush().unwrap();
        assert_eq!(restored.root, first.root);
        assert!(
            restored.new_blocks.is_empty(),
            "{:?}",
            restored.new_blocks.len()
        );
        assert!(restored.retired.is_empty());
    }

    /// The empty-tree node is written once, kept while the tree stays empty,
    /// and retired when the tree gains a key.
    #[test]
    fn empty_root_is_written_once_and_retired_with_the_first_key() {
        let mut tree = DetachedTree::new();
        let first = tree.flush().unwrap();
        assert_eq!(first.new_blocks.len(), 1);
        let empty = first.root;
        let again = tree.flush().unwrap();
        assert_eq!(again.root, empty);
        assert!(again.new_blocks.is_empty() && again.retired.is_empty());

        tree.insert(&NoBlocks, record_key(1), test_value_cid())
            .unwrap();
        let one = tree.flush().unwrap();
        assert_eq!(one.retired, [empty]);
        assert_eq!(one.new_blocks.len(), 1);

        tree.remove(&NoBlocks, &record_key(1)).unwrap();
        let emptied = tree.flush().unwrap();
        assert_eq!(emptied.root, empty);
        assert_eq!(emptied.retired, [one.root]);
        assert_eq!(emptied.new_blocks.len(), 1);
    }

    // --- search_path: the nodes a record proof carries ---

    /// The nodes `get` reads to find `key` in a tree it has not loaded, in
    /// the order read, and the value it finds. Proofs carried exactly these
    /// before they could come from a loaded tree.
    fn read_by_get(
        src: &dyn BlockSource,
        root: Cid,
        key: &str,
    ) -> (Vec<Cid>, Result<Option<Cid>, MstError>) {
        struct Reads<'a>(&'a dyn BlockSource, std::cell::RefCell<Vec<Cid>>);
        impl BlockSource for Reads<'_> {
            fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
                self.1.borrow_mut().push(*cid);
                self.0.read_block(cid)
            }
        }
        let reads = Reads(src, Default::default());
        let found = DetachedTree::load(root).get(&reads, key);
        (reads.1.into_inner(), found)
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(64))]

        /// `search_path` finds what `get` finds, through the nodes `get`
        /// reads from an unloaded tree, however much of the tree is in
        /// memory: none of it, the paths to some other keys, or all of it.
        #[test]
        fn search_path_is_the_path_get_reads(
            keys in proptest::collection::btree_set(0usize..3000, 0..600),
            loaded in proptest::collection::vec(0usize..3000, 0..30),
            queries in proptest::collection::vec(0usize..3000, 1..30),
        ) {
            let entries: std::collections::BTreeMap<String, Cid> = keys
                .iter()
                .map(|&i| (record_key(i), Cid::compute(Codec::Drisl, &i.to_be_bytes())))
                .collect();
            let write = canonical_write(&entries);
            let store: std::collections::HashMap<Cid, Vec<u8>> =
                write.new_blocks.into_iter().collect();

            let fresh = DetachedTree::load(write.root);
            let mut partial = DetachedTree::load(write.root);
            for i in loaded {
                partial.get(&store, &record_key(i)).unwrap();
            }
            let mut whole = DetachedTree::new();
            for (k, v) in &entries {
                whole.insert(&NoBlocks, k.clone(), *v).unwrap();
            }
            whole.flush().unwrap();

            for i in queries {
                let key = record_key(i);
                let (want, found) = read_by_get(&store, write.root, &key);
                let found = found.unwrap();
                proptest::prop_assert_eq!(found, entries.get(&key).copied());
                // The whole tree is in memory, so it reads nothing.
                let trees: [(&DetachedTree, &dyn BlockSource); 3] =
                    [(&fresh, &store), (&partial, &store), (&whole, &NoBlocks)];
                for (tree, src) in trees {
                    let mut path = vec![test_value_cid()];
                    proptest::prop_assert_eq!(tree.search_path(src, &key, &mut path).unwrap(), found);
                    proptest::prop_assert_eq!(path[0], test_value_cid());
                    proptest::prop_assert_eq!(&path[1..], &want[..]);
                }
            }
        }
    }

    #[test]
    fn search_path_of_empty_tree_is_the_empty_node() {
        let mut tree = DetachedTree::new();
        let empty = tree.flush().unwrap().root;
        let store: std::collections::HashMap<Cid, Vec<u8>> = [empty_node_block().unwrap()].into();
        let (want, _) = read_by_get(&store, empty, "com.example.record/a");
        assert_eq!(want, [empty]);
        for tree in [tree, DetachedTree::load(empty)] {
            let mut path = Vec::new();
            assert_eq!(
                tree.search_path(&store, "com.example.record/a", &mut path)
                    .unwrap(),
                None
            );
            assert_eq!(path, want);
        }
    }

    /// A path through nodes without CIDs could not be checked against a
    /// commit, so `search_path` refuses a tree with unflushed changes.
    #[test]
    fn search_path_refuses_unflushed_changes() {
        let unflushed = |tree: &DetachedTree| {
            let mut path = Vec::new();
            match tree.search_path(&NoBlocks, &record_key(1), &mut path) {
                Ok(_) => false,
                Err(MstError::Internal(msg)) if msg.contains("since its last flush") => {
                    assert!(path.is_empty());
                    true
                }
                Err(e) => panic!("{e}"),
            }
        };
        let mut tree = DetachedTree::new();
        assert!(unflushed(&tree), "never flushed");
        tree.flush().unwrap();
        assert!(!unflushed(&tree));

        // Two keys in one node, so removing one changes the root.
        let [(_, a), (_, b)] = keys_at(0, 0, 2).try_into().unwrap();
        tree.insert(&NoBlocks, a.clone(), test_value_cid()).unwrap();
        assert!(unflushed(&tree), "after an insert");
        let root = tree.flush().unwrap().root;
        let mut path = Vec::new();
        assert_eq!(
            tree.search_path(&NoBlocks, &a, &mut path).unwrap(),
            Some(test_value_cid())
        );
        assert_eq!(path, [root]);

        tree.insert(&NoBlocks, b.clone(), test_value_cid()).unwrap();
        tree.flush().unwrap();
        tree.remove(&NoBlocks, &b).unwrap();
        assert!(unflushed(&tree), "after a remove");
        assert_eq!(tree.flush().unwrap().root, root);
        assert!(!unflushed(&tree));
    }

    /// `search_path` rejects a malformed node, read below a loaded node or
    /// as the root, with the error loading it gives.
    #[test]
    fn search_path_rejects_malformed_nodes_like_get() {
        let val = test_value_cid();
        let entry = |prefix_len, key_suffix: &[u8]| EntryData {
            prefix_len,
            key_suffix: key_suffix.to_vec(),
            value: val,
            right: None,
        };
        let leaf = |entries| {
            encode_node_data(&NodeData {
                left: None,
                entries,
            })
            .unwrap()
        };
        let bad_blocks = [
            leaf(vec![entry(0, b"a/\xff")]),
            leaf(vec![entry(1, b"a/b")]),
            leaf(vec![entry(0, b"a/b"), entry(4, b"c")]),
            leaf(vec![entry(0, b"a/c"), entry(0, b"a/b")]),
            leaf(vec![entry(0, b"a/b"), entry(2, b"b")]),
            b"\xa1\x61x\x01".to_vec(),
            vec![0xff],
        ];
        for bad in bad_blocks {
            let bad_cid = Cid::compute(Codec::Drisl, &bad);
            let root = encode_node_data(&NodeData {
                left: Some(bad_cid),
                entries: vec![entry(0, b"m/m")],
            })
            .unwrap();
            let root_cid = Cid::compute(Codec::Drisl, &root);
            let store: std::collections::HashMap<Cid, Vec<u8>> =
                [(bad_cid, bad.clone()), (root_cid, root)].into();
            // Only the root is loaded: "n/n" sorts after its one entry.
            let mut partial = DetachedTree::load(root_cid);
            assert_eq!(partial.get(&store, "n/n").unwrap(), None);

            for (tree, top) in [(partial, root_cid), (DetachedTree::load(bad_cid), bad_cid)] {
                for key in ["a/a", "a/b", "a/bb", "a/z"] {
                    let (want_path, want) = read_by_get(&store, top, key);
                    let err = want.unwrap_err();
                    let mut path = Vec::new();
                    let got = tree.search_path(&store, key, &mut path).unwrap_err();
                    assert_eq!(format!("{got:?}"), format!("{err:?}"), "{bad:02x?} {key}");
                    assert_eq!(path, want_path);
                }
            }
        }

        // A node the source lacks.
        let missing = Cid::compute(Codec::Drisl, b"missing");
        let (_, want) = read_by_get(&NoBlocks, missing, "a/b");
        let got = DetachedTree::load(missing).search_path(&NoBlocks, "a/b", &mut Vec::new());
        assert!(matches!(&got, Err(MstError::BlockNotFound(c)) if *c == missing.to_string()));
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
    }
}
