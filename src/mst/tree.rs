use crate::cbor::{Cid, Codec};

use crate::mst::MstError;
use crate::mst::block_store::BlockStore;
use crate::mst::height::height_for_key;
use crate::mst::node::{EntryData, NodeData, decode_node_data, encode_node_data};

/// An in-memory MST entry: a key/value pair with optional right subtree.
struct Entry {
    key: String,
    val: Cid,
    right: Option<Box<Node>>,
}

/// An in-memory MST node.
struct Node {
    left: Option<Box<Node>>,
    entries: Vec<Entry>,
    /// Cached CID; only valid when `dirty` is false.
    cid: Option<Cid>,
    height: u8,
    dirty: bool,
}

/// AT Protocol Merkle Search Tree.
///
/// All operations (including reads like `get` and `walk`) take `&mut self`
/// because they may trigger lazy loading of child nodes from the block store.
pub struct Tree {
    root: Option<Box<Node>>,
    store: Box<dyn BlockStore>,
}

impl Tree {
    /// Create a new empty MST backed by the given store.
    pub fn new(store: Box<dyn BlockStore>) -> Self {
        Tree { root: None, store }
    }

    /// Load an MST from a root CID using the given store.
    /// Child nodes are loaded lazily on first access.
    pub fn load(store: Box<dyn BlockStore>, root: Cid) -> Self {
        Tree {
            root: Some(Box::new(Node {
                left: None,
                entries: Vec::new(),
                cid: Some(root),
                height: 0,
                dirty: false,
            })),
            store,
        }
    }

    /// Look up a key and return its value CID, or `None` if not found.
    pub fn get(&mut self, key: &str) -> Result<Option<Cid>, MstError> {
        match &mut self.root {
            None => Ok(None),
            Some(n) => Self::get_node(&*self.store, n, key),
        }
    }

    fn get_node(store: &dyn BlockStore, n: &mut Node, key: &str) -> Result<Option<Cid>, MstError> {
        ensure_loaded(store, n)?;

        for i in 0..n.entries.len() {
            if key < n.entries[i].key.as_str() {
                let child = if i == 0 {
                    &mut n.left
                } else {
                    &mut n.entries[i - 1].right
                };
                if let Some(child) = child {
                    return Self::get_node(store, child, key);
                }
                return Ok(None);
            }
            if key == n.entries[i].key {
                return Ok(Some(n.entries[i].val));
            }
        }

        // Check rightmost subtree.
        if !n.entries.is_empty() {
            let last = n.entries.len() - 1;
            if let Some(child) = &mut n.entries[last].right {
                return Self::get_node(store, child, key);
            }
        } else if let Some(left) = &mut n.left {
            return Self::get_node(store, left, key);
        }
        Ok(None)
    }

    /// Insert or update a key/value pair.
    pub fn insert(&mut self, key: String, cid: Cid) -> Result<(), MstError> {
        let h = height_for_key(&key);
        let old_root = self.root.take();
        let new_root = Self::insert_node(&*self.store, old_root, key, cid, h)?;
        self.root = Some(new_root);
        Ok(())
    }

    fn insert_node(
        store: &dyn BlockStore,
        n: Option<Box<Node>>,
        key: String,
        val: Cid,
        height: u8,
    ) -> Result<Box<Node>, MstError> {
        let Some(mut n) = n else {
            return Ok(Box::new(Node {
                left: None,
                entries: vec![Entry {
                    key,
                    val,
                    right: None,
                }],
                cid: None,
                height,
                dirty: true,
            }));
        };

        ensure_loaded(store, &mut n)?;

        if height > n.height {
            // Step up one level, wrapping the current node as a child.
            let child_height = n.height;
            let parent = Box::new(Node {
                left: Some(n),
                entries: Vec::new(),
                cid: None,
                height: child_height + 1,
                dirty: true,
            });
            return Self::insert_node(store, Some(parent), key, val, height);
        }

        if height < n.height {
            return Self::insert_below(store, n, key, val, height);
        }

        // Same height: insert into this node's entries.
        Self::insert_at_level(store, n, key, val)
    }

    /// Insert a key into a subtree of `n` (key height < n.height).
    fn insert_below(
        store: &dyn BlockStore,
        mut n: Box<Node>,
        key: String,
        val: Cid,
        height: u8,
    ) -> Result<Box<Node>, MstError> {
        let idx = find_child_index(&n, &key);

        let child = if idx == 0 {
            n.left.take()
        } else {
            n.entries[idx - 1].right.take()
        };

        // If no child exists and we're exactly one level above, create leaf directly.
        if child.is_none() && n.height - 1 == height {
            let new_child = Box::new(Node {
                left: None,
                entries: vec![Entry {
                    key,
                    val,
                    right: None,
                }],
                cid: None,
                height,
                dirty: true,
            });
            n.dirty = true;
            if idx == 0 {
                n.left = Some(new_child);
            } else {
                n.entries[idx - 1].right = Some(new_child);
            }
            return Ok(n);
        }

        let child = match child {
            Some(c) => Some(c),
            None => Some(Box::new(Node {
                left: None,
                entries: Vec::new(),
                cid: None,
                height: n.height - 1,
                dirty: true,
            })),
        };

        let new_child = Self::insert_node(store, child, key, val, height)?;

        n.dirty = true;
        if idx == 0 {
            n.left = Some(new_child);
        } else {
            n.entries[idx - 1].right = Some(new_child);
        }
        Ok(n)
    }

    /// Insert a key at the same height level as `n`.
    fn insert_at_level(
        store: &dyn BlockStore,
        mut n: Box<Node>,
        key: String,
        val: Cid,
    ) -> Result<Box<Node>, MstError> {
        // Binary search for insertion point.
        let i = n
            .entries
            .binary_search_by(|e| e.key.as_str().cmp(&key))
            .unwrap_or_else(|x| x);

        // Check for update of existing key.
        if i < n.entries.len() && n.entries[i].key == key {
            n.entries[i].val = val;
            n.dirty = true;
            return Ok(n);
        }

        // Split the child between entries[i-1] and entries[i].
        let child_to_split = if i == 0 {
            n.left.take()
        } else {
            n.entries[i - 1].right.take()
        };

        let (left, right) = Self::split_node(store, child_to_split, &key)?;

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

        n.dirty = true;
        Ok(n)
    }

    /// Split a node at key, returning (left, right) subtrees.
    /// Left contains everything < key, right contains everything > key.
    fn split_node(
        store: &dyn BlockStore,
        n: Option<Box<Node>>,
        key: &str,
    ) -> Result<(Option<Node>, Option<Node>), MstError> {
        let Some(mut n) = n else {
            return Ok((None, None));
        };

        ensure_loaded(store, &mut n)?;

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
                let (child_left, child_right) = Self::split_node(store, last_child, key)?;
                if let Some(last) = n.entries.last_mut() {
                    last.right = child_left.map(Box::new);
                } else {
                    n.left = child_left.map(Box::new);
                }
                n.dirty = true;
                let right_node = child_right.map(|cr| Node {
                    left: Some(Box::new(cr)),
                    entries: Vec::new(),
                    cid: None,
                    height: n.height,
                    dirty: true,
                });
                Ok((trim_node(*n), trim_node_opt(right_node)))
            }
            Some(0) => {
                // All entries >= key. The left child may still need splitting.
                let left_child = n.left.take();
                let (child_left, child_right) = Self::split_node(store, left_child, key)?;
                n.left = child_right.map(Box::new);
                n.dirty = true;
                let left_node = child_left.map(|cl| Node {
                    left: Some(Box::new(cl)),
                    entries: Vec::new(),
                    cid: None,
                    height: n.height,
                    dirty: true,
                });
                Ok((trim_node_opt(left_node), trim_node(*n)))
            }
            Some(split_i) => {
                // Split in the middle.
                let right_entries: Vec<Entry> = n.entries.drain(split_i..).collect();
                let left_entries = std::mem::take(&mut n.entries);

                let mut left_node = Node {
                    left: n.left.take(),
                    entries: left_entries,
                    cid: None,
                    height: n.height,
                    dirty: true,
                };

                // The child between the two halves needs recursive splitting.
                // split_i > 0 guarantees left_entries is non-empty.
                let last = left_node
                    .entries
                    .last_mut()
                    .ok_or_else(|| MstError::Internal("split produced empty left".into()))?;
                let mid_child = last.right.take();
                let (mid_left, mid_right) = Self::split_node(store, mid_child, key)?;
                let last = left_node
                    .entries
                    .last_mut()
                    .ok_or_else(|| MstError::Internal("split produced empty left".into()))?;
                last.right = mid_left.map(Box::new);

                let right_node = Node {
                    left: mid_right.map(Box::new),
                    entries: right_entries,
                    cid: None,
                    height: n.height,
                    dirty: true,
                };

                Ok((trim_node(left_node), trim_node(right_node)))
            }
        }
    }

    /// Remove a key from the tree. Returns the removed value CID, or `None`.
    pub fn remove(&mut self, key: &str) -> Result<Option<Cid>, MstError> {
        let Some(root) = self.root.take() else {
            return Ok(None);
        };
        let (new_root, removed) = Self::remove_node(&*self.store, root, key)?;
        self.root = trim_top(&*self.store, new_root)?;
        Ok(removed)
    }

    fn remove_node(
        store: &dyn BlockStore,
        mut n: Box<Node>,
        key: &str,
    ) -> Result<(Option<Box<Node>>, Option<Cid>), MstError> {
        ensure_loaded(store, &mut n)?;

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

                let merged = Self::merge_nodes(store, left_child, right_child)?;

                n.entries.remove(i);

                if i == 0 {
                    n.left = merged;
                } else {
                    n.entries[i - 1].right = merged;
                }
                n.dirty = true;

                if n.entries.is_empty() {
                    return Ok((n.left, Some(removed_val)));
                }
                return Ok((Some(n), Some(removed_val)));
            }

            if key < n.entries[i].key.as_str() {
                // Descend into left child.
                let child = if i == 0 {
                    n.left.take()
                } else {
                    n.entries[i - 1].right.take()
                };
                if let Some(child) = child {
                    let (new_child, removed) = Self::remove_node(store, child, key)?;
                    if removed.is_some() {
                        n.dirty = true;
                    }
                    if i == 0 {
                        n.left = new_child;
                    } else {
                        n.entries[i - 1].right = new_child;
                    }
                    return Ok((Some(n), removed));
                }
                return Ok((Some(n), None));
            }
        }

        // Key > all entries, descend into rightmost child.
        if !n.entries.is_empty() {
            let last = n.entries.len() - 1;
            let child = n.entries[last].right.take();
            if let Some(child) = child {
                let (new_child, removed) = Self::remove_node(store, child, key)?;
                if removed.is_some() {
                    n.dirty = true;
                }
                n.entries[last].right = new_child;
                return Ok((Some(n), removed));
            }
        } else if let Some(left) = n.left.take() {
            let (new_child, removed) = Self::remove_node(store, left, key)?;
            if removed.is_some() {
                n.dirty = true;
            }
            n.left = new_child;
            return Ok((Some(n), removed));
        }
        Ok((Some(n), None))
    }

    /// Merge two sibling subtrees back together.
    fn merge_nodes(
        store: &dyn BlockStore,
        left: Option<Box<Node>>,
        right: Option<Box<Node>>,
    ) -> Result<Option<Box<Node>>, MstError> {
        let (mut left, mut right) = match (left, right) {
            (None, r) => return Ok(r),
            (l, None) => return Ok(l),
            (Some(l), Some(r)) => (l, r),
        };

        ensure_loaded(store, &mut left)?;
        ensure_loaded(store, &mut right)?;

        // Merge the rightmost child of left with the left child of right.
        let left_right_child = if let Some(last) = left.entries.last_mut() {
            last.right.take()
        } else {
            left.left.take()
        };

        let merged = Self::merge_nodes(store, left_right_child, right.left.take())?;

        if let Some(last) = left.entries.last_mut() {
            last.right = merged;
        } else {
            left.left = merged;
        }

        // Append right's entries to left.
        left.entries.append(&mut right.entries);
        left.dirty = true;

        Ok(Some(left))
    }

    /// Compute and return the root CID of the tree.
    /// Serializes all dirty nodes to the block store.
    pub fn root_cid(&mut self) -> Result<Cid, MstError> {
        match self.root.take() {
            None => {
                // Empty tree: encode an empty node.
                let nd = NodeData {
                    left: None,
                    entries: vec![],
                };
                let data = encode_node_data(&nd)?;
                let cid = Cid::compute(Codec::Drisl, &data);
                self.store.put_block(cid, data)?;
                Ok(cid)
            }
            Some(mut root) => {
                let cid = Self::write_node(&*self.store, &mut root)?;
                self.root = Some(root);
                Ok(cid)
            }
        }
    }

    /// Recursively write dirty nodes to the store. Returns the CID.
    fn write_node(store: &dyn BlockStore, n: &mut Node) -> Result<Cid, MstError> {
        if let (false, Some(cid)) = (n.dirty, n.cid) {
            return Ok(cid);
        }

        ensure_loaded(store, n)?;

        // Recursively write children first.
        if let Some(left) = &mut n.left {
            Self::write_node(store, left)?;
        }
        for entry in &mut n.entries {
            if let Some(right) = &mut entry.right {
                Self::write_node(store, right)?;
            }
        }

        let nd = Self::node_to_data(n)?;
        let data = encode_node_data(&nd)?;
        let cid = Cid::compute(Codec::Drisl, &data);
        store.put_block(cid, data)?;
        n.cid = Some(cid);
        n.dirty = false;
        Ok(cid)
    }

    /// Convert an in-memory node to the serializable NodeData.
    fn node_to_data(n: &Node) -> Result<NodeData, MstError> {
        let mut nd = NodeData {
            left: None,
            entries: Vec::with_capacity(n.entries.len()),
        };

        if let Some(left) = &n.left {
            nd.left = Some(left.cid.ok_or_else(|| {
                MstError::Internal("left node CID not computed; call write_node first".into())
            })?);
        }

        let mut prev_key: &str = "";
        for e in &n.entries {
            let prefix_len = shared_prefix_len(prev_key, &e.key);
            let mut ed = EntryData {
                prefix_len,
                key_suffix: e.key.as_bytes()[prefix_len..].to_vec(),
                value: e.val,
                right: None,
            };
            if let Some(right) = &e.right {
                ed.right = Some(right.cid.ok_or_else(|| {
                    MstError::Internal("right node CID not computed; call write_node first".into())
                })?);
            }
            nd.entries.push(ed);
            prev_key = &e.key;
        }

        Ok(nd)
    }

    /// Collect all key/value pairs in sorted order into a Vec.
    pub fn entries(&mut self) -> Result<Vec<(String, Cid)>, MstError> {
        let mut result = Vec::new();
        if let Some(root) = &mut self.root {
            Self::walk_node(&*self.store, root, &mut result)?;
        }
        Ok(result)
    }

    /// Walk the tree in sorted order, calling `f` for each entry.
    pub fn walk<F>(&mut self, mut f: F) -> Result<(), MstError>
    where
        F: FnMut(&str, Cid) -> Result<(), MstError>,
    {
        if let Some(root) = &mut self.root {
            Self::walk_node_fn(&*self.store, root, &mut f)?;
        }
        Ok(())
    }

    fn walk_node(
        store: &dyn BlockStore,
        n: &mut Node,
        result: &mut Vec<(String, Cid)>,
    ) -> Result<(), MstError> {
        ensure_loaded(store, n)?;

        if let Some(left) = &mut n.left {
            Self::walk_node(store, left, result)?;
        }

        for entry in &mut n.entries {
            result.push((entry.key.clone(), entry.val));
            if let Some(right) = &mut entry.right {
                Self::walk_node(store, right, result)?;
            }
        }
        Ok(())
    }

    fn walk_node_fn<F>(store: &dyn BlockStore, n: &mut Node, f: &mut F) -> Result<(), MstError>
    where
        F: FnMut(&str, Cid) -> Result<(), MstError>,
    {
        ensure_loaded(store, n)?;

        if let Some(left) = &mut n.left {
            Self::walk_node_fn(store, left, f)?;
        }

        for entry in &mut n.entries {
            f(&entry.key, entry.val)?;
            if let Some(right) = &mut entry.right {
                Self::walk_node_fn(store, right, f)?;
            }
        }
        Ok(())
    }
}

/// Collapse an empty-passthrough root chain after a remove.
///
/// When `remove` deletes the last entry from a multi-level root it leaves
/// behind a non-`None`, entries-empty node whose only useful state lives
/// on its left child. This walks down that chain until it finds a node
/// with real entries (or runs out of nodes).
///
/// Each candidate must be loaded from blocks before we test its emptiness:
/// an unloaded stub looks like `(entries: [], left: None)` at the in-memory
/// level even when its CID points at a real subtree. Without
/// `ensure_loaded`, the loop would see `left.is_some() == false`, replace
/// the root with `None`, and silently drop every record below the removed
/// key.
fn trim_top(
    store: &dyn BlockStore,
    mut n: Option<Box<Node>>,
) -> Result<Option<Box<Node>>, MstError> {
    while let Some(mut node) = n {
        ensure_loaded(store, &mut node)?;
        if !node.entries.is_empty() {
            return Ok(Some(node));
        }
        n = node.left;
    }
    Ok(None)
}

/// Ensure a node is loaded from the block store.
#[inline]
fn ensure_loaded(store: &dyn BlockStore, n: &mut Node) -> Result<(), MstError> {
    if n.dirty || !n.entries.is_empty() || n.left.is_some() {
        return Ok(()); // already loaded or newly created
    }
    let Some(cid) = n.cid else {
        return Ok(()); // empty node
    };

    let data = store.get_block(&cid)?;
    let nd = decode_node_data(&data)?;
    populate_node(n, &nd)?;

    Ok(())
}

/// Populate a node's in-memory fields from decoded `NodeData`.
///
/// Height handling is subtle. In the canonical MST every parent-child edge
/// spans exactly one level, but on-disk node blocks do not record their
/// height — it is recomputed from a key. For nodes with at least one
/// entry that's straightforward (`height_for_key(entries[0])`). For
/// empty-entries intermediates — the height-fillers the canonical shape
/// requires whenever a parent and its only descendant span >1 level —
/// there is no key to hash, so we rely on the parent having seeded
/// `n.height` before calling `ensure_loaded`. After we know this node's
/// own height we propagate `height - 1` down into each newly-created
/// child stub so the chain stays correct as subsequent `ensure_loaded`
/// calls walk further. atproto/indigo handles the same case via a
/// post-load `ensureHeights` walk; we propagate eagerly during the
/// existing lazy load instead.
fn populate_node(n: &mut Node, nd: &NodeData) -> Result<(), MstError> {
    if let Some(left_cid) = nd.left {
        n.left = Some(Box::new(Node {
            left: None,
            entries: Vec::new(),
            cid: Some(left_cid),
            height: 0,
            dirty: false,
        }));
    }

    let mut key_buf = Vec::new();
    n.entries = Vec::with_capacity(nd.entries.len());
    let mut prev_key: Option<String> = None;
    for ed in &nd.entries {
        // The prefix length must not exceed the previous key's length. For the
        // first entry this means prefix_len must be 0 (full key). Vec::truncate
        // is a silent no-op when the requested length exceeds the current
        // length, so without this guard a malformed/hostile node block would
        // silently reconstruct the WRONG key — silent corruption of a
        // content-addressed structure. Reject instead. (atmos mst.go:886-888)
        if ed.prefix_len > key_buf.len() {
            return Err(MstError::InvalidNode(format!(
                "entry prefix length {} exceeds previous key length {}",
                ed.prefix_len,
                key_buf.len()
            )));
        }
        key_buf.truncate(ed.prefix_len);
        key_buf.extend_from_slice(&ed.key_suffix);
        let key = String::from_utf8(key_buf.clone())
            .map_err(|_| MstError::InvalidNode("key is not valid UTF-8".into()))?;

        // Entries within a node must be in strictly ascending key order; the
        // whole tree's get/diff/binary-search logic relies on it. A block whose
        // entries are out of order (malformed or hostile) must be rejected, not
        // loaded as-is. (atmos mst.go:894-896)
        if let Some(prev) = &prev_key
            && key.as_str() <= prev.as_str()
        {
            return Err(MstError::InvalidNode(format!(
                "entry key {key:?} is not greater than previous key {prev:?}"
            )));
        }

        let right = ed.right.map(|right_cid| {
            Box::new(Node {
                left: None,
                entries: Vec::new(),
                cid: Some(right_cid),
                height: 0,
                dirty: false,
            })
        });

        n.entries.push(Entry {
            key: key.clone(),
            val: ed.value,
            right,
        });
        prev_key = Some(key);
    }

    // Derive height from entries when we have one; otherwise preserve the
    // parent-seeded height for empty intermediates.
    if let Some(first) = n.entries.first() {
        n.height = height_for_key(&first.key);
    }

    // Propagate height down to freshly-built child stubs. They were
    // constructed above with a placeholder of 0 because n.height was not
    // yet known. This is what keeps empty intermediates loadable: when a
    // later ensure_loaded reaches such a child and finds entries empty,
    // the height we seeded here is the only signal it has.
    let child_height = n.height.saturating_sub(1);
    if let Some(left) = &mut n.left {
        left.height = child_height;
    }
    for entry in &mut n.entries {
        if let Some(right) = &mut entry.right {
            right.height = child_height;
        }
    }

    Ok(())
}

/// Find the entry index where key would be found.
/// Returns 0 if key < all entries (meaning use n.left).
/// Returns i if key should be in the subtree after entries[i-1].
fn find_child_index(n: &Node, key: &str) -> usize {
    n.entries
        .binary_search_by(|e| e.key.as_str().cmp(key))
        .unwrap_or_else(|x| x)
}

/// Return the length of the common prefix between two strings.
#[inline]
fn shared_prefix_len(a: &str, b: &str) -> usize {
    a.as_bytes()
        .iter()
        .zip(b.as_bytes().iter())
        .take_while(|(x, y)| x == y)
        .count()
}

/// Remove completely empty nodes (no entries and no children).
fn trim_node(n: Node) -> Option<Node> {
    if n.entries.is_empty() && n.left.is_none() {
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
    use std::rc::Rc;

    use super::*;
    use crate::mst::block_store::MemBlockStore;

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
        tree.insert("key".to_string(), cid).unwrap();
        let removed = tree.remove("key").unwrap();
        assert_eq!(removed, Some(cid));
        assert_eq!(tree.get("key").unwrap(), None);
    }

    #[test]
    fn insert_update() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        let val1 = Cid::compute(Codec::Drisl, b"v1");
        let val2 = Cid::compute(Codec::Drisl, b"v2");
        tree.insert("key".to_string(), val1).unwrap();
        assert_eq!(tree.get("key").unwrap(), Some(val1));
        tree.insert("key".to_string(), val2).unwrap();
        assert_eq!(tree.get("key").unwrap(), Some(val2));
    }

    #[test]
    fn entries_sorted() {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for key in ["c", "a", "b"] {
            tree.insert(key.to_string(), Cid::compute(Codec::Raw, key.as_bytes()))
                .unwrap();
        }
        let entries = tree.entries().unwrap();
        assert_eq!(entries[0].0, "a");
        assert_eq!(entries[1].0, "b");
        assert_eq!(entries[2].0, "c");
    }

    #[test]
    fn root_cid_deterministic_regardless_of_insertion_order() {
        let keys: Vec<(&str, &[u8])> = vec![("a", b"va"), ("b", b"vb"), ("c", b"vc")];

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
        for key in ["a", "b", "c"] {
            tree.insert(key.to_string(), val).unwrap();
        }
        for key in ["a", "b", "c"] {
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
        tree.insert("a".to_string(), val).unwrap();
        let removed = tree.remove("nonexistent").unwrap();
        assert!(removed.is_none());
        assert!(tree.get("a").unwrap().is_some());
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
        for key in ["a", "b", "c"] {
            tree.insert(key.to_string(), val).unwrap();
        }
        let root_cid = tree.root_cid().unwrap();

        // Walk to verify entries are correct
        let entries = tree.entries().unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0, "a");
        assert_eq!(entries[1].0, "b");
        assert_eq!(entries[2].0, "c");

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
}
