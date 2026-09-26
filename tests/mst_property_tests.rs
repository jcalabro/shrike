#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::{BTreeMap, HashMap, HashSet};

use proptest::prelude::*;
use proptest::sample::Index;
use shrike::cbor::{Cid, Codec};
use shrike::mst::{
    BlockSource, DetachedTree, MemBlockStore, MstError, NoBlocks, Tree, TreeWrite, diff,
};

/// Generate unique, sorted AT Protocol-style keys.
fn gen_unique_keys(max_count: usize) -> impl Strategy<Value = Vec<String>> {
    prop::collection::hash_set("[a-z.]{3,15}/[a-z0-9]{5,13}", 1..max_count).prop_map(|set| {
        let mut keys: Vec<String> = set.into_iter().collect();
        keys.sort();
        keys
    })
}

/// One mutation: remove the pool key at the index, or set it to one of a
/// few values (so updates and same-value inserts both occur).
type OpSpec = (Index, bool, u8);

fn gen_ops(max: usize) -> impl Strategy<Value = Vec<OpSpec>> {
    prop::collection::vec((any::<Index>(), any::<bool>(), 0u8..3), 0..max)
}

fn op_value(v: u8) -> Cid {
    Cid::compute(Codec::Drisl, &[v])
}

/// Apply an op to the tree and, if it succeeds, to the model, checking the
/// tree reports the model's previous value.
fn apply_op(
    tree: &mut DetachedTree,
    src: &dyn BlockSource,
    model: &mut BTreeMap<String, Cid>,
    pool: &[String],
    &(idx, remove, v): &OpSpec,
) -> Result<(), MstError> {
    let key = idx.get(pool);
    let prev = if remove {
        tree.remove(src, key)?
    } else {
        tree.insert(src, key.clone(), op_value(v))?
    };
    let model_prev = if remove {
        model.remove(key)
    } else {
        model.insert(key.clone(), op_value(v))
    };
    assert_eq!(prev, model_prev, "wrong previous value for {key}");
    Ok(())
}

/// Build a tree from scratch and flush it. The MST is canonical, so this is
/// the only acceptable root and node block set for the entries.
fn canonical_write(model: &BTreeMap<String, Cid>) -> TreeWrite {
    let mut tree = DetachedTree::new();
    for (k, v) in model {
        tree.insert(&NoBlocks, k.clone(), *v).unwrap();
    }
    tree.flush().unwrap()
}

/// Serves blocks from a map but reports each read missing with
/// probability 1/4, from a deterministic seed.
struct FlakySource<'a> {
    blocks: &'a HashMap<Cid, Vec<u8>>,
    rng: Cell<u64>,
}

impl BlockSource for FlakySource<'_> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        let rng = self
            .rng
            .get()
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1);
        self.rng.set(rng);
        if (rng >> 33).is_multiple_of(4) {
            return Ok(None);
        }
        self.blocks.read_block(cid)
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

    #[test]
    fn flush_keeps_store_equal_to_reachable_blocks(
        pool in gen_unique_keys(60),
        batches in prop::collection::vec((gen_ops(30), any::<bool>()), 1..8),
    ) {
        // Persist each flush's new blocks and delete its retired ones. The
        // store must then hold exactly the canonical tree's node blocks:
        // nothing missing, nothing leaked. Reloading between batches makes
        // later batches load nodes from the store rather than reuse them.
        let mut store: HashMap<Cid, Vec<u8>> = HashMap::new();
        let mut model = BTreeMap::new();
        let mut tree = DetachedTree::new();
        for (ops, reload) in &batches {
            for op in ops {
                apply_op(&mut tree, &store, &mut model, &pool, op).unwrap();
            }
            let write = tree.flush().unwrap();
            for cid in &write.retired {
                prop_assert!(store.remove(cid).is_some(), "retired a block never stored");
            }
            for (cid, data) in write.new_blocks {
                prop_assert!(!write.retired.contains(&cid), "block both new and retired");
                store.insert(cid, data);
            }

            let canonical = canonical_write(&model);
            prop_assert_eq!(write.root, canonical.root);
            let stored: HashSet<Cid> = store.keys().copied().collect();
            let reachable: HashSet<Cid> = canonical.new_blocks.iter().map(|(c, _)| *c).collect();
            prop_assert_eq!(stored, reachable);

            if *reload {
                tree = DetachedTree::load(write.root);
            }
        }

        let mut reloaded = DetachedTree::load(tree.flush().unwrap().root);
        let entries: BTreeMap<String, Cid> = reloaded.entries(&store).unwrap().into_iter().collect();
        prop_assert_eq!(entries, model);
    }

    #[test]
    fn failed_ops_on_flaky_source_change_nothing(
        base in gen_unique_keys(80),
        pool in gen_unique_keys(40),
        ops in gen_ops(40),
        seed in any::<u64>(),
    ) {
        // Every op either succeeds or fails with no effect, so the final
        // tree matches a canonical build of just the ops that succeeded.
        let mut model: BTreeMap<String, Cid> =
            base.iter().map(|k| (k.clone(), op_value(0))).collect();
        let base_write = canonical_write(&model);
        let blocks: HashMap<Cid, Vec<u8>> = base_write.new_blocks.into_iter().collect();
        let flaky = FlakySource { blocks: &blocks, rng: Cell::new(seed) };

        let mut tree = DetachedTree::load(base_write.root);
        let pool: Vec<String> = pool.into_iter().chain(base).collect();
        for op in &ops {
            match apply_op(&mut tree, &flaky, &mut model, &pool, op) {
                Ok(()) | Err(MstError::BlockNotFound(_)) => {}
                Err(e) => return Err(TestCaseError::fail(format!("unexpected error: {e}"))),
            }
        }

        let write = tree.flush().unwrap();
        prop_assert_eq!(write.root, canonical_write(&model).root);
        // Blocks not yet loaded still come from the original set.
        let mut all = blocks.clone();
        all.extend(write.new_blocks);
        let entries: BTreeMap<String, Cid> = tree.entries(&all).unwrap().into_iter().collect();
        prop_assert_eq!(entries, model);
    }

    #[test]
    fn insertion_order_does_not_affect_root_cid(
        keys in gen_unique_keys(50),
        seed in any::<u64>(),
    ) {
        // Insert keys in sorted order
        let store1 = MemBlockStore::new();
        let mut tree1 = Tree::new(Box::new(store1));
        for key in &keys {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree1.insert(key.clone(), val).unwrap();
        }
        let root1 = tree1.root_cid().unwrap();

        // Insert same keys in a shuffled order (deterministic from seed)
        let mut shuffled = keys.clone();
        // Simple deterministic shuffle using seed
        let n = shuffled.len();
        if n > 1 {
            let mut rng = seed;
            for i in (1..n).rev() {
                rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
                let j = (rng >> 33) as usize % (i + 1);
                shuffled.swap(i, j);
            }
        }

        let store2 = MemBlockStore::new();
        let mut tree2 = Tree::new(Box::new(store2));
        for key in &shuffled {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree2.insert(key.clone(), val).unwrap();
        }
        let root2 = tree2.root_cid().unwrap();

        prop_assert_eq!(root1, root2, "root CID must be independent of insertion order");
    }

    #[test]
    fn diff_is_symmetric(
        keys_a in gen_unique_keys(30),
        keys_b in gen_unique_keys(30),
    ) {
        let store_a = MemBlockStore::new();
        let mut tree_a = Tree::new(Box::new(store_a));
        for key in &keys_a {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree_a.insert(key.clone(), val).unwrap();
        }
        tree_a.root_cid().unwrap();

        let store_b = MemBlockStore::new();
        let mut tree_b = Tree::new(Box::new(store_b));
        for key in &keys_b {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree_b.insert(key.clone(), val).unwrap();
        }
        tree_b.root_cid().unwrap();

        let d_ab = diff(&mut tree_a, &mut tree_b).unwrap();
        let d_ba = diff(&mut tree_b, &mut tree_a).unwrap();

        // added in A→B should be removed in B→A and vice versa
        prop_assert_eq!(d_ab.added.len(), d_ba.removed.len(),
            "added(A→B) count must equal removed(B→A) count");
        prop_assert_eq!(d_ab.removed.len(), d_ba.added.len(),
            "removed(A→B) count must equal added(B→A) count");
        prop_assert_eq!(d_ab.updated.len(), d_ba.updated.len(),
            "updated count must be same both ways");
    }

    #[test]
    fn insert_then_remove_all_yields_empty_root(
        keys in gen_unique_keys(50),
    ) {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for key in &keys {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree.insert(key.clone(), val).unwrap();
        }

        // Remove all keys
        for key in &keys {
            tree.remove(key).unwrap();
        }

        let entries = tree.entries().unwrap();
        prop_assert!(entries.is_empty(), "tree should be empty after removing all keys");
    }

    #[test]
    fn remove_matches_fresh_build(
        keys in gen_unique_keys(80),
        remove_mask in prop::collection::vec(any::<bool>(), 80),
    ) {
        // Removing keys from a built tree must land on the same root as
        // building the surviving keys from scratch: the MST is canonical.
        let mut tree = Tree::new(Box::new(MemBlockStore::new()));
        for key in &keys {
            tree.insert(key.clone(), Cid::compute(Codec::Drisl, key.as_bytes())).unwrap();
        }
        tree.root_cid().unwrap();

        let mut survivors = Tree::new(Box::new(MemBlockStore::new()));
        for (key, &remove) in keys.iter().zip(&remove_mask) {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            if remove {
                prop_assert_eq!(tree.remove(key).unwrap(), Some(val));
            } else {
                survivors.insert(key.clone(), val).unwrap();
            }
        }

        prop_assert_eq!(tree.root_cid().unwrap(), survivors.root_cid().unwrap());
    }

    #[test]
    fn entries_are_always_sorted(
        keys in gen_unique_keys(100),
    ) {
        let store = MemBlockStore::new();
        let mut tree = Tree::new(Box::new(store));
        for key in &keys {
            let val = Cid::compute(Codec::Drisl, key.as_bytes());
            tree.insert(key.clone(), val).unwrap();
        }

        let entries = tree.entries().unwrap();
        for window in entries.windows(2) {
            prop_assert!(window[0].0 < window[1].0,
                "entries must be sorted: {:?} should be < {:?}", window[0].0, window[1].0);
        }
    }
}
