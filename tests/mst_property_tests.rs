#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use shrike::cbor::{Cid, Codec};
use shrike::mst::{MemBlockStore, Tree, diff};

/// Generate unique, sorted AT Protocol-style keys.
fn gen_unique_keys(max_count: usize) -> impl Strategy<Value = Vec<String>> {
    prop::collection::hash_set("[a-z.]{3,15}/[a-z0-9]{5,13}", 1..max_count).prop_map(|set| {
        let mut keys: Vec<String> = set.into_iter().collect();
        keys.sort();
        keys
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(50))]

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
