#![no_main]
//! MST mutation invariants on arbitrary key sets:
//!   1. every key that inserts successfully is retrievable with its value;
//!   2. the root CID is independent of insertion order (a core MST property —
//!      the same logical key/value set must produce the same content address).
//! Structured input (a list of keys) drives real tree shapes: splits, merges,
//! shared prefixes, varying heights.

use libfuzzer_sys::fuzz_target;
use shrike::Cid;
use shrike::cbor::Codec;
use shrike::mst::{MemBlockStore, Tree};

fn val_for(key: &str) -> Cid {
    Cid::compute(Codec::Drisl, key.as_bytes())
}

fuzz_target!(|keys: Vec<String>| {
    // Insert in given order, recording which keys were accepted.
    let mut tree = Tree::new(Box::new(MemBlockStore::new()));
    let mut accepted: Vec<String> = Vec::new();
    for k in &keys {
        if tree.insert(k.clone(), val_for(k)).is_ok() {
            // Deduplicate: a re-insert overwrites, which is fine, but we only
            // want one copy in `accepted` for the order-independence check.
            if !accepted.iter().any(|a| a == k) {
                accepted.push(k.clone());
            }
        }
    }

    // Invariant 1: every accepted key is retrievable with the right value.
    for k in &accepted {
        let got = tree
            .get(k)
            .expect("get must not error after successful insert");
        assert_eq!(
            got,
            Some(val_for(k)),
            "key {k:?} not retrievable (or wrong value) after insert"
        );
    }

    let root1 = tree.root_cid().expect("root_cid");

    // Invariant 2: inserting the same set in reverse order yields the same root.
    let mut tree2 = Tree::new(Box::new(MemBlockStore::new()));
    for k in accepted.iter().rev() {
        tree2
            .insert(k.clone(), val_for(k))
            .expect("re-insert of an already-accepted key must succeed");
    }
    let root2 = tree2.root_cid().expect("root_cid");
    assert_eq!(
        root1,
        root2,
        "MST root CID depends on insertion order ({} keys)",
        accepted.len()
    );
});
