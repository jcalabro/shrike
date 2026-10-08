#![no_main]
//! MST mutation invariants on arbitrary key sets:
//!   1. every key that inserts successfully is retrievable with its value;
//!   2. the root CID is independent of insertion order (a core MST property —
//!      the same logical key/value set must produce the same content address);
//!   3. the node blocks a flush writes load back to the same entries.
//! Structured input (a list of keys) drives real tree shapes: splits, merges,
//! shared prefixes, varying heights. Each input string is used as a key if it
//! is a valid MST key, and otherwise (after checking the tree refuses it)
//! turned into one by keeping its allowed characters as a record key.

use libfuzzer_sys::fuzz_target;
use shrike::Cid;
use shrike::cbor::Codec;
use shrike::mst::{DetachedTree, MemBlockStore, MstError, NoBlocks, Tree, is_valid_key};

fn val_for(key: &str) -> Cid {
    Cid::compute(Codec::Drisl, key.as_bytes())
}

fuzz_target!(|input: Vec<String>| {
    // Insert in given order, recording which keys were accepted.
    let mut tree = Tree::new(Box::new(MemBlockStore::new()));
    let mut keys = Vec::new();
    for k in input {
        if is_valid_key(&k) {
            keys.push(k);
            continue;
        }
        assert!(
            matches!(tree.insert(k.clone(), val_for(&k)), Err(MstError::InvalidKey(_))),
            "invalid key {k:?} accepted"
        );
        let rkey: String = k
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || "_~-:.".contains(*c))
            .take(1000)
            .collect();
        if !rkey.is_empty() {
            keys.push(format!("com.example/{rkey}"));
        }
    }
    let mut accepted: Vec<String> = Vec::new();
    for k in &keys {
        tree.insert(k.clone(), val_for(k))
            .expect("insert of a valid key must succeed");
        // Deduplicate: a re-insert overwrites, which is fine, but we only
        // want one copy in `accepted` for the order-independence check.
        if !accepted.iter().any(|a| a == k) {
            accepted.push(k.clone());
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

    // Invariant 3: the blocks a `DetachedTree` writes for the same set load
    // back to exactly that set, under the same root.
    let mut detached = DetachedTree::new();
    for k in &accepted {
        detached
            .insert(&NoBlocks, k.clone(), val_for(k))
            .expect("insert of an accepted key must succeed");
    }
    let write = detached.flush().expect("flush");
    assert_eq!(write.root, root1, "Tree and DetachedTree roots differ");
    let blocks: std::collections::HashMap<Cid, Vec<u8>> = write.new_blocks.into_iter().collect();
    let mut want: Vec<(String, Cid)> = accepted.iter().map(|k| (k.clone(), val_for(k))).collect();
    want.sort();
    let got = DetachedTree::load(write.root)
        .entries(&blocks)
        .expect("written blocks must load");
    assert_eq!(got, want, "written blocks load back to different entries");
});
