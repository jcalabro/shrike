#![no_main]
//! Commit inversion, as a sync verifier does it: apply a batch of ops to an
//! arbitrary tree, then undo them (in reverse, starting from the new root)
//! with only the blocks a producer ships, and land on the old root. Two
//! producer shapes must both suffice:
//!   1. indigo-style: the rewritten nodes plus covering proofs for creates
//!      and deletes only (an update carries just its root-to-key path);
//!   2. reference-style: the rewritten nodes plus covering proofs for every op.

use std::collections::{BTreeMap, HashMap};

use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use shrike::Cid;
use shrike::cbor::Codec;
use shrike::mst::{DetachedTree, NoBlocks};

#[derive(Arbitrary, Debug)]
struct Input {
    base: Vec<u16>,
    /// (key, delete): a create or update, or a delete if the key exists.
    ops: Vec<(u16, bool)>,
}

/// A dense key space, so trees reach several levels and ops hit existing keys.
fn key(i: u16) -> String {
    format!("com.example.k/{:04}", i % 4096)
}

enum Op {
    Create(String),
    Update(String, Cid),
    Delete(String, Cid),
}

fn invert(root: Cid, ops: &[Op], blocks: &HashMap<Cid, Vec<u8>>) -> Cid {
    let mut tree = DetachedTree::load(root);
    for op in ops.iter().rev() {
        match op {
            Op::Create(k) => {
                tree.remove(blocks, k).expect("undo create");
            }
            Op::Update(k, prev) | Op::Delete(k, prev) => {
                tree.insert(blocks, k.clone(), *prev)
                    .expect("undo update/delete");
            }
        }
    }
    tree.flush().expect("flush inverted tree").root
}

fuzz_target!(|input: Input| {
    let old = Cid::compute(Codec::Drisl, b"old");
    let new = Cid::compute(Codec::Drisl, b"new");
    let base: BTreeMap<String, Cid> = input
        .base
        .iter()
        .take(512)
        .map(|&i| (key(i), old))
        .collect();

    let mut tree = DetachedTree::new();
    for (k, v) in &base {
        tree.insert(&NoBlocks, k.clone(), *v).expect("build");
    }
    let base_write = tree.flush().expect("flush base");
    let mut store: HashMap<Cid, Vec<u8>> = base_write.new_blocks.into_iter().collect();

    // Each key at most once per commit, as the firehose requires.
    let ops: BTreeMap<String, bool> = input
        .ops
        .iter()
        .take(32)
        .map(|&(i, d)| (key(i), d))
        .collect();
    let mut done = Vec::new();
    for (k, delete) in ops {
        match (base.get(&k), delete) {
            (None, _) => {
                tree.insert(&store, k.clone(), new).expect("create");
                done.push(Op::Create(k));
            }
            (Some(&prev), false) => {
                tree.insert(&store, k.clone(), new).expect("update");
                done.push(Op::Update(k, prev));
            }
            (Some(&prev), true) => {
                tree.remove(&store, &k).expect("delete");
                done.push(Op::Delete(k, prev));
            }
        }
    }
    let write = tree.flush().expect("flush commit");
    store.extend(write.new_blocks.iter().cloned());
    let rewritten: HashMap<Cid, Vec<u8>> = write.new_blocks.into_iter().collect();

    let with_proofs = |tree: &mut DetachedTree, keys: Vec<&str>| {
        let mut blocks = rewritten.clone();
        for cid in tree.covering_proof(&store, keys).expect("covering proof") {
            blocks.insert(cid, store[&cid].clone());
        }
        blocks
    };

    let indigo = with_proofs(
        &mut tree,
        done.iter()
            .filter_map(|op| match op {
                Op::Create(k) | Op::Delete(k, _) => Some(k.as_str()),
                Op::Update(..) => None,
            })
            .collect(),
    );
    assert_eq!(
        invert(write.root, &done, &indigo),
        base_write.root,
        "indigo-style"
    );

    let reference = with_proofs(
        &mut tree,
        done.iter()
            .map(|op| match op {
                Op::Create(k) | Op::Update(k, _) | Op::Delete(k, _) => k.as_str(),
            })
            .collect(),
    );
    assert_eq!(
        invert(write.root, &done, &reference),
        base_write.root,
        "reference-style"
    );
});
