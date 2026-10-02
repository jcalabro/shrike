#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::rc::Rc;
use std::time::Duration;

use criterion::{BatchSize, BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use shrike::cbor::{Cid, Codec};
use shrike::mst::{
    BlockStore, DetachedTree, MemBlockStore, MstError, NoBlocks, Tree, height_for_key,
};

// ---------------------------------------------------------------------------
// Shared block store wrapper (MemBlockStore isn't Clone, so use Rc)
// ---------------------------------------------------------------------------

struct SharedStore(Rc<MemBlockStore>);

impl SharedStore {
    fn new() -> Self {
        SharedStore(Rc::new(MemBlockStore::new()))
    }

    fn another_ref(&self) -> Self {
        SharedStore(Rc::clone(&self.0))
    }
}

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

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate realistic AT Protocol keys: "collection/rkey" format.
fn gen_keys(n: usize) -> Vec<String> {
    let collections = [
        "app.bsky.feed.post",
        "app.bsky.feed.like",
        "app.bsky.feed.repost",
        "app.bsky.graph.follow",
        "app.bsky.actor.profile",
    ];
    (0..n)
        .map(|i| {
            let col = collections[i % collections.len()];
            format!("{col}/3k{i:010}")
        })
        .collect()
}

/// Pre-compute CIDs for keys (avoids measuring SHA-256 during insert benchmarks).
fn gen_cids(keys: &[String]) -> Vec<Cid> {
    keys.iter()
        .map(|k| Cid::compute(Codec::Drisl, k.as_bytes()))
        .collect()
}

/// Build a tree with N entries, persist it, return root CID + shared store.
fn build_persisted_tree(n: usize) -> (Cid, SharedStore, Vec<String>) {
    let store = SharedStore::new();
    let mut tree = Tree::new(Box::new(store.another_ref()));
    let keys = gen_keys(n);

    for key in &keys {
        let val = Cid::compute(Codec::Drisl, key.as_bytes());
        tree.insert(key.clone(), val).expect("insert");
    }

    let root = tree.root_cid().expect("root_cid");
    (root, store, keys)
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_height_for_key(c: &mut Criterion) {
    let mut group = c.benchmark_group("height_for_key");

    group.bench_function("typical_atproto_key", |b| {
        b.iter(|| {
            black_box(height_for_key(black_box("app.bsky.feed.post/3k0000000042")));
        });
    });

    group.finish();
}

fn bench_insert(c: &mut Criterion) {
    let mut group = c.benchmark_group("insert");

    for &n in &[100, 1000, 10_000] {
        let keys = gen_keys(n);
        let cids = gen_cids(&keys);

        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, _| {
            b.iter(|| {
                let store = MemBlockStore::new();
                let mut tree = Tree::new(Box::new(store));
                for (key, cid) in keys.iter().zip(cids.iter()) {
                    tree.insert(key.clone(), *cid).expect("insert");
                }
                black_box(&tree);
            });
        });
    }

    group.finish();
}

fn bench_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("get");

    for &n in &[100, 1000, 10_000] {
        let (root, store, keys) = build_persisted_tree(n);

        // Look up 10 keys spread across the tree (from cold/persisted state)
        let probe_keys: Vec<&str> = keys
            .iter()
            .step_by(keys.len() / 10)
            .map(|s| s.as_str())
            .collect();

        group.bench_with_input(
            BenchmarkId::new("10_lookups_cold", n),
            &probe_keys,
            |b, probes| {
                b.iter(|| {
                    let mut tree = Tree::load(Box::new(store.another_ref()), root);
                    for key in probes {
                        let result = tree.get(black_box(key)).expect("get");
                        black_box(result);
                    }
                });
            },
        );

        // Single lookup on a warm (already loaded) tree
        group.bench_with_input(BenchmarkId::new("single_lookup_warm", n), &n, |b, _| {
            let mut tree = Tree::load(Box::new(store.another_ref()), root);
            // Warm up — load the tree
            tree.entries().expect("warm up");
            let mid_key = &keys[keys.len() / 2];
            b.iter(|| {
                let result = tree.get(black_box(mid_key)).expect("get");
                black_box(result);
            });
        });
    }

    group.finish();
}

fn bench_root_cid(c: &mut Criterion) {
    let mut group = c.benchmark_group("root_cid");

    for &n in &[100, 1000] {
        let keys = gen_keys(n);
        let cids = gen_cids(&keys);

        group.bench_with_input(BenchmarkId::new("insert_then_commit", n), &n, |b, _| {
            b.iter(|| {
                let store = MemBlockStore::new();
                let mut tree = Tree::new(Box::new(store));
                for (key, cid) in keys.iter().zip(cids.iter()) {
                    tree.insert(key.clone(), *cid).expect("insert");
                }
                let root = tree.root_cid().expect("root_cid");
                black_box(root);
            });
        });
    }

    group.finish();
}

fn bench_entries(c: &mut Criterion) {
    let mut group = c.benchmark_group("entries");

    for &n in &[100, 1000, 10_000] {
        let (root, store, _) = build_persisted_tree(n);

        group.bench_with_input(BenchmarkId::new("walk_all", n), &n, |b, _| {
            b.iter(|| {
                let mut tree = Tree::load(Box::new(store.another_ref()), root);
                let entries = tree.entries().expect("entries");
                black_box(entries.len());
            });
        });
    }

    group.finish();
}

fn bench_remove(c: &mut Criterion) {
    let mut group = c.benchmark_group("remove");

    for &n in &[100, 1000] {
        let keys = gen_keys(n);
        let cids = gen_cids(&keys);
        let remove_indices: Vec<usize> = (0..keys.len()).step_by(10).collect();

        group.bench_with_input(BenchmarkId::new("10pct", n), &n, |b, _| {
            b.iter(|| {
                let store = MemBlockStore::new();
                let mut tree = Tree::new(Box::new(store));
                for (key, cid) in keys.iter().zip(cids.iter()) {
                    tree.insert(key.clone(), *cid).expect("insert");
                }
                for &i in &remove_indices {
                    tree.remove(&keys[i]).expect("remove");
                }
                black_box(&tree);
            });
        });
    }

    group.finish();
}

fn bench_node_codec(c: &mut Criterion) {
    let mut group = c.benchmark_group("node_codec");

    let (root, store, _) = build_persisted_tree(1000);
    let root_block = store.0.get_block(&root).expect("get root block");

    group.bench_function("decode_node", |b| {
        b.iter(|| {
            let nd = shrike::mst::node::decode_node_data(black_box(&root_block)).expect("decode");
            black_box(nd);
        });
    });

    let nd = shrike::mst::node::decode_node_data(&root_block).expect("decode");
    group.bench_function("encode_node", |b| {
        b.iter(|| {
            let encoded = shrike::mst::node::encode_node_data(black_box(&nd)).expect("encode");
            black_box(encoded);
        });
    });

    group.finish();
}

/// A fully loaded, flushed tree of `n` keys, as a long-lived tree is once a
/// bulk build or many commits have touched every node, plus its blocks.
fn loaded_tree(n: usize) -> (DetachedTree, Vec<String>, HashMap<Cid, Vec<u8>>) {
    let keys = gen_keys(n);
    let mut tree = DetachedTree::new();
    for key in &keys {
        let val = Cid::compute(Codec::Drisl, key.as_bytes());
        tree.insert(&NoBlocks, key.clone(), val).expect("insert");
    }
    let blocks = tree
        .flush()
        .expect("flush")
        .new_blocks
        .into_iter()
        .collect();
    (tree, keys, blocks)
}

/// One-key commits (a mutation then `flush`) against long-lived trees and
/// freshly loaded ones.
fn bench_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    let vals = [
        Cid::compute(Codec::Raw, b"a"),
        Cid::compute(Codec::Raw, b"b"),
    ];

    for &n in &[43_649, 200_000, 1_000_000] {
        let (mut tree, keys, blocks) = loaded_tree(n);
        let root = tree.flush().expect("flush").root;
        let key = keys[n / 2].clone();
        let new_key = format!("{key}x");
        if n > 100_000 {
            group.sample_size(10);
            group.measurement_time(Duration::from_secs(10));
        } else {
            group.sample_size(30);
            group.measurement_time(Duration::from_secs(5));
        }

        let mut flip = 0;
        group.bench_function(BenchmarkId::new("update_loaded", n), |b| {
            b.iter(|| {
                flip ^= 1;
                tree.insert(&NoBlocks, key.clone(), vals[flip])
                    .expect("insert");
                black_box(tree.flush().expect("flush"));
            });
        });

        group.bench_function(BenchmarkId::new("insert_remove_loaded", n), |b| {
            b.iter(|| {
                tree.insert(&NoBlocks, new_key.clone(), vals[0])
                    .expect("insert");
                black_box(tree.flush().expect("flush"));
                tree.remove(&NoBlocks, &new_key).expect("remove");
                black_box(tree.flush().expect("flush"));
            });
        });

        group.bench_function(BenchmarkId::new("update_fresh", n), |b| {
            b.iter(|| {
                let mut tree = DetachedTree::load(root);
                tree.insert(&blocks, key.clone(), vals[1]).expect("insert");
                black_box(tree.flush().expect("flush"));
            });
        });
    }

    group.finish();
}

/// Flush a tree built from scratch, where every node is dirty.
fn bench_flush_dirty(c: &mut Criterion) {
    let mut group = c.benchmark_group("flush_dirty");
    group.sample_size(20);

    for &n in &[1_000, 10_000, 100_000] {
        let keys = gen_keys(n);
        let cids = gen_cids(&keys);
        group.bench_with_input(BenchmarkId::new("all_nodes", n), &n, |b, _| {
            b.iter_batched(
                || {
                    let mut tree = DetachedTree::new();
                    for (key, cid) in keys.iter().zip(&cids) {
                        tree.insert(&NoBlocks, key.clone(), *cid).expect("insert");
                    }
                    tree
                },
                |mut tree| black_box(tree.flush().expect("flush")),
                BatchSize::LargeInput,
            );
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_height_for_key,
    bench_insert,
    bench_get,
    bench_root_cid,
    bench_entries,
    bench_remove,
    bench_node_codec,
    bench_commit,
    bench_flush_dirty,
);
criterion_main!(benches);
