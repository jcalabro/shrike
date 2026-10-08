//! A model check of `DetachedTree` on trees it did not build: trees of any
//! shape that keep their keys in order, as other implementations may write
//! them, and hostile trees that link a block twice, misplace a key, run
//! deeper than any MST can, or lack blocks. Shared by `mst_property_tests`
//! and the `mst_hostile_tree` fuzz target.
//!
//! Whatever the tree, no operation may panic or report an internal error,
//! an operation that fails must leave the tree as it was, and once
//! `missing_blocks` or `missing_blocks_for_remove` reports nothing, the
//! operation must need no blocks. On a tree that keeps its keys in order,
//! every operation must also agree with a map, and what a flush writes must
//! load back.

use std::collections::{BTreeMap, HashMap};

use shrike::cbor::{Cid, Codec};
use shrike::mst::node::{EntryData, NodeData, encode_node_data};
use shrike::mst::{BlockSource, DetachedTree, MstError, NoBlocks};

/// One case, as plain data that proptest and the fuzzer can both produce.
#[derive(Debug, Clone)]
pub struct Case {
    /// Seeds the tree's shape and any damage to it.
    pub seed: u64,
    /// How many keys of the pool the tree holds: under 8 if below 128,
    /// so that small trees, where the root's shape matters most, are common.
    pub keys: u8,
    /// How the tree is built or damaged (modulo 8): 0-1 by inserting
    /// keys, 2-4 any ordered shape, 5 under a chain of empty nodes, 6 with
    /// a block linked twice, 7 with a key out of place.
    pub shape: u8,
    /// Blocks the partial source lacks: bit `i % 64` hides the `i`th.
    pub hide: u64,
    /// (operation, key, read from the partial source). An even key picks
    /// one of the tree's own keys, an odd one any key of the pool.
    pub ops: Vec<(u8, u8, bool)>,
}

const POOL: usize = 48;

/// How many levels below the root `DetachedTree` loads a node.
const MAX_DEPTH: usize = 128;

fn pool_key(i: u8) -> String {
    format!("com.example.k/{:04}", i as usize % (POOL + 8))
}

fn value(tag: u8, key: u8) -> Cid {
    Cid::compute(Codec::Raw, &[tag, key])
}

/// splitmix64, and whether the tree has its one empty node yet: a second
/// would encode to the same block, and a block linked twice is rejected.
struct Rng(u64, bool);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

/// A node before encoding.
#[derive(Default)]
struct Spec {
    left: Option<Box<Spec>>,
    entries: Vec<(String, Cid, Option<Box<Spec>>)>,
}

impl Spec {
    fn children(&self) -> impl Iterator<Item = &Spec> {
        let rights = self.entries.iter().filter_map(|e| e.2.as_deref());
        self.left.as_deref().into_iter().chain(rights)
    }

    fn depth(&self) -> usize {
        self.children().map(|c| 1 + c.depth()).max().unwrap_or(0)
    }

    fn count(&self) -> usize {
        1 + self.children().map(Spec::count).sum::<usize>()
    }

    /// The `n`th node in pre-order.
    fn nth(&mut self, n: usize) -> Option<&mut Spec> {
        let Some(mut n) = n.checked_sub(1) else {
            return Some(self);
        };
        let rights = self.entries.iter_mut().filter_map(|e| e.2.as_deref_mut());
        for child in self.left.as_deref_mut().into_iter().chain(rights) {
            let count = child.count();
            if n < count {
                return child.nth(n);
            }
            n -= count;
        }
        None
    }
}

/// A tree holding `keys` (sorted) in some order-keeping shape: each node
/// takes a few of its keys as entries and hands the gaps to its subtrees.
fn ordered(rng: &mut Rng, keys: &[(String, Cid)], depth: usize) -> Spec {
    let child = |rng: &mut Rng, gap: &[(String, Cid)]| -> Option<Box<Spec>> {
        if gap.is_empty() {
            // Rarely, an empty node, which no MST has but which is in order.
            let empty = !rng.1 && rng.below(6) == 0;
            rng.1 |= empty;
            return empty.then(Box::default);
        }
        Some(Box::new(ordered(rng, gap, depth + 1)))
    };
    if depth >= 8 {
        let entries = keys.iter().map(|(k, v)| (k.clone(), *v, None)).collect();
        return Spec {
            left: None,
            entries,
        };
    }
    if rng.below(4) == 0 {
        return Spec {
            left: child(rng, keys),
            entries: Vec::new(),
        };
    }
    let mut picks: Vec<usize> = (0..keys.len()).collect();
    let m = 1 + rng.below(keys.len().min(4));
    for i in 0..m {
        let j = i + rng.below(picks.len() - i);
        picks.swap(i, j);
    }
    picks.truncate(m);
    picks.sort_unstable();
    let mut spec = Spec {
        left: child(rng, &keys[..picks[0]]),
        entries: Vec::new(),
    };
    for (n, &p) in picks.iter().enumerate() {
        let end = picks.get(n + 1).copied().unwrap_or(keys.len());
        let (k, v) = &keys[p];
        spec.entries
            .push((k.clone(), *v, child(rng, &keys[p + 1..end])));
    }
    spec
}

/// Encode `spec` into `blocks`, children first, and return its CID. With
/// `share` set, the node links one block that was already encoded in
/// place of one of its own links (or as its left subtree).
fn encode(
    spec: &Spec,
    blocks: &mut HashMap<Cid, Vec<u8>>,
    order: &mut Vec<Cid>,
    share: Option<&mut Rng>,
) -> Cid {
    let mut left = spec.left.as_ref().map(|l| encode(l, blocks, order, None));
    let mut rights: Vec<Option<Cid>> = spec
        .entries
        .iter()
        .map(|e| e.2.as_ref().map(|r| encode(r, blocks, order, None)))
        .collect();
    if let Some(rng) = share
        && !order.is_empty()
    {
        let shared = order[rng.below(order.len())];
        match rng.below(rights.len() + 1) {
            0 => left = Some(shared),
            i => rights[i - 1] = Some(shared),
        }
    }
    let mut prev: &str = "";
    let entries = spec
        .entries
        .iter()
        .zip(rights)
        .map(|((key, val, _), right)| {
            let p = prev
                .bytes()
                .zip(key.bytes())
                .take_while(|(a, b)| a == b)
                .count();
            prev = key;
            EntryData {
                prefix_len: p,
                key_suffix: key.as_bytes()[p..].to_vec(),
                value: *val,
                right,
            }
        })
        .collect();
    let data = encode_node_data(&NodeData { left, entries }).unwrap();
    let cid = Cid::compute(Codec::Drisl, &data);
    blocks.insert(cid, data);
    order.push(cid);
    cid
}

/// The tree a case describes.
struct Built {
    root: Cid,
    blocks: HashMap<Cid, Vec<u8>>,
    /// The pool indices of its keys.
    chosen: Vec<u8>,
    /// Its entries, if it keeps its keys in order (and so must behave
    /// like a map).
    model: Option<BTreeMap<String, Cid>>,
}

fn build(case: &Case) -> Built {
    let mut rng = Rng(case.seed, false);
    let count = match case.keys {
        k @ 0..128 => k as usize % 8,
        k => k as usize % (POOL + 1),
    };
    let mut chosen: Vec<u8> = (0..POOL as u8).collect();
    for i in 0..count {
        let j = i + rng.below(POOL - i);
        chosen.swap(i, j);
    }
    chosen.truncate(count);
    chosen.sort_unstable();
    let keys: Vec<(String, Cid)> = chosen.iter().map(|&k| (pool_key(k), value(0, k))).collect();
    let model: BTreeMap<String, Cid> = keys.iter().cloned().collect();
    let mut blocks = HashMap::new();

    let shape = case.shape % 8;
    if shape < 2 || keys.is_empty() {
        let mut tree = DetachedTree::new();
        for (k, v) in &keys {
            tree.insert(&NoBlocks, k.clone(), *v).unwrap();
        }
        let write = tree.flush().unwrap();
        blocks.extend(write.new_blocks);
        return Built {
            root: write.root,
            blocks,
            chosen,
            model: Some(model),
        };
    }

    let mut spec = ordered(&mut rng, &keys, 0);
    let mut valid = true;
    match shape {
        5 => {
            // Either well within the depth limit or well past it, so that
            // inserts above the chain cannot push it over.
            let chain = if rng.below(2) == 0 {
                rng.below(100)
            } else {
                MAX_DEPTH + 1 + rng.below(20)
            };
            for _ in 0..chain {
                spec = Spec {
                    left: Some(Box::new(spec)),
                    entries: Vec::new(),
                };
            }
            valid = spec.depth() + 8 <= MAX_DEPTH;
        }
        7 => {
            let pick = rng.below(spec.count());
            let key = pool_key(rng.below(POOL + 8) as u8);
            if let Some(node) = spec.nth(pick).filter(|n| !n.entries.is_empty()) {
                let i = rng.below(node.entries.len());
                node.entries[i].0 = key;
                node.entries.sort_by(|a, b| a.0.cmp(&b.0));
                node.entries.dedup_by(|a, b| a.0 == b.0);
                valid = false;
            }
        }
        _ => {}
    }
    let mut order = Vec::new();
    let share = (shape == 6).then_some(&mut rng);
    let root = encode(&spec, &mut blocks, &mut order, share);
    valid &= shape != 6;
    Built {
        root,
        blocks,
        chosen,
        model: valid.then_some(model),
    }
}

fn sources<'a>(
    full: &'a HashMap<Cid, Vec<u8>>,
    partial: &'a HashMap<Cid, Vec<u8>>,
    use_partial: bool,
) -> &'a dyn BlockSource {
    if use_partial { partial } else { full }
}

/// Run a case, returning a description of the first property it breaks.
pub fn run(case: &Case) -> Result<(), String> {
    let Built {
        root,
        blocks: mut full,
        chosen,
        mut model,
    } = build(case);
    let canonical = case.shape % 8 < 2;
    let mut partial = full.clone();
    for (i, cid) in full.keys().enumerate() {
        if *cid != root && case.hide >> (i % 64) & 1 == 1 {
            partial.remove(cid);
        }
    }
    let mut tree = DetachedTree::load(root);

    for (step, &(op, k, use_partial)) in case.ops.iter().enumerate() {
        let k = match chosen.get((k / 2) as usize % chosen.len().max(1)) {
            Some(&own) if k % 2 == 0 => own,
            _ => k / 2,
        };
        let key = pool_key(k);
        let ctx =
            |what: &str| format!("step {step} op {op} key {key} partial {use_partial}: {what}");
        let before = tree.flush().map_err(|e| ctx(&format!("flush: {e}")))?;
        full.extend(before.new_blocks.iter().cloned());
        partial.extend(before.new_blocks.iter().cloned());
        let src = sources(&full, &partial, use_partial);

        let result: Result<(), MstError> = match op % 10 {
            0 => tree.get(src, &key).map(|got| {
                if let Some(m) = &model {
                    assert_eq!(got, m.get(&key).copied(), "{}", ctx("get"));
                }
            }),
            1 => {
                let val = value(step as u8 + 1, k);
                tree.insert(src, key.clone(), val).map(|prev| {
                    if let Some(m) = &mut model {
                        assert_eq!(prev, m.insert(key.clone(), val), "{}", ctx("insert"));
                    }
                })
            }
            2 => tree.remove(src, &key).map(|prev| {
                if let Some(m) = &mut model {
                    assert_eq!(prev, m.remove(&key), "{}", ctx("remove"));
                }
            }),
            3 => tree.entries(src).map(|got| {
                if let Some(m) = &model {
                    let want: Vec<(String, Cid)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
                    assert_eq!(got, want, "{}", ctx("entries"));
                }
            }),
            4 => {
                let mut got = Vec::new();
                tree.walk_reachable(src, |k, v| {
                    got.push((k.to_owned(), v));
                    Ok(())
                })
                .map(|()| {
                    if let Some(m) = model.as_ref().filter(|_| !use_partial) {
                        let want: Vec<(String, Cid)> =
                            m.iter().map(|(k, v)| (k.clone(), *v)).collect();
                        assert_eq!(got, want, "{}", ctx("walk_reachable"));
                    }
                })
            }
            5 | 6 => {
                let remove = op % 10 == 6;
                let missing = if remove {
                    tree.missing_blocks_for_remove(src, [key.as_str()])
                } else {
                    tree.missing_blocks(src, [key.as_str()])
                };
                missing.and_then(|missing| {
                    if !missing.is_empty() {
                        return Ok(());
                    }
                    // Everything the operation needs is loaded now.
                    let val = value(step as u8 + 1, k);
                    let done = if remove {
                        tree.remove(&NoBlocks, &key)
                    } else {
                        tree.insert(&NoBlocks, key.clone(), val)
                    };
                    match done {
                        Err(MstError::BlockNotFound(cid)) => {
                            Err(MstError::Internal(format!("needed {cid} after prefetch")))
                        }
                        Err(e) => Err(e),
                        Ok(prev) => {
                            if let Some(m) = &mut model {
                                let want = if remove {
                                    m.remove(&key)
                                } else {
                                    m.insert(key.clone(), val)
                                };
                                assert_eq!(prev, want, "{}", ctx("after prefetch"));
                            }
                            Ok(())
                        }
                    }
                })
            }
            7 => tree.covering_proof(src, [key.as_str()]).map(drop),
            8 => {
                let mut path = Vec::new();
                tree.search_path(src, &key, &mut path).map(|got| {
                    if let Some(m) = &model {
                        assert_eq!(got, m.get(&key).copied(), "{}", ctx("search_path"));
                    }
                })
            }
            _ => {
                // Reload from blocks: what earlier flushes wrote must load.
                tree = DetachedTree::load(before.root);
                Ok(())
            }
        };

        match result {
            Ok(()) => {}
            Err(MstError::Internal(e)) => return Err(ctx(&format!("internal error: {e}"))),
            Err(e) => {
                if model.is_some() && !use_partial {
                    return Err(ctx(&format!("failed on an ordered tree: {e}")));
                }
                let after = tree.flush().map_err(|e| ctx(&format!("flush: {e}")))?;
                if after.root != before.root {
                    return Err(ctx(&format!("failed ({e}) but changed the tree")));
                }
            }
        }
    }

    let write = tree.flush().map_err(|e| format!("final flush: {e}"))?;
    full.extend(write.new_blocks);
    if let Some(m) = &model {
        let want: Vec<(String, Cid)> = m.iter().map(|(k, v)| (k.clone(), *v)).collect();
        let got = DetachedTree::load(write.root)
            .entries(&full)
            .map_err(|e| format!("written tree does not load: {e}"))?;
        if got != want {
            let keys = |v: &[(String, Cid)]| v.iter().map(|e| e.0.clone()).collect::<Vec<_>>();
            return Err(format!(
                "written tree holds {:?}, want {:?}",
                keys(&got),
                keys(&want)
            ));
        }
        if canonical {
            let mut fresh = DetachedTree::new();
            for (k, v) in m {
                fresh.insert(&NoBlocks, k.clone(), *v).unwrap();
            }
            if fresh.flush().unwrap().root != write.root {
                return Err("root differs from a fresh build of the same entries".into());
            }
        }
    }
    Ok(())
}
