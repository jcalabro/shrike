//! Model-based property tests for repository writes: random batches of
//! writes, interleaved with reopening the store and round-tripping through a
//! CAR, always leave the repository matching a simple map, and every commit
//! carries what a firehose consumer needs to verify and invert it.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::LazyLock;

use proptest::prelude::*;
use proptest::sample::Index;
use shrike::cbor::{Cid, Codec};
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::mst::DetachedTree;
use shrike::repo::{
    CommitData, MemRepoStore, RecordAction, RecordClaim, Repo, RepoError, RepoStore, WriteOp,
    verify_proofs,
};
use shrike::syntax::{Did, Nsid, RecordKey, TidClock};

static KEY: LazyLock<P256SigningKey> = LazyLock::new(P256SigningKey::generate);

fn did() -> Did {
    Did::try_from("did:plc:modelmodelmodelmodelmode").unwrap()
}

fn col(c: u8) -> Nsid {
    Nsid::try_from(["com.example.a", "com.example.b"][c as usize % 2]).unwrap()
}

fn rkey(k: u8) -> RecordKey {
    RecordKey::try_from(format!("k{k:03}").as_str()).unwrap()
}

/// DRISL `{"v": v}`: few distinct values, so keys often share a block.
fn record(v: u8) -> Vec<u8> {
    vec![0xa1, 0x61, b'v', 0x18, v]
}

#[derive(Debug, Clone)]
enum Step {
    /// Writes as (kind, which key, value), resolved against the current
    /// contents by [`resolve`].
    Batch(Vec<(u8, Index, u8)>),
    /// Drop the repo and reopen its store.
    Reopen,
    /// Replace the repo with one loaded from its exported CAR.
    RoundTrip,
}

fn steps() -> impl Strategy<Value = Vec<Step>> {
    let write = (0u8..20, any::<Index>(), 24u8..32);
    let step = prop_oneof![
        8 => prop::collection::vec(write, 0..16).prop_map(Step::Batch),
        1 => Just(Step::Reopen),
        1 => Just(Step::RoundTrip),
    ];
    prop::collection::vec(step, 1..16)
}

type Model = BTreeMap<String, Vec<u8>>;

/// A write as (action, collection, key, value): 0 create, 1 update, 2 delete.
type Write = (u8, u8, u8, u8);

/// Every path the tests use: two collections of 40 keys.
fn all_paths() -> Vec<(u8, u8)> {
    (0..2).flat_map(|c| (0..40).map(move |k| (c, k))).collect()
}

fn path(c: u8, k: u8) -> String {
    format!("{}/{}", col(c), rkey(k))
}

/// Turn generated writes into concrete ones: creates of absent paths and
/// updates and deletes of present ones, except that kind 19 picks the
/// wrong kind of path and so makes the batch invalid.
fn resolve(model: &Model, planned: &[(u8, Index, u8)]) -> Vec<Write> {
    let mut present: Vec<(u8, u8)> = all_paths()
        .into_iter()
        .filter(|&(c, k)| model.contains_key(&path(c, k)))
        .collect();
    let mut absent: Vec<(u8, u8)> = all_paths()
        .into_iter()
        .filter(|&(c, k)| !model.contains_key(&path(c, k)))
        .collect();
    let mut out = Vec::new();
    for &(kind, ix, v) in planned {
        let invalid = kind == 19;
        let action = match kind % 10 {
            0..=4 => 0,
            5..=7 => 1,
            _ => 2,
        };
        let pool = if (action == 0) != invalid {
            &absent
        } else {
            &present
        };
        if pool.is_empty() {
            continue;
        }
        let (c, k) = pool[ix.index(pool.len())];
        out.push((action, c, k, v));
        if invalid {
            continue;
        }
        match action {
            0 => {
                absent.retain(|&p| p != (c, k));
                present.push((c, k));
            }
            2 => {
                present.retain(|&p| p != (c, k));
                absent.push((c, k));
            }
            _ => {}
        }
    }
    out
}

/// Apply a batch to the model as the reference implementation would, or
/// report that it is invalid.
fn model_apply(model: &Model, writes: &[Write]) -> Option<Model> {
    let mut next = model.clone();
    for &(a, c, k, v) in writes {
        let p = path(c, k);
        let present = next.contains_key(&p);
        match a {
            0 if present => return None,
            1 | 2 if !present => return None,
            0 | 1 => {
                next.insert(p, record(v));
            }
            _ => {
                next.remove(&p);
            }
        }
    }
    Some(next)
}

fn to_writes(writes: &[Write]) -> Vec<WriteOp> {
    writes
        .iter()
        .map(|&(a, c, k, v)| match a {
            0 => WriteOp::Create {
                collection: col(c),
                rkey: rkey(k),
                record: record(v),
            },
            1 => WriteOp::Update {
                collection: col(c),
                rkey: rkey(k),
                record: record(v),
            },
            _ => WriteOp::Delete {
                collection: col(c),
                rkey: rkey(k),
            },
        })
        .collect()
}

fn contents(repo: &mut Repo) -> Model {
    let mut out = Model::new();
    for c in 0..2 {
        for (k, cid) in repo.list(&col(c)).unwrap() {
            let (got, data) = repo.get(&col(c), &k).unwrap().unwrap();
            assert_eq!(got, cid);
            assert_eq!(Cid::compute(Codec::Drisl, &data), cid);
            out.insert(format!("{}/{k}", col(c)), data);
        }
    }
    out
}

/// Check a commit as a firehose consumer would: with only its relevant
/// blocks, the ops check out against the new tree and invert to the old one.
fn check_commit(commit: &CommitData, before: &Model, after: &Model) {
    commit.commit.verify(KEY.public_key()).unwrap();
    let blocks: HashMap<Cid, Vec<u8>> = commit
        .relevant_blocks
        .iter()
        .map(|(c, d)| (*c, d.clone()))
        .collect();
    let mut tree = DetachedTree::load(commit.commit.data);

    let paths: BTreeSet<&String> = before.keys().chain(after.keys()).collect();
    let changed: Vec<&String> = paths
        .into_iter()
        .filter(|p| before.get(*p) != after.get(*p))
        .collect();
    assert_eq!(commit.ops.len(), changed.len());

    let cid = |d: Option<&Vec<u8>>| d.map(|d| Cid::compute(Codec::Drisl, d));
    for (op, p) in commit.ops.iter().zip(changed) {
        let (b, a) = (before.get(p), after.get(p));
        assert_eq!(&op.path(), p);
        assert_eq!(op.prev, cid(b));
        assert_eq!(op.cid, cid(a));
        let action = match (b, a) {
            (None, _) => RecordAction::Create,
            (_, None) => RecordAction::Delete,
            _ => RecordAction::Update,
        };
        assert_eq!(op.action, action);
        assert_eq!(tree.get(&blocks, p).unwrap(), op.cid);
        if let Some(c) = op.cid {
            assert!(blocks.contains_key(&c), "record block for {p} not relevant");
        }
    }

    for op in commit.ops.iter().rev() {
        match op.prev {
            None => {
                tree.remove(&blocks, &op.path()).unwrap();
            }
            Some(prev) => {
                tree.insert(&blocks, op.path(), prev).unwrap();
            }
        }
    }
    let inverted = tree.flush().unwrap().root;
    match commit.prev_data {
        Some(prev) => assert_eq!(inverted, prev),
        None => assert_eq!(inverted, DetachedTree::new().flush().unwrap().root),
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(128))]

    #[test]
    fn writes_match_model(steps in steps()) {
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        let mut model = Model::new();
        let mut committed = false;
        for step in steps {
            match step {
                Step::Batch(planned) => {
                    let writes = resolve(&model, &planned);
                    let head = repo.head_cid();
                    let result = repo.apply_writes(&to_writes(&writes), &*KEY);
                    match (model_apply(&model, &writes), result) {
                        (Some(next), Ok(commit)) => {
                            prop_assert_eq!(commit.prev, head);
                            check_commit(&commit, &model, &next);
                            model = next;
                            committed = true;
                        }
                        (None, Err(RepoError::RecordExists(_) | RepoError::RecordNotFound(_))) => {
                            prop_assert_eq!(repo.head_cid(), head);
                            prop_assert!(!repo.has_staged_writes());
                        }
                        (want, got) => panic!("model {want:?}, repo {got:?}"),
                    }
                }
                Step::Reopen if committed => {
                    repo = Repo::open(repo.into_store()).unwrap();
                }
                Step::RoundTrip if committed => {
                    let car = repo.export_car().unwrap();
                    repo = Repo::load_car(&car).unwrap();
                }
                Step::Reopen | Step::RoundTrip => {}
            }
            prop_assert_eq!(&contents(&mut repo), &model);
        }

        if committed {
            // One proof covers every key, present or not.
            let paths: Vec<(Nsid, RecordKey)> = (0..2)
                .flat_map(|c| (0..40).map(move |k| (col(c), rkey(k))))
                .collect();
            let claims: Vec<RecordClaim> = paths
                .iter()
                .map(|(c, k)| RecordClaim {
                    collection: c.clone(),
                    rkey: k.clone(),
                    cid: model.get(&format!("{c}/{k}")).map(|d| Cid::compute(Codec::Drisl, d)),
                })
                .collect();
            let proof = repo.records_proof(&paths).unwrap();
            let verdict = verify_proofs(&proof, &did(), KEY.public_key(), &claims).unwrap();
            prop_assert_eq!(verdict.verified.len(), claims.len());

            // The store holds the live tree, and otherwise only records.
            let live = repo.export_car().unwrap();
            let live: BTreeSet<Cid> =
                shrike::car::read_all(&live[..]).unwrap().1.iter().map(|b| b.cid).collect();
            let records: BTreeSet<Cid> =
                (24u8..32).map(|v| Cid::compute(Codec::Drisl, &record(v))).collect();
            let store: MemRepoStore = repo.into_store();
            for cid in &live {
                prop_assert!(store.get_block(cid).unwrap().is_some());
            }
            for (cid, _) in store.iter() {
                prop_assert!(live.contains(cid) || records.contains(cid), "stale block {}", cid);
            }
        }
    }
}
