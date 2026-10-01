//! Differential tests for repository writes and proofs against the reference
//! TypeScript implementation.
//!
//! `testdata/repo_proofs/commit_vectors.json` comes from
//! `node scripts/repo-commit-vectors.mjs`: covering proofs on random trees,
//! batches of writes applied to repos loaded from `getFullRepo` CARs, and
//! multi-record proofs with the reference verifiers' verdicts.
//! `testdata/repo_proofs/commit_proof_fixtures.json` is the commit-proof
//! fixture file shared by `@atproto/repo` and indigo.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::{BTreeMap, BTreeSet};

use serde::Deserialize;
use shrike::cbor::Cid;
use shrike::crypto::{K256SigningKey, parse_did_key};
use shrike::mst::{DetachedTree, NoBlocks};
use shrike::repo::{
    RecordClaim, Repo, RepoError, WriteOp, record_proofs_car, verify_proofs, verify_records,
};
use shrike::syntax::{Did, Nsid, RecordKey};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    leaf: String,
    covering_proofs: Vec<CoveringTree>,
    commits: Vec<CommitCase>,
    multi_proofs: Vec<MultiProof>,
}

#[derive(Deserialize)]
struct CoveringTree {
    name: String,
    keys: Vec<String>,
    root: String,
    probes: Vec<CoveringProbe>,
}

#[derive(Deserialize)]
struct CoveringProbe {
    key: String,
    proof: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitCase {
    name: String,
    car: String,
    data_before: String,
    writes: Vec<Write>,
    /// `"error"` or the expected commit.
    expect: serde_json::Value,
}

#[derive(Deserialize)]
struct Write {
    action: String,
    key: String,
    v: Option<u64>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Expected {
    data_after: String,
    new_blocks: Vec<String>,
    relevant_blocks: Vec<String>,
    removed_mst: Vec<String>,
    ops: Vec<ExpectedOp>,
}

#[derive(Deserialize)]
struct ExpectedOp {
    action: String,
    key: String,
    cid: Option<String>,
    prev: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct MultiProof {
    name: String,
    did: String,
    signing_key: String,
    paths: Vec<String>,
    proof: String,
    claims: Vec<Claim>,
    /// Per-claim verdicts, or `"error"`.
    verified: serde_json::Value,
    /// `[{key, cid}]`, or `"error"`.
    records: serde_json::Value,
}

#[derive(Deserialize)]
struct Claim {
    key: String,
    cid: Option<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CommitProofFixture {
    comment: String,
    leaf_value: String,
    keys: Vec<String>,
    adds: Vec<String>,
    dels: Vec<String>,
    root_before_commit: String,
    root_after_commit: String,
    blocks_in_proof: Vec<String>,
}

fn read<T: serde::de::DeserializeOwned>(name: &str) -> T {
    let path = format!("{}/testdata/repo_proofs/{name}", env!("CARGO_MANIFEST_DIR"));
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    data_encoding::BASE64.decode(s.as_bytes()).unwrap()
}

fn cid(s: &str) -> Cid {
    s.parse().unwrap()
}

fn path(key: &str) -> (Nsid, RecordKey) {
    let (c, r) = key.split_once('/').unwrap();
    (Nsid::try_from(c).unwrap(), RecordKey::try_from(r).unwrap())
}

/// Must match scripts/repo-commit-vectors.mjs.
fn record_for(collection: &str, rkey: &str, v: u64) -> Vec<u8> {
    let json = serde_json::json!({ "$type": collection, "rkey": rkey, "v": v });
    shrike::cbor::json::json_to_drisl(&json, shrike::cbor::json::Integers::Safe).unwrap()
}

fn strings<'a>(cids: impl IntoIterator<Item = &'a Cid>) -> Vec<String> {
    let set: BTreeSet<String> = cids.into_iter().map(Cid::to_string).collect();
    set.into_iter().collect()
}

fn sorted(mut v: Vec<String>) -> Vec<String> {
    v.sort();
    v
}

/// A tree of `keys`, all mapped to `leaf`, flushed, with its blocks.
fn build_tree(keys: &[String], leaf: Cid) -> (DetachedTree, BTreeMap<Cid, Vec<u8>>) {
    let mut tree = DetachedTree::new();
    for k in keys {
        tree.insert(&NoBlocks, k.clone(), leaf).unwrap();
    }
    let blocks = tree.flush().unwrap().new_blocks.into_iter().collect();
    (tree, blocks)
}

fn as_source(blocks: &BTreeMap<Cid, Vec<u8>>) -> std::collections::HashMap<Cid, Vec<u8>> {
    blocks.iter().map(|(c, d)| (*c, d.clone())).collect()
}

#[test]
fn covering_proofs_match_reference() {
    let v: Vectors = read("commit_vectors.json");
    let leaf = cid(&v.leaf);
    let mut probes = 0;
    for t in &v.covering_proofs {
        let (mut tree, blocks) = build_tree(&t.keys, leaf);
        let src = as_source(&blocks);
        assert_eq!(tree.flush().unwrap().root.to_string(), t.root, "{}", t.name);
        for p in &t.probes {
            let got = tree.covering_proof(&src, [p.key.as_str()]).unwrap();
            assert_eq!(
                strings(&got),
                sorted(p.proof.clone()),
                "{}: {}",
                t.name,
                p.key
            );
            // The same proof from a tree that loads every node on demand.
            let mut lazy = DetachedTree::load(tree.flush().unwrap().root);
            assert_eq!(lazy.covering_proof(&src, [p.key.as_str()]).unwrap(), got);
            probes += 1;
        }
    }
    assert!(probes >= 100, "vector file looks truncated");
}

#[test]
fn commit_proof_fixtures() {
    let fixtures: Vec<CommitProofFixture> = read("commit_proof_fixtures.json");
    assert!(fixtures.len() >= 6);
    for f in &fixtures {
        let leaf = cid(&f.leaf_value);
        let (mut tree, mut blocks) = build_tree(&f.keys, leaf);
        let before = tree.flush().unwrap().root;
        assert_eq!(before.to_string(), f.root_before_commit, "{}", f.comment);

        for k in &f.adds {
            tree.insert(&NoBlocks, k.clone(), leaf).unwrap();
        }
        for k in &f.dels {
            tree.remove(&NoBlocks, k).unwrap().unwrap();
        }
        let write = tree.flush().unwrap();
        assert_eq!(write.root.to_string(), f.root_after_commit, "{}", f.comment);
        blocks.extend(write.new_blocks);
        let src = as_source(&blocks);

        let mut proof = BTreeSet::new();
        for k in f.adds.iter().chain(&f.dels) {
            proof.extend(tree.covering_proof(&src, [k.as_str()]).unwrap());
        }
        // One call for every key proves the same nodes.
        let batched = tree
            .covering_proof(&src, f.adds.iter().chain(&f.dels).map(String::as_str))
            .unwrap();
        assert_eq!(
            batched,
            proof.iter().copied().collect::<Vec<_>>(),
            "{}",
            f.comment
        );
        for c in &f.blocks_in_proof {
            assert!(proof.contains(&cid(c)), "{}: proof lacks {c}", f.comment);
        }

        // Inverting the ops in every order, with only the proof's blocks,
        // restores the previous root.
        let proof_blocks: std::collections::HashMap<Cid, Vec<u8>> =
            proof.iter().map(|c| (*c, src[c].clone())).collect();
        let inverses: Vec<(&str, bool)> = f
            .adds
            .iter()
            .map(|k| (k.as_str(), true))
            .chain(f.dels.iter().map(|k| (k.as_str(), false)))
            .collect();
        for order in permutations(&inverses) {
            let mut t = DetachedTree::load(write.root);
            for (k, was_add) in order {
                if was_add {
                    t.remove(&proof_blocks, k).unwrap().unwrap();
                } else {
                    t.insert(&proof_blocks, k.to_owned(), leaf).unwrap();
                }
            }
            assert_eq!(t.flush().unwrap().root, before, "{}", f.comment);
        }
    }
}

fn permutations<T: Clone>(items: &[T]) -> Vec<Vec<T>> {
    if items.len() <= 1 {
        return vec![items.to_vec()];
    }
    let mut out = Vec::new();
    for i in 0..items.len() {
        let mut rest = items.to_vec();
        let first = rest.remove(i);
        for mut p in permutations(&rest) {
            p.insert(0, first.clone());
            out.push(p);
        }
    }
    out
}

fn writes_for(case: &CommitCase) -> Vec<WriteOp> {
    case.writes
        .iter()
        .map(|w| {
            let (collection, rkey) = path(&w.key);
            let record = || record_for(collection.as_str(), rkey.as_str(), w.v.unwrap());
            match w.action.as_str() {
                "create" => WriteOp::Create {
                    record: record(),
                    collection,
                    rkey,
                },
                "update" => WriteOp::Update {
                    record: record(),
                    collection,
                    rkey,
                },
                "delete" => WriteOp::Delete { collection, rkey },
                a => panic!("unknown action {a}"),
            }
        })
        .collect()
}

#[test]
fn commits_match_reference() {
    let v: Vectors = read("commit_vectors.json");
    let key = K256SigningKey::generate();
    assert!(v.commits.len() >= 20, "vector file looks truncated");
    for case in &v.commits {
        let car = b64(&case.car);
        let mut repo = Repo::load_car(&car).unwrap();
        let head = repo.head_cid().unwrap();
        assert_eq!(
            repo.head().unwrap().data.to_string(),
            case.data_before,
            "{}",
            case.name
        );
        // Our export of the loaded repository loads back to the same state.
        let reloaded = Repo::load_car(&repo.export_car().unwrap()).unwrap();
        assert_eq!(reloaded.head_cid(), Some(head), "{}", case.name);
        let blocks_before = repo.store().len();

        let writes = writes_for(case);
        if case.expect == "error" {
            let err = repo.apply_writes(&writes, &key).unwrap_err();
            assert!(
                matches!(
                    err,
                    RepoError::RecordExists(_) | RepoError::RecordNotFound(_)
                ),
                "{}: {err:?}",
                case.name
            );
            // Nothing changed.
            assert!(!repo.has_staged_writes(), "{}", case.name);
            assert_eq!(repo.head_cid(), Some(head), "{}", case.name);
            assert_eq!(repo.store().len(), blocks_before, "{}", case.name);
            assert_eq!(repo.export_car().unwrap(), reloaded.export_car().unwrap());
            continue;
        }
        let expect: Expected = serde_json::from_value(case.expect.clone()).unwrap();
        let commit = repo.apply_writes(&writes, &key).unwrap();
        let ours = commit.cid;

        assert_eq!(
            commit.commit.data.to_string(),
            expect.data_after,
            "{}",
            case.name
        );
        assert_eq!(commit.prev, Some(head), "{}", case.name);
        assert_eq!(commit.prev_data.unwrap().to_string(), case.data_before);
        let without_commit = |m: &BTreeMap<Cid, Vec<u8>>| strings(m.keys().filter(|c| **c != ours));
        assert_eq!(
            without_commit(&commit.new_blocks),
            expect.new_blocks,
            "{}: new",
            case.name
        );
        assert_eq!(
            without_commit(&commit.relevant_blocks),
            expect.relevant_blocks,
            "{}: relevant",
            case.name
        );
        assert_eq!(
            strings(commit.removed_cids.iter().filter(|c| **c != head)),
            expect.removed_mst,
            "{}: removed",
            case.name
        );
        assert!(commit.removed_cids.contains(&head), "{}", case.name);

        let ops: Vec<(String, String, Option<String>, Option<String>)> = commit
            .ops
            .iter()
            .map(|o| {
                (
                    o.action.as_str().to_owned(),
                    o.path(),
                    o.cid.map(|c| c.to_string()),
                    o.prev.map(|c| c.to_string()),
                )
            })
            .collect();
        let want: Vec<_> = expect
            .ops
            .iter()
            .map(|o| {
                (
                    o.action.clone(),
                    o.key.clone(),
                    o.cid.clone(),
                    o.prev.clone(),
                )
            })
            .collect();
        assert_eq!(ops, want, "{}: ops", case.name);

        #[cfg(feature = "sync")]
        assert_inverts(&commit, case);
    }
}

/// Our commit, published as a firehose event, passes the sync verifier's
/// inversion back to the previous MST root.
#[cfg(feature = "sync")]
fn assert_inverts(commit: &shrike::repo::CommitData, case: &CommitCase) {
    use shrike::repo::RecordAction;
    use shrike::sync::{RawCommit, RawRepoOp, invert_commit};
    let raw = RawCommit {
        repo: commit.commit.did.clone(),
        rev: commit.rev(),
        seq: 1,
        time: "2026-01-01T00:00:00Z".into(),
        since: commit.since,
        commit: commit.cid,
        blocks: commit.relevant_car().unwrap(),
        ops: commit
            .ops
            .iter()
            .map(|o| RawRepoOp {
                action: o.action.as_str().into(),
                path: o.path(),
                cid: o.cid,
                prev: o.prev,
            })
            .collect(),
        blobs: Vec::new(),
        prev_data: commit.prev_data,
        too_big: false,
        rebase: false,
    };
    assert_eq!(
        invert_commit(&raw).unwrap(),
        commit.prev_data.unwrap(),
        "{}",
        case.name
    );
    assert!(commit.ops.iter().all(|o| match o.action {
        RecordAction::Create => o.cid.is_some() && o.prev.is_none(),
        RecordAction::Update => o.cid.is_some() && o.prev.is_some(),
        RecordAction::Delete => o.cid.is_none() && o.prev.is_some(),
    }));
}

#[test]
fn multi_record_proofs_match_reference() {
    let v: Vectors = read("commit_vectors.json");
    assert!(v.multi_proofs.len() >= 40, "vector file looks truncated");
    for case in &v.multi_proofs {
        let car = b64(&case.proof);
        let did = Did::try_from(case.did.as_str()).unwrap();
        let key = parse_did_key(&case.signing_key).unwrap();
        let claims: Vec<RecordClaim> = case
            .claims
            .iter()
            .map(|c| {
                let (collection, rkey) = path(&c.key);
                RecordClaim {
                    collection,
                    rkey,
                    cid: c.cid.as_deref().map(cid),
                }
            })
            .collect();

        match (
            verify_proofs(&car, &did, key.as_ref(), &claims),
            &case.verified,
        ) {
            (Err(_), serde_json::Value::String(s)) if s == "error" => {}
            (Ok(got), serde_json::Value::Array(want)) => {
                let verdicts: Vec<bool> = claims.iter().map(|c| got.verified.contains(c)).collect();
                let want: Vec<bool> = want.iter().map(|b| b.as_bool().unwrap()).collect();
                assert_eq!(verdicts, want, "{}", case.name);
                assert_eq!(got.verified.len() + got.unverified.len(), claims.len());
            }
            (got, want) => panic!("{}: expected {want}, got {got:?}", case.name),
        }

        match (verify_records(&car, &did, key.as_ref()), &case.records) {
            (Err(_), serde_json::Value::String(s)) if s == "error" => {}
            (Ok(got), serde_json::Value::Array(want)) => {
                let got: Vec<(String, String)> = got
                    .iter()
                    .map(|r| (format!("{}/{}", r.collection, r.rkey), r.cid.to_string()))
                    .collect();
                let want: Vec<(String, String)> = want
                    .iter()
                    .map(|r| {
                        (
                            r["key"].as_str().unwrap().to_owned(),
                            r["cid"].as_str().unwrap().to_owned(),
                        )
                    })
                    .collect();
                assert_eq!(got, want, "{}", case.name);
            }
            (got, want) => panic!("{}: expected {want}, got {got:?}", case.name),
        }
    }
}

#[test]
fn generated_multi_record_proofs_match_reference() {
    // Rebuild each repository and proof, then compare the proof's blocks,
    // ignoring the commit (its rev and signature differ).
    let v: Vectors = read("commit_vectors.json");
    let key = K256SigningKey::generate();
    let mut checked = 0;
    for case in v.multi_proofs.iter().filter(|c| c.name.ends_with("/ok")) {
        let fill: usize = case.name["fill".len()..]
            .split('/')
            .next()
            .unwrap()
            .parse()
            .unwrap();
        let did = Did::try_from(case.did.as_str()).unwrap();
        let mut repo = Repo::new(did, shrike::syntax::TidClock::new(0).unwrap());
        let mut writes = Vec::new();
        for i in 0..fill {
            let collection = ["com.example.alpha", "com.example.beta"][i % 2];
            let rkey = format!("r{i:05}");
            writes.push(WriteOp::Create {
                record: record_for(collection, &rkey, 0),
                collection: Nsid::try_from(collection).unwrap(),
                rkey: RecordKey::try_from(rkey.as_str()).unwrap(),
            });
        }
        repo.apply_writes(&writes, &key).unwrap();
        let paths: Vec<(Nsid, RecordKey)> = case.paths.iter().map(|p| path(p)).collect();
        let ours = repo.records_proof(&paths).unwrap();
        // The free function on the store directly builds the same CAR.
        let head = repo.head_cid().unwrap();
        let blocks: std::collections::HashMap<Cid, Vec<u8>> = shrike::car::read_all(&ours[..])
            .unwrap()
            .1
            .into_iter()
            .map(|b| (b.cid, b.data))
            .collect();
        assert_eq!(record_proofs_car(&blocks, &head, &paths).unwrap(), ours);

        let block_set = |car: &[u8]| {
            let (roots, blocks) = shrike::car::read_all(car).unwrap();
            strings(blocks.iter().map(|b| &b.cid).filter(|c| **c != roots[0]))
        };
        assert_eq!(
            block_set(&ours),
            block_set(&b64(&case.proof)),
            "{}",
            case.name
        );
        checked += 1;
    }
    assert!(checked >= 10);
}

/// Real firehose commits from indigo's test data. They predate `prevData`,
/// so the check is that the commit's blocks suffice to invert its ops.
/// 4623075231 creates a repo's only root-level key, so inverting it leaves
/// the root's lone subtree, absent from the CAR, as the new root; indigo
/// inverts it too. The other three, from the bridgyfed PDS, omit blocks
/// that indigo also needs.
#[cfg(feature = "sync")]
#[test]
fn indigo_firehose_commits_invert() {
    use shrike::sync::{RawCommit, RawRepoOp, invert_commit};
    let link = |v: &serde_json::Value| v["$link"].as_str().map(cid);
    for (seq, inverted) in [
        (
            4623075231u64,
            Some("bafyreicfeeojgjj7gtgl6go25tk5jmcuoytjp5hhulbdd7gwzk7gtqw3ka"),
        ),
        (4621317030, None),
        (4621317332, None),
        (4621332152, None),
    ] {
        let path = format!(
            "{}/testdata/repo_proofs/firehose_commits/firehose_commit_{seq}.json",
            env!("CARGO_MANIFEST_DIR")
        );
        let m: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
        let raw = RawCommit {
            repo: Did::try_from(m["repo"].as_str().unwrap()).unwrap(),
            rev: m["rev"].as_str().unwrap().parse().unwrap(),
            seq: m["seq"].as_i64().unwrap(),
            time: m["time"].as_str().unwrap().into(),
            since: m["since"].as_str().map(|s| s.parse().unwrap()),
            commit: link(&m["commit"]).unwrap(),
            blocks: shrike::cbor::json::decode_base64(m["blocks"]["$bytes"].as_str().unwrap())
                .unwrap(),
            ops: m["ops"]
                .as_array()
                .unwrap()
                .iter()
                .map(|o| RawRepoOp {
                    action: o["action"].as_str().unwrap().into(),
                    path: o["path"].as_str().unwrap().into(),
                    cid: link(&o["cid"]),
                    prev: link(&o["prev"]),
                })
                .collect(),
            blobs: Vec::new(),
            prev_data: None,
            too_big: false,
            rebase: false,
        };
        let got = invert_commit(&raw);
        assert_eq!(
            got.as_ref().ok(),
            inverted.map(cid).as_ref(),
            "{seq}: {got:?}"
        );
    }
}
