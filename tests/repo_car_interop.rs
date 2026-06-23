//! Cross-implementation repository-CAR golden vectors.
//!
//! These two CAR files are vendored verbatim from the atmos Go reference
//! (`car/testdata/`). They pin shrike's CAR reader + commit decoder + MST
//! loader against the exact bytes and the assertions atmos makes in its
//! `repo/repo_test.go`:
//!
//!   - `greenground.repo.car`  → commit DID `did:plc:kzcqyc3unb33eh5sxzsfs25z`,
//!     a present MST data root, a non-empty signature, and a walkable tree.
//!   - `repo_slice.car`        → commit DID `did:plc:6evlgoug7wwijzxhzt2riyic`,
//!     containing record `app.bsky.feed.post/3jquh3emtzo2o` whose decoded
//!     value carries `$type == "app.bsky.feed.post"`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(all(feature = "repo", feature = "car", feature = "mst"))]

use std::collections::HashMap;

use shrike::car::read_all;
use shrike::cbor::{Cid, Value, decode};
use shrike::mst::{BlockStore, MemBlockStore, Tree};
use shrike::repo::Commit;

/// Load a CAR file: return (root commit, cid -> block bytes).
fn load_car(path: &str) -> (Commit, HashMap<Cid, Vec<u8>>) {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("read {path}: {e}"));
    let (roots, blocks) = read_all(&bytes[..]).unwrap_or_else(|e| panic!("read_all {path}: {e}"));
    assert_eq!(roots.len(), 1, "expected exactly one CAR root in {path}");

    let mut index = HashMap::new();
    for b in blocks {
        index.insert(b.cid, b.data);
    }

    let root_bytes = index
        .get(&roots[0])
        .unwrap_or_else(|| panic!("root block {} missing from {path}", roots[0]));
    let commit = Commit::from_cbor(root_bytes)
        .unwrap_or_else(|e| panic!("decode root commit in {path}: {e}"));
    (commit, index)
}

/// Build an MST block store seeded with every block from the CAR.
fn store_from(index: &HashMap<Cid, Vec<u8>>) -> MemBlockStore {
    let store = MemBlockStore::new();
    for (cid, data) in index {
        store.put_block(*cid, data.clone()).unwrap();
    }
    store
}

#[test]
fn greenground_repo_car_matches_reference() {
    let (commit, index) = load_car("testdata/greenground.repo.car");

    // Matches atmos repo_test.go: DID, present data root, non-empty signature.
    assert_eq!(commit.did.as_str(), "did:plc:kzcqyc3unb33eh5sxzsfs25z");
    let sig = commit.sig.expect("commit must be signed");
    // A real ECDSA signature is never all-zero.
    assert!(
        sig.as_bytes().iter().any(|&b| b != 0),
        "signature must be non-zero"
    );

    // The MST rooted at commit.data must load and walk without error, yielding
    // at least one record entry (atmos asserts a non-zero walk count).
    let store = store_from(&index);
    let mut tree = Tree::load(Box::new(store), commit.data);
    let entries = tree.entries().expect("MST must walk");
    assert!(
        !entries.is_empty(),
        "expected a non-empty MST for greenground"
    );

    // Every entry's value block must be present in the CAR and decode as CBOR.
    for (key, val) in &entries {
        let block = index
            .get(val)
            .unwrap_or_else(|| panic!("record block for {key} missing"));
        decode(block).unwrap_or_else(|e| panic!("record {key} is not valid CBOR: {e}"));
    }
}

#[test]
fn repo_slice_car_contains_known_post() {
    let (commit, index) = load_car("testdata/repo_slice.car");

    assert_eq!(commit.did.as_str(), "did:plc:6evlgoug7wwijzxhzt2riyic");

    // repo_slice.car is a *partial* CAR (a proof slice): it only carries the
    // MST blocks along the path to the target record, so a full tree walk would
    // hit missing internal nodes. A keyed lookup follows just that path.
    let store = store_from(&index);
    let mut tree = Tree::load(Box::new(store), commit.data);

    // The MST key is "<collection>/<rkey>".
    const KEY: &str = "app.bsky.feed.post/3jquh3emtzo2o";
    let record_cid = tree
        .get(KEY)
        .expect("MST lookup must succeed")
        .unwrap_or_else(|| panic!("record {KEY} not found in MST"));

    let record_bytes = index
        .get(&record_cid)
        .expect("record block must be present in the CAR");
    let value = decode(record_bytes).expect("record must decode as CBOR");

    // $type must be the post lexicon, matching atmos's assertion.
    let entries = match value {
        Value::Map(e) => e,
        other => panic!("record is not a CBOR map: {other:?}"),
    };
    let ty = entries
        .iter()
        .find(|(k, _)| *k == "$type")
        .map(|(_, v)| v)
        .expect("record must carry $type");
    match ty {
        Value::Text(s) => assert_eq!(*s, "app.bsky.feed.post"),
        other => panic!("$type is not text: {other:?}"),
    }
}
