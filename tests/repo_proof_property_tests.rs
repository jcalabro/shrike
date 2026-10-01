//! Property tests for record proofs: generated proofs always verify to the
//! repository's contents, and no corruption of a proof makes it verify to
//! anything else.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;
use std::sync::LazyLock;

use proptest::prelude::*;
use proptest::sample::Index;
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::repo::{Repo, verify_record_proof};
use shrike::syntax::{Did, Nsid, RecordKey, TidClock};

static KEY: LazyLock<P256SigningKey> = LazyLock::new(P256SigningKey::generate);

const DID: &str = "did:plc:propproppropproppropprop";

fn did() -> Did {
    Did::try_from(DID).unwrap()
}

fn col() -> Nsid {
    Nsid::try_from("com.example.records").unwrap()
}

/// DRISL `{"k": rkey}` (keys are under 24 bytes): the record for `rkey`.
fn record(rkey: &str) -> Vec<u8> {
    let mut v = vec![0xa1, 0x61, b'k', 0x60 | rkey.len() as u8];
    v.extend_from_slice(rkey.as_bytes());
    v
}

fn repo_with(rkeys: &BTreeSet<String>) -> Repo {
    let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
    for k in rkeys {
        repo.create(
            &col(),
            &RecordKey::try_from(k.as_str()).unwrap(),
            &record(k),
        )
        .unwrap();
    }
    repo.commit(&*KEY).unwrap();
    repo
}

/// What verifying `car` for `probe` reports: `Ok(Some(bytes))`, `Ok(None)`
/// for a proven absence, or `Err` for a rejected proof.
fn outcome(car: &[u8], probe: &str) -> Result<Option<Vec<u8>>, ()> {
    verify_record_proof(
        car,
        &did(),
        KEY.public_key(),
        &col(),
        &RecordKey::try_from(probe).unwrap(),
    )
    .map(|p| p.record.map(|(_, bytes)| bytes))
    .map_err(|_| ())
}

fn rkeys() -> impl Strategy<Value = BTreeSet<String>> {
    prop::collection::btree_set("[a-z0-9]{1,12}", 0..150)
}

/// A key from the repo (if any) or a fresh one.
fn probe(keys: &BTreeSet<String>, pick: Index, fresh: &str, use_existing: bool) -> String {
    if use_existing && !keys.is_empty() {
        keys.iter().nth(pick.index(keys.len())).unwrap().clone()
    } else {
        fresh.to_owned()
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn proofs_verify_to_repo_contents(
        keys in rkeys(),
        pick in any::<Index>(),
        fresh in "[a-z0-9]{1,12}",
        use_existing in any::<bool>(),
    ) {
        let repo = repo_with(&keys);
        let probe = probe(&keys, pick, &fresh, use_existing);
        let car = repo.record_proof(&col(), &RecordKey::try_from(probe.as_str()).unwrap()).unwrap();
        let expected = keys.contains(&probe).then(|| record(&probe));
        prop_assert_eq!(outcome(&car, &probe), Ok(expected));
    }

    #[test]
    fn corrupted_proofs_never_verify_to_something_else(
        keys in rkeys(),
        pick in any::<Index>(),
        fresh in "[a-z0-9]{1,12}",
        use_existing in any::<bool>(),
        at in any::<Index>(),
        mask in 1u8..=255,
    ) {
        let repo = repo_with(&keys);
        let probe = probe(&keys, pick, &fresh, use_existing);
        let car = repo.record_proof(&col(), &RecordKey::try_from(probe.as_str()).unwrap()).unwrap();
        let expected = keys.contains(&probe).then(|| record(&probe));

        let mut flipped = car.clone();
        flipped[at.index(car.len())] ^= mask;
        let got = outcome(&flipped, &probe);
        prop_assert!(got.is_err() || got == Ok(expected.clone()), "flip accepted: {:?}", got);

        let truncated = &car[..at.index(car.len())];
        prop_assert!(outcome(truncated, &probe).is_err());
    }
}
