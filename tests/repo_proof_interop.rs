//! Differential tests for record proofs against the reference TypeScript
//! implementation. `testdata/repo_proofs/ts_vectors.json` holds proofs that
//! `@atproto/repo` served (as the PDS's `com.atproto.sync.getRecord` does)
//! with the reference verifier's verdict on each; regenerate it with
//! `node scripts/repo-proof-vectors.mjs`.
//!
//! Each proof must verify to the same verdict here, and shrike must build the
//! same proof for the same repository contents: identical MST root and
//! identical MST and record blocks (commits differ only in rev and signature).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::BTreeSet;

use serde::Deserialize;
use shrike::cbor::Cid;
use shrike::crypto::{P256SigningKey, parse_did_key};
use shrike::repo::{Repo, verify_record_proof};
use shrike::syntax::{Did, Nsid, RecordKey, TidClock};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Vectors {
    repo_did: String,
    collection: String,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Case {
    name: String,
    fill: usize,
    did: String,
    signing_key: String,
    rkey: String,
    data_cid: String,
    proof: String,
    /// Record CID, `null` for a proven absence, or `"error"`.
    expect: Option<String>,
}

fn vectors() -> Vectors {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/testdata/repo_proofs/ts_vectors.json"
    );
    serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
}

fn b64(s: &str) -> Vec<u8> {
    data_encoding::BASE64.decode(s.as_bytes()).unwrap()
}

/// Must match scripts/repo-proof-vectors.mjs.
fn rkey_for(i: usize) -> String {
    format!("com.example.n{i:04}")
}

fn record_for(rkey: &str) -> Vec<u8> {
    let json = serde_json::json!({
        "$type": "com.atproto.lexicon.schema",
        "lexicon": 1,
        "id": rkey,
        "defs": {},
    });
    shrike::cbor::json::json_to_drisl(&json, shrike::cbor::json::Integers::Safe).unwrap()
}

#[test]
fn verdicts_match_reference() {
    let v = vectors();
    let col = Nsid::try_from(v.collection.as_str()).unwrap();
    assert!(v.cases.len() >= 100, "vector file looks truncated");
    for case in &v.cases {
        let key = parse_did_key(&case.signing_key).unwrap();
        let did = Did::try_from(case.did.as_str()).unwrap();
        let rkey = RecordKey::try_from(case.rkey.as_str()).unwrap();
        let got = verify_record_proof(&b64(&case.proof), &did, key.as_ref(), &col, &rkey);
        match (&case.expect, got) {
            (Some(e), Err(_)) if e == "error" => {}
            (None, Ok(p)) => assert!(p.record.is_none(), "{}: expected absent", case.name),
            (Some(cid), Ok(p)) => {
                let (got_cid, bytes) = p.record.unwrap_or_else(|| panic!("{}: absent", case.name));
                assert_eq!(&got_cid.to_string(), cid, "{}", case.name);
                assert_eq!(bytes, record_for(&case.rkey), "{}", case.name);
                assert_eq!(p.commit.data.to_string(), case.data_cid, "{}", case.name);
            }
            (expect, got) => panic!("{}: expected {expect:?}, got {got:?}", case.name),
        }
    }
}

#[test]
fn generated_proofs_match_reference() {
    let v = vectors();
    let col = Nsid::try_from(v.collection.as_str()).unwrap();
    let did = Did::try_from(v.repo_did.as_str()).unwrap();
    let key = P256SigningKey::generate();
    let mut checked = 0;
    for case in v.cases.iter().filter(|c| c.name.ends_with("/ok")) {
        let mut repo = Repo::new(did.clone(), TidClock::new(0).unwrap());
        for i in 0..case.fill {
            let rkey = rkey_for(i);
            repo.create(
                &col,
                &RecordKey::try_from(rkey.as_str()).unwrap(),
                &record_for(&rkey),
            )
            .unwrap();
        }
        let commit = repo.commit(&key).unwrap();
        assert_eq!(
            commit.data.to_string(),
            case.data_cid,
            "{}: MST root",
            case.name
        );

        let rkey = RecordKey::try_from(case.rkey.as_str()).unwrap();
        let ours = repo.record_proof(&col, &rkey).unwrap();
        // Everything but the commit (rev and signature differ by design).
        let blocks = |car: &[u8]| -> BTreeSet<(Cid, Vec<u8>)> {
            let (roots, blocks) = shrike::car::read_all(car).unwrap();
            blocks
                .into_iter()
                .filter(|b| b.cid != roots[0])
                .map(|b| (b.cid, b.data))
                .collect()
        };
        assert_eq!(
            blocks(&ours),
            blocks(&b64(&case.proof)),
            "{}: proof blocks differ",
            case.name
        );
        checked += 1;
    }
    assert!(checked >= 50, "only {checked} cases checked");
}
