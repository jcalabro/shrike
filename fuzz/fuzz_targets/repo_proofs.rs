#![no_main]
//! `verify_proofs` and `verify_records` must never panic on arbitrary bytes,
//! and must never accept a record the signing key did not commit to.
//!
//! The key is fixed (see `gen_seeds`, shared with `repo_record_proof`), and
//! every commit it signs holds `RECORD` at `com.example.present`, `{}` at
//! some `com.example.fNNNN` keys, and nothing else.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use shrike::cbor::{Cid, Codec};
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::repo::{RecordClaim, verify_proofs, verify_records};
use shrike::syntax::{Did, Nsid, RecordKey};

const KEY: [u8; 32] = [7; 32];
const DID: &str = "did:plc:fuzzfuzzfuzzfuzzfuzzfuzz";
const RECORD: &[u8] = b"\xa1\x62id\x73com.example.present";
const FILLER: &[u8] = b"\xa0";

static SETUP: LazyLock<(P256SigningKey, Did, Nsid)> = LazyLock::new(|| {
    (
        P256SigningKey::from_bytes(&KEY).expect("valid key"),
        Did::try_from(DID).expect("valid DID"),
        Nsid::try_from("com.atproto.lexicon.schema").expect("valid NSID"),
    )
});

/// Whether the key could have committed `record` (`None` for absence) at
/// `rkey`. Filler keys are present in some commits and absent in others.
fn possible(rkey: &str, record: Option<&[u8]>) -> bool {
    if rkey == "com.example.present" {
        record == Some(RECORD)
    } else if rkey.starts_with("com.example.f") {
        record.is_none_or(|r| r == FILLER)
    } else {
        record.is_none()
    }
}

fn cid(record: &[u8]) -> Cid {
    Cid::compute(Codec::Drisl, record)
}

fuzz_target!(|data: &[u8]| {
    let (key, did, collection) = &*SETUP;
    let records: [&[u8]; 3] = [RECORD, FILLER, b"\xa1\x61x\x01"];
    let mut claims = Vec::new();
    for rkey in [
        "com.example.present",
        "com.example.absent",
        "com.example.f0003",
    ] {
        let rkey = RecordKey::try_from(rkey).expect("valid rkey");
        for cid in records.iter().map(|r| Some(cid(r))).chain([None]) {
            claims.push(RecordClaim {
                collection: collection.clone(),
                rkey: rkey.clone(),
                cid,
            });
        }
    }
    if let Ok(verdict) = verify_proofs(data, did, key.public_key(), &claims) {
        for claim in &verdict.verified {
            let record = claim
                .cid
                .map(|c| *records.iter().find(|r| cid(r) == c).expect("claimed"));
            assert!(
                possible(claim.rkey.as_str(), record),
                "verified a false claim"
            );
        }
    }
    if let Ok(found) = verify_records(data, did, key.public_key()) {
        for r in found {
            assert_eq!(r.collection, *collection);
            assert!(
                possible(r.rkey.as_str(), Some(&r.record)),
                "accepted a record the key never signed"
            );
        }
    }
});
