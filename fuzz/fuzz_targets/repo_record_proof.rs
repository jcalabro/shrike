#![no_main]
//! `verify_record_proof` must never panic on arbitrary bytes, and must never
//! accept a record the signing key did not commit to.
//!
//! The key is fixed, and every commit it signs (see `gen_seeds`) holds
//! `RECORD` at `com.example.present` and nothing at `com.example.absent`.
//! Mutations cannot produce new signatures, so any accepted proof must report
//! exactly that.

use std::sync::LazyLock;

use libfuzzer_sys::fuzz_target;
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::repo::verify_record_proof;
use shrike::syntax::{Did, Nsid, RecordKey};

/// Shared with `gen_seeds`.
const KEY: [u8; 32] = [7; 32];
const DID: &str = "did:plc:fuzzfuzzfuzzfuzzfuzzfuzz";
const RECORD: &[u8] = b"\xa1\x62id\x73com.example.present";

static SETUP: LazyLock<(P256SigningKey, Did, Nsid)> = LazyLock::new(|| {
    (
        P256SigningKey::from_bytes(&KEY).expect("valid key"),
        Did::try_from(DID).expect("valid DID"),
        Nsid::try_from("com.atproto.lexicon.schema").expect("valid NSID"),
    )
});

fuzz_target!(|data: &[u8]| {
    let (key, did, collection) = &*SETUP;
    for (rkey, expected) in [
        ("com.example.present", Some(RECORD)),
        ("com.example.absent", None),
    ] {
        let rkey = RecordKey::try_from(rkey).expect("valid rkey");
        if let Ok(proof) = verify_record_proof(data, did, key.public_key(), collection, &rkey) {
            assert_eq!(
                proof.record.as_ref().map(|(_, bytes)| bytes.as_slice()),
                expected,
                "accepted a record the key never signed"
            );
        }
    }
});
