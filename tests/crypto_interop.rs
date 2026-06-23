//! Cross-implementation crypto interop tests driven by the official atproto
//! signature fixtures (vendored from atproto-interop-tests / atmos at
//! `testdata/crypto_signature_fixtures.json`).
//!
//! These assert that signature verification matches the spec: low-S signatures
//! verify, while high-S (malleable) and DER-encoded signatures are rejected on
//! BOTH curves. The high-S cases are regression guards for the P-256
//! malleability bug (verify_prehash does not enforce low-S on its own).
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "crypto")]

use serde::Deserialize;
use shrike::crypto::{Signature, parse_did_key};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    comment: String,
    message_base64: String,
    public_key_did: String,
    signature_base64: String,
    valid_signature: bool,
    #[serde(default)]
    tags: Vec<String>,
}

fn b64(s: &str) -> Vec<u8> {
    // atproto fixtures use standard base64 without padding (RawStdEncoding).
    data_encoding::BASE64_NOPAD.decode(s.as_bytes()).unwrap()
}

#[test]
fn signature_fixtures_interop() {
    let raw = std::fs::read_to_string("testdata/crypto_signature_fixtures.json").unwrap();
    let fixtures: Vec<Fixture> = serde_json::from_str(&raw).unwrap();
    assert!(!fixtures.is_empty(), "no fixtures loaded");

    let mut saw_low_s = false;
    let mut saw_high_s = false;
    let mut saw_der = false;

    for f in &fixtures {
        let key = parse_did_key(&f.public_key_did)
            .unwrap_or_else(|e| panic!("parse did key {}: {e}", f.public_key_did));
        let msg = b64(&f.message_base64);
        let sig_bytes = b64(&f.signature_base64);

        // DER-encoded signatures are not 64-byte compact; constructing a
        // Signature requires exactly 64 bytes, so these must fail to even build
        // a signature (which is itself a valid rejection).
        if sig_bytes.len() != 64 {
            assert!(
                !f.valid_signature,
                "fixture {:?} has non-64-byte sig but claims valid",
                f.comment
            );
            saw_der = true;
            continue;
        }

        let mut arr = [0u8; 64];
        arr.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(arr);
        let result = key.verify(&msg, &sig);

        if f.valid_signature {
            saw_low_s = true;
            assert!(
                result.is_ok(),
                "fixture {:?} should verify but did not: {result:?}",
                f.comment
            );
        } else {
            if f.tags.iter().any(|t| t == "high-s") {
                saw_high_s = true;
            }
            assert!(
                result.is_err(),
                "fixture {:?} (tags {:?}) must be REJECTED but verified Ok — signature malleability",
                f.comment,
                f.tags
            );
        }
    }

    // Make sure the corpus actually exercised all three categories on both
    // curves, so a future corpus change can't silently gut the test.
    assert!(saw_low_s, "no valid low-S fixture exercised");
    assert!(saw_high_s, "no high-S rejection fixture exercised");
    assert!(saw_der, "no DER-encoded rejection fixture exercised");
}
