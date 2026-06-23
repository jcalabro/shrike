//! Cross-implementation DRISL/DAG-CBOR conformance, driven by vendored vectors:
//!
//! - `testdata/cbor_data_model_fixtures.json` — AT Protocol data-model fixtures
//!   (JSON + canonical CBOR + the resulting CID). Pins shrike's decode and CID
//!   computation against the canonical cross-impl values.
//! - `testdata/cbor_rfc8949_vectors.json` — the RFC 8949 test corpus
//!   (valid/canonical/invalid). DAG-CBOR is *stricter* than standard CBOR, so
//!   every RFC-invalid vector must be rejected, and the canonical vectors in
//!   the DAG-CBOR-supported subset must decode and re-encode unchanged.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
#![cfg(feature = "cbor")]

use serde::Deserialize;
use shrike::cbor::{Cid, Codec, decode, encode_value};

fn b64(s: &str) -> Vec<u8> {
    // The data-model fixtures use unpadded standard base64.
    data_encoding::BASE64_NOPAD.decode(s.as_bytes()).unwrap()
}

fn hex(s: &str) -> Vec<u8> {
    data_encoding::HEXLOWER_PERMISSIVE
        .decode(s.as_bytes())
        .unwrap()
}

#[derive(Debug, Deserialize)]
struct DataModelFixture {
    cbor_base64: String,
    cid: String,
}

#[test]
fn data_model_fixtures_cid_matches() {
    let raw = std::fs::read_to_string("testdata/cbor_data_model_fixtures.json").unwrap();
    let fixtures: Vec<DataModelFixture> = serde_json::from_str(&raw).unwrap();
    assert!(!fixtures.is_empty(), "no fixtures loaded");

    for f in &fixtures {
        let bytes = b64(&f.cbor_base64);

        // 1. The canonical CBOR must decode.
        let value = decode(&bytes)
            .unwrap_or_else(|e| panic!("canonical fixture must decode: {e} (cid {})", f.cid));

        // 2. The CID over those exact bytes must equal the canonical CID.
        let computed = Cid::compute(Codec::Drisl, &bytes);
        assert_eq!(
            computed.to_string(),
            f.cid,
            "CID mismatch for a data-model fixture"
        );

        // 3. Re-encoding the decoded value must reproduce the canonical bytes
        //    (shrike's encoding agrees with the cross-impl canonical form).
        let re = encode_value(&value).unwrap();
        assert_eq!(
            re, bytes,
            "re-encode diverged from the canonical CBOR for cid {}",
            f.cid
        );
    }
}

#[derive(Debug, Deserialize)]
struct Rfc8949Vector {
    hex: String,
    #[serde(default)]
    flags: Vec<String>,
}

impl Rfc8949Vector {
    fn has_flag(&self, f: &str) -> bool {
        self.flags.iter().any(|x| x == f)
    }
}

fn load_rfc8949() -> Vec<Rfc8949Vector> {
    let raw = std::fs::read_to_string("testdata/cbor_rfc8949_vectors.json").unwrap();
    serde_json::from_str(&raw).unwrap()
}

#[test]
fn rfc8949_invalid_must_reject() {
    // DAG-CBOR is stricter than standard CBOR: every RFC-8949-invalid vector
    // must be rejected by shrike's strict decoder.
    let vectors = load_rfc8949();
    let mut ran = 0;
    for v in &vectors {
        if !v.has_flag("invalid") {
            continue;
        }
        ran += 1;
        let bytes = hex(&v.hex);
        assert!(
            decode(&bytes).is_err(),
            "expected rejection of RFC-invalid CBOR {}",
            v.hex
        );
    }
    assert!(ran > 600, "expected the full invalid corpus, ran {ran}");
}

#[test]
fn rfc8949_canonical_roundtrips_or_is_rejected() {
    // For every RFC-8949 *canonical* vector, shrike must either (a) decode it
    // and re-encode to the identical bytes — a canonical fixed point — or
    // (b) reject it outright (DAG-CBOR is stricter than standard CBOR, e.g. it
    // forbids integer map keys, non-42 tags, simple values, float16/32). It must
    // NEVER decode a canonical vector into something that re-encodes
    // differently; that would be a canonicalization bug. This invariant holds
    // for the whole canonical corpus without needing to enumerate every DRISL
    // restriction in the filter.
    let vectors = load_rfc8949();
    let mut accepted = 0;
    let mut rejected = 0;
    for v in &vectors {
        if !v.has_flag("canonical") {
            continue;
        }
        let bytes = hex(&v.hex);
        match decode(&bytes) {
            Ok(value) => {
                let re = encode_value(&value).unwrap();
                assert_eq!(
                    re, bytes,
                    "canonical vector {} decoded but re-encoded differently",
                    v.hex
                );
                accepted += 1;
            }
            Err(_) => rejected += 1,
        }
    }
    // Sanity: the corpus exercised both branches.
    assert!(
        accepted > 20,
        "expected a meaningful accept subset, got {accepted}"
    );
    assert!(
        rejected > 0,
        "expected some canonical-but-non-DRISL rejections"
    );
}
