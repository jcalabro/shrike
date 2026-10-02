#![no_main]
//! Differential oracle: `drisl_to_json_into` MUST write exactly the bytes
//! `serde_json::to_vec` writes of `drisl_to_json`, or fail with the same error,
//! leaving its buffer as it was.

use libfuzzer_sys::fuzz_target;
use shrike::cbor::json::{drisl_to_json, drisl_to_json_into};

fuzz_target!(|data: &[u8]| {
    let mut out = b"held".to_vec();
    let actual = drisl_to_json_into(data, &mut out);
    match drisl_to_json(data) {
        Ok(json) => {
            actual.expect("the writer rejected what drisl_to_json accepts");
            assert_eq!(out[..4], *b"held");
            assert_eq!(out[4..], serde_json::to_vec(&json).unwrap());
        }
        Err(want) => {
            let got = actual.expect_err("the writer accepted what drisl_to_json rejects");
            assert_eq!(format!("{got:?}"), format!("{want:?}"));
            assert_eq!(out, b"held");
        }
    }
});
