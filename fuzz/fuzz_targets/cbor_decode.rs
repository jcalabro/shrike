#![no_main]
//! The strict DRISL/DAG-CBOR decoder must never panic on arbitrary input, and
//! anything it accepts must re-encode to the identical bytes (canonical form is
//! a fixed point — no non-canonical input is ever accepted).

use libfuzzer_sys::fuzz_target;
use shrike::cbor::{decode, encode_value};

fuzz_target!(|data: &[u8]| {
    let Ok(value) = decode(data) else {
        return;
    };
    // A strict canonical decoder only accepts canonical bytes, so re-encoding a
    // decoded value must reproduce the exact input.
    let re_encoded = encode_value(&value).expect("re-encode of a decoded value must succeed");
    assert_eq!(
        data, re_encoded,
        "decoded value did not re-encode to identical (canonical) bytes"
    );
});
