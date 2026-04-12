#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_cbor::Cid;

// Fuzz CID binary parsing with arbitrary bytes.
//
// Invariants tested:
// 1. from_bytes must never panic on any input.
// 2. If from_bytes succeeds, to_bytes -> from_bytes must produce an equal CID.
fuzz_target!(|data: &[u8]| {
    let cid = match Cid::from_bytes(data) {
        Ok(c) => c,
        Err(_) => return,
    };

    let bytes = cid.to_bytes();
    let roundtripped = Cid::from_bytes(&bytes)
        .expect("CID roundtrip from_bytes -> to_bytes -> from_bytes must succeed");
    assert_eq!(cid, roundtripped, "CID binary roundtrip mismatch");
});
