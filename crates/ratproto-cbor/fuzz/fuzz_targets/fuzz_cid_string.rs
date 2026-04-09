#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_cbor::Cid;

// Fuzz CID string parsing (base32lower format).
//
// Invariants tested:
// 1. from_str must never panic on any input.
// 2. If from_str succeeds, to_string -> from_str must produce an equal CID.
fuzz_target!(|data: &str| {
    let cid: Cid = match data.parse() {
        Ok(c) => c,
        Err(_) => return,
    };

    let s = cid.to_string();
    let roundtripped: Cid = s
        .parse()
        .expect("CID string roundtrip to_string -> from_str must succeed");
    assert_eq!(cid, roundtripped, "CID string roundtrip mismatch");
});
