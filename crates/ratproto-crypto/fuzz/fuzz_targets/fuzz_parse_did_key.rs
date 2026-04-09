#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_crypto::parse_did_key;

// Fuzz did:key string parsing with arbitrary input.
//
// Invariants tested:
// 1. parse_did_key must never panic on any input.
// 2. If parsing succeeds, did_key() on the result must produce a string
//    that re-parses to a key with the same bytes.
fuzz_target!(|data: &str| {
    let key = match parse_did_key(data) {
        Ok(k) => k,
        Err(_) => return,
    };

    // Roundtrip: the parsed key's did_key() string must re-parse to the same key.
    let did_key_str = key.did_key();
    let reparsed = parse_did_key(&did_key_str)
        .expect("re-parsing did_key() output must succeed");
    assert_eq!(
        key.to_bytes(),
        reparsed.to_bytes(),
        "did:key roundtrip produced different key bytes"
    );
});
