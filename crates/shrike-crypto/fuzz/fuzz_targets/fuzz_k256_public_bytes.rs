#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_crypto::{K256VerifyingKey, VerifyingKey};

// Fuzz K-256 (secp256k1) public key parsing from arbitrary 33-byte compressed point bytes.
//
// Invariants tested:
// 1. from_bytes must never panic on any input.
// 2. If parsing succeeds, to_bytes -> from_bytes must produce an equal key.
fuzz_target!(|data: &[u8]| {
    if data.len() != 33 {
        return;
    }
    let mut arr = [0u8; 33];
    arr.copy_from_slice(data);

    let key = match K256VerifyingKey::from_bytes(&arr) {
        Ok(k) => k,
        Err(_) => return,
    };

    let bytes = key.to_bytes();
    let roundtripped = K256VerifyingKey::from_bytes(&bytes)
        .expect("K256 key roundtrip must succeed");
    assert_eq!(
        key.to_bytes(),
        roundtripped.to_bytes(),
        "K256 key roundtrip mismatch"
    );
});
