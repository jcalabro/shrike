#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_crypto::{P256VerifyingKey, VerifyingKey};

// Fuzz P-256 public key parsing from arbitrary 33-byte SEC1 compressed point bytes.
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

    let key = match P256VerifyingKey::from_bytes(&arr) {
        Ok(k) => k,
        Err(_) => return,
    };

    let bytes = key.to_bytes();
    let roundtripped = P256VerifyingKey::from_bytes(&bytes)
        .expect("P256 key roundtrip must succeed");
    assert_eq!(
        key.to_bytes(),
        roundtripped.to_bytes(),
        "P256 key roundtrip mismatch"
    );
});
