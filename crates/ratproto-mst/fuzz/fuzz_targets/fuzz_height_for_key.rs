#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_mst::height_for_key;

// Fuzz MST key height computation.
//
// Invariants tested:
// 1. height_for_key must never panic on any input.
// 2. The result must be deterministic (same input always gives same height).
// 3. Height must be <= 128 (theoretical maximum for 32-byte SHA-256 hash).
fuzz_target!(|data: &str| {
    let h1 = height_for_key(data);
    let h2 = height_for_key(data);

    assert_eq!(h1, h2, "height_for_key is not deterministic");
    assert!(h1 <= 128, "height exceeds maximum of 128");
});
