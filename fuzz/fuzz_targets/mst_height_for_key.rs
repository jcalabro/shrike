#![no_main]
//! MST height computation must never panic, be deterministic, and stay in
//! range [0, 128].

use libfuzzer_sys::fuzz_target;
use shrike::mst::height_for_key;

fuzz_target!(|key: &str| {
    let h1 = height_for_key(key);
    let h2 = height_for_key(key);
    assert_eq!(h1, h2, "non-deterministic height for {key:?}");
    assert!(h1 <= 128, "height out of range for {key:?}: {h1}");
});
