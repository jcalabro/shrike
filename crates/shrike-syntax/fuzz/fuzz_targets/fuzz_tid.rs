#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_syntax::Tid;

// Fuzz TID parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, to_string must produce the original input.
fuzz_target!(|data: &str| {
    let tid = match Tid::try_from(data) {
        Ok(t) => t,
        Err(_) => return,
    };

    assert_eq!(
        tid.to_string(),
        data,
        "TID display roundtrip mismatch"
    );
});
