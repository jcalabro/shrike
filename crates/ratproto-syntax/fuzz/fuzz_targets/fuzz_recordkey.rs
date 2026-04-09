#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_syntax::RecordKey;

// Fuzz RecordKey parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, to_string must produce the original input.
fuzz_target!(|data: &str| {
    let rk = match RecordKey::try_from(data) {
        Ok(r) => r,
        Err(_) => return,
    };

    assert_eq!(
        rk.to_string(),
        data,
        "RecordKey display roundtrip mismatch"
    );
});
