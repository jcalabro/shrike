#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_syntax::Language;

// Fuzz Language tag parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, to_string must produce the original input.
fuzz_target!(|data: &str| {
    let lang = match Language::try_from(data) {
        Ok(l) => l,
        Err(_) => return,
    };

    assert_eq!(
        lang.to_string(),
        data,
        "Language display roundtrip mismatch"
    );
});
