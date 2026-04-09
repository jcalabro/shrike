#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_syntax::Did;

// Fuzz DID parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, to_string must produce the original input.
fuzz_target!(|data: &str| {
    let did = match Did::try_from(data) {
        Ok(d) => d,
        Err(_) => return,
    };

    assert_eq!(
        did.to_string(),
        data,
        "DID display roundtrip mismatch"
    );
});
