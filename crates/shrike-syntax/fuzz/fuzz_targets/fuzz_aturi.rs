#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_syntax::AtUri;

// Fuzz AT-URI parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, to_string must produce the original input.
fuzz_target!(|data: &str| {
    let uri = match AtUri::try_from(data) {
        Ok(u) => u,
        Err(_) => return,
    };

    assert_eq!(
        uri.to_string(),
        data,
        "AT-URI display roundtrip mismatch"
    );
});
