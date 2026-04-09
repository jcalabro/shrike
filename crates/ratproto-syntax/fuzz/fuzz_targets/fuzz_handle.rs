#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_syntax::Handle;

// Fuzz Handle parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, the handle is stored in normalized (lowercase) form,
//    so to_string equals the lowercased input.
fuzz_target!(|data: &str| {
    let handle = match Handle::try_from(data) {
        Ok(h) => h,
        Err(_) => return,
    };

    // Handles normalize to lowercase, so compare against lowercased input.
    assert_eq!(
        handle.to_string(),
        data.to_ascii_lowercase(),
        "Handle display roundtrip mismatch"
    );
});
