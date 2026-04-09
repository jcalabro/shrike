#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_syntax::Datetime;

// Fuzz Datetime parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom (strict) and parse_lenient must never panic on any input.
// 2. If strict parsing succeeds, to_string must produce the original input.
// 3. If lenient parsing succeeds, re-parsing the output strictly must also succeed.
fuzz_target!(|data: &str| {
    // Strict parsing.
    if let Ok(dt) = Datetime::try_from(data) {
        assert_eq!(
            dt.to_string(),
            data,
            "Datetime strict display roundtrip mismatch"
        );
    }

    // Lenient parsing — the output must be valid under strict parsing.
    if let Ok(dt) = Datetime::parse_lenient(data) {
        let s = dt.to_string();
        let _ = Datetime::try_from(s.as_str())
            .expect("lenient output must pass strict validation");
    }
});
