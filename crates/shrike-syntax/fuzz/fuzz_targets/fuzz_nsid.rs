#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_syntax::Nsid;

// Fuzz NSID parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, re-parsing the display output must produce an equal NSID.
//    (Direct string comparison is not valid because authority segments are lowercased.)
fuzz_target!(|data: &str| {
    let nsid = match Nsid::try_from(data) {
        Ok(n) => n,
        Err(_) => return,
    };

    let displayed = nsid.to_string();
    let reparsed = Nsid::try_from(displayed.as_str())
        .expect("re-parsing displayed NSID must succeed");
    assert_eq!(nsid, reparsed, "NSID parse-display roundtrip mismatch");
});
