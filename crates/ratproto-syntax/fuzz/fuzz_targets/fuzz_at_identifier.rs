#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_syntax::AtIdentifier;

// Fuzz AtIdentifier parsing with arbitrary string input.
//
// Invariants tested:
// 1. TryFrom must never panic on any input.
// 2. If parsing succeeds, exactly one of is_did() / is_handle() must be true.
// 3. Re-parsing the display output must produce an equal identifier.
fuzz_target!(|data: &str| {
    let id = match AtIdentifier::try_from(data) {
        Ok(i) => i,
        Err(_) => return,
    };

    // Exactly one variant must be active.
    assert!(
        id.is_did() ^ id.is_handle(),
        "AtIdentifier must be exactly one of DID or Handle"
    );

    // Roundtrip through display.
    let displayed = id.to_string();
    let reparsed = AtIdentifier::try_from(displayed.as_str())
        .expect("re-parsing displayed AtIdentifier must succeed");
    assert_eq!(
        id, reparsed,
        "AtIdentifier display roundtrip mismatch"
    );
});
