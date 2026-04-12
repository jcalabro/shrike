#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_lexicon::Catalog;

// Fuzz Lexicon schema parsing with arbitrary bytes (treated as JSON).
//
// This is a medium-value target: Lexicon schemas are typically trusted, but
// the parser should still be robust against malformed input. Crashes and
// panics are bugs.
fuzz_target!(|data: &[u8]| {
    let mut catalog = Catalog::new();
    // Attempt to parse the data as a Lexicon schema. Any error is expected.
    let _ = catalog.add_schema(data);
});
