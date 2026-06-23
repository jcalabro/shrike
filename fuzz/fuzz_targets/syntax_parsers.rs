#![no_main]
//! All AT Protocol identifier parsers must never panic on arbitrary UTF-8, and
//! each must be *idempotent under normalization*: if a string parses, then
//! re-parsing its canonical (`Display`) form must succeed and yield the same
//! canonical form. This catches normalization bugs and any input that parses
//! but whose output the parser would then reject (a round-trip hole).

use libfuzzer_sys::fuzz_target;
use shrike::syntax::{AtIdentifier, AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid};

/// Parse `s` with `T::try_from`; if it succeeds, the canonical form must
/// re-parse to the identical canonical form (idempotent normalization).
macro_rules! check {
    ($ty:ty, $s:expr) => {{
        if let Ok(v) = <$ty>::try_from($s) {
            let canon = v.to_string();
            let v2 = <$ty>::try_from(canon.as_str())
                .expect(concat!(stringify!($ty), ": canonical form must re-parse"));
            assert_eq!(
                canon,
                v2.to_string(),
                concat!(stringify!($ty), ": normalization is not idempotent")
            );
        }
    }};
}

fuzz_target!(|s: &str| {
    check!(Did, s);
    check!(Handle, s);
    check!(Nsid, s);
    check!(AtUri, s);
    check!(RecordKey, s);
    check!(Tid, s);
    check!(Datetime, s);
    check!(Language, s);
    check!(AtIdentifier, s);
});
