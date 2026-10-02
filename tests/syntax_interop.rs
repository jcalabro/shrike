//! Differential tests against the reference TypeScript `@atproto/syntax`.
//!
//! The vectors come from `scripts/syntax-vectors.mjs`, which runs the
//! reference over its interop fixtures, every string in its own tests, and
//! generated and mutated values, recording each verdict. Point
//! `SHRIKE_SYNTAX_VECTORS` at a larger generated file for a deeper run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::Deserialize;
use shrike::syntax::Language;

#[derive(Deserialize)]
struct Vectors {
    atproto: String,
    language: Verdicts,
}

#[derive(Deserialize)]
struct Verdicts {
    valid: Vec<String>,
    invalid: Vec<String>,
}

fn vectors() -> Vectors {
    let path = std::env::var("SHRIKE_SYNTAX_VECTORS")
        .unwrap_or_else(|_| "testdata/syntax/ts_vectors.json".to_owned());
    serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap()
}

/// Every value must get the reference's verdict.
fn check(name: &str, atproto: &str, verdicts: &Verdicts, accepts: impl Fn(&str) -> bool) {
    assert!(
        !verdicts.valid.is_empty() && !verdicts.invalid.is_empty(),
        "{name}: no vectors"
    );
    let mut wrong: Vec<String> = Vec::new();
    for (expected, values) in [(true, &verdicts.valid), (false, &verdicts.invalid)] {
        for v in values {
            if accepts(v) != expected {
                wrong.push(format!("{v:?} (reference: {expected})"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{name}: {} of {} values disagree with @atproto/syntax at {atproto}:\n{}",
        wrong.len(),
        verdicts.valid.len() + verdicts.invalid.len(),
        wrong
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn language_matches_reference() {
    let v = vectors();
    check("language", &v.atproto, &v.language, |s| {
        Language::try_from(s).is_ok()
    });
}
