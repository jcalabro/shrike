use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::syntax::SyntaxError;

/// A validated BCP-47 language tag ([RFC 5646]).
///
/// Matches the reference implementation's strict check (`@atproto/syntax`
/// `parseLanguageString`, which the lexicon `language` format uses):
/// - a well-formed tag per the RFC 5646 §2.1 grammar: a language with up to
///   three extlangs, then an optional script and region, variants,
///   extensions, and a private-use part; a private-use tag (`x-…`); or one
///   of the grandfathered tags, matched exactly
/// - the primary language subtag is 2–3 lowercase letters; the other
///   subtags are case-insensitive
/// - no variant or extension singleton repeats (RFC 5646 §2.2.5, §2.2.6),
///   compared case-insensitively
///
/// [RFC 5646]: https://www.rfc-editor.org/rfc/rfc5646.html
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Language(String);

impl Language {
    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Language {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Language {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Language {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Language {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidLanguage(format!("{raw:?}: {msg}"));

        if !GRANDFATHERED.contains(&raw) && !is_langtag_or_private_use(raw) {
            return Err(err("not a valid BCP-47 language tag"));
        }
        Ok(Language(raw.to_owned()))
    }
}

impl FromStr for Language {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Language::try_from(s)
    }
}

impl Serialize for Language {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Language {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Language::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

/// The RFC 5646 §2.1 irregular and regular grandfathered tags, matched
/// case-sensitively as the reference does.
const GRANDFATHERED: [&str; 26] = [
    "en-GB-oed",
    "i-ami",
    "i-bnn",
    "i-default",
    "i-enochian",
    "i-hak",
    "i-klingon",
    "i-lux",
    "i-mingo",
    "i-navajo",
    "i-pwn",
    "i-tao",
    "i-tay",
    "i-tsu",
    "sgn-BE-FR",
    "sgn-BE-NL",
    "sgn-CH-DE",
    "art-lojban",
    "cel-gaulish",
    "no-bok",
    "no-nyn",
    "zh-guoyu",
    "zh-hakka",
    "zh-min",
    "zh-min-nan",
    "zh-xiang",
];

/// Whether `raw` is a `langtag` or a private-use tag. Every subtag kind has
/// a distinct shape where it can appear, so taking each greedily in grammar
/// order parses exactly what the RFC's ABNF accepts.
fn is_langtag_or_private_use(raw: &str) -> bool {
    let mut tags = raw.split('-').peekable();
    let Some(primary) = tags.next() else {
        return false;
    };
    if primary.eq_ignore_ascii_case("x") {
        return is_private_use(tags);
    }
    if !(2..=3).contains(&primary.len()) || !primary.bytes().all(|b| b.is_ascii_lowercase()) {
        return false;
    }

    for _ in 0..3 {
        if tags.next_if(|t| t.len() == 3 && is_alpha(t)).is_none() {
            break;
        }
    }
    tags.next_if(|t| t.len() == 4 && is_alpha(t));
    tags.next_if(|t| (t.len() == 2 && is_alpha(t)) || (t.len() == 3 && is_digit(t)));

    let mut variants: Vec<&str> = Vec::new();
    while let Some(v) = tags.next_if(|t| is_variant(t)) {
        if variants.iter().any(|seen| seen.eq_ignore_ascii_case(v)) {
            return false;
        }
        variants.push(v);
    }

    let mut singletons: Vec<u8> = Vec::new();
    while let Some(s) =
        tags.next_if(|t| t.len() == 1 && is_alnum(t) && !t.eq_ignore_ascii_case("x"))
    {
        let s = s.as_bytes()[0].to_ascii_lowercase();
        if singletons.contains(&s) {
            return false;
        }
        singletons.push(s);
        let mut subtags = 0;
        while tags
            .next_if(|t| (2..=8).contains(&t.len()) && is_alnum(t))
            .is_some()
        {
            subtags += 1;
        }
        if subtags == 0 {
            return false;
        }
    }

    match tags.next() {
        None => true,
        Some(x) if x.eq_ignore_ascii_case("x") => is_private_use(tags),
        Some(_) => false,
    }
}

/// One or more 1–8 character alphanumeric subtags.
fn is_private_use<'a>(tags: impl Iterator<Item = &'a str>) -> bool {
    let mut any = false;
    for t in tags {
        if !(1..=8).contains(&t.len()) || !is_alnum(t) {
            return false;
        }
        any = true;
    }
    any
}

/// 5–8 alphanumerics, or a digit and three alphanumerics.
fn is_variant(t: &str) -> bool {
    is_alnum(t)
        && ((5..=8).contains(&t.len()) || (t.len() == 4 && t.as_bytes()[0].is_ascii_digit()))
}

fn is_alpha(t: &str) -> bool {
    t.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_digit(t: &str) -> bool {
    t.bytes().all(|b| b.is_ascii_digit())
}

fn is_alnum(t: &str) -> bool {
    t.bytes().all(|b| b.is_ascii_alphanumeric())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    #[test]
    fn language_valid_en() {
        Language::try_from("en").unwrap();
    }

    #[test]
    fn language_valid_en_us() {
        Language::try_from("en-US").unwrap();
    }

    #[test]
    fn language_reject_uppercase_primary() {
        assert!(Language::try_from("EN").is_err());
    }

    #[test]
    fn language_reject_empty_subtag() {
        assert!(Language::try_from("en-").is_err());
    }

    #[test]
    fn language_serde_roundtrip() {
        let lang = Language::try_from("en").unwrap();
        let json = serde_json::to_string(&lang).unwrap();
        let parsed: Language = serde_json::from_str(&json).unwrap();
        assert_eq!(lang, parsed);
    }

    fn load_vectors(path: &str) -> Vec<String> {
        std::fs::read_to_string(path)
            .unwrap()
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    #[test]
    fn language_interop_valid() {
        let vectors = load_vectors("testdata/language_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no vectors loaded");
        for v in &vectors {
            Language::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid language: {v:?}, got error: {e}"));
        }
    }

    #[test]
    fn language_interop_invalid() {
        // language_parse_invalid.txt holds tags that are well-formed but
        // fail the reference's strict check, which is the one we implement.
        for path in [
            "testdata/language_syntax_invalid.txt",
            "testdata/language_parse_invalid.txt",
        ] {
            let vectors = load_vectors(path);
            assert!(!vectors.is_empty(), "no vectors loaded from {path}");
            for v in &vectors {
                assert!(
                    Language::try_from(v.as_str()).is_err(),
                    "should be invalid language: {v:?}"
                );
            }
        }
    }

    /// Regression test: the simplified check rejected private-use tags and
    /// accepted ungrammatical subtag sequences.
    #[test]
    fn language_follows_rfc_5646_grammar() {
        for valid in [
            "X-fr-CH",
            "x-foo",
            "x-a-12345678",
            "en-x-a",
            "en-x-a-x-b",
            "de-X-foo",
            "zh-yue",
            "zh-yue-abc-def",
            "zh-Hant-TW",
            "sr-Latn-RS",
            "es-419",
            "en-US-u-ca-gregory",
            "en-a-bb-b-cc",
            "de-CH-1901",
            "sl-rozaj-biske-1994",
            "en-GB-oed",
            "i-klingon",
            "zh-min-nan",
            "art-lojban",
            "en-us",
            "en-Us",
        ] {
            assert!(
                Language::try_from(valid).is_ok(),
                "{valid:?} should be valid"
            );
        }
        for invalid in [
            "",
            "i",
            "i-foo",
            "I-default",
            "en-gb-oed",
            "en-a",
            "en-a-b",
            "en-a-123456789",
            "en-x",
            "x",
            "x-",
            "x-123456789",
            "sl-rozaj-rozaj",
            "en-rozaj-ROZAJ",
            "en-a-foo-A-bar",
            "en-US-US",
            "en-Latn-Latn",
            "zh-yue-abc-def-ghi",
            "en-1",
            "en-12",
            "en-1234567890",
            "en-abc1",
            "abcd",
            "abcde-US",
            "En",
            "en_US",
            "en-",
            "-en",
            "en--US",
            "en-US-",
            "en-US ",
            " en",
            "en\n",
            "e\u{301}n",
            "en-x-123456789",
        ] {
            assert!(
                Language::try_from(invalid).is_err(),
                "{invalid:?} should be invalid"
            );
        }
    }

    #[test]
    fn language_has_no_length_limit() {
        // The grammar bounds no tag's length, and neither does the reference.
        let long = format!("en-a{}", "-abcdefgh".repeat(100));
        assert!(long.len() > 128);
        Language::try_from(long.as_str()).unwrap();
    }

    #[test]
    fn language_reject_single_non_i() {
        assert!(Language::try_from("a").is_err());
    }

    #[test]
    fn language_valid_zh_hans() {
        Language::try_from("zh-Hans").unwrap();
    }

    #[test]
    fn language_reject_empty() {
        assert!(Language::try_from("").is_err());
    }

    #[test]
    fn language_reject_primary_too_long() {
        assert!(Language::try_from("engl").is_err());
    }
}
