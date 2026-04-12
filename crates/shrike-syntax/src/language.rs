use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// A validated BCP-47 language tag (simplified).
///
/// Rules:
/// - Primary subtag: 2–3 lowercase ASCII letters, or `"i"` for grandfathered tags
/// - Optional subtags separated by `-`
/// - Each subtag: 1–8 alphanumeric characters (case-insensitive in value, but
///   primary must be lowercase)
/// - No empty subtags (no trailing or double hyphens)
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

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 128 {
            return Err(err("too long"));
        }

        let b = raw.as_bytes();

        // Primary subtag: lowercase alpha characters (until '-' or end)
        let mut i = 0usize;
        while i < b.len() && b[i] != b'-' {
            if !b[i].is_ascii_lowercase() {
                return Err(err("primary subtag must be lowercase alpha"));
            }
            i += 1;
        }

        if i == 0 {
            return Err(err("empty primary subtag"));
        }
        if i == 1 && b[0] != b'i' {
            return Err(err("single-char primary subtag must be 'i'"));
        }
        if i > 3 {
            return Err(err("primary subtag too long"));
        }

        // Subsequent subtags: hyphen-separated alphanumeric (1-8 chars each)
        while i < b.len() {
            if b[i] != b'-' {
                return Err(err("expected hyphen"));
            }
            i += 1; // skip hyphen
            let start = i;
            while i < b.len() && b[i] != b'-' {
                if !b[i].is_ascii_alphanumeric() {
                    return Err(err("subtag must be alphanumeric"));
                }
                i += 1;
            }
            let subtag_len = i - start;
            if subtag_len == 0 {
                return Err(err("empty subtag"));
            }
            if subtag_len > 8 {
                return Err(err("subtag too long"));
            }
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

    #[test]
    fn language_valid_grandfathered_i() {
        Language::try_from("i").unwrap();
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
