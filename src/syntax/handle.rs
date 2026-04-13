use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::syntax::SyntaxError;

/// A validated AT Protocol Handle (domain-name-based user identifier).
///
/// Guaranteed to be valid on construction and stored in normalized (lowercase) form.
/// Use `TryFrom<&str>` or `.parse()`.
///
/// The sentinel value `"handle.invalid"` is accepted as a valid handle.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Handle(String);

impl Handle {
    /// Returns the inner string slice (normalized to lowercase).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Handle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Handle {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Handle {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Handle {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidHandle(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 253 {
            return Err(err("too long"));
        }

        // Walk through dot-separated labels, validating each one.
        let mut label_count = 0usize;
        let bytes = raw.as_bytes();
        let mut start = 0usize;

        let mut i = 0usize;
        loop {
            let at_end = i == bytes.len();
            if at_end || bytes[i] == b'.' {
                let label = &raw[start..i];

                if label.is_empty() {
                    return Err(err("empty label"));
                }
                if label.len() > 63 {
                    return Err(err("label too long"));
                }

                let lb = label.as_bytes();

                // First character must be ASCII alphanumeric.
                if !lb[0].is_ascii_alphanumeric() {
                    return Err(err("label must start with alphanumeric"));
                }

                // Last character must be ASCII alphanumeric.
                if !lb[lb.len() - 1].is_ascii_alphanumeric() {
                    return Err(err("label must end with alphanumeric"));
                }

                // Interior characters must be alphanumeric or hyphen.
                // Only exists when label has at least 3 characters.
                if lb.len() >= 3 {
                    for &b in &lb[1..lb.len() - 1] {
                        if !b.is_ascii_alphanumeric() && b != b'-' {
                            return Err(err("invalid character in label"));
                        }
                    }
                }

                label_count += 1;
                start = i + 1;
            } else {
                // Character is not '.' — validate it is ASCII alphanumeric or hyphen.
                // (We still do per-character checks below inside label validation above,
                // but we also need to reject non-ASCII bytes that might appear between dots.)
                if !bytes[i].is_ascii() {
                    return Err(err("non-ASCII character"));
                }
            }

            if at_end {
                break;
            }
            i += 1;
        }

        if label_count < 2 {
            return Err(err("must have at least two labels"));
        }

        // TLD (last label) must start with a letter (not a digit).
        let Some(last_dot) = raw.rfind('.') else {
            return Err(err("must have at least two labels"));
        };
        let tld = &raw[last_dot + 1..];
        if !tld.as_bytes()[0].is_ascii_alphabetic() {
            return Err(err("TLD must start with a letter"));
        }

        // Normalize to lowercase.
        Ok(Handle(raw.to_ascii_lowercase()))
    }
}

impl FromStr for Handle {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Handle::try_from(s)
    }
}

impl Serialize for Handle {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Handle {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Handle::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    fn load_vectors(path: &str) -> Vec<String> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .filter(|l| {
                let t = l.trim();
                !t.is_empty() && !t.starts_with('#')
            })
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_valid_handles() {
        let vectors = load_vectors("testdata/handle_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            Handle::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid handle: {v:?}, got error: {e}"));
        }
    }

    #[test]
    fn parse_invalid_handles() {
        let vectors = load_vectors("testdata/handle_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            assert!(
                Handle::try_from(v.as_str()).is_err(),
                "should be invalid handle: {v:?}"
            );
        }
    }

    #[test]
    fn handle_normalize_lowercase() {
        let h = Handle::try_from("Alice.Bsky.Social").unwrap();
        assert_eq!(h.as_str(), "alice.bsky.social");
        assert_eq!(h.to_string(), "alice.bsky.social");
    }

    #[test]
    fn handle_serde_roundtrip() {
        let h = Handle::try_from("alice.bsky.social").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        let parsed: Handle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn handle_reject_single_label() {
        assert!(Handle::try_from("localhost").is_err());
    }

    #[test]
    fn handle_reject_hyphen_boundaries() {
        assert!(Handle::try_from("-alice.example.com").is_err());
        assert!(Handle::try_from("alice-.example.com").is_err());
    }
}
