use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// A validated AT Protocol record key.
///
/// Rules:
/// - 1–512 characters
/// - Allowed characters: alphanumeric, `.`, `-`, `_`, `~`, `:`
/// - `"."` and `".."` are rejected (reserved path components)
/// - No `/` or whitespace
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RecordKey(String);

impl RecordKey {
    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RecordKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for RecordKey {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for RecordKey {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for RecordKey {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidRecordKey(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 512 {
            return Err(err("too long"));
        }
        if raw == "." || raw == ".." {
            return Err(err("disallowed value"));
        }
        for b in raw.bytes() {
            if !is_record_key_char(b) {
                return Err(err("invalid character"));
            }
        }

        Ok(RecordKey(raw.to_owned()))
    }
}

impl FromStr for RecordKey {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        RecordKey::try_from(s)
    }
}

impl Serialize for RecordKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for RecordKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        RecordKey::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Character helpers
// ---------------------------------------------------------------------------

#[inline]
fn is_record_key_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'~' || b == b'.' || b == b':' || b == b'-'
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
    fn recordkey_valid_tid() {
        RecordKey::try_from("3jui7kd2z3b2a").unwrap();
    }

    #[test]
    fn recordkey_valid_self() {
        RecordKey::try_from("self").unwrap();
    }

    #[test]
    fn recordkey_reject_dot() {
        assert!(RecordKey::try_from(".").is_err());
    }

    #[test]
    fn recordkey_reject_dotdot() {
        assert!(RecordKey::try_from("..").is_err());
    }

    #[test]
    fn recordkey_reject_slash() {
        assert!(RecordKey::try_from("a/b").is_err());
    }

    #[test]
    fn recordkey_reject_empty() {
        assert!(RecordKey::try_from("").is_err());
    }

    #[test]
    fn recordkey_serde_roundtrip() {
        let rk = RecordKey::try_from("abc123").unwrap();
        let json = serde_json::to_string(&rk).unwrap();
        let parsed: RecordKey = serde_json::from_str(&json).unwrap();
        assert_eq!(rk, parsed);
    }

    #[test]
    fn recordkey_valid_colon() {
        RecordKey::try_from("a:b").unwrap();
    }

    #[test]
    fn recordkey_valid_tilde() {
        RecordKey::try_from("a~b").unwrap();
    }

    #[test]
    fn recordkey_reject_too_long() {
        let s = "a".repeat(513);
        assert!(RecordKey::try_from(s.as_str()).is_err());
    }
}
