use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// A validated AT Protocol DID (Decentralized Identifier).
///
/// Guaranteed to be valid on construction. Use `TryFrom<&str>` or `.parse()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did(String);

impl Did {
    /// Returns the DID method (e.g. "plc" from "did:plc:abc123").
    pub fn method(&self) -> &str {
        // Validated on construction — always has "did:<method>:<id>" form.
        let rest = &self.0[4..]; // skip "did:"
        let colon = rest.find(':').unwrap_or(rest.len());
        &rest[..colon]
    }

    /// Returns the method-specific identifier (e.g. "abc123" from "did:plc:abc123").
    pub fn identifier(&self) -> &str {
        let rest = &self.0[4..]; // skip "did:"
        let colon = rest.find(':').unwrap_or(rest.len());
        &rest[colon.saturating_add(1).min(rest.len())..]
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Did {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Did {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidDid(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 2048 {
            return Err(err("too long"));
        }

        // Must start with "did:".
        if !raw.starts_with("did:") {
            return Err(err("must start with \"did:\""));
        }

        // Validate method: one or more lowercase ASCII letters, terminated by ':'.
        let after_prefix = &raw[4..];
        let method_end = after_prefix
            .bytes()
            .position(|b| b == b':')
            .ok_or_else(|| err("missing identifier after method"))?;

        if method_end == 0 {
            return Err(err("empty method"));
        }

        for b in after_prefix[..method_end].bytes() {
            if !b.is_ascii_lowercase() {
                return Err(err("method must be lowercase alpha"));
            }
        }

        // after_prefix[method_end] == ':', so identifier starts at method_end + 1.
        let ident_start = 4 + method_end + 1; // absolute index into raw
        if ident_start >= raw.len() {
            return Err(err("empty identifier"));
        }

        let ident = &raw[ident_start..];

        // Validate identifier characters: [a-zA-Z0-9._:-]
        for b in ident.bytes() {
            if !is_did_ident_char(b) {
                return Err(err("invalid character in identifier"));
            }
        }

        // Last character cannot be ':'.
        let Some(&last) = ident.as_bytes().last() else {
            return Err(err("empty identifier"));
        };
        if last == b':' {
            return Err(err("identifier cannot end with ':'"));
        }

        Ok(Did(raw.to_owned()))
    }
}

impl FromStr for Did {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Did::try_from(s)
    }
}

impl Serialize for Did {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Did::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

#[inline]
fn is_did_ident_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b':' || b == b'-'
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
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_valid_dids() {
        let vectors = load_vectors("testdata/did_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            let did = Did::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid DID: {v:?}, got error: {e}"));
            assert_eq!(did.to_string(), *v);
        }
    }

    #[test]
    fn parse_invalid_dids() {
        let vectors = load_vectors("testdata/did_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            assert!(
                Did::try_from(v.as_str()).is_err(),
                "should be invalid DID: {v:?}"
            );
        }
    }

    #[test]
    fn did_method_and_identifier() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.method(), "plc");
        assert_eq!(did.identifier(), "z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn did_plc_fast_path() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.to_string().len(), 32);
    }

    #[test]
    fn did_display_roundtrip() {
        let input = "did:web:example.com";
        let did = Did::try_from(input).unwrap();
        assert_eq!(did.to_string(), input);
    }

    #[test]
    fn did_serde_roundtrip() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        let parsed: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn did_reject_empty() {
        assert!(Did::try_from("").is_err());
    }

    #[test]
    fn did_reject_no_method() {
        assert!(Did::try_from("did:").is_err());
    }

    #[test]
    fn did_reject_uppercase_method() {
        assert!(Did::try_from("did:PLC:abc123").is_err());
    }

    #[test]
    fn did_reject_percent_encoding() {
        // Percent-encoded characters are not allowed in DIDs.
        assert!(Did::try_from("did:method:val%BB").is_err());
        assert!(Did::try_from("did:method:val%3A1234").is_err());
        assert!(Did::try_from("did:web:localhost%3A1234").is_err());
        assert!(Did::try_from("did:method:-:_:.:%ab").is_err());
        assert!(Did::try_from("did:method:val%").is_err());
        assert!(Did::try_from("did:plc:%3Fblah").is_err());
    }
}
