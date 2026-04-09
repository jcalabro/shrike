use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// A validated AT Protocol NSID (Namespaced Identifier, e.g. `"app.bsky.feed.post"`).
///
/// Guaranteed to be valid on construction. Authority segments are lowercased;
/// the name segment (last component) preserves its original case.
/// Use `TryFrom<&str>` or `.parse()`.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Nsid(String);

impl Nsid {
    /// Returns the authority in normal DNS order (reversed domain portion), lowercased.
    ///
    /// For `"app.bsky.feed.post"` returns `"bsky.app"`.
    pub fn authority(&self) -> String {
        let s = &self.0;
        // Validated on construction — always has at least 3 dot-separated segments.
        let last_dot = s.rfind('.').unwrap_or(0);
        // Domain portion is everything before the last dot.
        let domain = &s[..last_dot];
        // Reverse the dot-separated segments.
        let segments: Vec<&str> = domain.split('.').collect();
        segments.into_iter().rev().collect::<Vec<_>>().join(".")
    }

    /// Returns the name segment (the final dot-separated component).
    ///
    /// For `"app.bsky.feed.post"` returns `"post"`.
    pub fn name(&self) -> &str {
        let s = &self.0;
        // Validated on construction — always has at least 3 dot-separated segments.
        let last_dot = s.rfind('.').unwrap_or(0);
        &s[last_dot + 1..]
    }

    /// Returns the inner string slice (authority lowercased, name case-preserved).
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Nsid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Nsid {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Nsid {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Nsid {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidNsid(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 317 {
            return Err(err("too long"));
        }

        // Single-pass validation: walk segments separated by '.'.
        // All segments except the last are domain labels.
        // The last segment is the name.
        let bytes = raw.as_bytes();
        let mut seg_count = 0usize;
        let mut start = 0usize;
        let mut last_dot: Option<usize> = None;

        let mut i = 0usize;
        loop {
            let at_end = i == bytes.len();
            if at_end || bytes[i] == b'.' {
                let seg = &raw[start..i];
                seg_count += 1;

                if !at_end {
                    // This is a domain label (authority segment), not the name.
                    validate_domain_label(seg, raw)?;

                    // First segment (TLD in reversed NSID) must start with a letter.
                    if seg_count == 1 && (seg.is_empty() || !is_alpha(seg.as_bytes()[0])) {
                        return Err(err("first segment must start with a letter"));
                    }

                    last_dot = Some(i);
                }

                start = i + 1;
            }

            if at_end {
                break;
            }
            i += 1;
        }

        if seg_count < 3 {
            return Err(err("must have at least 3 segments"));
        }

        // Validate name segment (last): must start with letter, alphanumeric only.
        let name_start = last_dot.map(|d| d + 1).unwrap_or(0);
        let name = &raw[name_start..];
        if name.is_empty() || name.len() > 63 {
            return Err(err("name segment must be 1-63 characters"));
        }
        if !is_alpha(name.as_bytes()[0]) {
            return Err(err("name segment must start with a letter"));
        }
        for &b in &name.as_bytes()[1..] {
            if !is_alphanumeric(b) {
                return Err(err("name segment must be alphanumeric only"));
            }
        }

        // Normalize authority (everything before the last dot) to lowercase,
        // but preserve the name segment's original case.
        let last_dot = raw.rfind('.').unwrap_or(0);
        let mut normalized = raw[..last_dot].to_ascii_lowercase();
        normalized.push_str(&raw[last_dot..]);
        Ok(Nsid(normalized))
    }
}

impl FromStr for Nsid {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Nsid::try_from(s)
    }
}

impl Serialize for Nsid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Nsid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Nsid::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

/// Validates a single domain label (authority segment, not the name segment).
fn validate_domain_label(label: &str, raw: &str) -> Result<(), SyntaxError> {
    let err = |msg: &str| SyntaxError::InvalidNsid(format!("{raw:?}: {msg}"));

    if label.is_empty() {
        return Err(err("empty label"));
    }
    if label.len() > 63 {
        return Err(err("label too long"));
    }

    let lb = label.as_bytes();

    if !is_alphanumeric(lb[0]) {
        return Err(err("label must start with alphanumeric"));
    }
    if !is_alphanumeric(lb[lb.len() - 1]) {
        return Err(err("label must end with alphanumeric"));
    }
    // Interior characters (only exist when label has 3+ chars).
    if lb.len() >= 3 {
        for &b in &lb[1..lb.len() - 1] {
            if !is_alphanumeric_or_hyphen(b) {
                return Err(err("invalid character in label"));
            }
        }
    }

    Ok(())
}

#[inline]
fn is_alpha(b: u8) -> bool {
    b.is_ascii_alphabetic()
}

#[inline]
fn is_alphanumeric(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

#[inline]
fn is_alphanumeric_or_hyphen(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'-'
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
    fn parse_valid_nsids() {
        let vectors = load_vectors("testdata/nsid_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            Nsid::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid NSID: {v:?}, got error: {e}"));
        }
    }

    #[test]
    fn parse_invalid_nsids() {
        let vectors = load_vectors("testdata/nsid_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            assert!(
                Nsid::try_from(v.as_str()).is_err(),
                "should be invalid NSID: {v:?}"
            );
        }
    }

    #[test]
    fn nsid_authority() {
        // "app.bsky.feed.post": domain = "app.bsky.feed", reversed = "feed.bsky.app"
        let nsid = Nsid::try_from("app.bsky.feed.post").unwrap();
        assert_eq!(nsid.authority(), "feed.bsky.app");
        assert_eq!(nsid.name(), "post");

        // "com.example.fooBar": domain = "com.example", reversed = "example.com"
        let nsid2 = Nsid::try_from("com.example.fooBar").unwrap();
        assert_eq!(nsid2.authority(), "example.com");
        assert_eq!(nsid2.name(), "fooBar"); // name segment preserves case
    }

    #[test]
    fn nsid_serde_roundtrip() {
        let nsid = Nsid::try_from("app.bsky.feed.post").unwrap();
        let json = serde_json::to_string(&nsid).unwrap();
        let parsed: Nsid = serde_json::from_str(&json).unwrap();
        assert_eq!(nsid, parsed);
    }

    #[test]
    fn nsid_reject_two_segments() {
        assert!(Nsid::try_from("example.com").is_err());
    }

    #[test]
    fn nsid_normalize_lowercase() {
        // Authority segments are lowercased, but the name segment preserves case.
        let nsid = Nsid::try_from("COM.Example.fooBar").unwrap();
        assert_eq!(nsid.as_str(), "com.example.fooBar");
    }

    #[test]
    fn nsid_display_roundtrip() {
        let input = "app.bsky.feed.post";
        let nsid = Nsid::try_from(input).unwrap();
        assert_eq!(nsid.to_string(), input);
    }
}
