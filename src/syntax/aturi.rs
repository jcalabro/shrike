use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::syntax::{AtIdentifier, Nsid, RecordKey, SyntaxError};

/// A validated AT Protocol URI (e.g. `"at://did:plc:abc123/app.bsky.feed.post/tid"`).
///
/// Guaranteed to be valid on construction. Use `TryFrom<&str>` or `.parse()`.
///
/// Format: `at://<authority>[/<collection>[/<rkey>]]`
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AtUri(String);

impl AtUri {
    /// Returns the authority portion (DID or handle).
    ///
    /// For `"at://did:plc:abc123/app.bsky.feed.post/tid"` returns `"did:plc:abc123"`.
    pub fn authority(&self) -> &str {
        // Safety: validated on construction — always has "at://<authority>" form.
        let rest = &self.0[5..]; // skip "at://"
        match rest.find('/') {
            Some(idx) => &rest[..idx],
            None => rest,
        }
    }

    /// Returns the collection NSID path segment, or `None` if not present.
    pub fn collection(&self) -> Option<&str> {
        let rest = &self.0[5..]; // skip "at://"
        let after_auth = match rest.find('/') {
            Some(idx) => &rest[idx + 1..],
            None => return None,
        };
        if after_auth.is_empty() {
            return None;
        }
        match after_auth.find('/') {
            Some(idx) => Some(&after_auth[..idx]),
            None => Some(after_auth),
        }
    }

    /// Returns the record key path segment, or `None` if not present.
    pub fn rkey(&self) -> Option<&str> {
        let rest = &self.0[5..]; // skip "at://"
        let after_auth = match rest.find('/') {
            Some(idx) => &rest[idx + 1..],
            None => return None,
        };
        let after_coll = match after_auth.find('/') {
            Some(idx) => &after_auth[idx + 1..],
            None => return None,
        };
        if after_coll.is_empty() {
            None
        } else {
            Some(after_coll)
        }
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AtUri {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for AtUri {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for AtUri {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AtUri {
    pub(crate) fn validate(raw: &str) -> Result<(), SyntaxError> {
        let err = |msg: &str| SyntaxError::InvalidAtUri(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 8192 {
            return Err(err("too long"));
        }
        if !raw.starts_with("at://") {
            return Err(err("must start with \"at://\""));
        }

        // The authority, NSID and record-key validators below each reject
        // '?' and '#'; no separate pass over the complete URI is needed.
        let rest = &raw[5..];
        if rest.is_empty() {
            return Err(err("empty authority"));
        }

        // Split authority from the path on the first '/'.
        let (authority, has_path) = match rest.find('/') {
            Some(idx) => (&rest[..idx], true),
            None => (rest, false),
        };

        if authority.is_empty() {
            return Err(err("empty authority"));
        }

        // The authority MUST be a valid AT identifier (DID or handle). Delegate
        // to the canonical parser rather than a loose character class, so the
        // AT-URI grammar can't drift from the identifier grammar.
        AtIdentifier::validate(authority).map_err(|e| err(&format!("invalid authority: {e}")))?;

        // No path — authority only is valid.
        if !has_path {
            return Ok(());
        }

        let after_auth = &rest[authority.len() + 1..]; // skip the '/'
        if after_auth.is_empty() {
            return Err(err("trailing slash without collection"));
        }

        // Split collection from rkey on the second '/'.
        let (collection, has_rkey) = match after_auth.find('/') {
            Some(idx) => (&after_auth[..idx], true),
            None => (after_auth, false),
        };

        if collection.is_empty() {
            return Err(err("empty collection segment"));
        }

        // The collection MUST be a valid NSID. Delegate to the canonical parser.
        Nsid::validate(collection).map_err(|e| err(&format!("invalid collection: {e}")))?;

        if !has_rkey {
            return Ok(());
        }

        let rkey = &after_auth[collection.len() + 1..]; // skip the '/'
        if rkey.is_empty() {
            return Err(err("trailing slash without record key"));
        }

        // The record key MUST satisfy the record-key grammar (which also
        // rejects the reserved "." and ".." values and the over-broad
        // URI-sub-delims charset). Delegate to the canonical parser.
        RecordKey::validate(rkey).map_err(|e| err(&format!("invalid record key: {e}")))?;

        Ok(())
    }
}

impl TryFrom<&str> for AtUri {
    type Error = SyntaxError;
    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        Self::validate(raw)?;
        Ok(Self(raw.to_owned()))
    }
}

/// A validated AtUri borrowing its original text.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AtUriRef<'a>(&'a str);

impl<'a> AtUriRef<'a> {
    pub fn as_str(&self) -> &'a str {
        self.0
    }
    pub fn to_owned(self) -> AtUri {
        AtUri(self.0.to_owned())
    }
}

impl<'a> TryFrom<&'a str> for AtUriRef<'a> {
    type Error = SyntaxError;
    fn try_from(raw: &'a str) -> Result<Self, Self::Error> {
        AtUri::validate(raw)?;
        Ok(Self(raw))
    }
}

impl FromStr for AtUri {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AtUri::try_from(s)
    }
}

impl Serialize for AtUri {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AtUri {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AtUri::try_from(s.as_str()).map_err(serde::de::Error::custom)
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

    /// Load test vectors, keeping each raw line (untrimmed) so that vectors
    /// whose (in)validity depends on leading/trailing whitespace are preserved.
    /// Comment (`#`) and blank lines are filtered on the trimmed form.
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
    fn component_validation_rejects_queries_fragments_and_extra_segments() {
        for valid in [
            "at://alice.test",
            "at://did:plc:abc/app.bsky.feed.post",
            "at://alice.test/app.bsky.feed.post/3l3qo2vuowo2b",
        ] {
            assert!(AtUri::try_from(valid).is_ok());
            for index in 5..=valid.len() {
                for marker in ['?', '#'] {
                    let mut changed = valid.to_owned();
                    changed.insert(index, marker);
                    assert!(AtUri::try_from(changed.as_str()).is_err(), "{changed}");
                }
            }
        }
        for bad in [
            "at://alice.test/app.bsky.feed.post/a/b",
            "at://alice.test/app.bsky.feed.post/a/",
            "at://alice.test/app.bsky.feed.post//b",
        ] {
            assert!(AtUri::try_from(bad).is_err());
        }
    }

    #[test]
    fn aturi_interop_valid() {
        let vectors = load_vectors("testdata/aturi_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no vectors loaded");
        for v in &vectors {
            AtUri::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid AT-URI: {v:?}, got error: {e}"));
        }
    }

    #[test]
    fn aturi_interop_invalid() {
        let vectors = load_vectors("testdata/aturi_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no vectors loaded");
        for v in &vectors {
            assert!(
                AtUri::try_from(v.as_str()).is_err(),
                "should be invalid AT-URI: {v:?}"
            );
        }
    }

    #[test]
    fn aturi_full_path() {
        let u = AtUri::try_from(
            "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jui7kd2z3b2a",
        )
        .unwrap();
        assert_eq!(u.authority(), "did:plc:z72i7hdynmk6r22z27h6tvur");
        assert_eq!(u.collection(), Some("app.bsky.feed.post"));
        assert_eq!(u.rkey(), Some("3jui7kd2z3b2a"));
    }

    #[test]
    fn aturi_authority_only() {
        let u = AtUri::try_from("at://did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(u.collection(), None);
        assert_eq!(u.rkey(), None);
    }

    #[test]
    fn aturi_with_handle() {
        let u = AtUri::try_from("at://alice.bsky.social/app.bsky.feed.post/abc").unwrap();
        assert_eq!(u.authority(), "alice.bsky.social");
    }

    #[test]
    fn aturi_collection_only() {
        let u =
            AtUri::try_from("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post").unwrap();
        assert_eq!(u.collection(), Some("app.bsky.feed.post"));
        assert_eq!(u.rkey(), None);
    }

    #[test]
    fn aturi_reject_trailing_slash() {
        assert!(AtUri::try_from("at://did:plc:abc/").is_err());
    }

    #[test]
    fn aturi_reject_fragment() {
        assert!(AtUri::try_from("at://did:plc:abc#frag").is_err());
    }

    #[test]
    fn aturi_reject_query() {
        assert!(AtUri::try_from("at://did:plc:abc?q=1").is_err());
    }

    #[test]
    fn aturi_reject_wrong_scheme() {
        assert!(AtUri::try_from("http://example.com").is_err());
    }

    #[test]
    fn aturi_reject_percent_encoding_in_authority() {
        // Percent-encoding is never valid in AT URI authorities.
        assert!(AtUri::try_from("at://did:web:localhost%3A1234/app.bsky.feed.post/abc").is_err());
        assert!(AtUri::try_from("at://did:method:val%BB").is_err());
        assert!(AtUri::try_from("at://did%3Aplc%3Amy_did").is_err());
        assert!(AtUri::try_from("at://did%3Aplc%3Amy_did/com.atproto.feed.post/record").is_err());
        assert!(AtUri::try_from("at://user%2Ebsky%2Esocial").is_err());
    }

    #[test]
    fn aturi_serde_roundtrip() {
        let u = AtUri::try_from("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/abc")
            .unwrap();
        let json = serde_json::to_string(&u).unwrap();
        let parsed: AtUri = serde_json::from_str(&json).unwrap();
        assert_eq!(u, parsed);
    }
}
