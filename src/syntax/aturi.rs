use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::syntax::SyntaxError;

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

impl TryFrom<&str> for AtUri {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
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

        // Reject query params and fragments.
        for b in raw[5..].bytes() {
            if b == b'?' || b == b'#' {
                return Err(err("query and fragment not allowed"));
            }
        }

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

        // Validate authority characters (must be a valid DID or handle).
        // We do a lightweight character-level check here (non-empty, no control chars,
        // no whitespace) without fully re-parsing the DID/handle.
        for b in authority.bytes() {
            if !is_authority_char(b) {
                return Err(err("invalid character in authority"));
            }
        }

        // No path — authority only is valid.
        if !has_path {
            return Ok(AtUri(raw.to_owned()));
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

        // Validate collection as an NSID (dot-separated segments, at least 3).
        validate_collection(collection, raw)?;

        if !has_rkey {
            return Ok(AtUri(raw.to_owned()));
        }

        let rkey = &after_auth[collection.len() + 1..]; // skip the '/'
        if rkey.is_empty() {
            return Err(err("trailing slash without record key"));
        }

        // Reject any additional path segments.
        if rkey.contains('/') {
            return Err(err("too many path segments"));
        }

        // Validate rkey characters.
        validate_rkey(rkey, raw)?;

        Ok(AtUri(raw.to_owned()))
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

/// Validates a collection NSID segment: at least 3 dot-separated segments,
/// each non-empty, first segment starts with a letter, all chars alphanumeric or hyphen.
fn validate_collection(collection: &str, raw: &str) -> Result<(), SyntaxError> {
    let err = |msg: &str| SyntaxError::InvalidAtUri(format!("{raw:?}: invalid collection: {msg}"));

    let segments: Vec<&str> = collection.split('.').collect();
    if segments.len() < 3 {
        return Err(err("must have at least 3 dot-separated segments"));
    }

    for (i, seg) in segments.iter().enumerate() {
        if seg.is_empty() {
            return Err(err("empty segment"));
        }
        let bytes = seg.as_bytes();
        // First segment must start with a letter.
        if i == 0 && !bytes[0].is_ascii_alphabetic() {
            return Err(err("first segment must start with a letter"));
        }
        for &b in bytes {
            if !b.is_ascii_alphanumeric() && b != b'-' {
                return Err(err("invalid character in segment"));
            }
        }
    }

    Ok(())
}

/// Validates record key characters: printable ASCII excluding space and certain reserved chars.
fn validate_rkey(rkey: &str, raw: &str) -> Result<(), SyntaxError> {
    let err = |msg: &str| SyntaxError::InvalidAtUri(format!("{raw:?}: invalid record key: {msg}"));

    if rkey.is_empty() {
        return Err(err("empty"));
    }
    if rkey.len() > 512 {
        return Err(err("too long"));
    }

    for b in rkey.bytes() {
        if !is_rkey_char(b) {
            return Err(err("invalid character"));
        }
    }

    Ok(())
}

/// Characters valid in the authority portion: alphanumeric, '.', '-', '_', ':'.
#[inline]
fn is_authority_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'.' || b == b'-' || b == b'_' || b == b':'
}

/// Characters valid in a record key: printable ASCII excluding '/' and certain specials.
/// Follows the AT Protocol record key spec: [a-zA-Z0-9._~:@!$&'()*+,;=-]
#[inline]
fn is_rkey_char(b: u8) -> bool {
    b.is_ascii_alphanumeric()
        || b == b'.'
        || b == b'_'
        || b == b'~'
        || b == b':'
        || b == b'@'
        || b == b'!'
        || b == b'$'
        || b == b'&'
        || b == b'\''
        || b == b'('
        || b == b')'
        || b == b'*'
        || b == b'+'
        || b == b','
        || b == b';'
        || b == b'='
        || b == b'-'
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
