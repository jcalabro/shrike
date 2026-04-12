use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{Did, Handle, SyntaxError};

/// An AT Protocol identifier that is either a [`Did`] or a [`Handle`].
///
/// `TryFrom<&str>` / `.parse()` tries DID first (if the string starts with
/// `"did:"`), then Handle.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum AtIdentifier {
    Did(Did),
    Handle(Handle),
}

impl AtIdentifier {
    /// Returns `true` if this identifier is a DID.
    pub fn is_did(&self) -> bool {
        matches!(self, AtIdentifier::Did(_))
    }

    /// Returns `true` if this identifier is a Handle.
    pub fn is_handle(&self) -> bool {
        matches!(self, AtIdentifier::Handle(_))
    }

    /// Returns a reference to the inner [`Did`], or `None` if this is a Handle.
    pub fn as_did(&self) -> Option<&Did> {
        match self {
            AtIdentifier::Did(d) => Some(d),
            AtIdentifier::Handle(_) => None,
        }
    }

    /// Returns a reference to the inner [`Handle`], or `None` if this is a DID.
    pub fn as_handle(&self) -> Option<&Handle> {
        match self {
            AtIdentifier::Did(_) => None,
            AtIdentifier::Handle(h) => Some(h),
        }
    }
}

impl Default for AtIdentifier {
    fn default() -> Self {
        AtIdentifier::Did(Did::default())
    }
}

impl fmt::Display for AtIdentifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtIdentifier::Did(d) => d.fmt(f),
            AtIdentifier::Handle(h) => h.fmt(f),
        }
    }
}

impl TryFrom<&str> for AtIdentifier {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        if raw.starts_with("did:") {
            return Did::try_from(raw).map(AtIdentifier::Did);
        }
        Handle::try_from(raw).map(AtIdentifier::Handle)
    }
}

impl FromStr for AtIdentifier {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        AtIdentifier::try_from(s)
    }
}

impl From<Did> for AtIdentifier {
    fn from(d: Did) -> Self {
        AtIdentifier::Did(d)
    }
}

impl From<Handle> for AtIdentifier {
    fn from(h: Handle) -> Self {
        AtIdentifier::Handle(h)
    }
}

impl Serialize for AtIdentifier {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for AtIdentifier {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        AtIdentifier::try_from(s.as_str()).map_err(serde::de::Error::custom)
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
    fn at_identifier_did() {
        let id: AtIdentifier = "did:plc:z72i7hdynmk6r22z27h6tvur".parse().unwrap();
        assert!(id.is_did());
        assert!(!id.is_handle());
    }

    #[test]
    fn at_identifier_handle() {
        let id: AtIdentifier = "alice.bsky.social".parse().unwrap();
        assert!(id.is_handle());
        assert!(!id.is_did());
    }

    #[test]
    fn at_identifier_serde_roundtrip_did() {
        let id: AtIdentifier = "did:plc:z72i7hdynmk6r22z27h6tvur".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: AtIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn at_identifier_serde_roundtrip_handle() {
        let id: AtIdentifier = "alice.bsky.social".parse().unwrap();
        let json = serde_json::to_string(&id).unwrap();
        let parsed: AtIdentifier = serde_json::from_str(&json).unwrap();
        assert_eq!(id, parsed);
    }

    #[test]
    fn at_identifier_as_did() {
        let id: AtIdentifier = "did:plc:z72i7hdynmk6r22z27h6tvur".parse().unwrap();
        assert!(id.as_did().is_some());
        assert!(id.as_handle().is_none());
    }

    #[test]
    fn at_identifier_as_handle() {
        let id: AtIdentifier = "alice.bsky.social".parse().unwrap();
        assert!(id.as_handle().is_some());
        assert!(id.as_did().is_none());
    }

    #[test]
    fn at_identifier_display_did() {
        let id: AtIdentifier = "did:plc:z72i7hdynmk6r22z27h6tvur".parse().unwrap();
        assert_eq!(id.to_string(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn at_identifier_display_handle() {
        let id: AtIdentifier = "alice.bsky.social".parse().unwrap();
        assert_eq!(id.to_string(), "alice.bsky.social");
    }

    #[test]
    fn at_identifier_reject_invalid() {
        assert!(AtIdentifier::try_from("").is_err());
        assert!(AtIdentifier::try_from("not-a-handle").is_err());
        assert!(AtIdentifier::try_from("did:").is_err());
    }

    #[test]
    fn at_identifier_from_did() {
        let did = Did::try_from("did:plc:abc123").unwrap();
        let id = AtIdentifier::from(did.clone());
        assert_eq!(id.as_did(), Some(&did));
    }

    #[test]
    fn at_identifier_from_handle() {
        let handle = Handle::try_from("alice.bsky.social").unwrap();
        let id = AtIdentifier::from(handle.clone());
        assert_eq!(id.as_handle(), Some(&handle));
    }
}
