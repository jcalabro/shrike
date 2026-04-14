use crate::cbor::CborError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::fmt;
use std::str::FromStr;

/// Multicodec identifier for CID content encoding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Codec {
    /// DRISL (deterministic CBOR / DAG-CBOR) — used for structured AT Protocol data.
    Drisl = 0x71,
    /// Raw bytes — used for unstructured binary data (blobs, images).
    Raw = 0x55,
}

/// Stack-allocated CIDv1 (SHA-256 only). No heap allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Cid {
    codec: Codec,
    hash: [u8; 32],
}

impl Cid {
    /// Create a CID with all-zero hash. Not valid for content addressing —
    /// intended as a cheap placeholder that will be overwritten.
    #[inline]
    pub fn zeroed() -> Self {
        Cid {
            codec: Codec::Raw,
            hash: [0u8; 32],
        }
    }

    /// Compute a CID by SHA-256 hashing the given data.
    pub fn compute(codec: Codec, data: &[u8]) -> Self {
        let hash: [u8; 32] = Sha256::digest(data).into();
        Cid { codec, hash }
    }

    /// Return the multicodec identifier (Drisl or Raw).
    pub fn codec(&self) -> Codec {
        self.codec
    }

    /// Return the raw 32-byte SHA-256 hash.
    pub fn hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// Encode to binary CID bytes (version + codec + hash_type + hash_size + hash).
    #[allow(clippy::wrong_self_convention)]
    pub fn to_bytes(&self) -> [u8; 36] {
        let mut buf = [0u8; 36];
        buf[0] = 0x01; // version
        buf[1] = self.codec as u8;
        buf[2] = 0x12; // SHA-256
        buf[3] = 0x20; // 32 bytes
        buf[4..].copy_from_slice(&self.hash);
        buf
    }

    /// Decode from binary CID bytes.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CborError> {
        if bytes.len() != 36 {
            return Err(CborError::InvalidCid("wrong length".into()));
        }
        if bytes[0] != 0x01 {
            return Err(CborError::InvalidCid("unsupported CID version".into()));
        }
        let codec = match bytes[1] {
            0x71 => Codec::Drisl,
            0x55 => Codec::Raw,
            _ => return Err(CborError::InvalidCid("unsupported codec".into())),
        };
        if bytes[2] != 0x12 || bytes[3] != 0x20 {
            return Err(CborError::InvalidCid("unsupported hash".into()));
        }
        let mut hash = [0u8; 32];
        hash.copy_from_slice(&bytes[4..]);
        Ok(Cid { codec, hash })
    }

    /// For CBOR tag 42: 0x00 prefix + binary CID
    #[allow(clippy::wrong_self_convention)]
    pub fn to_tag42_bytes(&self) -> [u8; 37] {
        let mut buf = [0u8; 37];
        buf[0] = 0x00;
        buf[1..].copy_from_slice(&self.to_bytes());
        buf
    }

    /// Decode from tag 42 bytes (strip 0x00 prefix)
    pub fn from_tag42_bytes(bytes: &[u8]) -> Result<Self, CborError> {
        if bytes.is_empty() || bytes[0] != 0x00 {
            return Err(CborError::InvalidCid("missing tag 42 prefix".into()));
        }
        Self::from_bytes(&bytes[1..])
    }
}

/// Base32 of 36 CID bytes = ceil(36 * 8 / 5) = 58 characters.
const CID_BASE32_LEN: usize = 58;

// Display: 'b' prefix + base32lower (RFC 4648 lowercase)
//
// Uses encode_mut into a stack buffer + in-place lowercasing to avoid
// the two heap allocations that encode() + to_lowercase() would require.
impl fmt::Display for Cid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let raw = self.to_bytes();
        let mut buf = [0u8; CID_BASE32_LEN];
        data_encoding::BASE32_NOPAD.encode_mut(&raw, &mut buf);
        // Convert A-Z to a-z in-place; digits 2-7 are unchanged
        for b in &mut buf {
            *b = b.to_ascii_lowercase();
        }
        f.write_str("b")?;
        // Base32 output is always valid ASCII
        match std::str::from_utf8(&buf) {
            Ok(s) => f.write_str(s),
            Err(_) => Err(fmt::Error),
        }
    }
}

// FromStr: strip 'b' prefix, base32lower decode, then from_bytes
//
// Uppercases into a stack buffer and decodes into another stack buffer
// to avoid all heap allocations on the happy path.
impl FromStr for Cid {
    type Err = CborError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let rest = s
            .strip_prefix('b')
            .ok_or_else(|| CborError::InvalidCid("missing 'b' prefix".into()))?;
        // CID is exactly 36 bytes, base32(36 bytes) = 58 chars
        if rest.len() != CID_BASE32_LEN {
            return Err(CborError::InvalidCid("wrong base32 length".into()));
        }
        // Uppercase into stack buffer (BASE32_NOPAD expects uppercase)
        let mut upper = [0u8; CID_BASE32_LEN];
        for (i, &b) in rest.as_bytes().iter().enumerate() {
            upper[i] = b.to_ascii_uppercase();
        }
        // Decode into stack buffer
        let mut cid_bytes = [0u8; 36];
        if data_encoding::BASE32_NOPAD
            .decode_mut(&upper, &mut cid_bytes)
            .is_err()
        {
            return Err(CborError::InvalidCid("invalid base32 encoding".into()));
        }
        Self::from_bytes(&cid_bytes)
    }
}

impl Serialize for Cid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Cid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Cid::from_str(&s).map_err(serde::de::Error::custom)
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

    #[test]
    fn compute_cid_drisl() {
        let cid = Cid::compute(Codec::Drisl, b"hello world");
        assert_eq!(cid.codec(), Codec::Drisl);
        assert_eq!(cid.hash().len(), 32);
    }

    #[test]
    fn cid_string_roundtrip() {
        let cid = Cid::compute(Codec::Drisl, b"test data");
        let s = cid.to_string();
        assert!(s.starts_with('b'));
        let parsed: Cid = s.parse().unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_bytes_roundtrip() {
        let cid = Cid::compute(Codec::Raw, b"raw data");
        let bytes = cid.to_bytes();
        assert_eq!(bytes.len(), 36);
        let parsed = Cid::from_bytes(&bytes).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_tag42_roundtrip() {
        let cid = Cid::compute(Codec::Drisl, b"tag 42 test");
        let tag_bytes = cid.to_tag42_bytes();
        assert_eq!(tag_bytes[0], 0x00);
        assert_eq!(tag_bytes.len(), 37);
        let parsed = Cid::from_tag42_bytes(&tag_bytes).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_different_data_different_cid() {
        let a = Cid::compute(Codec::Drisl, b"hello");
        let b = Cid::compute(Codec::Drisl, b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn cid_different_codec_different_cid() {
        let a = Cid::compute(Codec::Drisl, b"same");
        let b = Cid::compute(Codec::Raw, b"same");
        assert_ne!(a, b);
    }

    #[test]
    fn cid_reject_invalid_prefix() {
        assert!("zNotBase32".parse::<Cid>().is_err());
    }

    #[test]
    fn cid_reject_wrong_version() {
        let mut bytes = Cid::compute(Codec::Drisl, b"test").to_bytes();
        bytes[0] = 0x02;
        assert!(Cid::from_bytes(&bytes).is_err());
    }

    #[test]
    fn cid_reject_wrong_hash_type() {
        let mut bytes = Cid::compute(Codec::Drisl, b"test").to_bytes();
        bytes[2] = 0x13; // not SHA-256
        assert!(Cid::from_bytes(&bytes).is_err());
    }
}
