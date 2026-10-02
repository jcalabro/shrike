use crate::cbor::CborError;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use std::collections::hash_map::RandomState;
use std::fmt;
use std::hash::{BuildHasher, Hash, Hasher};
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct Cid {
    codec: Codec,
    hash: [u8; 32],
}

impl Hash for Cid {
    fn hash<H: Hasher>(&self, state: &mut H) {
        // The digest is uniformly distributed, so eight bytes of it tell CIDs
        // apart as well as all 32 do, at a quarter of the hashing. The codec
        // separates the raw and DRISL CIDs of the same bytes.
        let mut prefix = [0; 8];
        prefix.copy_from_slice(&self.hash[..8]);
        state.write_u64(u64::from_le_bytes(prefix) ^ self.codec as u64);
    }
}

/// A [`BuildHasher`] for maps and sets keyed by [`Cid`]: one keyed multiply
/// per lookup instead of SipHash.
///
/// The key is random per instance, so blocks an attacker chooses cannot be
/// aimed at one bucket.
#[derive(Clone)]
pub(crate) struct CidHashState {
    seed: u64,
    multiplier: u64,
}

impl Default for CidHashState {
    fn default() -> Self {
        let random = RandomState::new();
        CidHashState {
            seed: random.hash_one(0u64),
            multiplier: random.hash_one(1u64) | 1,
        }
    }
}

impl BuildHasher for CidHashState {
    type Hasher = CidHasher;

    fn build_hasher(&self) -> CidHasher {
        CidHasher {
            state: self.seed,
            multiplier: self.multiplier,
        }
    }
}

pub(crate) struct CidHasher {
    state: u64,
    multiplier: u64,
}

impl Hasher for CidHasher {
    #[inline]
    fn write_u64(&mut self, n: u64) {
        // A folded 64x64->128 multiply spreads every input bit over the
        // whole output, so the low (bucket) bits depend on the key too.
        let product = u128::from(self.state ^ n) * u128::from(self.multiplier);
        self.state = (product as u64) ^ ((product >> 64) as u64);
    }

    fn write(&mut self, bytes: &[u8]) {
        for chunk in bytes.chunks(8) {
            let mut word = [0; 8];
            word[..chunk.len()].copy_from_slice(chunk);
            self.write_u64(u64::from_le_bytes(word));
        }
    }

    #[inline]
    fn finish(&self) -> u64 {
        self.state
    }
}

/// A `HashMap` keyed by [`Cid`] with [`CidHashState`].
pub(crate) type CidMap<V> = std::collections::HashMap<Cid, V, CidHashState>;

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
// The canonical AT Protocol/multibase form is `b` + base32 LOWERCASE. We reject
// any uppercase letters so there is exactly one canonical string per CID
// (round-trip identity: from_str(s).to_string() == s). Internally we uppercase
// into a stack buffer because data-encoding's BASE32_NOPAD expects uppercase.
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
        // Reject any non-lowercase body: only base32-lower is canonical, and
        // accepting uppercase would let two distinct strings parse to one CID.
        if rest.bytes().any(|b| b.is_ascii_uppercase()) {
            return Err(CborError::InvalidCid("CID base32 must be lowercase".into()));
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

    #[test]
    fn hash_separates_codecs_and_digests() {
        let state = CidHashState::default();
        let raw = Cid::compute(Codec::Raw, b"same");
        let drisl = Cid::compute(Codec::Drisl, b"same");
        assert_eq!(raw.hash(), drisl.hash());
        assert_ne!(state.hash_one(raw), state.hash_one(drisl));
        assert_eq!(state.hash_one(raw), state.hash_one(raw));

        // Two instances key the hash differently.
        let other = CidHashState::default();
        let differ = (0..32u8)
            .map(|i| Cid::compute(Codec::Drisl, &[i]))
            .filter(|c| state.hash_one(c) != other.hash_one(c))
            .count();
        assert!(differ > 30);
    }

    #[test]
    fn cid_map_holds_many_cids() {
        let mut map = CidMap::default();
        for i in 0..10_000u32 {
            map.insert(Cid::compute(Codec::Drisl, &i.to_be_bytes()), i);
        }
        assert_eq!(map.len(), 10_000);
        for i in 0..10_000u32 {
            assert_eq!(map[&Cid::compute(Codec::Drisl, &i.to_be_bytes())], i);
        }
        assert!(!map.contains_key(&Cid::compute(Codec::Raw, &0u32.to_be_bytes())));
    }

    #[test]
    fn cid_reject_uppercase_base32() {
        // Only base32-lowercase is canonical; an uppercased body must be
        // rejected so there is exactly one string per CID. (L2)
        let cid = Cid::compute(Codec::Drisl, b"uppercase test");
        let lower = cid.to_string();
        let upper = format!("b{}", lower[1..].to_ascii_uppercase());
        assert_ne!(lower, upper);
        assert!(
            upper.parse::<Cid>().is_err(),
            "uppercase base32 CID must be rejected"
        );
        // And the canonical form round-trips to itself.
        assert_eq!(lower.parse::<Cid>().unwrap().to_string(), lower);
    }
}
