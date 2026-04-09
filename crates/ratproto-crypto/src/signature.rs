/// 64-byte compact ECDSA signature [R || S], always low-S normalized.
///
/// Signatures should be validated using [`VerifyingKey::verify`], not by
/// comparing bytes. Byte-level comparison is deliberately not provided
/// to prevent timing side-channel attacks.
#[derive(Clone, Copy)]
pub struct Signature(pub(crate) [u8; 64]);

impl Signature {
    #[inline]
    pub fn from_bytes(bytes: [u8; 64]) -> Self {
        Signature(bytes)
    }

    #[inline]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }
}

impl std::fmt::Debug for Signature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Signature").field(&"[64 bytes]").finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn from_bytes_as_bytes_roundtrip() {
        let bytes = [0xAB; 64];
        let sig = Signature::from_bytes(bytes);
        assert_eq!(sig.as_bytes(), &bytes);
    }

    #[test]
    fn clone_preserves_bytes() {
        let sig = Signature::from_bytes([0x42; 64]);
        let cloned = sig;
        assert_eq!(sig.as_bytes(), cloned.as_bytes());
    }

    #[test]
    fn debug_redacts_content() {
        let sig = Signature::from_bytes([0xFF; 64]);
        let debug = format!("{sig:?}");
        assert!(!debug.contains("255"), "Debug must not show byte values");
        assert!(!debug.contains("0xff"), "Debug must not show hex values");
        assert!(debug.contains("64 bytes"), "Debug must show size");
    }
}
