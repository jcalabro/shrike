use crate::crypto::{
    CryptoError, VerifyingKey, k256_impl::K256VerifyingKey, p256_impl::P256VerifyingKey,
};

/// Parse a did:key string and return the appropriate VerifyingKey based on the multicodec prefix.
/// Supports P-256 (0x1200, varint [0x80, 0x24]) and K-256/secp256k1 (0xe7, varint [0xe7, 0x01]).
pub fn parse_did_key(s: &str) -> Result<Box<dyn VerifyingKey>, CryptoError> {
    let rest = s
        .strip_prefix("did:key:z")
        .ok_or_else(|| CryptoError::InvalidKey("not a did:key".into()))?;

    let bytes = bs58::decode(rest)
        .into_vec()
        .map_err(|e| CryptoError::InvalidKey(format!("base58 decode: {e}")))?;

    if bytes.len() < 2 {
        return Err(CryptoError::InvalidKey("too short".into()));
    }

    // P-256: multicodec prefix [0x80, 0x24]
    if bytes.starts_with(&[0x80, 0x24]) {
        let key_bytes = &bytes[2..];
        if key_bytes.len() != 33 {
            return Err(CryptoError::InvalidKey("wrong key length".into()));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(key_bytes);
        Ok(Box::new(P256VerifyingKey::from_bytes(&arr)?))
    }
    // K-256: multicodec prefix [0xe7, 0x01]
    else if bytes.starts_with(&[0xe7, 0x01]) {
        let key_bytes = &bytes[2..];
        if key_bytes.len() != 33 {
            return Err(CryptoError::InvalidKey("wrong key length".into()));
        }
        let mut arr = [0u8; 33];
        arr.copy_from_slice(key_bytes);
        Ok(Box::new(K256VerifyingKey::from_bytes(&arr)?))
    } else {
        Err(CryptoError::InvalidKey("unsupported multicodec".into()))
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
    use crate::crypto::{SigningKey, k256_impl::K256SigningKey, p256_impl::P256SigningKey};

    #[test]
    fn k256_generate_sign_verify() {
        let sk = K256SigningKey::generate();
        let sig = sk.sign(b"test").unwrap();
        sk.public_key().verify(b"test", &sig).unwrap();
    }

    #[test]
    fn k256_did_key_roundtrip() {
        let sk = K256SigningKey::generate();
        let did_key_str = sk.public_key().did_key();
        assert!(did_key_str.starts_with("did:key:z"));
        let parsed = parse_did_key(&did_key_str).unwrap();
        assert_eq!(sk.public_key().to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn p256_did_key_roundtrip_via_parse() {
        let sk = P256SigningKey::generate();
        let did_key_str = sk.public_key().did_key();
        let parsed = parse_did_key(&did_key_str).unwrap();
        assert_eq!(sk.public_key().to_bytes(), parsed.to_bytes());
        // Verify signature still works through parsed key
        let sig = sk.sign(b"roundtrip").unwrap();
        parsed.verify(b"roundtrip", &sig).unwrap();
    }

    #[test]
    fn cross_curve_cannot_verify() {
        let p256 = P256SigningKey::generate();
        let k256 = K256SigningKey::generate();
        let sig = p256.sign(b"test").unwrap();
        assert!(k256.public_key().verify(b"test", &sig).is_err());
    }

    #[test]
    fn parse_did_key_detects_curve() {
        let p = P256SigningKey::generate();
        let k = K256SigningKey::generate();
        let p_parsed = parse_did_key(&p.public_key().did_key()).unwrap();
        let k_parsed = parse_did_key(&k.public_key().did_key()).unwrap();
        let sig_p = p.sign(b"test").unwrap();
        let sig_k = k.sign(b"test").unwrap();
        p_parsed.verify(b"test", &sig_p).unwrap();
        k_parsed.verify(b"test", &sig_k).unwrap();
    }

    #[test]
    fn parse_did_key_invalid_prefix() {
        assert!(parse_did_key("did:key:invalid").is_err());
        assert!(parse_did_key("not-a-did-key").is_err());
    }

    #[test]
    fn parse_did_key_wrong_multicodec() {
        // Valid base58 but wrong multicodec prefix
        assert!(parse_did_key("did:key:z111111111").is_err());
    }

    #[test]
    fn parse_did_key_empty_after_prefix() {
        assert!(parse_did_key("did:key:z").is_err());
    }

    #[test]
    fn parse_did_key_truncated_key_bytes() {
        // Valid multicodec prefix but truncated key material
        let sk = P256SigningKey::generate();
        let full_did = sk.public_key().did_key();
        // Truncate: take first 20 chars (not enough for full key)
        let truncated = &full_did[..20];
        assert!(parse_did_key(truncated).is_err());
    }

    #[test]
    fn parse_did_key_rejects_lowercase_prefix() {
        // "did:KEY:z..." should fail (case-sensitive prefix)
        assert!(parse_did_key("did:KEY:z111111111").is_err());
    }

    #[test]
    fn sign_verify_empty_message() {
        // Edge case: signing an empty message
        let sk = P256SigningKey::generate();
        let sig = sk.sign(b"").unwrap();
        sk.public_key().verify(b"", &sig).unwrap();

        let sk2 = K256SigningKey::generate();
        let sig2 = sk2.sign(b"").unwrap();
        sk2.public_key().verify(b"", &sig2).unwrap();
    }

    #[test]
    fn sign_verify_large_message() {
        // Edge case: 1MB message
        let data = vec![0xABu8; 1_048_576];
        let sk = P256SigningKey::generate();
        let sig = sk.sign(&data).unwrap();
        sk.public_key().verify(&data, &sig).unwrap();
    }

    #[test]
    fn debug_does_not_leak_private_key() {
        let sk = P256SigningKey::generate();
        let debug_str = format!("{sk:?}");
        // Debug should identify the type
        assert!(
            debug_str.contains("P256SigningKey"),
            "Debug should identify the type: {debug_str}"
        );
        // Debug should use finish_non_exhaustive (..) to indicate hidden fields
        assert!(
            debug_str.contains(".."),
            "Debug should use finish_non_exhaustive to hide private key: {debug_str}"
        );
        // The inner p256 SigningKey uses "SecretKey" or "SigningKey" — neither should appear
        assert!(
            !debug_str.contains("SecretKey"),
            "Debug must not expose secret key: {debug_str}"
        );
    }

    #[test]
    fn signature_debug_does_not_leak_bytes() {
        let sk = P256SigningKey::generate();
        let sig = sk.sign(b"test").unwrap();
        let debug_str = format!("{sig:?}");
        assert!(
            debug_str.contains("64 bytes"),
            "Signature debug should be redacted: {debug_str}"
        );
    }
}
