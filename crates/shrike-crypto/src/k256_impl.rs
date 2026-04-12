use k256::ecdsa::{
    Signature as K256Sig, SigningKey as InnerSigningKey, VerifyingKey as InnerVerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use crate::{CryptoError, Signature, SigningKey, VerifyingKey};

// Static assertion: InnerSigningKey zeroizes on drop.
const _: () = {
    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    fn _check() {
        _assert_zeroize_on_drop::<InnerSigningKey>();
    }
};

// K-256 (secp256k1) multicodec prefix: varint encoding of 0xe7 → [0xe7, 0x01]
const K256_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

pub struct K256SigningKey {
    inner: InnerSigningKey,
    verifying: K256VerifyingKey,
}

impl std::fmt::Debug for K256SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("K256SigningKey")
            .field("public_key", &self.verifying)
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
pub struct K256VerifyingKey {
    inner: InnerVerifyingKey,
}

impl K256SigningKey {
    /// Generate a random K-256 signing key.
    pub fn generate() -> Self {
        let inner = InnerSigningKey::random(&mut OsRng);
        let verifying = K256VerifyingKey {
            inner: *inner.verifying_key(),
        };
        Self { inner, verifying }
    }

    /// Construct from raw 32-byte private key scalar bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let inner = InnerSigningKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        let verifying = K256VerifyingKey {
            inner: *inner.verifying_key(),
        };
        Ok(Self { inner, verifying })
    }

    /// Export raw 32-byte private key scalar bytes.
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes().into()
    }
}

impl SigningKey for K256SigningKey {
    fn public_key(&self) -> &dyn VerifyingKey {
        &self.verifying
    }

    fn sign(&self, content: &[u8]) -> Result<Signature, CryptoError> {
        // SHA-256 hash the content, then sign the prehashed digest
        let digest = Sha256::digest(content);
        let (sig, _): (K256Sig, _) = self
            .inner
            .sign_prehash(&digest)
            .map_err(|e| CryptoError::SigningFailed(e.to_string()))?;
        let sig = sig.normalize_s().unwrap_or(sig); // normalize to low-S if needed
        // Convert to compact 64-byte [R || S]
        let bytes: [u8; 64] = sig.to_bytes().into();
        Ok(Signature::from_bytes(bytes))
    }
}

impl K256VerifyingKey {
    /// Construct from a 33-byte SEC1 compressed public key.
    pub fn from_bytes(bytes: &[u8; 33]) -> Result<Self, CryptoError> {
        let inner = InnerVerifyingKey::from_sec1_bytes(bytes)
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Ok(Self { inner })
    }
}

impl VerifyingKey for K256VerifyingKey {
    fn to_bytes(&self) -> [u8; 33] {
        let point = self.inner.to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        let digest = Sha256::digest(content);
        let k256_sig = K256Sig::from_bytes(sig.as_bytes().into())
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        self.inner
            .verify_prehash(&digest, &k256_sig)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    }

    fn did_key(&self) -> String {
        let mb = self.multibase();
        format!("did:key:{}", mb)
    }

    fn multibase(&self) -> String {
        let compressed = self.to_bytes();
        let mut payload = Vec::with_capacity(2 + 33);
        payload.extend_from_slice(&K256_MULTICODEC_PREFIX);
        payload.extend_from_slice(&compressed);
        format!("z{}", bs58::encode(&payload).into_string())
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
    fn k256_generate_sign_verify() {
        let sk = K256SigningKey::generate();
        let msg = b"hello world";
        let sig = sk.sign(msg).unwrap();
        assert_eq!(sig.as_bytes().len(), 64);
        sk.public_key().verify(msg, &sig).unwrap();
    }

    #[test]
    fn k256_verify_wrong_data() {
        let sk = K256SigningKey::generate();
        let sig = sk.sign(b"hello").unwrap();
        assert!(sk.public_key().verify(b"world", &sig).is_err());
    }

    #[test]
    fn k256_compressed_bytes_roundtrip() {
        let sk = K256SigningKey::generate();
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), 33);
        let parsed = K256VerifyingKey::from_bytes(&bytes).unwrap();
        assert_eq!(pk.to_bytes(), parsed.to_bytes());
    }

    #[test]
    fn k256_did_key_format() {
        let sk = K256SigningKey::generate();
        let did_key = sk.public_key().did_key();
        assert!(did_key.starts_with("did:key:z"));
    }

    #[test]
    fn k256_private_key_roundtrip() {
        let sk = K256SigningKey::generate();
        let bytes = sk.to_bytes();
        let restored = K256SigningKey::from_bytes(&bytes).unwrap();
        let sig = restored.sign(b"test").unwrap();
        sk.public_key().verify(b"test", &sig).unwrap();
    }

    #[test]
    fn k256_sign_multiple_verifiable() {
        let sk = K256SigningKey::generate();
        for _ in 0..10 {
            let sig = sk.sign(b"test").unwrap();
            assert_eq!(sig.as_bytes().len(), 64);
            sk.public_key().verify(b"test", &sig).unwrap();
        }
    }

    #[test]
    fn k256_multibase_format() {
        let sk = K256SigningKey::generate();
        let mb = sk.public_key().multibase();
        assert!(mb.starts_with('z'));
    }

    #[test]
    fn k256_low_s_enforcement() {
        let sk = K256SigningKey::generate();
        for _ in 0..50 {
            let sig = sk.sign(b"test low-s").unwrap();
            let s = &sig.as_bytes()[32..];
            // For K-256, the curve order N/2 has high byte < 0x80
            // A low-S signature has S <= N/2, meaning the high byte of S should be < 0x80
            // (This is a simplified check — the actual N/2 boundary is more specific)
            assert!(
                s[0] < 0x80,
                "signature S component should be low-S: first byte was 0x{:02x}",
                s[0]
            );
        }
    }
}
