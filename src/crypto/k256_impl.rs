use k256::ecdsa::{
    Signature as K256Sig, SigningKey as InnerSigningKey, VerifyingKey as InnerVerifyingKey,
    signature::hazmat::{PrehashSigner, PrehashVerifier},
};
use k256::elliptic_curve::scalar::IsHigh;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use zeroize::ZeroizeOnDrop;

use crate::crypto::{CryptoError, Signature, SigningKey, VerifyingKey, require_compressed};

// Static assertion: InnerSigningKey zeroizes on drop.
const _: () = {
    fn _assert_zeroize_on_drop<T: ZeroizeOnDrop>() {}
    fn _check() {
        _assert_zeroize_on_drop::<InnerSigningKey>();
    }
};

// K-256 (secp256k1) multicodec prefix: varint encoding of 0xe7 → [0xe7, 0x01]
const K256_MULTICODEC_PREFIX: [u8; 2] = [0xe7, 0x01];

/// The public-key half of K-256: `k256`, or libsecp256k1 with the `secp256k1`
/// feature. Signing stays on `k256`, keeping secret keys out of C code and
/// zeroized on drop; `secp256k1` 0.33 also re-blinds its context after every
/// signature, which makes it sign slower than `k256`. The `k256`
/// implementation is always compiled, so tests can check that the two agree.
trait PublicKeyBackend: Sized {
    /// Parse a compressed point whose tag [`require_compressed`] has checked.
    fn from_compressed(bytes: &[u8; 33]) -> Result<Self, CryptoError>;
    fn from_signing_key(key: &InnerSigningKey) -> Result<Self, CryptoError>;
    fn to_compressed(&self) -> [u8; 33];
    /// Verify a signature over a SHA-256 digest, rejecting high-S.
    fn verify_digest(&self, digest: &[u8; 32], sig: &K256Sig) -> Result<(), CryptoError>;
}

#[cfg(not(feature = "secp256k1"))]
type PublicKey = InnerVerifyingKey;
#[cfg(feature = "secp256k1")]
type PublicKey = secp256k1::PublicKey;

/// K-256 (secp256k1) signing key. Zeroizes private key material on drop.
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

/// K-256 (secp256k1) public key for signature verification. With the
/// `secp256k1` feature, verification uses libsecp256k1.
#[derive(Debug)]
pub struct K256VerifyingKey {
    inner: PublicKey,
}

impl K256SigningKey {
    fn new(inner: InnerSigningKey) -> Result<Self, CryptoError> {
        let verifying = K256VerifyingKey {
            inner: PublicKey::from_signing_key(&inner)?,
        };
        Ok(Self { inner, verifying })
    }

    /// Generate a random K-256 signing key.
    pub fn generate() -> Self {
        // `new` only fails on an invalid public key, which a signing key never
        // has, so this returns on the first pass.
        loop {
            if let Ok(key) = Self::new(InnerSigningKey::random(&mut OsRng)) {
                return key;
            }
        }
    }

    /// Construct from raw 32-byte private key scalar bytes.
    pub fn from_bytes(bytes: &[u8; 32]) -> Result<Self, CryptoError> {
        let inner = InnerSigningKey::from_bytes(bytes.into())
            .map_err(|e| CryptoError::InvalidKey(e.to_string()))?;
        Self::new(inner)
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
        require_compressed(bytes)?;
        Ok(Self {
            inner: PublicKey::from_compressed(bytes)?,
        })
    }
}

/// Verify `sig` over `content`, also accepting its high-S form if `malleable`.
fn verify_with<K: PublicKeyBackend>(
    key: &K,
    content: &[u8],
    sig: &Signature,
    malleable: bool,
) -> Result<(), CryptoError> {
    let digest = Sha256::digest(content);
    let sig = K256Sig::from_bytes(sig.as_bytes().into())
        .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
    let sig = if malleable {
        // (r, s) verifies iff (r, n - s) does, so check the low-S form.
        sig.normalize_s().unwrap_or(sig)
    } else if bool::from(sig.s().is_high()) {
        // atproto requires the low-S signature variant on both curves. Both
        // backends happen to reject high-S today, but we do not rely on that
        // incidental behavior — reject high-S explicitly so the invariant is
        // enforced by shrike and cannot regress.
        return Err(CryptoError::InvalidSignature(
            "high-S signature rejected (atproto requires low-S)".into(),
        ));
    } else {
        sig
    };
    key.verify_digest(&digest.into(), &sig)
}

impl VerifyingKey for K256VerifyingKey {
    fn to_bytes(&self) -> [u8; 33] {
        self.inner.to_compressed()
    }

    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        verify_with(&self.inner, content, sig, false)
    }

    fn verify_malleable(&self, content: &[u8], sig: &Signature) -> Result<(), CryptoError> {
        verify_with(&self.inner, content, sig, true)
    }

    fn jwt_alg(&self) -> &'static str {
        "ES256K"
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

impl PublicKeyBackend for InnerVerifyingKey {
    fn from_compressed(bytes: &[u8; 33]) -> Result<Self, CryptoError> {
        Self::from_sec1_bytes(bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn from_signing_key(key: &InnerSigningKey) -> Result<Self, CryptoError> {
        Ok(*key.verifying_key())
    }

    fn to_compressed(&self) -> [u8; 33] {
        let point = self.to_encoded_point(true);
        let bytes = point.as_bytes();
        let mut out = [0u8; 33];
        out.copy_from_slice(bytes);
        out
    }

    fn verify_digest(&self, digest: &[u8; 32], sig: &K256Sig) -> Result<(), CryptoError> {
        self.verify_prehash(digest, sig)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
    }
}

#[cfg(feature = "secp256k1")]
impl PublicKeyBackend for secp256k1::PublicKey {
    fn from_compressed(bytes: &[u8; 33]) -> Result<Self, CryptoError> {
        Self::from_byte_array_compressed(*bytes).map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn from_signing_key(key: &InnerSigningKey) -> Result<Self, CryptoError> {
        // The uncompressed form parses without a square root.
        let point = key.verifying_key().to_encoded_point(false);
        Self::from_slice(point.as_bytes()).map_err(|e| CryptoError::InvalidKey(e.to_string()))
    }

    fn to_compressed(&self) -> [u8; 33] {
        self.serialize()
    }

    fn verify_digest(&self, digest: &[u8; 32], sig: &K256Sig) -> Result<(), CryptoError> {
        let sig = secp256k1::ecdsa::Signature::from_compact(&sig.to_bytes())
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))?;
        secp256k1::ecdsa::verify(&sig, secp256k1::Message::from_digest(*digest), self)
            .map_err(|e| CryptoError::InvalidSignature(e.to_string()))
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

    fn high_s(sig: &Signature) -> Signature {
        let low = K256Sig::from_bytes(sig.as_bytes().into()).unwrap();
        let high = K256Sig::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes()).unwrap();
        Signature::from_bytes(high.to_bytes().into())
    }

    #[test]
    fn k256_malleable_verification_accepts_high_s() {
        let sk = K256SigningKey::generate();
        let pk = sk.public_key();
        assert_eq!(pk.jwt_alg(), "ES256K");
        let low = sk.sign(b"jwt").unwrap();
        let high = high_s(&low);
        assert_ne!(low.as_bytes(), high.as_bytes());

        pk.verify(b"jwt", &low).unwrap();
        assert!(pk.verify(b"jwt", &high).is_err());
        pk.verify_malleable(b"jwt", &low).unwrap();
        pk.verify_malleable(b"jwt", &high).unwrap();

        assert!(pk.verify_malleable(b"other", &high).is_err());
        let other = K256SigningKey::generate();
        assert!(other.public_key().verify_malleable(b"jwt", &high).is_err());
    }

    // The backends must agree on every input; `agreed` checks that, and
    // without the `secp256k1` feature it pins the `k256` behavior.

    use k256::elliptic_curve::{
        ops::Reduce, point::DecompressPoint, sec1::ToEncodedPoint, subtle::Choice,
    };
    use k256::{AffinePoint, ProjectivePoint, Scalar, U256};
    use proptest::collection::vec;
    use proptest::prelude::*;

    /// secp256k1's group order n.
    const N: &str = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141";
    /// secp256k1's field prime p.
    const P: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

    fn hex32(s: &str) -> [u8; 32] {
        data_encoding::HEXLOWER
            .decode(s.as_bytes())
            .unwrap()
            .try_into()
            .unwrap()
    }

    /// A key's re-encoding and its strict and malleable verification results,
    /// as error variants only (the messages differ by backend).
    type Outcome =
        Result<([u8; 33], Result<(), &'static str>, Result<(), &'static str>), &'static str>;

    fn kind(e: CryptoError) -> &'static str {
        match e {
            CryptoError::InvalidKey(_) => "key",
            CryptoError::InvalidSignature(_) => "signature",
            CryptoError::SigningFailed(_) => "signing",
        }
    }

    fn outcome<K: PublicKeyBackend>(key: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> Outcome {
        require_compressed(key).map_err(kind)?;
        let key = K::from_compressed(key).map_err(kind)?;
        let sig = Signature::from_bytes(*sig);
        Ok((
            key.to_compressed(),
            verify_with(&key, msg, &sig, false).map_err(kind),
            verify_with(&key, msg, &sig, true).map_err(kind),
        ))
    }

    /// The outcome of `(key, msg, sig)`, asserting every backend agrees on it,
    /// and that they agree on any in-range signature (high-S included) without
    /// shrike's own low-S check in front.
    fn agreed(key: &[u8; 33], msg: &[u8], sig: &[u8; 64]) -> Outcome {
        let rust = outcome::<InnerVerifyingKey>(key, msg, sig);
        #[cfg(feature = "secp256k1")]
        {
            assert_eq!(outcome::<secp256k1::PublicKey>(key, msg, sig), rust);
            let keys = (
                InnerVerifyingKey::from_compressed(key),
                secp256k1::PublicKey::from_compressed(key),
            );
            if let ((Ok(a), Ok(b)), Ok(sig)) = (keys, K256Sig::from_bytes(sig.into())) {
                let digest = Sha256::digest(msg).into();
                assert_eq!(
                    a.verify_digest(&digest, &sig).is_ok(),
                    b.verify_digest(&digest, &sig).is_ok()
                );
            }
        }
        rust
    }

    /// The public key each backend derives from a signing key.
    fn derived(sk: &K256SigningKey) -> [u8; 33] {
        let key = InnerVerifyingKey::from_signing_key(&sk.inner)
            .unwrap()
            .to_compressed();
        #[cfg(feature = "secp256k1")]
        assert_eq!(
            secp256k1::PublicKey::from_signing_key(&sk.inner)
                .unwrap()
                .to_compressed(),
            key
        );
        assert_eq!(sk.public_key().to_bytes(), key);
        key
    }

    /// Valid secret scalars, so shrinking cannot swap a failure for a panic.
    fn secret() -> impl Strategy<Value = [u8; 32]> {
        any::<[u8; 32]>().prop_filter("scalar in range", |b| K256SigningKey::from_bytes(b).is_ok())
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Valid signatures, their high-S twins and mutations, mismatched keys,
        /// and arbitrary signature and public-key bytes.
        #[test]
        fn backends_agree(
            secret in secret(),
            other in secret(),
            msg in vec(any::<u8>(), 0..64),
            flips in vec((0..64usize, 1..=255u8), 1..4),
            arbitrary_sig in any::<[u8; 64]>(),
            mut arbitrary_key in any::<[u8; 33]>(),
            tag in 0..3u8,
        ) {
            // Mostly well-formed tags, so about half the arbitrary keys parse.
            if tag < 2 {
                arbitrary_key[0] = 0x02 | tag;
            }
            let sk = K256SigningKey::from_bytes(&secret).unwrap();
            let key = derived(&sk);
            let sig = *sk.sign(&msg).unwrap().as_bytes();
            assert_eq!(agreed(&key, &msg, &sig), Ok((key, Ok(()), Ok(()))));

            let high = *high_s(&Signature::from_bytes(sig)).as_bytes();
            assert_eq!(agreed(&key, &msg, &high), Ok((key, Err("signature"), Ok(()))));

            let mut mutated = sig;
            for (i, mask) in flips {
                mutated[i] ^= mask;
            }
            let rejected = Ok((key, Err("signature"), Err("signature")));
            assert_eq!(agreed(&key, &msg, &mutated), rejected);
            assert_eq!(agreed(&key, &[&msg[..], b"!"].concat(), &sig), rejected);

            let other = derived(&K256SigningKey::from_bytes(&other).unwrap());
            assert_eq!(agreed(&other, &msg, &sig), Ok((other, Err("signature"), Err("signature"))));

            // Nothing arbitrary verifies, and a key that parses re-encodes as is.
            let arbitrary = [
                (&key, &arbitrary_sig),
                (&arbitrary_key, &sig),
                (&arbitrary_key, &arbitrary_sig),
            ];
            for (key, sig) in arbitrary {
                match agreed(key, &msg, sig) {
                    Ok((bytes, Err(_), Err(_))) => assert_eq!(&bytes, key),
                    Err(e) => assert_eq!(e, "key"),
                    other => panic!("unexpected outcome {other:?}"),
                }
            }
        }
    }

    #[test]
    fn k256_from_bytes_rejects_out_of_range_scalars() {
        let n = hex32(N);
        let mut above = n;
        above[31] += 1;
        for bad in [[0; 32], n, above, [0xff; 32]] {
            assert!(matches!(
                K256SigningKey::from_bytes(&bad),
                Err(CryptoError::InvalidKey(_))
            ));
        }
        let mut one = [0; 32];
        one[31] = 1;
        let mut below = n;
        below[31] -= 1;
        for good in [one, below] {
            derived(&K256SigningKey::from_bytes(&good).unwrap());
        }
    }

    #[test]
    fn backends_agree_on_malformed_public_keys() {
        let sk = K256SigningKey::from_bytes(&[7; 32]).unwrap();
        let sig = *sk.sign(b"key").unwrap().as_bytes();
        let valid = sk.public_key().to_bytes();
        assert_eq!(agreed(&valid, b"key", &sig), Ok((valid, Ok(()), Ok(()))));
        // x-coordinates that are not field elements.
        for x in [hex32(P), [0xff; 32]] {
            for tag in [0x02, 0x03] {
                let mut key = [tag; 33];
                key[1..].copy_from_slice(&x);
                assert_eq!(agreed(&key, b"key", &sig), Err("key"));
            }
        }

        // Small x-coordinates, both on and off the curve.
        let mut on_curve = 0;
        for x in 0..=255 {
            for tag in [0x02, 0x03] {
                let mut key = [0; 33];
                key[0] = tag;
                key[32] = x;
                match agreed(&key, b"key", &sig) {
                    Ok((bytes, Err(_), Err(_))) if bytes == key => on_curve += 1,
                    Err("key") => {}
                    other => panic!("unexpected outcome {other:?}"),
                }
            }
        }
        assert!(0 < on_curve && on_curve < 512, "{on_curve}");
    }

    #[test]
    fn backends_agree_on_out_of_range_signature_scalars() {
        let sk = K256SigningKey::from_bytes(&[7; 32]).unwrap();
        let key = sk.public_key().to_bytes();
        let sig = *sk.sign(b"scalars").unwrap().as_bytes();
        let n = hex32(N);
        let mut above = n;
        above[31] += 1;
        let rejected = Ok((key, Err("signature"), Err("signature")));
        for bad in [[0; 32], n, above, [0xff; 32]] {
            for half in [0..32, 32..64] {
                let mut sig = sig;
                sig[half].copy_from_slice(&bad);
                assert_eq!(agreed(&key, b"scalars", &sig), rejected);
            }
        }
    }

    fn digest_scalar(msg: &[u8]) -> Scalar {
        let digest: [u8; 32] = Sha256::digest(msg).into();
        <Scalar as Reduce<U256>>::reduce_bytes(&digest.into())
    }

    fn compressed(point: ProjectivePoint) -> [u8; 33] {
        point
            .to_affine()
            .to_encoded_point(true)
            .as_bytes()
            .try_into()
            .unwrap()
    }

    fn compact(r: Scalar, s: Scalar) -> [u8; 64] {
        [r.to_bytes(), s.to_bytes()].concat().try_into().unwrap()
    }

    /// The nonce point's x-coordinate is at or above n, so r = x - n: a rare
    /// branch that libsecp256k1 checks separately.
    #[test]
    fn backends_accept_nonce_x_above_group_order() {
        let msg = b"r = x - n";
        let mut x = hex32(N);
        let (r, point) = (1..=0xbe)
            .find_map(|i| {
                x[31] = 0x41 + i;
                let point = AffinePoint::decompress(&x.into(), Choice::from(0));
                Option::<AffinePoint>::from(point).map(|p| (Scalar::from(u64::from(i)), p))
            })
            .unwrap();
        // The key that (r, s = 1) verifies under: Q = r⁻¹(R - zG).
        let q = (ProjectivePoint::from(point) - ProjectivePoint::GENERATOR * digest_scalar(msg))
            * r.invert().unwrap();
        let key = compressed(q);
        let sig = compact(r, Scalar::ONE);
        assert_eq!(agreed(&key, msg, &sig), Ok((key, Ok(()), Ok(()))));
        let high = *high_s(&Signature::from_bytes(sig)).as_bytes();
        assert_eq!(
            agreed(&key, msg, &high),
            Ok((key, Err("signature"), Ok(())))
        );
        // The unreduced x is out of range as r.
        let mut unreduced = sig;
        unreduced[..32].copy_from_slice(&x);
        assert_eq!(
            agreed(&key, msg, &unreduced),
            Ok((key, Err("signature"), Err("signature")))
        );
    }

    /// u₁G + u₂Q is the point at infinity, whose x-coordinate matches no r.
    #[test]
    fn backends_reject_verification_at_infinity() {
        let msg = b"infinity";
        let r = Scalar::from(12345u64);
        // With s = 1, u₁G + u₂Q = zG + rQ, which vanishes for Q = -(z/r)G.
        let q = ProjectivePoint::GENERATOR * -(digest_scalar(msg) * r.invert().unwrap());
        let key = compressed(q);
        let sig = compact(r, Scalar::ONE);
        assert_eq!(
            agreed(&key, msg, &sig),
            Ok((key, Err("signature"), Err("signature")))
        );
    }
}
