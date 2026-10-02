#![no_main]
//! Differential oracle: shrike's K-256 keys, which verify with libsecp256k1
//! under the `secp256k1` feature, MUST behave exactly like the pure-Rust
//! `k256` crate: the same public keys parse and re-encode identically, the
//! same secret keys are accepted and sign identically, and every signature
//! (valid, high-S, mutated or arbitrary, under the right key or another)
//! verifies, strictly and malleably, exactly when `k256` says it does.

use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::{Signature as RefSig, SigningKey as RefSigningKey, VerifyingKey as RefKey};
use libfuzzer_sys::arbitrary::{self, Arbitrary};
use libfuzzer_sys::fuzz_target;
use sha2::{Digest, Sha256};
use shrike::crypto::{
    K256SigningKey, K256VerifyingKey, Signature, SigningKey, VerifyingKey, parse_did_key,
};

#[derive(Arbitrary, Debug)]
struct Input {
    secret: [u8; 32],
    message: Vec<u8>,
    public_key: [u8; 33],
    /// Force a compressed tag onto `public_key`, so about half of them parse.
    odd: Option<bool>,
    signature: [u8; 64],
    /// (byte index, xor mask) mutations of the valid signature.
    flips: Vec<(u8, u8)>,
}

/// `k256` verification as atproto requires it: low-S only unless `malleable`.
fn ref_verify(key: &RefKey, msg: &[u8], sig: &[u8; 64], malleable: bool) -> bool {
    let Ok(sig) = RefSig::from_bytes(sig.into()) else {
        return false;
    };
    let sig = match sig.normalize_s() {
        Some(low) if malleable => low,
        Some(_) => return false,
        None => sig,
    };
    key.verify_prehash(&Sha256::digest(msg), &sig).is_ok()
}

fn check(key: &dyn VerifyingKey, reference: &RefKey, msg: &[u8], sig: &[u8; 64]) {
    let shrike = Signature::from_bytes(*sig);
    for malleable in [false, true] {
        let got = if malleable {
            key.verify_malleable(msg, &shrike)
        } else {
            key.verify(msg, &shrike)
        };
        assert_eq!(
            got.is_ok(),
            ref_verify(reference, msg, sig, malleable),
            "malleable {malleable}: {got:?}"
        );
    }
}

fn high_s(sig: &[u8; 64]) -> [u8; 64] {
    let low = RefSig::from_bytes(sig.into()).unwrap();
    let high = RefSig::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes()).unwrap();
    high.to_bytes().into()
}

fuzz_target!(|input: Input| {
    let msg = &input.message[..];
    let mut public_key = input.public_key;
    if let Some(odd) = input.odd {
        public_key[0] = 0x02 | u8::from(odd);
    }

    // Arbitrary public keys: only compressed (0x02 or 0x03) points parse, and
    // they re-encode as given.
    let parsed = K256VerifyingKey::from_bytes(&public_key).ok();
    let parsed_ref = RefKey::from_sec1_bytes(&public_key)
        .ok()
        .filter(|_| matches!(public_key[0], 0x02 | 0x03));
    assert_eq!(parsed.is_some(), parsed_ref.is_some(), "{public_key:02x?}");
    let arbitrary = parsed.zip(parsed_ref);
    if let Some((key, reference)) = &arbitrary {
        assert_eq!(key.to_bytes(), public_key);
        assert_eq!(
            key.to_bytes()[..],
            *reference.to_encoded_point(true).as_bytes()
        );
        assert_eq!(
            parse_did_key(&key.did_key()).unwrap().to_bytes(),
            public_key
        );
        check(key, reference, msg, &input.signature);
    }

    // Arbitrary secret keys: accepted alike, deriving the same public key.
    let sk = K256SigningKey::from_bytes(&input.secret).ok();
    let ref_sk = RefSigningKey::from_bytes((&input.secret).into()).ok();
    assert_eq!(sk.is_some(), ref_sk.is_some());
    let (Some(sk), Some(ref_sk)) = (sk, ref_sk) else {
        return;
    };
    let key = sk.public_key();
    let reference = ref_sk.verifying_key();
    assert_eq!(
        key.to_bytes()[..],
        *reference.to_encoded_point(true).as_bytes()
    );

    // RFC 6979 low-S signatures, identical to `k256`'s own.
    let sig = *sk.sign(msg).unwrap().as_bytes();
    let (ref_sig, _): (RefSig, _) = ref_sk.sign_prehash(&Sha256::digest(msg)).unwrap();
    let ref_sig = ref_sig.normalize_s().unwrap_or(ref_sig);
    assert_eq!(sig[..], ref_sig.to_bytes()[..]);
    assert!(key.verify(msg, &Signature::from_bytes(sig)).is_ok());

    let mut mutated = sig;
    for (i, mask) in &input.flips {
        mutated[usize::from(*i) % 64] ^= mask;
    }
    let mut other_msg = msg.to_vec();
    other_msg.push(0);
    for sig in [sig, high_s(&sig), mutated, input.signature] {
        check(key, reference, msg, &sig);
        check(key, reference, &other_msg, &sig);
        // Under another key.
        if let Some((other, other_ref)) = &arbitrary {
            check(other, other_ref, msg, &sig);
        }
    }
});
