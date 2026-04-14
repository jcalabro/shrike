//! P-256 and secp256k1 signing and verification for AT Protocol.
//!
//! Supports two elliptic curve families: P-256 (NIST P-256) and secp256k1
//! (Bitcoin curve). Both implement SigningKey and VerifyingKey traits.
//! Use parse_did_key to extract keys from did:key identifiers.

pub mod did_key;
pub mod k256_impl;
pub mod p256_impl;
pub mod signature;

pub use did_key::parse_did_key;
pub use k256_impl::{K256SigningKey, K256VerifyingKey};
pub use p256_impl::{P256SigningKey, P256VerifyingKey};
pub use signature::Signature;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
}

/// Trait for signing keys
pub trait SigningKey: Send + Sync {
    fn public_key(&self) -> &dyn VerifyingKey;
    fn sign(&self, content: &[u8]) -> Result<Signature, CryptoError>;
}

/// Trait for verifying keys
pub trait VerifyingKey: Send + Sync {
    /// 33-byte SEC1 compressed point
    fn to_bytes(&self) -> [u8; 33];
    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), CryptoError>;
    /// Returns did:key:z... string
    fn did_key(&self) -> String;
    /// Returns z-prefixed base58btc multibase string
    fn multibase(&self) -> String;
}
