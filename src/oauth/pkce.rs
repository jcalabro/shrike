use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};

use crate::oauth::OAuthError;

/// A PKCE challenge pair for OAuth 2.0 authorization requests.
#[derive(Debug, Clone)]
pub struct PkceChallenge {
    /// The code verifier (base64url-encoded random bytes).
    pub verifier: String,
    /// The code challenge (base64url-encoded SHA-256 of verifier).
    pub challenge: String,
    /// The challenge method — always "S256".
    pub method: &'static str,
}

/// Generates a new PKCE challenge pair using SHA-256.
pub fn generate_pkce() -> PkceChallenge {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);

    let verifier = base64url_encode(&bytes);

    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    let challenge = base64url_encode(&hash);

    PkceChallenge {
        verifier,
        challenge,
        method: "S256",
    }
}

/// Base64url-encode bytes without padding.
pub(crate) fn base64url_encode(data: &[u8]) -> String {
    BASE64URL_NOPAD.encode(data)
}

/// Base64url-decode a string without padding.
pub(crate) fn base64url_decode(s: &str) -> Result<Vec<u8>, OAuthError> {
    BASE64URL_NOPAD
        .decode(s.as_bytes())
        .map_err(|e| OAuthError::Crypto(format!("base64url decode error: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pkce_verifier_length() {
        let pkce = generate_pkce();
        // 32 bytes base64url-encoded without padding = 43 characters
        assert_eq!(pkce.verifier.len(), 43);
    }

    #[test]
    fn pkce_challenge_is_sha256_of_verifier() {
        let pkce = generate_pkce();

        let mut hasher = Sha256::new();
        hasher.update(pkce.verifier.as_bytes());
        let expected = base64url_encode(&hasher.finalize());

        assert_eq!(pkce.challenge, expected);
    }

    #[test]
    fn pkce_different_each_time() {
        let a = generate_pkce();
        let b = generate_pkce();
        assert_ne!(a.verifier, b.verifier);
        assert_ne!(a.challenge, b.challenge);
    }

    #[test]
    fn pkce_method_is_s256() {
        let pkce = generate_pkce();
        assert_eq!(pkce.method, "S256");
    }

    #[test]
    fn base64url_roundtrip() {
        let data = b"hello world";
        let encoded = base64url_encode(data);
        let decoded = base64url_decode(&encoded).unwrap_or_default();
        assert_eq!(decoded, data);
    }
}
