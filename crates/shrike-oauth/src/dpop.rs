use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::RwLock;

use crate::OAuthError;
use crate::jwk::p256_public_jwk;
use crate::pkce::base64url_encode;
use shrike_crypto::SigningKey;

/// Create a DPoP proof JWT (RFC 9449).
///
/// - `key`: P-256 signing key for the proof
/// - `method`: HTTP method (e.g., "POST", "GET")
/// - `target_url`: Full URL (query/fragment will be stripped for `htu`)
/// - `nonce`: Server-provided nonce (None to omit)
/// - `access_token`: Access token for `ath` claim (None to omit)
pub fn create_dpop_proof(
    key: &shrike_crypto::P256SigningKey,
    method: &str,
    target_url: &str,
    nonce: Option<&str>,
    access_token: Option<&str>,
) -> Result<String, OAuthError> {
    // 1. Generate jti: 16 random bytes, base64url encoded
    let mut jti_bytes = [0u8; 16];
    rand::fill(&mut jti_bytes);
    let jti = base64url_encode(&jti_bytes);

    // 2. Compute htu: parse URL, strip query and fragment
    let mut parsed =
        url::Url::parse(target_url).map_err(|e| OAuthError::Http(format!("invalid URL: {e}")))?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    let htu = parsed.to_string();

    // 3. Get current unix timestamp for iat
    let iat = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| OAuthError::Crypto(format!("system time error: {e}")))?
        .as_secs();

    // 4. Build header JSON with JWK
    let pub_bytes = key.public_key().to_bytes();
    let jwk = p256_public_jwk(&pub_bytes)?;
    let header = serde_json::json!({
        "alg": "ES256",
        "typ": "dpop+jwt",
        "jwk": jwk,
    });
    let header_json = serde_json::to_string(&header)?;

    // 5. Build payload JSON
    let mut payload = serde_json::json!({
        "jti": jti,
        "htm": method,
        "htu": htu,
        "iat": iat,
    });

    // Optionally add nonce
    if let Some(n) = nonce {
        payload["nonce"] = serde_json::Value::String(n.to_string());
    }

    // 6. Optionally add ath = base64url(SHA-256(access_token_bytes))
    if let Some(token) = access_token {
        let hash = Sha256::digest(token.as_bytes());
        let ath = base64url_encode(&hash);
        payload["ath"] = serde_json::Value::String(ath);
    }

    let payload_json = serde_json::to_string(&payload)?;

    // 7. Encode: message = base64url(header_json) + "." + base64url(payload_json)
    let header_b64 = base64url_encode(header_json.as_bytes());
    let payload_b64 = base64url_encode(payload_json.as_bytes());
    let message = format!("{header_b64}.{payload_b64}");

    // 8. Sign the message
    let sig = key.sign(message.as_bytes())?;

    // 9. Base64url encode the 64-byte signature
    let sig_b64 = base64url_encode(sig.as_bytes());

    // 10. Return: message + "." + base64url(signature)
    Ok(format!("{message}.{sig_b64}"))
}

/// Thread-safe per-origin DPoP nonce store with bounded size.
///
/// Stores at most 256 origin→nonce mappings to prevent unbounded memory
/// growth. When full, the oldest entry is evicted (simple FIFO via
/// insertion order in the HashMap — not perfect LRU, but sufficient
/// since the number of unique origins in practice is small).
const MAX_NONCE_ENTRIES: usize = 256;

pub struct NonceStore {
    nonces: RwLock<HashMap<String, String>>,
}

impl NonceStore {
    /// Create a new empty nonce store.
    pub fn new() -> Self {
        Self {
            nonces: RwLock::new(HashMap::new()),
        }
    }

    /// Get the stored nonce for an origin (e.g., "https://bsky.social").
    pub fn get(&self, origin: &str) -> Option<String> {
        let guard = self.nonces.read().ok()?;
        guard.get(origin).cloned()
    }

    /// Store a nonce for an origin. Evicts an arbitrary entry if at capacity.
    pub fn set(&self, origin: &str, nonce: String) {
        if let Ok(mut guard) = self.nonces.write() {
            if guard.len() >= MAX_NONCE_ENTRIES && !guard.contains_key(origin) {
                // Evict an arbitrary entry to stay within bounds.
                if let Some(key) = guard.keys().next().cloned() {
                    guard.remove(&key);
                }
            }
            guard.insert(origin.to_string(), nonce);
        }
    }

    /// Extract the origin from a URL.
    pub fn origin_from_url(url: &str) -> Result<String, OAuthError> {
        let parsed =
            url::Url::parse(url).map_err(|e| OAuthError::Http(format!("invalid URL: {e}")))?;
        Ok(parsed.origin().ascii_serialization())
    }
}

impl Default for NonceStore {
    fn default() -> Self {
        Self::new()
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
    use crate::pkce::base64url_decode;
    use shrike_crypto::{P256SigningKey, P256VerifyingKey, Signature, VerifyingKey};

    fn gen_key() -> P256SigningKey {
        P256SigningKey::generate()
    }

    fn decode_jwt_parts(jwt: &str) -> (serde_json::Value, serde_json::Value, Vec<u8>) {
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header_bytes = base64url_decode(parts[0]).unwrap();
        let payload_bytes = base64url_decode(parts[1]).unwrap();
        let sig_bytes = base64url_decode(parts[2]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        (header, payload, sig_bytes)
    }

    #[test]
    fn dpop_proof_has_three_parts() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        // Each part is non-empty
        for part in &parts {
            assert!(!part.is_empty());
        }
    }

    #[test]
    fn dpop_proof_header_fields() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();
        let (header, _, _) = decode_jwt_parts(&jwt);
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["typ"], "dpop+jwt");
        assert_eq!(header["jwk"]["kty"], "EC");
        assert_eq!(header["jwk"]["crv"], "P-256");
        assert!(header["jwk"]["x"].as_str().is_some());
        assert!(header["jwk"]["y"].as_str().is_some());
    }

    #[test]
    fn dpop_proof_payload_required_claims() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert!(payload["jti"].as_str().is_some());
        assert_eq!(payload["htm"], "POST");
        assert_eq!(payload["htu"], "https://server.example/token");
        assert!(payload["iat"].as_u64().is_some());
    }

    #[test]
    fn dpop_proof_htu_strips_query() {
        let key = gen_key();
        let jwt = create_dpop_proof(
            &key,
            "GET",
            "https://server.example/path?foo=bar&baz=1",
            None,
            None,
        )
        .unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert_eq!(payload["htu"], "https://server.example/path");
    }

    #[test]
    fn dpop_proof_htu_strips_fragment() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "GET", "https://server.example/path#frag", None, None).unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert_eq!(payload["htu"], "https://server.example/path");
    }

    #[test]
    fn dpop_proof_includes_nonce() {
        let key = gen_key();
        let jwt = create_dpop_proof(
            &key,
            "POST",
            "https://server.example/token",
            Some("server-nonce-123"),
            None,
        )
        .unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert_eq!(payload["nonce"], "server-nonce-123");
    }

    #[test]
    fn dpop_proof_omits_nonce_when_none() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert!(payload.get("nonce").is_none());
    }

    #[test]
    fn dpop_proof_includes_ath() {
        let key = gen_key();
        let token = "my-access-token";
        let jwt = create_dpop_proof(
            &key,
            "GET",
            "https://resource.example/api",
            None,
            Some(token),
        )
        .unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);

        // Compute expected ath
        let hash = Sha256::digest(token.as_bytes());
        let expected_ath = base64url_encode(&hash);
        assert_eq!(payload["ath"], expected_ath);
    }

    #[test]
    fn dpop_proof_omits_ath_when_none() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();
        let (_, payload, _) = decode_jwt_parts(&jwt);
        assert!(payload.get("ath").is_none());
    }

    #[test]
    fn dpop_proof_signature_verifies() {
        let key = gen_key();
        let jwt =
            create_dpop_proof(&key, "POST", "https://server.example/token", None, None).unwrap();

        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);

        // Reconstruct the signed message (header.payload)
        let message = format!("{}.{}", parts[0], parts[1]);

        // Decode the signature
        let sig_bytes = base64url_decode(parts[2]).unwrap();
        assert_eq!(sig_bytes.len(), 64);
        let mut sig_array = [0u8; 64];
        sig_array.copy_from_slice(&sig_bytes);
        let sig = Signature::from_bytes(sig_array);

        // Get the verifying key
        let pub_bytes = key.public_key().to_bytes();
        let vk = P256VerifyingKey::from_bytes(&pub_bytes).unwrap();

        // Verify: the verify method internally SHA-256 hashes the content
        vk.verify(message.as_bytes(), &sig).unwrap();
    }

    #[test]
    fn nonce_store_get_set() {
        let store = NonceStore::new();
        store.set("https://bsky.social", "nonce-abc".to_string());
        let result = store.get("https://bsky.social");
        assert_eq!(result, Some("nonce-abc".to_string()));
    }

    #[test]
    fn nonce_store_returns_none_for_unknown() {
        let store = NonceStore::new();
        assert_eq!(store.get("https://unknown.example"), None);
    }

    #[test]
    fn nonce_store_origin_extraction() {
        let origin =
            NonceStore::origin_from_url("https://bsky.social/xrpc/com.atproto.foo").unwrap();
        assert_eq!(origin, "https://bsky.social");

        let origin2 = NonceStore::origin_from_url("https://example.com:8080/path?query=1").unwrap();
        assert_eq!(origin2, "https://example.com:8080");

        let origin3 = NonceStore::origin_from_url("http://localhost:3000/token").unwrap();
        assert_eq!(origin3, "http://localhost:3000");
    }
}
