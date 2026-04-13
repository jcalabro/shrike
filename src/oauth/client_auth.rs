use std::time::SystemTime;

use crate::crypto::{P256SigningKey, SigningKey};

use crate::oauth::OAuthError;
use crate::oauth::pkce::base64url_encode;

/// Client authentication for OAuth token endpoint requests.
pub trait ClientAuth: Send + Sync {
    /// Add authentication parameters to the form body.
    fn apply(&self, params: &mut Vec<(String, String)>, issuer: &str) -> Result<(), OAuthError>;
}

/// Public client authentication (`token_endpoint_auth_method: "none"`).
///
/// Adds only `client_id` to the request parameters.
pub struct PublicClientAuth {
    pub client_id: String,
}

impl ClientAuth for PublicClientAuth {
    fn apply(&self, params: &mut Vec<(String, String)>, _issuer: &str) -> Result<(), OAuthError> {
        params.push(("client_id".into(), self.client_id.clone()));
        Ok(())
    }
}

/// Confidential client authentication (`token_endpoint_auth_method: "private_key_jwt"`).
///
/// Adds `client_id`, `client_assertion_type`, and a signed JWT `client_assertion`
/// to the request parameters.
pub struct ConfidentialClientAuth {
    pub client_id: String,
    pub key: P256SigningKey,
    pub key_id: String,
}

impl ClientAuth for ConfidentialClientAuth {
    fn apply(&self, params: &mut Vec<(String, String)>, issuer: &str) -> Result<(), OAuthError> {
        params.push(("client_id".into(), self.client_id.clone()));
        params.push((
            "client_assertion_type".into(),
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer".into(),
        ));

        let assertion = self.build_assertion(issuer)?;
        params.push(("client_assertion".into(), assertion));

        Ok(())
    }
}

impl ConfidentialClientAuth {
    fn build_assertion(&self, issuer: &str) -> Result<String, OAuthError> {
        // Header
        let header = serde_json::json!({
            "alg": "ES256",
            "kid": self.key_id,
        });
        let header_json =
            serde_json::to_string(&header).map_err(|e| OAuthError::Crypto(e.to_string()))?;
        let header_b64 = base64url_encode(header_json.as_bytes());

        // Generate jti (16 random bytes -> base64url)
        let mut jti_bytes = [0u8; 16];
        rand::Fill::fill(&mut jti_bytes, &mut rand::rng());
        let jti = base64url_encode(&jti_bytes);

        // Timestamps
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_err(|e| OAuthError::Crypto(format!("system time error: {e}")))?;
        let iat = now.as_secs();
        let exp = iat + 60;

        // Payload
        let payload = serde_json::json!({
            "iss": self.client_id,
            "sub": self.client_id,
            "aud": issuer,
            "jti": jti,
            "iat": iat,
            "exp": exp,
        });
        let payload_json =
            serde_json::to_string(&payload).map_err(|e| OAuthError::Crypto(e.to_string()))?;
        let payload_b64 = base64url_encode(payload_json.as_bytes());

        // Sign header.payload
        let message = format!("{header_b64}.{payload_b64}");
        let signature = self
            .key
            .sign(message.as_bytes())
            .map_err(|e| OAuthError::Crypto(e.to_string()))?;
        let sig_b64 = base64url_encode(signature.as_bytes());

        Ok(format!("{message}.{sig_b64}"))
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
    use crate::oauth::pkce::base64url_decode;

    #[test]
    fn public_auth_adds_client_id() {
        let auth = PublicClientAuth {
            client_id: "https://example.com/client".into(),
        };
        let mut params = Vec::new();
        auth.apply(&mut params, "https://issuer.example.com")
            .unwrap();

        assert_eq!(params.len(), 1);
        assert_eq!(params[0].0, "client_id");
        assert_eq!(params[0].1, "https://example.com/client");
    }

    #[test]
    fn confidential_auth_adds_assertion() {
        let key = P256SigningKey::generate();
        let auth = ConfidentialClientAuth {
            client_id: "https://example.com/client".into(),
            key,
            key_id: "key-1".into(),
        };
        let mut params = Vec::new();
        auth.apply(&mut params, "https://issuer.example.com")
            .unwrap();

        assert_eq!(params.len(), 3);

        let names: Vec<&str> = params.iter().map(|(k, _)| k.as_str()).collect();
        assert!(names.contains(&"client_id"));
        assert!(names.contains(&"client_assertion_type"));
        assert!(names.contains(&"client_assertion"));

        let assertion_type = params
            .iter()
            .find(|(k, _)| k == "client_assertion_type")
            .unwrap();
        assert_eq!(
            assertion_type.1,
            "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
        );
    }

    #[test]
    fn confidential_assertion_is_valid_jwt() {
        let key = P256SigningKey::generate();
        let auth = ConfidentialClientAuth {
            client_id: "https://example.com/client".into(),
            key,
            key_id: "key-1".into(),
        };
        let mut params = Vec::new();
        auth.apply(&mut params, "https://issuer.example.com")
            .unwrap();

        let assertion = &params
            .iter()
            .find(|(k, _)| k == "client_assertion")
            .unwrap()
            .1;
        let parts: Vec<&str> = assertion.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT must have 3 dot-separated parts");

        // Each part should be valid base64url
        for (i, part) in parts.iter().enumerate() {
            assert!(
                base64url_decode(part).is_ok(),
                "JWT part {i} is not valid base64url"
            );
        }
    }

    #[test]
    fn confidential_assertion_has_correct_claims() {
        let client_id = "https://example.com/client";
        let issuer = "https://issuer.example.com";

        let key = P256SigningKey::generate();
        let auth = ConfidentialClientAuth {
            client_id: client_id.into(),
            key,
            key_id: "key-1".into(),
        };
        let mut params = Vec::new();
        auth.apply(&mut params, issuer).unwrap();

        let assertion = &params
            .iter()
            .find(|(k, _)| k == "client_assertion")
            .unwrap()
            .1;
        let parts: Vec<&str> = assertion.split('.').collect();

        // Decode and check header
        let header_bytes = base64url_decode(parts[0]).unwrap();
        let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "key-1");

        // Decode and check payload
        let payload_bytes = base64url_decode(parts[1]).unwrap();
        let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();
        assert_eq!(payload["iss"], client_id);
        assert_eq!(payload["sub"], client_id);
        assert_eq!(payload["aud"], issuer);

        let iat = payload["iat"].as_u64().unwrap();
        let exp = payload["exp"].as_u64().unwrap();
        assert_eq!(exp, iat + 60);

        // jti should be a non-empty string
        let jti = payload["jti"].as_str().unwrap();
        assert!(!jti.is_empty());
    }
}
