use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint};

use crate::oauth::OAuthError;
use crate::oauth::pkce::{base64url_decode, base64url_encode};

/// A public P-256 key used in a confidential client's JWKS.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct EcPublicJwk {
    pub kty: String,
    pub crv: String,
    pub x: String,
    pub y: String,
    #[serde(rename = "kid", skip_serializing_if = "String::is_empty", default)]
    pub key_id: String,
}

/// Public keys advertised by a confidential OAuth client.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct JwkSet {
    pub keys: Vec<EcPublicJwk>,
}

impl EcPublicJwk {
    pub(crate) fn from_compressed(
        compressed_bytes: &[u8; 33],
        key_id: &str,
    ) -> Result<Self, OAuthError> {
        let value = p256_public_jwk(compressed_bytes)?;
        let mut key: Self = serde_json::from_value(value)?;
        key.key_id = key_id.to_string();
        Ok(key)
    }

    pub(crate) fn validate(&self) -> Result<(), OAuthError> {
        let invalid =
            |reason: &str| OAuthError::InvalidMetadata(format!("public JWK in jwks {reason}"));
        if self.key_id.is_empty() {
            return Err(invalid("requires kid"));
        }
        if self.kty != "EC" || self.crv != "P-256" {
            return Err(invalid("must be an EC P-256 key"));
        }
        let x = base64url_decode(&self.x).map_err(|_| invalid("has invalid x coordinate"))?;
        let y = base64url_decode(&self.y).map_err(|_| invalid("has invalid y coordinate"))?;
        if x.len() != 32 {
            return Err(invalid("has invalid x coordinate"));
        }
        if y.len() != 32 {
            return Err(invalid("has invalid y coordinate"));
        }
        let mut point = Vec::with_capacity(65);
        point.push(4);
        point.extend_from_slice(&x);
        point.extend_from_slice(&y);
        let encoded =
            EncodedPoint::from_bytes(&point).map_err(|_| invalid("is not a P-256 point"))?;
        let valid: Option<AffinePoint> = AffinePoint::from_encoded_point(&encoded).into();
        if valid.is_none() {
            return Err(invalid("is not a P-256 point"));
        }
        Ok(())
    }
}

/// Converts a SEC1-compressed P-256 public key (33 bytes) to a JWK JSON object.
///
/// The returned value has `kty`, `crv`, `x`, and `y` fields suitable for
/// use in DPoP headers and client metadata.
pub fn p256_public_jwk(compressed_bytes: &[u8; 33]) -> Result<serde_json::Value, OAuthError> {
    let encoded = EncodedPoint::from_bytes(compressed_bytes)
        .map_err(|e| OAuthError::Crypto(format!("invalid SEC1 point: {e}")))?;

    let point: AffinePoint = Option::from(AffinePoint::from_encoded_point(&encoded))
        .ok_or_else(|| OAuthError::Crypto("failed to decompress P-256 point".to_string()))?;

    let uncompressed = point.to_encoded_point(false);
    let x_bytes = uncompressed
        .x()
        .ok_or_else(|| OAuthError::Crypto("missing x coordinate".to_string()))?;
    let y_bytes = uncompressed
        .y()
        .ok_or_else(|| OAuthError::Crypto("missing y coordinate".to_string()))?;

    Ok(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": base64url_encode(x_bytes),
        "y": base64url_encode(y_bytes),
    }))
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
    use crate::crypto::{P256SigningKey, SigningKey};
    use crate::oauth::pkce::base64url_decode;

    #[test]
    fn jwk_has_correct_fields() {
        let sk = P256SigningKey::generate();
        let pub_bytes = sk.public_key().to_bytes();
        let jwk = p256_public_jwk(&pub_bytes).unwrap();

        assert_eq!(jwk["kty"], "EC");
        assert_eq!(jwk["crv"], "P-256");

        let x = jwk["x"].as_str().unwrap();
        let y = jwk["y"].as_str().unwrap();

        // 32 bytes base64url-encoded = 43 characters
        assert_eq!(x.len(), 43);
        assert_eq!(y.len(), 43);
    }

    #[test]
    fn jwk_coordinates_roundtrip() {
        let sk = P256SigningKey::generate();
        let pub_bytes = sk.public_key().to_bytes();
        let jwk = p256_public_jwk(&pub_bytes).unwrap();

        let x_bytes = base64url_decode(jwk["x"].as_str().unwrap()).unwrap();
        let y_bytes = base64url_decode(jwk["y"].as_str().unwrap()).unwrap();

        // Reconstruct the uncompressed point: 0x04 || x || y
        let mut uncompressed = vec![0x04u8];
        uncompressed.extend_from_slice(&x_bytes);
        uncompressed.extend_from_slice(&y_bytes);

        let point = EncodedPoint::from_bytes(&uncompressed).unwrap();
        let compressed = point.compress();
        let mut result = [0u8; 33];
        result.copy_from_slice(compressed.as_bytes());

        assert_eq!(result, pub_bytes);
    }

    #[test]
    fn client_jwk_rejects_malformed_and_off_curve_points() {
        let key = P256SigningKey::generate();
        let other = P256SigningKey::generate();
        let jwk = EcPublicJwk::from_compressed(&key.public_key().to_bytes(), "key-1").unwrap();
        assert!(jwk.validate().is_ok());
        let no_kid = EcPublicJwk {
            key_id: String::new(),
            ..jwk.clone()
        };
        assert!(no_kid.validate().is_err());
        let malformed = EcPublicJwk {
            x: "not-base64".into(),
            ..jwk.clone()
        };
        assert!(malformed.validate().is_err());
        let other_jwk =
            EcPublicJwk::from_compressed(&other.public_key().to_bytes(), "key-2").unwrap();
        let off_curve = EcPublicJwk {
            y: other_jwk.y,
            ..jwk
        };
        assert!(off_curve.validate().is_err());
    }
}
