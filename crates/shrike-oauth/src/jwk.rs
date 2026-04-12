use p256::elliptic_curve::sec1::{FromEncodedPoint, ToEncodedPoint};
use p256::{AffinePoint, EncodedPoint};

use crate::OAuthError;
use crate::pkce::base64url_encode;

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
    use crate::pkce::base64url_decode;
    use shrike_crypto::{P256SigningKey, SigningKey};

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
}
