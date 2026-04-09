use serde::{Deserialize, Serialize};

use crate::OAuthError;
use crate::dpop::NonceStore;

/// OAuth token set returned from the token endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenSet {
    pub issuer: String,
    pub sub: String,
    pub aud: String,
    pub scope: String,
    pub access_token: String,
    pub token_type: String,
    /// Unix timestamp when the access token expires.
    pub expires_at: Option<u64>,
    pub refresh_token: Option<String>,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
}

impl TokenSet {
    /// Whether the token is stale and should be refreshed.
    ///
    /// Returns true if within 10-40 seconds of expiry. Jitter is derived
    /// from a hash of the access token to distribute refresh times across
    /// clients without requiring mutable state.
    pub fn is_stale(&self) -> bool {
        let Some(expires_at) = self.expires_at else {
            return false;
        };
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        // Jitter: 10-40 seconds before expiry, derived from token hash
        // to distribute refresh across clients deterministically.
        let token_hash = self.access_token.as_bytes().first().copied().unwrap_or(0);
        let jitter = 10 + (u64::from(token_hash) % 30);
        now + jitter >= expires_at
    }
}

/// Exchange an authorization code for a token set.
#[allow(clippy::too_many_arguments)]
pub async fn exchange_code(
    http: &reqwest::Client,
    token_endpoint: &str,
    revocation_endpoint: &str,
    code: &str,
    verifier: &str,
    redirect_uri: &str,
    auth: &dyn crate::client_auth::ClientAuth,
    dpop_key: &ratproto_crypto::P256SigningKey,
    nonces: &NonceStore,
) -> Result<TokenSet, OAuthError> {
    let mut params = vec![
        ("grant_type".into(), "authorization_code".into()),
        ("code".into(), code.into()),
        ("code_verifier".into(), verifier.into()),
        ("redirect_uri".into(), redirect_uri.into()),
    ];

    let origin = NonceStore::origin_from_url(token_endpoint)?;
    auth.apply(&mut params, &origin)?;

    post_token_request(
        http,
        token_endpoint,
        revocation_endpoint,
        &params,
        dpop_key,
        nonces,
    )
    .await
}

/// Refresh an expired token set.
pub async fn refresh_token(
    http: &reqwest::Client,
    token_set: &TokenSet,
    auth: &dyn crate::client_auth::ClientAuth,
    dpop_key: &ratproto_crypto::P256SigningKey,
    nonces: &NonceStore,
) -> Result<TokenSet, OAuthError> {
    let refresh = token_set
        .refresh_token
        .as_deref()
        .ok_or(OAuthError::NoRefreshToken)?;

    let mut params = vec![
        ("grant_type".into(), "refresh_token".into()),
        ("refresh_token".into(), refresh.into()),
    ];

    let origin = NonceStore::origin_from_url(&token_set.token_endpoint)?;
    auth.apply(&mut params, &origin)?;

    post_token_request(
        http,
        &token_set.token_endpoint,
        &token_set.revocation_endpoint,
        &params,
        dpop_key,
        nonces,
    )
    .await
}

/// Best-effort token revocation. Silently ignores all errors.
pub async fn revoke_token(
    http: &reqwest::Client,
    endpoint: &str,
    token: &str,
    auth: &dyn crate::client_auth::ClientAuth,
    dpop_key: &ratproto_crypto::P256SigningKey,
    nonces: &NonceStore,
) {
    let mut params: Vec<(String, String)> = vec![
        ("token".into(), token.into()),
        ("token_type_hint".into(), "access_token".into()),
    ];

    let origin = match NonceStore::origin_from_url(endpoint) {
        Ok(o) => o,
        Err(_) => return,
    };

    if auth.apply(&mut params, &origin).is_err() {
        return;
    }

    let nonce = nonces.get(&origin);
    let proof =
        match crate::dpop::create_dpop_proof(dpop_key, "POST", endpoint, nonce.as_deref(), None) {
            Ok(p) => p,
            Err(_) => return,
        };

    let _ = http
        .post(endpoint)
        .header("DPoP", &proof)
        .form(&params)
        .send()
        .await;
}

/// Shared logic for POST-ing to the token endpoint with DPoP and nonce retry.
async fn post_token_request(
    http: &reqwest::Client,
    token_endpoint: &str,
    revocation_endpoint: &str,
    params: &[(String, String)],
    dpop_key: &ratproto_crypto::P256SigningKey,
    nonces: &NonceStore,
) -> Result<TokenSet, OAuthError> {
    let origin = NonceStore::origin_from_url(token_endpoint)?;
    let nonce = nonces.get(&origin);

    let proof =
        crate::dpop::create_dpop_proof(dpop_key, "POST", token_endpoint, nonce.as_deref(), None)?;

    let resp = http
        .post(token_endpoint)
        .header("DPoP", &proof)
        .form(params)
        .send()
        .await?;

    // Update nonce from response header
    if let Some(new_nonce) = resp
        .headers()
        .get("DPoP-Nonce")
        .and_then(|v| v.to_str().ok())
    {
        nonces.set(&origin, new_nonce.to_string());
    }

    let status = resp.status();
    let resp_body: serde_json::Value = resp.json().await?;

    // If use_dpop_nonce error, retry once with the updated nonce
    if is_dpop_nonce_error(status, &resp_body) {
        let retry_nonce = nonces.get(&origin);
        let retry_proof = crate::dpop::create_dpop_proof(
            dpop_key,
            "POST",
            token_endpoint,
            retry_nonce.as_deref(),
            None,
        )?;

        let retry_resp = http
            .post(token_endpoint)
            .header("DPoP", &retry_proof)
            .form(params)
            .send()
            .await?;

        // Update nonce again
        if let Some(new_nonce) = retry_resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            nonces.set(&origin, new_nonce.to_string());
        }

        let retry_status = retry_resp.status();
        let retry_body: serde_json::Value = retry_resp.json().await?;

        if !retry_status.is_success() {
            return Err(oauth_error_from_json(&retry_body));
        }

        return parse_token_response(retry_body, token_endpoint, revocation_endpoint);
    }

    if !status.is_success() {
        return Err(oauth_error_from_json(&resp_body));
    }

    parse_token_response(resp_body, token_endpoint, revocation_endpoint)
}

/// Parse and validate an OAuth token response.
pub fn parse_token_response(
    json: serde_json::Value,
    token_endpoint: &str,
    revocation_endpoint: &str,
) -> Result<TokenSet, OAuthError> {
    let access_token = json["access_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::OAuthResponse {
            code: "invalid_response".into(),
            description: "missing or empty access_token".into(),
        })?
        .to_string();

    let sub = json["sub"]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| OAuthError::OAuthResponse {
            code: "invalid_response".into(),
            description: "missing or empty sub".into(),
        })?
        .to_string();

    let scope = json["scope"].as_str().unwrap_or_default().to_string();

    if !scope.split_whitespace().any(|s| s == "atproto") {
        return Err(OAuthError::MissingScope);
    }

    let token_type = json["token_type"].as_str().unwrap_or("DPoP").to_string();

    if token_type != "DPoP" {
        return Err(OAuthError::OAuthResponse {
            code: "invalid_response".into(),
            description: format!("expected token_type 'DPoP', got '{token_type}'"),
        });
    }

    let expires_at = json["expires_in"].as_u64().map(|expires_in| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
            + expires_in
    });

    let refresh_token = json["refresh_token"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from);

    let issuer = json["iss"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| NonceStore::origin_from_url(token_endpoint).unwrap_or_default());

    // The audience is the PDS URL — either from the response or from the issuer.
    let aud = json["aud"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| issuer.clone());

    Ok(TokenSet {
        issuer,
        sub,
        aud,
        scope,
        access_token,
        token_type,
        expires_at,
        refresh_token,
        token_endpoint: token_endpoint.to_string(),
        revocation_endpoint: revocation_endpoint.to_string(),
    })
}

/// Check if a response is a "use_dpop_nonce" error.
fn is_dpop_nonce_error(status: reqwest::StatusCode, body: &serde_json::Value) -> bool {
    status == reqwest::StatusCode::BAD_REQUEST
        && body.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce")
}

/// Extract an OAuthError from a JSON error response body.
fn oauth_error_from_json(body: &serde_json::Value) -> OAuthError {
    let code = body["error"].as_str().unwrap_or("unknown").to_string();
    let description = body["error_description"].as_str().unwrap_or("").to_string();
    OAuthError::OAuthResponse { code, description }
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

    fn make_token_set(expires_at: Option<u64>) -> TokenSet {
        TokenSet {
            issuer: "https://example.com".into(),
            sub: "did:plc:test".into(),
            aud: "https://example.com".into(),
            scope: "atproto".into(),
            access_token: "access".into(),
            token_type: "DPoP".into(),
            expires_at,
            refresh_token: Some("refresh".into()),
            token_endpoint: "https://example.com/oauth/token".into(),
            revocation_endpoint: "https://example.com/oauth/revoke".into(),
        }
    }

    #[test]
    fn token_set_stale_when_expired() {
        // Set expires_at to a timestamp in the past
        let ts = make_token_set(Some(1_000_000));
        assert!(ts.is_stale());
    }

    #[test]
    fn token_set_not_stale_when_fresh() {
        // Set expires_at far in the future (year ~2100)
        let ts = make_token_set(Some(4_000_000_000));
        assert!(!ts.is_stale());
    }

    #[test]
    fn parse_valid_token_response() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto transition:generic",
            "token_type": "DPoP",
            "refresh_token": "rt-456",
            "expires_in": 3600,
        });

        let ts = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap();

        assert_eq!(ts.access_token, "at-123");
        assert_eq!(ts.sub, "did:plc:user1");
        assert_eq!(ts.scope, "atproto transition:generic");
        assert_eq!(ts.token_type, "DPoP");
        assert_eq!(ts.refresh_token.as_deref(), Some("rt-456"));
        assert_eq!(ts.token_endpoint, "https://auth.example.com/oauth/token");
        assert_eq!(
            ts.revocation_endpoint,
            "https://auth.example.com/oauth/revoke"
        );
        assert_eq!(ts.issuer, "https://auth.example.com");
        assert!(ts.expires_at.is_some());
    }

    #[test]
    fn parse_token_response_missing_sub() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "scope": "atproto",
            "token_type": "DPoP",
        });

        let err = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap_err();

        match err {
            OAuthError::OAuthResponse { description, .. } => {
                assert!(description.contains("sub"));
            }
            other => panic!("expected OAuthResponse, got: {other:?}"),
        }
    }

    #[test]
    fn parse_token_response_missing_scope() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "read write",
            "token_type": "DPoP",
        });

        let err = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap_err();

        assert!(matches!(err, OAuthError::MissingScope));
    }

    #[test]
    fn parse_token_response_wrong_token_type() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto",
            "token_type": "Bearer",
        });

        let err = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap_err();

        match err {
            OAuthError::OAuthResponse { description, .. } => {
                assert!(description.contains("Bearer"));
            }
            other => panic!("expected OAuthResponse, got: {other:?}"),
        }
    }

    #[test]
    fn parse_token_response_computes_expires_at() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto",
            "token_type": "DPoP",
            "expires_in": 3600,
        });

        let ts = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let expires_at = ts.expires_at.unwrap();
        // Should be approximately now + 3600 (allow 5 seconds tolerance)
        assert!(expires_at >= now + 3595);
        assert!(expires_at <= now + 3605);
    }

    #[test]
    fn parse_token_response_no_expires_in() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto",
            "token_type": "DPoP",
        });

        let ts = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap();

        assert!(ts.expires_at.is_none());
    }

    #[test]
    fn parse_token_response_missing_token_type_defaults_to_dpop() {
        // When token_type is absent, it defaults to "DPoP"
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto",
        });

        let ts = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap();

        assert_eq!(ts.token_type, "DPoP");
    }

    #[test]
    fn parse_token_response_empty_token_type_rejected() {
        let json = serde_json::json!({
            "access_token": "at-123",
            "sub": "did:plc:user1",
            "scope": "atproto",
            "token_type": "",
        });

        let result = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        );
        assert!(result.is_err());
    }

    #[test]
    fn parse_token_response_missing_access_token() {
        let json = serde_json::json!({
            "sub": "did:plc:user1",
            "scope": "atproto",
            "token_type": "DPoP",
        });

        let err = parse_token_response(
            json,
            "https://auth.example.com/oauth/token",
            "https://auth.example.com/oauth/revoke",
        )
        .unwrap_err();

        match err {
            OAuthError::OAuthResponse { description, .. } => {
                assert!(description.contains("access_token"));
            }
            other => panic!("expected OAuthResponse, got: {other:?}"),
        }
    }

    #[test]
    fn is_dpop_nonce_error_detects_correctly() {
        let body = serde_json::json!({"error": "use_dpop_nonce"});
        assert!(is_dpop_nonce_error(reqwest::StatusCode::BAD_REQUEST, &body));
    }

    #[test]
    fn is_dpop_nonce_error_false_for_other_errors() {
        let body = serde_json::json!({"error": "invalid_grant"});
        assert!(!is_dpop_nonce_error(
            reqwest::StatusCode::BAD_REQUEST,
            &body
        ));
    }

    #[test]
    fn is_dpop_nonce_error_false_for_wrong_status() {
        let body = serde_json::json!({"error": "use_dpop_nonce"});
        assert!(!is_dpop_nonce_error(
            reqwest::StatusCode::UNAUTHORIZED,
            &body
        ));
    }

    #[test]
    fn is_dpop_nonce_error_false_for_no_error_field() {
        let body = serde_json::json!({"message": "something"});
        assert!(!is_dpop_nonce_error(
            reqwest::StatusCode::BAD_REQUEST,
            &body
        ));
    }
}
