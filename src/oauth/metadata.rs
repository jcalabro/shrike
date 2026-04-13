use crate::oauth::OAuthError;

/// Metadata for a protected resource (PDS), fetched from
/// `{pds_url}/.well-known/oauth-protected-resource`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ProtectedResourceMetadata {
    pub resource: String,
    pub authorization_servers: Vec<String>,
}

/// OAuth 2.0 Authorization Server metadata, fetched from
/// `{issuer}/.well-known/oauth-authorization-server`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuthServerMetadata {
    pub issuer: String,
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    #[serde(default)]
    pub pushed_authorization_request_endpoint: String,
    #[serde(default)]
    pub revocation_endpoint: String,
    #[serde(default)]
    pub dpop_signing_alg_values_supported: Vec<String>,
    #[serde(default)]
    pub scopes_supported: Vec<String>,
    #[serde(default)]
    pub response_types_supported: Vec<String>,
    #[serde(default)]
    pub grant_types_supported: Vec<String>,
    #[serde(default)]
    pub code_challenge_methods_supported: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_methods_supported: Vec<String>,
    #[serde(default)]
    pub authorization_response_iss_parameter_supported: bool,
    #[serde(default)]
    pub require_pushed_authorization_requests: bool,
    #[serde(default)]
    pub client_id_metadata_document_supported: bool,
    #[serde(default)]
    pub protected_resources: Vec<String>,
}

/// Client metadata document used for client registration via `client_id` URL.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub token_endpoint_auth_method: String,
    #[serde(default)]
    pub application_type: String,
    #[serde(default)]
    pub grant_types: Vec<String>,
    #[serde(default)]
    pub response_types: Vec<String>,
    #[serde(default)]
    pub dpop_bound_access_tokens: bool,
    #[serde(default)]
    pub client_name: String,
    #[serde(default)]
    pub client_uri: String,
}

/// Fetch the protected resource metadata from a PDS.
///
/// Builds the URL `{pds_url}/.well-known/oauth-protected-resource`, sends a
/// GET request (following no redirects), and validates the response.
pub async fn fetch_protected_resource_metadata(
    pds_url: &str,
) -> Result<ProtectedResourceMetadata, OAuthError> {
    let url = format!(
        "{}/.well-known/oauth-protected-resource",
        pds_url.trim_end_matches('/')
    );

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| OAuthError::Http(format!("failed to build HTTP client: {e}")))?;

    let resp = no_redirect
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if resp.status() != reqwest::StatusCode::OK {
        return Err(OAuthError::Http(format!(
            "protected resource metadata: HTTP {}",
            resp.status()
        )));
    }

    let meta: ProtectedResourceMetadata = resp.json().await?;

    if meta.authorization_servers.is_empty() {
        return Err(OAuthError::InvalidMetadata(
            "authorization_servers must not be empty".to_string(),
        ));
    }

    Ok(meta)
}

/// Fetch the authorization server metadata from an issuer.
///
/// Builds the URL `{issuer}/.well-known/oauth-authorization-server`, sends a
/// GET request (following no redirects), and validates the issuer matches.
pub async fn fetch_auth_server_metadata(issuer: &str) -> Result<AuthServerMetadata, OAuthError> {
    let url = format!(
        "{}/.well-known/oauth-authorization-server",
        issuer.trim_end_matches('/')
    );

    let no_redirect = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| OAuthError::Http(format!("failed to build HTTP client: {e}")))?;

    let resp = no_redirect
        .get(&url)
        .header("Accept", "application/json")
        .send()
        .await?;

    if resp.status() != reqwest::StatusCode::OK {
        return Err(OAuthError::Http(format!(
            "auth server metadata: HTTP {}",
            resp.status()
        )));
    }

    let meta: AuthServerMetadata = resp.json().await?;

    let expected_issuer = issuer.trim_end_matches('/');
    let actual_issuer = meta.issuer.trim_end_matches('/');
    if actual_issuer != expected_issuer {
        return Err(OAuthError::IssuerMismatch {
            expected: expected_issuer.to_string(),
            actual: actual_issuer.to_string(),
        });
    }

    Ok(meta)
}

/// Validate authorization server metadata for AT Protocol compliance.
///
/// Checks that the server supports the features required by the AT Protocol
/// OAuth profile: PAR endpoint, PAR requirement, client_id metadata documents,
/// and ES256 DPoP signing.
pub fn validate_auth_server_metadata(meta: &AuthServerMetadata) -> Result<(), OAuthError> {
    if meta.authorization_endpoint.is_empty() {
        return Err(OAuthError::InvalidMetadata(
            "authorization_endpoint must not be empty".to_string(),
        ));
    }

    if meta.token_endpoint.is_empty() {
        return Err(OAuthError::InvalidMetadata(
            "token_endpoint must not be empty".to_string(),
        ));
    }

    if meta.pushed_authorization_request_endpoint.is_empty() {
        return Err(OAuthError::InvalidMetadata(
            "pushed_authorization_request_endpoint must not be empty".to_string(),
        ));
    }

    if !meta.require_pushed_authorization_requests {
        return Err(OAuthError::InvalidMetadata(
            "require_pushed_authorization_requests must be true".to_string(),
        ));
    }

    if !meta.client_id_metadata_document_supported {
        return Err(OAuthError::InvalidMetadata(
            "client_id_metadata_document_supported must be true".to_string(),
        ));
    }

    if !meta
        .dpop_signing_alg_values_supported
        .iter()
        .any(|alg| alg == "ES256")
    {
        return Err(OAuthError::InvalidMetadata(
            "dpop_signing_alg_values_supported must include ES256".to_string(),
        ));
    }

    Ok(())
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

    fn valid_as_metadata_json() -> serde_json::Value {
        serde_json::json!({
            "issuer": "https://bsky.social",
            "authorization_endpoint": "https://bsky.social/oauth/authorize",
            "token_endpoint": "https://bsky.social/oauth/token",
            "pushed_authorization_request_endpoint": "https://bsky.social/oauth/par",
            "revocation_endpoint": "https://bsky.social/oauth/revoke",
            "dpop_signing_alg_values_supported": ["ES256"],
            "scopes_supported": ["atproto", "transition:generic"],
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
            "authorization_response_iss_parameter_supported": true,
            "require_pushed_authorization_requests": true,
            "client_id_metadata_document_supported": true,
            "protected_resources": ["https://bsky.social"]
        })
    }

    fn valid_as_metadata() -> AuthServerMetadata {
        serde_json::from_value(valid_as_metadata_json()).unwrap()
    }

    #[test]
    fn parse_valid_as_metadata() {
        let json = valid_as_metadata_json();
        let meta: AuthServerMetadata = serde_json::from_value(json).unwrap();

        assert_eq!(meta.issuer, "https://bsky.social");
        assert_eq!(
            meta.authorization_endpoint,
            "https://bsky.social/oauth/authorize"
        );
        assert_eq!(meta.token_endpoint, "https://bsky.social/oauth/token");
        assert_eq!(
            meta.pushed_authorization_request_endpoint,
            "https://bsky.social/oauth/par"
        );
        assert_eq!(meta.revocation_endpoint, "https://bsky.social/oauth/revoke");
        assert_eq!(meta.dpop_signing_alg_values_supported, vec!["ES256"]);
        assert_eq!(meta.scopes_supported, vec!["atproto", "transition:generic"]);
        assert_eq!(meta.response_types_supported, vec!["code"]);
        assert_eq!(
            meta.grant_types_supported,
            vec!["authorization_code", "refresh_token"]
        );
        assert_eq!(meta.code_challenge_methods_supported, vec!["S256"]);
        assert_eq!(
            meta.token_endpoint_auth_methods_supported,
            vec!["none", "private_key_jwt"]
        );
        assert!(meta.authorization_response_iss_parameter_supported);
        assert!(meta.require_pushed_authorization_requests);
        assert!(meta.client_id_metadata_document_supported);
        assert_eq!(meta.protected_resources, vec!["https://bsky.social"]);
    }

    #[test]
    fn parse_protected_resource_metadata() {
        let json = serde_json::json!({
            "resource": "https://puffball.us-east.host.bsky.network",
            "authorization_servers": [
                "https://bsky.social"
            ]
        });

        let meta: ProtectedResourceMetadata = serde_json::from_value(json).unwrap();
        assert_eq!(meta.resource, "https://puffball.us-east.host.bsky.network");
        assert_eq!(meta.authorization_servers, vec!["https://bsky.social"]);
    }

    #[test]
    fn validate_rejects_missing_par_endpoint() {
        let mut meta = valid_as_metadata();
        meta.pushed_authorization_request_endpoint = String::new();

        let err = validate_auth_server_metadata(&meta).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("pushed_authorization_request_endpoint"),
            "expected PAR endpoint error, got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_par_not_required() {
        let mut meta = valid_as_metadata();
        meta.require_pushed_authorization_requests = false;

        let err = validate_auth_server_metadata(&meta).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("require_pushed_authorization_requests"),
            "expected PAR required error, got: {msg}"
        );
    }

    #[test]
    fn validate_rejects_missing_es256() {
        let mut meta = valid_as_metadata();
        meta.dpop_signing_alg_values_supported = vec!["RS256".to_string()];

        let err = validate_auth_server_metadata(&meta).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("ES256"), "expected ES256 error, got: {msg}");
    }

    #[test]
    fn validate_accepts_valid_metadata() {
        let meta = valid_as_metadata();
        validate_auth_server_metadata(&meta).unwrap();
    }
}
