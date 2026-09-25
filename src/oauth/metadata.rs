use crate::oauth::OAuthError;
use crate::oauth::jwk::JwkSet;

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

/// OAuth client metadata. Discoverable clients host this at their `client_id` URL;
/// loopback clients encode their callback and scope in the client ID.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct ClientMetadata {
    pub client_id: String,
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub token_endpoint_auth_method: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub token_endpoint_auth_signing_alg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks: Option<JwkSet>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub jwks_uri: Option<String>,
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

impl ClientMetadata {
    /// Build a public native client for a callback on 127.0.0.1 or [::1].
    /// The resulting client ID needs no hosted metadata document.
    pub fn loopback(redirect_uri: &str, scope: &str) -> Result<Self, OAuthError> {
        validate_loopback_redirect_uri(redirect_uri)?;
        validate_scope(scope)?;
        let query = url::form_urlencoded::Serializer::new(String::new())
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", scope)
            .finish();
        Ok(Self {
            client_id: format!("http://localhost?{query}"),
            redirect_uris: vec![redirect_uri.to_string()],
            scope: scope.to_string(),
            token_endpoint_auth_method: "none".into(),
            application_type: "native".into(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            dpop_bound_access_tokens: true,
            ..Self::default()
        })
    }

    /// Check AT Protocol client authentication metadata.
    pub fn validate_client_auth(&self) -> Result<(), OAuthError> {
        let invalid = |reason: &str| OAuthError::InvalidMetadata(reason.to_string());
        if self.jwks.is_some() && self.jwks_uri.is_some() {
            return Err(invalid("jwks and jwks_uri are mutually exclusive"));
        }
        if let Some(uri) = &self.jwks_uri {
            validate_jwks_uri(uri)?;
        }
        match self.token_endpoint_auth_method.as_str() {
            "none" => {
                if !self.token_endpoint_auth_signing_alg.is_empty()
                    || self.jwks.is_some()
                    || self.jwks_uri.is_some()
                {
                    return Err(invalid(
                        "public client must not advertise signing keys or algorithm",
                    ));
                }
            }
            "private_key_jwt" => {
                if self.token_endpoint_auth_signing_alg != "ES256" {
                    return Err(invalid(
                        "private_key_jwt requires token_endpoint_auth_signing_alg ES256",
                    ));
                }
                if self.jwks.is_none() && self.jwks_uri.is_none() {
                    return Err(invalid("private_key_jwt requires jwks or jwks_uri"));
                }
                if let Some(set) = &self.jwks {
                    if set.keys.is_empty() {
                        return Err(invalid(
                            "private_key_jwt requires at least one public key in jwks",
                        ));
                    }
                    for key in &set.keys {
                        key.validate()?;
                    }
                }
            }
            other => {
                return Err(invalid(&format!(
                    "unsupported token_endpoint_auth_method {other:?}"
                )));
            }
        }
        Ok(())
    }
}

fn validate_loopback_redirect_uri(raw: &str) -> Result<(), OAuthError> {
    let invalid = || OAuthError::InvalidMetadata(format!("invalid loopback redirect URI {raw:?}"));
    if raw.contains('\\') || !raw.starts_with("http://") {
        return Err(invalid());
    }
    let parsed = url::Url::parse(raw).map_err(|_| invalid())?;
    if parsed.username() != "" || parsed.password().is_some() || parsed.fragment().is_some() {
        return Err(invalid());
    }
    let host = match parsed.host() {
        Some(url::Host::Ipv4(ip)) if ip.is_loopback() && ip.octets() == [127, 0, 0, 1] => {
            "127.0.0.1"
        }
        Some(url::Host::Ipv6(ip)) if ip.is_loopback() => "[::1]",
        _ => return Err(invalid()),
    };
    let authority = raw[7..].split(['/', '?', '#']).next().ok_or_else(invalid)?;
    let rest = authority.strip_prefix(host).ok_or_else(invalid)?;
    if !rest.is_empty() {
        let port = rest.strip_prefix(':').ok_or_else(invalid)?;
        if port.is_empty()
            || !port.bytes().all(|b| b.is_ascii_digit())
            || port.parse::<u16>().ok().is_none_or(|n| n == 0)
        {
            return Err(invalid());
        }
    }
    if parsed.query().is_some_and(|q| !valid_percent_encoding(q)) {
        return Err(invalid());
    }
    Ok(())
}

fn valid_percent_encoding(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    bytes.iter().enumerate().all(|(i, b)| {
        *b != b'%'
            || bytes.get(i + 1).is_some_and(u8::is_ascii_hexdigit)
                && bytes.get(i + 2).is_some_and(u8::is_ascii_hexdigit)
    })
}

fn validate_scope(scope: &str) -> Result<(), OAuthError> {
    let mut has_atproto = false;
    if scope.is_empty()
        || scope.split(' ').any(|token| {
            if token == "atproto" {
                has_atproto = true;
            }
            token.is_empty()
                || !token
                    .bytes()
                    .all(|b| b == b'!' || (b'#'..=b'[').contains(&b) || (b']'..=b'~').contains(&b))
        })
        || !has_atproto
    {
        return Err(OAuthError::InvalidMetadata(format!(
            "invalid loopback client scope {scope:?}"
        )));
    }
    Ok(())
}

fn validate_jwks_uri(raw: &str) -> Result<(), OAuthError> {
    let invalid = || OAuthError::InvalidMetadata(format!("invalid jwks_uri {raw:?}"));
    if raw.contains('\\') {
        return Err(invalid());
    }
    let parsed = url::Url::parse(raw).map_err(|_| invalid())?;
    let authority = raw
        .split_once("://")
        .and_then(|(_, rest)| rest.split(['/', '?', '#']).next())
        .ok_or_else(invalid)?;
    if parsed.username() != ""
        || parsed.password().is_some()
        || parsed.fragment().is_some()
        || authority.contains('@')
    {
        return Err(invalid());
    }
    let loopback = match parsed.host() {
        Some(url::Host::Domain(host)) => host == "localhost",
        Some(url::Host::Ipv4(ip)) => ip.is_loopback() && ip.octets() == [127, 0, 0, 1],
        Some(url::Host::Ipv6(ip)) => ip.is_loopback(),
        None => return Err(invalid()),
    };
    if parsed.scheme() != "https" && (parsed.scheme() != "http" || !loopback)
        || parsed.scheme() == "https" && loopback
    {
        return Err(invalid());
    }
    if parsed.scheme() == "https"
        && let Some(url::Host::Domain(host)) = parsed.host()
        && (!host.contains('.') || host.ends_with(".local") || numeric_ipv4_host(host))
    {
        return Err(invalid());
    }
    if parsed.scheme() == "https"
        && let Some(url::Host::Ipv4(ip)) = parsed.host()
        && let Some(raw_host) = authority.split(':').next()
        && numeric_ipv4_host(raw_host)
        && raw_host != ip.to_string()
    {
        return Err(invalid());
    }
    Ok(())
}

fn numeric_ipv4_host(host: &str) -> bool {
    let parts: Vec<_> = host.trim_end_matches('.').split('.').collect();
    parts.len() <= 4
        && parts.iter().all(|part| {
            if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
                !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
            } else {
                !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit())
            }
        })
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

    let no_redirect = crate::outbound::no_redirect_client()
        .map_err(|e| OAuthError::Http(format!("failed to build HTTP client: {e}")))?;

    let resp = crate::outbound::apply_user_agent(
        no_redirect.get(&url).header("Accept", "application/json"),
    )
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

    let no_redirect = crate::outbound::no_redirect_client()
        .map_err(|e| OAuthError::Http(format!("failed to build HTTP client: {e}")))?;

    let resp = crate::outbound::apply_user_agent(
        no_redirect.get(&url).header("Accept", "application/json"),
    )
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

    #[test]
    fn loopback_metadata_encodes_callback_and_scope() {
        for (redirect, scope) in [
            (
                "http://127.0.0.1:8120/oauth/callback",
                "atproto include:fm.leadsheet.authFull",
            ),
            ("http://[::1]:8120/callback", "atproto"),
            ("http://127.0.0.1:80/callback", "atproto"),
            (
                "http://127.0.0.1/callback?return=%2Fapp",
                "atproto repo:example.record?action=create",
            ),
        ] {
            let meta = ClientMetadata::loopback(redirect, scope).unwrap();
            assert!(meta.client_id.starts_with("http://localhost?"));
            let client_id = url::Url::parse(&meta.client_id).unwrap();
            let query: std::collections::HashMap<_, _> =
                client_id.query_pairs().into_owned().collect();
            assert_eq!(query.get("redirect_uri").unwrap(), redirect);
            assert_eq!(query.get("scope").unwrap(), scope);
            assert_eq!(meta.redirect_uris, [redirect]);
            assert_eq!(meta.application_type, "native");
            assert_eq!(meta.token_endpoint_auth_method, "none");
            assert!(meta.dpop_bound_access_tokens);
            assert!(meta.validate_client_auth().is_ok());
            let json = serde_json::to_value(meta).unwrap();
            assert!(json.get("jwks").is_none());
            assert!(json.get("jwks_uri").is_none());
        }
        let meta = ClientMetadata::loopback(
            "http://127.0.0.1:8120/oauth/callback",
            "atproto include:fm.leadsheet.authFull",
        )
        .unwrap();
        assert_eq!(
            meta.client_id,
            "http://localhost?redirect_uri=http%3A%2F%2F127.0.0.1%3A8120%2Foauth%2Fcallback&scope=atproto+include%3Afm.leadsheet.authFull"
        );
    }

    #[test]
    fn loopback_metadata_rejects_bad_callbacks_and_scopes() {
        for raw in [
            "",
            "http://localhost:8120/callback",
            "https://127.0.0.1/callback",
            "http://127.0.0.2/callback",
            "http://127.0.0.1.evil.example/callback",
            "http://[::2]/callback",
            "http://user@127.0.0.1/callback",
            "http://127.0.0.1/callback#fragment",
            "http://127.0.0.1:0/callback",
            "http://127.0.0.1:65536/callback",
            "http://127.0.0.1:abc/callback",
            "http://127.0.0.1:/callback",
            "http://127.0.0.1/callback?bad=%ZZ",
            "http://127.0.0.1/\\evil",
            "127.0.0.1:8120/callback",
        ] {
            assert!(
                ClientMetadata::loopback(raw, "atproto").is_err(),
                "accepted {raw:?}"
            );
        }
        for scope in [
            "",
            "openid",
            "notatproto",
            "atprotoish",
            "atproto ",
            " atproto",
            "atproto  include:foo",
            "atproto\nopenid",
            "atproto \"quoted\"",
            "atproto \\escaped",
            "atproto café",
        ] {
            assert!(
                ClientMetadata::loopback("http://127.0.0.1/callback", scope).is_err(),
                "accepted {scope:?}"
            );
        }
    }

    #[test]
    fn client_auth_metadata_validates_key_sources_and_uris() {
        let uri = "https://example.com/jwks.json".to_string();
        let mut meta = ClientMetadata {
            token_endpoint_auth_method: "private_key_jwt".into(),
            token_endpoint_auth_signing_alg: "ES256".into(),
            jwks_uri: Some(uri),
            ..Default::default()
        };
        assert!(meta.validate_client_auth().is_ok());
        for valid_uri in [
            "http://localhost:8120/jwks.json",
            "http://127.0.0.1:8120/jwks.json",
            "http://[::1]:8120/jwks.json",
        ] {
            meta.jwks_uri = Some(valid_uri.into());
            assert!(meta.validate_client_auth().is_ok(), "rejected {valid_uri}");
        }
        for bad_uri in [
            "",
            "oauth/jwks.json",
            "ftp://example.com/jwks.json",
            "http://example.com/jwks.json",
            "http://127.0.0.2/jwks.json",
            "https://localhost/jwks.json",
            "https://127.0.0.1/jwks.json",
            "https://127.1/jwks.json",
            "https://0x7f.1/jwks.json",
            "https://10.1/jwks.json",
            "https://0x8.1/jwks.json",
            "https://127.0.0.1./jwks.json",
            "https://internal.local/jwks.json",
            "https://intranet/jwks.json",
            "https://user@example.com/jwks.json",
            "https://example.com/jwks.json#fragment",
            "https://example.com/\\evil",
        ] {
            meta.jwks_uri = Some(bad_uri.into());
            assert!(meta.validate_client_auth().is_err(), "accepted {bad_uri}");
        }
        meta.jwks_uri = Some("https://example.com/jwks.json".into());
        meta.jwks = Some(JwkSet::default());
        assert!(
            meta.validate_client_auth()
                .unwrap_err()
                .to_string()
                .contains("mutually exclusive")
        );
        meta.jwks_uri = None;
        assert!(
            meta.validate_client_auth()
                .unwrap_err()
                .to_string()
                .contains("at least one")
        );
        meta.jwks = None;
        assert!(
            meta.validate_client_auth()
                .unwrap_err()
                .to_string()
                .contains("requires jwks")
        );
        meta.token_endpoint_auth_method = "none".into();
        assert!(meta.validate_client_auth().is_err());
        meta.token_endpoint_auth_signing_alg.clear();
        assert!(meta.validate_client_auth().is_ok());
    }
}
