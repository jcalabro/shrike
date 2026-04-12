use std::sync::Arc;

use shrike_crypto::P256SigningKey;
use shrike_identity::Directory;
use shrike_syntax::Did;

use crate::OAuthError;
use crate::client_auth::{ClientAuth, ConfidentialClientAuth, PublicClientAuth};
use crate::dpop::{self, NonceStore};
use crate::metadata::{self, ClientMetadata};
use crate::pkce::{self, base64url_encode};
use crate::session::{AuthState, Session, SessionStore, StateStore};
use crate::token;

/// Configuration for constructing an [`OAuthClient`].
pub struct OAuthClientConfig {
    pub metadata: ClientMetadata,
    pub session_store: Box<dyn SessionStore>,
    pub state_store: Box<dyn StateStore>,
    /// P-256 signing key + key ID for confidential clients. `None` for public clients.
    pub signing_key: Option<(P256SigningKey, String)>,
    /// Skip issuer verification during callback (for testing only).
    /// When true, the callback will not resolve the DID to verify the issuer
    /// matches the authorization server. Defaults to `false`.
    pub skip_issuer_verification: bool,
}

/// Main OAuth client that orchestrates the full AT Protocol OAuth flow.
pub struct OAuthClient {
    metadata: ClientMetadata,
    sessions: Box<dyn SessionStore>,
    states: Box<dyn StateStore>,
    auth: Box<dyn ClientAuth>,
    http: reqwest::Client,
    nonces: Arc<NonceStore>,
    skip_issuer_verification: bool,
    /// Per-DID refresh mutex to prevent concurrent refresh of single-use tokens.
    refresh_locks: tokio::sync::Mutex<std::collections::HashMap<String, ()>>,
}

/// Options for starting the authorization flow.
#[derive(Debug, Clone)]
pub struct AuthorizeOptions {
    /// Handle or DID to authorize as.
    pub input: String,
    /// Redirect URI for the callback.
    pub redirect_uri: String,
    /// OAuth scope (defaults to client metadata scope if not provided).
    pub scope: Option<String>,
    /// Application state (random value generated if not provided).
    pub state: Option<String>,
}

/// Result of the authorization flow — a URL to redirect the user to.
#[derive(Debug, Clone)]
pub struct AuthorizeResult {
    /// The authorization URL the user should be directed to.
    pub url: String,
    /// The state parameter used for this authorization request.
    pub state: String,
}

/// Parameters received from the OAuth callback.
#[derive(Debug, Clone)]
pub struct CallbackParams {
    /// The authorization code.
    pub code: String,
    /// The state parameter (must match the one from authorize).
    pub state: String,
    /// The issuer (required by AT Protocol for verification).
    pub iss: Option<String>,
}

impl OAuthClient {
    /// Create a new `OAuthClient` from the given configuration.
    pub fn new(config: OAuthClientConfig) -> Self {
        let client_id = config.metadata.client_id.clone();

        let auth: Box<dyn ClientAuth> = match config.signing_key {
            Some((key, key_id)) => Box::new(ConfidentialClientAuth {
                client_id,
                key,
                key_id,
            }),
            None => Box::new(PublicClientAuth { client_id }),
        };

        OAuthClient {
            metadata: config.metadata,
            sessions: config.session_store,
            states: config.state_store,
            auth,
            http: reqwest::Client::new(),
            nonces: Arc::new(NonceStore::new()),
            skip_issuer_verification: config.skip_issuer_verification,
            refresh_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Start the authorization flow.
    ///
    /// Resolves the input (handle or DID) to find the user's PDS, discovers
    /// the authorization server, submits a Pushed Authorization Request (PAR),
    /// and returns the URL the user should be redirected to.
    pub async fn authorize(&self, opts: AuthorizeOptions) -> Result<AuthorizeResult, OAuthError> {
        // 1. Resolve input to a DID and get PDS endpoint.
        let did = self.resolve_input_to_did(&opts.input).await?;
        let directory = Directory::new();
        let identity = directory.lookup_did(&did).await?;
        let pds_url = identity
            .pds_endpoint()
            .ok_or_else(|| OAuthError::Identity("no PDS endpoint in DID document".into()))?;

        // 2. Fetch protected resource metadata from PDS.
        let pr_meta = metadata::fetch_protected_resource_metadata(pds_url).await?;

        // 3. Get the first authorization server URL.
        let issuer = pr_meta
            .authorization_servers
            .first()
            .ok_or_else(|| {
                OAuthError::InvalidMetadata("no authorization servers in resource metadata".into())
            })?
            .clone();

        // 4. Fetch and validate AS metadata.
        let as_meta = metadata::fetch_auth_server_metadata(&issuer).await?;
        metadata::validate_auth_server_metadata(&as_meta)?;

        // 5. Generate a P-256 DPoP key.
        let dpop_key = P256SigningKey::generate();

        // 6. Generate PKCE.
        let pkce = pkce::generate_pkce();

        // 7. Generate state.
        let state = opts.state.unwrap_or_else(|| {
            let mut bytes = [0u8; 16];
            rand::fill(&mut bytes);
            base64url_encode(&bytes)
        });

        // 8. Determine scope.
        let scope = opts.scope.unwrap_or_else(|| self.metadata.scope.clone());

        // 9. Store AuthState for later callback validation.
        let auth_state = AuthState {
            issuer: issuer.clone(),
            dpop_key_bytes: base64url_encode(&dpop_key.to_bytes()),
            auth_method: self.metadata.token_endpoint_auth_method.clone(),
            verifier: pkce.verifier.clone(),
            redirect_uri: opts.redirect_uri.clone(),
            app_state: state.clone(),
            token_endpoint: as_meta.token_endpoint.clone(),
            revocation_endpoint: as_meta.revocation_endpoint.clone(),
        };
        self.states.set(&state, &auth_state).await?;

        // 10. Build PAR request params.
        let mut params: Vec<(String, String)> = vec![
            ("response_type".into(), "code".into()),
            ("code_challenge".into(), pkce.challenge),
            ("code_challenge_method".into(), "S256".into()),
            ("state".into(), state.clone()),
            ("redirect_uri".into(), opts.redirect_uri),
            ("scope".into(), scope),
            ("login_hint".into(), opts.input),
        ];

        // 11. Apply client auth to params.
        let par_origin =
            NonceStore::origin_from_url(&as_meta.pushed_authorization_request_endpoint)?;
        self.auth.apply(&mut params, &par_origin)?;

        // 12. Create DPoP proof for PAR endpoint.
        let par_endpoint = &as_meta.pushed_authorization_request_endpoint;
        let nonce = self.nonces.get(&par_origin);
        let proof =
            dpop::create_dpop_proof(&dpop_key, "POST", par_endpoint, nonce.as_deref(), None)?;

        // 13. POST params to PAR endpoint with DPoP header.
        let resp = self
            .http
            .post(par_endpoint)
            .header("DPoP", &proof)
            .form(&params)
            .send()
            .await?;

        // Update nonce from response header.
        if let Some(new_nonce) = resp
            .headers()
            .get("DPoP-Nonce")
            .and_then(|v| v.to_str().ok())
        {
            self.nonces.set(&par_origin, new_nonce.to_string());
        }

        let status = resp.status();
        let resp_body: serde_json::Value = resp.json().await?;

        // 14. Handle `use_dpop_nonce` retry.
        let request_uri = if status == reqwest::StatusCode::BAD_REQUEST
            && resp_body.get("error").and_then(|v| v.as_str()) == Some("use_dpop_nonce")
        {
            let retry_nonce = self.nonces.get(&par_origin);
            let retry_proof = dpop::create_dpop_proof(
                &dpop_key,
                "POST",
                par_endpoint,
                retry_nonce.as_deref(),
                None,
            )?;

            let retry_resp = self
                .http
                .post(par_endpoint)
                .header("DPoP", &retry_proof)
                .form(&params)
                .send()
                .await?;

            if let Some(new_nonce) = retry_resp
                .headers()
                .get("DPoP-Nonce")
                .and_then(|v| v.to_str().ok())
            {
                self.nonces.set(&par_origin, new_nonce.to_string());
            }

            let retry_status = retry_resp.status();
            let retry_body: serde_json::Value = retry_resp.json().await?;

            if !retry_status.is_success() {
                return Err(oauth_error_from_json(&retry_body));
            }

            extract_request_uri(&retry_body)?
        } else if !status.is_success() {
            return Err(oauth_error_from_json(&resp_body));
        } else {
            extract_request_uri(&resp_body)?
        };

        // 15. Build authorization URL.
        let mut auth_url = url::Url::parse(&as_meta.authorization_endpoint)
            .map_err(|e| OAuthError::Http(format!("invalid authorization endpoint URL: {e}")))?;
        auth_url
            .query_pairs_mut()
            .append_pair("client_id", &self.metadata.client_id)
            .append_pair("request_uri", &request_uri);
        let url = auth_url.to_string();

        Ok(AuthorizeResult { url, state })
    }

    /// Handle the OAuth callback after the user authorizes.
    ///
    /// Exchanges the authorization code for tokens, verifies the issuer,
    /// and stores the session.
    pub async fn callback(&self, params: CallbackParams) -> Result<Session, OAuthError> {
        // 1. Atomically retrieve and delete state (one-time use).
        // Using take() instead of get()+delete() prevents a race where
        // two concurrent callbacks with the same state both succeed.
        let auth_state = self
            .states
            .take(&params.state)
            .await?
            .ok_or(OAuthError::InvalidState)?;

        // 2. Verify issuer parameter.
        match params.iss {
            Some(ref iss) if iss != &auth_state.issuer => {
                return Err(OAuthError::IssuerMismatch {
                    expected: auth_state.issuer.clone(),
                    actual: iss.clone(),
                });
            }
            None => {
                return Err(OAuthError::MissingIssuer);
            }
            _ => {}
        }

        // 3. Recover DPoP key from auth state.
        let dpop_key = auth_state.dpop_key()?;

        // 4. Exchange code for tokens.
        let token_set = token::exchange_code(
            &self.http,
            &auth_state.token_endpoint,
            &auth_state.revocation_endpoint,
            &params.code,
            &auth_state.verifier,
            &auth_state.redirect_uri,
            self.auth.as_ref(),
            &dpop_key,
            &self.nonces,
        )
        .await?;

        // 5. Verify issuer by resolving the DID fresh (unless skipped for testing).
        if !self.skip_issuer_verification {
            let sub_did = Did::try_from(token_set.sub.as_str())
                .map_err(|e| OAuthError::Identity(format!("invalid sub DID: {e}")))?;
            let directory = Directory::new();
            let identity = directory.lookup_did(&sub_did).await?;
            let pds_url = identity.pds_endpoint().ok_or_else(|| {
                OAuthError::IssuerVerification("no PDS endpoint in DID document".into())
            })?;

            let pr_meta = metadata::fetch_protected_resource_metadata(pds_url).await?;
            let actual_issuer = pr_meta.authorization_servers.first().ok_or_else(|| {
                OAuthError::IssuerVerification(
                    "no authorization servers in resource metadata".into(),
                )
            })?;

            if *actual_issuer != auth_state.issuer {
                // Revoke the token before returning error (best-effort).
                token::revoke_token(
                    &self.http,
                    &auth_state.revocation_endpoint,
                    &token_set.access_token,
                    self.auth.as_ref(),
                    &dpop_key,
                    &self.nonces,
                )
                .await;
                return Err(OAuthError::IssuerVerification(format!(
                    "AS mismatch: expected {}, got {}",
                    auth_state.issuer, actual_issuer
                )));
            }
        }

        // 6. Delete any existing session for this user, then store the new one.
        let _ = self.sessions.delete(&token_set.sub).await;
        let session = Session::from_key_and_tokens(&dpop_key, token_set);
        self.sessions.set(&session.token_set.sub, &session).await?;

        Ok(session)
    }

    /// Sign out a user by revoking their token and deleting their session.
    pub async fn sign_out(&self, did: &str) -> Result<(), OAuthError> {
        let session = self.sessions.get(did).await?;
        if let Some(ref session) = session {
            // Revoke token best-effort.
            if let Ok(dpop_key) = session.dpop_key() {
                token::revoke_token(
                    &self.http,
                    &session.token_set.revocation_endpoint,
                    &session.token_set.access_token,
                    self.auth.as_ref(),
                    &dpop_key,
                    &self.nonces,
                )
                .await;
            }
        }
        self.sessions.delete(did).await?;
        Ok(())
    }

    /// Get an existing session, refreshing if the token is stale.
    ///
    /// Uses a per-DID mutex to prevent concurrent refresh of single-use
    /// refresh tokens. If multiple callers hit this simultaneously for the
    /// same DID, only one performs the refresh; the others get the updated
    /// session from the store.
    pub async fn get_session(&self, did: &str) -> Result<Session, OAuthError> {
        let session = self
            .sessions
            .get(did)
            .await?
            .ok_or_else(|| OAuthError::NoSession(did.to_string()))?;

        if !session.token_set.is_stale() || session.token_set.refresh_token.is_none() {
            return Ok(session);
        }

        // Acquire refresh lock for this DID to prevent concurrent refresh.
        let _lock = self.refresh_locks.lock().await;

        // Re-read session — another caller may have already refreshed.
        let session = self
            .sessions
            .get(did)
            .await?
            .ok_or_else(|| OAuthError::NoSession(did.to_string()))?;

        if !session.token_set.is_stale() {
            return Ok(session);
        }

        let dpop_key = session.dpop_key()?;
        let new_tokens = token::refresh_token(
            &self.http,
            &session.token_set,
            self.auth.as_ref(),
            &dpop_key,
            &self.nonces,
        )
        .await?;

        let new_session = Session::from_key_and_tokens(&dpop_key, new_tokens);
        self.sessions.set(did, &new_session).await?;
        Ok(new_session)
    }

    /// Resolve an input string to a DID.
    ///
    /// If the input starts with "did:", parse it directly as a DID.
    /// Otherwise, try to resolve it as a handle using `.well-known/atproto-did`
    /// with a fallback to `com.atproto.identity.resolveHandle` on the public API.
    async fn resolve_input_to_did(&self, input: &str) -> Result<Did, OAuthError> {
        // Try parsing as a DID first.
        if let Ok(did) = Did::try_from(input) {
            return Ok(did);
        }

        // Try .well-known/atproto-did first (cheapest).
        let url = format!("https://{}/.well-known/atproto-did", input);
        if let Ok(resp) = self.http.get(&url).send().await
            && resp.status().is_success()
            && let Ok(body) = resp.text().await
            && let Ok(did) = Did::try_from(body.trim())
        {
            return Ok(did);
        }

        // Fall back to XRPC resolveHandle on the public API.
        let resolve_url = format!(
            "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={}",
            input
        );
        let resp = self.http.get(&resolve_url).send().await.map_err(|e| {
            OAuthError::Identity(format!("failed to resolve handle '{input}': {e}"))
        })?;

        if !resp.status().is_success() {
            return Err(OAuthError::Identity(format!(
                "handle resolution failed for '{input}': HTTP {}",
                resp.status()
            )));
        }

        let json: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| OAuthError::Identity(format!("failed to parse resolve response: {e}")))?;

        let did_str = json["did"]
            .as_str()
            .ok_or_else(|| OAuthError::Identity("resolveHandle response missing 'did'".into()))?;

        Did::try_from(did_str)
            .map_err(|e| OAuthError::Identity(format!("invalid DID from resolution: {e}")))
    }
}

/// Extract the `request_uri` from a PAR response body.
fn extract_request_uri(body: &serde_json::Value) -> Result<String, OAuthError> {
    body["request_uri"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .ok_or_else(|| OAuthError::OAuthResponse {
            code: "invalid_response".into(),
            description: "missing or empty request_uri in PAR response".into(),
        })
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
    use crate::session::{MemorySessionStore, MemoryStateStore};

    fn make_client_metadata() -> ClientMetadata {
        ClientMetadata {
            client_id: "https://example.com/client-metadata.json".into(),
            redirect_uris: vec!["http://127.0.0.1:8080/callback".into()],
            scope: "atproto transition:generic".into(),
            token_endpoint_auth_method: "none".into(),
            application_type: "web".into(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            dpop_bound_access_tokens: true,
            client_name: "Test App".into(),
            client_uri: "https://example.com".into(),
        }
    }

    #[test]
    fn client_new_public() {
        let config = OAuthClientConfig {
            metadata: make_client_metadata(),
            session_store: Box::new(MemorySessionStore::new()),
            state_store: Box::new(MemoryStateStore::new()),
            signing_key: None,
            skip_issuer_verification: false,
        };

        let client = OAuthClient::new(config);
        // Verify the client was constructed correctly.
        assert_eq!(
            client.metadata.client_id,
            "https://example.com/client-metadata.json"
        );
    }

    #[test]
    fn client_new_confidential() {
        let key = P256SigningKey::generate();
        let config = OAuthClientConfig {
            metadata: make_client_metadata(),
            session_store: Box::new(MemorySessionStore::new()),
            state_store: Box::new(MemoryStateStore::new()),
            signing_key: Some((key, "key-1".into())),
            skip_issuer_verification: false,
        };

        let client = OAuthClient::new(config);
        assert_eq!(
            client.metadata.client_id,
            "https://example.com/client-metadata.json"
        );
    }
}
