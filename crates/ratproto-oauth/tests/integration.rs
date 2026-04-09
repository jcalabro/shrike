//! Integration tests for ratproto-oauth using a mock OAuth server.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]

use std::collections::HashMap;
use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use data_encoding::BASE64URL_NOPAD;
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;

use ratproto_oauth::*;

// ---------------------------------------------------------------------------
// Mock server state
// ---------------------------------------------------------------------------

#[derive(Default)]
struct MockState {
    /// PKCE challenges stored during PAR, keyed by request_uri.
    pkce_challenges: HashMap<String, String>,
    /// Number of times the token endpoint has been called (for nonce retry tests).
    token_call_count: u32,
    /// If set, the token endpoint returns use_dpop_nonce on the first call.
    require_nonce_retry: bool,
    /// Number of times the revoke endpoint has been called.
    revoke_call_count: u32,
    /// Track calls to the resource endpoint for nonce retry tests.
    resource_call_count: u32,
    /// If set, the resource endpoint returns 401 with use_dpop_nonce on first call.
    resource_require_nonce: bool,
}

type SharedState = Arc<Mutex<MockState>>;

// ---------------------------------------------------------------------------
// Mock endpoints
// ---------------------------------------------------------------------------

/// `GET /.well-known/oauth-protected-resource`
async fn protected_resource_metadata(
    State(state): State<SharedState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:0");
    let base_url = format!("http://{host}");
    let _ = state;
    Json(serde_json::json!({
        "resource": base_url,
        "authorization_servers": [base_url]
    }))
}

/// `GET /.well-known/oauth-authorization-server`
async fn auth_server_metadata(headers: HeaderMap) -> impl IntoResponse {
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:0");
    let base_url = format!("http://{host}");
    Json(serde_json::json!({
        "issuer": base_url,
        "authorization_endpoint": format!("{base_url}/oauth/authorize"),
        "token_endpoint": format!("{base_url}/oauth/token"),
        "pushed_authorization_request_endpoint": format!("{base_url}/oauth/par"),
        "revocation_endpoint": format!("{base_url}/oauth/revoke"),
        "dpop_signing_alg_values_supported": ["ES256"],
        "scopes_supported": ["atproto", "transition:generic"],
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],
        "token_endpoint_auth_methods_supported": ["none", "private_key_jwt"],
        "authorization_response_iss_parameter_supported": true,
        "require_pushed_authorization_requests": true,
        "client_id_metadata_document_supported": true,
        "protected_resources": [base_url]
    }))
}

/// `POST /oauth/par` — Pushed Authorization Request
async fn par_endpoint(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Validate DPoP header is present.
    assert!(
        headers.get("dpop").is_some(),
        "PAR request must include DPoP header"
    );

    // Parse the form body.
    let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();

    // Store the PKCE challenge for later verification.
    let challenge = params.get("code_challenge").cloned().unwrap_or_default();
    let request_uri = "urn:test:request:123".to_string();

    {
        let mut s = state.lock().await;
        s.pkce_challenges.insert(request_uri.clone(), challenge);
    }

    (
        StatusCode::CREATED,
        Json(serde_json::json!({
            "request_uri": request_uri,
            "expires_in": 60
        })),
    )
}

/// `POST /oauth/token` — Token exchange and refresh
async fn token_endpoint(
    State(state): State<SharedState>,
    headers: HeaderMap,
    body: String,
) -> impl IntoResponse {
    // Validate DPoP header.
    assert!(
        headers.get("dpop").is_some(),
        "Token request must include DPoP header"
    );

    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("127.0.0.1:0");
    let base_url = format!("http://{host}");

    let params: HashMap<String, String> = url::form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();

    let grant_type = params.get("grant_type").map(|s| s.as_str()).unwrap_or("");

    // Check if we should force a nonce retry.
    {
        let mut s = state.lock().await;
        s.token_call_count += 1;
        if s.require_nonce_retry && s.token_call_count == 1 {
            return (
                StatusCode::BAD_REQUEST,
                [(
                    axum::http::header::HeaderName::from_static("dpop-nonce"),
                    "server-nonce-abc".to_string(),
                )],
                Json(serde_json::json!({
                    "error": "use_dpop_nonce",
                    "error_description": "DPoP nonce required"
                })),
            );
        }
    }

    match grant_type {
        "authorization_code" => {
            // Validate PKCE: we stored the challenge during PAR (or seeded it)
            // and now verify that S256(verifier) == challenge.
            let verifier = params.get("code_verifier").cloned().unwrap_or_default();
            let expected_challenge = {
                let s = state.lock().await;
                s.pkce_challenges
                    .values()
                    .next()
                    .cloned()
                    .unwrap_or_default()
            };

            // Compute S256 of the verifier.
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(verifier.as_bytes());
            let hash = hasher.finalize();
            let computed = BASE64URL_NOPAD.encode(&hash);

            if computed != expected_challenge {
                return (
                    StatusCode::BAD_REQUEST,
                    [(
                        axum::http::header::HeaderName::from_static("dpop-nonce"),
                        String::new(),
                    )],
                    Json(serde_json::json!({
                        "error": "invalid_grant",
                        "error_description": "PKCE verification failed"
                    })),
                );
            }

            (
                StatusCode::OK,
                [(
                    axum::http::header::HeaderName::from_static("dpop-nonce"),
                    String::new(),
                )],
                Json(serde_json::json!({
                    "access_token": "test-at",
                    "token_type": "DPoP",
                    "expires_in": 3600,
                    "refresh_token": "test-rt",
                    "sub": "did:plc:test123456789abcdefghij",
                    "scope": "atproto",
                    "iss": base_url
                })),
            )
        }
        "refresh_token" => (
            StatusCode::OK,
            [(
                axum::http::header::HeaderName::from_static("dpop-nonce"),
                String::new(),
            )],
            Json(serde_json::json!({
                "access_token": "test-at-refreshed",
                "token_type": "DPoP",
                "expires_in": 3600,
                "refresh_token": "test-rt-2",
                "sub": "did:plc:test123456789abcdefghij",
                "scope": "atproto",
                "iss": base_url
            })),
        ),
        _ => (
            StatusCode::BAD_REQUEST,
            [(
                axum::http::header::HeaderName::from_static("dpop-nonce"),
                String::new(),
            )],
            Json(serde_json::json!({
                "error": "unsupported_grant_type",
                "error_description": "unsupported grant type"
            })),
        ),
    }
}

/// `POST /oauth/revoke` — Token revocation
async fn revoke_endpoint(State(state): State<SharedState>) -> impl IntoResponse {
    {
        let mut s = state.lock().await;
        s.revoke_call_count += 1;
    }
    StatusCode::OK
}

/// `GET /xrpc/com.example.ping` — Protected resource endpoint
async fn xrpc_ping(State(state): State<SharedState>, headers: HeaderMap) -> impl IntoResponse {
    // Check for nonce retry simulation.
    {
        let mut s = state.lock().await;
        s.resource_call_count += 1;
        if s.resource_require_nonce && s.resource_call_count == 1 {
            return (
                StatusCode::UNAUTHORIZED,
                [
                    (
                        axum::http::header::HeaderName::from_static("www-authenticate"),
                        "DPoP error=\"use_dpop_nonce\"".to_string(),
                    ),
                    (
                        axum::http::header::HeaderName::from_static("dpop-nonce"),
                        "resource-nonce-xyz".to_string(),
                    ),
                ],
                Json(serde_json::json!({"error": "use_dpop_nonce"})),
            );
        }
    }

    // Validate Authorization header.
    let auth = headers
        .get("authorization")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(
        auth.starts_with("DPoP "),
        "Expected DPoP authorization, got: {auth}"
    );

    // Validate DPoP header is present.
    assert!(
        headers.get("dpop").is_some(),
        "Resource request must include DPoP header"
    );

    (
        StatusCode::OK,
        [
            (
                axum::http::header::HeaderName::from_static("www-authenticate"),
                String::new(),
            ),
            (
                axum::http::header::HeaderName::from_static("dpop-nonce"),
                String::new(),
            ),
        ],
        Json(serde_json::json!({"message": "pong"})),
    )
}

// ---------------------------------------------------------------------------
// Server setup
// ---------------------------------------------------------------------------

async fn start_mock_server() -> (String, SharedState) {
    start_mock_server_with_state(MockState::default()).await
}

async fn start_mock_server_with_state(initial_state: MockState) -> (String, SharedState) {
    let state: SharedState = Arc::new(Mutex::new(initial_state));

    let app = axum::Router::new()
        .route(
            "/.well-known/oauth-protected-resource",
            get(protected_resource_metadata),
        )
        .route(
            "/.well-known/oauth-authorization-server",
            get(auth_server_metadata),
        )
        .route("/oauth/par", post(par_endpoint))
        .route("/oauth/token", post(token_endpoint))
        .route("/oauth/revoke", post(revoke_endpoint))
        .route("/xrpc/com.example.ping", get(xrpc_ping))
        .with_state(state.clone());

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base_url = format!("http://{addr}");

    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });

    (base_url, state)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn make_client_with_stores(
    base_url: &str,
    session_store: Box<dyn SessionStore>,
    state_store: Box<dyn StateStore>,
) -> OAuthClient {
    OAuthClient::new(OAuthClientConfig {
        metadata: ClientMetadata {
            client_id: format!("{base_url}/client-metadata.json"),
            redirect_uris: vec![format!("{base_url}/callback")],
            scope: "atproto".into(),
            token_endpoint_auth_method: "none".into(),
            application_type: "web".into(),
            grant_types: vec!["authorization_code".into(), "refresh_token".into()],
            response_types: vec!["code".into()],
            dpop_bound_access_tokens: true,
            client_name: "Test App".into(),
            client_uri: base_url.into(),
        },
        session_store,
        state_store,
        signing_key: None,
        skip_issuer_verification: true,
    })
}

fn make_client(base_url: &str) -> OAuthClient {
    make_client_with_stores(
        base_url,
        Box::new(MemorySessionStore::new()),
        Box::new(MemoryStateStore::new()),
    )
}

fn make_token_set(base_url: &str) -> TokenSet {
    TokenSet {
        issuer: base_url.into(),
        sub: "did:plc:test123456789abcdefghij".into(),
        aud: base_url.into(),
        scope: "atproto".into(),
        access_token: "test-at".into(),
        token_type: "DPoP".into(),
        expires_at: Some(4_000_000_000),
        refresh_token: Some("test-rt".into()),
        token_endpoint: format!("{base_url}/oauth/token"),
        revocation_endpoint: format!("{base_url}/oauth/revoke"),
    }
}

/// Build a mock `AuthState` as if `authorize()` had been called, storing it in
/// the given `StateStore`. Returns the state key and the PKCE challenge (which
/// must also be seeded into the mock server state for verification).
async fn seed_auth_state(state_store: &dyn StateStore, base_url: &str) -> (String, String) {
    let dpop_key = ratproto_crypto::P256SigningKey::generate();
    let pkce = ratproto_oauth::pkce::generate_pkce();
    let state_key = "test-state-abc".to_string();

    let auth_state = AuthState {
        issuer: base_url.to_string(),
        dpop_key_bytes: BASE64URL_NOPAD.encode(&dpop_key.to_bytes()),
        auth_method: "none".into(),
        verifier: pkce.verifier.clone(),
        redirect_uri: format!("{base_url}/callback"),
        app_state: state_key.clone(),
        token_endpoint: format!("{base_url}/oauth/token"),
        revocation_endpoint: format!("{base_url}/oauth/revoke"),
    };

    state_store.set(&state_key, &auth_state).await.unwrap();

    (state_key, pkce.challenge)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// The callback flow exchanges an authorization code for tokens.
///
/// Seeds an AuthState (simulating what `authorize()` would do), calls
/// `callback()` against the mock token endpoint, and verifies the resulting
/// session has the correct token fields.
#[tokio::test]
async fn callback_exchanges_code_for_tokens() {
    let (base_url, mock_state) = start_mock_server().await;

    let session_store = Box::new(MemorySessionStore::new());
    let state_store = Box::new(MemoryStateStore::new());

    // Seed an AuthState in the state store.
    let (state_key, pkce_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    // Store the PKCE challenge in the mock server so it can verify the code_verifier.
    {
        let mut s = mock_state.lock().await;
        s.pkce_challenges
            .insert("urn:test:request:123".into(), pkce_challenge);
    }

    let client = make_client_with_stores(&base_url, session_store, state_store);

    // Call callback with a mock authorization code.
    let session = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: Some(base_url.clone()),
        })
        .await
        .unwrap();

    assert_eq!(session.token_set.sub, "did:plc:test123456789abcdefghij");
    assert_eq!(session.token_set.scope, "atproto");
    assert_eq!(session.token_set.access_token, "test-at");
    assert_eq!(session.token_set.token_type, "DPoP");
    assert_eq!(session.token_set.refresh_token.as_deref(), Some("test-rt"));

    // Verify the session was stored and is retrievable.
    let retrieved = client
        .get_session("did:plc:test123456789abcdefghij")
        .await
        .unwrap();
    assert_eq!(retrieved.token_set.access_token, "test-at");
}

/// An authenticated request sends DPoP + Authorization headers.
///
/// Constructs a session directly, creates an `AuthenticatedClient`, makes a
/// query to the mock protected resource, and verifies the response.
#[tokio::test]
async fn authenticated_request_sends_dpop() {
    let (base_url, _mock_state) = start_mock_server().await;

    let dpop_key = ratproto_crypto::P256SigningKey::generate();
    let session = Session::from_key_and_tokens(&dpop_key, make_token_set(&base_url));

    let nonces = Arc::new(NonceStore::new());
    let auth_client = AuthenticatedClient::from_session(&session, nonces).unwrap();

    let resp: serde_json::Value = auth_client
        .query("com.example.ping", &serde_json::json!({}))
        .await
        .unwrap();

    assert_eq!(resp["message"], "pong");
}

/// The authenticated client retries with a nonce on 401 use_dpop_nonce.
///
/// The mock resource endpoint returns 401 with use_dpop_nonce on the first
/// call, then succeeds on retry.
#[tokio::test]
async fn nonce_retry_on_401() {
    let initial = MockState {
        resource_require_nonce: true,
        ..Default::default()
    };
    let (base_url, _mock_state) = start_mock_server_with_state(initial).await;

    let dpop_key = ratproto_crypto::P256SigningKey::generate();
    let session = Session::from_key_and_tokens(&dpop_key, make_token_set(&base_url));

    let nonces = Arc::new(NonceStore::new());
    let auth_client = AuthenticatedClient::from_session(&session, nonces).unwrap();

    // First call gets 401, library retries automatically, second call succeeds.
    let resp: serde_json::Value = auth_client
        .query("com.example.ping", &serde_json::json!({}))
        .await
        .unwrap();

    assert_eq!(resp["message"], "pong");
}

/// Sign out revokes the token and deletes the session.
#[tokio::test]
async fn sign_out_revokes_and_deletes() {
    let (base_url, mock_state) = start_mock_server().await;

    let did = "did:plc:test123456789abcdefghij";

    // Pre-populate a session store.
    let dpop_key = ratproto_crypto::P256SigningKey::generate();
    let session = Session::from_key_and_tokens(&dpop_key, make_token_set(&base_url));

    let session_store = MemorySessionStore::new();
    session_store.set(did, &session).await.unwrap();

    let client = make_client_with_stores(
        &base_url,
        Box::new(session_store),
        Box::new(MemoryStateStore::new()),
    );

    // Verify the session exists.
    let existing = client.get_session(did).await;
    assert!(existing.is_ok());

    // Sign out.
    client.sign_out(did).await.unwrap();

    // Verify the session was deleted.
    let result = client.get_session(did).await;
    assert!(result.is_err());

    // Verify the revocation endpoint was called.
    let s = mock_state.lock().await;
    assert!(s.revoke_call_count >= 1, "expected revoke to be called");
}

/// Callback rejects an unknown state parameter.
#[tokio::test]
async fn callback_rejects_wrong_state() {
    let (base_url, _mock_state) = start_mock_server().await;
    let client = make_client(&base_url);

    let result = client
        .callback(CallbackParams {
            code: "any-code".into(),
            state: "nonexistent-state".into(),
            iss: Some(base_url),
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::InvalidState => {} // expected
        other => panic!("expected InvalidState, got: {other:?}"),
    }
}

/// Callback rejects a mismatched issuer.
#[tokio::test]
async fn callback_rejects_wrong_issuer() {
    let (base_url, _mock_state) = start_mock_server().await;

    let state_store = Box::new(MemoryStateStore::new());
    let (state_key, _pkce_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    let client =
        make_client_with_stores(&base_url, Box::new(MemorySessionStore::new()), state_store);

    // Call callback with a different issuer.
    let result = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: Some("http://evil-server.example.com".into()),
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::IssuerMismatch { expected, actual } => {
            assert_eq!(expected, base_url);
            assert_eq!(actual, "http://evil-server.example.com");
        }
        other => panic!("expected IssuerMismatch, got: {other:?}"),
    }
}

/// Callback rejects a missing issuer parameter.
#[tokio::test]
async fn callback_rejects_missing_issuer() {
    let (base_url, _mock_state) = start_mock_server().await;

    let state_store = Box::new(MemoryStateStore::new());
    let (state_key, _pkce_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    let client =
        make_client_with_stores(&base_url, Box::new(MemorySessionStore::new()), state_store);

    let result = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: None,
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::MissingIssuer => {} // expected
        other => panic!("expected MissingIssuer, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Security tests
// ---------------------------------------------------------------------------

/// State parameters are one-time use: replaying a state is rejected.
///
/// After a successful callback, the AuthState is deleted from the store.
/// A second callback attempt with the same state must fail with InvalidState.
#[tokio::test]
async fn state_replay_rejected() {
    let (base_url, mock_state) = start_mock_server().await;

    let session_store = Box::new(MemorySessionStore::new());
    let state_store = Box::new(MemoryStateStore::new());

    let (state_key, pkce_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    // Seed PKCE challenge in mock server.
    {
        let mut s = mock_state.lock().await;
        s.pkce_challenges
            .insert("urn:test:request:123".into(), pkce_challenge);
    }

    let client = make_client_with_stores(&base_url, session_store, state_store);

    // First callback succeeds.
    let session = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key.clone(),
            iss: Some(base_url.clone()),
        })
        .await
        .unwrap();
    assert_eq!(session.token_set.sub, "did:plc:test123456789abcdefghij");

    // Second callback with the same state must fail — state was consumed.
    let result = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: Some(base_url),
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::InvalidState => {} // expected: state is one-time use
        other => panic!("expected InvalidState on replay, got: {other:?}"),
    }
}

/// Sending a wrong PKCE verifier is rejected by the token endpoint.
///
/// Seeds an AuthState whose verifier produces challenge X, but the mock
/// token endpoint has a *different* challenge stored. The S256 check fails
/// and the server returns `invalid_grant`.
#[tokio::test]
async fn pkce_verifier_mismatch_rejected() {
    let (base_url, mock_state) = start_mock_server().await;

    let session_store = Box::new(MemorySessionStore::new());
    let state_store = Box::new(MemoryStateStore::new());

    let (state_key, _correct_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    // Seed a *different* PKCE challenge in the mock server so the verifier won't match.
    {
        let mut s = mock_state.lock().await;
        s.pkce_challenges.insert(
            "urn:test:request:123".into(),
            "wrong-challenge-value".into(),
        );
    }

    let client = make_client_with_stores(&base_url, session_store, state_store);

    let result = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: Some(base_url),
        })
        .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        OAuthError::OAuthResponse { code, description } => {
            assert_eq!(code, "invalid_grant");
            assert!(
                description.contains("PKCE"),
                "expected PKCE error, got: {description}"
            );
        }
        other => panic!("expected OAuthResponse with invalid_grant, got: {other:?}"),
    }
}

/// A DPoP proof JWT has the correct structure per RFC 9449.
///
/// Creates a proof directly and decodes the JWT parts to verify:
/// - Header: alg=ES256, typ=dpop+jwt, jwk with kty/crv/x/y
/// - Payload: jti, htm, htu, iat (all present and correct types)
/// - Optional claims: nonce and ath when provided
#[tokio::test]
async fn dpop_proof_has_correct_structure() {
    let key = ratproto_crypto::P256SigningKey::generate();

    // Create a proof with nonce and access token.
    let jwt = ratproto_oauth::dpop::create_dpop_proof(
        &key,
        "POST",
        "https://auth.example.com/oauth/token?foo=bar#frag",
        Some("server-nonce-xyz"),
        Some("my-access-token"),
    )
    .unwrap();

    // Split into three parts.
    let parts: Vec<&str> = jwt.split('.').collect();
    assert_eq!(parts.len(), 3, "JWT must have exactly 3 parts");

    // Decode header.
    let header_bytes = BASE64URL_NOPAD.decode(parts[0].as_bytes()).unwrap();
    let header: serde_json::Value = serde_json::from_slice(&header_bytes).unwrap();

    assert_eq!(header["alg"], "ES256");
    assert_eq!(header["typ"], "dpop+jwt");
    let jwk = &header["jwk"];
    assert_eq!(jwk["kty"], "EC");
    assert_eq!(jwk["crv"], "P-256");
    assert!(jwk["x"].is_string(), "jwk.x must be a string");
    assert!(jwk["y"].is_string(), "jwk.y must be a string");

    // Decode payload.
    let payload_bytes = BASE64URL_NOPAD.decode(parts[1].as_bytes()).unwrap();
    let payload: serde_json::Value = serde_json::from_slice(&payload_bytes).unwrap();

    // Required claims.
    assert!(payload["jti"].is_string(), "jti must be a string");
    assert!(
        !payload["jti"].as_str().unwrap().is_empty(),
        "jti must not be empty"
    );
    assert_eq!(payload["htm"], "POST");
    // htu must have query and fragment stripped.
    assert_eq!(payload["htu"], "https://auth.example.com/oauth/token");
    assert!(payload["iat"].is_u64(), "iat must be a number");

    // Nonce claim.
    assert_eq!(payload["nonce"], "server-nonce-xyz");

    // ath claim: base64url(SHA-256("my-access-token"))
    let expected_hash = Sha256::digest(b"my-access-token");
    let expected_ath = BASE64URL_NOPAD.encode(&expected_hash);
    assert_eq!(payload["ath"], expected_ath);

    // Decode and verify signature length (P-256 produces 64-byte signatures).
    let sig_bytes = BASE64URL_NOPAD.decode(parts[2].as_bytes()).unwrap();
    assert_eq!(sig_bytes.len(), 64, "P-256 signature must be 64 bytes");
}

/// Token exchange handles use_dpop_nonce retry transparently.
///
/// Configures the mock to require a nonce retry on the first token request,
/// then verifies that callback still succeeds after the automatic retry.
#[tokio::test]
async fn callback_handles_dpop_nonce_retry() {
    let initial = MockState {
        require_nonce_retry: true,
        ..Default::default()
    };
    let (base_url, mock_state) = start_mock_server_with_state(initial).await;

    let state_store = Box::new(MemoryStateStore::new());
    let (state_key, pkce_challenge) = seed_auth_state(state_store.as_ref(), &base_url).await;

    // Seed the PKCE challenge.
    {
        let mut s = mock_state.lock().await;
        s.pkce_challenges
            .insert("urn:test:request:123".into(), pkce_challenge);
    }

    let client =
        make_client_with_stores(&base_url, Box::new(MemorySessionStore::new()), state_store);

    // The first token call returns use_dpop_nonce; the library retries and succeeds.
    let session = client
        .callback(CallbackParams {
            code: "test-auth-code".into(),
            state: state_key,
            iss: Some(base_url.clone()),
        })
        .await
        .unwrap();

    assert_eq!(session.token_set.sub, "did:plc:test123456789abcdefghij");
    assert_eq!(session.token_set.access_token, "test-at");

    // Verify the token endpoint was called twice (once failed, once succeeded).
    let s = mock_state.lock().await;
    assert_eq!(s.token_call_count, 2);
}
