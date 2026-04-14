//! OAuth 2.0 client with DPoP and PKCE for AT Protocol authentication.
//!
//! Implements the OAuth 2.0 authorization code flow with Proof of Possession
//! (DPoP) tokens and PKCE for secure authentication. The OAuthClient type
//! manages the full flow from authorization to token refresh.
//!
//! Basic flow:
//! 1. Create an OAuthClient with your client credentials and redirect URI
//! 2. Call authorize to get an authorization URL and state
//! 3. Redirect the user to the authorization URL
//! 4. On callback, call callback with the authorization code and state
//! 5. Use the returned Session to make authenticated requests
//!
//! Sessions can be refreshed with refresh_session when tokens expire.
//! Use MemorySessionStore for development or implement SessionStore for
//! persistent storage.
//!
//! ```ignore
//! use shrike::oauth::{OAuthClient, OAuthClientConfig, AuthorizeOptions};
//! use shrike::oauth::session::{MemorySessionStore, MemoryStateStore};
//! use shrike::oauth::metadata::ClientMetadata;
//!
//! let client = OAuthClient::new(OAuthClientConfig {
//!     metadata: ClientMetadata {
//!         client_id: "https://myapp.example/client-metadata.json".into(),
//!         ..Default::default()
//!     },
//!     session_store: Box::new(MemorySessionStore::new()),
//!     state_store: Box::new(MemoryStateStore::new()),
//!     signing_key: None,
//!     skip_issuer_verification: false,
//! });
//!
//! // Start authorization
//! let result = client.authorize(AuthorizeOptions {
//!     input: "alice.bsky.social".into(),
//!     redirect_uri: "http://localhost:8080/callback".into(),
//!     scope: None,
//!     state: None,
//! }).await?;
//! // Redirect user to result.url
//!
//! // On callback:
//! let session = client.callback(params).await?;
//! // Use session to make authenticated requests
//! ```

pub mod client;
pub mod client_auth;
pub mod dpop;
pub mod jwk;
pub mod metadata;
pub mod pkce;
pub mod session;
pub mod token;
pub mod transport;

pub use client::{
    AuthorizeOptions, AuthorizeResult, CallbackParams, OAuthClient, OAuthClientConfig,
};
pub use client_auth::{ClientAuth, ConfidentialClientAuth, PublicClientAuth};
pub use dpop::NonceStore;
pub use metadata::{AuthServerMetadata, ClientMetadata, ProtectedResourceMetadata};
pub use session::{
    AuthState, MemorySessionStore, MemoryStateStore, Session, SessionStore, StateStore,
};
pub use token::{TokenSet, parse_token_response};
pub use transport::AuthenticatedClient;

/// Errors that can occur during OAuth operations.
#[derive(Debug, thiserror::Error)]
pub enum OAuthError {
    #[error("invalid state parameter")]
    InvalidState,

    #[error("issuer mismatch: expected {expected}, got {actual}")]
    IssuerMismatch { expected: String, actual: String },

    #[error("missing issuer in response")]
    MissingIssuer,

    #[error("issuer verification failed: {0}")]
    IssuerVerification(String),

    #[error("missing required scope")]
    MissingScope,

    #[error("no session for {0}")]
    NoSession(String),

    #[error("token expired")]
    TokenExpired,

    #[error("no refresh token available")]
    NoRefreshToken,

    #[error("OAuth error response: {code} — {description}")]
    OAuthResponse { code: String, description: String },

    #[error("HTTP error: {0}")]
    Http(String),

    #[error("JSON error: {0}")]
    Json(String),

    #[error("crypto error: {0}")]
    Crypto(String),

    #[error("identity error: {0}")]
    Identity(String),

    #[error("invalid metadata: {0}")]
    InvalidMetadata(String),

    #[error("storage error: {0}")]
    Storage(String),
}

impl From<reqwest::Error> for OAuthError {
    fn from(err: reqwest::Error) -> Self {
        OAuthError::Http(err.to_string())
    }
}

impl From<serde_json::Error> for OAuthError {
    fn from(err: serde_json::Error) -> Self {
        OAuthError::Json(err.to_string())
    }
}

impl From<crate::crypto::CryptoError> for OAuthError {
    fn from(err: crate::crypto::CryptoError) -> Self {
        OAuthError::Crypto(err.to_string())
    }
}

impl From<crate::identity::IdentityError> for OAuthError {
    fn from(err: crate::identity::IdentityError) -> Self {
        OAuthError::Identity(err.to_string())
    }
}
