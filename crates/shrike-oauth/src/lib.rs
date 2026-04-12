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

impl From<shrike_crypto::CryptoError> for OAuthError {
    fn from(err: shrike_crypto::CryptoError) -> Self {
        OAuthError::Crypto(err.to_string())
    }
}

impl From<shrike_identity::IdentityError> for OAuthError {
    fn from(err: shrike_identity::IdentityError) -> Self {
        OAuthError::Identity(err.to_string())
    }
}
