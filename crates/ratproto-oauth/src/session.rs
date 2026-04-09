use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tokio::sync::RwLock;

use crate::OAuthError;
use crate::token::TokenSet;

/// Persisted OAuth session, keyed by user DID.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    /// P-256 DPoP private key as base64url of 32-byte scalar.
    pub dpop_key_bytes: String,
    /// Token set.
    pub token_set: TokenSet,
}

impl Session {
    /// Reconstruct the P-256 signing key from the stored base64url bytes.
    pub fn dpop_key(&self) -> Result<ratproto_crypto::P256SigningKey, OAuthError> {
        let bytes = crate::pkce::base64url_decode(&self.dpop_key_bytes)?;
        if bytes.len() != 32 {
            return Err(OAuthError::Crypto("key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        ratproto_crypto::P256SigningKey::from_bytes(&arr)
            .map_err(|e| OAuthError::Crypto(e.to_string()))
    }

    /// Create a session from a signing key and token set.
    pub fn from_key_and_tokens(key: &ratproto_crypto::P256SigningKey, token_set: TokenSet) -> Self {
        Session {
            dpop_key_bytes: crate::pkce::base64url_encode(&key.to_bytes()),
            token_set,
        }
    }
}

/// Authorization state during the OAuth flow, keyed by state parameter.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthState {
    pub issuer: String,
    pub dpop_key_bytes: String,
    pub auth_method: String,
    pub verifier: String,
    pub redirect_uri: String,
    pub app_state: String,
    pub token_endpoint: String,
    pub revocation_endpoint: String,
}

impl AuthState {
    /// Reconstruct the P-256 signing key from the stored base64url bytes.
    pub fn dpop_key(&self) -> Result<ratproto_crypto::P256SigningKey, OAuthError> {
        let bytes = crate::pkce::base64url_decode(&self.dpop_key_bytes)?;
        if bytes.len() != 32 {
            return Err(OAuthError::Crypto("key must be 32 bytes".into()));
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        ratproto_crypto::P256SigningKey::from_bytes(&arr)
            .map_err(|e| OAuthError::Crypto(e.to_string()))
    }
}

/// Persistent storage for OAuth sessions, keyed by user DID.
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, did: &str) -> Result<Option<Session>, OAuthError>;
    async fn set(&self, did: &str, session: &Session) -> Result<(), OAuthError>;
    async fn delete(&self, did: &str) -> Result<(), OAuthError>;
}

/// Persistent storage for authorization state during the OAuth flow,
/// keyed by the `state` parameter.
/// Stores authorization state during the OAuth flow.
///
/// The `take` method atomically retrieves and deletes state to prevent
/// replay attacks from concurrent callback requests.
#[async_trait]
pub trait StateStore: Send + Sync {
    async fn get(&self, state: &str) -> Result<Option<AuthState>, OAuthError>;
    async fn set(&self, state: &str, data: &AuthState) -> Result<(), OAuthError>;
    async fn delete(&self, state: &str) -> Result<(), OAuthError>;
    /// Atomically retrieve and delete state (one-time use).
    /// Returns `None` if the state doesn't exist. A second call with the
    /// same key MUST return `None` even under concurrent access.
    async fn take(&self, state: &str) -> Result<Option<AuthState>, OAuthError>;
}

/// In-memory session store backed by a `RwLock<HashMap>`.
pub struct MemorySessionStore {
    sessions: RwLock<HashMap<String, Session>>,
}

impl MemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    async fn get(&self, did: &str) -> Result<Option<Session>, OAuthError> {
        let guard = self.sessions.read().await;
        Ok(guard.get(did).cloned())
    }

    async fn set(&self, did: &str, session: &Session) -> Result<(), OAuthError> {
        let mut guard = self.sessions.write().await;
        guard.insert(did.to_string(), session.clone());
        Ok(())
    }

    async fn delete(&self, did: &str) -> Result<(), OAuthError> {
        let mut guard = self.sessions.write().await;
        guard.remove(did);
        Ok(())
    }
}

/// In-memory state store backed by a `RwLock<HashMap>`.
pub struct MemoryStateStore {
    states: RwLock<HashMap<String, AuthState>>,
}

impl MemoryStateStore {
    pub fn new() -> Self {
        Self {
            states: RwLock::new(HashMap::new()),
        }
    }
}

impl Default for MemoryStateStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StateStore for MemoryStateStore {
    async fn get(&self, state: &str) -> Result<Option<AuthState>, OAuthError> {
        let guard = self.states.read().await;
        Ok(guard.get(state).cloned())
    }

    async fn set(&self, state: &str, data: &AuthState) -> Result<(), OAuthError> {
        let mut guard = self.states.write().await;
        guard.insert(state.to_string(), data.clone());
        Ok(())
    }

    async fn delete(&self, state: &str) -> Result<(), OAuthError> {
        let mut guard = self.states.write().await;
        guard.remove(state);
        Ok(())
    }

    async fn take(&self, state: &str) -> Result<Option<AuthState>, OAuthError> {
        let mut guard = self.states.write().await;
        Ok(guard.remove(state))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pkce::base64url_encode;

    fn make_token_set() -> TokenSet {
        TokenSet {
            issuer: "https://example.com".into(),
            sub: "did:plc:test".into(),
            aud: "https://example.com".into(),
            scope: "atproto".into(),
            access_token: "access".into(),
            token_type: "DPoP".into(),
            expires_at: Some(4_000_000_000),
            refresh_token: Some("refresh".into()),
            token_endpoint: "https://example.com/oauth/token".into(),
            revocation_endpoint: "https://example.com/oauth/revoke".into(),
        }
    }

    fn make_session() -> Session {
        let key = ratproto_crypto::P256SigningKey::generate();
        Session::from_key_and_tokens(&key, make_token_set())
    }

    fn make_auth_state() -> AuthState {
        let key = ratproto_crypto::P256SigningKey::generate();
        AuthState {
            issuer: "https://example.com".into(),
            dpop_key_bytes: base64url_encode(&key.to_bytes()),
            auth_method: "none".into(),
            verifier: "verifier123".into(),
            redirect_uri: "http://localhost:8080/callback".into(),
            app_state: "app-state-xyz".into(),
            token_endpoint: "https://example.com/oauth/token".into(),
            revocation_endpoint: "https://example.com/oauth/revoke".into(),
        }
    }

    #[tokio::test]
    async fn memory_session_store_crud() {
        let store = MemorySessionStore::new();
        let did = "did:plc:test123";
        let session = make_session();

        // Initially empty
        let result = store.get(did).await;
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());

        // Set
        store.set(did, &session).await.ok();

        // Get returns Some
        let result = store.get(did).await;
        assert!(result.is_ok());
        let retrieved = result.ok().flatten();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap_or_else(make_session);
        assert_eq!(retrieved.dpop_key_bytes, session.dpop_key_bytes);

        // Delete
        store.delete(did).await.ok();

        // Get returns None
        let result = store.get(did).await;
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());
    }

    #[tokio::test]
    async fn memory_state_store_crud() {
        let store = MemoryStateStore::new();
        let state_key = "random-state-abc";
        let auth_state = make_auth_state();

        // Initially empty
        let result = store.get(state_key).await;
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());

        // Set
        store.set(state_key, &auth_state).await.ok();

        // Get returns Some
        let result = store.get(state_key).await;
        assert!(result.is_ok());
        let retrieved = result.ok().flatten();
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap_or_else(make_auth_state);
        assert_eq!(retrieved.issuer, auth_state.issuer);
        assert_eq!(retrieved.dpop_key_bytes, auth_state.dpop_key_bytes);

        // Delete
        store.delete(state_key).await.ok();

        // Get returns None
        let result = store.get(state_key).await;
        assert!(result.is_ok());
        assert!(result.ok().flatten().is_none());
    }

    #[test]
    fn session_key_roundtrip() {
        let key = ratproto_crypto::P256SigningKey::generate();
        let session = Session::from_key_and_tokens(&key, make_token_set());
        let recovered = session.dpop_key();
        assert!(recovered.is_ok());
        let recovered = recovered.unwrap_or_else(|_| ratproto_crypto::P256SigningKey::generate());
        assert_eq!(recovered.to_bytes(), key.to_bytes());
    }

    #[test]
    fn auth_state_key_roundtrip() {
        let key = ratproto_crypto::P256SigningKey::generate();
        let auth_state = AuthState {
            issuer: "https://example.com".into(),
            dpop_key_bytes: base64url_encode(&key.to_bytes()),
            auth_method: "none".into(),
            verifier: "verifier".into(),
            redirect_uri: "http://localhost/cb".into(),
            app_state: "state".into(),
            token_endpoint: "https://example.com/oauth/token".into(),
            revocation_endpoint: "https://example.com/oauth/revoke".into(),
        };
        let recovered = auth_state.dpop_key();
        assert!(recovered.is_ok());
        let recovered = recovered.unwrap_or_else(|_| ratproto_crypto::P256SigningKey::generate());
        assert_eq!(recovered.to_bytes(), key.to_bytes());
    }
}
