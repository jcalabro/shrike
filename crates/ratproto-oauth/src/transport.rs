use std::sync::Arc;

use serde::{Serialize, de::DeserializeOwned};

use crate::OAuthError;
use crate::dpop::{self, NonceStore};
use crate::session::Session;
use crate::token::TokenSet;
use ratproto_crypto::P256SigningKey;

/// HTTP client with DPoP authentication for AT Protocol XRPC calls.
///
/// Adds `Authorization: DPoP {access_token}` and `DPoP: {proof}` headers
/// to every request. Handles `use_dpop_nonce` retry automatically.
pub struct AuthenticatedClient {
    http: reqwest::Client,
    host: String,
    dpop_key: P256SigningKey,
    token_set: tokio::sync::RwLock<TokenSet>,
    nonces: Arc<NonceStore>,
}

impl AuthenticatedClient {
    /// Create from a session. The `host` is the PDS URL (audience).
    pub fn from_session(session: &Session, nonces: Arc<NonceStore>) -> Result<Self, OAuthError> {
        let dpop_key = session.dpop_key()?;
        let host = session.token_set.aud.clone();
        Ok(Self {
            http: reqwest::Client::new(),
            host,
            dpop_key,
            token_set: tokio::sync::RwLock::new(session.token_set.clone()),
            nonces,
        })
    }

    /// Returns the host (PDS URL / audience) this client targets.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// XRPC query (GET request).
    pub async fn query<P: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &P,
    ) -> Result<O, OAuthError> {
        let url = format!("{}/xrpc/{}", self.host, nsid);

        // Hold the read lock only long enough to clone the access token.
        let access_token = {
            let token_set = self.token_set.read().await;
            token_set.access_token.clone()
        };

        // Create DPoP proof with ath (access token hash)
        let nonce = self.nonces.get(&NonceStore::origin_from_url(&url)?);
        let proof = dpop::create_dpop_proof(
            &self.dpop_key,
            "GET",
            &url,
            nonce.as_deref(),
            Some(&access_token),
        )?;

        let resp = self
            .http
            .get(&url)
            .query(params)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof)
            .send()
            .await?;

        // Update nonce from response
        self.update_nonce_from_response(&url, &resp)?;

        // Handle DPoP nonce retry
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            && resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.contains("use_dpop_nonce"))
        {
            return self.query_retry(nsid, params, &url, &access_token).await;
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::Http(format!(
                "XRPC {nsid} returned {status}: {body}"
            )));
        }

        resp.json::<O>()
            .await
            .map_err(|e| OAuthError::Json(e.to_string()))
    }

    /// Retry a query after receiving a `use_dpop_nonce` response.
    async fn query_retry<P: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &P,
        url: &str,
        access_token: &str,
    ) -> Result<O, OAuthError> {
        let nonce = self.nonces.get(&NonceStore::origin_from_url(url)?);
        let proof = dpop::create_dpop_proof(
            &self.dpop_key,
            "GET",
            url,
            nonce.as_deref(),
            Some(access_token),
        )?;

        let resp = self
            .http
            .get(url)
            .query(params)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof)
            .send()
            .await?;

        // Update nonce from retry response
        self.update_nonce_from_response(url, &resp)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::Http(format!(
                "XRPC {nsid} returned {status}: {body}"
            )));
        }

        resp.json::<O>()
            .await
            .map_err(|e| OAuthError::Json(e.to_string()))
    }

    /// XRPC procedure (POST request with JSON body).
    pub async fn procedure<I: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &I,
    ) -> Result<O, OAuthError> {
        let url = format!("{}/xrpc/{}", self.host, nsid);

        // Hold the read lock only long enough to clone the access token.
        let access_token = {
            let token_set = self.token_set.read().await;
            token_set.access_token.clone()
        };

        // Create DPoP proof with ath (access token hash)
        let nonce = self.nonces.get(&NonceStore::origin_from_url(&url)?);
        let proof = dpop::create_dpop_proof(
            &self.dpop_key,
            "POST",
            &url,
            nonce.as_deref(),
            Some(&access_token),
        )?;

        let resp = self
            .http
            .post(&url)
            .json(input)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof)
            .send()
            .await?;

        // Update nonce from response
        self.update_nonce_from_response(&url, &resp)?;

        // Handle DPoP nonce retry
        if resp.status() == reqwest::StatusCode::UNAUTHORIZED
            && resp
                .headers()
                .get("www-authenticate")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|s| s.contains("use_dpop_nonce"))
        {
            return self.procedure_retry(nsid, input, &url, &access_token).await;
        }

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::Http(format!(
                "XRPC {nsid} returned {status}: {body}"
            )));
        }

        resp.json::<O>()
            .await
            .map_err(|e| OAuthError::Json(e.to_string()))
    }

    /// Retry a procedure after receiving a `use_dpop_nonce` response.
    async fn procedure_retry<I: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &I,
        url: &str,
        access_token: &str,
    ) -> Result<O, OAuthError> {
        let nonce = self.nonces.get(&NonceStore::origin_from_url(url)?);
        let proof = dpop::create_dpop_proof(
            &self.dpop_key,
            "POST",
            url,
            nonce.as_deref(),
            Some(access_token),
        )?;

        let resp = self
            .http
            .post(url)
            .json(input)
            .header("Authorization", format!("DPoP {access_token}"))
            .header("DPoP", &proof)
            .send()
            .await?;

        // Update nonce from retry response
        self.update_nonce_from_response(url, &resp)?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(OAuthError::Http(format!(
                "XRPC {nsid} returned {status}: {body}"
            )));
        }

        resp.json::<O>()
            .await
            .map_err(|e| OAuthError::Json(e.to_string()))
    }

    /// Extract and store a `DPoP-Nonce` header from a response.
    fn update_nonce_from_response(
        &self,
        url: &str,
        resp: &reqwest::Response,
    ) -> Result<(), OAuthError> {
        if let Some(new_nonce) = resp.headers().get("dpop-nonce")
            && let Ok(nonce_str) = new_nonce.to_str()
        {
            let origin = NonceStore::origin_from_url(url)?;
            self.nonces.set(&origin, nonce_str.to_owned());
        }
        Ok(())
    }
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
    use crate::pkce::base64url_encode;
    use crate::token::TokenSet;

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
        Session {
            dpop_key_bytes: base64url_encode(&key.to_bytes()),
            token_set: make_token_set(),
        }
    }

    #[test]
    fn authenticated_client_from_session() {
        let session = make_session();
        let nonces = Arc::new(NonceStore::new());
        let client = AuthenticatedClient::from_session(&session, nonces);
        assert!(client.is_ok());
        let client = client.unwrap();
        assert_eq!(client.host(), "https://example.com");
    }

    #[test]
    fn authenticated_client_from_session_preserves_dpop_key() {
        let key = ratproto_crypto::P256SigningKey::generate();
        let session = Session {
            dpop_key_bytes: base64url_encode(&key.to_bytes()),
            token_set: make_token_set(),
        };
        let nonces = Arc::new(NonceStore::new());
        let client = AuthenticatedClient::from_session(&session, nonces).unwrap();
        assert_eq!(client.dpop_key.to_bytes(), key.to_bytes());
    }

    #[test]
    fn authenticated_client_invalid_key_fails() {
        let session = Session {
            dpop_key_bytes: base64url_encode(&[0u8; 16]), // wrong length
            token_set: make_token_set(),
        };
        let nonces = Arc::new(NonceStore::new());
        let result = AuthenticatedClient::from_session(&session, nonces);
        assert!(result.is_err());
    }
}
