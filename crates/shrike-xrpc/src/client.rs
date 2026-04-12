use serde::Deserialize;
use serde::{Serialize, de::DeserializeOwned};
use tokio::sync::RwLock;

use crate::auth::AuthInfo;
use crate::error::Error;
use crate::retry::RetryPolicy;

const MAX_RESPONSE_BODY: u64 = 5 << 20; // 5 MB for JSON
const MAX_RAW_RESPONSE_BODY: u64 = 512 << 20; // 512 MB for binary

#[derive(Deserialize)]
struct XrpcErrorBody {
    error: String,
    #[serde(default)]
    message: String,
}

/// XRPC HTTP client for AT Protocol PDS/relay communication.
pub struct Client {
    http: reqwest::Client,
    host: String,
    auth: RwLock<Option<AuthInfo>>,
    retry: RetryPolicy,
}

impl Client {
    pub fn new(host: &str) -> Self {
        Client {
            http: reqwest::Client::new(),
            host: host.to_owned(),
            auth: RwLock::new(None),
            retry: RetryPolicy::default(),
        }
    }

    pub fn with_auth(host: &str, auth: AuthInfo) -> Self {
        Client {
            http: reqwest::Client::new(),
            host: host.to_owned(),
            auth: RwLock::new(Some(auth)),
            retry: RetryPolicy::default(),
        }
    }

    pub fn with_retry(host: &str, retry: RetryPolicy) -> Self {
        Client {
            http: reqwest::Client::new(),
            host: host.to_owned(),
            auth: RwLock::new(None),
            retry,
        }
    }

    fn xrpc_url(&self, nsid: &str) -> String {
        format!("{}/xrpc/{}", self.host, nsid)
    }

    async fn bearer(&self) -> Option<String> {
        let guard = self.auth.read().await;
        guard.as_ref().map(|a| a.access_jwt.clone())
    }

    async fn refresh_bearer(&self) -> Option<String> {
        let guard = self.auth.read().await;
        guard.as_ref().map(|a| a.refresh_jwt.clone())
    }

    fn apply_auth(
        &self,
        rb: reqwest::RequestBuilder,
        token: Option<&str>,
    ) -> reqwest::RequestBuilder {
        if let Some(t) = token {
            rb.header("Authorization", format!("Bearer {t}"))
        } else {
            rb
        }
    }

    async fn check_response_size(resp: &reqwest::Response, limit: u64) -> Result<(), Error> {
        if let Some(len) = resp.content_length()
            && len > limit
        {
            return Err(Error::ResponseTooLarge { size: len, limit });
        }
        Ok(())
    }

    fn parse_retry_after(resp: &reqwest::Response) -> Option<std::time::Duration> {
        resp.headers()
            .get("retry-after")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .map(std::time::Duration::from_secs)
    }

    async fn parse_error_response(resp: reqwest::Response) -> Error {
        let status = resp.status().as_u16();

        if status == 429 {
            let retry_after = Self::parse_retry_after(&resp);
            return Error::RateLimited { retry_after };
        }

        match resp.text().await {
            Ok(body) => {
                if let Ok(err_body) = serde_json::from_str::<XrpcErrorBody>(&body) {
                    Error::Xrpc {
                        status,
                        error: err_body.error,
                        message: err_body.message,
                    }
                } else {
                    Error::Xrpc {
                        status,
                        error: String::from("Unknown"),
                        message: body,
                    }
                }
            }
            Err(e) => Error::Network(e),
        }
    }

    fn is_retryable(status: u16) -> bool {
        status >= 500 || status == 429
    }

    /// GET /xrpc/{nsid}?{params}
    pub async fn query<P: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        params: &P,
    ) -> Result<O, Error> {
        let url = self.xrpc_url(nsid);
        let bearer = self.bearer().await;
        let max_retries = self.retry.max_retries;

        let mut last_err: Option<Error> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.retry.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let rb = self.http.get(&url).query(params);
            let rb = self.apply_auth(rb, bearer.as_deref());

            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(Error::Network(e));
                    continue;
                }
            };

            let status = resp.status();

            if status.is_success() {
                Self::check_response_size(&resp, MAX_RESPONSE_BODY).await?;
                return resp.json::<O>().await.map_err(Error::Network);
            }

            let status_u16 = status.as_u16();
            if Self::is_retryable(status_u16) && attempt < max_retries {
                let retry_after = Self::parse_retry_after(&resp);
                last_err = Some(Error::RateLimited { retry_after });
                continue;
            }

            return Err(Self::parse_error_response(resp).await);
        }

        Err(last_err.unwrap_or_else(|| Error::Xrpc {
            status: 0,
            error: String::from("Unknown"),
            message: String::from("max retries exceeded"),
        }))
    }

    /// POST /xrpc/{nsid} with JSON body
    pub async fn procedure<I: Serialize, O: DeserializeOwned>(
        &self,
        nsid: &str,
        input: &I,
    ) -> Result<O, Error> {
        let url = self.xrpc_url(nsid);
        let bearer = self.bearer().await;
        let body = serde_json::to_vec(input)?;
        let max_retries = self.retry.max_retries;

        let mut last_err: Option<Error> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.retry.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let rb = self
                .http
                .post(&url)
                .header("Content-Type", "application/json")
                .body(body.clone());
            let rb = self.apply_auth(rb, bearer.as_deref());

            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(Error::Network(e));
                    continue;
                }
            };

            let status = resp.status();

            if status.is_success() {
                Self::check_response_size(&resp, MAX_RESPONSE_BODY).await?;
                return resp.json::<O>().await.map_err(Error::Network);
            }

            let status_u16 = status.as_u16();
            if Self::is_retryable(status_u16) && attempt < max_retries {
                let retry_after = Self::parse_retry_after(&resp);
                last_err = Some(Error::RateLimited { retry_after });
                continue;
            }

            return Err(Self::parse_error_response(resp).await);
        }

        Err(last_err.unwrap_or_else(|| Error::Xrpc {
            status: 0,
            error: String::from("Unknown"),
            message: String::from("max retries exceeded"),
        }))
    }

    /// GET with raw binary response
    pub async fn query_raw(&self, nsid: &str, params: &impl Serialize) -> Result<Vec<u8>, Error> {
        let url = self.xrpc_url(nsid);
        let bearer = self.bearer().await;
        let max_retries = self.retry.max_retries;

        let mut last_err: Option<Error> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.retry.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let rb = self.http.get(&url).query(params);
            let rb = self.apply_auth(rb, bearer.as_deref());

            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(Error::Network(e));
                    continue;
                }
            };

            let status = resp.status();

            if status.is_success() {
                if let Some(len) = resp.content_length()
                    && len > MAX_RAW_RESPONSE_BODY
                {
                    return Err(Error::ResponseTooLarge {
                        size: len,
                        limit: MAX_RAW_RESPONSE_BODY,
                    });
                }
                return resp
                    .bytes()
                    .await
                    .map(|b| b.to_vec())
                    .map_err(Error::Network);
            }

            let status_u16 = status.as_u16();
            if Self::is_retryable(status_u16) && attempt < max_retries {
                let retry_after = Self::parse_retry_after(&resp);
                last_err = Some(Error::RateLimited { retry_after });
                continue;
            }

            return Err(Self::parse_error_response(resp).await);
        }

        Err(last_err.unwrap_or_else(|| Error::Xrpc {
            status: 0,
            error: String::from("Unknown"),
            message: String::from("max retries exceeded"),
        }))
    }

    /// POST with raw binary body
    pub async fn procedure_raw(
        &self,
        nsid: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<serde_json::Value, Error> {
        let url = self.xrpc_url(nsid);
        let bearer = self.bearer().await;
        let max_retries = self.retry.max_retries;

        let mut last_err: Option<Error> = None;
        for attempt in 0..=max_retries {
            if attempt > 0 {
                let delay = self.retry.delay_for_attempt(attempt - 1);
                tokio::time::sleep(delay).await;
            }

            let rb = self
                .http
                .post(&url)
                .header("Content-Type", content_type)
                .body(body.clone());
            let rb = self.apply_auth(rb, bearer.as_deref());

            let resp = match rb.send().await {
                Ok(r) => r,
                Err(e) => {
                    last_err = Some(Error::Network(e));
                    continue;
                }
            };

            let status = resp.status();

            if status.is_success() {
                Self::check_response_size(&resp, MAX_RESPONSE_BODY).await?;
                return resp
                    .json::<serde_json::Value>()
                    .await
                    .map_err(Error::Network);
            }

            let status_u16 = status.as_u16();
            if Self::is_retryable(status_u16) && attempt < max_retries {
                let retry_after = Self::parse_retry_after(&resp);
                last_err = Some(Error::RateLimited { retry_after });
                continue;
            }

            return Err(Self::parse_error_response(resp).await);
        }

        Err(last_err.unwrap_or_else(|| Error::Xrpc {
            status: 0,
            error: String::from("Unknown"),
            message: String::from("max retries exceeded"),
        }))
    }

    /// Create a session (login)
    pub async fn create_session(
        &self,
        identifier: &str,
        password: &str,
    ) -> Result<AuthInfo, Error> {
        let url = self.xrpc_url("com.atproto.server.createSession");
        let body = serde_json::json!({
            "identifier": identifier,
            "password": password,
        });
        let body_bytes = serde_json::to_vec(&body)?;

        let resp = self
            .http
            .post(&url)
            .header("Content-Type", "application/json")
            .body(body_bytes)
            .send()
            .await?;

        let status = resp.status();
        if status.is_success() {
            let auth: AuthInfo = resp.json().await.map_err(Error::Network)?;
            let mut guard = self.auth.write().await;
            *guard = Some(auth.clone());
            return Ok(auth);
        }

        Err(Self::parse_error_response(resp).await)
    }

    /// Refresh the current session
    pub async fn refresh_session(&self) -> Result<AuthInfo, Error> {
        let url = self.xrpc_url("com.atproto.server.refreshSession");
        let refresh_jwt = self.refresh_bearer().await;

        let rb = self.http.post(&url);
        let rb = self.apply_auth(rb, refresh_jwt.as_deref());

        let resp = rb.send().await?;

        let status = resp.status();
        if status.is_success() {
            let auth: AuthInfo = resp.json().await.map_err(Error::Network)?;
            let mut guard = self.auth.write().await;
            *guard = Some(auth.clone());
            return Ok(auth);
        }

        Err(Self::parse_error_response(resp).await)
    }

    /// Delete the current session (logout)
    pub async fn delete_session(&self) -> Result<(), Error> {
        let url = self.xrpc_url("com.atproto.server.deleteSession");
        let refresh_jwt = self.refresh_bearer().await;

        let rb = self.http.post(&url);
        let rb = self.apply_auth(rb, refresh_jwt.as_deref());

        let resp = rb.send().await?;

        let status = resp.status();
        if status.is_success() {
            let mut guard = self.auth.write().await;
            *guard = None;
            return Ok(());
        }

        Err(Self::parse_error_response(resp).await)
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
    use axum::{
        Json, Router,
        extract::Query,
        http::StatusCode,
        routing::{get, post},
    };
    use serde::Deserialize;
    use serde_json::json;
    use std::collections::HashMap;
    use tokio::net::TcpListener;

    async fn start_mock() -> String {
        let app =
            Router::new()
                .route(
                    "/xrpc/com.example.ping",
                    get(|| async { Json(json!({"message": "pong"})) }),
                )
                .route(
                    "/xrpc/com.example.echo",
                    post(|Json(body): Json<serde_json::Value>| async move {
                        Json(json!({"echoed": body}))
                    }),
                )
                .route(
                    "/xrpc/com.example.fail",
                    get(|| async {
                        (
                            StatusCode::BAD_REQUEST,
                            Json(json!({"error": "InvalidRequest", "message": "bad"})),
                        )
                    }),
                )
                .route(
                    "/xrpc/com.example.ratelimit",
                    get(|| async {
                        (
                            StatusCode::TOO_MANY_REQUESTS,
                            [("retry-after", "5")],
                            Json(json!({"error": "RateLimited", "message": "slow down"})),
                        )
                    }),
                )
                .route(
                    "/xrpc/com.example.servererror",
                    get(|| async {
                        (
                            StatusCode::INTERNAL_SERVER_ERROR,
                            Json(json!({"error": "InternalError", "message": "boom"})),
                        )
                    }),
                )
                .route(
                    "/xrpc/com.example.authcheck",
                    get(|headers: axum::http::HeaderMap| async move {
                        let auth = headers
                            .get("authorization")
                            .and_then(|v| v.to_str().ok())
                            .unwrap_or("")
                            .to_owned();
                        Json(json!({"authorization": auth}))
                    }),
                )
                .route(
                    "/xrpc/com.example.largeresponse",
                    get(|| async {
                        // Return 1 MB of JSON data
                        let data: Vec<String> =
                            (0..10_000).map(|i| format!("item-{i:06}")).collect();
                        Json(json!({"items": data}))
                    }),
                )
                .route(
                    "/xrpc/com.example.queryparams",
                    get(|Query(params): Query<HashMap<String, String>>| async move {
                        Json(json!({"received": params}))
                    }),
                )
                .route(
                    "/xrpc/com.atproto.server.createSession",
                    post(|| async {
                        Json(json!({
                            "accessJwt": "test-access",
                            "refreshJwt": "test-refresh",
                            "handle": "alice.test",
                            "did": "did:plc:test123456789abcdefghij"
                        }))
                    }),
                );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        format!("http://{addr}")
    }

    #[tokio::test]
    async fn query_returns_json() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let result: serde_json::Value = client.query("com.example.ping", &json!({})).await.unwrap();
        assert_eq!(result["message"], "pong");
    }

    #[tokio::test]
    async fn procedure_posts_json() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let result: serde_json::Value = client
            .procedure("com.example.echo", &json!({"text": "hi"}))
            .await
            .unwrap();
        assert_eq!(result["echoed"]["text"], "hi");
    }

    #[tokio::test]
    async fn xrpc_error_parsed() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let err = client
            .query::<_, serde_json::Value>("com.example.fail", &json!({}))
            .await
            .unwrap_err();
        match err {
            Error::Xrpc { status, error, .. } => {
                assert_eq!(status, 400);
                assert_eq!(error, "InvalidRequest");
            }
            other => panic!("expected Xrpc error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn create_session() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let auth = client
            .create_session("alice.test", "password")
            .await
            .unwrap();
        assert_eq!(auth.access_jwt, "test-access");
        assert_eq!(auth.did.as_str(), "did:plc:test123456789abcdefghij");
    }

    // --- RetryPolicy tests ---

    #[test]
    fn retry_policy_delay_for_attempt_zero() {
        let policy = RetryPolicy::default();
        assert_eq!(
            policy.delay_for_attempt(0),
            std::time::Duration::from_millis(500)
        );
    }

    #[test]
    fn retry_policy_delay_doubles_each_attempt() {
        let policy = RetryPolicy::default();
        assert_eq!(
            policy.delay_for_attempt(0),
            std::time::Duration::from_millis(500)
        );
        assert_eq!(
            policy.delay_for_attempt(1),
            std::time::Duration::from_millis(1000)
        );
        assert_eq!(
            policy.delay_for_attempt(2),
            std::time::Duration::from_millis(2000)
        );
    }

    #[test]
    fn retry_policy_max_delay_cap() {
        let policy = RetryPolicy {
            max_retries: 10,
            base_delay: std::time::Duration::from_millis(500),
            max_delay: std::time::Duration::from_secs(30),
        };
        // attempt 10 would be 500ms * 2^10 = 512_000ms without cap
        let delay = policy.delay_for_attempt(10);
        assert_eq!(delay, std::time::Duration::from_secs(30));
    }

    #[test]
    fn retry_policy_default_values() {
        let policy = RetryPolicy::default();
        assert_eq!(policy.max_retries, 3);
        assert_eq!(policy.base_delay, std::time::Duration::from_millis(500));
        assert_eq!(policy.max_delay, std::time::Duration::from_secs(30));
    }

    // --- Client construction tests ---

    #[test]
    fn client_new_has_no_auth() {
        // Client::new should construct successfully with no auth.
        let client = Client::new("https://bsky.social");
        let _ = client;
    }

    #[tokio::test]
    async fn client_with_auth_stores_token() {
        use crate::auth::AuthInfo;
        use shrike_syntax::{Did, Handle};

        let auth = AuthInfo {
            access_jwt: "my-access-token".to_owned(),
            refresh_jwt: "my-refresh-token".to_owned(),
            handle: Handle::try_from("alice.test").unwrap(),
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
        };
        let client = Client::with_auth("https://bsky.social", auth);
        // bearer() reads the stored auth
        let bearer = client.bearer().await;
        assert_eq!(bearer.as_deref(), Some("my-access-token"));
        let refresh = client.refresh_bearer().await;
        assert_eq!(refresh.as_deref(), Some("my-refresh-token"));
    }

    // --- Error handling tests ---

    #[tokio::test]
    async fn rate_limit_429_returns_rate_limited_error() {
        let url = start_mock().await;
        // Disable retries so the 429 is returned immediately.
        let client = Client::with_retry(
            &url,
            RetryPolicy {
                max_retries: 0,
                base_delay: std::time::Duration::from_millis(1),
                max_delay: std::time::Duration::from_millis(1),
            },
        );
        let err = client
            .query::<_, serde_json::Value>("com.example.ratelimit", &json!({}))
            .await
            .unwrap_err();
        match err {
            Error::RateLimited { retry_after } => {
                assert_eq!(retry_after, Some(std::time::Duration::from_secs(5)));
            }
            other => panic!("expected RateLimited, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn server_error_500_returns_xrpc_error() {
        let url = start_mock().await;
        let client = Client::with_retry(
            &url,
            RetryPolicy {
                max_retries: 0,
                base_delay: std::time::Duration::from_millis(1),
                max_delay: std::time::Duration::from_millis(1),
            },
        );
        let err = client
            .query::<_, serde_json::Value>("com.example.servererror", &json!({}))
            .await
            .unwrap_err();
        match err {
            Error::Xrpc { status, error, .. } => {
                assert_eq!(status, 500);
                assert_eq!(error, "InternalError");
            }
            other => panic!("expected Xrpc error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn network_timeout_returns_network_error() {
        // Connect to a port that is not listening — reqwest will get a connection refused.
        // Use zero retries to avoid 3.5s of exponential backoff in tests.
        let client = Client::with_retry(
            "http://127.0.0.1:1",
            RetryPolicy {
                max_retries: 0,
                ..RetryPolicy::default()
            },
        );
        let err = client
            .query::<_, serde_json::Value>("com.example.ping", &json!({}))
            .await
            .unwrap_err();
        assert!(
            matches!(err, Error::Network(_)),
            "expected Network error, got {err:?}"
        );
    }

    // --- Auth header tests ---

    #[tokio::test]
    async fn bearer_token_sent_when_auth_set() {
        use crate::auth::AuthInfo;
        use shrike_syntax::{Did, Handle};

        let url = start_mock().await;
        let auth = AuthInfo {
            access_jwt: "super-secret-token".to_owned(),
            refresh_jwt: "refresh".to_owned(),
            handle: Handle::try_from("alice.test").unwrap(),
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
        };
        let client = Client::with_auth(&url, auth);
        let result: serde_json::Value = client
            .query("com.example.authcheck", &json!({}))
            .await
            .unwrap();
        assert_eq!(result["authorization"], "Bearer super-secret-token");
    }

    #[tokio::test]
    async fn no_auth_header_when_no_auth_set() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let result: serde_json::Value = client
            .query("com.example.authcheck", &json!({}))
            .await
            .unwrap();
        // No Authorization header should be sent, so the server sees an empty string.
        assert_eq!(result["authorization"], "");
    }

    // --- Response size tests ---

    #[tokio::test]
    async fn query_raw_large_response_succeeds() {
        let url = start_mock().await;
        let client = Client::new(&url);
        // query_raw returns bytes; 1 MB of JSON should succeed (well under 512 MB limit).
        let bytes = client
            .query_raw("com.example.largeresponse", &json!({}))
            .await
            .unwrap();
        assert!(!bytes.is_empty());
        // Must be valid JSON containing items.
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        assert!(parsed["items"].is_array());
        assert_eq!(parsed["items"].as_array().unwrap().len(), 10_000);
    }

    #[test]
    fn response_too_large_error_carries_size_and_limit() {
        let err = Error::ResponseTooLarge {
            size: 600,
            limit: 512,
        };
        let msg = err.to_string();
        assert!(msg.contains("600"));
        assert!(msg.contains("512"));
    }

    // --- Query params test ---

    #[derive(serde::Serialize, Deserialize)]
    struct MultiParams {
        alpha: String,
        beta: u32,
    }

    #[tokio::test]
    async fn query_with_multiple_params() {
        let url = start_mock().await;
        let client = Client::new(&url);
        let params = MultiParams {
            alpha: "hello".to_owned(),
            beta: 42,
        };
        let result: serde_json::Value = client
            .query("com.example.queryparams", &params)
            .await
            .unwrap();
        assert_eq!(result["received"]["alpha"], "hello");
        assert_eq!(result["received"]["beta"], "42");
    }
}
