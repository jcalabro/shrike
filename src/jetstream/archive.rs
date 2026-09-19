//! The archive client shared by the planner and the downloader: it bundles a
//! portable [`HttpTransport`] with the normalized target, the redacting
//! [`ApiKey`], the retry policies, and the safety limits, and provides the
//! request-building, body-reading, and status/XRPC-error helpers both use.
//!
//! Two separate retry policies live here on purpose (plan requirement): short
//! control requests (`planSnapshot`) and bulk downloads (`getSegment`,
//! `getBlock`) are retried under their own [`RetryConfig`] so their timing can
//! diverge without touching call sites.
//!
//! # Cleartext key refusal
//!
//! The API key is a bearer secret. Sending it over cleartext `http` would expose
//! it on the wire, so [`ArchiveClient::new`] refuses a non-empty key on an
//! insecure target unless the host is loopback — the only case where cleartext
//! is a legitimate developer/test convenience. A keyless insecure target (public
//! archive, no auth) is allowed; a keyed `https` target is always allowed.

use bytes::Bytes;

use super::cancel::CancelToken;
use super::error::{Error, Result};
use super::key::ApiKey;
use super::retry::RetryConfig;
use super::transport::{HttpBody, HttpRequest, HttpResponse, HttpTransport, TransportError};

/// Safety limits bounding archive work regardless of what a plan or server
/// claims. Every bound is enforced client-side so a hostile or buggy server
/// cannot drive unbounded allocation or an unbounded request count.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The largest whole segment the downloader will assemble, in bytes.
    pub max_segment_bytes: u64,
    /// The largest single `getBlock` frame the downloader will accept, in bytes.
    pub max_block_frame_bytes: u64,
    /// The largest `planSnapshot`/error JSON body accepted, in bytes.
    pub max_control_body_bytes: u64,
    /// The byte size of each range stripe in a ranged whole-segment download.
    pub stripe_bytes: u64,
    /// The maximum number of concurrent in-flight block/stripe downloads.
    pub concurrency: usize,
    /// The maximum number of `planSnapshot` pages before giving up.
    pub max_plan_pages: u32,
    /// The maximum number of segments a single plan may contain.
    pub max_plan_segments: usize,
    /// The maximum number of whole-segment generation restarts before failing.
    pub max_generation_restarts: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            max_segment_bytes: 1 << 30,       // 1 GiB
            max_block_frame_bytes: 64 << 20,  // 64 MiB
            max_control_body_bytes: 16 << 20, // 16 MiB
            stripe_bytes: 8 << 20,            // 8 MiB
            concurrency: 8,
            max_plan_pages: 100_000,
            max_plan_segments: 1_000_000,
            max_generation_restarts: 2,
        }
    }
}

/// Configuration for an [`ArchiveClient`].
pub struct ArchiveConfig {
    /// The normalized target authority (see [`super::normalize_host`]).
    pub host: String,
    /// Whether to reach the target over `https` (true) or `http` (false).
    pub secure: bool,
    /// The archive bearer key. May be empty for an unauthenticated archive.
    pub key: ApiKey,
    /// The retry policy for short control requests.
    pub control_retry: RetryConfig,
    /// The retry policy for bulk downloads.
    pub download_retry: RetryConfig,
    /// Client-side safety limits.
    pub limits: Limits,
}

impl ArchiveConfig {
    /// A config for `host` with default retry policies and limits, reaching the
    /// target over `https`.
    pub fn new(host: impl Into<String>, key: ApiKey) -> Self {
        ArchiveConfig {
            host: host.into(),
            secure: true,
            key,
            control_retry: RetryConfig::control(),
            download_retry: RetryConfig::download(),
            limits: Limits::default(),
        }
    }
}

/// The archive client. Generic over the transport so native and browser builds
/// share one planner and one downloader.
pub struct ArchiveClient<T> {
    pub(crate) transport: T,
    pub(crate) base_url: String,
    pub(crate) key: ApiKey,
    pub(crate) control_retry: RetryConfig,
    pub(crate) download_retry: RetryConfig,
    pub(crate) limits: Limits,
}

impl<T> ArchiveClient<T>
where
    T: HttpTransport,
{
    /// Build a client, validating the target and the cleartext-key rule.
    pub fn new(transport: T, config: ArchiveConfig) -> Result<Self> {
        let ArchiveConfig {
            host,
            secure,
            key,
            control_retry,
            download_retry,
            limits,
        } = config;

        if host.is_empty() {
            return Err(Error::InvalidConfig("archive host is empty"));
        }
        // Never send the bearer key in cleartext except to a loopback dev/test
        // host. A keyless insecure target is allowed (public, unauthenticated).
        if !secure && !key.is_empty() && !is_loopback_host(&host) {
            return Err(Error::InvalidConfig(
                "refusing to send API key over cleartext http to a non-loopback host",
            ));
        }
        let scheme = if secure { "https" } else { "http" };
        let base_url = format!("{scheme}://{host}");

        Ok(ArchiveClient {
            transport,
            base_url,
            key,
            control_retry,
            download_retry,
            limits,
        })
    }

    /// The safety limits in force.
    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Build the XRPC URL for `method` with an already-encoded `query` string
    /// (without the leading `?`), or no query.
    pub(crate) fn xrpc_url(&self, method: &str, query: Option<&str>) -> String {
        match query {
            Some(q) => format!("{}/xrpc/{}?{}", self.base_url, method, q),
            None => format!("{}/xrpc/{}", self.base_url, method),
        }
    }

    /// Add the standard headers (user agent, authorization when a key is set) to
    /// a request. The authorization value comes from the redacting [`ApiKey`], so
    /// it is never logged.
    pub(crate) fn authorized(&self, mut req: HttpRequest) -> HttpRequest {
        req = req.header("user-agent", crate::USER_AGENT);
        if !self.key.is_empty() {
            req = req.header("authorization", self.key.header_value());
        }
        req
    }

    /// Send a request, checking cancellation first. A cancelled send never
    /// touches the network.
    pub(crate) async fn send(
        &self,
        req: HttpRequest,
        cancel: &CancelToken,
    ) -> core::result::Result<HttpResponse<T::Body>, SendError> {
        if cancel.is_cancelled() {
            return Err(SendError::Canceled);
        }
        self.transport.send(req).await.map_err(SendError::Transport)
    }

    /// Perform a short control request (a `planSnapshot` page) under the control
    /// retry policy, returning the success body fully buffered under the control
    /// body limit.
    ///
    /// `make` builds a fresh request per attempt (the authorization and user
    /// agent are added here, so callers never touch the key). Transient failures
    /// — retryable transport faults, `408`/`429`/`5xx` — are retried with
    /// `Retry-After`/`RateLimit-Reset` as a floor; terminal `4xx` bodies become a
    /// structured [`Error::Protocol`]; cancellation short-circuits.
    pub(crate) async fn control_request<F>(&self, cancel: &CancelToken, make: F) -> Result<Vec<u8>>
    where
        F: Fn() -> HttpRequest,
    {
        super::retry::with_retry(&self.control_retry, cancel, |_attempt| {
            let make = &make;
            async move {
                let req = self.authorized(make());
                let resp = match self.send(req, cancel).await {
                    Ok(resp) => resp,
                    Err(SendError::Canceled) => {
                        return super::retry::Attempt::Fatal(Error::Canceled);
                    }
                    Err(SendError::Transport(err)) => {
                        let retryable = err.is_retryable();
                        let err = Error::from(err);
                        return if retryable {
                            super::retry::Attempt::Retry {
                                delay_hint: None,
                                err,
                            }
                        } else {
                            super::retry::Attempt::Fatal(err)
                        };
                    }
                };
                let status = resp.status;
                let hint = resp.headers.retry_hint(now_unix_secs());
                let limit = self.limits.max_control_body_bytes;
                match classify_status(status) {
                    StatusClass::Success => {
                        match read_body_bounded(resp.body, limit, cancel).await {
                            Ok(bytes) => super::retry::Attempt::Ok(bytes),
                            Err(BodyReadError::Canceled) => {
                                super::retry::Attempt::Fatal(Error::Canceled)
                            }
                            Err(BodyReadError::TooLarge) => super::retry::Attempt::Fatal(
                                Error::DownloadFailed("control response body exceeded limit"),
                            ),
                            Err(BodyReadError::Transport(err)) => {
                                let retryable = err.is_retryable();
                                let err = Error::from(err);
                                if retryable {
                                    super::retry::Attempt::Retry {
                                        delay_hint: None,
                                        err,
                                    }
                                } else {
                                    super::retry::Attempt::Fatal(err)
                                }
                            }
                        }
                    }
                    StatusClass::Retryable => {
                        let body = match read_body_bounded(resp.body, limit, cancel).await {
                            Ok(body) => body,
                            Err(BodyReadError::Canceled) => {
                                return super::retry::Attempt::Fatal(Error::Canceled);
                            }
                            Err(_) => Vec::new(),
                        };
                        super::retry::Attempt::Retry {
                            delay_hint: hint,
                            err: parse_xrpc_error(&body, status),
                        }
                    }
                    StatusClass::Terminal => {
                        let body = match read_body_bounded(resp.body, limit, cancel).await {
                            Ok(body) => body,
                            Err(BodyReadError::Canceled) => {
                                return super::retry::Attempt::Fatal(Error::Canceled);
                            }
                            Err(_) => Vec::new(),
                        };
                        super::retry::Attempt::Fatal(parse_xrpc_error(&body, status))
                    }
                }
            }
        })
        .await
    }
}

/// The current Unix time in whole seconds, for converting an absolute
/// `RateLimit-Reset` header into a delay. Best-effort; a zero clock simply makes
/// an absolute reset read as "already elapsed".
pub(crate) fn now_unix_secs() -> u64 {
    crate::platform::unix_time_millis() / 1_000
}

/// Whether `host` (authority, possibly with a port) is a loopback address for
/// which cleartext http is a legitimate developer/test convenience.
pub(crate) fn is_loopback_host(host: &str) -> bool {
    // Strip a trailing :port, taking care with bracketed IPv6 literals.
    let bare = if let Some(rest) = host.strip_prefix('[') {
        // [::1] or [::1]:port -> ::1
        match rest.split_once(']') {
            Some((inner, _)) => inner,
            None => rest,
        }
    } else {
        // host or host:port -> host (a bare IPv6 without brackets has multiple
        // colons and is not a form we accept, so split on the last colon only
        // when there is exactly one).
        match host.rsplit_once(':') {
            Some((h, port)) if port.chars().all(|c| c.is_ascii_digit()) => h,
            _ => host,
        }
    };
    let bare = bare.to_ascii_lowercase();
    // Accept the full 127.0.0.0/8 loopback block, but only as a numeric literal:
    // a string prefix like `127.` would also match a DNS name such as
    // `127.evil.example`, which can resolve to a remote host and would then
    // receive the bearer key over cleartext. Parsing as an IPv4 address rejects
    // any hostname while still accepting every real loopback address.
    let numeric_loopback = bare
        .parse::<std::net::Ipv4Addr>()
        .is_ok_and(|ip| ip.octets()[0] == 127);
    bare == "localhost" || bare == "::1" || numeric_loopback
}

/// The outcome of a low-level send: either a transport failure or a caller
/// cancellation observed before the request left.
pub(crate) enum SendError {
    /// A transport-layer failure.
    Transport(TransportError),
    /// Cancellation observed before sending.
    Canceled,
}

/// How an HTTP status maps onto retry/terminal handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum StatusClass {
    /// 2xx.
    Success,
    /// A status a bounded retry may clear (`408`, `429`, `5xx`).
    Retryable,
    /// A terminal client error (other `4xx`).
    Terminal,
}

/// Classify an HTTP status for archive requests.
pub(crate) fn classify_status(status: u16) -> StatusClass {
    match status {
        200..=299 => StatusClass::Success,
        408 | 429 => StatusClass::Retryable,
        500..=599 => StatusClass::Retryable,
        _ => StatusClass::Terminal,
    }
}

/// A minimal XRPC error envelope, for turning a terminal `4xx` body into a
/// structured [`Error::Protocol`].
#[derive(serde::Deserialize)]
struct XrpcError {
    error: Option<String>,
    message: Option<String>,
}

/// Parse an XRPC error body into an [`Error::Protocol`], falling back to a
/// generic download error when the body is not a recognizable envelope. The
/// server-supplied name and message are bounded by [`Error::protocol`].
pub(crate) fn parse_xrpc_error(body: &[u8], status: u16) -> Error {
    match serde_json::from_slice::<XrpcError>(body) {
        Ok(env) => {
            let name = env.error.unwrap_or_else(|| format!("HTTP {status}"));
            Error::protocol(name, env.message)
        }
        Err(_) => Error::protocol(format!("HTTP {status}"), None::<String>),
    }
}

/// A bounded body-read failure.
pub(crate) enum BodyReadError {
    /// A transport failure mid-body.
    Transport(TransportError),
    /// The body exceeded the supplied cap.
    TooLarge,
    /// Cancellation observed mid-body.
    Canceled,
}

/// Read a streaming body fully into memory, refusing to exceed `limit` bytes and
/// checking `cancel` between chunks. Bounds memory against an oversized or
/// unterminated body.
pub(crate) async fn read_body_bounded<B: HttpBody>(
    mut body: B,
    limit: u64,
    cancel: &CancelToken,
) -> core::result::Result<Vec<u8>, BodyReadError> {
    let mut out: Vec<u8> = Vec::new();
    loop {
        if cancel.is_cancelled() {
            return Err(BodyReadError::Canceled);
        }
        match body.chunk().await {
            Ok(Some(chunk)) => {
                let next = out.len() as u64 + chunk.len() as u64;
                if next > limit {
                    return Err(BodyReadError::TooLarge);
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(out),
            Err(err) => return Err(BodyReadError::Transport(err)),
        }
    }
}

/// Read exactly `expected` bytes from a body (a range stripe), enforcing the
/// exact length: a short body is a truncation, an over-long body is corruption.
pub(crate) async fn read_body_exact<B: HttpBody>(
    mut body: B,
    expected: u64,
    cancel: &CancelToken,
) -> core::result::Result<Vec<u8>, BodyReadError> {
    let mut out: Vec<u8> = Vec::with_capacity(expected.min(1 << 20) as usize);
    loop {
        if cancel.is_cancelled() {
            return Err(BodyReadError::Canceled);
        }
        match body.chunk().await {
            Ok(Some(chunk)) => {
                let next = out.len() as u64 + chunk.len() as u64;
                if next > expected {
                    return Err(BodyReadError::TooLarge);
                }
                out.extend_from_slice(&chunk);
            }
            Ok(None) => return Ok(out),
            Err(err) => return Err(BodyReadError::Transport(err)),
        }
    }
}

/// Build a JSON request body as [`Bytes`].
pub(crate) fn json_body<S: serde::Serialize>(value: &S) -> Result<Bytes> {
    let vec = serde_json::to_vec(value)
        .map_err(|_| Error::InvalidConfig("failed to serialize request body"))?;
    Ok(Bytes::from(vec))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn loopback_detection() {
        assert!(is_loopback_host("localhost"));
        assert!(is_loopback_host("localhost:3000"));
        assert!(is_loopback_host("127.0.0.1"));
        assert!(is_loopback_host("127.0.0.1:8080"));
        assert!(is_loopback_host("127.5.6.7"));
        assert!(is_loopback_host("[::1]"));
        assert!(is_loopback_host("[::1]:3000"));
        assert!(!is_loopback_host("jetstream.us-east.bsky.network"));
        assert!(!is_loopback_host("example.com:443"));
        assert!(!is_loopback_host("10.0.0.1"));
        // Regression: a DNS name that merely begins with "127." is not loopback;
        // only a numeric address in 127.0.0.0/8 is. Otherwise an attacker-named
        // host could receive the bearer key over cleartext.
        assert!(!is_loopback_host("127.evil.example"));
        assert!(!is_loopback_host("127.0.0.1.evil.example"));
        assert!(!is_loopback_host("127x0"));
        assert!(is_loopback_host("127.255.255.254"));
    }

    #[test]
    fn status_classification() {
        assert_eq!(classify_status(200), StatusClass::Success);
        assert_eq!(classify_status(206), StatusClass::Success);
        assert_eq!(classify_status(429), StatusClass::Retryable);
        assert_eq!(classify_status(503), StatusClass::Retryable);
        assert_eq!(classify_status(408), StatusClass::Retryable);
        assert_eq!(classify_status(400), StatusClass::Terminal);
        assert_eq!(classify_status(404), StatusClass::Terminal);
        assert_eq!(classify_status(416), StatusClass::Terminal);
    }

    #[test]
    fn xrpc_error_parsing() {
        let body = br#"{"error":"CursorTooOld","message":"too far back"}"#;
        match parse_xrpc_error(body, 400) {
            Error::Protocol { name, message } => {
                assert_eq!(name, "CursorTooOld");
                assert_eq!(message.as_deref(), Some("too far back"));
            }
            other => panic!("expected protocol error, got {other:?}"),
        }
        // A non-JSON body falls back to an HTTP-status name.
        match parse_xrpc_error(b"<html>", 404) {
            Error::Protocol { name, .. } => assert_eq!(name, "HTTP 404"),
            other => panic!("expected protocol error, got {other:?}"),
        }
    }
}
