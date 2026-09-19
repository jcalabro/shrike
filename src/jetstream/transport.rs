//! The portable HTTP transport abstraction the archive planner and downloader
//! are written against.
//!
//! The archive control and bulk endpoints are plain XRPC over HTTPS, but the two
//! targets that reach them could not be more different: native builds use a
//! Tokio/`reqwest` client whose futures are `Send`, while the browser build uses
//! `fetch`, whose response bodies are not `Send` and whose header/range
//! capabilities are constrained by CORS. To keep one planner and one downloader
//! serving both, this module defines a small trait surface — [`HttpTransport`]
//! and its streaming [`HttpBody`] — using return-position `impl Future` rather
//! than `async fn` in traits or boxed futures. That keeps `Send` *off* the
//! portable core: native usage still gets `Send` for free through auto-trait
//! leakage on `reqwest`'s concrete futures, while the wasm transport is free to
//! be `!Send`.
//!
//! The types here are deliberately transport-agnostic wire primitives: a request
//! is a method, URL, header list, and optional body; a response is a status, a
//! parsed subset of headers relevant to archive downloads, and a streaming body.
//! Interpreting a status or a `Content-Range` is the caller's job (see
//! `download` and `planner`), not the transport's. A [`TransportError`] carries
//! only redacted, bounded text — never the API key or an authorization header —
//! and classifies itself as retryable or not.

use bytes::Bytes;
use core::time::Duration;

use super::error::truncate_on_char_boundary;

/// The maximum length of a transport error message retained from an underlying
/// client. Underlying errors are bounded so an oversized or unexpected message
/// cannot bloat logs or error chains. The API key never appears in these
/// messages by construction (it lives only in a request header).
pub const MAX_TRANSPORT_MESSAGE_LEN: usize = 256;

/// The HTTP method for an archive request. Only the two the archive uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// A `GET`, used by `getSegment`/`getBlock` (and range probes).
    Get,
    /// A `POST`, used by `planSnapshot`.
    Post,
}

impl Method {
    /// The uppercase wire token.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Post => "POST",
        }
    }
}

/// A fully-formed archive request: method, absolute URL, header list, and an
/// optional body. The header list is ordered and may include the authorization
/// header, whose value comes from [`super::key::ApiKey::header_value`] — it is
/// therefore never logged or rendered.
#[derive(Clone)]
pub struct HttpRequest {
    /// The request method.
    pub method: Method,
    /// The absolute request URL. Never contains the API key (auth is a header).
    pub url: String,
    /// Ordered request headers. Static names, owned values.
    pub headers: Vec<(&'static str, String)>,
    /// The optional request body (a `planSnapshot` JSON payload).
    pub body: Option<Bytes>,
}

impl HttpRequest {
    /// Begin a `GET` request to `url`.
    pub fn get(url: impl Into<String>) -> Self {
        HttpRequest {
            method: Method::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Begin a `POST` request to `url`.
    pub fn post(url: impl Into<String>) -> Self {
        HttpRequest {
            method: Method::Post,
            url: url.into(),
            headers: Vec::new(),
            body: None,
        }
    }

    /// Append a header. Chainable.
    pub fn header(mut self, name: &'static str, value: impl Into<String>) -> Self {
        self.headers.push((name, value.into()));
        self
    }

    /// Attach a request body. Chainable.
    pub fn with_body(mut self, body: Bytes) -> Self {
        self.body = Some(body);
        self
    }

    /// Redact the request for logging: method and URL only, never headers (which
    /// may carry the authorization bearer) or body.
    pub fn redacted_summary(&self) -> String {
        format!("{} {}", self.method.as_str(), self.url)
    }
}

/// The subset of response headers the archive planner and downloader interpret,
/// parsed once from a case-insensitive header source. Everything here is derived
/// from server-controlled input, so string fields are bounded and numeric fields
/// are parsed leniently (an unparseable value reads as absent).
#[derive(Debug, Default, Clone)]
pub struct ResponseHeaders {
    /// `Content-Type`, lowercased for prefix matching.
    pub content_type: Option<String>,
    /// `Content-Length`, if a valid non-negative integer.
    pub content_length: Option<u64>,
    /// `Content-Range`, verbatim (parsed by the downloader).
    pub content_range: Option<String>,
    /// `Accept-Ranges`, lowercased (`bytes` signals range support).
    pub accept_ranges: Option<String>,
    /// `ETag`, verbatim including quotes (the archive uses a quoted plan hash).
    pub etag: Option<String>,
    /// `Retry-After` as a delta in seconds, if given as an integer.
    pub retry_after_secs: Option<u64>,
    /// `RateLimit-Reset` as an absolute Unix time in seconds, if an integer.
    pub ratelimit_reset_secs: Option<u64>,
}

/// The largest header string value retained. Bounds an oversized server header.
const MAX_HEADER_VALUE_LEN: usize = 512;

impl ResponseHeaders {
    /// Parse the interpreted subset from case-insensitive `(name, value)` pairs.
    ///
    /// Names are matched case-insensitively (HTTP headers are case-insensitive);
    /// the last occurrence of a header wins. String values are length-bounded;
    /// numeric values that do not parse are treated as absent.
    pub fn from_pairs<I, K, V>(pairs: I) -> Self
    where
        I: IntoIterator<Item = (K, V)>,
        K: AsRef<str>,
        V: AsRef<str>,
    {
        let mut out = ResponseHeaders::default();
        for (name, value) in pairs {
            let name = name.as_ref().to_ascii_lowercase();
            let value = value.as_ref();
            match name.as_str() {
                "content-type" => out.content_type = Some(bound_lower(value)),
                "content-length" => out.content_length = value.trim().parse::<u64>().ok(),
                "content-range" => out.content_range = Some(bound(value)),
                "accept-ranges" => out.accept_ranges = Some(bound_lower(value)),
                "etag" => out.etag = Some(bound(value)),
                "retry-after" => out.retry_after_secs = value.trim().parse::<u64>().ok(),
                "ratelimit-reset" | "x-ratelimit-reset" => {
                    out.ratelimit_reset_secs = value.trim().parse::<u64>().ok();
                }
                _ => {}
            }
        }
        out
    }

    /// Whether the response advertises byte-range support via `Accept-Ranges`.
    pub fn accepts_byte_ranges(&self) -> bool {
        self.accept_ranges
            .as_deref()
            .is_some_and(|v| v.split(',').any(|t| t.trim() == "bytes"))
    }

    /// A retry delay hint derived from rate-limit headers, if any: `Retry-After`
    /// (a delta) takes precedence over `RateLimit-Reset` (an absolute time,
    /// converted against `now_unix_secs`). A reset already in the past yields a
    /// zero delay. Returns `None` when neither header constrains the retry.
    pub fn retry_hint(&self, now_unix_secs: u64) -> Option<Duration> {
        if let Some(secs) = self.retry_after_secs {
            return Some(Duration::from_secs(secs));
        }
        if let Some(reset) = self.ratelimit_reset_secs {
            return Some(Duration::from_secs(reset.saturating_sub(now_unix_secs)));
        }
        None
    }
}

/// Bound a header value to [`MAX_HEADER_VALUE_LEN`] on a char boundary.
fn bound(value: &str) -> String {
    let mut s = value.trim().to_owned();
    truncate_on_char_boundary(&mut s, MAX_HEADER_VALUE_LEN);
    s
}

/// Bound and lowercase a header value (for case-insensitive comparisons).
fn bound_lower(value: &str) -> String {
    let mut s = value.trim().to_ascii_lowercase();
    truncate_on_char_boundary(&mut s, MAX_HEADER_VALUE_LEN);
    s
}

/// A response with a streaming body. The status and headers are available before
/// any body byte is read; the body is consumed incrementally through
/// [`HttpBody`] so a bulk download never buffers more than one chunk at a time
/// beyond what the caller accumulates under its own bound.
pub struct HttpResponse<B> {
    /// The HTTP status code.
    pub status: u16,
    /// The interpreted response headers.
    pub headers: ResponseHeaders,
    /// The streaming response body.
    pub body: B,
}

impl<B> HttpResponse<B> {
    /// Whether the status is in the 2xx success range.
    pub fn is_success(&self) -> bool {
        (200..300).contains(&self.status)
    }
}

/// A streaming response body yielding chunks until exhausted.
///
/// `chunk` returns `Ok(Some(bytes))` for each successive piece, `Ok(None)` at
/// clean end of body, or `Err(_)` on a mid-stream transport failure. The future
/// is intentionally not required to be `Send`, so the wasm `fetch` body (which
/// is `!Send`) satisfies this trait as-is.
pub trait HttpBody {
    /// Read the next body chunk, or `None` at end of stream.
    fn chunk(
        &mut self,
    ) -> impl core::future::Future<Output = Result<Option<Bytes>, TransportError>>;
}

/// A minimal HTTP transport for archive requests.
///
/// The single method sends a fully-formed [`HttpRequest`] and resolves to an
/// [`HttpResponse`] whose body streams. A non-2xx status is *not* an error here —
/// it is returned as a response for the caller to interpret (an XRPC error body,
/// a 429, a 416, and so on). Only genuine transport failures — connect, timeout,
/// a body that breaks mid-stream, a missing browser capability — are `Err`.
pub trait HttpTransport {
    /// The streaming body type this transport produces.
    type Body: HttpBody;

    /// Send a request and resolve to a streaming response, or a transport error.
    fn send(
        &self,
        request: HttpRequest,
    ) -> impl core::future::Future<Output = Result<HttpResponse<Self::Body>, TransportError>>;
}

/// How a transport failure is classified, driving retry and capability handling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportErrorKind {
    /// Could not establish a connection (DNS, TCP, TLS).
    Connect,
    /// The request or a body read timed out.
    Timeout,
    /// The response body broke mid-stream.
    Body,
    /// The caller cancelled the request.
    Canceled,
    /// The target lacks a capability the request required (e.g. a browser
    /// `fetch` that cannot expose a needed header or issue a range request).
    Capability,
    /// Any other transport failure.
    Other,
}

impl TransportErrorKind {
    /// Whether a failure of this kind could plausibly succeed on a bounded retry.
    /// Transient network faults are retryable; cancellation and a missing
    /// capability are not.
    pub fn is_retryable(self) -> bool {
        matches!(
            self,
            TransportErrorKind::Connect | TransportErrorKind::Timeout | TransportErrorKind::Body
        )
    }
}

/// A transport-layer failure with a redacted, bounded message.
///
/// The `message` is guaranteed free of the API key: the secret is only ever a
/// request header value, and adapters construct these messages from
/// error categories and URL-free descriptions — never by rendering headers.
#[derive(Debug, thiserror::Error)]
#[error("{kind:?} transport error: {message}")]
pub struct TransportError {
    kind: TransportErrorKind,
    message: String,
}

impl TransportError {
    /// Construct a transport error, bounding the (already redacted) message.
    pub fn new(kind: TransportErrorKind, message: impl Into<String>) -> Self {
        let mut message = message.into();
        truncate_on_char_boundary(&mut message, MAX_TRANSPORT_MESSAGE_LEN);
        TransportError { kind, message }
    }

    /// A connect failure.
    pub fn connect(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Connect, message)
    }

    /// A timeout.
    pub fn timeout(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Timeout, message)
    }

    /// A mid-stream body failure.
    pub fn body(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Body, message)
    }

    /// A cancellation.
    pub fn canceled(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Canceled, message)
    }

    /// A missing-capability failure.
    pub fn capability(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Capability, message)
    }

    /// Any other failure.
    pub fn other(message: impl Into<String>) -> Self {
        Self::new(TransportErrorKind::Other, message)
    }

    /// The failure classification.
    pub fn kind(&self) -> TransportErrorKind {
        self.kind
    }

    /// The redacted, bounded message.
    pub fn message(&self) -> &str {
        &self.message
    }

    /// Whether a bounded retry could plausibly succeed.
    pub fn is_retryable(&self) -> bool {
        self.kind.is_retryable()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_and_lowercases_known_headers() {
        let h = ResponseHeaders::from_pairs([
            ("Content-Type", "Application/Vnd.Ipld.Car"),
            ("Content-Length", "1024"),
            ("Accept-Ranges", "Bytes"),
            ("ETag", "\"0123456789abcdef\""),
        ]);
        assert_eq!(h.content_type.as_deref(), Some("application/vnd.ipld.car"));
        assert_eq!(h.content_length, Some(1024));
        assert!(h.accepts_byte_ranges());
        assert_eq!(h.etag.as_deref(), Some("\"0123456789abcdef\""));
    }

    #[test]
    fn last_header_occurrence_wins_and_case_insensitive_names() {
        let h = ResponseHeaders::from_pairs([("etag", "\"a\""), ("ETAG", "\"b\"")]);
        assert_eq!(h.etag.as_deref(), Some("\"b\""));
    }

    #[test]
    fn unparseable_numeric_headers_read_as_absent() {
        let h = ResponseHeaders::from_pairs([("Content-Length", "not-a-number")]);
        assert_eq!(h.content_length, None);
    }

    #[test]
    fn retry_hint_prefers_retry_after_then_reset() {
        let h = ResponseHeaders::from_pairs([("Retry-After", "12")]);
        assert_eq!(h.retry_hint(1_000), Some(Duration::from_secs(12)));

        let h = ResponseHeaders::from_pairs([("RateLimit-Reset", "1050")]);
        assert_eq!(h.retry_hint(1_000), Some(Duration::from_secs(50)));

        // A reset already in the past yields zero, not an underflow.
        let h = ResponseHeaders::from_pairs([("RateLimit-Reset", "900")]);
        assert_eq!(h.retry_hint(1_000), Some(Duration::ZERO));

        let h = ResponseHeaders::default();
        assert_eq!(h.retry_hint(1_000), None);
    }

    #[test]
    fn error_kind_retry_classification() {
        assert!(TransportError::connect("x").is_retryable());
        assert!(TransportError::timeout("x").is_retryable());
        assert!(TransportError::body("x").is_retryable());
        assert!(!TransportError::canceled("x").is_retryable());
        assert!(!TransportError::capability("x").is_retryable());
        assert!(!TransportError::other("x").is_retryable());
    }

    #[test]
    fn error_message_is_bounded() {
        let long = "e".repeat(MAX_TRANSPORT_MESSAGE_LEN * 3);
        let err = TransportError::other(long);
        assert!(err.message().len() <= MAX_TRANSPORT_MESSAGE_LEN);
    }

    #[test]
    fn accept_ranges_none_when_not_bytes() {
        let h = ResponseHeaders::from_pairs([("Accept-Ranges", "none")]);
        assert!(!h.accepts_byte_ranges());
    }
}
