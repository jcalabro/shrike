//! The native archive HTTP transport, backed by [`reqwest`].
//!
//! This adapter is the built-in [`HttpTransport`] for native Tokio targets. It
//! is deliberately thin: it maps the portable [`HttpRequest`] onto a `reqwest`
//! request, exposes the streaming response body through [`HttpBody`], and
//! classifies `reqwest`'s errors into the portable [`TransportError`] kinds the
//! planner and downloader already understand. All policy — retries, status
//! interpretation, range logic, integrity — lives in the portable core; the
//! transport only moves bytes.
//!
//! Two properties matter for the rest of the client:
//!
//! - **Redirects are disabled.** The archive endpoints are exact and
//!   authenticated; silently following a redirect could replay the bearer key to
//!   an unintended host. A 3xx is surfaced to the caller as an ordinary response
//!   instead.
//! - **Errors are redacted.** `reqwest`'s own error text can embed the request
//!   URL; the mapping here reports only a fixed category string per error kind,
//!   so neither the URL nor (by construction — the key is only ever a header
//!   value) the API key can leak into a message, log, or error chain.
//!
//! The streaming body is boxed as `Send`, so a stream built from `Send` inputs
//! stays `Send` on native, matching the plan's target-transport contract.

use core::pin::Pin;

use bytes::Bytes;
use futures::{Stream, StreamExt};

use super::transport::{
    HttpBody, HttpRequest, HttpResponse, HttpTransport, Method, ResponseHeaders, TransportError,
};

/// A native archive HTTP transport backed by a shared [`reqwest::Client`].
pub struct NativeHttpTransport {
    client: reqwest::Client,
}

impl NativeHttpTransport {
    /// Build a transport with a fresh client configured for archive use:
    /// redirects disabled so the bearer key is never replayed across hosts.
    pub fn new() -> Result<Self, TransportError> {
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| TransportError::other("failed to build the HTTP client"))?;
        Ok(NativeHttpTransport { client })
    }

    /// Build a transport over a caller-supplied client. The caller is
    /// responsible for keeping redirects disabled if it shares this concern.
    pub fn with_client(client: reqwest::Client) -> Self {
        NativeHttpTransport { client }
    }
}

impl HttpTransport for NativeHttpTransport {
    type Body = NativeBody;

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse<Self::Body>, TransportError> {
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
        };
        let mut builder = self.client.request(method, &request.url);
        for (name, value) in &request.headers {
            builder = builder.header(*name, value);
        }
        if let Some(body) = request.body {
            builder = builder.body(body);
        }

        let resp = builder.send().await.map_err(map_reqwest_error)?;
        let status = resp.status().as_u16();
        // Parse the interpreted header subset; skip values that are not valid
        // header text rather than failing the whole response.
        let headers = ResponseHeaders::from_pairs(
            resp.headers()
                .iter()
                .filter_map(|(name, value)| value.to_str().ok().map(|v| (name.as_str(), v))),
        );
        let body = NativeBody {
            stream: Box::pin(resp.bytes_stream()),
        };
        Ok(HttpResponse {
            status,
            headers,
            body,
        })
    }
}

/// The streaming body of a native response: a boxed `reqwest` byte stream.
pub struct NativeBody {
    stream: Pin<Box<dyn Stream<Item = reqwest::Result<Bytes>> + Send>>,
}

impl HttpBody for NativeBody {
    async fn chunk(&mut self) -> Result<Option<Bytes>, TransportError> {
        match self.stream.next().await {
            Some(Ok(bytes)) => Ok(Some(bytes)),
            Some(Err(err)) => Err(map_reqwest_error(err)),
            None => Ok(None),
        }
    }
}

/// Map a `reqwest` error onto a portable, redacted [`TransportError`].
///
/// The message is a fixed per-kind string, never the error's own `Display`
/// (which can embed the request URL), so nothing host- or request-specific — and
/// in particular never the bearer key — leaks into the message.
fn map_reqwest_error(err: reqwest::Error) -> TransportError {
    if err.is_timeout() {
        TransportError::timeout("request timed out")
    } else if err.is_connect() {
        TransportError::connect("failed to connect to the archive host")
    } else if err.is_body() || err.is_decode() {
        TransportError::body("response body read failed")
    } else {
        TransportError::other("archive request failed")
    }
}
