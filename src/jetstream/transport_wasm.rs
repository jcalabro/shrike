//! The browser archive HTTP transport, backed by `gloo-net`'s `fetch` wrapper,
//! and the browser live WebSocket transport, backed by `gloo-net`'s socket.
//!
//! The HTTP adapter is the built-in [`HttpTransport`] for the browser target
//! (`wasm32-unknown-unknown`); the WebSocket adapter is the built-in
//! [`WsTransport`]. Both are the browser counterparts of the `reqwest` /
//! `tokio-tungstenite` adapters in `transport_native`, and the portable core
//! (planner, downloader, live tail) is written against the shared traits so it
//! is identical on both targets.
//!
//! Three browser realities shape the HTTP adapter, and each is a deliberate
//! security or robustness choice rather than an accident of the platform:
//!
//! - **Redirects are refused.** The request is issued with `redirect: "error"`,
//!   so `fetch` rejects rather than follow a 3xx. An archive request carries the
//!   bearer key in an `Authorization` header; following a redirect could replay
//!   that key to an unintended host. This mirrors the native adapter, which
//!   disables redirects in the `reqwest` client. A defensive post-flight
//!   `redirected()` check backstops the mode.
//! - **No ambient credentials.** The request is issued with
//!   `credentials: "omit"`, so browser cookies and TLS client certificates are
//!   never attached; the only authenticator is the explicit `Authorization`
//!   header the caller sets. Combined with `mode: "cors"`, a cross-origin
//!   archive host that does not return the required CORS headers makes `fetch`
//!   reject rather than hand back an opaque, silently-empty response. That
//!   rejection is indistinguishable from a transient network fault (the browser
//!   exposes no detail), so it surfaces as a retryable transport error and the
//!   caller's bounded retry decides when to give up — see [`map_fetch_error`].
//! - **The body streams under the caller's bound.** The response body is read
//!   incrementally through a `ReadableStream` reader, one chunk per
//!   [`HttpBody::chunk`], so `read_body_bounded` enforces the caller's exact
//!   byte cap chunk-by-chunk. A hostile or misconfigured host therefore cannot
//!   force the browser to buffer a whole oversized response before the bound is
//!   checked, matching the native streaming path.
//!
//! Every error message is a fixed, redacted, bounded per-kind string: the
//! underlying JS error text (which can name the URL) is never rendered, and the
//! API key — which lives only in a request header — cannot appear by
//! construction.
//!
//! The live WebSocket adapter, below, carries no authorization header (the live
//! endpoint is unauthenticated) and rejects any message larger than the tail's
//! read limit before it is processed: the oversized frame never reaches
//! decompression or decode, and the connection is torn down. Note the bound's
//! reach, though. Unlike the native adapter — which configures
//! `tokio-tungstenite`'s `max_message_size` / `max_frame_size` to bound receipt
//! itself — the browser `WebSocket` API delivers each message fully buffered
//! before any handler runs and exposes no receive-size cap. The read limit here
//! therefore bounds what a single message costs *downstream*, not the transient
//! buffer the browser allocates to receive it: one oversized message can be
//! materialized by the browser before this check rejects it (and only one, since
//! the connection is then dropped). That residual is a browser-platform limit —
//! the same shape as the missing-CORS case above, a capability the browser does
//! not expose rather than a gap the adapter can close.
//!
//! Two browser constraints shape the mapping, and both are deliberate:
//!
//! - **No pre-upgrade status.** The browser owns the WebSocket handshake and does
//!   not expose the HTTP response of a rejected upgrade, so a pre-upgrade XRPC
//!   error (e.g. `CursorTooOld`) cannot be surfaced as [`DialError::Http`]; it
//!   arrives as a generic [`DialError::Transport`] and the tail reconnects. The
//!   native adapter, which does see the status, carries the [`DialError::Http`]
//!   path.
//! - **Subprotocol enforcement is the browser's.** The subprotocol is requested
//!   via `open_with_protocol`, and per RFC 6455 the browser itself fails the
//!   handshake if the server selects a subprotocol that was not offered (an empty
//!   echo is accepted). We therefore rely on that enforcement rather than an
//!   explicit post-connect check, since the negotiated value is not known
//!   synchronously at dial time.
//!
//! The socket is `!Send`; the portable [`WsConnection`]/[`WsTransport`] contract
//! does not require `Send` on the returned futures, so this adapter satisfies it
//! as written.

use futures::StreamExt;
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::{Message, WebSocketError};

use super::live::{DialError, WsConnection, WsError, WsMessage, WsTransport};

// === Browser archive HTTP transport =====================================

use bytes::Bytes;
use gloo_net::http::Request;
use js_sys::{Reflect, Uint8Array};
use wasm_bindgen::{JsCast, JsValue};
use wasm_bindgen_futures::JsFuture;
use web_sys::{
    ReadableStream, ReadableStreamDefaultReader, RequestCredentials, RequestMode, RequestRedirect,
};

use super::transport::{
    HttpBody, HttpRequest, HttpResponse, HttpTransport, Method, ResponseHeaders, TransportError,
};

/// The browser archive HTTP transport backed by `gloo-net`'s `fetch` wrapper.
///
/// It is stateless: `fetch` is a global with no connection pool to hold, so a
/// clone is free. The engine clones the transport when it rebuilds the live tail
/// at an archive→live cutover; the browser archive path itself needs no shared
/// state between requests.
#[derive(Clone, Default)]
pub struct WasmHttpTransport {
    _private: (),
}

impl WasmHttpTransport {
    /// Build a browser archive HTTP transport.
    pub fn new() -> Self {
        WasmHttpTransport { _private: () }
    }
}

impl HttpTransport for WasmHttpTransport {
    type Body = WasmHttpBody;

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse<Self::Body>, TransportError> {
        // `redirect: "error"` refuses to replay the bearer across a redirect;
        // `credentials: "omit"` keeps ambient cookies/TLS certs off the request
        // so the only authenticator is the caller's explicit header; `mode:
        // "cors"` makes a host without the required CORS headers reject (surfaced
        // as a capability error) rather than return an opaque, empty response.
        let mut builder = match request.method {
            Method::Get => Request::get(&request.url),
            Method::Post => Request::post(&request.url),
        }
        .redirect(RequestRedirect::Error)
        .credentials(RequestCredentials::Omit)
        .mode(RequestMode::Cors);
        for (name, value) in &request.headers {
            builder = builder.header(name, value);
        }

        // A body only rides on the `planSnapshot` POST. `body` finalizes the
        // builder into a `Request`; a GET sends the builder directly.
        let response = match request.body {
            Some(body) => {
                let payload = Uint8Array::from(body.as_ref());
                builder
                    .body(payload)
                    .map_err(|_| TransportError::other("failed to attach the request body"))?
                    .send()
                    .await
            }
            None => builder.send().await,
        }
        .map_err(map_fetch_error)?;

        // `redirect: "error"` already rejects a redirect before we get here; this
        // is a defensive backstop so a redirected response can never be trusted.
        if response.redirected() {
            return Err(TransportError::capability(
                "archive response was redirected; refusing to trust it",
            ));
        }

        let status = response.status();
        let headers = ResponseHeaders::from_pairs(response.headers().entries());

        // Take the body as a streaming reader. An absent body (e.g. a bodyless
        // status) yields an immediately-exhausted reader rather than an error.
        let reader = match response.body() {
            Some(stream) => Some(into_reader(stream)?),
            None => None,
        };

        Ok(HttpResponse {
            status,
            headers,
            body: WasmHttpBody { reader },
        })
    }
}

/// Acquire a default reader over a `fetch` response's [`ReadableStream`].
///
/// `get_reader` returns a generic `Object`; the default reader is the concrete
/// type whose `read()` yields `{ value, done }`. A byte-stream response uses the
/// default reader, so the cast is sound; if a future browser handed back a BYOB
/// reader instead, the subsequent `read()` would fail and surface as a bounded
/// body error rather than a panic.
fn into_reader(stream: ReadableStream) -> Result<ReadableStreamDefaultReader, TransportError> {
    let reader: JsValue = stream.get_reader().into();
    reader
        .dyn_into::<ReadableStreamDefaultReader>()
        .map_err(|_| TransportError::capability("fetch response body reader is unavailable"))
}

/// The streaming body of a browser archive response: a `ReadableStream` default
/// reader drained one chunk at a time.
pub struct WasmHttpBody {
    /// `None` once the stream is exhausted (or was absent), so a further
    /// [`HttpBody::chunk`] cleanly reports end of stream.
    reader: Option<ReadableStreamDefaultReader>,
}

impl HttpBody for WasmHttpBody {
    async fn chunk(&mut self) -> Result<Option<Bytes>, TransportError> {
        let Some(reader) = self.reader.as_ref() else {
            return Ok(None);
        };

        // `read()` resolves to a `{ value: Uint8Array, done: bool }` object.
        let result = JsFuture::from(reader.read())
            .await
            .map_err(|_| TransportError::body("response body read failed"))?;

        let done = Reflect::get(&result, &JsValue::from_str("done"))
            .ok()
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        if done {
            // Drop the reader so any later call short-circuits to end-of-stream.
            self.reader = None;
            return Ok(None);
        }

        let value = Reflect::get(&result, &JsValue::from_str("value"))
            .map_err(|_| TransportError::body("response body chunk was malformed"))?;
        // A non-final chunk always carries a `Uint8Array` value; treat a missing
        // or wrongly-typed value as a mid-stream body failure rather than a panic.
        let chunk = value
            .dyn_into::<Uint8Array>()
            .map_err(|_| TransportError::body("response body chunk was not bytes"))?;
        Ok(Some(Bytes::from(chunk.to_vec())))
    }
}

/// Map a `gloo-net` `fetch` failure onto a portable, redacted [`TransportError`].
///
/// A rejected `fetch` in the browser is opaque by design — a transient network
/// fault, a missing-CORS rejection, and a blocked redirect all surface as the
/// same `TypeError`, and the message can embed the URL — so this reports a
/// fixed, redacted string that names the likely causes without echoing the
/// underlying text or the URL.
///
/// The failure is classified [`TransportErrorKind::Connect`], which is
/// **retryable**, and that classification is load-bearing: because the browser
/// cannot tell a transient fault apart from a permanent one, the safe default is
/// to let the caller's bounded retry run. A genuinely transient blip then
/// recovers, while a permanent cause (missing CORS, a refused redirect) costs
/// only a bounded handful of retries before it surfaces. Classifying every
/// failure non-retryable (`Capability`) would instead abort an archive download
/// on the first network blip — the strictly worse trade — since `Capability` is
/// terminal for both control requests (`archive.rs`) and page downloads
/// (`download.rs`). Do not narrow this back to `Capability`.
fn map_fetch_error(_err: gloo_net::Error) -> TransportError {
    TransportError::connect("archive fetch failed (network error, missing CORS, or redirect)")
}

/// The browser live WebSocket transport backed by `gloo-net`.
#[derive(Clone)]
pub struct WasmWsTransport {
    read_limit: usize,
}

impl WasmWsTransport {
    /// Build a transport rejecting any message larger than `read_limit` bytes
    /// before it is processed. See the module docs for why this bounds
    /// downstream cost rather than the browser's transient receive buffer.
    pub fn new(read_limit: usize) -> Self {
        WasmWsTransport { read_limit }
    }
}

impl WsTransport for WasmWsTransport {
    type Conn = WasmWsConnection;

    async fn dial(
        &self,
        url: String,
        subprotocol: &'static str,
    ) -> core::result::Result<Self::Conn, DialError> {
        // `open_with_protocol` requests the subprotocol; the browser rejects a
        // server that selects an unoffered one (see the module docs). A failure
        // here is a generic transport error — the HTTP status of a rejected
        // upgrade is not exposed to browser scripts.
        let ws = WebSocket::open_with_protocol(&url, subprotocol)
            .map_err(|_| DialError::Transport("websocket open failed".to_owned()))?;
        Ok(WasmWsConnection {
            ws: Some(ws),
            read_limit: self.read_limit,
        })
    }
}

/// An established browser live WebSocket connection.
pub struct WasmWsConnection {
    ws: Option<WebSocket>,
    read_limit: usize,
}

impl WsConnection for WasmWsConnection {
    async fn read(&mut self) -> core::result::Result<Option<WsMessage>, WsError> {
        let Some(ws) = self.ws.as_mut() else {
            return Ok(None);
        };
        // The browser has already buffered the whole message by the time
        // `ws.next()` yields it (see the module docs); this check bounds what
        // reaches decompression/decode, not the receive buffer. Moving it into a
        // match guard would not change that — the guard still runs post-receipt.
        match ws.next().await {
            // Stream ended: the socket is done; treat as a clean close.
            None => Ok(None),
            Some(Ok(Message::Text(text))) => {
                let bytes = text.into_bytes();
                if bytes.len() > self.read_limit {
                    return Err(WsError::new("websocket message exceeded read limit"));
                }
                Ok(Some(WsMessage::Text(bytes)))
            }
            Some(Ok(Message::Bytes(bytes))) => {
                if bytes.len() > self.read_limit {
                    return Err(WsError::new("websocket message exceeded read limit"));
                }
                Ok(Some(WsMessage::Binary(bytes)))
            }
            // A close event ends the stream cleanly; the tail reconnects.
            Some(Err(WebSocketError::ConnectionClose(_))) => Ok(None),
            Some(Err(err)) => Err(map_ws_error(err)),
        }
    }

    async fn close(&mut self) {
        // `WebSocket::close` consumes the socket; take it so a second call is a
        // no-op. Best-effort — errors on a discarded connection are ignored.
        if let Some(ws) = self.ws.take() {
            let _ = ws.close(None, None);
        }
    }
}

/// Map a `gloo-net` WebSocket error onto a redacted [`WsError`]. As on native,
/// the tail treats any read failure as a recoverable disconnect; the message is a
/// fixed per-kind string so nothing server-supplied leaks into it.
fn map_ws_error(err: WebSocketError) -> WsError {
    match err {
        WebSocketError::ConnectionError => WsError::new("websocket connection error"),
        WebSocketError::ConnectionClose(_) => WsError::new("websocket closed by peer"),
        WebSocketError::MessageSendError(_) => WsError::new("websocket send error"),
        _ => WsError::new("websocket read failed"),
    }
}
