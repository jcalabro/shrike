//! The native archive HTTP transport, backed by [`reqwest`], and the native live
//! WebSocket transport, backed by [`tokio_tungstenite`].
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
///
/// Cloning is cheap: [`reqwest::Client`] is an `Arc` handle over one connection
/// pool, so a clone shares that pool. The engine clones the transport to build a
/// fresh live tail at each archive→live cutover.
#[derive(Clone)]
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

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::result_large_err
)]
mod http_tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// The transport's only construction path builds a client with redirects
    /// disabled: a 3xx is surfaced verbatim to the caller instead of being
    /// followed, so an authenticated archive request can never replay its bearer
    /// key to the redirect target. Regression test guarding the removal of the
    /// `with_client` escape hatch, which could have installed a
    /// redirect-following client behind the same authenticated request path.
    #[tokio::test]
    async fn new_transport_does_not_follow_redirects() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Drain the request head; we only need the client's write to complete.
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await.unwrap();
            // Redirect to a port that is not listening: were the transport to
            // follow it, the follow-up connect would fail and `send` would error
            // instead of returning the 302 below.
            let response = "HTTP/1.1 302 Found\r\n\
                Location: http://127.0.0.1:1/elsewhere\r\n\
                Content-Length: 0\r\n\
                Connection: close\r\n\r\n";
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.flush().await.unwrap();
        });

        let transport = NativeHttpTransport::new().unwrap();
        let request = HttpRequest::get(format!("http://{addr}/segment"));
        let response = transport
            .send(request)
            .await
            .unwrap_or_else(|e| panic!("send failed: {e:?}"));

        // The redirect is surfaced as an ordinary response, not followed.
        assert_eq!(response.status, 302);
        server.await.unwrap();
    }
}

// === Native live WebSocket transport ====================================

use futures::SinkExt;
use tokio::net::TcpStream;
use tokio_tungstenite::tungstenite::Error as TungError;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::error::ProtocolError;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::tungstenite::http::header::SEC_WEBSOCKET_PROTOCOL;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async_with_config};

use super::live::{DialError, WsConnection, WsError, WsMessage, WsTransport};

/// The native live WebSocket transport backed by `tokio-tungstenite`.
///
/// It dials the `subscribeEvents` endpoint with the negotiated subprotocol,
/// caps both the message and frame size at the tail's read limit (so a hostile
/// or misconfigured server cannot force an unbounded buffer), and — like the
/// HTTP adapter — carries no authorization header, since the live endpoint is
/// unauthenticated.
#[derive(Clone)]
pub struct NativeWsTransport {
    read_limit: usize,
}

impl NativeWsTransport {
    /// Build a transport capping incoming messages and frames at `read_limit`.
    pub fn new(read_limit: usize) -> Self {
        NativeWsTransport { read_limit }
    }
}

impl WsTransport for NativeWsTransport {
    type Conn = NativeWsConnection;

    async fn dial(&self, url: String, subprotocol: &'static str) -> Result<Self::Conn, DialError> {
        let mut request = url
            .into_client_request()
            .map_err(|_| DialError::Transport("invalid websocket request".to_owned()))?;
        request.headers_mut().insert(
            SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(subprotocol),
        );

        let config = WebSocketConfig::default()
            .max_message_size(Some(self.read_limit))
            .max_frame_size(Some(self.read_limit));

        // `tokio-tungstenite` performs RFC 6455 step-6 subprotocol verification
        // during the handshake: because we requested `subprotocol`, a server that
        // echoes a different one — or none at all — fails the connect with a
        // subprotocol protocol error, which `map_ws_dial_error` surfaces as the
        // fatal `DialError::Subprotocol`. So a successful connect already implies
        // the negotiated subprotocol is the one we asked for; no further check is
        // needed here.
        let (stream, _response) = connect_async_with_config(request, Some(config), true)
            .await
            .map_err(map_ws_dial_error)?;
        Ok(NativeWsConnection { stream })
    }
}

/// An established native live WebSocket connection.
pub struct NativeWsConnection {
    stream: WebSocketStream<MaybeTlsStream<TcpStream>>,
}

impl WsConnection for NativeWsConnection {
    async fn read(&mut self) -> Result<Option<WsMessage>, WsError> {
        loop {
            match self.stream.next().await {
                // Stream ended without a close frame: treat as a clean close.
                None => return Ok(None),
                Some(Ok(message)) => match message {
                    Message::Text(text) => {
                        return Ok(Some(WsMessage::Text(text.as_bytes().to_vec())));
                    }
                    Message::Binary(bytes) => return Ok(Some(WsMessage::Binary(bytes.to_vec()))),
                    // Answer server pings transparently, then keep reading.
                    Message::Ping(payload) => {
                        if self.stream.send(Message::Pong(payload)).await.is_err() {
                            return Err(WsError::new("failed to answer ping"));
                        }
                    }
                    Message::Pong(_) => {}
                    Message::Close(_) => return Ok(None),
                    // Raw frames are never surfaced by the reader; ignore.
                    Message::Frame(_) => {}
                },
                Some(Err(err)) => return Err(map_ws_read_error(err)),
            }
        }
    }

    async fn close(&mut self) {
        // Best-effort: ignore errors on a connection we are discarding anyway.
        let _ = self.stream.close(None).await;
    }
}

/// Map a `tungstenite` dial error onto a portable [`DialError`]. A pre-upgrade
/// HTTP rejection is surfaced with its status and (bounded) body so the tail can
/// classify the XRPC error; a subprotocol negotiation failure is fatal; every
/// other failure is a redacted, recoverable transport error.
fn map_ws_dial_error(err: TungError) -> DialError {
    match err {
        TungError::Http(response) => {
            let status = response.status().as_u16();
            let body = response.into_body().unwrap_or_default();
            DialError::Http { status, body }
        }
        // A server that echoes the wrong subprotocol — or none when one was
        // requested — breaks the framing contract; fatal, not retryable. The
        // variant carries no server-supplied text, so nothing can leak.
        TungError::Protocol(ProtocolError::SecWebSocketSubProtocolError(_)) => {
            DialError::Subprotocol("server negotiated an unexpected subprotocol".to_owned())
        }
        // Fixed per-kind text, never the error's own Display (which can embed the
        // dialed URL): nothing host-specific leaks into the message.
        TungError::Io(_) => DialError::Transport("websocket i/o error".to_owned()),
        TungError::Tls(_) => DialError::Transport("websocket tls error".to_owned()),
        TungError::Protocol(_) => DialError::Transport("websocket protocol error".to_owned()),
        TungError::Url(_) => DialError::Transport("invalid websocket url".to_owned()),
        _ => DialError::Transport("websocket connection failed".to_owned()),
    }
}

/// Map a mid-stream `tungstenite` read error onto a redacted [`WsError`]. The
/// tail treats any read failure as a recoverable disconnect and reconnects.
fn map_ws_read_error(err: TungError) -> WsError {
    match err {
        TungError::Io(_) => WsError::new("websocket i/o error"),
        TungError::Protocol(_) => WsError::new("websocket protocol error"),
        TungError::Capacity(_) => WsError::new("websocket message exceeded read limit"),
        _ => WsError::new("websocket read failed"),
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::result_large_err
)]
mod ws_tests {
    use super::*;
    use tokio::net::TcpListener;
    use tokio_tungstenite::accept_hdr_async;
    use tokio_tungstenite::tungstenite::handshake::server::{Request, Response};

    /// A loopback server accepts one connection, echoes the requested
    /// subprotocol, sends a text then a binary frame, pings, waits for the
    /// client's pong, and closes. Exercises the whole native adapter path —
    /// dial, subprotocol negotiation, text/binary decode, transparent ping
    /// answering, and clean-close mapping — against a real WebSocket peer.
    #[tokio::test]
    async fn native_ws_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            // Echo the client's requested subprotocol verbatim, mirroring a
            // conforming Jetstream server.
            let echo = |req: &Request, mut resp: Response| {
                if let Some(proto) = req.headers().get(SEC_WEBSOCKET_PROTOCOL) {
                    resp.headers_mut()
                        .insert(SEC_WEBSOCKET_PROTOCOL, proto.clone());
                }
                Ok(resp)
            };
            let mut ws = accept_hdr_async(stream, echo).await.unwrap();
            ws.send(Message::Text("hello".into())).await.unwrap();
            ws.send(Message::Binary(vec![1, 2, 3].into()))
                .await
                .unwrap();
            ws.send(Message::Ping(vec![9, 9].into())).await.unwrap();
            // The client answers the ping only when it next reads; wait for it.
            let mut got_pong = false;
            while let Some(msg) = ws.next().await {
                if let Ok(Message::Pong(payload)) = msg {
                    assert_eq!(payload.to_vec(), vec![9, 9]);
                    got_pong = true;
                    break;
                }
            }
            assert!(got_pong, "client never answered the ping");
            ws.close(None).await.unwrap();
        });

        let transport = NativeWsTransport::new(1 << 20);
        let url = format!("ws://{addr}/xrpc/{}", super::super::live::SUBSCRIBE_METHOD);
        let mut conn = transport
            .dial(url, super::super::live::XRPC_SUBPROTOCOL)
            .await
            .unwrap_or_else(|e| panic!("dial failed: {e:?}"));

        match conn.read().await.unwrap() {
            Some(WsMessage::Text(bytes)) => assert_eq!(bytes, b"hello"),
            other => panic!("expected text frame, got {other:?}"),
        }
        match conn.read().await.unwrap() {
            Some(WsMessage::Binary(bytes)) => assert_eq!(bytes, vec![1, 2, 3]),
            other => panic!("expected binary frame, got {other:?}"),
        }
        // The ping is answered transparently; the next surfaced read is the
        // clean close, reported as `None`.
        assert!(conn.read().await.unwrap().is_none());
        conn.close().await;
        server.await.unwrap();
    }

    /// A server that negotiates a *different* subprotocol than the one requested
    /// must be rejected as a fatal [`DialError::Subprotocol`] — the framing
    /// contract cannot be assumed.
    #[tokio::test]
    async fn native_ws_wrong_subprotocol_is_rejected() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let wrong = |_req: &Request, mut resp: Response| {
                resp.headers_mut().insert(
                    SEC_WEBSOCKET_PROTOCOL,
                    HeaderValue::from_static("something.else"),
                );
                Ok(resp)
            };
            // The handshake itself may fail once the client rejects; ignore.
            let _ = accept_hdr_async(stream, wrong).await;
        });

        let transport = NativeWsTransport::new(1 << 20);
        let url = format!("ws://{addr}/xrpc/{}", super::super::live::SUBSCRIBE_METHOD);
        let result = transport
            .dial(url, super::super::live::XRPC_SUBPROTOCOL)
            .await;
        assert!(matches!(result, Err(DialError::Subprotocol(_))));
        let _ = server.await;
    }
}
