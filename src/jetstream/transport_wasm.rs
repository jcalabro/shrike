//! The browser live WebSocket transport, backed by `gloo-net`.
//!
//! This adapter is the built-in [`WsTransport`] for the browser target
//! (`wasm32-unknown-unknown`). Like the native adapter it carries no
//! authorization header — the live endpoint is unauthenticated — and it caps the
//! size of an accepted message at the tail's read limit so a hostile or
//! misconfigured server cannot force an unbounded buffer.
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

/// The browser live WebSocket transport backed by `gloo-net`.
pub struct WasmWsTransport {
    read_limit: usize,
}

impl WasmWsTransport {
    /// Build a transport capping an accepted message at `read_limit` bytes.
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
