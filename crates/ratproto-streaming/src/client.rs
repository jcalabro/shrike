use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};

use futures::StreamExt;
use futures::stream::Stream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::StreamError;
use crate::event::Event;
use crate::jetstream::JetstreamEvent;
use crate::reconnect::BackoffPolicy;

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

type WsStream =
    futures::stream::SplitStream<WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>>;

struct StreamState {
    ws: Option<WsStream>,
    attempt: u32,
}

impl StreamState {
    fn new() -> Self {
        StreamState {
            ws: None,
            attempt: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a streaming client.
pub struct Config {
    /// WebSocket URL (e.g., `"wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"`).
    pub url: String,
    /// Starting cursor (sequence number for firehose, `time_us` for Jetstream).
    pub cursor: Option<i64>,
    /// Backoff policy for reconnection.
    pub backoff: BackoffPolicy,
    /// Maximum WebSocket message size (default 2 MB).
    pub max_message_size: usize,
    /// For Jetstream: filter by collections.
    pub collections: Option<Vec<String>>,
    /// For Jetstream: filter by DIDs.
    pub dids: Option<Vec<String>>,
}

impl Config {
    /// Create a new configuration for the given WebSocket URL.
    pub fn new(url: &str) -> Self {
        Config {
            url: url.to_string(),
            cursor: None,
            backoff: BackoffPolicy::default(),
            max_message_size: 2 * 1024 * 1024,
            collections: None,
            dids: None,
        }
    }

    /// Create a configuration pre-set for firehose/label streams.
    pub fn firehose(url: &str) -> Self {
        Self::new(url)
    }

    /// Create a configuration pre-set for Jetstream.
    pub fn jetstream(url: &str) -> Self {
        Self::new(url)
    }

    /// Set a starting cursor (sequence number or `time_us` for Jetstream).
    pub fn with_cursor(mut self, cursor: i64) -> Self {
        self.cursor = Some(cursor);
        self
    }

    /// Set the collections filter (Jetstream `wantedCollections`).
    pub fn with_collections(mut self, collections: Vec<String>) -> Self {
        self.collections = Some(collections);
        self
    }

    /// Set the DIDs filter (Jetstream `wantedDids`).
    pub fn with_dids(mut self, dids: Vec<String>) -> Self {
        self.dids = Some(dids);
        self
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for consuming AT Protocol event streams (firehose or Jetstream).
///
/// The WebSocket connection is established lazily when [`Client::subscribe`] or
/// [`Client::jetstream`] is called.
pub struct Client {
    config: Config,
    cursor: Arc<AtomicI64>,
}

impl Client {
    /// Create a new client with the given configuration.
    pub fn new(config: Config) -> Self {
        let cursor_val = config.cursor.unwrap_or(-1);
        Client {
            config,
            cursor: Arc::new(AtomicI64::new(cursor_val)),
        }
    }

    /// Return the current cursor position (for checkpointing).
    ///
    /// Returns `None` if no cursor has been set or observed yet.
    pub fn cursor(&self) -> Option<i64> {
        let val = self.cursor.load(Ordering::SeqCst);
        if val < 0 { None } else { Some(val) }
    }

    /// Connect to a firehose or label stream (CBOR protocol).
    ///
    /// Returns an async stream of [`Event`] values. The stream reconnects
    /// automatically on connection failure with exponential backoff + jitter.
    ///
    /// Info and sync frames are silently skipped. All other parse/connection
    /// errors are yielded as `Err` items without terminating the stream.
    pub fn subscribe(&self) -> impl Stream<Item = Result<Event, StreamError>> + '_ {
        let cursor = Arc::clone(&self.cursor);
        let config = &self.config;

        futures::stream::unfold(StreamState::new(), move |mut state| {
            let cursor = Arc::clone(&cursor);
            async move {
                loop {
                    // Establish a connection if we don't have one.
                    if state.ws.is_none() {
                        match connect_ws(
                            &config.url,
                            cursor.load(Ordering::SeqCst),
                            &config.collections,
                            &config.dids,
                        )
                        .await
                        {
                            Ok(ws) => {
                                state.ws = Some(ws);
                                state.attempt = 0;
                            }
                            Err(e) => {
                                let delay = config.backoff.delay(state.attempt);
                                state.attempt = state.attempt.saturating_add(1);
                                tokio::time::sleep(delay).await;
                                return Some((Err(e), state));
                            }
                        }
                    }

                    // Read the next message from the WebSocket.
                    let ws = state.ws.as_mut()?;
                    match ws.next().await {
                        Some(Ok(Message::Binary(data))) => {
                            match crate::parse_firehose_frame(&data) {
                                Ok(event) => {
                                    let seq = event_seq(&event);
                                    if seq > 0 {
                                        cursor.store(seq, Ordering::SeqCst);
                                    }
                                    return Some((Ok(event), state));
                                }
                                // Info/sync frames return UnknownType — skip them.
                                Err(StreamError::UnknownType(_)) => continue,
                                Err(e) => return Some((Err(e), state)),
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            // Connection closed — reconnect.
                            state.ws = None;
                            let delay = config.backoff.delay(state.attempt);
                            state.attempt = state.attempt.saturating_add(1);
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        Some(Ok(_)) => continue, // ping/pong/text — skip
                        Some(Err(e)) => {
                            state.ws = None;
                            let delay = config.backoff.delay(state.attempt);
                            state.attempt = state.attempt.saturating_add(1);
                            tokio::time::sleep(delay).await;
                            return Some((Err(StreamError::WebSocket(e.to_string())), state));
                        }
                    }
                }
            }
        })
    }

    /// Connect to a Jetstream endpoint (JSON protocol).
    ///
    /// Returns an async stream of [`JetstreamEvent`] values. The stream
    /// reconnects automatically on connection failure with exponential
    /// backoff + jitter.
    pub fn jetstream(&self) -> impl Stream<Item = Result<JetstreamEvent, StreamError>> + '_ {
        let cursor = Arc::clone(&self.cursor);
        let config = &self.config;

        futures::stream::unfold(StreamState::new(), move |mut state| {
            let cursor = Arc::clone(&cursor);
            async move {
                loop {
                    if state.ws.is_none() {
                        match connect_ws(
                            &config.url,
                            cursor.load(Ordering::SeqCst),
                            &config.collections,
                            &config.dids,
                        )
                        .await
                        {
                            Ok(ws) => {
                                state.ws = Some(ws);
                                state.attempt = 0;
                            }
                            Err(e) => {
                                let delay = config.backoff.delay(state.attempt);
                                state.attempt = state.attempt.saturating_add(1);
                                tokio::time::sleep(delay).await;
                                return Some((Err(e), state));
                            }
                        }
                    }

                    let ws = state.ws.as_mut()?;
                    match ws.next().await {
                        Some(Ok(Message::Text(text))) => {
                            match crate::jetstream::parse_jetstream_message(&text) {
                                Ok(event) => {
                                    let time_us = jetstream_time_us(&event);
                                    if time_us > 0 {
                                        cursor.store(time_us, Ordering::SeqCst);
                                    }
                                    return Some((Ok(event), state));
                                }
                                Err(e) => return Some((Err(e), state)),
                            }
                        }
                        Some(Ok(Message::Close(_))) | None => {
                            state.ws = None;
                            let delay = config.backoff.delay(state.attempt);
                            state.attempt = state.attempt.saturating_add(1);
                            tokio::time::sleep(delay).await;
                            continue;
                        }
                        Some(Ok(_)) => continue,
                        Some(Err(e)) => {
                            state.ws = None;
                            let delay = config.backoff.delay(state.attempt);
                            state.attempt = state.attempt.saturating_add(1);
                            tokio::time::sleep(delay).await;
                            return Some((Err(StreamError::WebSocket(e.to_string())), state));
                        }
                    }
                }
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Build a WebSocket URL with cursor and filter query params, then connect.
async fn connect_ws(
    base_url: &str,
    cursor: i64,
    collections: &Option<Vec<String>>,
    dids: &Option<Vec<String>>,
) -> Result<WsStream, StreamError> {
    let mut url = url::Url::parse(base_url)
        .map_err(|e| StreamError::WebSocket(format!("invalid URL: {e}")))?;

    if cursor > 0 {
        url.query_pairs_mut()
            .append_pair("cursor", &cursor.to_string());
    }
    if let Some(cols) = collections {
        for col in cols {
            url.query_pairs_mut().append_pair("wantedCollections", col);
        }
    }
    if let Some(ds) = dids {
        for d in ds {
            url.query_pairs_mut().append_pair("wantedDids", d);
        }
    }

    let (ws_stream, _response) = tokio_tungstenite::connect_async(url.as_str())
        .await
        .map_err(|e| StreamError::WebSocket(format!("connection failed: {e}")))?;

    let (_write, read) = ws_stream.split();
    Ok(read)
}

fn event_seq(event: &Event) -> i64 {
    match event {
        Event::Commit { seq, .. }
        | Event::Identity { seq, .. }
        | Event::Account { seq, .. }
        | Event::Labels { seq, .. } => *seq,
    }
}

fn jetstream_time_us(event: &JetstreamEvent) -> i64 {
    match event {
        JetstreamEvent::Commit { time_us, .. }
        | JetstreamEvent::Identity { time_us, .. }
        | JetstreamEvent::Account { time_us, .. } => *time_us,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    #[test]
    fn config_new_defaults() {
        let cfg = Config::new("wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos");
        assert_eq!(
            cfg.url,
            "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
        );
        assert!(cfg.cursor.is_none());
        assert_eq!(cfg.max_message_size, 2 * 1024 * 1024);
    }

    #[test]
    fn config_firehose_defaults() {
        let cfg = Config::firehose("wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos");
        assert_eq!(
            cfg.url,
            "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
        );
        assert!(cfg.cursor.is_none());
        assert_eq!(cfg.max_message_size, 2 * 1024 * 1024);
    }

    #[test]
    fn config_with_cursor() {
        let cfg = Config::firehose("wss://example.com").with_cursor(12345);
        assert_eq!(cfg.cursor, Some(12345));
    }

    #[test]
    fn config_with_collections() {
        let cfg = Config::jetstream("wss://example.com")
            .with_collections(vec!["app.bsky.feed.post".into()]);
        assert_eq!(cfg.collections.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn config_with_dids() {
        let cfg = Config::jetstream("wss://example.com")
            .with_dids(vec!["did:plc:test123456789abcdefghij".into()]);
        assert_eq!(cfg.dids.as_ref().unwrap().len(), 1);
    }

    #[test]
    fn client_cursor_none_initially() {
        let client = Client::new(Config::firehose("wss://example.com"));
        assert_eq!(client.cursor(), None);
    }

    #[test]
    fn client_cursor_from_config() {
        let client = Client::new(Config::firehose("wss://example.com").with_cursor(42));
        assert_eq!(client.cursor(), Some(42));
    }

    #[test]
    fn event_seq_extraction() {
        let event = Event::Commit {
            did: ratproto_syntax::Did::default(),
            rev: ratproto_syntax::Tid::new(0, 0),
            seq: 999,
            operations: vec![],
        };
        assert_eq!(event_seq(&event), 999);
    }

    #[test]
    fn event_seq_identity() {
        let event = Event::Identity {
            did: ratproto_syntax::Did::default(),
            seq: 123,
            handle: None,
        };
        assert_eq!(event_seq(&event), 123);
    }

    #[test]
    fn event_seq_account() {
        let event = Event::Account {
            did: ratproto_syntax::Did::default(),
            seq: 456,
            active: true,
        };
        assert_eq!(event_seq(&event), 456);
    }

    #[test]
    fn event_seq_labels() {
        let event = Event::Labels {
            seq: 789,
            labels: vec![],
        };
        assert_eq!(event_seq(&event), 789);
    }

    #[test]
    fn jetstream_time_us_extraction() {
        let event = JetstreamEvent::Identity {
            did: ratproto_syntax::Did::default(),
            time_us: 1_700_000_000_000_000,
        };
        assert_eq!(jetstream_time_us(&event), 1_700_000_000_000_000);
    }

    #[test]
    fn jetstream_time_us_commit() {
        let event = JetstreamEvent::Commit {
            did: ratproto_syntax::Did::default(),
            time_us: 42,
            collection: ratproto_syntax::Nsid::default(),
            rkey: ratproto_syntax::RecordKey::default(),
            operation: crate::jetstream::JetstreamCommit::Delete,
        };
        assert_eq!(jetstream_time_us(&event), 42);
    }

    #[test]
    fn jetstream_time_us_account() {
        let event = JetstreamEvent::Account {
            did: ratproto_syntax::Did::default(),
            time_us: 99,
            active: false,
        };
        assert_eq!(jetstream_time_us(&event), 99);
    }
}
