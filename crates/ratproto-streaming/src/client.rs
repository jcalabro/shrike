use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

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

/// Batching state shared by both firehose and Jetstream streams.
struct BatchState<E> {
    ws: Option<WsStream>,
    attempt: u32,
    batch: Vec<E>,
    pending_error: Option<StreamError>,
    deadline: Option<tokio::time::Instant>,
}

impl<E> BatchState<E> {
    fn new(capacity: usize) -> Self {
        BatchState {
            ws: None,
            attempt: 0,
            batch: Vec::with_capacity(capacity),
            pending_error: None,
            deadline: None,
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
    /// Maximum number of events per batch (default 50).
    pub batch_size: usize,
    /// Maximum time to wait for a full batch before flushing (default 500ms).
    pub batch_timeout: Duration,
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
            batch_size: 50,
            batch_timeout: Duration::from_millis(500),
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

    /// Set the maximum number of events per batch (default 50).
    pub fn with_batch_size(mut self, batch_size: usize) -> Self {
        self.batch_size = batch_size;
        self
    }

    /// Set the maximum time to wait for a full batch before flushing
    /// (default 500ms).
    pub fn with_batch_timeout(mut self, batch_timeout: Duration) -> Self {
        self.batch_timeout = batch_timeout;
        self
    }
}

// ---------------------------------------------------------------------------
// Client
// ---------------------------------------------------------------------------

/// Client for consuming AT Protocol event streams (firehose or Jetstream).
///
/// Events are delivered in batches for efficient bulk processing. The
/// [`Config::batch_size`] and [`Config::batch_timeout`] fields control
/// batching behavior (defaults: 50 events, 500ms). Each yield from
/// [`Client::subscribe`] or [`Client::jetstream`] delivers a `Vec` of 1 to
/// `batch_size` events. Batches flush when full, when the timeout elapses,
/// or when an error (decode error, connection loss) is encountered — in
/// which case the partial batch is yielded first, followed by the error.
///
/// The WebSocket connection is established lazily when [`Client::subscribe`]
/// or [`Client::jetstream`] is called.
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
    /// Returns an async stream of event batches. Events are accumulated up to
    /// [`Config::batch_size`] (default 50) or until [`Config::batch_timeout`]
    /// (default 500ms) elapses, whichever comes first. Partial batches are
    /// flushed before errors or connection loss.
    ///
    /// The stream reconnects automatically on connection failure with
    /// exponential backoff + jitter. Info and sync frames are silently
    /// skipped. All other parse/connection errors are yielded as `Err`
    /// items without terminating the stream.
    pub fn subscribe(&self) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        let cursor = Arc::clone(&self.cursor);
        let config = &self.config;
        let batch_size = config.batch_size;
        let batch_timeout = config.batch_timeout;

        futures::stream::unfold(BatchState::<Event>::new(batch_size), move |mut state| {
            let cursor = Arc::clone(&cursor);
            async move {
                // Yield any pending error from a previous partial-batch flush.
                if let Some(err) = state.pending_error.take() {
                    return Some((Err(err), state));
                }

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
                                // Flush partial batch before yielding connection error.
                                if !state.batch.is_empty() {
                                    state.pending_error = Some(e);
                                    state.deadline = None;
                                    let batch = std::mem::take(&mut state.batch);
                                    update_firehose_cursor(&cursor, &batch);
                                    return Some((Ok(batch), state));
                                }
                                let delay = config.backoff.delay(state.attempt);
                                state.attempt = state.attempt.saturating_add(1);
                                tokio::time::sleep(delay).await;
                                return Some((Err(e), state));
                            }
                        }
                    }

                    let deadline = *state
                        .deadline
                        .get_or_insert_with(|| tokio::time::Instant::now() + batch_timeout);

                    // Take ws out of state to avoid borrow conflicts in select!.
                    let Some(mut ws) = state.ws.take() else {
                        continue;
                    };

                    tokio::select! {
                        msg = ws.next() => {
                            match msg {
                                Some(Ok(Message::Binary(data))) => {
                                    state.ws = Some(ws);
                                    match crate::parse_firehose_frame(&data) {
                                        Ok(event) => {
                                            state.batch.push(event);
                                            if state.batch.len() >= batch_size {
                                                state.deadline = None;
                                                let batch = std::mem::take(&mut state.batch);
                                                update_firehose_cursor(&cursor, &batch);
                                                return Some((Ok(batch), state));
                                            }
                                        }
                                        // Info/sync frames return UnknownType — skip.
                                        Err(StreamError::UnknownType(_)) => continue,
                                        Err(e) => {
                                            if !state.batch.is_empty() {
                                                state.pending_error = Some(e);
                                                state.deadline = None;
                                                let batch = std::mem::take(&mut state.batch);
                                                update_firehose_cursor(&cursor, &batch);
                                                return Some((Ok(batch), state));
                                            }
                                            state.deadline = None;
                                            return Some((Err(e), state));
                                        }
                                    }
                                }
                                Some(Ok(Message::Close(_))) | None => {
                                    // Connection closed — flush partial batch,
                                    // then reconnect on next iteration.
                                    drop(ws);
                                    if !state.batch.is_empty() {
                                        state.deadline = None;
                                        let batch = std::mem::take(&mut state.batch);
                                        update_firehose_cursor(&cursor, &batch);
                                        return Some((Ok(batch), state));
                                    }
                                    let delay = config.backoff.delay(state.attempt);
                                    state.attempt = state.attempt.saturating_add(1);
                                    tokio::time::sleep(delay).await;
                                    continue;
                                }
                                Some(Ok(_)) => {
                                    state.ws = Some(ws);
                                    continue; // ping/pong/text — skip
                                }
                                Some(Err(e)) => {
                                    // WebSocket error — flush partial batch,
                                    // then reconnect on next iteration.
                                    drop(ws);
                                    let err = StreamError::WebSocket(e.to_string());
                                    if !state.batch.is_empty() {
                                        state.pending_error = Some(err);
                                        state.deadline = None;
                                        let batch = std::mem::take(&mut state.batch);
                                        update_firehose_cursor(&cursor, &batch);
                                        return Some((Ok(batch), state));
                                    }
                                    let delay = config.backoff.delay(state.attempt);
                                    state.attempt = state.attempt.saturating_add(1);
                                    tokio::time::sleep(delay).await;
                                    return Some((Err(err), state));
                                }
                            }
                        }
                        _ = tokio::time::sleep_until(deadline) => {
                            state.ws = Some(ws);
                            if !state.batch.is_empty() {
                                state.deadline = None;
                                let batch = std::mem::take(&mut state.batch);
                                update_firehose_cursor(&cursor, &batch);
                                return Some((Ok(batch), state));
                            }
                            // Empty batch — reset deadline and keep waiting.
                            state.deadline = Some(
                                tokio::time::Instant::now() + batch_timeout,
                            );
                        }
                    }
                }
            }
        })
    }

    /// Connect to a Jetstream endpoint (JSON protocol).
    ///
    /// Returns an async stream of event batches. Batching behavior is
    /// identical to [`Client::subscribe`] — see its documentation for
    /// details on batch size, timeout, and partial-batch flushing.
    ///
    /// The stream reconnects automatically on connection failure with
    /// exponential backoff + jitter.
    pub fn jetstream(&self) -> impl Stream<Item = Result<Vec<JetstreamEvent>, StreamError>> + '_ {
        let cursor = Arc::clone(&self.cursor);
        let config = &self.config;
        let batch_size = config.batch_size;
        let batch_timeout = config.batch_timeout;

        futures::stream::unfold(
            BatchState::<JetstreamEvent>::new(batch_size),
            move |mut state| {
                let cursor = Arc::clone(&cursor);
                async move {
                    if let Some(err) = state.pending_error.take() {
                        return Some((Err(err), state));
                    }

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
                                    if !state.batch.is_empty() {
                                        state.pending_error = Some(e);
                                        state.deadline = None;
                                        let batch = std::mem::take(&mut state.batch);
                                        update_jetstream_cursor(&cursor, &batch);
                                        return Some((Ok(batch), state));
                                    }
                                    let delay = config.backoff.delay(state.attempt);
                                    state.attempt = state.attempt.saturating_add(1);
                                    tokio::time::sleep(delay).await;
                                    return Some((Err(e), state));
                                }
                            }
                        }

                        let deadline = *state
                            .deadline
                            .get_or_insert_with(|| tokio::time::Instant::now() + batch_timeout);

                        let Some(mut ws) = state.ws.take() else {
                            continue;
                        };

                        tokio::select! {
                            msg = ws.next() => {
                                match msg {
                                    Some(Ok(Message::Text(text))) => {
                                        state.ws = Some(ws);
                                        match crate::jetstream::parse_jetstream_message(&text) {
                                            Ok(event) => {
                                                state.batch.push(event);
                                                if state.batch.len() >= batch_size {
                                                    state.deadline = None;
                                                    let batch = std::mem::take(&mut state.batch);
                                                    update_jetstream_cursor(&cursor, &batch);
                                                    return Some((Ok(batch), state));
                                                }
                                            }
                                            Err(e) => {
                                                if !state.batch.is_empty() {
                                                    state.pending_error = Some(e);
                                                    state.deadline = None;
                                                    let batch = std::mem::take(&mut state.batch);
                                                    update_jetstream_cursor(&cursor, &batch);
                                                    return Some((Ok(batch), state));
                                                }
                                                state.deadline = None;
                                                return Some((Err(e), state));
                                            }
                                        }
                                    }
                                    Some(Ok(Message::Close(_))) | None => {
                                        drop(ws);
                                        if !state.batch.is_empty() {
                                            state.deadline = None;
                                            let batch = std::mem::take(&mut state.batch);
                                            update_jetstream_cursor(&cursor, &batch);
                                            return Some((Ok(batch), state));
                                        }
                                        let delay = config.backoff.delay(state.attempt);
                                        state.attempt = state.attempt.saturating_add(1);
                                        tokio::time::sleep(delay).await;
                                        continue;
                                    }
                                    Some(Ok(_)) => {
                                        state.ws = Some(ws);
                                        continue;
                                    }
                                    Some(Err(e)) => {
                                        drop(ws);
                                        let err = StreamError::WebSocket(e.to_string());
                                        if !state.batch.is_empty() {
                                            state.pending_error = Some(err);
                                            state.deadline = None;
                                            let batch = std::mem::take(&mut state.batch);
                                            update_jetstream_cursor(&cursor, &batch);
                                            return Some((Ok(batch), state));
                                        }
                                        let delay = config.backoff.delay(state.attempt);
                                        state.attempt = state.attempt.saturating_add(1);
                                        tokio::time::sleep(delay).await;
                                        return Some((Err(err), state));
                                    }
                                }
                            }
                            _ = tokio::time::sleep_until(deadline) => {
                                state.ws = Some(ws);
                                if !state.batch.is_empty() {
                                    state.deadline = None;
                                    let batch = std::mem::take(&mut state.batch);
                                    update_jetstream_cursor(&cursor, &batch);
                                    return Some((Ok(batch), state));
                                }
                                state.deadline = Some(
                                    tokio::time::Instant::now() + batch_timeout,
                                );
                            }
                        }
                    }
                }
            },
        )
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

pub(crate) fn event_seq(event: &Event) -> i64 {
    match event {
        Event::Commit { seq, .. }
        | Event::Identity { seq, .. }
        | Event::Account { seq, .. }
        | Event::Labels { seq, .. } => *seq,
    }
}

pub(crate) fn jetstream_time_us(event: &JetstreamEvent) -> i64 {
    match event {
        JetstreamEvent::Commit { time_us, .. }
        | JetstreamEvent::Identity { time_us, .. }
        | JetstreamEvent::Account { time_us, .. } => *time_us,
    }
}

/// Update the cursor from the last event in a firehose batch.
fn update_firehose_cursor(cursor: &AtomicI64, batch: &[Event]) {
    if let Some(seq) = batch.iter().rev().map(event_seq).find(|&s| s > 0) {
        cursor.store(seq, Ordering::SeqCst);
    }
}

/// Update the cursor from the last event in a Jetstream batch.
fn update_jetstream_cursor(cursor: &AtomicI64, batch: &[JetstreamEvent]) {
    if let Some(t) = batch.iter().rev().map(jetstream_time_us).find(|&t| t > 0) {
        cursor.store(t, Ordering::SeqCst);
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
        assert_eq!(cfg.batch_size, 50);
        assert_eq!(cfg.batch_timeout, Duration::from_millis(500));
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
        assert_eq!(cfg.batch_size, 50);
        assert_eq!(cfg.batch_timeout, Duration::from_millis(500));
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
    fn config_with_batch_size() {
        let cfg = Config::new("wss://example.com").with_batch_size(100);
        assert_eq!(cfg.batch_size, 100);
    }

    #[test]
    fn config_with_batch_timeout() {
        let cfg = Config::new("wss://example.com").with_batch_timeout(Duration::from_secs(2));
        assert_eq!(cfg.batch_timeout, Duration::from_secs(2));
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

    #[test]
    fn update_firehose_cursor_finds_last_seq() {
        let cursor = AtomicI64::new(-1);
        let batch = vec![
            Event::Identity {
                did: ratproto_syntax::Did::default(),
                seq: 10,
                handle: None,
            },
            Event::Identity {
                did: ratproto_syntax::Did::default(),
                seq: 20,
                handle: None,
            },
        ];
        update_firehose_cursor(&cursor, &batch);
        assert_eq!(cursor.load(Ordering::SeqCst), 20);
    }

    #[test]
    fn update_jetstream_cursor_finds_last_time_us() {
        let cursor = AtomicI64::new(-1);
        let batch = vec![
            JetstreamEvent::Identity {
                did: ratproto_syntax::Did::default(),
                time_us: 100,
            },
            JetstreamEvent::Identity {
                did: ratproto_syntax::Did::default(),
                time_us: 200,
            },
        ];
        update_jetstream_cursor(&cursor, &batch);
        assert_eq!(cursor.load(Ordering::SeqCst), 200);
    }
}
