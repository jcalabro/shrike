//! Browser WebSocket implementation of the streaming client.
//!
//! Browsers own the WebSocket handshake, so custom headers (including
//! `User-Agent`) are intentionally ignored. Cursor and filter semantics match
//! the native client.

use std::cell::Cell;
use std::rc::Rc;
use std::time::Duration;

use futures::future::{Either, select};
use futures::stream::{SplitStream, Stream};
use futures::{FutureExt, StreamExt, pin_mut};
use gloo_net::websocket::futures::WebSocket;
use gloo_net::websocket::{Message, WebSocketError};

use crate::streaming::event::Event;
use crate::streaming::jetstream::JetstreamEvent;
use crate::streaming::reconnect::BackoffPolicy;
use crate::streaming::{StreamError, parse_firehose_frame, parse_jetstream_message};

type WsStream = SplitStream<WebSocket>;

/// Configuration for a browser streaming client.
#[derive(Default)]
pub struct Config {
    /// WebSocket URL.
    pub url: String,
    /// Starting cursor (sequence number or Jetstream `time_us`).
    pub cursor: Option<i64>,
    /// Reconnection backoff policy.
    pub backoff: Option<BackoffPolicy>,
    /// Maximum accepted message size. The default is 2 MiB.
    pub max_message_size: Option<usize>,
    /// Ignored in browsers, which prohibit setting `User-Agent`.
    pub user_agent: Option<String>,
    /// Jetstream collection filters.
    pub collections: Option<Vec<String>>,
    /// Jetstream DID filters.
    pub dids: Option<Vec<String>>,
    /// Maximum events per batch. The default is 50.
    pub batch_size: Option<usize>,
    /// Maximum batch latency. The default is 500ms.
    pub batch_timeout: Option<Duration>,
}

/// Browser WebSocket client for firehose and Jetstream subscriptions.
pub struct Client {
    url: String,
    collections: Option<Vec<String>>,
    dids: Option<Vec<String>>,
    backoff: BackoffPolicy,
    max_message_size: usize,
    batch_size: usize,
    batch_timeout: Duration,
    cursor: Rc<Cell<i64>>,
}

struct State<E> {
    ws: Option<WsStream>,
    attempt: u32,
    batch: Vec<E>,
    pending_error: Option<StreamError>,
    deadline_millis: Option<u64>,
}

impl<E> State<E> {
    fn new(capacity: usize) -> Self {
        Self {
            ws: None,
            attempt: 0,
            batch: Vec::with_capacity(capacity),
            pending_error: None,
            deadline_millis: None,
        }
    }
}

impl Client {
    /// Create a client. The connection is opened lazily by a stream method.
    pub fn new(config: Config) -> Self {
        Self {
            url: config.url,
            collections: config.collections,
            dids: config.dids,
            backoff: config.backoff.unwrap_or_default(),
            max_message_size: config.max_message_size.unwrap_or(2 * 1024 * 1024),
            batch_size: config.batch_size.unwrap_or(50).max(1),
            batch_timeout: config.batch_timeout.unwrap_or(Duration::from_millis(500)),
            cursor: Rc::new(Cell::new(config.cursor.unwrap_or(-1))),
        }
    }

    /// Return the last delivered cursor, if one has been observed.
    pub fn cursor(&self) -> Option<i64> {
        let cursor = self.cursor.get();
        (cursor >= 0).then_some(cursor)
    }

    /// Connect to a CBOR firehose or label stream.
    pub fn subscribe(&self) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        let cursor = Rc::clone(&self.cursor);
        futures::stream::unfold(State::new(self.batch_size), move |mut state| {
            let cursor = Rc::clone(&cursor);
            async move {
                if let Some(error) = state.pending_error.take() {
                    return Some((Err(error), state));
                }

                loop {
                    if state.ws.is_none() {
                        match connect_ws(&self.url, cursor.get(), &self.collections, &self.dids) {
                            Ok(ws) => {
                                state.ws = Some(ws);
                                state.attempt = 0;
                            }
                            Err(error) => {
                                let delay = self.backoff.delay(state.attempt);
                                state.attempt = state.attempt.saturating_add(1);
                                crate::platform::sleep(delay).await;
                                return Some((Err(error), state));
                            }
                        }
                    }

                    let Some(mut ws) = state.ws.take() else {
                        continue;
                    };
                    match next_message(&mut ws, &mut state.deadline_millis).await {
                        Next::Timeout => {
                            state.ws = Some(ws);
                            if !state.batch.is_empty() {
                                let batch = std::mem::take(&mut state.batch);
                                update_firehose_cursor(&cursor, &batch);
                                return Some((Ok(batch), state));
                            }
                        }
                        Next::Message(Some(Ok(Message::Bytes(bytes)))) => {
                            state.ws = Some(ws);
                            if bytes.len() > self.max_message_size {
                                let error = StreamError::WebSocket(
                                    "message exceeds configured size limit".into(),
                                );
                                return Some(match flush_before_error(&mut state, error) {
                                    Ok(batch) => {
                                        update_firehose_cursor(&cursor, &batch);
                                        (Ok(batch), state)
                                    }
                                    Err(error) => (Err(error), state),
                                });
                            }
                            match parse_firehose_frame(&bytes) {
                                Ok(event) => {
                                    state.batch.push(event);
                                    start_deadline(&mut state.deadline_millis, self.batch_timeout);
                                    if state.batch.len() >= self.batch_size {
                                        state.deadline_millis = None;
                                        let batch = std::mem::take(&mut state.batch);
                                        update_firehose_cursor(&cursor, &batch);
                                        return Some((Ok(batch), state));
                                    }
                                }
                                Err(StreamError::UnknownType(_)) => {}
                                Err(error) => {
                                    return Some(match flush_before_error(&mut state, error) {
                                        Ok(batch) => {
                                            update_firehose_cursor(&cursor, &batch);
                                            (Ok(batch), state)
                                        }
                                        Err(error) => (Err(error), state),
                                    });
                                }
                            }
                        }
                        Next::Message(Some(Ok(Message::Text(_)))) => {
                            state.ws = Some(ws);
                        }
                        Next::Message(Some(Err(error))) => {
                            let error = websocket_error(error);
                            return Some(match flush_before_error(&mut state, error) {
                                Ok(batch) => {
                                    update_firehose_cursor(&cursor, &batch);
                                    (Ok(batch), state)
                                }
                                Err(error) => (Err(error), state),
                            });
                        }
                        Next::Message(None) => {
                            if !state.batch.is_empty() {
                                state.deadline_millis = None;
                                let batch = std::mem::take(&mut state.batch);
                                update_firehose_cursor(&cursor, &batch);
                                return Some((Ok(batch), state));
                            }
                            reconnect_delay(&mut state, self.backoff).await;
                        }
                    }
                }
            }
        })
    }

    /// Connect to a JSON Jetstream stream.
    pub fn jetstream(&self) -> impl Stream<Item = Result<Vec<JetstreamEvent>, StreamError>> + '_ {
        let cursor = Rc::clone(&self.cursor);
        futures::stream::unfold(State::new(self.batch_size), move |mut state| {
            let cursor = Rc::clone(&cursor);
            async move {
                if let Some(error) = state.pending_error.take() {
                    return Some((Err(error), state));
                }

                loop {
                    if state.ws.is_none() {
                        match connect_ws(&self.url, cursor.get(), &self.collections, &self.dids) {
                            Ok(ws) => {
                                state.ws = Some(ws);
                                state.attempt = 0;
                            }
                            Err(error) => {
                                let delay = self.backoff.delay(state.attempt);
                                state.attempt = state.attempt.saturating_add(1);
                                crate::platform::sleep(delay).await;
                                return Some((Err(error), state));
                            }
                        }
                    }

                    let Some(mut ws) = state.ws.take() else {
                        continue;
                    };
                    match next_message(&mut ws, &mut state.deadline_millis).await {
                        Next::Timeout => {
                            state.ws = Some(ws);
                            if !state.batch.is_empty() {
                                let batch = std::mem::take(&mut state.batch);
                                update_jetstream_cursor(&cursor, &batch);
                                return Some((Ok(batch), state));
                            }
                        }
                        Next::Message(Some(Ok(Message::Text(text)))) => {
                            state.ws = Some(ws);
                            if text.len() > self.max_message_size {
                                let error = StreamError::WebSocket(
                                    "message exceeds configured size limit".into(),
                                );
                                return Some(match flush_before_error(&mut state, error) {
                                    Ok(batch) => {
                                        update_jetstream_cursor(&cursor, &batch);
                                        (Ok(batch), state)
                                    }
                                    Err(error) => (Err(error), state),
                                });
                            }
                            match parse_jetstream_message(&text) {
                                Ok(event) => {
                                    state.batch.push(event);
                                    start_deadline(&mut state.deadline_millis, self.batch_timeout);
                                    if state.batch.len() >= self.batch_size {
                                        state.deadline_millis = None;
                                        let batch = std::mem::take(&mut state.batch);
                                        update_jetstream_cursor(&cursor, &batch);
                                        return Some((Ok(batch), state));
                                    }
                                }
                                Err(error) => {
                                    return Some(match flush_before_error(&mut state, error) {
                                        Ok(batch) => {
                                            update_jetstream_cursor(&cursor, &batch);
                                            (Ok(batch), state)
                                        }
                                        Err(error) => (Err(error), state),
                                    });
                                }
                            }
                        }
                        Next::Message(Some(Ok(Message::Bytes(_)))) => {
                            state.ws = Some(ws);
                        }
                        Next::Message(Some(Err(error))) => {
                            let error = websocket_error(error);
                            return Some(match flush_before_error(&mut state, error) {
                                Ok(batch) => {
                                    update_jetstream_cursor(&cursor, &batch);
                                    (Ok(batch), state)
                                }
                                Err(error) => (Err(error), state),
                            });
                        }
                        Next::Message(None) => {
                            if !state.batch.is_empty() {
                                state.deadline_millis = None;
                                let batch = std::mem::take(&mut state.batch);
                                update_jetstream_cursor(&cursor, &batch);
                                return Some((Ok(batch), state));
                            }
                            reconnect_delay(&mut state, self.backoff).await;
                        }
                    }
                }
            }
        })
    }
}

enum Next {
    Message(Option<Result<Message, WebSocketError>>),
    Timeout,
}

async fn next_message(ws: &mut WsStream, deadline: &mut Option<u64>) -> Next {
    let Some(deadline_millis) = *deadline else {
        return Next::Message(ws.next().await);
    };
    let remaining = deadline_millis.saturating_sub(crate::platform::unix_time_millis());
    let message = ws.next().fuse();
    let timer = crate::platform::sleep(Duration::from_millis(remaining)).fuse();
    pin_mut!(message, timer);
    match select(message, timer).await {
        Either::Left((message, _)) => Next::Message(message),
        Either::Right(((), _)) => {
            *deadline = None;
            Next::Timeout
        }
    }
}

fn connect_ws(
    base_url: &str,
    cursor: i64,
    collections: &Option<Vec<String>>,
    dids: &Option<Vec<String>>,
) -> Result<WsStream, StreamError> {
    let mut url = url::Url::parse(base_url)
        .map_err(|error| StreamError::WebSocket(format!("invalid URL: {error}")))?;
    if cursor > 0 {
        url.query_pairs_mut()
            .append_pair("cursor", &cursor.to_string());
    }
    if let Some(collections) = collections {
        for collection in collections {
            url.query_pairs_mut()
                .append_pair("wantedCollections", collection);
        }
    }
    if let Some(dids) = dids {
        for did in dids {
            url.query_pairs_mut().append_pair("wantedDids", did);
        }
    }
    let ws = WebSocket::open(url.as_str())
        .map_err(|error| StreamError::WebSocket(format!("connection failed: {error}")))?;
    let (_write, read) = ws.split();
    Ok(read)
}

fn start_deadline(deadline: &mut Option<u64>, timeout: Duration) {
    if deadline.is_none() {
        let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
        *deadline = Some(crate::platform::unix_time_millis().saturating_add(millis));
    }
}

fn flush_before_error<E>(state: &mut State<E>, error: StreamError) -> Result<Vec<E>, StreamError> {
    state.deadline_millis = None;
    if state.batch.is_empty() {
        Err(error)
    } else {
        state.pending_error = Some(error);
        Ok(std::mem::take(&mut state.batch))
    }
}

async fn reconnect_delay<E>(state: &mut State<E>, backoff: BackoffPolicy) {
    let delay = backoff.delay(state.attempt);
    state.attempt = state.attempt.saturating_add(1);
    crate::platform::sleep(delay).await;
}

fn websocket_error(error: WebSocketError) -> StreamError {
    StreamError::WebSocket(error.to_string())
}

fn update_firehose_cursor(cursor: &Cell<i64>, batch: &[Event]) {
    if let Some(seq) = batch.iter().map(event_seq).filter(|seq| *seq > 0).max() {
        cursor.set(cursor.get().max(seq));
    }
}

fn event_seq(event: &Event) -> i64 {
    match event {
        Event::Commit { seq, .. }
        | Event::Identity { seq, .. }
        | Event::Account { seq, .. }
        | Event::Labels { seq, .. } => *seq,
    }
}

fn update_jetstream_cursor(cursor: &Cell<i64>, batch: &[JetstreamEvent]) {
    if let Some(time_us) = batch
        .iter()
        .map(jetstream_time_us)
        .filter(|time| *time > 0)
        .max()
    {
        cursor.set(cursor.get().max(time_us));
    }
}

fn jetstream_time_us(event: &JetstreamEvent) -> i64 {
    match event {
        JetstreamEvent::Commit { time_us, .. }
        | JetstreamEvent::Identity { time_us, .. }
        | JetstreamEvent::Account { time_us, .. } => *time_us,
    }
}
