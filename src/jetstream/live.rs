//! The proposal-0015 live tail: WebSocket dial, framing, dedup, reconnect, and
//! optional dictionary zstd, written against portable transport traits.
//!
//! This module owns the *live* half of a Jetstream v2 stream. It dials
//! `subscribeEvents`, reads proposal-0015 frames (text, or binary zstd frames
//! decoded against a fetched dictionary), deduplicates by the Jetstream
//! sequence, batches matching events for the consumer, and reconnects with
//! bounded exponential backoff across disconnects — resuming inclusively from
//! the last processed sequence. It mirrors the control flow of the Go client's
//! `liveConsumer` while speaking the plan's wire contract: the path
//! `/xrpc/network.bsky.jetstream.subscribeEvents`, the `xrpc.v1.json`
//! subprotocol, repeated `kinds`/`dids`/`collections` query parameters, and a
//! `cursor` — never the `maxMessageSizeBytes` parameter, which would silently
//! drop oversized events and markers.
//!
//! Framing itself lives in [`super::event::parse_live_frame`]; this module
//! drives it and layers the connection lifecycle on top. The WebSocket and
//! dictionary-fetch transports are abstracted behind [`WsTransport`] and
//! [`DictionarySource`] so the same run loop serves the native
//! (`tokio-tungstenite`) and browser (`gloo-net`) adapters and can be driven by
//! a deterministic in-memory transport in tests.
//!
//! # Error handling
//!
//! Terminal (fatal) errors — a frame from a non-v2 endpoint, an unusable
//! subprotocol, or `CursorTooOld` on this credential-free live tail — are
//! delivered to the consumer as a final `Err` item, in order after any buffered
//! batch, and then the tail stops. Recoverable conditions (a clean or dirty
//! disconnect, a reconnectable protocol error such as `ConsumerTooSlow`, a
//! per-frame malformed event, or a dictionary/decompression setup failure) are
//! handled internally by reconnecting or skipping, and are never surfaced as
//! stream errors. Advisory `#info` frames are delivered as [`Delivery::Info`].
//!
//! The archive bearer key is never attached to the dictionary fetch or the
//! WebSocket upgrade: both endpoints are unauthenticated.

use core::future::Future;
use core::time::Duration;

use futures::future::{Either, select};

use super::archive::{BodyReadError, parse_xrpc_error, read_body_bounded};
use super::cancel::CancelToken;
use super::compression::{decompress_bounded, parse_dictionary_id};
use super::config::Cursor;
use super::error::{Error, Result};
use super::event::{Batch, Delivery, Event, LiveFrame, parse_live_frame};
use super::filter::Filter;
use super::transport::{HttpRequest, HttpTransport};

/// The XRPC method the live tail subscribes to.
pub const SUBSCRIBE_METHOD: &str = "network.bsky.jetstream.subscribeEvents";
/// The XRPC method that serves the current live zstd dictionary.
pub const DICTIONARY_METHOD: &str = "network.bsky.jetstream.getZstdDictionary";
/// The WebSocket subprotocol the v2 live tail negotiates. An empty server echo
/// (the lexicon default, identical framing) is also accepted.
pub const XRPC_SUBPROTOCOL: &str = "xrpc.v1.json";

/// Go's `defaultLiveReadLimit` (32 MiB): the largest WebSocket message accepted,
/// which also caps the decompressed size of a binary frame.
pub const DEFAULT_LIVE_READ_LIMIT: usize = 32 << 20;
/// The default maximum number of events per delivered batch (Go default).
pub const DEFAULT_MAX_BATCH: usize = 64;
/// The default partial-batch flush delay (Go default): a non-empty batch is
/// flushed after this much quiet even if it has not reached [`DEFAULT_MAX_BATCH`].
pub const DEFAULT_FLUSH_DELAY: Duration = Duration::from_millis(20);
/// The default base reconnect backoff (Go default).
pub const DEFAULT_BACKOFF_BASE: Duration = Duration::from_millis(250);
/// The default maximum reconnect backoff (Go default).
pub const DEFAULT_BACKOFF_MAX: Duration = Duration::from_secs(30);

/// A bounded exponential reconnect backoff. Deterministic (no jitter) so tests
/// under a paused clock are reproducible.
#[derive(Debug, Clone, Copy)]
pub struct LiveBackoff {
    /// The delay before the first reconnect; doubles each consecutive failure.
    pub base_delay: Duration,
    /// The ceiling on the computed delay.
    pub max_delay: Duration,
}

impl LiveBackoff {
    /// The delay before the reconnect with 0-based index `n`: `base * 2^n`,
    /// saturating and capped at `max_delay`.
    pub fn delay(&self, n: u32) -> Duration {
        let shift = n.min(16);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        self.base_delay.saturating_mul(factor).min(self.max_delay)
    }
}

impl Default for LiveBackoff {
    fn default() -> Self {
        LiveBackoff {
            base_delay: DEFAULT_BACKOFF_BASE,
            max_delay: DEFAULT_BACKOFF_MAX,
        }
    }
}

/// Where a live subscription starts.
#[derive(Debug, Clone, Copy)]
pub enum LiveCursor {
    /// Start at the current tip: no `cursor` parameter is sent. This is a
    /// distinct state from a sequence of `0` (which would replay everything).
    Tip,
    /// Resume inclusively from a sequence or timestamp [`Cursor`].
    Resume(Cursor),
}

/// The live tail's configuration. Built and validated by the client builder in a
/// later milestone; the defaults here match the Go client.
pub struct LiveConfig {
    /// The normalized target authority (see [`super::normalize_host`]).
    pub host: String,
    /// Whether to dial over `wss` (true) or `ws` (false).
    pub secure: bool,
    /// The subscription filter (query parameters and post-decode re-check).
    pub filter: Filter,
    /// Where to start.
    pub cursor: LiveCursor,
    /// Whether to negotiate dictionary zstd compression (enabled by default).
    pub compression: bool,
    /// The read limit: the largest WebSocket message and decompressed frame.
    pub read_limit: usize,
    /// The maximum number of events per delivered batch.
    pub max_batch: usize,
    /// The partial-batch flush delay.
    pub flush_delay: Duration,
    /// The reconnect backoff policy.
    pub backoff: LiveBackoff,
}

impl LiveConfig {
    /// A config for `host` with the Go-matching defaults, an empty (match-all)
    /// filter, and tip-start.
    pub fn new(host: impl Into<String>, secure: bool) -> Self {
        LiveConfig {
            host: host.into(),
            secure,
            filter: Filter::new(),
            cursor: LiveCursor::Tip,
            compression: true,
            read_limit: DEFAULT_LIVE_READ_LIMIT,
            max_batch: DEFAULT_MAX_BATCH,
            flush_delay: DEFAULT_FLUSH_DELAY,
            backoff: LiveBackoff::default(),
        }
    }

    /// Validate the parts that must hold before any I/O: the filter and, when a
    /// resume cursor is set, its live-domain bounds.
    fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(Error::InvalidConfig("live host is empty"));
        }
        if self.max_batch == 0 {
            return Err(Error::InvalidConfig("max_batch must be >= 1"));
        }
        if self.read_limit == 0 {
            return Err(Error::InvalidConfig("read_limit must be >= 1"));
        }
        self.filter.validate()?;
        if let LiveCursor::Resume(cursor) = self.cursor {
            cursor.validate_live()?;
        }
        Ok(())
    }
}

/// One WebSocket application message: a UTF-8 text frame or a binary frame.
///
/// Control frames (ping, pong, close) are handled inside the transport adapter
/// and never surface here; a clean close is reported as `Ok(None)` from
/// [`WsConnection::read`].
#[derive(Debug, Clone)]
pub enum WsMessage {
    /// A text frame: proposal-0015 JSON.
    Text(Vec<u8>),
    /// A binary frame: one complete zstd frame (on a compressed connection).
    Binary(Vec<u8>),
}

/// A recoverable read failure on an established connection. The tail flushes any
/// pending batch and reconnects; the message is bounded and redacted.
#[derive(Debug, thiserror::Error)]
#[error("live read error: {message}")]
pub struct WsError {
    message: String,
}

impl WsError {
    /// Construct a read error, bounding the (already redacted) message.
    pub fn new(message: impl Into<String>) -> Self {
        let mut message = message.into();
        super::error::truncate_on_char_boundary(
            &mut message,
            super::error::MAX_PROTOCOL_MESSAGE_LEN,
        );
        WsError { message }
    }
}

/// The failure modes of a WebSocket dial.
#[derive(Debug)]
pub enum DialError {
    /// A transport-level failure establishing the connection. Recoverable: the
    /// tail reconnects after backoff.
    Transport(String),
    /// The server rejected the upgrade with an HTTP status and an optional body.
    /// For XRPC this carries an error name (e.g. `CursorTooOld`,
    /// `UnknownZstdDictionary`); the body is parsed by the tail.
    Http {
        /// The HTTP status of the rejection.
        status: u16,
        /// The (bounded) response body, an XRPC error envelope when present.
        body: Vec<u8>,
    },
    /// The server negotiated a subprotocol other than `xrpc.v1.json` or an empty
    /// echo. Fatal: the framing contract cannot be assumed.
    Subprotocol(String),
    /// The dial was cancelled.
    Canceled,
}

/// An established live WebSocket connection.
///
/// The adapter answers server pings transparently and surfaces only application
/// messages. [`WsConnection::read`] resolves to `Ok(Some(_))` for each message,
/// `Ok(None)` on a clean close, and `Err(_)` on a mid-stream failure. Neither
/// future is required to be `Send`, so the browser adapter (whose socket is
/// `!Send`) satisfies the trait as-is.
pub trait WsConnection {
    /// Read the next application message, or `None` at a clean close.
    fn read(&mut self) -> impl Future<Output = core::result::Result<Option<WsMessage>, WsError>>;

    /// Close the connection. Best-effort; errors are ignored.
    fn close(&mut self) -> impl Future<Output = ()>;
}

/// A transport that dials the live WebSocket.
pub trait WsTransport {
    /// The connection type this transport produces.
    type Conn: WsConnection;

    /// Dial `url`, requesting `subprotocol`, and resolve to a connection or a
    /// [`DialError`]. The adapter must verify the negotiated subprotocol and
    /// surface a pre-upgrade HTTP rejection as [`DialError::Http`].
    fn dial(
        &self,
        url: String,
        subprotocol: &'static str,
    ) -> impl Future<Output = core::result::Result<Self::Conn, DialError>>;
}

/// A source of the live zstd dictionary, fetched unauthenticated.
pub trait DictionarySource {
    /// Fetch the dictionary with the given `id`, or the current dictionary when
    /// `id` is `None`. Returns the raw structured-dictionary bytes.
    fn fetch(&self, id: Option<u32>) -> impl Future<Output = Result<Vec<u8>>>;
}

/// The largest zstd dictionary accepted from `getZstdDictionary`. Real
/// dictionaries are small (the Go server trains ~100 KiB); this cap bounds a
/// hostile or misconfigured response far above any legitimate dictionary while
/// keeping the failure recoverable (the tail degrades to uncompressed).
pub const MAX_DICTIONARY_BYTES: u64 = 8 << 20;

/// The largest error body read from a rejected dictionary fetch before parsing
/// the XRPC envelope. Error envelopes are tiny; this only bounds a hostile body.
const MAX_DICT_ERROR_BODY: u64 = 64 << 10;

/// A [`DictionarySource`] that fetches the live zstd dictionary over HTTP.
///
/// The fetch is **unauthenticated**: `getZstdDictionary` is a public,
/// CDN-cacheable endpoint, and the archive bearer key is never attached to it.
/// The request carries no authorization header by construction. Any failure
/// (transport, non-2xx, oversized body, or an unparsable dictionary) is returned
/// as an error; the live tail treats every dictionary failure as a safe,
/// recoverable degrade to uncompressed frames.
pub struct HttpDictionarySource<T> {
    transport: T,
    host: String,
    secure: bool,
    read_limit: u64,
    cancel: CancelToken,
}

impl<T: HttpTransport> HttpDictionarySource<T> {
    /// Build a source that fetches from `host` over `transport`, dialing `https`
    /// when `secure`. The dictionary endpoint is unauthenticated, so cleartext is
    /// permitted here even off loopback — no secret is exposed.
    pub fn new(transport: T, host: impl Into<String>, secure: bool, cancel: CancelToken) -> Self {
        HttpDictionarySource {
            transport,
            host: host.into(),
            secure,
            read_limit: MAX_DICTIONARY_BYTES,
            cancel,
        }
    }

    /// The `getZstdDictionary` URL, with an `id` query parameter when a specific
    /// dictionary is requested (omitted to fetch the server's current one).
    fn url(&self, id: Option<u32>) -> Result<String> {
        let scheme = if self.secure { "https" } else { "http" };
        let base = format!("{scheme}://{}/xrpc/{DICTIONARY_METHOD}", self.host);
        let mut url =
            url::Url::parse(&base).map_err(|_| Error::InvalidConfig("invalid dictionary host"))?;
        if let Some(id) = id {
            url.query_pairs_mut().append_pair("id", &id.to_string());
        }
        Ok(url.into())
    }
}

impl<T: HttpTransport> DictionarySource for HttpDictionarySource<T> {
    async fn fetch(&self, id: Option<u32>) -> Result<Vec<u8>> {
        let url = self.url(id)?;
        // No authorization header: the endpoint is unauthenticated.
        let response = self.transport.send(HttpRequest::get(url)).await?;
        if !response.is_success() {
            let status = response.status;
            let body = read_body_bounded(response.body, MAX_DICT_ERROR_BODY, &self.cancel)
                .await
                .unwrap_or_default();
            return Err(parse_xrpc_error(&body, status));
        }
        match read_body_bounded(response.body, self.read_limit, &self.cancel).await {
            Ok(bytes) => Ok(bytes),
            Err(BodyReadError::TooLarge) => {
                Err(Error::InvalidDictionary("dictionary exceeds size limit"))
            }
            Err(BodyReadError::Canceled) => Err(Error::Canceled),
            Err(BodyReadError::Transport(err)) => Err(err.into()),
        }
    }
}

/// The consumer's delivery sink. `deliver` resolves to `false` when the consumer
/// has gone away, at which point the tail shuts down cleanly. An `Err` item is
/// always terminal and is the last thing delivered.
pub trait DeliverySink {
    /// Deliver one stream item. Returns `false` to stop the tail.
    fn deliver(
        &mut self,
        item: core::result::Result<Delivery, Error>,
    ) -> impl Future<Output = bool>;
}

/// Build the `subscribeEvents` WebSocket URL with repeated filter parameters.
///
/// `wire_cursor` is the signed cursor value to send (omitted for a from-tip
/// start), and `dict_id` the negotiated dictionary ID when compression is
/// active. DIDs and collections are sorted so the URL is deterministic for
/// tests; parameter order is not significant to the server.
pub fn subscribe_url(
    host: &str,
    secure: bool,
    filter: &Filter,
    wire_cursor: Option<i64>,
    dict_id: Option<u32>,
) -> Result<String> {
    let scheme = if secure { "wss" } else { "ws" };
    let base = format!("{scheme}://{host}/xrpc/{SUBSCRIBE_METHOD}");
    let mut url = url::Url::parse(&base).map_err(|_| Error::InvalidConfig("invalid live host"))?;
    {
        let mut query = url.query_pairs_mut();
        for kind in filter.kind_wire_tokens() {
            query.append_pair("kinds", kind);
        }
        let mut dids: Vec<&str> = filter.did_wire_tokens().collect();
        dids.sort_unstable();
        for did in dids {
            query.append_pair("dids", did);
        }
        let mut collections: Vec<String> = filter.collection_wire_tokens().collect();
        collections.sort_unstable();
        for collection in &collections {
            query.append_pair("collections", collection);
        }
        if let Some(cursor) = wire_cursor {
            query.append_pair("cursor", &cursor.to_string());
        }
        if let Some(id) = dict_id {
            query.append_pair("zstdDictionary", &id.to_string());
        }
    }
    Ok(url.into())
}

/// The negotiated compression state of the tail.
enum DictState {
    /// Compression is off — either disabled by config or permanently disabled
    /// after a dictionary failure.
    Off,
    /// Compression is on with the given dictionary ID and raw bytes.
    Active { id: u32, bytes: Vec<u8> },
}

impl DictState {
    /// The dictionary ID to send on dial, if any.
    fn id(&self) -> Option<u32> {
        match self {
            DictState::Off => None,
            DictState::Active { id, .. } => Some(*id),
        }
    }

    /// The dictionary bytes for decoding a binary frame, if compression is on.
    fn bytes(&self) -> Option<&[u8]> {
        match self {
            DictState::Off => None,
            DictState::Active { bytes, .. } => Some(bytes),
        }
    }
}

/// The cross-session dedup and resume state.
struct StreamState {
    /// The highest processed sequence. A frame with `seq <= last_seq` is a
    /// duplicate (the server replays inclusively on reconnect) and dropped.
    last_seq: u64,
    /// Whether any event has advanced `last_seq` past its initial value; once
    /// true, reconnects resume from `last_seq` rather than the configured cursor.
    seen_any: bool,
}

/// What the tail should do after a session ends.
enum SessionOutcome {
    /// Reconnect after applying backoff (reset when the session progressed).
    Reconnect,
    /// Reconnect immediately with no backoff (e.g. after a dictionary rotation).
    ReconnectNow,
    /// Stop the tail. `Ok(())` on clean cancellation or after a terminal error
    /// was already delivered.
    Stop,
}

/// The result of one connected session.
struct SessionResult {
    /// What to do next.
    outcome: SessionOutcome,
    /// Whether the session advanced the cursor (drives backoff reset).
    progressed: bool,
}

/// The live tail. Generic over the WebSocket transport and dictionary source so
/// the same run loop serves native, browser, and test transports.
pub struct LiveConsumer<W, D> {
    ws: W,
    dict: D,
    config: LiveConfig,
    cancel: CancelToken,
}

impl<W, D> LiveConsumer<W, D>
where
    W: WsTransport,
    D: DictionarySource,
{
    /// Build a live consumer, validating the configuration before any I/O.
    pub fn new(ws: W, dict: D, config: LiveConfig, cancel: CancelToken) -> Result<Self> {
        config.validate()?;
        Ok(LiveConsumer {
            ws,
            dict,
            config,
            cancel,
        })
    }

    /// Run the live tail, delivering ordered, deduplicated batches (and advisory
    /// `#info` frames) to `sink` until cancellation, a terminal error, or the
    /// consumer going away. A terminal error is delivered as a final `Err` item
    /// before the loop returns.
    pub async fn run<S: DeliverySink>(self, sink: &mut S) -> Result<()> {
        let mut state = StreamState {
            last_seq: initial_last_seq(&self.config.cursor),
            seen_any: false,
        };
        let mut dict = self.initial_dict_state().await;
        let mut backoff_n: u32 = 0;

        loop {
            if self.cancel.is_cancelled() {
                return Ok(());
            }

            let conn = match self.dial(&state, &dict, sink).await {
                DialAttempt::Connected(conn) => conn,
                DialAttempt::Stop => return Ok(()),
                DialAttempt::Reconnect => {
                    if !self
                        .backoff_sleep(self.config.backoff.delay(backoff_n))
                        .await
                    {
                        return Ok(());
                    }
                    backoff_n = backoff_n.saturating_add(1);
                    continue;
                }
                DialAttempt::RecoverDict => {
                    // A pre-upgrade dictionary rejection: refetch the current
                    // dictionary (or degrade to uncompressed) and redial at once.
                    recover_dict(&self.dict, &mut dict).await;
                    backoff_n = 0;
                    continue;
                }
            };

            let result = self.session(conn, &mut state, &mut dict, sink).await;
            match result.outcome {
                SessionOutcome::Stop => return Ok(()),
                SessionOutcome::ReconnectNow => {
                    backoff_n = 0;
                }
                SessionOutcome::Reconnect => {
                    if result.progressed {
                        backoff_n = 0;
                    }
                    if !self
                        .backoff_sleep(self.config.backoff.delay(backoff_n))
                        .await
                    {
                        return Ok(());
                    }
                    backoff_n = backoff_n.saturating_add(1);
                }
            }
        }
    }

    /// Fetch and validate the starting dictionary state.
    async fn initial_dict_state(&self) -> DictState {
        if !self.config.compression {
            return DictState::Off;
        }
        fetch_dict_state(&self.dict, None).await
    }

    /// Attempt one dial, mapping a pre-upgrade rejection or dictionary rotation
    /// onto the next action. Terminal errors are delivered to `sink` here.
    async fn dial<S: DeliverySink>(
        &self,
        state: &StreamState,
        dict: &DictState,
        sink: &mut S,
    ) -> DialAttempt<W::Conn> {
        let wire_cursor = wire_cursor(&self.config.cursor, state);
        let url = match subscribe_url(
            &self.config.host,
            self.config.secure,
            &self.config.filter,
            wire_cursor,
            dict.id(),
        ) {
            Ok(url) => url,
            Err(err) => {
                sink.deliver(Err(err)).await;
                return DialAttempt::Stop;
            }
        };

        let dial = self.ws.dial(url, XRPC_SUBPROTOCOL);
        let cancelled = self.cancel.cancelled();
        futures::pin_mut!(dial, cancelled);
        match select(dial, cancelled).await {
            Either::Right(_) => DialAttempt::Stop,
            Either::Left((Ok(conn), _)) => DialAttempt::Connected(conn),
            Either::Left((Err(err), _)) => self.handle_dial_error(err, sink).await,
        }
    }

    /// Map a [`DialError`] onto the next action. A pre-upgrade dictionary
    /// rejection yields [`DialAttempt::RecoverDict`], which the run loop resolves
    /// by refetching against the current dictionary state before redialing; a
    /// fatal error is delivered to `sink` here.
    async fn handle_dial_error<S: DeliverySink>(
        &self,
        err: DialError,
        sink: &mut S,
    ) -> DialAttempt<W::Conn> {
        match err {
            DialError::Canceled => DialAttempt::Stop,
            DialError::Transport(_) => DialAttempt::Reconnect,
            DialError::Subprotocol(_) => {
                sink.deliver(Err(Error::Capability(
                    "server negotiated an unsupported subprotocol",
                )))
                .await;
                DialAttempt::Stop
            }
            DialError::Http { status, body } => {
                let err = super::archive::parse_xrpc_error(&body, status);
                match classify_protocol(&err) {
                    ProtoAction::Fatal => {
                        sink.deliver(Err(err)).await;
                        DialAttempt::Stop
                    }
                    ProtoAction::DictRotation => DialAttempt::RecoverDict,
                    ProtoAction::Reconnect => DialAttempt::Reconnect,
                }
            }
        }
    }

    /// Read one connected session to its end.
    async fn session<S: DeliverySink>(
        &self,
        mut conn: W::Conn,
        state: &mut StreamState,
        dict: &mut DictState,
        sink: &mut S,
    ) -> SessionResult {
        let mut batch: Vec<Event> = Vec::new();
        let mut progressed = false;

        loop {
            let timer = if batch.is_empty() {
                None
            } else {
                Some(self.config.flush_delay)
            };

            match next_read(&mut conn, &self.cancel, timer).await {
                ReadStep::Cancelled => {
                    deliver_batch(&mut batch, sink).await;
                    conn.close().await;
                    return SessionResult {
                        outcome: SessionOutcome::Stop,
                        progressed,
                    };
                }
                ReadStep::FlushTimer => {
                    if !deliver_batch(&mut batch, sink).await {
                        conn.close().await;
                        return SessionResult {
                            outcome: SessionOutcome::Stop,
                            progressed,
                        };
                    }
                }
                ReadStep::Closed | ReadStep::Failed => {
                    deliver_batch(&mut batch, sink).await;
                    conn.close().await;
                    return SessionResult {
                        outcome: SessionOutcome::Reconnect,
                        progressed,
                    };
                }
                ReadStep::Message(message) => {
                    match decode_message(message, dict, self.config.read_limit) {
                        MsgDecode::Skip => {}
                        MsgDecode::StreamError => {
                            deliver_batch(&mut batch, sink).await;
                            conn.close().await;
                            return SessionResult {
                                outcome: SessionOutcome::Reconnect,
                                progressed,
                            };
                        }
                        MsgDecode::Frame(LiveFrame::Event(event)) => {
                            match self
                                .accept_event(event, state, &mut batch, &mut progressed, sink)
                                .await
                            {
                                EventStep::Continue => {}
                                EventStep::Stop => {
                                    conn.close().await;
                                    return SessionResult {
                                        outcome: SessionOutcome::Stop,
                                        progressed,
                                    };
                                }
                            }
                        }
                        MsgDecode::Frame(LiveFrame::Info(info)) => {
                            if !deliver_batch(&mut batch, sink).await
                                || !sink.deliver(Ok(Delivery::Info(info))).await
                            {
                                conn.close().await;
                                return SessionResult {
                                    outcome: SessionOutcome::Stop,
                                    progressed,
                                };
                            }
                        }
                        MsgDecode::Fatal(err) => {
                            deliver_batch(&mut batch, sink).await;
                            sink.deliver(Err(err)).await;
                            conn.close().await;
                            return SessionResult {
                                outcome: SessionOutcome::Stop,
                                progressed,
                            };
                        }
                        MsgDecode::Proto(err) => {
                            deliver_batch(&mut batch, sink).await;
                            conn.close().await;
                            return match classify_protocol(&err) {
                                ProtoAction::Fatal => {
                                    sink.deliver(Err(err)).await;
                                    SessionResult {
                                        outcome: SessionOutcome::Stop,
                                        progressed,
                                    }
                                }
                                ProtoAction::DictRotation => {
                                    recover_dict(&self.dict, dict).await;
                                    SessionResult {
                                        outcome: SessionOutcome::ReconnectNow,
                                        progressed,
                                    }
                                }
                                ProtoAction::Reconnect => SessionResult {
                                    outcome: SessionOutcome::Reconnect,
                                    progressed,
                                },
                            };
                        }
                    }
                }
            }
        }
    }

    /// Apply dedup, cursor advance, and filtering to one event, batching it when
    /// it matches and flushing a full batch.
    async fn accept_event<S: DeliverySink>(
        &self,
        event: Event,
        state: &mut StreamState,
        batch: &mut Vec<Event>,
        progressed: &mut bool,
        sink: &mut S,
    ) -> EventStep {
        // Duplicate: the server replays inclusively, so drop anything at or
        // below the high-water mark.
        if event.seq <= state.last_seq {
            return EventStep::Continue;
        }
        state.last_seq = event.seq;
        state.seen_any = true;
        *progressed = true;

        // Advance the cursor for every event, but only deliver those the exact
        // filter admits (the server's coarser query may over-match).
        if !self.config.filter.matches(&event) {
            return EventStep::Continue;
        }
        batch.push(event);
        if batch.len() >= self.config.max_batch && !deliver_batch(batch, sink).await {
            return EventStep::Stop;
        }
        EventStep::Continue
    }

    /// Sleep for `delay`, racing cancellation. Returns `false` if cancelled.
    async fn backoff_sleep(&self, delay: Duration) -> bool {
        if self.cancel.is_cancelled() {
            return false;
        }
        let sleep = crate::platform::sleep(delay);
        let cancelled = self.cancel.cancelled();
        futures::pin_mut!(sleep, cancelled);
        matches!(select(sleep, cancelled).await, Either::Left(_))
    }
}

/// The outcome of a dial attempt, resolved against cancellation and protocol
/// classification.
enum DialAttempt<C> {
    /// A live connection.
    Connected(C),
    /// Reconnect after backoff.
    Reconnect,
    /// A pre-upgrade dictionary rejection: refetch the current dictionary (or
    /// degrade to uncompressed) and reconnect immediately.
    RecoverDict,
    /// Stop the tail.
    Stop,
}

/// Whether an accepted event's handling should continue or stop the tail.
enum EventStep {
    /// Keep reading.
    Continue,
    /// The consumer went away; stop.
    Stop,
}

/// The initial dedup high-water mark for a starting cursor. A sequence resume of
/// `n` must keep `seq == n` (the server replays inclusively), so the mark is
/// `n - 1`; tip and timestamp starts begin at `0`.
fn initial_last_seq(cursor: &LiveCursor) -> u64 {
    match cursor {
        LiveCursor::Tip => 0,
        LiveCursor::Resume(Cursor::Seq(n)) => n.saturating_sub(1),
        LiveCursor::Resume(Cursor::Timestamp(_)) => 0,
    }
}

/// The wire cursor to send on the next dial: the last processed sequence once any
/// event has been seen, otherwise the configured resume value (omitted for tip).
fn wire_cursor(cursor: &LiveCursor, state: &StreamState) -> Option<i64> {
    if state.seen_any {
        return Some(state.last_seq as i64);
    }
    match cursor {
        LiveCursor::Tip => None,
        LiveCursor::Resume(c) => Some(c.to_wire()),
    }
}

/// Fetch the dictionary identified by `id` (or the current one) and validate its
/// structured header, yielding an [`DictState`]. Any failure degrades to
/// uncompressed (`Off`), which is a safe, recoverable fallback.
async fn fetch_dict_state<D: DictionarySource>(source: &D, id: Option<u32>) -> DictState {
    match source.fetch(id).await {
        Ok(bytes) => match parse_dictionary_id(&bytes) {
            Ok(id) => DictState::Active { id, bytes },
            Err(_) => DictState::Off,
        },
        Err(_) => DictState::Off,
    }
}

/// Recover from a rejected dictionary: refetch the current dictionary and adopt
/// it only if it differs from the one just rejected; otherwise fall back to
/// uncompressed for the tail's lifetime.
async fn recover_dict<D: DictionarySource>(source: &D, dict: &mut DictState) {
    let rejected = dict.id();
    let next = fetch_dict_state(source, None).await;
    *dict = match next {
        DictState::Active { id, bytes } if Some(id) != rejected => DictState::Active { id, bytes },
        // Same ID back (or a fetch/parse failure): uncompressed for good.
        _ => DictState::Off,
    };
}

/// How a protocol error name maps onto the tail's next action.
enum ProtoAction {
    /// Terminal for the whole tail (e.g. `CursorTooOld` on a pure-live stream).
    Fatal,
    /// The server rotated its dictionary; refetch and reconnect.
    DictRotation,
    /// Reconnectable (e.g. `ConsumerTooSlow`).
    Reconnect,
}

/// Classify a server error for the credential-free live tail. `CursorTooOld` is
/// fatal here because there is no archive loop to re-enter; the engine layers a
/// different policy when it owns a backfill path. `InvalidFrame` (a non-v2
/// endpoint) is always fatal.
fn classify_protocol(err: &Error) -> ProtoAction {
    match err {
        Error::InvalidFrame(_) => ProtoAction::Fatal,
        Error::Protocol { name, .. } => match name.as_str() {
            "UnknownZstdDictionary" => ProtoAction::DictRotation,
            "CursorTooOld" => ProtoAction::Fatal,
            _ => ProtoAction::Reconnect,
        },
        _ => ProtoAction::Reconnect,
    }
}

/// The decode outcome of one WebSocket message.
enum MsgDecode {
    /// Ignore this message (forward-compatible unknown `$type`, a per-frame
    /// malformed event, or a stray binary frame on an uncompressed connection).
    Skip,
    /// A parsed frame.
    Frame(LiveFrame),
    /// A post-upgrade decompression failure: reconnect.
    StreamError,
    /// A frame from a non-v2 endpoint: fatal.
    Fatal(Error),
    /// A terminal `error` frame; classified by name.
    Proto(Error),
}

/// Decode one WebSocket message into a frame or an action.
fn decode_message(message: WsMessage, dict: &DictState, read_limit: usize) -> MsgDecode {
    match message {
        WsMessage::Text(bytes) => classify_frame(parse_live_frame(&bytes)),
        WsMessage::Binary(bytes) => match dict.bytes() {
            // Uncompressed connection: ignore stray binary frames (Go parity).
            None => MsgDecode::Skip,
            Some(dictionary) => match decompress_bounded(&bytes, read_limit, Some(dictionary)) {
                Ok(json) => classify_frame(parse_live_frame(&json)),
                // A malformed compressed frame after upgrade is a stream error.
                Err(_) => MsgDecode::StreamError,
            },
        },
    }
}

/// Map a [`parse_live_frame`] result onto a [`MsgDecode`]. A per-frame malformed
/// event is dropped (not delivered, cursor not advanced) so its valid siblings
/// on the same connection still flow.
fn classify_frame(parsed: Result<Option<LiveFrame>>) -> MsgDecode {
    match parsed {
        Ok(Some(frame)) => MsgDecode::Frame(frame),
        Ok(None) => MsgDecode::Skip,
        Err(err @ Error::InvalidFrame(_)) => MsgDecode::Fatal(err),
        Err(err @ Error::Protocol { .. }) => MsgDecode::Proto(err),
        // MalformedEvent / InvalidRecord / InvalidTimestamp and any other
        // per-frame error: skip this frame, keep the connection.
        Err(_) => MsgDecode::Skip,
    }
}

/// Flush a pending batch to the sink, clearing it. Returns `false` if the
/// consumer has gone away.
async fn deliver_batch<S: DeliverySink>(batch: &mut Vec<Event>, sink: &mut S) -> bool {
    if batch.is_empty() {
        return true;
    }
    let events = core::mem::take(batch);
    sink.deliver(Ok(Delivery::Batch(Batch::new(events)))).await
}

/// One step of the read loop: a message, a clean close, a read failure, the
/// partial-batch flush timer firing, or cancellation.
enum ReadStep {
    /// An application message.
    Message(WsMessage),
    /// A clean close.
    Closed,
    /// A mid-stream read failure.
    Failed,
    /// The flush timer fired (only armed when a batch is pending).
    FlushTimer,
    /// Cancellation was requested.
    Cancelled,
}

/// Read the next message, racing the (optional) flush timer and cancellation.
async fn next_read<C: WsConnection>(
    conn: &mut C,
    cancel: &CancelToken,
    timer: Option<Duration>,
) -> ReadStep {
    let read = conn.read();
    let cancelled = cancel.cancelled();
    futures::pin_mut!(read, cancelled);

    match timer {
        None => match select(read, cancelled).await {
            Either::Left((result, _)) => classify_read(result),
            Either::Right(_) => ReadStep::Cancelled,
        },
        Some(delay) => {
            let sleep = crate::platform::sleep(delay);
            futures::pin_mut!(sleep);
            // Race the read against (cancellation, then flush timer).
            match select(read, select(cancelled, sleep)).await {
                Either::Left((result, _)) => classify_read(result),
                Either::Right((Either::Left(_), _)) => ReadStep::Cancelled,
                Either::Right((Either::Right(_), _)) => ReadStep::FlushTimer,
            }
        }
    }
}

/// Map a raw read result to a [`ReadStep`].
fn classify_read(result: core::result::Result<Option<WsMessage>, WsError>) -> ReadStep {
    match result {
        Ok(Some(message)) => ReadStep::Message(message),
        Ok(None) => ReadStep::Closed,
        Err(_) => ReadStep::Failed,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::super::event::Info;
    use super::*;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::rc::Rc;

    // ---- Scripted transports ------------------------------------------------

    /// One programmed action a scripted connection yields from `read`.
    #[derive(Clone)]
    enum Action {
        Text(String),
        Binary(Vec<u8>),
        Close,
        Fail,
    }

    /// A scripted session: what a single connection yields, in order.
    struct SessionScript {
        actions: VecDeque<Action>,
    }

    /// A scripted WebSocket transport: each dial pops the next session script and
    /// records the dialed URL. When scripts run out, a dial fails at the
    /// transport level (tests cancel before that matters).
    #[derive(Clone)]
    struct ScriptedWs {
        sessions: Rc<RefCell<VecDeque<SessionScript>>>,
        dialed: Rc<RefCell<Vec<String>>>,
    }

    impl ScriptedWs {
        fn new(sessions: Vec<Vec<Action>>) -> Self {
            ScriptedWs {
                sessions: Rc::new(RefCell::new(
                    sessions
                        .into_iter()
                        .map(|actions| SessionScript {
                            actions: actions.into(),
                        })
                        .collect(),
                )),
                dialed: Rc::new(RefCell::new(Vec::new())),
            }
        }
    }

    struct ScriptedConn {
        actions: VecDeque<Action>,
    }

    impl WsConnection for ScriptedConn {
        async fn read(&mut self) -> core::result::Result<Option<WsMessage>, WsError> {
            match self.actions.pop_front() {
                Some(Action::Text(s)) => Ok(Some(WsMessage::Text(s.into_bytes()))),
                Some(Action::Binary(b)) => Ok(Some(WsMessage::Binary(b))),
                Some(Action::Close) | None => Ok(None),
                Some(Action::Fail) => Err(WsError::new("scripted failure")),
            }
        }

        async fn close(&mut self) {}
    }

    impl WsTransport for ScriptedWs {
        type Conn = ScriptedConn;

        async fn dial(
            &self,
            url: String,
            _subprotocol: &'static str,
        ) -> core::result::Result<Self::Conn, DialError> {
            self.dialed.borrow_mut().push(url);
            match self.sessions.borrow_mut().pop_front() {
                Some(script) => Ok(ScriptedConn {
                    actions: script.actions,
                }),
                None => Err(DialError::Transport("no more sessions".to_owned())),
            }
        }
    }

    /// A transport whose first dial(s) fail with a programmed [`DialError`],
    /// after which it defers to an inner scripted transport.
    struct DialFailingWs {
        failures: Rc<RefCell<VecDeque<DialError>>>,
        inner: ScriptedWs,
    }

    impl WsTransport for DialFailingWs {
        type Conn = ScriptedConn;

        async fn dial(
            &self,
            url: String,
            subprotocol: &'static str,
        ) -> core::result::Result<Self::Conn, DialError> {
            if let Some(err) = self.failures.borrow_mut().pop_front() {
                self.inner.dialed.borrow_mut().push(url);
                return Err(err);
            }
            self.inner.dial(url, subprotocol).await
        }
    }

    // ---- Dictionary sources -------------------------------------------------

    /// A dictionary source that returns programmed dictionaries in order.
    struct ScriptedDict {
        dicts: Rc<RefCell<VecDeque<Vec<u8>>>>,
        fetches: Rc<RefCell<u32>>,
    }

    impl ScriptedDict {
        fn new(dicts: Vec<Vec<u8>>) -> Self {
            ScriptedDict {
                dicts: Rc::new(RefCell::new(dicts.into())),
                fetches: Rc::new(RefCell::new(0)),
            }
        }
    }

    impl DictionarySource for ScriptedDict {
        async fn fetch(&self, _id: Option<u32>) -> Result<Vec<u8>> {
            *self.fetches.borrow_mut() += 1;
            match self.dicts.borrow_mut().pop_front() {
                Some(bytes) => Ok(bytes),
                None => Err(Error::Transport {
                    message: "no dictionary".to_owned(),
                    retryable: false,
                }),
            }
        }
    }

    /// A source that never yields a dictionary (compression-off tests).
    struct NoDict;

    impl DictionarySource for NoDict {
        async fn fetch(&self, _id: Option<u32>) -> Result<Vec<u8>> {
            Err(Error::Transport {
                message: "no dictionary".to_owned(),
                retryable: false,
            })
        }
    }

    // ---- Sinks --------------------------------------------------------------

    /// A sink that records every item and cancels the tail once it has collected
    /// `stop_after` events (counting individual events across batches), or when a
    /// terminal error arrives.
    struct CollectingSink {
        items: Vec<core::result::Result<Delivery, Error>>,
        event_count: usize,
        stop_after: usize,
        cancel: CancelToken,
    }

    impl CollectingSink {
        fn new(stop_after: usize, cancel: CancelToken) -> Self {
            CollectingSink {
                items: Vec::new(),
                event_count: 0,
                stop_after,
                cancel,
            }
        }

        /// The sequences delivered, in order, across all batches.
        fn seqs(&self) -> Vec<u64> {
            let mut out = Vec::new();
            for item in &self.items {
                if let Ok(Delivery::Batch(batch)) = item {
                    out.extend(batch.events().iter().map(|e| e.seq));
                }
            }
            out
        }

        fn infos(&self) -> Vec<&Info> {
            self.items
                .iter()
                .filter_map(|i| match i {
                    Ok(Delivery::Info(info)) => Some(info),
                    _ => None,
                })
                .collect()
        }

        fn error(&self) -> Option<&Error> {
            self.items.iter().find_map(|i| i.as_ref().err())
        }
    }

    impl DeliverySink for CollectingSink {
        async fn deliver(&mut self, item: core::result::Result<Delivery, Error>) -> bool {
            let mut stop = false;
            match &item {
                Ok(Delivery::Batch(batch)) => {
                    self.event_count += batch.len();
                    if self.event_count >= self.stop_after {
                        stop = true;
                    }
                }
                Err(_) => stop = true,
                _ => {}
            }
            self.items.push(item);
            if stop {
                self.cancel.cancel();
                return false;
            }
            true
        }
    }

    // ---- Frame builders -----------------------------------------------------

    const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
    const TIME: &str = "2024-01-01T00:00:00.000000Z";
    const REV: &str = "3l3qo2vutsw2b";
    const RKEY: &str = "3l3qo2vuowo2b";

    fn commit_text(seq: u64, collection: &str) -> String {
        serde_json::json!({
            "$type": "message",
            "payload": {
                "$type": "network.bsky.jetstream.subscribeEvents#commit",
                "seq": seq,
                "did": DID,
                "time": TIME,
                "operation": "delete",
                "collection": collection,
                "rkey": RKEY,
                "rev": REV,
            }
        })
        .to_string()
    }

    fn info_text(name: &str) -> String {
        serde_json::json!({
            "$type": "message",
            "payload": {
                "$type": "network.bsky.jetstream.subscribeEvents#info",
                "name": name,
                "message": "clamped",
            }
        })
        .to_string()
    }

    fn error_text(name: &str) -> String {
        serde_json::json!({"$type": "error", "error": name, "message": "x"}).to_string()
    }

    fn live_config() -> LiveConfig {
        // No compression by default in these tests; small flush delay.
        let mut config = LiveConfig::new("jetstream.test", true);
        config.compression = false;
        config
    }

    async fn run_scripted(
        sessions: Vec<Vec<Action>>,
        config: LiveConfig,
        stop_after: usize,
    ) -> (CollectingSink, ScriptedWs) {
        let cancel = CancelToken::new();
        let ws = ScriptedWs::new(sessions);
        let consumer = LiveConsumer::new(ws.clone(), NoDict, config, cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(stop_after, cancel);
        consumer.run(&mut sink).await.unwrap();
        (sink, ws)
    }

    // ---- Tests --------------------------------------------------------------

    #[tokio::test(start_paused = true)]
    async fn delivers_ordered_events_and_flushes_partial_batch() {
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Text(commit_text(1, "app.bsky.feed.post")),
                Action::Text(commit_text(2, "app.bsky.feed.post")),
                Action::Text(commit_text(3, "app.bsky.feed.post")),
            ]],
            live_config(),
            3,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2, 3]);
    }

    #[tokio::test(start_paused = true)]
    async fn deduplicates_replayed_events_across_reconnect() {
        // Session 1 delivers 1..3 then drops; session 2 replays 1..3 (inclusive
        // server replay) and adds 4..6. The tail must emit each seq once.
        let (sink, ws) = run_scripted(
            vec![
                vec![
                    Action::Text(commit_text(1, "app.bsky.feed.post")),
                    Action::Text(commit_text(2, "app.bsky.feed.post")),
                    Action::Text(commit_text(3, "app.bsky.feed.post")),
                    Action::Close,
                ],
                vec![
                    Action::Text(commit_text(1, "app.bsky.feed.post")),
                    Action::Text(commit_text(2, "app.bsky.feed.post")),
                    Action::Text(commit_text(3, "app.bsky.feed.post")),
                    Action::Text(commit_text(4, "app.bsky.feed.post")),
                    Action::Text(commit_text(5, "app.bsky.feed.post")),
                    Action::Text(commit_text(6, "app.bsky.feed.post")),
                ],
            ],
            live_config(),
            6,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2, 3, 4, 5, 6]);
        // The reconnect resumed from the last processed seq (3).
        let second = &ws.dialed.borrow()[1];
        assert!(second.contains("cursor=3"), "second dial URL: {second}");
    }

    #[tokio::test(start_paused = true)]
    async fn tolerates_sequence_gaps() {
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Text(commit_text(10, "app.bsky.feed.post")),
                Action::Text(commit_text(25, "app.bsky.feed.post")),
                Action::Text(commit_text(9000, "app.bsky.feed.post")),
            ]],
            live_config(),
            3,
        )
        .await;
        assert_eq!(sink.seqs(), vec![10, 25, 9000]);
    }

    #[tokio::test(start_paused = true)]
    async fn reconnects_after_dirty_disconnect() {
        let (sink, ws) = run_scripted(
            vec![
                vec![
                    Action::Text(commit_text(1, "app.bsky.feed.post")),
                    Action::Fail,
                ],
                vec![Action::Text(commit_text(2, "app.bsky.feed.post"))],
            ],
            live_config(),
            2,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2]);
        assert_eq!(ws.dialed.borrow().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn info_frame_is_delivered_and_does_not_advance_cursor() {
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Text(info_text("OutdatedCursor")),
                Action::Text(commit_text(1, "app.bsky.feed.post")),
            ]],
            live_config(),
            1,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1]);
        assert_eq!(sink.infos().len(), 1);
        assert_eq!(sink.infos()[0].name, "OutdatedCursor");
    }

    #[tokio::test(start_paused = true)]
    async fn future_cursor_starts_at_tip_without_cursor_param() {
        let config = live_config();
        let (_sink, ws) = run_scripted(
            vec![vec![Action::Text(commit_text(1, "app.bsky.feed.post"))]],
            config,
            1,
        )
        .await;
        let first = &ws.dialed.borrow()[0];
        assert!(
            !first.contains("cursor="),
            "tip start must omit cursor: {first}"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn resume_cursor_is_sent_and_kept_inclusive() {
        let mut config = live_config();
        config.cursor = LiveCursor::Resume(Cursor::Seq(5));
        let (sink, ws) = run_scripted(
            vec![vec![
                // Server replays inclusively from 5; seq 5 must be kept.
                Action::Text(commit_text(5, "app.bsky.feed.post")),
                Action::Text(commit_text(6, "app.bsky.feed.post")),
            ]],
            config,
            2,
        )
        .await;
        assert_eq!(sink.seqs(), vec![5, 6]);
        let first = &ws.dialed.borrow()[0];
        assert!(first.contains("cursor=5"), "resume dial URL: {first}");
    }

    #[tokio::test(start_paused = true)]
    async fn malformed_frame_is_skipped_not_fatal() {
        // A commit with a non-positive seq is a per-frame malformed event: it is
        // dropped, its valid siblings still flow, and the cursor is unaffected.
        let bad = serde_json::json!({
            "$type": "message",
            "payload": {
                "$type": "network.bsky.jetstream.subscribeEvents#commit",
                "seq": 0, "did": DID, "time": TIME, "operation": "delete",
                "collection": "app.bsky.feed.post", "rkey": RKEY, "rev": REV,
            }
        })
        .to_string();
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Text(commit_text(1, "app.bsky.feed.post")),
                Action::Text(bad),
                Action::Text(commit_text(2, "app.bsky.feed.post")),
            ]],
            live_config(),
            2,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2]);
        assert!(sink.error().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn non_v2_frame_is_fatal() {
        // A frame with no envelope $type looks like a legacy v1 endpoint.
        let (sink, _ws) = run_scripted(
            vec![vec![Action::Text(
                r#"{"seq":1,"kind":"commit"}"#.to_owned(),
            )]],
            live_config(),
            10,
        )
        .await;
        assert!(matches!(sink.error(), Some(Error::InvalidFrame(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn cursor_too_old_is_fatal_on_pure_live() {
        let (sink, _ws) = run_scripted(
            vec![vec![Action::Text(error_text("CursorTooOld"))]],
            live_config(),
            10,
        )
        .await;
        match sink.error() {
            Some(Error::Protocol { name, .. }) => assert_eq!(name, "CursorTooOld"),
            other => panic!("expected CursorTooOld, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn consumer_too_slow_reconnects() {
        let (sink, ws) = run_scripted(
            vec![
                vec![
                    Action::Text(commit_text(1, "app.bsky.feed.post")),
                    Action::Text(error_text("ConsumerTooSlow")),
                ],
                vec![Action::Text(commit_text(2, "app.bsky.feed.post"))],
            ],
            live_config(),
            2,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2]);
        assert!(sink.error().is_none());
        assert_eq!(ws.dialed.borrow().len(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn filter_is_applied_after_decode() {
        let mut config = live_config();
        config.filter = Filter::new().collection("app.bsky.feed.post").unwrap();
        let (sink, ws) = run_scripted(
            vec![vec![
                Action::Text(commit_text(1, "app.bsky.feed.post")),
                Action::Text(commit_text(2, "app.bsky.feed.like")),
                Action::Text(commit_text(3, "app.bsky.feed.post")),
            ]],
            config,
            2,
        )
        .await;
        // seq 2 is filtered out but still advances the cursor.
        assert_eq!(sink.seqs(), vec![1, 3]);
        // The filter rode along on the query.
        let first = &ws.dialed.borrow()[0];
        assert!(first.contains("collections=app.bsky.feed.post"), "{first}");
    }

    #[tokio::test(start_paused = true)]
    async fn pre_upgrade_http_error_is_parsed() {
        let cancel = CancelToken::new();
        let failures: VecDeque<DialError> = vec![DialError::Http {
            status: 400,
            body: br#"{"error":"CursorTooOld","message":"too far back"}"#.to_vec(),
        }]
        .into();
        let inner = ScriptedWs::new(vec![vec![Action::Text(commit_text(
            1,
            "app.bsky.feed.post",
        ))]]);
        let ws = DialFailingWs {
            failures: Rc::new(RefCell::new(failures)),
            inner,
        };
        let consumer = LiveConsumer::new(ws, NoDict, live_config(), cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(10, cancel);
        consumer.run(&mut sink).await.unwrap();
        match sink.error() {
            Some(Error::Protocol { name, .. }) => assert_eq!(name, "CursorTooOld"),
            other => panic!("expected CursorTooOld, got {other:?}"),
        }
    }

    #[tokio::test(start_paused = true)]
    async fn unsupported_subprotocol_is_fatal() {
        let cancel = CancelToken::new();
        let failures: VecDeque<DialError> =
            vec![DialError::Subprotocol("something-else".to_owned())].into();
        let inner = ScriptedWs::new(vec![]);
        let ws = DialFailingWs {
            failures: Rc::new(RefCell::new(failures)),
            inner,
        };
        let consumer = LiveConsumer::new(ws, NoDict, live_config(), cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(10, cancel);
        consumer.run(&mut sink).await.unwrap();
        assert!(matches!(sink.error(), Some(Error::Capability(_))));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_stops_cleanly_flushing_partial_batch() {
        // The tail keeps a partial batch (below max_batch) that only flushes on
        // the timer; cancel after the first event via the sink's stop_after.
        let (sink, _ws) = run_scripted(
            vec![vec![Action::Text(commit_text(1, "app.bsky.feed.post"))]],
            live_config(),
            1,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1]);
    }

    #[tokio::test(start_paused = true)]
    async fn full_batch_flushes_at_max() {
        let mut config = live_config();
        config.max_batch = 2;
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Text(commit_text(1, "app.bsky.feed.post")),
                Action::Text(commit_text(2, "app.bsky.feed.post")),
                Action::Text(commit_text(3, "app.bsky.feed.post")),
                Action::Text(commit_text(4, "app.bsky.feed.post")),
            ]],
            config,
            4,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1, 2, 3, 4]);
        // Two full batches of two.
        let batch_sizes: Vec<usize> = sink
            .items
            .iter()
            .filter_map(|i| match i {
                Ok(Delivery::Batch(b)) => Some(b.len()),
                _ => None,
            })
            .collect();
        assert_eq!(batch_sizes, vec![2, 2]);
    }

    // ---- Compression / dictionary tests ------------------------------------

    /// Train one structured zstd dictionary on a varied commit corpus. Training
    /// needs a real, multi-sample corpus; a single tiny sample makes ZDICT fail
    /// or emit an unusable dictionary, so we synthesize a few hundred distinct
    /// commit records.
    fn train_base_dict() -> Vec<u8> {
        let mut data = Vec::new();
        let mut sizes = Vec::new();
        let collections = [
            "app.bsky.feed.post",
            "app.bsky.feed.like",
            "app.bsky.graph.follow",
            "app.bsky.feed.repost",
        ];
        for i in 0..512u64 {
            let text = commit_text(i, collections[(i as usize) % collections.len()]);
            sizes.push(text.len());
            data.extend_from_slice(text.as_bytes());
        }
        // `from_continuous` requires the sample sizes to sum to the buffer len.
        assert_eq!(sizes.iter().sum::<usize>(), data.len());
        zstd::dict::from_continuous(&data, &sizes, 8 * 1024).expect("train dictionary")
    }

    /// Overwrite the dictionary ID in a structured dictionary's header (the 4
    /// little-endian bytes at offset 4, per RFC 8878 §5). This lets a test mint
    /// dictionaries with deterministic, distinct IDs from one trained base,
    /// which is what the rotation path keys on.
    fn dict_with_id(base: &[u8], id: u32) -> Vec<u8> {
        let mut dict = base.to_vec();
        dict[4..8].copy_from_slice(&id.to_le_bytes());
        // Sanity: the patched header parses back to the ID we set.
        assert_eq!(parse_dictionary_id(&dict).unwrap(), id);
        dict
    }

    /// Compress one commit as a single dictionary-keyed zstd frame. zstd reads
    /// the dictionary's own ID and stamps it into the frame header, so the tail's
    /// decode (with the same dictionary) round-trips.
    fn frame_for(dict: &[u8], seq: u64) -> Vec<u8> {
        let text = commit_text(seq, "app.bsky.feed.post");
        zstd::bulk::Compressor::with_dictionary(3, dict)
            .expect("compressor")
            .compress(text.as_bytes())
            .expect("compress with dict")
    }

    /// Build a structured dictionary (with a `seq`-derived, non-zero ID) and a
    /// matching dictionary-compressed frame, so the binary decode path is
    /// exercised end to end. Distinct `seq` values yield distinct dictionary IDs,
    /// which the rotation test relies on.
    fn make_dict_and_frame(seq: u64) -> (Vec<u8>, Vec<u8>) {
        let dict = dict_with_id(&train_base_dict(), 0x1000_0000 + seq as u32);
        let frame = frame_for(&dict, seq);
        (dict, frame)
    }

    #[tokio::test(start_paused = true)]
    async fn decodes_dictionary_compressed_binary_frames() {
        let (dict, frame) = make_dict_and_frame(1);
        let cancel = CancelToken::new();
        let ws = ScriptedWs::new(vec![vec![Action::Binary(frame)]]);
        let dict_src = ScriptedDict::new(vec![dict]);
        let mut config = LiveConfig::new("jetstream.test", true);
        config.compression = true;
        let consumer = LiveConsumer::new(ws.clone(), dict_src, config, cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(1, cancel);
        consumer.run(&mut sink).await.unwrap();
        assert_eq!(sink.seqs(), vec![1]);
        // The dial advertised the dictionary ID.
        let first = &ws.dialed.borrow()[0];
        assert!(first.contains("zstdDictionary="), "{first}");
    }

    #[tokio::test(start_paused = true)]
    async fn dictionary_rotation_refetches_and_reconnects() {
        let (dict1, _frame1) = make_dict_and_frame(1);
        let (dict2, frame2) = make_dict_and_frame(2);
        // The rotation recovery only adopts a refetched dictionary whose ID
        // differs from the rejected one, so the two dictionaries must have
        // distinct IDs for this test to exercise adoption rather than degrade.
        assert_ne!(
            parse_dictionary_id(&dict1).unwrap(),
            parse_dictionary_id(&dict2).unwrap()
        );
        let cancel = CancelToken::new();
        let ws = ScriptedWs::new(vec![
            vec![Action::Text(error_text("UnknownZstdDictionary"))],
            vec![Action::Binary(frame2)],
        ]);
        let dict_src = ScriptedDict::new(vec![dict1, dict2]);
        let fetches = dict_src.fetches.clone();
        let mut config = LiveConfig::new("jetstream.test", true);
        config.compression = true;
        let consumer = LiveConsumer::new(ws.clone(), dict_src, config, cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(1, cancel);
        consumer.run(&mut sink).await.unwrap();
        assert_eq!(sink.seqs(), vec![2]);
        assert!(sink.error().is_none());
        // Two dials (initial + after rotation), two dictionary fetches.
        assert_eq!(ws.dialed.borrow().len(), 2);
        assert_eq!(*fetches.borrow(), 2);
    }

    #[tokio::test(start_paused = true)]
    async fn dictionary_fetch_failure_degrades_to_uncompressed() {
        // Compression on, but the dictionary source yields nothing: the tail
        // must connect uncompressed and still deliver text frames.
        let cancel = CancelToken::new();
        let ws = ScriptedWs::new(vec![vec![Action::Text(commit_text(
            1,
            "app.bsky.feed.post",
        ))]]);
        let mut config = LiveConfig::new("jetstream.test", true);
        config.compression = true;
        let consumer = LiveConsumer::new(ws.clone(), NoDict, config, cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(1, cancel);
        consumer.run(&mut sink).await.unwrap();
        assert_eq!(sink.seqs(), vec![1]);
        let first = &ws.dialed.borrow()[0];
        assert!(!first.contains("zstdDictionary="), "{first}");
    }

    #[tokio::test(start_paused = true)]
    async fn stray_binary_ignored_on_uncompressed_connection() {
        let (sink, _ws) = run_scripted(
            vec![vec![
                Action::Binary(vec![1, 2, 3, 4]),
                Action::Text(commit_text(1, "app.bsky.feed.post")),
            ]],
            live_config(),
            1,
        )
        .await;
        assert_eq!(sink.seqs(), vec![1]);
        assert!(sink.error().is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn corrupt_binary_after_upgrade_reconnects() {
        let (dict, _frame) = make_dict_and_frame(1);
        let cancel = CancelToken::new();
        let ws = ScriptedWs::new(vec![
            vec![Action::Binary(vec![0xFF, 0xFF, 0xFF, 0xFF])],
            vec![Action::Text(commit_text(1, "app.bsky.feed.post"))],
        ]);
        let dict_src = ScriptedDict::new(vec![dict]);
        let mut config = LiveConfig::new("jetstream.test", true);
        config.compression = true;
        let consumer = LiveConsumer::new(ws.clone(), dict_src, config, cancel.clone()).unwrap();
        let mut sink = CollectingSink::new(1, cancel);
        consumer.run(&mut sink).await.unwrap();
        assert_eq!(sink.seqs(), vec![1]);
        assert_eq!(ws.dialed.borrow().len(), 2);
    }

    // ---- Pure-function tests ------------------------------------------------

    #[test]
    fn subscribe_url_has_repeated_params_and_no_max_message_size() {
        let filter = Filter::new()
            .kinds([Kind::Commit, Kind::Identity])
            .did(DID)
            .unwrap()
            .collection("app.bsky.feed.post")
            .unwrap();
        let url = subscribe_url("jetstream.test", true, &filter, Some(42), Some(7)).unwrap();
        assert!(
            url.starts_with("wss://jetstream.test/xrpc/network.bsky.jetstream.subscribeEvents?")
        );
        // Inspect decoded query pairs so the assertions hold regardless of the
        // percent-encoding `application/x-www-form-urlencoded` applies to a DID's
        // colons — the server decodes it back to the raw value.
        let parsed = url::Url::parse(&url).unwrap();
        let pairs: Vec<(String, String)> = parsed
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        let has = |k: &str, v: &str| pairs.iter().any(|(pk, pv)| pk == k && pv == v);
        assert!(has("kinds", "commit"));
        assert!(has("kinds", "identity"));
        assert!(has("dids", DID));
        assert!(has("collections", "app.bsky.feed.post"));
        assert!(has("cursor", "42"));
        assert!(has("zstdDictionary", "7"));
        assert!(pairs.iter().all(|(k, _)| k != "maxMessageSizeBytes"));
    }

    #[test]
    fn insecure_scheme_uses_ws() {
        let url = subscribe_url("localhost:3000", false, &Filter::new(), None, None).unwrap();
        assert!(url.starts_with("ws://localhost:3000/"));
        assert!(!url.contains("cursor="));
    }

    #[test]
    fn backoff_doubles_and_caps() {
        let backoff = LiveBackoff::default();
        assert_eq!(backoff.delay(0), Duration::from_millis(250));
        assert_eq!(backoff.delay(1), Duration::from_millis(500));
        assert_eq!(backoff.delay(2), Duration::from_secs(1));
        assert_eq!(backoff.delay(100), Duration::from_secs(30));
    }

    #[test]
    fn initial_last_seq_keeps_resume_inclusive() {
        assert_eq!(initial_last_seq(&LiveCursor::Tip), 0);
        assert_eq!(initial_last_seq(&LiveCursor::Resume(Cursor::Seq(5))), 4);
        assert_eq!(initial_last_seq(&LiveCursor::Resume(Cursor::Seq(1))), 0);
        assert_eq!(
            initial_last_seq(&LiveCursor::Resume(Cursor::Timestamp(999))),
            0
        );
    }

    #[test]
    fn config_validation_rejects_bad_values() {
        let mut config = LiveConfig::new("jetstream.test", true);
        config.max_batch = 0;
        assert!(config.validate().is_err());
        let mut config = LiveConfig::new("", true);
        config.max_batch = 1;
        assert!(config.validate().is_err());
    }

    use super::super::filter::Kind;
}
