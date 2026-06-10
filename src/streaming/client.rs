use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::Duration;

use futures::StreamExt;
use futures::stream::Stream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::http::HeaderValue;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream};

use crate::streaming::StreamError;
use crate::streaming::event::Event;
use crate::streaming::jetstream::JetstreamEvent;
use crate::streaming::reconnect::BackoffPolicy;

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
    /// Highest seq of a frame the verifier silently dropped (rev replay, queued
    /// resync, sync no-op) since the last cursor advance. Folded into the
    /// cursor on flush so a run of drops doesn't pin the checkpoint. Unused on
    /// the Jetstream path.
    dropped_watermark: i64,
    #[cfg(feature = "sync")]
    resync_events: Option<tokio::sync::mpsc::Receiver<crate::sync::ResyncEvent>>,
    #[cfg(feature = "sync")]
    async_errors: Option<tokio::sync::mpsc::Receiver<crate::sync::VerifierError>>,
}

impl<E> BatchState<E> {
    fn new(capacity: usize) -> Self {
        BatchState {
            ws: None,
            attempt: 0,
            batch: Vec::with_capacity(capacity),
            pending_error: None,
            deadline: None,
            dropped_watermark: 0,
            #[cfg(feature = "sync")]
            resync_events: None,
            #[cfg(feature = "sync")]
            async_errors: None,
        }
    }
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Configuration for a streaming client.
///
/// Only [`url`](Config::url) is required. All other fields default to `None`,
/// which means "use the built-in default" (see each field's doc comment).
///
/// ```
/// use shrike::streaming::{Client, Config};
///
/// let _client = Client::new(Config {
///     url: "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos".into(),
///     cursor: Some(12345),
///     ..Config::default()
/// });
/// ```
#[derive(Default)]
pub struct Config {
    /// WebSocket URL (e.g., `"wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"`).
    pub url: String,
    /// Starting cursor (sequence number for firehose, `time_us` for Jetstream).
    pub cursor: Option<i64>,
    /// Backoff policy for reconnection. None uses sensible defaults
    /// (1s initial, 30s max, full jitter).
    pub backoff: Option<BackoffPolicy>,
    /// Maximum WebSocket message size. None means 2 MB.
    pub max_message_size: Option<usize>,
    /// User-Agent header for outbound WebSocket connections. None means
    /// [`crate::USER_AGENT`].
    pub user_agent: Option<String>,
    /// For Jetstream: filter by collections.
    pub collections: Option<Vec<String>>,
    /// For Jetstream: filter by DIDs.
    pub dids: Option<Vec<String>>,
    /// Maximum number of events per batch. None means 50.
    pub batch_size: Option<usize>,
    /// Maximum time to wait for a full batch before flushing. None means 500ms.
    pub batch_timeout: Option<Duration>,
    /// Optional Sync 1.1 verifier for firehose events.
    #[cfg(feature = "sync")]
    pub verifier: Option<Arc<crate::sync::Verifier>>,
    /// Verifier parallelism. The serial streaming path uses 1.
    #[cfg(feature = "sync")]
    pub parallelism: Option<usize>,
    /// Per-DID queue bound for future parallel verifier integration.
    #[cfg(feature = "sync")]
    pub per_did_queue: Option<usize>,
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
    url: String,
    collections: Option<Vec<String>>,
    dids: Option<Vec<String>>,
    backoff: BackoffPolicy,
    batch_size: usize,
    batch_timeout: Duration,
    user_agent: String,
    cursor: Arc<AtomicI64>,
    #[cfg(feature = "sync")]
    verifier: Option<Arc<crate::sync::Verifier>>,
    #[cfg(feature = "sync")]
    parallelism: usize,
    #[cfg(feature = "sync")]
    per_did_queue: usize,
}

impl Client {
    /// Create a new client with the given configuration.
    pub fn new(config: Config) -> Self {
        let cursor_val = config.cursor.unwrap_or(-1);
        Client {
            url: config.url,
            collections: config.collections,
            dids: config.dids,
            backoff: config.backoff.unwrap_or_default(),
            batch_size: config.batch_size.unwrap_or(50),
            batch_timeout: config.batch_timeout.unwrap_or(Duration::from_millis(500)),
            user_agent: config
                .user_agent
                .unwrap_or_else(|| crate::USER_AGENT.to_owned()),
            cursor: Arc::new(AtomicI64::new(cursor_val)),
            #[cfg(feature = "sync")]
            verifier: config.verifier,
            #[cfg(feature = "sync")]
            parallelism: config.parallelism.unwrap_or(1).max(1),
            #[cfg(feature = "sync")]
            per_did_queue: config.per_did_queue.unwrap_or(2048).max(1),
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
    #[cfg(feature = "sync")]
    pub fn subscribe(&self) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        // Parallel path: a verifier configured with parallelism > 1 verifies
        // different DIDs concurrently while preserving same-DID FIFO. The
        // serial path (default) is used otherwise and stays byte-for-byte
        // compatible with the no-verifier behavior.
        match self.verifier.clone() {
            Some(verifier) if self.parallelism > 1 => {
                self.subscribe_parallel(verifier).left_stream()
            }
            _ => self.subscribe_serial().right_stream(),
        }
    }

    /// Connect to a firehose or label stream (CBOR protocol).
    #[cfg(not(feature = "sync"))]
    pub fn subscribe(&self) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        self.subscribe_serial()
    }

    fn subscribe_serial(&self) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        let cursor = Arc::clone(&self.cursor);
        let batch_size = self.batch_size;
        let batch_timeout = self.batch_timeout;
        #[cfg(feature = "sync")]
        let verifier = self.verifier.clone();

        #[cfg_attr(not(feature = "sync"), allow(unused_mut))]
        let mut initial_state = BatchState::<Event>::new(batch_size);
        #[cfg(feature = "sync")]
        if let Some(verifier) = verifier.as_ref() {
            initial_state.resync_events = Some(verifier.resync_events());
            initial_state.async_errors = Some(verifier.async_errors());
        }

        futures::stream::unfold(initial_state, move |mut state| {
            let cursor = Arc::clone(&cursor);
            #[cfg(feature = "sync")]
            let verifier = verifier.clone();
            async move {
                // Yield any pending error from a previous partial-batch flush.
                if let Some(err) = state.pending_error.take() {
                    return Some((Err(err), state));
                }

                loop {
                    #[cfg(feature = "sync")]
                    {
                        if let Some(err) = take_async_error(&mut state) {
                            if !state.batch.is_empty() {
                                state.pending_error = Some(err);
                                state.deadline = None;
                                let batch = std::mem::take(&mut state.batch);
                                update_firehose_cursor(
                                    &cursor,
                                    &batch,
                                    &mut state.dropped_watermark,
                                );
                                return Some((Ok(batch), state));
                            }
                            state.deadline = None;
                            return Some((Err(err), state));
                        }
                        match take_resync_event(&mut state) {
                            Ok(Some(event)) => {
                                state.batch.push(event);
                                if state.batch.len() >= batch_size {
                                    state.deadline = None;
                                    let batch = std::mem::take(&mut state.batch);
                                    update_firehose_cursor(
                                        &cursor,
                                        &batch,
                                        &mut state.dropped_watermark,
                                    );
                                    return Some((Ok(batch), state));
                                }
                            }
                            Ok(None) => {}
                            Err(err) => {
                                if !state.batch.is_empty() {
                                    state.pending_error = Some(err);
                                    state.deadline = None;
                                    let batch = std::mem::take(&mut state.batch);
                                    update_firehose_cursor(
                                        &cursor,
                                        &batch,
                                        &mut state.dropped_watermark,
                                    );
                                    return Some((Ok(batch), state));
                                }
                                state.deadline = None;
                                return Some((Err(err), state));
                            }
                        }
                    }

                    // Establish a connection if we don't have one.
                    if state.ws.is_none() {
                        match connect_ws(
                            &self.url,
                            cursor.load(Ordering::SeqCst),
                            &self.collections,
                            &self.dids,
                            &self.user_agent,
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
                                    update_firehose_cursor(
                                        &cursor,
                                        &batch,
                                        &mut state.dropped_watermark,
                                    );
                                    return Some((Ok(batch), state));
                                }
                                let delay = self.backoff.delay(state.attempt);
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
                                    let parsed = parse_firehose_outcome(
                                        #[cfg(feature = "sync")]
                                        verifier.as_ref(),
                                        &data,
                                    )
                                    .await;
                                    match parsed {
                                        Ok(VerifyOutcome { event: Some(event), .. }) => {
                                            state.batch.push(event);
                                            if state.batch.len() >= batch_size {
                                                state.deadline = None;
                                                let batch = std::mem::take(&mut state.batch);
                                                update_firehose_cursor(&cursor, &batch, &mut state.dropped_watermark);
                                                return Some((Ok(batch), state));
                                            }
                                        }
                                        // Silent drop (rev replay, queued resync, sync
                                        // no-op, control frame): no event to deliver, but
                                        // the seq must still advance the checkpoint.
                                        Ok(VerifyOutcome { event: None, seq }) => {
                                            state.dropped_watermark = state.dropped_watermark.max(seq);
                                            continue;
                                        }
                                        // Info/sync frames return UnknownType — skip.
                                        Err(StreamError::UnknownType(_)) => continue,
                                        Err(e) => {
                                            if !state.batch.is_empty() {
                                                state.pending_error = Some(e);
                                                state.deadline = None;
                                                let batch = std::mem::take(&mut state.batch);
                                                update_firehose_cursor(&cursor, &batch, &mut state.dropped_watermark);
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
                                        update_firehose_cursor(&cursor, &batch, &mut state.dropped_watermark);
                                        return Some((Ok(batch), state));
                                    }
                                    // No batch to flush, but advance the cursor
                                    // past any frames dropped before the close so
                                    // the reconnect resumes past them.
                                    if state.dropped_watermark > 0 {
                                        update_firehose_cursor(&cursor, &[], &mut state.dropped_watermark);
                                    }
                                    let delay = self.backoff.delay(state.attempt);
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
                                        update_firehose_cursor(&cursor, &batch, &mut state.dropped_watermark);
                                        return Some((Ok(batch), state));
                                    }
                                    if state.dropped_watermark > 0 {
                                        update_firehose_cursor(&cursor, &[], &mut state.dropped_watermark);
                                    }
                                    let delay = self.backoff.delay(state.attempt);
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
                                update_firehose_cursor(&cursor, &batch, &mut state.dropped_watermark);
                                return Some((Ok(batch), state));
                            }
                            // Empty batch — but if frames were silently dropped
                            // since the last flush, advance the checkpoint past
                            // them so an idle run of drops doesn't pin the cursor.
                            if state.dropped_watermark > 0 {
                                update_firehose_cursor(&cursor, &[], &mut state.dropped_watermark);
                            }
                            // Reset deadline and keep waiting.
                            state.deadline = Some(
                                tokio::time::Instant::now() + batch_timeout,
                            );
                        }
                    }
                }
            }
        })
    }

    /// Verifier-aware parallel firehose path: different DIDs verify
    /// concurrently across a worker pool while same-DID events keep FIFO order.
    /// The cursor advances by watermark (`min(inflight) - 1`), so a restart
    /// after parallel verification never skips an in-flight lower-seq event.
    #[cfg(feature = "sync")]
    fn subscribe_parallel(
        &self,
        verifier: Arc<crate::sync::Verifier>,
    ) -> impl Stream<Item = Result<Vec<Event>, StreamError>> + '_ {
        use crate::streaming::parallel::{InflightSeqs, Scheduler};

        let cursor = Arc::clone(&self.cursor);
        let batch_size = self.batch_size;
        let batch_timeout = self.batch_timeout;
        let parallelism = self.parallelism;
        let per_did_queue = self.per_did_queue;

        // Shared in-flight seq set: the dispatcher adds on submit, the collector
        // removes on result. Drives the watermark cursor.
        let inflight = Arc::new(std::sync::Mutex::new(InflightSeqs::new()));

        // Scheduler verifies each dispatched frame keyed by DID.
        let verifier_for_run = verifier.clone();
        let (scheduler, result_rx) = Scheduler::<crate::syntax::Did, ParallelJob>::new(
            parallelism,
            per_did_queue,
            batch_size.max(1) * 2,
            move |job: ParallelJob| {
                let verifier = verifier_for_run.clone();
                async move {
                    let outcome = verify_raw_event(&verifier, job.raw).await;
                    ParallelResult {
                        seq: job.seq,
                        outcome,
                    }
                }
            },
        );
        let scheduler = Arc::new(scheduler);

        // Dispatcher task: owns the websocket + reconnection, parses frames,
        // tracks inflight, and feeds the scheduler. Overflow + parse/connection
        // errors flow to the collector through `ctrl_tx`.
        let (ctrl_tx, ctrl_rx) = tokio::sync::mpsc::channel::<StreamError>(parallelism.max(1) * 4);
        let dispatch = {
            let url = self.url.clone();
            let collections = self.collections.clone();
            let dids = self.dids.clone();
            let user_agent = self.user_agent.clone();
            let backoff = self.backoff;
            let cursor = Arc::clone(&cursor);
            let inflight = Arc::clone(&inflight);
            let scheduler = Arc::clone(&scheduler);
            tokio::spawn(async move {
                dispatch_loop(
                    url,
                    collections,
                    dids,
                    user_agent,
                    backoff,
                    cursor,
                    inflight,
                    scheduler,
                    ctrl_tx,
                )
                .await;
            })
        };

        let resync_events = verifier.resync_events();
        let async_errors = verifier.async_errors();

        let state = ParallelState {
            cursor,
            batch_size,
            batch_timeout,
            inflight,
            scheduler,
            result_rx,
            ctrl_rx,
            resync_events,
            async_errors,
            dispatch: Some(dispatch),
            batch: Vec::with_capacity(batch_size),
            pending_error: None,
            deadline: None,
            _marker: std::marker::PhantomData,
        };

        futures::stream::unfold(state, move |mut state| async move {
            if let Some(err) = state.pending_error.take() {
                return Some((Err(err), state));
            }
            let deadline = *state
                .deadline
                .get_or_insert_with(|| tokio::time::Instant::now() + state.batch_timeout);

            loop {
                tokio::select! {
                    biased;

                    // Async verifier errors (resync failures, overflow, etc.).
                    Some(err) = state.async_errors.recv() => {
                        return parallel_yield_error(state, err.into());
                    }
                    // Dispatcher control errors (parse/connection/overflow).
                    Some(err) = state.ctrl_rx.recv() => {
                        return parallel_yield_error(state, err);
                    }
                    // Resync ops produced by async workers.
                    Some(event) = state.resync_events.recv() => {
                        match event_from_resync_event(event) {
                            Ok(event) => {
                                state.batch.push(event);
                                if state.batch.len() >= state.batch_size {
                                    return Some((parallel_flush(&mut state), state));
                                }
                            }
                            Err(err) => return parallel_yield_error(state, err),
                        }
                    }
                    // Verified results from the scheduler.
                    result = state.result_rx.recv() => {
                        let Some(result) = result else {
                            // Scheduler closed: dispatcher exited (consumer drop
                            // or fatal). Flush any partial batch, then end.
                            if !state.batch.is_empty() {
                                return Some((parallel_flush(&mut state), state));
                            }
                            return None;
                        };
                        lock_inflight(&state.inflight).remove(result.seq);
                        match result.outcome {
                            Ok(VerifyOutcome { event: Some(event), .. }) => {
                                state.batch.push(event);
                                if state.batch.len() >= state.batch_size {
                                    return Some((parallel_flush(&mut state), state));
                                }
                            }
                            // Silent drop: seq already removed from inflight, so
                            // the watermark advances past it on the next flush.
                            Ok(VerifyOutcome { event: None, .. }) => {}
                            Err(StreamError::UnknownType(_)) => {}
                            Err(err) => {
                                if !state.batch.is_empty() {
                                    state.pending_error = Some(err);
                                    return Some((parallel_flush(&mut state), state));
                                }
                                state.deadline = None;
                                return Some((Err(err), state));
                            }
                        }
                    }
                    _ = tokio::time::sleep_until(deadline) => {
                        if !state.batch.is_empty() {
                            return Some((parallel_flush(&mut state), state));
                        }
                        // Idle: advance the cursor to the current watermark so a
                        // run of in-flight/dropped events doesn't pin it.
                        parallel_advance_cursor(&state, &[]);
                        state.deadline =
                            Some(tokio::time::Instant::now() + state.batch_timeout);
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
        let batch_size = self.batch_size;
        let batch_timeout = self.batch_timeout;

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
                                &self.url,
                                cursor.load(Ordering::SeqCst),
                                &self.collections,
                                &self.dids,
                                &self.user_agent,
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
                                    let delay = self.backoff.delay(state.attempt);
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
                                        match crate::streaming::jetstream::parse_jetstream_message(&text) {
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
                                        let delay = self.backoff.delay(state.attempt);
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
                                        let delay = self.backoff.delay(state.attempt);
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
    user_agent: &str,
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

    let request = websocket_request(url.as_str(), user_agent)?;

    let (ws_stream, _response) = tokio_tungstenite::connect_async(request)
        .await
        .map_err(|e| StreamError::WebSocket(format!("connection failed: {e}")))?;

    let (_write, read) = ws_stream.split();
    Ok(read)
}

fn websocket_request(
    url: &str,
    user_agent: &str,
) -> Result<tokio_tungstenite::tungstenite::http::Request<()>, StreamError> {
    let mut request = url
        .into_client_request()
        .map_err(|e| StreamError::WebSocket(format!("invalid request: {e}")))?;
    let user_agent = HeaderValue::from_str(user_agent)
        .map_err(|e| StreamError::WebSocket(format!("invalid User-Agent header: {e}")))?;
    request.headers_mut().insert(
        tokio_tungstenite::tungstenite::http::header::USER_AGENT,
        user_agent,
    );
    Ok(request)
}

#[cfg(feature = "sync")]
fn take_async_error(state: &mut BatchState<Event>) -> Option<StreamError> {
    let rx = state.async_errors.as_mut()?;
    match rx.try_recv() {
        Ok(err) => Some(err.into()),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => None,
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            state.async_errors = None;
            None
        }
    }
}

#[cfg(feature = "sync")]
fn take_resync_event(state: &mut BatchState<Event>) -> Result<Option<Event>, StreamError> {
    let Some(rx) = state.resync_events.as_mut() else {
        return Ok(None);
    };
    match rx.try_recv() {
        Ok(event) => event_from_resync_event(event).map(Some),
        Err(tokio::sync::mpsc::error::TryRecvError::Empty) => Ok(None),
        Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => {
            state.resync_events = None;
            Ok(None)
        }
    }
}

/// Outcome of handling one firehose frame.
///
/// `seq` is the frame's firehose sequence number (0 for control frames that
/// carry none). It is reported even when `event` is `None` — a silent drop
/// (rev replay, queued resync, sync no-op) must still advance the cursor
/// watermark, otherwise a long run of drops would pin the checkpoint and force
/// the whole run to be reprocessed after a restart.
struct VerifyOutcome {
    event: Option<Event>,
    seq: i64,
}

/// Parse (and, when a verifier is configured, verify) a single firehose frame
/// into a [`VerifyOutcome`]. Without the `sync` feature, or with no verifier,
/// this is a plain parse that always yields the parsed event.
async fn parse_firehose_outcome(
    #[cfg(feature = "sync")] verifier: Option<&Arc<crate::sync::Verifier>>,
    data: &[u8],
) -> Result<VerifyOutcome, StreamError> {
    #[cfg(feature = "sync")]
    if let Some(verifier) = verifier {
        return verify_firehose_frame(verifier, data).await;
    }
    let event = crate::streaming::parse_firehose_frame(data)?;
    let seq = event_seq(&event);
    Ok(VerifyOutcome {
        event: Some(event),
        seq,
    })
}

#[cfg(feature = "sync")]
async fn verify_firehose_frame(
    verifier: &crate::sync::Verifier,
    data: &[u8],
) -> Result<VerifyOutcome, StreamError> {
    let raw = crate::streaming::parse_raw_sync_frame(data)
        .map_err(|err| StreamError::ParseCbor(err.to_string()))?;
    verify_raw_event(verifier, raw).await
}

/// The DID a raw event serializes on. Events for the same DID must verify in
/// arrival order (chain-state advances race otherwise); `None` events (control
/// frames) have no ordering constraint.
#[cfg(feature = "sync")]
fn frame_key(raw: &crate::sync::RawSyncEvent) -> Option<crate::syntax::Did> {
    match raw {
        crate::sync::RawSyncEvent::Commit(c) => Some(c.repo.clone()),
        crate::sync::RawSyncEvent::Sync(s) => Some(s.did.clone()),
        crate::sync::RawSyncEvent::Account(a) => Some(a.did.clone()),
        crate::sync::RawSyncEvent::Identity(i) => Some(i.did.clone()),
        crate::sync::RawSyncEvent::Info => None,
    }
}

#[cfg(feature = "sync")]
async fn verify_raw_event(
    verifier: &crate::sync::Verifier,
    raw: crate::sync::RawSyncEvent,
) -> Result<VerifyOutcome, StreamError> {
    match raw {
        crate::sync::RawSyncEvent::Commit(raw) => {
            let did = raw.repo.clone();
            let rev = raw.rev;
            let seq = raw.seq;
            let event = verifier
                .verify_commit(&raw)
                .await?
                .map(|ops| event_from_verifier_ops(did, rev, seq, ops))
                .transpose()?;
            Ok(VerifyOutcome { event, seq })
        }
        crate::sync::RawSyncEvent::Sync(raw) => {
            let did = raw.did.clone();
            let rev = crate::syntax::Tid::try_from(raw.rev.as_str())
                .map_err(|err| StreamError::ParseCbor(format!("invalid sync rev: {err}")))?;
            let seq = raw.seq;
            let event = verifier
                .verify_sync(&raw)
                .await?
                .map(|ops| event_from_verifier_ops(did, rev, seq, ops))
                .transpose()?;
            Ok(VerifyOutcome { event, seq })
        }
        crate::sync::RawSyncEvent::Account(raw) => {
            // A persistence failure must not suppress delivery of the account
            // event: the consumer still needs to see the hosting-status change.
            // Surface the bookkeeping error on the async-error channel instead
            // of dropping the event.
            if let Err(err) = verifier.on_account_event(&raw).await {
                verifier.report_async_error(err).await;
            }
            let seq = raw.seq;
            Ok(VerifyOutcome {
                event: Some(Event::Account {
                    did: raw.did,
                    seq,
                    active: raw.active,
                }),
                seq,
            })
        }
        crate::sync::RawSyncEvent::Identity(raw) => {
            let seq = raw.seq;
            Ok(VerifyOutcome {
                event: Some(Event::Identity {
                    did: raw.did,
                    seq,
                    handle: raw.handle,
                }),
                seq,
            })
        }
        crate::sync::RawSyncEvent::Info => Ok(VerifyOutcome {
            event: None,
            seq: 0,
        }),
    }
}

#[cfg(feature = "sync")]
fn event_from_resync_event(event: crate::sync::ResyncEvent) -> Result<Event, StreamError> {
    let rev = crate::syntax::Tid::try_from(event.new_rev.as_str())
        .map_err(|err| StreamError::ParseCbor(format!("invalid resync rev: {err}")))?;
    event_from_verifier_ops(event.did, rev, 0, event.ops)
}

// ---------------------------------------------------------------------------
// Parallel firehose path
// ---------------------------------------------------------------------------

/// A frame dispatched to the parallel verify scheduler.
#[cfg(feature = "sync")]
struct ParallelJob {
    raw: crate::sync::RawSyncEvent,
    seq: i64,
}

/// A scheduler result: the verify outcome plus the frame's seq (so the
/// collector can release it from the in-flight watermark set).
#[cfg(feature = "sync")]
struct ParallelResult {
    seq: i64,
    outcome: Result<VerifyOutcome, StreamError>,
}

#[cfg(feature = "sync")]
type SharedInflight = Arc<std::sync::Mutex<crate::streaming::parallel::InflightSeqs>>;

/// Lock the in-flight set, recovering the guard if a holder panicked. The set
/// is plain bookkeeping (sorted seqs); a poisoned lock carries no torn
/// invariant, so recovering is safe and preferable to propagating a panic into
/// the firehose loop.
#[cfg(feature = "sync")]
fn lock_inflight(
    inflight: &std::sync::Mutex<crate::streaming::parallel::InflightSeqs>,
) -> std::sync::MutexGuard<'_, crate::streaming::parallel::InflightSeqs> {
    inflight
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

#[cfg(feature = "sync")]
struct ParallelState<'a> {
    cursor: Arc<AtomicI64>,
    batch_size: usize,
    batch_timeout: Duration,
    inflight: SharedInflight,
    #[allow(dead_code)]
    scheduler: Arc<crate::streaming::parallel::Scheduler<crate::syntax::Did, ParallelJob>>,
    result_rx: tokio::sync::mpsc::Receiver<ParallelResult>,
    ctrl_rx: tokio::sync::mpsc::Receiver<StreamError>,
    resync_events: tokio::sync::mpsc::Receiver<crate::sync::ResyncEvent>,
    async_errors: tokio::sync::mpsc::Receiver<crate::sync::VerifierError>,
    dispatch: Option<tokio::task::JoinHandle<()>>,
    batch: Vec<Event>,
    pending_error: Option<StreamError>,
    deadline: Option<tokio::time::Instant>,
    _marker: std::marker::PhantomData<&'a ()>,
}

#[cfg(feature = "sync")]
impl Drop for ParallelState<'_> {
    fn drop(&mut self) {
        if let Some(handle) = self.dispatch.take() {
            handle.abort();
        }
    }
}

/// Advance the cursor to the parallel watermark: the highest seq guaranteed
/// fully processed. With work in flight that is `min(inflight) - 1`; when the
/// in-flight set is empty it is the highest seq in the just-flushed batch.
/// Monotonic — never rewinds a consumer's checkpoint.
#[cfg(feature = "sync")]
fn parallel_advance_cursor(state: &ParallelState<'_>, batch: &[Event]) {
    let watermark = lock_inflight(&state.inflight).min();
    let target = if watermark > 0 {
        watermark - 1
    } else {
        batch
            .iter()
            .map(event_seq)
            .filter(|&s| s > 0)
            .max()
            .unwrap_or(0)
    };
    if target > 0 {
        state.cursor.fetch_max(target, Ordering::SeqCst);
    }
}

/// Take the current batch, advance the cursor to the watermark, and return it.
#[cfg(feature = "sync")]
fn parallel_flush(state: &mut ParallelState<'_>) -> Result<Vec<Event>, StreamError> {
    state.deadline = None;
    let batch = std::mem::take(&mut state.batch);
    parallel_advance_cursor(state, &batch);
    Ok(batch)
}

/// Flush any partial batch before an error (stashing the error to yield next),
/// or yield the error directly when the batch is empty.
#[cfg(feature = "sync")]
fn parallel_yield_error(
    mut state: ParallelState<'_>,
    err: StreamError,
) -> Option<(Result<Vec<Event>, StreamError>, ParallelState<'_>)> {
    if !state.batch.is_empty() {
        state.pending_error = Some(err);
        let batch = parallel_flush(&mut state);
        return Some((batch, state));
    }
    state.deadline = None;
    Some((Err(err), state))
}

/// The parallel dispatcher: reads frames, parses them to extract the per-DID
/// key and seq, tracks in-flight seqs, and feeds the scheduler. Reconnects with
/// backoff. Control frames and parse/connection errors flow to `ctrl_tx`;
/// queue overflow drops the oldest in-flight unit and reports it.
#[cfg(feature = "sync")]
#[allow(clippy::too_many_arguments)]
async fn dispatch_loop(
    url: String,
    collections: Option<Vec<String>>,
    dids: Option<Vec<String>>,
    user_agent: String,
    backoff: BackoffPolicy,
    cursor: Arc<AtomicI64>,
    inflight: SharedInflight,
    scheduler: Arc<crate::streaming::parallel::Scheduler<crate::syntax::Did, ParallelJob>>,
    ctrl_tx: tokio::sync::mpsc::Sender<StreamError>,
) {
    use crate::streaming::parallel::AddOutcome;

    let mut attempt: u32 = 0;
    loop {
        let mut ws = match connect_ws(
            &url,
            cursor.load(Ordering::SeqCst),
            &collections,
            &dids,
            &user_agent,
        )
        .await
        {
            Ok(ws) => {
                attempt = 0;
                ws
            }
            Err(e) => {
                if ctrl_tx.send(e).await.is_err() {
                    return;
                }
                let delay = backoff.delay(attempt);
                attempt = attempt.saturating_add(1);
                tokio::time::sleep(delay).await;
                continue;
            }
        };

        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(data))) => {
                    let raw = match crate::streaming::parse_raw_sync_frame(&data) {
                        Ok(raw) => raw,
                        Err(err) => {
                            // Mirror serial behavior: info/sync frames surface
                            // as UnknownType and are skipped by the collector.
                            if ctrl_tx
                                .send(StreamError::ParseCbor(err.to_string()))
                                .await
                                .is_err()
                            {
                                return;
                            }
                            continue;
                        }
                    };
                    let seq = raw_event_seq(&raw);
                    let Some(key) = frame_key(&raw) else {
                        // Control frame (#info): nothing to verify or order.
                        continue;
                    };
                    // Reserve the seq before dispatch so the watermark cannot
                    // advance past an event still queued for verification.
                    lock_inflight(&inflight).add(seq);
                    match scheduler
                        .add_work(key.clone(), ParallelJob { raw, seq })
                        .await
                    {
                        AddOutcome::Queued => {}
                        AddOutcome::Dropped(job) => {
                            lock_inflight(&inflight).remove(job.seq);
                            let err = StreamError::QueueOverflow {
                                did: key.as_str().to_owned(),
                                seq: job.seq,
                            };
                            if ctrl_tx.send(err).await.is_err() {
                                return;
                            }
                        }
                        AddOutcome::ShuttingDown(job) => {
                            lock_inflight(&inflight).remove(job.seq);
                            return;
                        }
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    let delay = backoff.delay(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                    break;
                }
                Some(Ok(_)) => continue, // ping/pong/text
                Some(Err(e)) => {
                    if ctrl_tx
                        .send(StreamError::WebSocket(e.to_string()))
                        .await
                        .is_err()
                    {
                        return;
                    }
                    let delay = backoff.delay(attempt);
                    attempt = attempt.saturating_add(1);
                    tokio::time::sleep(delay).await;
                    break;
                }
            }
        }
    }
}

/// The firehose seq carried by a raw event (0 for control frames).
#[cfg(feature = "sync")]
fn raw_event_seq(raw: &crate::sync::RawSyncEvent) -> i64 {
    match raw {
        crate::sync::RawSyncEvent::Commit(c) => c.seq,
        crate::sync::RawSyncEvent::Sync(s) => s.seq,
        crate::sync::RawSyncEvent::Account(a) => a.seq,
        crate::sync::RawSyncEvent::Identity(i) => i.seq,
        crate::sync::RawSyncEvent::Info => 0,
    }
}

#[cfg(feature = "sync")]
fn event_from_verifier_ops(
    did: crate::syntax::Did,
    rev: crate::syntax::Tid,
    seq: i64,
    ops: Vec<crate::sync::VerifierOp>,
) -> Result<Event, StreamError> {
    let operations = ops
        .into_iter()
        .map(operation_from_verifier_op)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Event::Commit {
        did,
        rev,
        seq,
        operations,
    })
}

#[cfg(feature = "sync")]
fn operation_from_verifier_op(
    op: crate::sync::VerifierOp,
) -> Result<crate::streaming::Operation, StreamError> {
    use crate::streaming::Operation;
    use crate::syntax::{Nsid, RecordKey};

    let (collection, rkey) = op
        .path
        .split_once('/')
        .ok_or_else(|| StreamError::ParseCbor(format!("op path missing '/': {:?}", op.path)))?;
    let collection = Nsid::try_from(collection)
        .map_err(|err| StreamError::ParseCbor(format!("invalid op collection: {err}")))?;
    let rkey = RecordKey::try_from(rkey)
        .map_err(|err| StreamError::ParseCbor(format!("invalid op rkey: {err}")))?;

    match op.action.as_str() {
        "create" => Ok(Operation::Create {
            collection,
            rkey,
            cid: op
                .cid
                .ok_or_else(|| StreamError::ParseCbor("create op missing cid".to_owned()))?,
            record: op.record,
        }),
        "update" => Ok(Operation::Update {
            collection,
            rkey,
            cid: op
                .cid
                .ok_or_else(|| StreamError::ParseCbor("update op missing cid".to_owned()))?,
            record: op.record,
        }),
        "delete" => Ok(Operation::Delete { collection, rkey }),
        "resync" => Ok(Operation::Resync {
            collection,
            rkey,
            cid: op.cid,
            record: op.record,
        }),
        action => Err(StreamError::ParseCbor(format!(
            "unknown verified op action: {action}"
        ))),
    }
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

/// Advance the firehose cursor to the highest seq processed so far, then clear
/// the silent-drop watermark.
///
/// `watermark` is the high-water mark of frames the verifier silently dropped
/// (which never reach the batch but must still advance the checkpoint). The
/// cursor moves to the max of the highest delivered event seq, the watermark,
/// and the current value — it never moves backward, so a stale resync event
/// (seq 0) or an out-of-order flush cannot rewind a consumer's checkpoint.
fn update_firehose_cursor(cursor: &AtomicI64, batch: &[Event], watermark: &mut i64) {
    let batch_max = batch
        .iter()
        .map(event_seq)
        .filter(|&s| s > 0)
        .max()
        .unwrap_or(0);
    let target = batch_max.max(*watermark);
    *watermark = 0;
    if target > 0 {
        cursor.fetch_max(target, Ordering::SeqCst);
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
    fn config_defaults() {
        let cfg = Config::default();
        assert!(cfg.url.is_empty());
        assert!(cfg.cursor.is_none());
        assert!(cfg.user_agent.is_none());
        assert!(cfg.max_message_size.is_none());
        assert!(cfg.batch_size.is_none());
        assert!(cfg.batch_timeout.is_none());
        assert!(cfg.backoff.is_none());
        assert!(cfg.collections.is_none());
        assert!(cfg.dids.is_none());
    }

    #[test]
    fn config_struct_literal() {
        let cfg = Config {
            url: "wss://example.com".into(),
            cursor: Some(12345),
            batch_size: Some(100),
            batch_timeout: Some(Duration::from_secs(2)),
            collections: Some(vec!["app.bsky.feed.post".into()]),
            dids: Some(vec!["did:plc:test123456789abcdefghij".into()]),
            user_agent: Some("my-stream-consumer/1.0".into()),
            ..Config::default()
        };
        assert_eq!(cfg.url, "wss://example.com");
        assert_eq!(cfg.cursor, Some(12345));
        assert_eq!(cfg.batch_size, Some(100));
        assert_eq!(cfg.batch_timeout, Some(Duration::from_secs(2)));
        assert_eq!(cfg.collections.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.dids.as_ref().unwrap().len(), 1);
        assert_eq!(cfg.user_agent.as_deref(), Some("my-stream-consumer/1.0"));
    }

    #[test]
    fn client_resolves_defaults() {
        let client = Client::new(Config {
            url: "wss://example.com".into(),
            ..Config::default()
        });
        assert_eq!(client.cursor(), None);
        assert_eq!(client.user_agent, crate::USER_AGENT);
        assert_eq!(client.batch_size, 50);
        assert_eq!(client.batch_timeout, Duration::from_millis(500));
    }

    #[test]
    fn client_overrides_user_agent() {
        let client = Client::new(Config {
            url: "wss://example.com".into(),
            user_agent: Some("custom-client/2.3".into()),
            ..Config::default()
        });
        assert_eq!(client.user_agent, "custom-client/2.3");
    }

    #[test]
    fn client_cursor_from_config() {
        let client = Client::new(Config {
            url: "wss://example.com".into(),
            cursor: Some(42),
            ..Config::default()
        });
        assert_eq!(client.cursor(), Some(42));
    }

    #[test]
    fn client_overrides_batch_size() {
        let client = Client::new(Config {
            url: "wss://example.com".into(),
            batch_size: Some(200),
            ..Config::default()
        });
        assert_eq!(client.batch_size, 200);
    }

    #[test]
    fn event_seq_extraction() {
        let event = Event::Commit {
            did: crate::syntax::Did::default(),
            rev: crate::syntax::Tid::new(0, 0),
            seq: 999,
            operations: vec![],
        };
        assert_eq!(event_seq(&event), 999);
    }

    #[test]
    fn event_seq_identity() {
        let event = Event::Identity {
            did: crate::syntax::Did::default(),
            seq: 123,
            handle: None,
        };
        assert_eq!(event_seq(&event), 123);
    }

    #[test]
    fn event_seq_account() {
        let event = Event::Account {
            did: crate::syntax::Did::default(),
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
            did: crate::syntax::Did::default(),
            time_us: 1_700_000_000_000_000,
        };
        assert_eq!(jetstream_time_us(&event), 1_700_000_000_000_000);
    }

    #[test]
    fn jetstream_time_us_commit() {
        let event = JetstreamEvent::Commit {
            did: crate::syntax::Did::default(),
            time_us: 42,
            collection: crate::syntax::Nsid::default(),
            rkey: crate::syntax::RecordKey::default(),
            operation: crate::streaming::jetstream::JetstreamCommit::Delete,
        };
        assert_eq!(jetstream_time_us(&event), 42);
    }

    #[test]
    fn jetstream_time_us_account() {
        let event = JetstreamEvent::Account {
            did: crate::syntax::Did::default(),
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
                did: crate::syntax::Did::default(),
                seq: 10,
                handle: None,
            },
            Event::Identity {
                did: crate::syntax::Did::default(),
                seq: 20,
                handle: None,
            },
        ];
        let mut watermark = 0;
        update_firehose_cursor(&cursor, &batch, &mut watermark);
        assert_eq!(cursor.load(Ordering::SeqCst), 20);
    }

    #[test]
    fn update_firehose_cursor_advances_past_silent_drops() {
        // A run of silently-dropped frames (empty batch, high watermark) must
        // still advance the checkpoint, and the watermark is cleared after.
        let cursor = AtomicI64::new(5);
        let mut watermark = 42;
        update_firehose_cursor(&cursor, &[], &mut watermark);
        assert_eq!(cursor.load(Ordering::SeqCst), 42);
        assert_eq!(watermark, 0);
    }

    #[test]
    fn update_firehose_cursor_never_moves_backward() {
        // Already ahead of both the batch and the watermark: no rewind. Guards
        // against stale resync events (seq 0) or out-of-order flushes.
        let cursor = AtomicI64::new(100);
        let batch = vec![Event::Identity {
            did: crate::syntax::Did::default(),
            seq: 20,
            handle: None,
        }];
        let mut watermark = 10;
        update_firehose_cursor(&cursor, &batch, &mut watermark);
        assert_eq!(cursor.load(Ordering::SeqCst), 100);
    }

    #[test]
    fn update_jetstream_cursor_finds_last_time_us() {
        let cursor = AtomicI64::new(-1);
        let batch = vec![
            JetstreamEvent::Identity {
                did: crate::syntax::Did::default(),
                time_us: 100,
            },
            JetstreamEvent::Identity {
                did: crate::syntax::Did::default(),
                time_us: 200,
            },
        ];
        update_jetstream_cursor(&cursor, &batch);
        assert_eq!(cursor.load(Ordering::SeqCst), 200);
    }

    #[test]
    fn websocket_request_sets_shrike_user_agent() {
        let request = websocket_request(
            "wss://example.com/xrpc/com.atproto.sync.subscribeRepos",
            crate::USER_AGENT,
        )
        .unwrap();
        assert_eq!(
            request
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(crate::USER_AGENT)
        );
    }

    #[test]
    fn websocket_request_sets_custom_user_agent() {
        let request = websocket_request(
            "wss://example.com/xrpc/com.atproto.sync.subscribeRepos",
            "custom-client/2.3",
        )
        .unwrap();
        assert_eq!(
            request
                .headers()
                .get(tokio_tungstenite::tungstenite::http::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some("custom-client/2.3")
        );
    }

    #[test]
    fn websocket_request_rejects_invalid_user_agent() {
        let err = websocket_request(
            "wss://example.com/xrpc/com.atproto.sync.subscribeRepos",
            "bad\nagent",
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("invalid User-Agent"),
            "unexpected error: {err}"
        );
    }
}
