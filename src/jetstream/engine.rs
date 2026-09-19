//! The replay/live engine: the join of the archive replay and the live tail.
//!
//! The engine merges the sealed-archive snapshot ([`plan_snapshot`] +
//! [`download_segment`]) and the live WebSocket ([`LiveConsumer`]) into one
//! ordered, duplicate-free event stream, following the archive-to-live recovery
//! state machine in the design:
//!
//! 1. **Validate** the configuration before any I/O.
//! 2. **Pure live** (no [`ArchiveSource`]): run the live tail from the
//!    configured cursor. `CursorTooOld` is immediately fatal — there is no
//!    archive loop to re-enter.
//! 3. **Archive replay**: pin the sealed tip `S`, download the planned segments
//!    under bounded concurrency, and deliver their windowed events in ordered
//!    batches.
//! 4. **Snapshot-only** completion ends here.
//! 5. **Cutover** to the live tail exactly once at `max(S, last_processed_seq)`.
//!    Because `subscribeEvents` resumes *inclusively* and the archive already
//!    covered `(after, S]`, the live subscription resumes from
//!    `max(S, processed) + 1` so the boundary sequence is never delivered twice.
//! 6. On `CursorTooOld` **at cutover** the live tail flushes its pending batch,
//!    and the engine re-enters archive replay from the last processed sequence,
//!    pinning a fresh tip. This repeats until progress stalls: after
//!    [`EngineConfig::max_rebackfill_stalls`] consecutive cycles that neither
//!    advance the processed cursor nor extend archive coverage, the engine
//!    stops with a fatal [`Error::NoProgress`] (mirroring the Go client's
//!    `maxRebackfillStalls`).
//!
//! The engine is transport-generic and carries no `Send` bound, so the same code
//! drives the native and browser transports. Progress is observable through a
//! cheap atomic [`StatsHandle`] snapshot, and in-flight archive downloads are
//! tracked so tests can observe worker cleanup on cancellation.
//!
//! [`plan_snapshot`]: super::planner::plan_snapshot
//! [`download_segment`]: super::download::download_segment
//! [`LiveConsumer`]: super::live::LiveConsumer

use core::future::Future;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use futures::stream::{self, StreamExt};

use super::archive::ArchiveClient;
use super::cancel::CancelToken;
use super::config::Cursor;
use super::download::{DownloadedSegment, download_segment};
use super::error::{Error, Result};
use super::event::{Batch, Delivery, Event, Stats};
use super::filter::Filter;
use super::live::{
    DeliverySink, DictionarySource, LiveConfig, LiveConsumer, LiveCursor, WsTransport,
};
use super::planner::{PlanSegment, SnapshotPlan, plan_snapshot};
use super::transport::HttpTransport;

/// The default bound on consecutive no-progress re-backfill cycles before the
/// engine gives up with [`Error::NoProgress`]. Matches the Go client's
/// `maxRebackfillStalls`.
pub const DEFAULT_MAX_REBACKFILL_STALLS: u32 = 5;

/// The engine's consumer callback surface.
///
/// This is deliberately distinct from the live tail's [`DeliverySink`], because
/// the engine's error model is richer. A **recoverable** error (a dropped
/// archive row, for example) is delivered in order through
/// [`recoverable`](Self::recoverable) and the stream keeps going; the single
/// **terminal** outcome is the return value of [`Engine::run`] and never arrives
/// as a delivery here. Every method returns `false` to ask the engine to stop
/// early because the consumer has gone away; an early stop is clean and makes
/// [`Engine::run`] return `Ok(())`.
pub trait EngineSink {
    /// Deliver one ordered batch or advisory. Returns `false` to stop.
    fn deliver(&mut self, delivery: Delivery) -> impl Future<Output = bool>;

    /// Report one ordered, recoverable error. The stream continues after it.
    /// Returns `false` to stop.
    fn recoverable(&mut self, error: Error) -> impl Future<Output = bool>;
}

/// A source of archive snapshot plans and segment downloads.
///
/// The production implementation ([`ClientArchive`]) delegates to
/// [`plan_snapshot`] and [`download_segment`]; the seam lets the engine's
/// orchestration be driven by in-memory data in tests without scripting the full
/// `.jss` HTTP protocol.
pub trait ArchiveSource {
    /// Build a validated snapshot plan for `filter` over `(after_seq, before_seq]`
    /// (an open `before_seq` means up to the sealed tip), pinning the sealed tip.
    fn plan(
        &self,
        filter: &Filter,
        after_seq: u64,
        before_seq: Option<u64>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<SnapshotPlan>>;

    /// Download one planned segment and return its windowed, ordered events plus
    /// any recoverable row-level drops.
    fn download(
        &self,
        segment: &PlanSegment,
        after_seq: u64,
        before_seq: u64,
        filter: &Filter,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<DownloadedSegment>>;

    /// The maximum number of segment downloads to run concurrently.
    fn concurrency(&self) -> usize;
}

/// The production [`ArchiveSource`], backed by an [`ArchiveClient`].
pub struct ClientArchive<T> {
    client: ArchiveClient<T>,
}

impl<T> ClientArchive<T> {
    /// Wrap an [`ArchiveClient`] as an [`ArchiveSource`].
    pub fn new(client: ArchiveClient<T>) -> Self {
        ClientArchive { client }
    }
}

impl<T: HttpTransport> ArchiveSource for ClientArchive<T> {
    fn plan(
        &self,
        filter: &Filter,
        after_seq: u64,
        before_seq: Option<u64>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<SnapshotPlan>> {
        plan_snapshot(&self.client, filter, after_seq, before_seq, cancel)
    }

    fn download(
        &self,
        segment: &PlanSegment,
        after_seq: u64,
        before_seq: u64,
        filter: &Filter,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<DownloadedSegment>> {
        download_segment(&self.client, segment, after_seq, before_seq, filter, cancel)
    }

    fn concurrency(&self) -> usize {
        self.client.limits().concurrency
    }
}

/// The replay/live engine's configuration.
///
/// The archive window is `(after_seq, before_seq]`; an open `before_seq` runs to
/// the pinned sealed tip. The live tail's own knobs (host, filter, batch size,
/// backoff, compression) live in the embedded [`LiveConfig`], which is also the
/// single source of the subscription [`Filter`]. When an [`ArchiveSource`] is
/// present the engine derives the live resume cursor itself, so
/// [`LiveConfig::cursor`] is ignored in archive mode.
pub struct EngineConfig {
    /// The exclusive lower archive bound. `0` replays from the beginning.
    pub after_seq: u64,
    /// The optional inclusive upper archive bound. `None` runs to the sealed tip.
    pub before_seq: Option<u64>,
    /// Stop after the archive snapshot instead of cutting over to the live tail.
    pub snapshot_only: bool,
    /// The bound on consecutive no-progress re-backfill cycles.
    pub max_rebackfill_stalls: u32,
    /// The live tail configuration (and the source of the subscription filter).
    pub live: LiveConfig,
}

impl EngineConfig {
    /// Build a config wrapping `live` with archive replay from the beginning and
    /// the default re-backfill stall bound.
    pub fn new(live: LiveConfig) -> Self {
        EngineConfig {
            after_seq: 0,
            before_seq: None,
            snapshot_only: false,
            max_rebackfill_stalls: DEFAULT_MAX_REBACKFILL_STALLS,
            live,
        }
    }

    /// Validate the archive-independent parts of the config before any I/O.
    fn validate(&self) -> Result<()> {
        if let Some(before) = self.before_seq
            && before <= self.after_seq
        {
            return Err(Error::InvalidConfig(
                "before_seq must be greater than after_seq",
            ));
        }
        if self.max_rebackfill_stalls == 0 {
            return Err(Error::InvalidConfig("max_rebackfill_stalls must be >= 1"));
        }
        self.live.validate()
    }
}

/// The engine's shared, atomically-updated progress counters.
#[derive(Debug, Default)]
struct AtomicStats {
    /// Archive plan/replan cycles processed.
    pages: AtomicU64,
    /// The pinned sealed-tip sequence `S` (highest seen across replans).
    sealed_tip_seq: AtomicU64,
    /// The sequence archive coverage has reached.
    planned_through_seq: AtomicU64,
    /// Events delivered to the consumer.
    delivered_events: AtomicU64,
    /// The last processed (deduplicated) sequence.
    last_processed_seq: AtomicU64,
    /// Segment downloads currently in flight.
    active_downloads: AtomicUsize,
}

/// A cheap, cloneable handle onto the engine's live progress counters.
///
/// Obtain one with [`Engine::stats`] before calling [`Engine::run`]; it shares
/// the engine's counters, so [`snapshot`](Self::snapshot) reflects progress as
/// the run proceeds. This is a progress view, not a metrics registry.
#[derive(Clone)]
pub struct StatsHandle {
    inner: Arc<AtomicStats>,
}

impl StatsHandle {
    /// A consistent-enough point-in-time [`Stats`] snapshot. The residual gap is
    /// the pinned sealed tip minus coverage, saturating at zero.
    pub fn snapshot(&self) -> Stats {
        let sealed_tip_seq = self.inner.sealed_tip_seq.load(Ordering::Relaxed);
        let planned_through_seq = self.inner.planned_through_seq.load(Ordering::Relaxed);
        Stats {
            pages: self.inner.pages.load(Ordering::Relaxed),
            sealed_tip_seq,
            planned_through_seq,
            residual_gap: sealed_tip_seq.saturating_sub(planned_through_seq),
            delivered_events: self.inner.delivered_events.load(Ordering::Relaxed),
            last_processed_seq: self.inner.last_processed_seq.load(Ordering::Relaxed),
        }
    }

    /// The number of archive segment downloads currently in flight. Returns to
    /// zero once every worker has completed or been cancelled, so tests can
    /// observe clean worker shutdown.
    pub fn active_downloads(&self) -> usize {
        self.inner.active_downloads.load(Ordering::Relaxed)
    }
}

/// An RAII guard that counts one in-flight archive download.
///
/// Created inside each download task, it increments `active_downloads` on
/// construction and decrements on drop, so the count reflects work actually in
/// flight and returns to zero when a task completes *or* is cancelled (its future
/// dropped).
struct WorkerGuard {
    inner: Arc<AtomicStats>,
}

impl WorkerGuard {
    fn new(inner: Arc<AtomicStats>) -> Self {
        inner.active_downloads.fetch_add(1, Ordering::Relaxed);
        WorkerGuard { inner }
    }
}

impl Drop for WorkerGuard {
    fn drop(&mut self) {
        self.inner.active_downloads.fetch_sub(1, Ordering::Relaxed);
    }
}

/// The replay/live engine. Generic over the archive source, WebSocket transport,
/// and dictionary source; the transport and dictionary source must be `Clone` so
/// a fresh live tail can be built at each cutover.
pub struct Engine<A, W, D> {
    archive: Option<A>,
    ws: W,
    dict: D,
    config: EngineConfig,
    cancel: CancelToken,
    stats: Arc<AtomicStats>,
}

impl<A, W, D> Engine<A, W, D>
where
    A: ArchiveSource,
    W: WsTransport + Clone,
    D: DictionarySource + Clone,
{
    /// Build an engine. Pass `Some(archive)` for archive replay + live cutover,
    /// or `None` for a pure-live stream.
    pub fn new(
        archive: Option<A>,
        ws: W,
        dict: D,
        config: EngineConfig,
        cancel: CancelToken,
    ) -> Self {
        let stats = Arc::new(AtomicStats::default());
        // The processed floor starts at the archive lower bound so the cutover
        // math and stall detection are correct even before any event is seen.
        stats
            .last_processed_seq
            .store(config.after_seq, Ordering::Relaxed);
        Engine {
            archive,
            ws,
            dict,
            config,
            cancel,
            stats,
        }
    }

    /// A handle onto this engine's progress counters. Call before [`run`](Self::run).
    pub fn stats(&self) -> StatsHandle {
        StatsHandle {
            inner: self.stats.clone(),
        }
    }

    /// Run the engine to completion, delivering ordered batches, advisories, and
    /// recoverable errors to `sink`.
    ///
    /// Returns `Ok(())` on a clean end: the archive snapshot finished in
    /// snapshot-only mode, the live stream closed, the consumer asked to stop, or
    /// the operation was cancelled. Returns `Err` with the terminal fatal error
    /// otherwise. The fatal error is the return value only; it is never also
    /// delivered to `sink`.
    pub async fn run<S: EngineSink>(self, sink: &mut S) -> Result<()> {
        let Engine {
            archive,
            ws,
            dict,
            config,
            cancel,
            stats,
        } = self;

        config.validate()?;

        // Pure-live guards: archive-window knobs require an archive source.
        if archive.is_none()
            && (config.snapshot_only || config.after_seq != 0 || config.before_seq.is_some())
        {
            return Err(Error::InvalidConfig(
                "snapshot_only/after_seq/before_seq require an archive source",
            ));
        }

        let filter = &config.live.filter;
        let max_batch = config.live.max_batch;
        let can_backfill = archive.is_some();

        // Re-backfill state: the current archive floor and the last cutover's
        // progress markers, used to bound no-progress cycles.
        let mut after = config.after_seq;
        let mut prev_processed = stats.last_processed_seq.load(Ordering::Relaxed);
        let mut prev_tip = 0u64;
        let mut stalls = 0u32;

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }

            // === Archive phase ===
            if let Some(arch) = &archive {
                stats.pages.fetch_add(1, Ordering::Relaxed);
                let plan = match arch.plan(filter, after, config.before_seq, &cancel).await {
                    Ok(plan) => plan,
                    Err(Error::Canceled) => return Ok(()),
                    Err(err) => return Err(err),
                };
                stats
                    .sealed_tip_seq
                    .fetch_max(plan.sealed_tip_seq, Ordering::Relaxed);
                stats
                    .planned_through_seq
                    .fetch_max(plan.before_seq, Ordering::Relaxed);

                match replay_archive(arch, &plan, after, filter, max_batch, &cancel, &stats, sink)
                    .await
                {
                    Ok(true) => return Ok(()), // consumer gone or cancelled
                    Ok(false) => {}
                    Err(err) => return Err(err),
                }

                if config.snapshot_only {
                    return Ok(());
                }
            }

            if cancel.is_cancelled() {
                return Ok(());
            }

            // === Cutover / live phase ===
            let live_config = if can_backfill {
                let tip = stats.sealed_tip_seq.load(Ordering::Relaxed);
                let processed = stats.last_processed_seq.load(Ordering::Relaxed);
                // Resume inclusively from the sequence *after* the covered
                // boundary so the boundary seq is never delivered twice.
                let resume_from = tip.max(processed).saturating_add(1);
                let mut live = config.live.clone();
                live.cursor = LiveCursor::Resume(Cursor::Seq(resume_from));
                live
            } else {
                config.live.clone()
            };

            let mut bridge = LiveBridge {
                user: sink,
                stats: stats.clone(),
                can_backfill,
                outcome: LiveOutcome::Open,
            };
            let consumer =
                LiveConsumer::new(ws.clone(), dict.clone(), live_config, cancel.clone())?;
            consumer.run(&mut bridge).await?;

            match bridge.outcome {
                LiveOutcome::Open | LiveOutcome::Stopped => return Ok(()),
                LiveOutcome::Fatal(err) => return Err(err),
                LiveOutcome::Backfill => {
                    // `CursorTooOld` at cutover with an archive to fall back on.
                    // The live tail already flushed its pending batch (updating
                    // the processed cursor) before delivering the error, so
                    // re-backfill resumes from the last processed sequence.
                    let processed = stats.last_processed_seq.load(Ordering::Relaxed);
                    let tip = stats.sealed_tip_seq.load(Ordering::Relaxed);
                    let advanced = processed > prev_processed || tip > prev_tip;
                    if advanced {
                        stalls = 0;
                    } else {
                        stalls += 1;
                        if stalls >= config.max_rebackfill_stalls {
                            return Err(Error::NoProgress(
                                "archive re-backfill made no forward progress",
                            ));
                        }
                    }
                    prev_processed = processed;
                    prev_tip = tip;
                    after = processed;
                }
            }
        }
    }
}

/// Download and deliver the archive snapshot for `plan` in order.
///
/// Events are windowed and seq-ascending within each segment, and segments come
/// back in plan order, so a running floor over the whole snapshot yields a
/// strictly ascending, duplicate-free stream even if a straddling unit or a
/// misbehaving source overlaps a boundary. Events are batched to `max_batch`;
/// when a segment carries recoverable row drops, the pending batch is flushed
/// first so the ordered errors follow the valid rows that preceded them.
///
/// Returns `Ok(true)` if the consumer asked to stop or the run was cancelled,
/// `Ok(false)` on normal completion, or `Err` on a fatal download error.
#[allow(clippy::too_many_arguments)]
async fn replay_archive<A, S>(
    arch: &A,
    plan: &SnapshotPlan,
    after: u64,
    filter: &Filter,
    max_batch: usize,
    cancel: &CancelToken,
    stats: &Arc<AtomicStats>,
    sink: &mut S,
) -> Result<bool>
where
    A: ArchiveSource,
    S: EngineSink,
{
    let before = plan.before_seq;
    let concurrency = arch.concurrency().max(1);
    let mut buf: Vec<Event> = Vec::new();
    // The dedup floor: only strictly-increasing sequences past it are delivered.
    let mut floor = after;

    let mut downloads = stream::iter(plan.segments.iter().map(|segment| {
        let stats = stats.clone();
        async move {
            let _guard = WorkerGuard::new(stats);
            arch.download(segment, after, before, filter, cancel).await
        }
    }))
    .buffered(concurrency);

    while let Some(result) = downloads.next().await {
        if cancel.is_cancelled() {
            return Ok(true);
        }
        let downloaded = match result {
            Ok(downloaded) => downloaded,
            Err(Error::Canceled) => return Ok(true),
            Err(err) => return Err(err),
        };

        for event in downloaded.events {
            if event.seq > floor {
                floor = event.seq;
                buf.push(event);
                if buf.len() >= max_batch && !flush_archive_batch(&mut buf, stats, sink).await {
                    return Ok(true);
                }
            }
        }

        // Emit recoverable row drops after flushing the rows that preceded them,
        // preserving the "valid rows, then the ordered error" contract.
        if !downloaded.dropped.is_empty() {
            if !flush_archive_batch(&mut buf, stats, sink).await {
                return Ok(true);
            }
            for dropped in downloaded.dropped {
                if !sink.recoverable(dropped).await {
                    return Ok(true);
                }
            }
        }
    }

    if !flush_archive_batch(&mut buf, stats, sink).await {
        return Ok(true);
    }
    Ok(false)
}

/// Flush the pending archive batch to the consumer, updating progress counters.
/// Returns `false` if the consumer has gone away.
async fn flush_archive_batch<S: EngineSink>(
    buf: &mut Vec<Event>,
    stats: &Arc<AtomicStats>,
    sink: &mut S,
) -> bool {
    if buf.is_empty() {
        return true;
    }
    let batch = Batch::new(core::mem::take(buf));
    stats
        .delivered_events
        .fetch_add(batch.len() as u64, Ordering::Relaxed);
    if let Some(cursor) = batch.last_cursor() {
        stats
            .last_processed_seq
            .fetch_max(cursor, Ordering::Relaxed);
    }
    sink.deliver(Delivery::Batch(batch)).await
}

/// What the live tail's session told the engine to do next.
enum LiveOutcome {
    /// The live stream ended cleanly (close or cancellation).
    Open,
    /// `CursorTooOld` at cutover: re-enter archive replay.
    Backfill,
    /// A terminal fatal error to propagate.
    Fatal(Error),
    /// The consumer asked to stop.
    Stopped,
}

/// Adapts an [`EngineSink`] to the live tail's [`DeliverySink`], recording
/// progress and capturing the session's terminal outcome for the engine.
///
/// The live tail only ever delivers `Ok(Delivery)` items and a single terminal
/// `Err`; it never interleaves recoverable errors. So an `Err` here always ends
/// the session: `CursorTooOld` becomes [`LiveOutcome::Backfill`] when an archive
/// fallback exists, and every other error becomes [`LiveOutcome::Fatal`].
struct LiveBridge<'a, S> {
    user: &'a mut S,
    stats: Arc<AtomicStats>,
    can_backfill: bool,
    outcome: LiveOutcome,
}

impl<S: EngineSink> DeliverySink for LiveBridge<'_, S> {
    async fn deliver(&mut self, item: core::result::Result<Delivery, Error>) -> bool {
        match item {
            Ok(Delivery::Batch(batch)) => {
                self.stats
                    .delivered_events
                    .fetch_add(batch.len() as u64, Ordering::Relaxed);
                if let Some(cursor) = batch.last_cursor() {
                    self.stats
                        .last_processed_seq
                        .fetch_max(cursor, Ordering::Relaxed);
                }
                if self.user.deliver(Delivery::Batch(batch)).await {
                    true
                } else {
                    self.outcome = LiveOutcome::Stopped;
                    false
                }
            }
            Ok(Delivery::Info(info)) => {
                if self.user.deliver(Delivery::Info(info)).await {
                    true
                } else {
                    self.outcome = LiveOutcome::Stopped;
                    false
                }
            }
            Err(err) => {
                self.outcome = if self.can_backfill && is_cursor_too_old(&err) {
                    LiveOutcome::Backfill
                } else {
                    LiveOutcome::Fatal(err)
                };
                false
            }
        }
    }
}

/// Whether a protocol error is the pre-upgrade `CursorTooOld` rejection.
fn is_cursor_too_old(err: &Error) -> bool {
    matches!(err, Error::Protocol { name, .. } if name == "CursorTooOld")
}
