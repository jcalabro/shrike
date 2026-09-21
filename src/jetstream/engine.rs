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
//! 3. **Archive replay**: pin the sealed tip `S` on the first plan page, then
//!    interleave planning and downloading page by page — plan a page, download
//!    its segments under bounded concurrency, deliver their windowed events in
//!    ordered batches, then plan the next page — exactly as the Go client
//!    does. A failed segment download is a *recoverable* per-entry error: it is
//!    reported in order through [`EngineSink::recoverable`] and the sweep
//!    continues with the next entry.
//! 4. **Snapshot-only** completion ends here.
//! 5. **Cutover** to the live tail exactly once at
//!    `max(S, last_processed_seq, live_seen_seq)`: the live subscription resumes
//!    *exclusively* from that boundary (the server's inclusive replay of the
//!    boundary itself is deduplicated), so the boundary sequence is never
//!    delivered twice — the Go cutover's `max(S, lastSeq)` floor exactly.
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

use super::archive::ArchiveClient;
use super::cancel::CancelToken;
use super::config::Cursor;
use super::download::{DownloadedSegment, download_segment};
use super::error::{Error, Result};
use super::event::{Batch, Delivery, Event, Sequenced, Stats};
use super::filter::Filter;
use super::live::{
    DeliverySink, DictionarySource, LiveConfig, LiveConsumer, LiveCursor, WsTransport,
};
use super::planner::{PlanPage, PlanSegment, PlanSweep, plan_page};
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
///
/// The delivered item is moved into the callback, so it has reached the consumer
/// by the time the callback returns: `false` is a request to stop *future*
/// deliveries, not a rejection of the item just handed over. Engine progress
/// counters ([`StatsHandle`]) therefore account for that final item too — they
/// report what was delivered, not what the consumer chose to do next.
pub trait EngineSink<E = Event> {
    /// Deliver one ordered batch or advisory. Returns `false` to stop; the item
    /// is still consumed (see the trait-level contract).
    fn deliver(&mut self, delivery: Delivery<E>) -> impl Future<Output = bool>;

    /// Report one ordered, recoverable error. The stream continues after it.
    /// Returns `false` to stop.
    fn recoverable(&mut self, error: Error) -> impl Future<Output = bool>;
}

/// A source of archive snapshot plan pages and segment downloads.
///
/// The production implementation ([`ClientArchive`]) delegates to
/// [`plan_page`] and [`download_segment`]; the seam lets the engine's
/// orchestration be driven by in-memory data in tests without scripting the full
/// `.jss` HTTP protocol. The engine drives planning page by page, interleaved
/// with downloads, and owns the sweep bookkeeping ([`PlanSweep`]).
pub trait ArchiveSource<E = Event> {
    /// Fetch and validate one `planSnapshot` page for `filter`. `after_seq` is
    /// the page's exclusive floor; `pinned_tip` is `None` for a sweep's first
    /// page (send the caller's `before_seq`) and `Some(S)` afterwards (freeze
    /// `beforeSeq` at `S`).
    fn plan_page(
        &self,
        filter: &Filter,
        after_seq: u64,
        before_seq: Option<u64>,
        pinned_tip: Option<u64>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<PlanPage>>;

    /// Download one planned segment and return its windowed, ordered events plus
    /// any recoverable row-level drops.
    fn download(
        &self,
        segment: &PlanSegment,
        after_seq: u64,
        before_seq: u64,
        filter: &Filter,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<DownloadedSegment<E>>>;

    /// The maximum number of segment downloads to run concurrently.
    fn concurrency(&self) -> usize;

    /// The bound on plan pages per sweep before the plan is rejected.
    fn max_plan_pages(&self) -> u32 {
        100_000
    }
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
    fn plan_page(
        &self,
        filter: &Filter,
        after_seq: u64,
        before_seq: Option<u64>,
        pinned_tip: Option<u64>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<PlanPage>> {
        plan_page(
            &self.client,
            filter,
            after_seq,
            before_seq,
            pinned_tip,
            cancel,
        )
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

    fn max_plan_pages(&self) -> u32 {
        self.client.limits().max_plan_pages
    }
}

/// A scoped archive transform. Results are owned, ordered, and use the same
/// transport, window, retry, generation, and corruption rules as owned replay.
pub struct MappedArchive<T, F> {
    client: ArchiveClient<T>,
    map: Arc<F>,
    decode_workers: usize,
}
impl<T> ClientArchive<T> {
    /// Transform validated archive envelopes while their record bytes are
    /// borrowed from the decompressed block. Return owned data to retain it.
    ///
    /// This is decoding, not delivery: calls may run concurrently, outside the
    /// requested window, or before a later error invalidates the whole segment.
    /// Commit external effects only in the ordered sink, after validation.
    pub fn map<F, U>(self, map: F) -> MappedArchive<T, F>
    where
        F: Fn(super::view::EventView<'_>) -> U + Send + Sync + 'static,
        U: Send + 'static,
    {
        MappedArchive {
            client: self.client,
            map: Arc::new(map),
            decode_workers: 1,
        }
    }
}
impl<T, F> MappedArchive<T, F> {
    /// Bound native CPU workers per whole segment; defaults to one. Browser
    /// execution remains sequential with identical ordered results.
    /// With concurrent segments, the total can reach archive concurrency times
    /// this value. Sparse block decoding uses the archive concurrency instead.
    pub fn with_decode_workers(mut self, workers: usize) -> Result<Self> {
        if !(1..=32).contains(&workers) {
            return Err(Error::InvalidConfig("decode workers must be in 1..=32"));
        }
        self.decode_workers = workers;
        Ok(self)
    }
}
impl<T, F, U> ArchiveSource<super::view::MappedEvent<U>> for MappedArchive<T, F>
where
    T: HttpTransport,
    F: Fn(super::view::EventView<'_>) -> U + Send + Sync + 'static,
    U: Send + 'static,
{
    fn plan_page(
        &self,
        filter: &Filter,
        after: u64,
        before: Option<u64>,
        tip: Option<u64>,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<PlanPage>> {
        plan_page(&self.client, filter, after, before, tip, cancel)
    }
    fn download(
        &self,
        segment: &PlanSegment,
        after: u64,
        before: u64,
        filter: &Filter,
        cancel: &CancelToken,
    ) -> impl Future<Output = Result<DownloadedSegment<super::view::MappedEvent<U>>>> {
        let map = self.map.clone();
        super::download::download_segment_mapped_workers(
            &self.client,
            segment,
            after,
            before,
            filter,
            cancel,
            move |event| map(event),
            self.decode_workers,
        )
    }
    fn concurrency(&self) -> usize {
        self.client.limits().concurrency
    }
    fn max_plan_pages(&self) -> u32 {
        self.client.limits().max_plan_pages
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
        if let Some(before) = self.before_seq {
            if before <= self.after_seq {
                return Err(Error::InvalidConfig(
                    "before_seq must be greater than after_seq",
                ));
            }
            // A bounded upper window is only meaningful for a snapshot: an
            // archive-plus-live run would honor `before_seq` for replay and then
            // stream the live tail unbounded, silently exceeding the caller's
            // requested bound.
            if !self.snapshot_only {
                return Err(Error::InvalidConfig(
                    "before_seq requires snapshot_only mode",
                ));
            }
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
    /// Server plan pages fully downloaded and delivered (counted after emit, so
    /// a monitor never sees a page claimed before its work reached the sink).
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

impl<A, W, D> Engine<A, W, D> {
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

    /// Run a scoped-transform archive through the same snapshot state machine.
    /// Only snapshot configurations are accepted; this API never dials live.
    pub async fn run_snapshot<E: Sequenced, S: EngineSink<E>>(self, sink: &mut S) -> Result<()>
    where
        A: ArchiveSource<E>,
    {
        self.config.validate()?;
        if !self.config.snapshot_only {
            return Err(Error::InvalidConfig("run_snapshot requires snapshot_only"));
        }
        let archive = self
            .archive
            .as_ref()
            .ok_or(Error::InvalidConfig("snapshot requires archive source"))?;
        replay_sweep(
            archive,
            self.config.after_seq,
            &self.config,
            &self.cancel,
            &self.stats,
            sink,
        )
        .await?;
        Ok(())
    }
}

impl<A, W, D> Engine<A, W, D>
where
    A: ArchiveSource,
    W: WsTransport + Clone,
    D: DictionarySource + Clone,
{
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

        let can_backfill = archive.is_some();

        // The live "seen" watermark: the highest sequence the live tail has
        // *accepted* (pre-filter), matching the Go consumer's LastSeq. It drives
        // re-backfill resume points and stall detection, so a live stream whose
        // events all fail the filter still counts as forward progress.
        let seen = Arc::new(AtomicU64::new(config.after_seq));

        // Re-backfill state: the current archive floor and the last cutover's
        // progress markers, used to bound no-progress cycles.
        let mut after = config.after_seq;
        let mut prev_processed = stats.last_processed_seq.load(Ordering::Relaxed);
        let mut prev_seen = seen.load(Ordering::Relaxed);
        let mut prev_tip = 0u64;
        let mut stalls = 0u32;

        loop {
            if cancel.is_cancelled() {
                return Ok(());
            }

            // === Archive phase: plan a page, download it, plan the next ===
            if let Some(arch) = &archive {
                if replay_sweep(arch, after, &config, &cancel, &stats, sink).await? {
                    return Ok(());
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
                let seen_seq = seen.load(Ordering::Relaxed);
                // Resume exclusively from the covered boundary — the pinned
                // tip, the delivered cursor, or the live seen watermark,
                // whichever is highest. `Resume(Seq(n))` delivers strictly
                // after `n` (the server's inclusive replay of `n` is
                // deduplicated), so the boundary seq is never delivered twice
                // and an empty archive (`n == 0`) replays from the start —
                // exactly the Go cutover's `max(S, lastSeq)` floor.
                let resume_from = tip.max(processed).max(seen_seq);
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
                LiveConsumer::new(ws.clone(), dict.clone(), live_config, cancel.clone())?
                    .with_seen_watermark(seen.clone());
            consumer.run(&mut bridge).await?;

            match bridge.outcome {
                LiveOutcome::Open | LiveOutcome::Stopped => return Ok(()),
                LiveOutcome::Fatal(err) => return Err(err),
                LiveOutcome::Backfill => {
                    // `CursorTooOld` at cutover with an archive to fall back on.
                    // The live tail already flushed its pending batch (updating
                    // the processed cursor) before delivering the error, so
                    // re-backfill resumes from the highest sequence the live
                    // tail accepted — filtered-out events included, as in Go.
                    let processed = stats.last_processed_seq.load(Ordering::Relaxed);
                    let seen_seq = seen.load(Ordering::Relaxed);
                    let tip = stats.sealed_tip_seq.load(Ordering::Relaxed);
                    let advanced =
                        processed > prev_processed || seen_seq > prev_seen || tip > prev_tip;
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
                    prev_seen = seen_seq;
                    prev_tip = tip;
                    after = processed.max(seen_seq);
                }
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn replay_sweep<A, E, S>(
    arch: &A,
    after: u64,
    config: &EngineConfig,
    cancel: &CancelToken,
    stats: &Arc<AtomicStats>,
    sink: &mut S,
) -> Result<bool>
where
    A: ArchiveSource<E>,
    E: Sequenced,
    S: EngineSink<E>,
{
    let filter = &config.live.filter;
    let max_batch = config.live.max_batch;
    let mut sweep = PlanSweep::new(after, config.before_seq, arch.max_plan_pages());
    // The ascending-delivery floor persists across the whole sweep.
    let mut floor = after;
    loop {
        if cancel.is_cancelled() {
            return Ok(true);
        }
        let (page_after, page_before, pinned) = sweep.bounds();
        let page = match arch
            .plan_page(filter, page_after, page_before, pinned, cancel)
            .await
        {
            Ok(page) => page,
            Err(Error::Canceled) => return Ok(true),
            Err(err) => return Err(err),
        };
        sweep.absorb(&page)?;
        let tip = sweep.tip().unwrap_or_default();
        // The tip is published as soon as it is known (a monitor may
        // see the goal before any download); pages and coverage are
        // published only after the page's work is delivered, so a
        // shrinking residual gap never claims undelivered work.
        stats.sealed_tip_seq.fetch_max(tip, Ordering::Relaxed);

        match replay_page(
            arch,
            &page.segments,
            page_after,
            tip,
            filter,
            max_batch,
            cancel,
            stats,
            sink,
            &mut floor,
        )
        .await
        {
            Ok(true) => return Ok(true), // consumer gone or cancelled
            Ok(false) => {}
            Err(err) => return Err(err),
        }

        stats.pages.fetch_add(1, Ordering::Relaxed);
        stats
            .planned_through_seq
            .fetch_max(sweep.planned_through(), Ordering::Relaxed);

        if sweep.done() {
            break;
        }
    }
    Ok(false)
}

/// Download and deliver one plan page's segments in order.
///
/// The [`ArchiveSource`] contract requires each segment's events to be
/// seq-ascending and the segments themselves to be globally ordered and
/// non-overlapping in plan order. Given that, the running `floor` (persisting
/// across a sweep's pages) yields a strictly ascending, duplicate-free stream:
/// events at or below `after` (already covered) are skipped, and a straddling
/// unit that repeats the boundary seq is collapsed. If a segment violates the
/// ordering contract — an in-window seq that regresses below one already
/// delivered — the plan is rejected as [`Error::PlanInvalid`] rather than
/// silently dropping the out-of-order event, since merging arbitrary overlap
/// would require unbounded buffering.
///
/// Events are batched to `max_batch` and the pending batch is flushed at each
/// segment boundary, so delivery latency is bounded by a segment's download,
/// mirroring the Go engine's block-aligned emission. A segment whose download or
/// decode fails is a *recoverable* per-entry error, as in Go: its decoded prefix
/// (blocks mode) is delivered, the ordered error follows through
/// [`EngineSink::recoverable`], and the sweep continues with the next entry.
/// Cancellation flushes the pending batch before stopping.
///
/// Returns `Ok(true)` if the consumer asked to stop or the run was cancelled,
/// `Ok(false)` on normal completion, or `Err` on a fatal error.
#[allow(clippy::too_many_arguments)]
async fn replay_page<A, S, E>(
    arch: &A,
    segments: &[PlanSegment],
    after: u64,
    before: u64,
    filter: &Filter,
    max_batch: usize,
    cancel: &CancelToken,
    stats: &Arc<AtomicStats>,
    sink: &mut S,
    floor: &mut u64,
) -> Result<bool>
where
    A: ArchiveSource<E>,
    E: Sequenced,
    S: EngineSink<E>,
{
    let concurrency = arch.concurrency().max(1);
    let mut buf: Vec<E> = Vec::new();

    let mut downloads = super::ordered::OrderedDownloads::new(
        segments.iter().map(|segment| {
            let stats = stats.clone();
            async move {
                let _guard = WorkerGuard::new(stats);
                arch.download(segment, after, before, filter, cancel).await
            }
        }),
        concurrency,
    );

    while let Some(result) = downloads.next().await {
        if cancel.is_cancelled() {
            // Deliver what was already decoded before winding down, as in Go,
            // where the final flush runs even after ctx cancellation.
            let _ = downloads
                .during(flush_archive_batch(&mut buf, stats, sink))
                .await;
            return Ok(true);
        }
        let downloaded = match result {
            Ok(downloaded) => downloaded,
            Err(Error::Canceled) => {
                let _ = downloads
                    .during(flush_archive_batch(&mut buf, stats, sink))
                    .await;
                return Ok(true);
            }
            // A failed entry is recoverable: report it in order and keep the
            // sweep going (Go's per-entry error contract). Later entries carry
            // higher sequences, so ordering is preserved.
            Err(err) => {
                if !downloads
                    .during(flush_archive_batch(&mut buf, stats, sink))
                    .await
                    || !downloads.during(sink.recoverable(err)).await
                {
                    return Ok(true);
                }
                continue;
            }
        };

        // Each delivery transfers the batch allocation to the consumer. Reserve
        // the next batch once, instead of repeatedly growing and copying it.
        // Cap the eager reservation independently of a caller's batch limit.
        let batch_reservation = max_batch.min(downloaded.events.len()).min(1024);
        for event in downloaded.events {
            // Already delivered before this run, or the same boundary event
            // repeated by a straddling unit or an inclusive segment boundary:
            // collapse without advancing. These are duplicates of an event we
            // have already emitted, not distinct data.
            if event.sequence() <= after || event.sequence() == *floor {
                continue;
            }
            // A *lower* seq inside the window, arriving after a higher one, is a
            // distinct event out of order: the source violated the global
            // ordering contract. Merging arbitrary overlap would need unbounded
            // buffering, so fail loud instead of silently dropping the event.
            if event.sequence() < *floor {
                return Err(Error::PlanInvalid(
                    "archive events are not strictly increasing across segments",
                ));
            }
            *floor = event.sequence();
            if buf.capacity() == 0 {
                buf.reserve(batch_reservation);
            }
            buf.push(event);
            if buf.len() >= max_batch
                && !downloads
                    .during(flush_archive_batch(&mut buf, stats, sink))
                    .await
            {
                return Ok(true);
            }
        }

        // Emit recoverable row drops after flushing the rows that preceded them,
        // preserving the "valid rows, then the ordered error" contract.
        if !downloaded.dropped.is_empty() {
            if !downloads
                .during(flush_archive_batch(&mut buf, stats, sink))
                .await
            {
                return Ok(true);
            }
            for dropped in downloaded.dropped {
                if !downloads.during(sink.recoverable(dropped)).await {
                    return Ok(true);
                }
            }
        }

        // A blocks-mode entry that failed partway delivers its decoded prefix
        // above, then its ordered per-entry error; the sweep continues.
        if let Some(failure) = downloaded.failure {
            if !downloads
                .during(flush_archive_batch(&mut buf, stats, sink))
                .await
                || !downloads.during(sink.recoverable(failure)).await
            {
                return Ok(true);
            }
            continue;
        }

        // Flush at the segment boundary so delivery latency is bounded by one
        // segment, not by the whole sweep.
        if !downloads
            .during(flush_archive_batch(&mut buf, stats, sink))
            .await
        {
            return Ok(true);
        }
    }

    if !downloads
        .during(flush_archive_batch(&mut buf, stats, sink))
        .await
    {
        return Ok(true);
    }
    Ok(false)
}

/// Flush the pending archive batch to the consumer, updating progress counters.
/// Returns `false` if the consumer has gone away.
async fn flush_archive_batch<E: Sequenced, S: EngineSink<E>>(
    buf: &mut Vec<E>,
    stats: &Arc<AtomicStats>,
    sink: &mut S,
) -> bool {
    if buf.is_empty() {
        return true;
    }
    let batch = Batch::new(core::mem::take(buf));
    // The batch is moved into `deliver`, so the consumer has received it by the
    // time this returns; a `false` return only asks us to stop sending more (see
    // the `EngineSink` contract). Progress therefore reflects this batch whether
    // or not the consumer wants further deliveries.
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
                // The batch is moved into `deliver`, so it has reached the
                // consumer regardless of the return value; `false` only asks us
                // to stop sending more (see the `EngineSink` contract), so
                // progress reflects this batch either way.
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

    async fn recoverable(&mut self, error: Error) -> bool {
        // Ordered recoverable errors from the live tail (malformed frames,
        // reconnect notices) flow straight through to the engine consumer.
        if self.user.recoverable(error).await {
            true
        } else {
            self.outcome = LiveOutcome::Stopped;
            false
        }
    }
}

/// Whether a protocol error is the pre-upgrade `CursorTooOld` rejection.
fn is_cursor_too_old(err: &Error) -> bool {
    matches!(err, Error::Protocol { name, .. } if name == "CursorTooOld")
}
