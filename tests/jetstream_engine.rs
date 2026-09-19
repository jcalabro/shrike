//! M5 replay/live engine acceptance tests.
//!
//! These tests drive the [`Engine`] — the join of the sealed-archive replay and
//! the live WebSocket tail — against deterministic, in-memory seams:
//!
//! - a scripted [`ArchiveSource`] ([`MockArchive`]) that serves programmed
//!   snapshot plans and segment downloads, with per-segment completion delays
//!   (to force out-of-order download completion), recoverable row drops, and a
//!   mutating "server" that can grow its sealed tip across re-plan cycles; and
//! - a scripted [`WsTransport`] ([`ScriptedWs`]) that replays proposal-0015
//!   frames per live session, plus a source that always rejects with a given
//!   protocol error ([`AlwaysProtoWs`]) for the re-backfill and stall paths.
//!
//! Correctness is checked against an **independent** synchronous replay oracle
//! ([`oracle`]) built on a normalized test event type ([`Me`]). The oracle
//! reimplements windowing, filtering, ordering, and cross-cutover dedup from
//! scratch — it does not call the production filter, batch, retry, or engine
//! code — so agreement between the engine and the oracle is a genuine cross-check
//! rather than a tautology. A property test drives random worlds through both.
//!
//! Together the cases cover the M5 acceptance list: ordered, duplicate-free
//! delivery across pagination (multi-segment plans), parallel completion,
//! sparse filters, seq gaps, cutover overlap, repeated `CursorTooOld`
//! re-backfill, the no-progress stall guard, cancellation with worker cleanup,
//! and server mutation.

#![cfg(feature = "jetstream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;
use std::time::Duration;

use proptest::prelude::*;

use shrike::jetstream::{
    ArchiveSource, CancelToken, Delivery, DialError, DictionarySource, DownloadedSegment, Engine,
    EngineConfig, EngineSink, Error, Event, Filter, LiveConfig, LiveFrame, PlanSegment,
    SegmentMode, SnapshotPlan, WsConnection, WsError, WsMessage, WsTransport, parse_live_frame,
};

// ===========================================================================
// Normalized test event + frame builders
// ===========================================================================

/// A normalized test event: just the sequence and collection the oracle and the
/// scripted sources reason about. All test events are `delete` commits (no
/// record body), so the collection is the only filterable axis exercised here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Me {
    seq: u64,
    coll: &'static str,
}

impl Me {
    fn new(seq: u64, coll: &'static str) -> Self {
        Me { seq, coll }
    }
}

/// The valid NSID collection pool the tests draw from.
const COLLS: [&str; 3] = [
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "app.bsky.graph.follow",
];

const DID: &str = "did:plc:abcdefghijklmnopqrstuvwx";
const TIME: &str = "2024-01-01T00:00:00.000000Z";
const REV: &str = "3l3qo2vutsw2b";
const RKEY: &str = "3l3qo2vuowo2b";

/// A proposal-0015 `#commit` (delete) text frame.
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

/// A proposal-0015 `#info` advisory text frame.
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

/// A terminal `error` envelope text frame (classified by name).
fn error_text(name: &str) -> String {
    serde_json::json!({"$type": "error", "error": name, "message": "x"}).to_string()
}

/// Build a production [`Event`] for a normalized test event by parsing a live
/// commit frame. This is test infrastructure feeding the engine, not part of the
/// oracle.
fn make_event(me: Me) -> Event {
    match parse_live_frame(commit_text(me.seq, me.coll).as_bytes()) {
        Ok(Some(LiveFrame::Event(event))) => event,
        other => panic!("failed to build test event: {other:?}"),
    }
}

// ===========================================================================
// Independent replay oracle
// ===========================================================================

/// Whether a collection passes the filter described by `allowed`. An empty
/// `allowed` is match-all (mirrors `Filter::new()`); otherwise membership.
fn allows(allowed: &[&str], coll: &str) -> bool {
    allowed.is_empty() || allowed.contains(&coll)
}

/// The independent, synchronous replay model.
///
/// Given the full archive world (any order), the pinned sealed tip, the archive
/// lower bound, the filter, and — for the live phase — the frames the tail will
/// emit in order, this returns the exact sequence of event `seq`s the engine is
/// expected to deliver. It reimplements the engine's contract from first
/// principles: window `(after, tip]`, filter, strictly-increasing dedup, then a
/// single inclusive cutover at `max(tip, processed)` for the live tail.
fn oracle(
    world: &[Me],
    tip: u64,
    after: u64,
    allowed: &[&str],
    snapshot_only: bool,
    live: &[Me],
) -> Vec<u64> {
    let mut sorted = world.to_vec();
    sorted.sort_by_key(|e| e.seq);

    let mut out = Vec::new();
    let mut floor = after;
    for e in &sorted {
        if e.seq > after && e.seq <= tip && allows(allowed, e.coll) && e.seq > floor {
            floor = e.seq;
            out.push(e.seq);
        }
    }

    if snapshot_only {
        return out;
    }

    // The live tail resumes inclusively from `max(tip, processed) + 1`, so its
    // dedup floor is `max(tip, processed)`; a frame at or below it is a boundary
    // duplicate and is dropped without lowering the floor.
    let mut live_floor = tip.max(floor);
    for e in live {
        if allows(allowed, e.coll) && e.seq > live_floor {
            live_floor = e.seq;
            out.push(e.seq);
        }
    }
    out
}

// ===========================================================================
// Scripted archive source
// ===========================================================================

/// One programmed segment: the raw events it covers (unfiltered, unwindowed),
/// the recoverable row-drop messages it reports, and a completion delay used to
/// force out-of-order download completion.
#[derive(Clone)]
struct Segment {
    name: String,
    index: u64,
    min_seq: u64,
    max_seq: u64,
    raw: Vec<Me>,
    dropped: Vec<&'static str>,
    delay_ms: u64,
}

/// One "server generation": what a single `plan()` call observes. Re-backfill
/// consumes successive generations, modeling a server whose sealed tip grows.
#[derive(Clone)]
struct Generation {
    tip: u64,
    after: u64,
    segments: Vec<Segment>,
}

/// A scripted [`ArchiveSource`]. `plan()` consumes the next generation (retaining
/// the last one as a steady state, so repeated re-plans without new data model a
/// stall), and `download()` returns each segment's windowed, filtered, ordered
/// events after its programmed delay, racing cancellation.
struct MockArchive {
    gens: RefCell<VecDeque<Generation>>,
    current: RefCell<Vec<Segment>>,
    allowed: Vec<&'static str>,
    concurrency: usize,
}

impl MockArchive {
    fn new(gens: Vec<Generation>, allowed: Vec<&'static str>, concurrency: usize) -> Self {
        MockArchive {
            gens: RefCell::new(gens.into()),
            current: RefCell::new(Vec::new()),
            allowed,
            concurrency: concurrency.max(1),
        }
    }
}

/// Wait until `cancel` is cancelled, polling under a paused clock. `cancelled()`
/// is crate-private, so tests poll the public predicate instead.
async fn wait_cancel(cancel: &CancelToken) {
    while !cancel.is_cancelled() {
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
}

impl ArchiveSource for MockArchive {
    async fn plan(
        &self,
        _filter: &Filter,
        _after_seq: u64,
        before_seq: Option<u64>,
        _cancel: &CancelToken,
    ) -> core::result::Result<SnapshotPlan, Error> {
        let generation = {
            let mut gens = self.gens.borrow_mut();
            if gens.len() > 1 {
                gens.pop_front().expect("len checked")
            } else {
                gens.front().cloned().unwrap_or(Generation {
                    tip: 0,
                    after: 0,
                    segments: Vec::new(),
                })
            }
        };
        *self.current.borrow_mut() = generation.segments.clone();
        // Honor a caller-requested upper bound (snapshot-only), defaulting to the
        // sealed tip when unbounded.
        let before_seq = before_seq.unwrap_or(generation.tip).min(generation.tip);
        Ok(SnapshotPlan {
            sealed_tip_seq: generation.tip,
            after_seq: generation.after,
            before_seq,
            segments: generation
                .segments
                .iter()
                .map(|s| PlanSegment {
                    name: s.name.clone(),
                    index: s.index,
                    min_seq: s.min_seq,
                    max_seq: s.max_seq,
                    checksum: "0000000000000000".to_owned(),
                    mode: SegmentMode::Whole,
                })
                .collect(),
        })
    }

    async fn download(
        &self,
        segment: &PlanSegment,
        after_seq: u64,
        before_seq: u64,
        _filter: &Filter,
        cancel: &CancelToken,
    ) -> core::result::Result<DownloadedSegment, Error> {
        // Clone the segment's data out before any await so no RefCell borrow is
        // held across a suspension point.
        let seg = self
            .current
            .borrow()
            .iter()
            .find(|s| s.name == segment.name)
            .cloned();
        let Some(seg) = seg else {
            return Ok(DownloadedSegment::default());
        };

        if seg.delay_ms > 0 {
            let sleep = tokio::time::sleep(Duration::from_millis(seg.delay_ms));
            tokio::select! {
                _ = sleep => {}
                _ = wait_cancel(cancel) => return Err(Error::Canceled),
            }
        } else if cancel.is_cancelled() {
            return Err(Error::Canceled);
        }

        let mut events: Vec<Event> = seg
            .raw
            .iter()
            .filter(|e| e.seq > after_seq && e.seq <= before_seq && allows(&self.allowed, e.coll))
            .map(|e| make_event(*e))
            .collect();
        events.sort_by_key(|e| e.seq);
        let dropped = seg
            .dropped
            .iter()
            .map(|m| Error::protocol("BadArchiveRow", Some(*m)))
            .collect();
        Ok(DownloadedSegment { events, dropped })
    }

    fn concurrency(&self) -> usize {
        self.concurrency
    }
}

/// Build contiguous segments from a world, split into `n_seg` chunks in seq
/// order (each chunk is a "page" of the plan).
fn segments_from(world: &[Me], n_seg: usize) -> Vec<Segment> {
    if world.is_empty() {
        return Vec::new();
    }
    let mut sorted = world.to_vec();
    sorted.sort_by_key(|e| e.seq);
    let n = n_seg.clamp(1, sorted.len());
    let chunk = sorted.len().div_ceil(n);
    sorted
        .chunks(chunk)
        .enumerate()
        .map(|(i, ch)| Segment {
            name: format!("seg-{i}.jss"),
            index: i as u64,
            min_seq: ch.first().map(|e| e.seq).unwrap_or(0),
            max_seq: ch.last().map(|e| e.seq).unwrap_or(0),
            raw: ch.to_vec(),
            dropped: Vec::new(),
            delay_ms: 0,
        })
        .collect()
}

// ===========================================================================
// Scripted WebSocket transport + dictionary source
// ===========================================================================

/// One programmed action a scripted connection yields from `read`.
#[derive(Clone)]
enum Action {
    Text(String),
    Close,
}

/// A scripted WebSocket transport: each dial pops the next session's action
/// list. When sessions run out it yields a single fatal `InvalidRequest` error
/// frame — a deliberate safety net so a bug that fails to stop the tail
/// surfaces as a terminal error (and a failing assertion) rather than an
/// infinite reconnect loop.
#[derive(Clone)]
struct ScriptedWs {
    sessions: Rc<RefCell<VecDeque<Vec<Action>>>>,
    dials: Rc<RefCell<usize>>,
}

impl ScriptedWs {
    fn new(sessions: Vec<Vec<Action>>) -> Self {
        ScriptedWs {
            sessions: Rc::new(RefCell::new(sessions.into())),
            dials: Rc::new(RefCell::new(0)),
        }
    }

    fn dial_count(&self) -> usize {
        *self.dials.borrow()
    }
}

struct ScriptedConn {
    actions: VecDeque<Action>,
}

impl WsConnection for ScriptedConn {
    async fn read(&mut self) -> core::result::Result<Option<WsMessage>, WsError> {
        match self.actions.pop_front() {
            Some(Action::Text(s)) => Ok(Some(WsMessage::Text(s.into_bytes()))),
            Some(Action::Close) | None => Ok(None),
        }
    }

    async fn close(&mut self) {}
}

impl WsTransport for ScriptedWs {
    type Conn = ScriptedConn;

    async fn dial(
        &self,
        _url: String,
        _subprotocol: &'static str,
    ) -> core::result::Result<Self::Conn, DialError> {
        *self.dials.borrow_mut() += 1;
        let actions = self
            .sessions
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| vec![Action::Text(error_text("InvalidRequest"))]);
        Ok(ScriptedConn {
            actions: actions.into(),
        })
    }
}

/// A transport whose every dial rejects with a pre-upgrade HTTP error carrying
/// the given XRPC error name. Used to drive repeated cutover rejections.
#[derive(Clone)]
struct AlwaysProtoWs {
    name: &'static str,
    dials: Rc<RefCell<usize>>,
}

impl AlwaysProtoWs {
    fn new(name: &'static str) -> Self {
        AlwaysProtoWs {
            name,
            dials: Rc::new(RefCell::new(0)),
        }
    }
}

impl WsTransport for AlwaysProtoWs {
    type Conn = ScriptedConn;

    async fn dial(
        &self,
        _url: String,
        _subprotocol: &'static str,
    ) -> core::result::Result<Self::Conn, DialError> {
        *self.dials.borrow_mut() += 1;
        Err(DialError::Http {
            status: 400,
            body: error_text(self.name).into_bytes(),
        })
    }
}

/// A dictionary source that never yields a dictionary (compression is disabled
/// in these tests, so it is never actually consulted).
#[derive(Clone)]
struct NoDict;

impl DictionarySource for NoDict {
    async fn fetch(&self, _id: Option<u32>) -> core::result::Result<Vec<u8>, Error> {
        Err(Error::protocol("NoDictionary", None::<String>))
    }
}

// ===========================================================================
// Recording sink
// ===========================================================================

/// One recorded delivery, preserving relative order across batches, advisories,
/// and recoverable errors.
#[derive(Debug)]
enum Rec {
    Batch(Vec<u64>),
    Info(String),
    Recoverable(String),
}

/// An [`EngineSink`] that records everything and stops the engine once it has
/// delivered `stop_after` events (counting individual events across batches).
struct RecordingSink {
    log: Vec<Rec>,
    events: usize,
    stop_after: usize,
    cancel: Option<CancelToken>,
}

impl RecordingSink {
    fn new(stop_after: usize, cancel: Option<CancelToken>) -> Self {
        RecordingSink {
            log: Vec::new(),
            events: 0,
            stop_after,
            cancel,
        }
    }

    /// All delivered sequences, in order across batches.
    fn seqs(&self) -> Vec<u64> {
        let mut out = Vec::new();
        for rec in &self.log {
            if let Rec::Batch(seqs) = rec {
                out.extend_from_slice(seqs);
            }
        }
        out
    }

    fn recoverable_msgs(&self) -> Vec<&str> {
        self.log
            .iter()
            .filter_map(|r| match r {
                Rec::Recoverable(msg) => Some(msg.as_str()),
                _ => None,
            })
            .collect()
    }

    fn infos(&self) -> Vec<&str> {
        self.log
            .iter()
            .filter_map(|r| match r {
                Rec::Info(name) => Some(name.as_str()),
                _ => None,
            })
            .collect()
    }
}

impl EngineSink for RecordingSink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        match delivery {
            Delivery::Batch(batch) => {
                let seqs: Vec<u64> = batch.events().iter().map(|e| e.seq).collect();
                self.events += seqs.len();
                self.log.push(Rec::Batch(seqs));
            }
            Delivery::Info(info) => self.log.push(Rec::Info(info.name)),
        }
        if self.events >= self.stop_after {
            if let Some(cancel) = &self.cancel {
                cancel.cancel();
            }
            return false;
        }
        true
    }

    async fn recoverable(&mut self, error: Error) -> bool {
        self.log.push(Rec::Recoverable(error.to_string()));
        true
    }
}

// ===========================================================================
// Config + run helpers
// ===========================================================================

fn build_filter(allowed: &[&str]) -> Filter {
    if allowed.is_empty() {
        Filter::new()
    } else {
        Filter::new()
            .collections(allowed.iter().copied())
            .expect("valid collections")
    }
}

fn live_config(filter: Filter, max_batch: usize) -> LiveConfig {
    let mut config = LiveConfig::new("jetstream.test", true);
    config.compression = false;
    config.filter = filter;
    config.max_batch = max_batch;
    config
}

/// Turn a live world into a scripted single-session action list: every frame,
/// then a clean close.
fn live_session(frames: &[Me]) -> Vec<Action> {
    let mut actions: Vec<Action> = frames
        .iter()
        .map(|f| Action::Text(commit_text(f.seq, f.coll)))
        .collect();
    actions.push(Action::Close);
    actions
}

// ===========================================================================
// Deterministic tests
// ===========================================================================

/// Multi-segment (paginated) archive with sequence gaps, snapshot-only: events
/// are stitched across segments into one ordered, gap-preserving stream.
#[tokio::test(start_paused = true)]
async fn archive_ordered_across_segments_snapshot_only() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(3, COLLS[1]),
        Me::new(4, COLLS[0]),
        Me::new(7, COLLS[2]),
        Me::new(9, COLLS[0]),
    ];
    let tip = 9;
    let segments = segments_from(&world, 3);
    let archive = MockArchive::new(
        vec![Generation {
            tip,
            after: 0,
            segments,
        }],
        Vec::new(),
        4,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&[]), 2));
    config.snapshot_only = true;

    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok(), "snapshot run should be Ok: {res:?}");
    let expected = oracle(&world, tip, 0, &[], true, &[]);
    assert_eq!(sink.seqs(), expected);
    assert_eq!(sink.seqs(), vec![1, 3, 4, 7, 9]);
}

/// Segments whose downloads complete out of order (earlier plan segments finish
/// later) still deliver in ascending plan order — `buffered` preserves order.
#[tokio::test(start_paused = true)]
async fn parallel_completion_preserves_order() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[0]),
    ];
    // Two segments: the earlier one is slow, the later one is fast, so the fast
    // (higher-seq) segment's download completes first.
    let mut segments = segments_from(&world, 2);
    segments[0].delay_ms = 100;
    segments[1].delay_ms = 5;

    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments,
        }],
        Vec::new(),
        4,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;

    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    assert_eq!(sink.seqs(), vec![1, 2, 3, 4]);
}

/// A collection filter drops non-matching archive rows; only matching events are
/// delivered, in order.
#[tokio::test(start_paused = true)]
async fn sparse_filter_drops_nonmatching() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[1]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[2]),
        Me::new(5, COLLS[0]),
    ];
    let allowed = vec![COLLS[0]];
    let tip = 5;
    let archive = MockArchive::new(
        vec![Generation {
            tip,
            after: 0,
            segments: segments_from(&world, 2),
        }],
        allowed.clone(),
        4,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&allowed), 8));
    config.snapshot_only = true;

    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    let expected = oracle(&world, tip, 0, &allowed, true, &[]);
    assert_eq!(sink.seqs(), expected);
    assert_eq!(sink.seqs(), vec![1, 3, 5]);
}

/// The archive covers `(0, S]`; the live tail replays the boundary inclusively.
/// The engine must resume from `S + 1` so the boundary sequences are never
/// delivered twice, while genuinely new live events flow through.
#[tokio::test(start_paused = true)]
async fn cutover_overlap_dedups_boundary() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
    ];
    let tip = 3;
    // The live tail replays 2 and 3 (boundary duplicates) before new 4 and 5.
    let live = vec![
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[0]),
        Me::new(5, COLLS[0]),
    ];
    let archive = MockArchive::new(
        vec![Generation {
            tip,
            after: 0,
            segments: segments_from(&world, 1),
        }],
        Vec::new(),
        4,
    );

    let config = EngineConfig::new(live_config(build_filter(&[]), 8));
    let cancel = CancelToken::new();
    let ws = ScriptedWs::new(vec![live_session(&live)]);
    let expected = oracle(&world, tip, 0, &[], false, &live);
    assert_eq!(expected, vec![1, 2, 3, 4, 5]);

    let engine = Engine::new(Some(archive), ws, NoDict, config, cancel.clone());
    let mut sink = RecordingSink::new(expected.len(), Some(cancel));
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok(), "run should be Ok: {res:?}");
    assert_eq!(sink.seqs(), expected);
}

/// A `CursorTooOld` rejection at cutover triggers a re-backfill: the engine
/// re-plans (against a server whose tip has grown — mutation), replays the newly
/// sealed range, and cuts over again to a live tail that now succeeds. The whole
/// stream is ordered and duplicate-free.
#[tokio::test(start_paused = true)]
async fn repeated_cursor_too_old_rebackfills() {
    // Generation 1: sealed tip 3.
    let world1 = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
    ];
    // Generation 2: server has grown; sealed tip 6, covering (3, 6].
    let world2 = vec![
        Me::new(4, COLLS[0]),
        Me::new(5, COLLS[0]),
        Me::new(6, COLLS[0]),
    ];
    let gens = vec![
        Generation {
            tip: 3,
            after: 0,
            segments: segments_from(&world1, 1),
        },
        Generation {
            tip: 6,
            after: 3,
            segments: segments_from(&world2, 1),
        },
    ];
    let archive = MockArchive::new(gens, Vec::new(), 4);

    // First live session rejects with CursorTooOld; second delivers 7 and 8.
    let sessions = vec![
        vec![Action::Text(error_text("CursorTooOld"))],
        live_session(&[Me::new(7, COLLS[0]), Me::new(8, COLLS[0])]),
    ];
    let ws = ScriptedWs::new(sessions);

    let config = EngineConfig::new(live_config(build_filter(&[]), 8));
    let cancel = CancelToken::new();
    let engine = Engine::new(Some(archive), ws.clone(), NoDict, config, cancel.clone());
    let stats = engine.stats();
    let mut sink = RecordingSink::new(8, Some(cancel));
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok(), "re-backfill run should be Ok: {res:?}");
    assert_eq!(sink.seqs(), vec![1, 2, 3, 4, 5, 6, 7, 8]);
    // Two live dials: the rejected one and the successful one.
    assert_eq!(ws.dial_count(), 2);
    // The engine planned twice (initial + one re-backfill).
    assert_eq!(stats.snapshot().pages, 2);
    assert_eq!(stats.snapshot().sealed_tip_seq, 6);
}

/// Repeated `CursorTooOld` with no forward progress (the server never seals new
/// data) is bounded: after `max_rebackfill_stalls` fruitless cycles the engine
/// gives up with a fatal `NoProgress`, rather than looping forever.
#[tokio::test(start_paused = true)]
async fn rebackfill_stall_returns_no_progress() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
    ];
    // A single generation, reused on every re-plan: the tip never grows, so the
    // re-backfill can never catch the (perpetually rejecting) live tail.
    let archive = MockArchive::new(
        vec![Generation {
            tip: 3,
            after: 0,
            segments: segments_from(&world, 1),
        }],
        Vec::new(),
        4,
    );

    let ws = AlwaysProtoWs::new("CursorTooOld");
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.max_rebackfill_stalls = 2;

    let cancel = CancelToken::new();
    let engine = Engine::new(Some(archive), ws, NoDict, config, cancel);
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(
        matches!(res, Err(Error::NoProgress(_))),
        "expected NoProgress, got {res:?}"
    );
    // The archive events were still delivered (once) before the stall.
    assert_eq!(sink.seqs(), vec![1, 2, 3]);
}

/// Cancellation mid-download stops the run cleanly and every in-flight worker is
/// torn down: `active_downloads` peaks above zero and returns to zero.
#[tokio::test(start_paused = true)]
async fn cancellation_cleans_up_workers() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[0]),
    ];
    // Four one-event segments, each with a long delay, so all four downloads are
    // in flight (and stuck) when we cancel.
    let mut segments = segments_from(&world, 4);
    for seg in &mut segments {
        seg.delay_ms = 10_000;
    }
    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments,
        }],
        Vec::new(),
        4,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;

    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel.clone(),
    );
    let stats = engine.stats();
    let mut sink = RecordingSink::new(usize::MAX, None);

    let controller = async {
        // Wait until downloads are in flight, capture the peak, then cancel.
        while stats.active_downloads() == 0 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let peak = stats.active_downloads();
        cancel.cancel();
        peak
    };

    let (res, peak) = tokio::join!(engine.run(&mut sink), controller);

    assert!(res.is_ok(), "cancelled run should be Ok: {res:?}");
    assert!(peak >= 1, "expected in-flight downloads, saw {peak}");
    assert_eq!(
        stats.active_downloads(),
        0,
        "workers should be torn down after cancellation"
    );
}

/// Recoverable row drops are delivered in order, after the valid rows that
/// preceded them and before the rows that follow.
#[tokio::test(start_paused = true)]
async fn recoverable_drops_delivered_in_order() {
    let mut segments = vec![
        Segment {
            name: "seg-0.jss".to_owned(),
            index: 0,
            min_seq: 1,
            max_seq: 2,
            raw: vec![Me::new(1, COLLS[0]), Me::new(2, COLLS[0])],
            dropped: vec!["row 3 malformed"],
            delay_ms: 0,
        },
        Segment {
            name: "seg-1.jss".to_owned(),
            index: 1,
            min_seq: 4,
            max_seq: 4,
            raw: vec![Me::new(4, COLLS[0])],
            dropped: vec![],
            delay_ms: 0,
        },
    ];
    // Keep declaration order stable for the assertion below.
    segments.sort_by_key(|s| s.index);

    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments,
        }],
        Vec::new(),
        1,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;

    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    assert_eq!(sink.seqs(), vec![1, 2, 4]);
    let recoverable = sink.recoverable_msgs();
    assert_eq!(recoverable.len(), 1);
    assert!(
        recoverable[0].contains("row 3 malformed"),
        "recoverable message should carry the drop reason: {recoverable:?}"
    );

    // The recoverable error must sit between the [1,2] batch and the [4] batch.
    let kinds: Vec<&str> = sink
        .log
        .iter()
        .map(|r| match r {
            Rec::Batch(_) => "batch",
            Rec::Recoverable(_) => "err",
            Rec::Info(_) => "info",
        })
        .collect();
    let first_err = kinds.iter().position(|k| *k == "err").unwrap();
    let last_batch = kinds.iter().rposition(|k| *k == "batch").unwrap();
    assert!(
        first_err < last_batch,
        "recoverable error must precede the trailing batch: {kinds:?}"
    );
}

/// `#info` advisories from the live tail are delivered as `Delivery::Info`,
/// interleaved with events but never folded into a batch.
#[tokio::test(start_paused = true)]
async fn info_frames_delivered_from_live() {
    let session = vec![
        Action::Text(commit_text(1, COLLS[0])),
        Action::Text(info_text("OutdatedCursor")),
        Action::Text(commit_text(2, COLLS[0])),
        Action::Close,
    ];
    let ws = ScriptedWs::new(vec![session]);

    // Pure-live from tip (no archive).
    let config = EngineConfig::new(live_config(build_filter(&[]), 8));
    let cancel = CancelToken::new();
    let engine = Engine::new(None::<MockArchive>, ws, NoDict, config, cancel.clone());
    let mut sink = RecordingSink::new(2, Some(cancel));
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok(), "pure-live run should be Ok: {res:?}");
    assert_eq!(sink.seqs(), vec![1, 2]);
    assert_eq!(sink.infos(), vec!["OutdatedCursor"]);
}

/// A pure-live stream (no archive) delivers live events from the tip.
#[tokio::test(start_paused = true)]
async fn pure_live_from_tip() {
    let live = vec![
        Me::new(10, COLLS[0]),
        Me::new(11, COLLS[1]),
        Me::new(12, COLLS[0]),
    ];
    let allowed = vec![COLLS[0]];
    let ws = ScriptedWs::new(vec![live_session(&live)]);

    let config = EngineConfig::new(live_config(build_filter(&allowed), 8));
    let cancel = CancelToken::new();
    let expected = oracle(&[], 0, 0, &allowed, false, &live);
    assert_eq!(expected, vec![10, 12]);

    let engine = Engine::new(None::<MockArchive>, ws, NoDict, config, cancel.clone());
    let mut sink = RecordingSink::new(expected.len(), Some(cancel));
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    assert_eq!(sink.seqs(), expected);
}

/// Snapshot-only mode returns after the archive and never dials the live tail.
#[tokio::test(start_paused = true)]
async fn snapshot_only_never_dials_live() {
    let world = vec![Me::new(1, COLLS[0]), Me::new(2, COLLS[0])];
    let archive = MockArchive::new(
        vec![Generation {
            tip: 2,
            after: 0,
            segments: segments_from(&world, 1),
        }],
        Vec::new(),
        4,
    );

    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;

    let ws = ScriptedWs::new(vec![]);
    let cancel = CancelToken::new();
    let engine = Engine::new(Some(archive), ws.clone(), NoDict, config, cancel);
    let mut sink = RecordingSink::new(usize::MAX, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    assert_eq!(sink.seqs(), vec![1, 2]);
    assert_eq!(
        ws.dial_count(),
        0,
        "snapshot-only must not dial the live tail"
    );
}

/// Server mutation: the sealed tip grows between the plan and a re-backfill; the
/// stats reflect the highest pinned tip and coverage catches up.
#[tokio::test(start_paused = true)]
async fn stats_reflect_progress_and_mutation() {
    let world1 = vec![Me::new(1, COLLS[0]), Me::new(2, COLLS[0])];
    let world2 = vec![Me::new(3, COLLS[0]), Me::new(4, COLLS[0])];
    let gens = vec![
        Generation {
            tip: 2,
            after: 0,
            segments: segments_from(&world1, 1),
        },
        Generation {
            tip: 4,
            after: 2,
            segments: segments_from(&world2, 1),
        },
    ];
    let archive = MockArchive::new(gens, Vec::new(), 4);

    let sessions = vec![
        vec![Action::Text(error_text("CursorTooOld"))],
        live_session(&[Me::new(5, COLLS[0])]),
    ];
    let ws = ScriptedWs::new(sessions);

    let config = EngineConfig::new(live_config(build_filter(&[]), 8));
    let cancel = CancelToken::new();
    let engine = Engine::new(Some(archive), ws, NoDict, config, cancel.clone());
    let stats = engine.stats();
    let mut sink = RecordingSink::new(5, Some(cancel));
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    assert_eq!(sink.seqs(), vec![1, 2, 3, 4, 5]);

    let snap = stats.snapshot();
    assert_eq!(snap.sealed_tip_seq, 4);
    assert_eq!(snap.planned_through_seq, 4);
    assert_eq!(snap.residual_gap, 0);
    assert_eq!(snap.last_processed_seq, 5);
    assert_eq!(snap.delivered_events, 5);
}

/// Regression (roast R-d57226 adjudication): the `EngineSink` contract is
/// accept-and-stop — a batch is moved into `deliver` and thus reaches the
/// consumer even when the call returns `false`, which only halts *future*
/// deliveries. Progress counters must therefore account for that final,
/// stop-triggering archive batch. (Pins the archive flush path; the live path is
/// pinned by `stats_reflect_progress_and_mutation`.)
#[tokio::test(start_paused = true)]
async fn stopping_batch_counted_in_progress() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[0]),
    ];
    // max_batch 2 over a single segment yields batches [1,2] then [3,4]; the sink
    // stops after 3 events, so the [3,4] batch is the one that returns false.
    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments: segments_from(&world, 1),
        }],
        Vec::new(),
        1,
    );
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 2));
    config.snapshot_only = true;
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let stats = engine.stats();
    let mut sink = RecordingSink::new(3, None);
    let res = engine.run(&mut sink).await;

    assert!(res.is_ok());
    // The stop-triggering batch [3,4] was delivered in full and is counted.
    assert_eq!(sink.seqs(), vec![1, 2, 3, 4]);
    let snap = stats.snapshot();
    assert_eq!(snap.delivered_events, 4);
    assert_eq!(snap.last_processed_seq, 4);
}

/// Regression (roast R-8eb742): a distinct lower-seq event arriving after a
/// higher one — a source that violates the global-ordering contract with
/// overlapping segments — is rejected as `PlanInvalid`, never silently dropped.
#[tokio::test(start_paused = true)]
async fn overlapping_segments_out_of_order_rejected() {
    // Two segments whose windows overlap: [1,3] then [2,4]. Seq 2 is a distinct
    // event that would be lost by a running-floor dedup; the engine must instead
    // reject the plan.
    let seg_a = Segment {
        name: "seg-a.jss".to_owned(),
        index: 0,
        min_seq: 1,
        max_seq: 3,
        raw: vec![Me::new(1, COLLS[0]), Me::new(3, COLLS[0])],
        dropped: Vec::new(),
        delay_ms: 0,
    };
    let seg_b = Segment {
        name: "seg-b.jss".to_owned(),
        index: 1,
        min_seq: 2,
        max_seq: 4,
        raw: vec![Me::new(2, COLLS[0]), Me::new(4, COLLS[0])],
        dropped: Vec::new(),
        delay_ms: 0,
    };
    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments: vec![seg_a, seg_b],
        }],
        Vec::new(),
        1,
    );
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(matches!(
        engine.run(&mut sink).await,
        Err(Error::PlanInvalid(_))
    ));
}

// ===========================================================================
// Config validation
// ===========================================================================

#[tokio::test]
async fn rejects_before_le_after() {
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.after_seq = 5;
    config.before_seq = Some(5);
    let archive = MockArchive::new(Vec::new(), Vec::new(), 1);
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(matches!(
        engine.run(&mut sink).await,
        Err(Error::InvalidConfig(_))
    ));
}

#[tokio::test]
async fn rejects_zero_stalls() {
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.max_rebackfill_stalls = 0;
    let archive = MockArchive::new(Vec::new(), Vec::new(), 1);
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(matches!(
        engine.run(&mut sink).await,
        Err(Error::InvalidConfig(_))
    ));
}

/// Regression (roast R-e96dad): `before_seq` bounds only the archive replay, so
/// pairing it with a live tail would silently stream past the requested upper
/// bound. It is valid only in snapshot-only mode.
#[tokio::test]
async fn rejects_before_seq_without_snapshot_only() {
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.after_seq = 0;
    config.before_seq = Some(5);
    // snapshot_only left false: archive-plus-live.
    let archive = MockArchive::new(Vec::new(), Vec::new(), 1);
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(matches!(
        engine.run(&mut sink).await,
        Err(Error::InvalidConfig(_))
    ));
}

/// Regression (roast R-e96dad): the same `before_seq` bound is accepted once
/// snapshot-only is set, and it windows the delivered snapshot.
#[tokio::test(start_paused = true)]
async fn before_seq_allowed_with_snapshot_only() {
    let world = vec![
        Me::new(1, COLLS[0]),
        Me::new(2, COLLS[0]),
        Me::new(3, COLLS[0]),
        Me::new(4, COLLS[0]),
    ];
    let archive = MockArchive::new(
        vec![Generation {
            tip: 4,
            after: 0,
            segments: segments_from(&world, 1),
        }],
        Vec::new(),
        1,
    );
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.snapshot_only = true;
    config.before_seq = Some(2);
    let cancel = CancelToken::new();
    let engine = Engine::new(
        Some(archive),
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(engine.run(&mut sink).await.is_ok());
    assert_eq!(sink.seqs(), vec![1, 2]);
}

#[tokio::test]
async fn pure_live_rejects_archive_knobs() {
    let mut config = EngineConfig::new(live_config(build_filter(&[]), 8));
    config.after_seq = 10; // requires an archive source
    let cancel = CancelToken::new();
    let engine = Engine::new(
        None::<MockArchive>,
        ScriptedWs::new(vec![]),
        NoDict,
        config,
        cancel,
    );
    let mut sink = RecordingSink::new(usize::MAX, None);
    assert!(matches!(
        engine.run(&mut sink).await,
        Err(Error::InvalidConfig(_))
    ));
}

// ===========================================================================
// Property test: engine == oracle over random worlds
// ===========================================================================

/// A random world of strictly-increasing sequences (with gaps) and random
/// collections, plus a plan split, filter mask, and archive lower bound.
#[derive(Debug, Clone)]
struct Raw {
    steps: Vec<(u64, usize)>, // (seq delta 1..=3, collection index)
    after_frac: u64,          // 0..=100, scaled to the tip
    n_seg: usize,             // 1..=4
    mask: u8,                 // filter bitmask over COLLS
}

fn raw_strategy() -> impl Strategy<Value = Raw> {
    (
        prop::collection::vec((1u64..=3, 0usize..COLLS.len()), 0..12),
        0u64..=100,
        1usize..=4,
        0u8..8,
    )
        .prop_map(|(steps, after_frac, n_seg, mask)| Raw {
            steps,
            after_frac,
            n_seg,
            mask,
        })
}

/// Build the world, tip, lower bound, and allowed set from raw components.
fn build_case(raw: &Raw) -> (Vec<Me>, u64, u64, Vec<&'static str>) {
    let mut world = Vec::new();
    let mut seq = 0u64;
    for (delta, coll_idx) in &raw.steps {
        seq += *delta;
        world.push(Me::new(seq, COLLS[*coll_idx]));
    }
    let tip = seq; // 0 when the world is empty
    let after = tip * raw.after_frac / 100;
    let allowed: Vec<&'static str> = (0..COLLS.len())
        .filter(|i| raw.mask & (1 << i) != 0)
        .map(|i| COLLS[i])
        .collect();
    (world, tip, after, allowed)
}

fn paused_runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .start_paused(true)
        .build()
        .expect("runtime")
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// Snapshot-only: the engine delivers exactly the oracle's windowed,
    /// filtered, ordered, duplicate-free sequence — across any pagination split,
    /// filter, gap pattern, and lower bound.
    #[test]
    fn engine_matches_oracle_snapshot(raw in raw_strategy()) {
        let (world, tip, after, allowed) = build_case(&raw);
        let expected = oracle(&world, tip, after, &allowed, true, &[]);

        let rt = paused_runtime();
        let delivered = rt.block_on(async {
            let archive = MockArchive::new(
                vec![Generation { tip, after, segments: segments_from(&world, raw.n_seg) }],
                allowed.clone(),
                4,
            );
            let mut config = EngineConfig::new(live_config(build_filter(&allowed), 3));
            config.after_seq = after;
            config.snapshot_only = true;
            let cancel = CancelToken::new();
            let engine =
                Engine::new(Some(archive), ScriptedWs::new(vec![]), NoDict, config, cancel);
            let mut sink = RecordingSink::new(usize::MAX, None);
            let res = engine.run(&mut sink).await;
            (sink.seqs(), res.is_ok())
        });

        prop_assert!(delivered.1, "snapshot run should be Ok");
        prop_assert_eq!(delivered.0, expected);
    }

    /// Archive + live cutover: the merged stream matches the oracle. A guaranteed
    /// net-new terminator event ensures the live tail always makes progress and
    /// the count-based sink terminates the run.
    #[test]
    fn engine_matches_oracle_with_cutover(raw in raw_strategy(), live_seed in prop::collection::vec(0usize..COLLS.len(), 0..5)) {
        let (world, tip, after, allowed) = build_case(&raw);

        // Live frames carry strictly-increasing, unique sequences (the real
        // Jetstream invariant): the enumerate index guarantees uniqueness while
        // straddling the sealed boundary (some <= tip overlaps, some > tip new).
        // A guaranteed-allowed terminator far past the tip always ends the run.
        let base = tip.saturating_sub(2);
        let mut live: Vec<Me> = live_seed
            .iter()
            .enumerate()
            .map(|(i, coll)| Me::new(base + i as u64, COLLS[*coll]))
            .collect();
        let terminator_coll = allowed.first().copied().unwrap_or(COLLS[0]);
        live.push(Me::new(tip + 1000, terminator_coll));

        let expected = oracle(&world, tip, after, &allowed, false, &live);

        let rt = paused_runtime();
        let (delivered, ok) = rt.block_on(async {
            let archive = MockArchive::new(
                vec![Generation { tip, after, segments: segments_from(&world, raw.n_seg) }],
                allowed.clone(),
                4,
            );
            let mut config = EngineConfig::new(live_config(build_filter(&allowed), 3));
            config.after_seq = after;
            let cancel = CancelToken::new();
            let ws = ScriptedWs::new(vec![live_session(&live)]);
            let engine = Engine::new(Some(archive), ws, NoDict, config, cancel.clone());
            // Safety cap above the expected count: an over-delivering bug ends
            // the run (and fails the assert) instead of hanging.
            let mut sink = RecordingSink::new(expected.len(), Some(cancel));
            let res = engine.run(&mut sink).await;
            (sink.seqs(), res.is_ok())
        });

        prop_assert!(ok, "cutover run should be Ok");
        prop_assert_eq!(delivered, expected);
    }
}
