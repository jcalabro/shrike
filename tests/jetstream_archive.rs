//! M3 archive acceptance tests: the authenticated planner and the bounded
//! archive downloader, driven against a deterministic in-memory scripted
//! transport with fault injection.
//!
//! The scripted transport ([`Scripted`]) matches each request to a per-key FIFO
//! of programmed responses, so a sequence of retries, restarts, and concurrent
//! stripe/block fetches is fully reproducible regardless of task scheduling: two
//! distinct requests never share a queue, and retries of one request drain its
//! queue in order. Retry backoff is exercised under `tokio`'s paused clock
//! (`start_paused`), which auto-advances virtual time while all tasks are idle,
//! so the bounded exponential backoff is covered without any wall-clock waiting.
//!
//! Coverage mirrors the M3 acceptance list — whole, sparse, ranged, non-ranged,
//! interrupted, rate-limited, generation-changing, corrupt, truncated,
//! oversized, and stalled — plus planner pinned-pagination, strict response
//! validation, retry classification, cancellation, and the secret-redaction
//! invariant. The CORS and real-socket capability cases belong to the browser
//! `fetch` transport and are covered when that transport lands; `reqwest`
//! ignores CORS by design, so there is nothing native to assert there.

#![cfg(feature = "jetstream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::collections::VecDeque;
use std::sync::Mutex;

use shrike::jetstream::{
    ApiKey, ArchiveClient, ArchiveConfig, BlockSpan, CancelToken, Error, Filter, HttpBody,
    HttpRequest, HttpResponse, HttpTransport, PlanSegment, ResponseHeaders, SegmentMode,
    SegmentReader, TransportError, download_segment, plan_snapshot,
};

// ---------------------------------------------------------------------------
// A minimal sealed-segment writer, matching the on-disk format the reader and
// decoder verify. Rows here use valid atproto syntax so every row converts.
// ---------------------------------------------------------------------------

const RESERVED_HEADER_BYTES: usize = 256;
const BLOCK_INDEX_ENTRY_SIZE: usize = 52;

const DID_A: &str = "did:plc:abcdefghijklmnopqrstuvwx";
const RKEY: &str = "3l3qo2vuowo2b";
const REV: &str = "3l3qo2vutsw2b";

/// One create-commit row with a minimal (empty-map) CBOR record body.
fn row(seq: u64) -> Row {
    Row {
        seq,
        witnessed_at: seq as i64 * 100,
        indexed_at: 0,
        kind: 1, // create
        collection: b"app.bsky.feed.post".to_vec(),
        did: DID_A.as_bytes().to_vec(),
        rkey: RKEY.as_bytes().to_vec(),
        rev: REV.as_bytes().to_vec(),
        payload: vec![0xA0], // CBOR {}
    }
}

struct Row {
    seq: u64,
    witnessed_at: i64,
    indexed_at: i64,
    kind: u8,
    collection: Vec<u8>,
    did: Vec<u8>,
    rkey: Vec<u8>,
    rev: Vec<u8>,
    payload: Vec<u8>,
}

/// Encode the decompressed columnar body for one block.
fn block_body(rows: &[Row]) -> Vec<u8> {
    let n = rows.len();
    let mut b = Vec::new();
    b.extend_from_slice(&(n as u32).to_le_bytes());
    if n == 0 {
        return b;
    }
    for r in rows {
        b.extend_from_slice(&r.seq.to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.witnessed_at.to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.indexed_at.to_le_bytes());
    }
    for r in rows {
        b.push(r.kind);
    }
    for r in rows {
        b.push(r.collection.len() as u8);
    }
    for r in rows {
        b.extend_from_slice(&(r.did.len() as u16).to_le_bytes());
    }
    for r in rows {
        b.push(r.rkey.len() as u8);
    }
    for r in rows {
        b.push(r.rev.len() as u8);
    }
    for r in rows {
        b.extend_from_slice(&(r.payload.len() as u32).to_le_bytes());
    }
    for r in rows {
        b.extend_from_slice(&r.collection);
    }
    for r in rows {
        b.extend_from_slice(&r.did);
    }
    for r in rows {
        b.extend_from_slice(&r.rkey);
    }
    for r in rows {
        b.extend_from_slice(&r.rev);
    }
    for r in rows {
        b.extend_from_slice(&r.payload);
    }
    b
}

/// The compressed zstd frame for a single block, as `getBlock` returns it.
fn block_frame(rows: &[Row]) -> Vec<u8> {
    zstd::bulk::compress(&block_body(rows), 3).expect("compress block")
}

/// Assemble a complete sealed segment and return its bytes plus the lowercase
/// 16-hex checksum the plan would name for it.
fn seal(blocks: &[Vec<Row>]) -> (Vec<u8>, String) {
    use core::hash::Hasher;
    use twox_hash::XxHash3_64;

    let mut file = vec![0u8; RESERVED_HEADER_BYTES];
    let mut index: Vec<[u8; BLOCK_INDEX_ENTRY_SIZE]> = Vec::new();
    let mut ev_count = 0u32;
    let (mut min_seq, mut max_seq) = (u64::MAX, 0u64);
    let (mut min_w, mut max_w) = (i64::MAX, i64::MIN);

    for rows in blocks {
        let body = block_body(rows);
        let frame = zstd::bulk::compress(&body, 3).expect("compress block");
        let offset = file.len() as u64;
        file.extend_from_slice(&(frame.len() as u64).to_le_bytes());
        file.extend_from_slice(&frame);

        let (mut bmin_s, mut bmax_s) = (u64::MAX, 0u64);
        let (mut bmin_w, mut bmax_w) = (i64::MAX, i64::MIN);
        for r in rows {
            ev_count += 1;
            bmin_s = bmin_s.min(r.seq);
            bmax_s = bmax_s.max(r.seq);
            bmin_w = bmin_w.min(r.witnessed_at);
            bmax_w = bmax_w.max(r.witnessed_at);
        }
        if rows.is_empty() {
            bmin_s = 0;
            bmax_s = 0;
            bmin_w = 0;
            bmax_w = 0;
        } else {
            min_seq = min_seq.min(bmin_s);
            max_seq = max_seq.max(bmax_s);
            min_w = min_w.min(bmin_w);
            max_w = max_w.max(bmax_w);
        }

        let mut e = [0u8; BLOCK_INDEX_ENTRY_SIZE];
        e[0..8].copy_from_slice(&offset.to_le_bytes());
        e[8..12].copy_from_slice(&(frame.len() as u32).to_le_bytes());
        e[12..16].copy_from_slice(&(body.len() as u32).to_le_bytes());
        e[16..20].copy_from_slice(&(rows.len() as u32).to_le_bytes());
        e[20..28].copy_from_slice(&bmin_s.to_le_bytes());
        e[28..36].copy_from_slice(&bmax_s.to_le_bytes());
        e[36..44].copy_from_slice(&bmin_w.to_le_bytes());
        e[44..52].copy_from_slice(&bmax_w.to_le_bytes());
        index.push(e);
    }

    let footer_offset = file.len() as u64;
    for e in &index {
        file.extend_from_slice(e);
    }
    let file_len = file.len() as u64;

    if ev_count == 0 {
        min_seq = 0;
        max_seq = 0;
        min_w = 0;
        max_w = 0;
    }

    file[0..4].copy_from_slice(b"jss0");
    file[12..14].copy_from_slice(&1u16.to_le_bytes());
    file[14..18].copy_from_slice(&(blocks.len() as u32).to_le_bytes());
    file[18..22].copy_from_slice(&ev_count.to_le_bytes());
    file[22..26].copy_from_slice(&0u32.to_le_bytes());
    file[26..34].copy_from_slice(&min_seq.to_le_bytes());
    file[34..42].copy_from_slice(&max_seq.to_le_bytes());
    file[42..50].copy_from_slice(&min_w.to_le_bytes());
    file[50..58].copy_from_slice(&max_w.to_le_bytes());
    file[58..66].copy_from_slice(&footer_offset.to_le_bytes());
    file[66..74].copy_from_slice(&file_len.to_le_bytes());
    file[74..82].copy_from_slice(&file_len.to_le_bytes());
    file[82..90].copy_from_slice(&file_len.to_le_bytes());
    file[90..98].copy_from_slice(&footer_offset.to_le_bytes());

    let mut hasher = XxHash3_64::new();
    hasher.write(&file[12..RESERVED_HEADER_BYTES]);
    hasher.write(&file[footer_offset as usize..]);
    let checksum = hasher.finish();
    file[4..12].copy_from_slice(&checksum.to_le_bytes());
    (file, format!("{checksum:016x}"))
}

// ---------------------------------------------------------------------------
// The scripted transport.
// ---------------------------------------------------------------------------

/// A programmed body: either delivered whole, or delivered as a sequence of
/// chunks followed by a mid-stream transport failure (an interrupted download).
#[derive(Clone)]
enum BodyScript {
    Full(Vec<u8>),
    ErrorAfter(Vec<Vec<u8>>),
}

/// A single programmed response for one request.
#[derive(Clone)]
enum Resp {
    /// An HTTP response with a status, header pairs, and a body script.
    Http {
        status: u16,
        headers: Vec<(String, String)>,
        body: BodyScript,
    },
    /// A transport-layer failure before any response (connect/timeout/body).
    Timeout,
}

impl Resp {
    fn ok(status: u16, body: Vec<u8>) -> Self {
        Resp::Http {
            status,
            headers: Vec::new(),
            body: BodyScript::Full(body),
        }
    }
    fn with_header(mut self, name: &str, value: &str) -> Self {
        if let Resp::Http { headers, .. } = &mut self {
            headers.push((name.to_owned(), value.to_owned()));
        }
        self
    }
}

/// A record of one request the transport served, for assertions.
#[derive(Clone)]
struct Recorded {
    url: String,
    authorization: Option<String>,
    range: Option<String>,
    if_range: Option<String>,
}

struct State {
    queues: HashMap<String, VecDeque<Resp>>,
    log: Vec<Recorded>,
}

#[derive(Clone)]
struct Scripted {
    state: std::sync::Arc<Mutex<State>>,
}

impl Scripted {
    fn new() -> Self {
        Scripted {
            state: std::sync::Arc::new(Mutex::new(State {
                queues: HashMap::new(),
                log: Vec::new(),
            })),
        }
    }

    /// Append a response to the FIFO for `key`.
    fn push(&self, key: &str, resp: Resp) {
        self.state
            .lock()
            .unwrap()
            .queues
            .entry(key.to_owned())
            .or_default()
            .push_back(resp);
    }

    fn log(&self) -> Vec<Recorded> {
        self.state.lock().unwrap().log.clone()
    }
}

/// The routing key for a request: distinct requests get distinct queues, and
/// retries/re-probes of the same request drain one queue in order.
fn key_for(req: &HttpRequest) -> String {
    let url = &req.url;
    if url.contains("planSnapshot") {
        return "plan".to_owned();
    }
    if url.contains("getBlock") {
        let idx = query_param(url, "blockIndex").unwrap_or_default();
        return format!("block:{idx}");
    }
    if url.contains("getSegment") {
        return match header(req, "range") {
            None => "seg:whole".to_owned(),
            Some("bytes=0-0") => "seg:probe".to_owned(),
            Some(r) => {
                let start = r
                    .strip_prefix("bytes=")
                    .and_then(|x| x.split('-').next())
                    .unwrap_or("");
                format!("seg:range:{start}")
            }
        };
    }
    "other".to_owned()
}

fn header<'a>(req: &'a HttpRequest, name: &str) -> Option<&'a str> {
    req.headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

fn query_param(url: &str, name: &str) -> Option<String> {
    let query = url.split_once('?')?.1;
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=')
            && k == name
        {
            return Some(v.to_owned());
        }
    }
    None
}

impl HttpTransport for Scripted {
    type Body = ScriptedBody;

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse<Self::Body>, TransportError> {
        let key = key_for(&request);
        let resp = {
            let mut state = self.state.lock().unwrap();
            state.log.push(Recorded {
                url: request.url.clone(),
                authorization: header(&request, "authorization").map(str::to_owned),
                range: header(&request, "range").map(str::to_owned),
                if_range: header(&request, "if-range").map(str::to_owned),
            });
            state
                .queues
                .get_mut(&key)
                .and_then(|q| q.pop_front())
                .unwrap_or_else(|| panic!("no scripted response for key {key:?}"))
        };
        match resp {
            Resp::Timeout => Err(TransportError::timeout("scripted stall")),
            Resp::Http {
                status,
                headers,
                body,
            } => {
                let headers = ResponseHeaders::from_pairs(headers.iter().map(|(k, v)| (k, v)));
                let (chunks, err_at_end) = match body {
                    BodyScript::Full(bytes) => (vec![bytes], false),
                    BodyScript::ErrorAfter(chunks) => (chunks, true),
                };
                Ok(HttpResponse {
                    status,
                    headers,
                    body: ScriptedBody {
                        chunks: chunks.into(),
                        err_at_end,
                    },
                })
            }
        }
    }
}

struct ScriptedBody {
    chunks: VecDeque<Vec<u8>>,
    err_at_end: bool,
}

impl HttpBody for ScriptedBody {
    async fn chunk(&mut self) -> Result<Option<bytes::Bytes>, TransportError> {
        match self.chunks.pop_front() {
            Some(chunk) => Ok(Some(bytes::Bytes::from(chunk))),
            None => {
                if self.err_at_end {
                    // Fire the mid-stream failure exactly once.
                    self.err_at_end = false;
                    Err(TransportError::body("scripted interrupted body"))
                } else {
                    Ok(None)
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers to build a client and plan segments.
// ---------------------------------------------------------------------------

const SECRET: &str = "sk-archive-super-secret-abcdef";

fn client(transport: Scripted) -> ArchiveClient<Scripted> {
    let config = ArchiveConfig::new("archive.example.com", ApiKey::new(SECRET));
    ArchiveClient::new(transport, config).expect("build client")
}

/// A client whose stripe size is shrunk so small segments actually stripe
/// (the default 8 MiB stripe would swallow every test segment in one read).
fn client_with_stripe(transport: Scripted, stripe_bytes: u64) -> ArchiveClient<Scripted> {
    let mut config = ArchiveConfig::new("archive.example.com", ApiKey::new(SECRET));
    config.limits.stripe_bytes = stripe_bytes;
    ArchiveClient::new(transport, config).expect("build client")
}

fn whole_segment(name: &str, checksum: String) -> PlanSegment {
    PlanSegment {
        name: name.to_owned(),
        index: 0,
        min_seq: 1,
        max_seq: 100,
        checksum,
        mode: SegmentMode::Whole,
    }
}

// ---------------------------------------------------------------------------
// Downloader — whole-segment cases.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn whole_non_ranged_200_download() {
    // A server that ignores the probe range answers 200 with the whole body.
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3)]]);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes.clone()));
    let c = client(t.clone());
    let seg = whole_segment("seg-0001.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(
        out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3]
    );
    assert!(out.dropped.is_empty());
    // The bearer key rode the request as an Authorization header and nowhere else.
    let log = t.log();
    assert_eq!(
        log[0].authorization.as_deref(),
        Some(&format!("Bearer {SECRET}")[..])
    );
    assert!(!log[0].url.contains(SECRET));
}

#[tokio::test(start_paused = true)]
async fn whole_ranged_striped_download() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4)]]);
    let total = bytes.len();
    // Force exactly two stripes.
    let stripe = total / 2 + 1;
    let t = Scripted::new();
    // Probe: 206 with a Content-Range revealing the total, and a generation ETag.
    t.push(
        "seg:probe",
        Resp::ok(206, bytes[0..1].to_vec())
            .with_header("content-range", &format!("bytes 0-0/{total}"))
            .with_header("etag", "\"gen-A\""),
    );
    // Stripe 0 and stripe 1, each a 206 with the matching Content-Range + ETag.
    let end0 = stripe - 1;
    t.push(
        "seg:range:0",
        Resp::ok(206, bytes[0..stripe].to_vec())
            .with_header("content-range", &format!("bytes 0-{end0}/{total}"))
            .with_header("etag", "\"gen-A\""),
    );
    let end1 = total - 1;
    t.push(
        &format!("seg:range:{stripe}"),
        Resp::ok(206, bytes[stripe..total].to_vec())
            .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
            .with_header("etag", "\"gen-A\""),
    );
    let c = client_with_stripe(t.clone(), stripe as u64);
    let seg = whole_segment("seg-0002.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(out.events.len(), 4);
    // Stripe requests carried If-Range pinned to the probe's ETag.
    let log = t.log();
    let stripes: Vec<_> = log.iter().filter(|r| r.range.is_some()).collect();
    for s in stripes {
        if s.range.as_deref() != Some("bytes=0-0") {
            assert_eq!(s.if_range.as_deref(), Some("\"gen-A\""));
        }
    }
}

#[tokio::test(start_paused = true)]
async fn whole_416_falls_back_to_full_get() {
    let (bytes, checksum) = seal(&[vec![row(1)]]);
    let t = Scripted::new();
    // Probe cannot be satisfied → 416; the client falls back to an un-ranged GET.
    t.push("seg:probe", Resp::ok(416, Vec::new()));
    t.push("seg:whole", Resp::ok(200, bytes.clone()));
    let c = client(t.clone());
    let seg = whole_segment("seg-0003.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(out.events.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn whole_window_clips_events_outside_bounds() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4), row(5)]]);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    let seg = whole_segment("seg-0004.jss", checksum);
    // Window (2, 4]: keep seq 3 and 4 only.
    let out = download_segment(&c, &seg, 2, 4, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(
        out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![3, 4]
    );
}

#[tokio::test(start_paused = true)]
async fn interrupted_body_is_retried_then_succeeds() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    let t = Scripted::new();
    // First probe: deliver a couple of chunks then break mid-stream.
    let half = bytes.len() / 2;
    t.push(
        "seg:probe",
        Resp::Http {
            status: 200,
            headers: Vec::new(),
            body: BodyScript::ErrorAfter(vec![bytes[..half].to_vec()]),
        },
    );
    // Retry succeeds with the whole body.
    t.push("seg:probe", Resp::ok(200, bytes.clone()));
    let c = client(t.clone());
    let seg = whole_segment("seg-0005.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(out.events.len(), 2);
    // Two probe attempts were made.
    assert_eq!(t.log().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn rate_limited_download_honors_retry_after_then_succeeds() {
    let (bytes, checksum) = seal(&[vec![row(1)]]);
    let t = Scripted::new();
    t.push(
        "seg:probe",
        Resp::Http {
            status: 429,
            headers: vec![("retry-after".to_owned(), "1".to_owned())],
            body: BodyScript::Full(br#"{"error":"RateLimited"}"#.to_vec()),
        },
    );
    t.push("seg:probe", Resp::ok(200, bytes.clone()));
    let c = client(t.clone());
    let seg = whole_segment("seg-0006.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download");
    assert_eq!(out.events.len(), 1);
    assert_eq!(t.log().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn generation_change_triggers_clean_restart() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4)]]);
    let total = bytes.len();
    let stripe = total / 2 + 1;
    let end0 = stripe - 1;
    let end1 = total - 1;
    let t = Scripted::new();

    // Generation A probe + stripes, but stripe 0 comes back 200 (If-Range miss),
    // signaling the object changed generation mid-download.
    t.push(
        "seg:probe",
        Resp::ok(206, bytes[0..1].to_vec())
            .with_header("content-range", &format!("bytes 0-0/{total}"))
            .with_header("etag", "\"gen-A\""),
    );
    t.push("seg:range:0", Resp::ok(200, bytes.clone())); // If-Range miss → restart
    t.push(
        &format!("seg:range:{stripe}"),
        Resp::ok(206, bytes[stripe..total].to_vec())
            .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
            .with_header("etag", "\"gen-A\""),
    );

    // Generation B: a fresh, consistent probe + stripes succeed.
    t.push(
        "seg:probe",
        Resp::ok(206, bytes[0..1].to_vec())
            .with_header("content-range", &format!("bytes 0-0/{total}"))
            .with_header("etag", "\"gen-B\""),
    );
    t.push(
        "seg:range:0",
        Resp::ok(206, bytes[0..stripe].to_vec())
            .with_header("content-range", &format!("bytes 0-{end0}/{total}"))
            .with_header("etag", "\"gen-B\""),
    );
    t.push(
        &format!("seg:range:{stripe}"),
        Resp::ok(206, bytes[stripe..total].to_vec())
            .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
            .with_header("etag", "\"gen-B\""),
    );

    let c = client_with_stripe(t.clone(), stripe as u64);
    let seg = whole_segment("seg-0007.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download after restart");
    assert_eq!(out.events.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn generation_restart_budget_is_bounded() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4)]]);
    let total = bytes.len();
    let stripe = total / 2 + 1;
    let end1 = total - 1;
    let t = Scripted::new();
    // Every probe succeeds but every stripe 0 returns 200 (perpetual generation
    // change). The client must give up after the bounded restart budget rather
    // than loop forever. Provide enough entries for probe + both stripes across
    // the initial attempt and two restarts (3 generations).
    for _ in 0..3 {
        t.push(
            "seg:probe",
            Resp::ok(206, bytes[0..1].to_vec())
                .with_header("content-range", &format!("bytes 0-0/{total}"))
                .with_header("etag", "\"gen\""),
        );
        t.push("seg:range:0", Resp::ok(200, bytes.clone()));
        t.push(
            &format!("seg:range:{stripe}"),
            Resp::ok(206, bytes[stripe..total].to_vec())
                .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
                .with_header("etag", "\"gen\""),
        );
    }
    let c = client_with_stripe(t.clone(), stripe as u64);
    let seg = whole_segment("seg-0008.jss", checksum);
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("restart budget exhausted");
    assert!(matches!(err, Error::DownloadFailed(_)));
}

#[tokio::test(start_paused = true)]
async fn corrupt_segment_fails_integrity() {
    let (mut bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    // Flip a byte inside the checksum-protected footer region.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    let seg = whole_segment("seg-0009.jss", checksum);
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("integrity failure");
    assert!(matches!(err, Error::DownloadFailed(_)));
}

#[tokio::test(start_paused = true)]
async fn truncated_segment_fails_integrity() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    let truncated = bytes[..bytes.len() - 10].to_vec();
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, truncated));
    let c = client(t.clone());
    let seg = whole_segment("seg-0010.jss", checksum);
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("truncation failure");
    assert!(matches!(err, Error::DownloadFailed(_)));
}

#[tokio::test(start_paused = true)]
async fn checksum_mismatch_against_plan_is_rejected() {
    let (bytes, _checksum) = seal(&[vec![row(1)]]);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    // A structurally valid segment, but the plan names a different checksum.
    let seg = whole_segment("seg-0011.jss", "0000000000000000".to_owned());
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("plan checksum mismatch");
    assert!(matches!(err, Error::DownloadFailed(_)));
}

#[tokio::test(start_paused = true)]
async fn oversized_segment_is_capped() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes.clone()));
    // Shrink the segment cap below the body size.
    let mut config = ArchiveConfig::new("archive.example.com", ApiKey::new(SECRET));
    config.limits.max_segment_bytes = 16;
    let c = ArchiveClient::new(t.clone(), config).expect("client");
    let seg = whole_segment("seg-0012.jss", checksum);
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("oversized");
    assert!(matches!(err, Error::DownloadFailed(_)));
}

#[tokio::test(start_paused = true)]
async fn stalled_download_exhausts_retries() {
    let t = Scripted::new();
    // Every attempt stalls (transport timeout); the bounded retry budget is spent.
    for _ in 0..8 {
        t.push("seg:probe", Resp::Timeout);
    }
    let c = client(t.clone());
    let seg = whole_segment("seg-0013.jss", "0000000000000000".to_owned());
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("stalled");
    assert!(matches!(err, Error::Transport { .. }));
    // Default download policy is three attempts.
    assert_eq!(t.log().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn permanent_4xx_is_fatal_without_retry() {
    let t = Scripted::new();
    t.push(
        "seg:probe",
        Resp::Http {
            status: 404,
            headers: Vec::new(),
            body: BodyScript::Full(br#"{"error":"NotFound","message":"gone"}"#.to_vec()),
        },
    );
    let c = client(t.clone());
    let seg = whole_segment("seg-0014.jss", "0000000000000000".to_owned());
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("fatal 4xx");
    match err {
        Error::Protocol { name, .. } => assert_eq!(name, "NotFound"),
        other => panic!("expected protocol error, got {other:?}"),
    }
    // No retry on a permanent 4xx.
    assert_eq!(t.log().len(), 1);
}

// ---------------------------------------------------------------------------
// Downloader — blocks-mode cases.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn blocks_mode_reassembles_in_order() {
    // Three blocks, fetched individually and reassembled in block order.
    let frame0 = block_frame(&[row(1), row(2)]);
    let frame1 = block_frame(&[row(3)]);
    let frame2 = block_frame(&[row(4), row(5)]);
    let t = Scripted::new();
    t.push("block:0", Resp::ok(200, frame0));
    t.push("block:1", Resp::ok(200, frame1));
    t.push("block:2", Resp::ok(200, frame2));
    let c = client(t.clone());
    let seg = PlanSegment {
        name: "seg-blocks.jss".to_owned(),
        index: 0,
        min_seq: 1,
        max_seq: 5,
        checksum: "0000000000000000".to_owned(),
        mode: SegmentMode::Blocks(vec![BlockSpan { first: 0, last: 2 }]),
    };
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("download blocks");
    assert_eq!(
        out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![1, 2, 3, 4, 5]
    );
}

#[tokio::test(start_paused = true)]
async fn blocks_mode_applies_window() {
    let frame0 = block_frame(&[row(1), row(2), row(3)]);
    let t = Scripted::new();
    t.push("block:0", Resp::ok(200, frame0));
    let c = client(t.clone());
    let seg = PlanSegment {
        name: "seg-blocks2.jss".to_owned(),
        index: 0,
        min_seq: 1,
        max_seq: 3,
        checksum: "0000000000000000".to_owned(),
        mode: SegmentMode::Blocks(vec![BlockSpan { first: 0, last: 0 }]),
    };
    // Window (1, 3]: drop seq 1.
    let out = download_segment(&c, &seg, 1, 3, &Filter::new(), &CancelToken::new())
        .await
        .expect("download blocks");
    assert_eq!(
        out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );
}

// ---------------------------------------------------------------------------
// Cancellation.
// ---------------------------------------------------------------------------

#[tokio::test(start_paused = true)]
async fn cancelled_download_never_touches_the_network() {
    let t = Scripted::new();
    let c = client(t.clone());
    let cancel = CancelToken::new();
    cancel.cancel();
    let seg = whole_segment("seg-cancel.jss", "0000000000000000".to_owned());
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &cancel)
        .await
        .expect_err("cancelled");
    assert!(matches!(err, Error::Canceled));
    assert!(t.log().is_empty());
}

// ---------------------------------------------------------------------------
// Planner — pinned pagination and strict response validation.
// ---------------------------------------------------------------------------

/// A `network.bsky.jetstream.planSnapshot` page response.
fn plan_page(planned_through: i64, sealed_tip: i64, segments: &str) -> Resp {
    let body = format!(
        r#"{{"plannedThroughSeq":{planned_through},"sealedTipSeq":{sealed_tip},"segments":[{segments}],"stats":{{"blocksMatched":0,"entries":0,"segmentsExamined":0,"segmentsMatched":0}}}}"#
    );
    Resp::ok(200, body.into_bytes())
}

fn seg_json(name: &str, index: i64, min: i64, max: i64) -> String {
    format!(
        r#"{{"checksum":"0123456789abcdef","index":{index},"maxSeq":{max},"minSeq":{min},"mode":"segment","name":"{name}"}}"#
    )
}

#[tokio::test(start_paused = true)]
async fn planner_pins_tip_and_accumulates_pages() {
    let t = Scripted::new();
    // Page 1 covers through 50 of a tip at 100; page 2 completes coverage.
    t.push("plan", plan_page(50, 100, &seg_json("s0.jss", 0, 1, 50)));
    t.push("plan", plan_page(100, 100, &seg_json("s1.jss", 1, 51, 100)));
    let c = client(t.clone());
    let plan = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect("plan");
    assert_eq!(plan.sealed_tip_seq, 100);
    assert_eq!(plan.before_seq, 100);
    assert_eq!(plan.segments.len(), 2);
    assert_eq!(plan.segments[0].name, "s0.jss");
    assert_eq!(plan.segments[1].name, "s1.jss");
    assert_eq!(t.log().len(), 2);
    // The bearer key rode as Authorization on every control request, never in the URL.
    for r in t.log() {
        assert_eq!(
            r.authorization.as_deref(),
            Some(&format!("Bearer {SECRET}")[..])
        );
        assert!(!r.url.contains(SECRET));
    }
}

#[tokio::test(start_paused = true)]
async fn planner_single_page_completes() {
    let t = Scripted::new();
    t.push("plan", plan_page(100, 100, &seg_json("s0.jss", 0, 1, 100)));
    let c = client(t.clone());
    let plan = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect("plan");
    assert_eq!(plan.segments.len(), 1);
    assert_eq!(t.log().len(), 1);
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_sealed_tip_drift() {
    let t = Scripted::new();
    t.push("plan", plan_page(50, 100, &seg_json("s0.jss", 0, 1, 50)));
    t.push("plan", plan_page(100, 101, &seg_json("s1.jss", 1, 51, 100)));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("tip drift");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_planned_through_past_tip() {
    let t = Scripted::new();
    t.push("plan", plan_page(101, 100, ""));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("pts > tip");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_non_advancing_page() {
    let t = Scripted::new();
    t.push("plan", plan_page(50, 100, &seg_json("s0.jss", 0, 1, 50)));
    t.push("plan", plan_page(50, 100, ""));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("non-advancing");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_duplicate_segment_index() {
    let t = Scripted::new();
    // Two entries share index 0 on one page: a duplicate that would double-count.
    let segs = format!(
        "{},{}",
        seg_json("s0.jss", 0, 1, 50),
        seg_json("s0-dup.jss", 0, 51, 100)
    );
    t.push("plan", plan_page(100, 100, &segs));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("duplicate index");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_decreasing_segment_index_across_pages() {
    let t = Scripted::new();
    // Page 2's segment index goes backwards relative to page 1 — a reorder that
    // could reintroduce already-covered events.
    t.push("plan", plan_page(50, 100, &seg_json("s5.jss", 5, 1, 50)));
    t.push("plan", plan_page(100, 100, &seg_json("s3.jss", 3, 51, 100)));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("decreasing index");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_accepts_sparse_increasing_indices() {
    let t = Scripted::new();
    // Filtered plans can skip indices; strictly-increasing (not contiguous) is ok.
    let segs = format!(
        "{},{}",
        seg_json("s0.jss", 0, 1, 50),
        seg_json("s7.jss", 7, 51, 100)
    );
    t.push("plan", plan_page(100, 100, &segs));
    let c = client(t.clone());
    let plan = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect("sparse indices");
    assert_eq!(plan.segments.len(), 2);
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_bad_checksum() {
    let t = Scripted::new();
    let seg = r#"{"checksum":"NOTHEX","index":0,"maxSeq":100,"minSeq":1,"mode":"segment","name":"s0.jss"}"#;
    t.push("plan", plan_page(100, 100, seg));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("bad checksum");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_rejects_traversal_in_segment_name() {
    let t = Scripted::new();
    let seg = r#"{"checksum":"0123456789abcdef","index":0,"maxSeq":100,"minSeq":1,"mode":"segment","name":"../etc/passwd"}"#;
    t.push("plan", plan_page(100, 100, seg));
    let c = client(t.clone());
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect_err("traversal");
    assert!(matches!(err, Error::PlanInvalid(_)));
}

#[tokio::test(start_paused = true)]
async fn planner_cancellation_is_immediate() {
    let t = Scripted::new();
    let c = client(t.clone());
    let cancel = CancelToken::new();
    cancel.cancel();
    let err = plan_snapshot(&c, &Filter::new(), 0, None, &cancel)
        .await
        .expect_err("cancelled");
    assert!(matches!(err, Error::Canceled));
    assert!(t.log().is_empty());
}

// ---------------------------------------------------------------------------
// Segment builder sanity: the sealed bytes really validate through the reader.
// ---------------------------------------------------------------------------

#[test]
fn built_segment_is_readable() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    let reader = SegmentReader::open(&bytes).expect("open");
    assert_eq!(format!("{:016x}", reader.header().checksum), checksum);
}
