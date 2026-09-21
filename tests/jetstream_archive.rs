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

#[allow(dead_code)]
#[path = "support/jetstream_segment.rs"]
mod segment_fixture;
use segment_fixture::*;

#[test]
fn filtered_records_survive_their_input_and_sibling_events() {
    use shrike::jetstream::{EventPayload, decode_block_frame_filtered};
    let rows = [row(1), row(2), row(3)];
    let mut frame = block_frame(&rows);
    let mut decoded = decode_block_frame_filtered(&frame, &Filter::new()).unwrap();
    assert!(decoded.dropped.is_empty());
    let event = decoded.events.remove(1);
    let EventPayload::Commit(commit) = event.payload else {
        panic!("not commit")
    };
    let record = commit.record.unwrap();
    let retained = record.clone();
    drop(record);
    drop(decoded);
    // Neither changing nor releasing the compressed input may affect records.
    frame.fill(0);
    drop(frame);
    assert_eq!(retained.as_cbor(), rows[1].payload);
    assert_eq!(retained.to_json().unwrap(), serde_json::json!({}));
    assert_eq!(
        retained.cid(),
        shrike::cbor::Cid::compute(shrike::cbor::Codec::Drisl, &rows[1].payload)
    );
}

#[test]
fn filtering_cannot_hide_structural_corruption() {
    use shrike::jetstream::decode_block_frame_filtered;
    let reject = Filter::new().collection("app.bsky.feed.like").unwrap();
    let mut rows = [row(1), row(2), row(3)];
    rows[2].kind = 255;
    let frame = block_frame(&rows);
    assert!(decode_block_frame_filtered(&frame, &Filter::new()).is_err());
    assert!(decode_block_frame_filtered(&frame, &reject).is_err());
    rows[2].kind = 1;
    let mut body = block_body(&rows);
    body.pop();
    let truncated = zstd::bulk::compress(&body, 3).unwrap();
    assert!(decode_block_frame_filtered(&truncated, &reject).is_err());
}

#[test]
fn borrowed_decode_matches_owned_rows_including_recoverable_failures() {
    use shrike::jetstream::{
        EventPayload, RawEvent, SegmentKind, decode_block_frame_filtered, raw_event_to_event,
    };
    fn project(e: &shrike::jetstream::Event) -> (String, Option<Vec<u8>>) {
        let record = match &e.payload {
            EventPayload::Commit(c) => c.record.as_ref().map(|r| r.as_cbor().to_vec()),
            _ => None,
        };
        (format!("{e:?}"), record)
    }
    let mut rows: Vec<_> = (0..16).map(row).collect();
    rows[1].did = vec![255];
    rows[2].collection = vec![255];
    rows[3].rkey = b"bad/key".to_vec();
    rows[4].rev = b"bad".to_vec();
    rows[5].collection = b"APP.BSKY.FEED.post".to_vec();
    rows[6].collection = b"app.bsky.feed.Post".to_vec();
    rows[7].kind = 3;
    rows[7].payload.clear();
    rows[8].kind = 7;
    rows[9].kind = 2;
    rows[10].kind = 4;
    rows[11].kind = 5;
    rows[12].kind = 6;
    rows[13].indexed_at = -123;
    rows[14].collection = b"app.bsky.feed.like".to_vec();
    for filter in [
        Filter::new(),
        Filter::new().collection("app.bsky.feed.post").unwrap(),
        Filter::new().collection("app.bsky.feed.*").unwrap(),
        Filter::new().did(DID_A).unwrap(),
    ] {
        let mut expected = Vec::new();
        let mut errors = Vec::new();
        for r in &rows {
            let raw = RawEvent {
                seq: r.seq,
                witnessed_at: r.witnessed_at,
                indexed_at: r.indexed_at,
                kind: SegmentKind::from_u8(r.kind).unwrap(),
                collection: r.collection.clone(),
                did: r.did.clone(),
                rkey: r.rkey.clone(),
                rev: r.rev.clone(),
                payload: r.payload.clone(),
            };
            if !filter.matches_segment(
                raw.kind.public_kind(),
                std::str::from_utf8(&raw.did).unwrap_or(""),
                std::str::from_utf8(&raw.collection).unwrap_or(""),
            ) {
                continue;
            }
            match raw_event_to_event(raw) {
                Ok(event) => expected.push(project(&event)),
                Err(error) => errors.push(error.to_string()),
            }
        }
        let got = decode_block_frame_filtered(&block_frame(&rows), &filter).unwrap();
        assert_eq!(got.events.iter().map(project).collect::<Vec<_>>(), expected);
        let mapped =
            shrike::jetstream::decode_block_frame_mapped(&block_frame(&rows), &filter, &|e| {
                e.to_owned().unwrap()
            })
            .unwrap();
        assert_eq!(
            mapped
                .events
                .iter()
                .map(|e| project(&e.value))
                .collect::<Vec<_>>(),
            expected
        );
        assert_eq!(
            mapped
                .dropped
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            errors
        );

        assert_eq!(
            got.dropped
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            errors
        );
    }
}

#[test]
fn whole_segment_matches_individual_blocks_with_filtered_and_malformed_rows() {
    use shrike::jetstream::{decode_block_frame_filtered, decode_segment_filtered};
    let mut blocks: Vec<Vec<Row>> = (0..5)
        .map(|block| ((block * 8 + 1)..=(block * 8 + 8)).map(row).collect())
        .collect();
    blocks[0][3].did = vec![255];
    blocks[1][2].collection = b"app.bsky.feed.like".to_vec();
    blocks[2][4].rev = b"bad".to_vec();
    blocks[3][0].rkey = b"bad/key".to_vec();
    blocks[4][6].collection = vec![255];
    let (segment, _) = seal(&blocks);
    for filter in [
        Filter::new(),
        Filter::new().collection("app.bsky.feed.post").unwrap(),
    ] {
        let mut events = Vec::new();
        let mut errors = Vec::new();
        for block in &blocks {
            let decoded = decode_block_frame_filtered(&block_frame(block), &filter).unwrap();
            events.extend(decoded.events.into_iter().map(|e| format!("{e:?}")));
            errors.extend(decoded.dropped.into_iter().map(|e| e.to_string()));
        }
        let decoded = decode_segment_filtered(&segment, &filter).unwrap();
        assert_eq!(
            decoded
                .events
                .iter()
                .map(|e| format!("{e:?}"))
                .collect::<Vec<_>>(),
            events
        );
        assert_eq!(
            decoded
                .dropped
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            errors
        );
    }
    // A later corrupt block must fail the entire segment, never return an
    // apparently successful partial prefix accumulated from earlier blocks.
    blocks[4][0].kind = 255;
    let (corrupt, _) = seal(&blocks);
    assert!(decode_segment_filtered(&corrupt, &Filter::new()).is_err());
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
async fn whole_content_length_hint_cannot_truncate_or_bypass_the_body_cap() {
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3)]]);
    for hint in [0, 1, bytes.len() as u64, u64::MAX] {
        let t = Scripted::new();
        t.push(
            "seg:probe",
            Resp::ok(200, bytes.clone()).with_header("content-length", &hint.to_string()),
        );
        let mut config = ArchiveConfig::new("archive.example.com", ApiKey::new(SECRET));
        config.limits.max_segment_bytes = bytes.len() as u64;
        let c = ArchiveClient::new(t, config).unwrap();
        let out = download_segment(
            &c,
            &whole_segment("seg-hint.jss", checksum.clone()),
            0,
            100,
            &Filter::new(),
            &CancelToken::new(),
        )
        .await
        .unwrap();
        assert_eq!(
            out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            [1, 2, 3]
        );
    }
    let t = Scripted::new();
    t.push(
        "seg:probe",
        Resp::ok(200, bytes.clone()).with_header("content-length", "1"),
    );
    let mut config = ArchiveConfig::new("archive.example.com", ApiKey::new(SECRET));
    config.limits.max_segment_bytes = bytes.len() as u64 - 2;
    let c = ArchiveClient::new(t, config).unwrap();
    assert!(matches!(
        download_segment(
            &c,
            &whole_segment("seg-hint.jss", checksum),
            0,
            100,
            &Filter::new(),
            &CancelToken::new(),
        )
        .await,
        Err(Error::DownloadFailed(_))
    ));
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
    // the initial attempt and one restart (2 generations — Go's
    // maxGenerationAttempts of two total attempts).
    for _ in 0..2 {
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
async fn stripe_without_etag_is_not_spliced() {
    // A 206 stripe that arrives without a validator is indistinguishable from a
    // different generation (e.g. a proxy honoring Range but stripping ETag), so
    // it must trigger a clean restart, never a splice — Go treats a missing
    // ETag the same as a mismatch.
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4)]]);
    let total = bytes.len();
    let stripe = total / 2 + 1;
    let end0 = stripe - 1;
    let end1 = total - 1;
    let t = Scripted::new();

    t.push(
        "seg:probe",
        Resp::ok(206, bytes[0..1].to_vec())
            .with_header("content-range", &format!("bytes 0-0/{total}"))
            .with_header("etag", "\"gen-A\""),
    );
    // Stripe 0 comes back valid-looking but with no ETag: restart, not splice.
    t.push(
        "seg:range:0",
        Resp::ok(206, bytes[0..stripe].to_vec())
            .with_header("content-range", &format!("bytes 0-{end0}/{total}")),
    );
    t.push(
        &format!("seg:range:{stripe}"),
        Resp::ok(206, bytes[stripe..total].to_vec())
            .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
            .with_header("etag", "\"gen-A\""),
    );

    // The fresh generation is consistent and succeeds.
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
    let seg = whole_segment("seg-0012.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("restart after unverifiable stripe");
    assert_eq!(out.events.len(), 4);
}

#[tokio::test(start_paused = true)]
async fn short_stripe_body_is_retried_then_succeeds() {
    // A stripe whose body ends cleanly short of its Content-Range is a
    // transient truncation (Go's io.ReadFull path): retried per-part with the
    // sibling stripe untouched, never classified permanent.
    let (bytes, checksum) = seal(&[vec![row(1), row(2), row(3), row(4)]]);
    let total = bytes.len();
    let stripe = total / 2 + 1;
    let end0 = stripe - 1;
    let end1 = total - 1;
    let t = Scripted::new();

    t.push(
        "seg:probe",
        Resp::ok(206, bytes[0..1].to_vec())
            .with_header("content-range", &format!("bytes 0-0/{total}"))
            .with_header("etag", "\"gen\""),
    );
    // First stripe-0 answer ends short of the declared range (clean EOF).
    t.push(
        "seg:range:0",
        Resp::ok(206, bytes[0..stripe / 2].to_vec())
            .with_header("content-range", &format!("bytes 0-{end0}/{total}"))
            .with_header("etag", "\"gen\""),
    );
    // The per-part retry serves the full stripe.
    t.push(
        "seg:range:0",
        Resp::ok(206, bytes[0..stripe].to_vec())
            .with_header("content-range", &format!("bytes 0-{end0}/{total}"))
            .with_header("etag", "\"gen\""),
    );
    t.push(
        &format!("seg:range:{stripe}"),
        Resp::ok(206, bytes[stripe..total].to_vec())
            .with_header("content-range", &format!("bytes {stripe}-{end1}/{total}"))
            .with_header("etag", "\"gen\""),
    );

    let c = client_with_stripe(t.clone(), stripe as u64);
    let seg = whole_segment("seg-0013.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("per-part retry after short body");
    assert_eq!(out.events.len(), 4);
    // Probe + failed stripe 0 + retried stripe 0 + stripe 1 = four requests.
    assert_eq!(t.log().len(), 4);
}

#[tokio::test(start_paused = true)]
async fn corrupt_segment_is_redownloaded_then_fails_bounded() {
    let (mut bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    // Flip a byte inside the checksum-protected footer region.
    let last = bytes.len() - 1;
    bytes[last] ^= 0xFF;
    let t = Scripted::new();
    // An integrity failure is treated like a torn generation: redownloaded once
    // within the bounded budget, then surfaced. Both attempts serve corruption.
    t.push("seg:probe", Resp::ok(200, bytes.clone()));
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    let seg = whole_segment("seg-0009.jss", checksum);
    let err = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect_err("integrity failure");
    assert!(matches!(err, Error::DownloadFailed(_)));
    // Exactly two attempts: the initial download plus one bounded redownload.
    assert_eq!(t.log().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn truncated_segment_is_redownloaded_then_succeeds() {
    // Regression (the 2026-06-28 oracle shape): a clean-EOF truncation that
    // still parses as a complete HTTP body must be classified transient — the
    // segment is redownloaded and the retry succeeds, never misreported as a
    // permanent failure.
    let (bytes, checksum) = seal(&[vec![row(1), row(2)]]);
    let truncated = bytes[..bytes.len() - 10].to_vec();
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, truncated));
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    let seg = whole_segment("seg-0010.jss", checksum);
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("redownload after truncation");
    assert_eq!(out.events.len(), 2);
    assert_eq!(t.log().len(), 2);
}

#[tokio::test(start_paused = true)]
async fn plan_checksum_mismatch_is_accepted_as_new_generation() {
    // The plan checksum is a generation identity, not an integrity bind: a
    // structurally valid segment whose checksum differs from the plan's (e.g.
    // rewritten by compaction between planning and download) is delivered, as
    // in Go, rather than failed.
    let (bytes, _checksum) = seal(&[vec![row(1)]]);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t.clone());
    let seg = whole_segment("seg-0011.jss", "0000000000000000".to_owned());
    let out = download_segment(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new())
        .await
        .expect("new generation accepted");
    assert_eq!(out.events.len(), 1);
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
async fn planner_accepts_block_truncation_index_continuation() {
    // Regression: the server's per-page entry cap truncates block-mode plans
    // *mid-segment*, and the next page re-plans that segment's remaining blocks
    // under the same index. The Go client accepts this; rejecting it (as a
    // "duplicate index") made every large sparse plan fatally unplannable.
    let blocks_seg = |name: &str, index: i64, min: i64, max: i64, first: i64, last: i64| {
        format!(
            r#"{{"checksum":"0123456789abcdef","index":{index},"maxSeq":{max},"minSeq":{min},"mode":"blocks","name":"{name}","blocks":[{{"first":{first},"last":{last}}}]}}"#
        )
    };
    let t = Scripted::new();
    t.push(
        "plan",
        plan_page(50, 100, &blocks_seg("s7.jss", 7, 1, 100, 0, 2)),
    );
    t.push(
        "plan",
        plan_page(100, 100, &blocks_seg("s7.jss", 7, 1, 100, 3, 5)),
    );
    let c = client(t.clone());
    let plan = plan_snapshot(&c, &Filter::new(), 0, None, &CancelToken::new())
        .await
        .expect("block-truncation continuation accepted");
    assert_eq!(plan.segments.len(), 2);
    assert_eq!(plan.segments[0].index, 7);
    assert_eq!(plan.segments[1].index, 7);
}

#[tokio::test(start_paused = true)]
async fn planner_accepts_before_seq_inside_a_segment() {
    // Regression: with a caller beforeSeq landing inside a segment, the server
    // caps sealedTipSeq at beforeSeq but reports the segment's *true* maxSeq.
    // The plan must be accepted (the download window clips the extra rows) —
    // rejecting it made every non-boundary --before-seq snapshot fatally
    // unplannable against the real server.
    let t = Scripted::new();
    t.push("plan", plan_page(100, 100, &seg_json("s0.jss", 0, 50, 150)));
    let c = client(t.clone());
    let plan = plan_snapshot(&c, &Filter::new(), 0, Some(100), &CancelToken::new())
        .await
        .expect("straddling segment accepted");
    assert_eq!(plan.sealed_tip_seq, 100);
    assert_eq!(plan.before_seq, 100);
    assert_eq!(plan.segments[0].max_seq, 150);
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

// ---------------------------------------------------------------------------
// Config validation: the host is normalized before it can misdirect the key.
// ---------------------------------------------------------------------------

/// Regression: `ArchiveClient::new` must normalize the host through
/// `normalize_host`, so a URL-shaped authority cannot slip through and redirect
/// the bearer key to a different origin than the leading label suggests. Before
/// the fix, `new` interpolated the raw string straight into the request URL, so
/// a host like `trusted.example@attacker.example` would send `authorization:
/// <key>` to `attacker.example` (the part after `@` is the real authority).
#[test]
fn rejects_url_shaped_host_that_could_redirect_the_key() {
    // Userinfo: the real authority is everything after `@`.
    let config = ArchiveConfig::new("trusted.example@attacker.example", ApiKey::new(SECRET));
    assert!(matches!(
        ArchiveClient::new(Scripted::new(), config),
        Err(Error::InvalidConfig(_))
    ));

    // Userinfo carrying explicit credentials is likewise rejected.
    let config = ArchiveConfig::new("user:pass@attacker.example", ApiKey::new(SECRET));
    assert!(matches!(
        ArchiveClient::new(Scripted::new(), config),
        Err(Error::InvalidConfig(_))
    ));

    // Whitespace inside the authority is not a valid host.
    let config = ArchiveConfig::new("good.example evil.example", ApiKey::new(SECRET));
    assert!(matches!(
        ArchiveClient::new(Scripted::new(), config),
        Err(Error::InvalidConfig(_))
    ));

    // A disallowed scheme is rejected rather than silently coerced.
    let config = ArchiveConfig::new("ftp://good.example", ApiKey::new(SECRET));
    assert!(matches!(
        ArchiveClient::new(Scripted::new(), config),
        Err(Error::InvalidConfig(_))
    ));

    // The empty host remains rejected.
    let config = ArchiveConfig::new("", ApiKey::new(SECRET));
    assert!(matches!(
        ArchiveClient::new(Scripted::new(), config),
        Err(Error::InvalidConfig(_))
    ));
}

/// A well-formed host is accepted even when it carries a redundant scheme or
/// mixed case: `new` normalizes it rather than rejecting it, so the client is
/// built against the canonical authority.
#[test]
fn accepts_and_normalizes_well_formed_host() {
    let config = ArchiveConfig::new("https://Archive.Example.com", ApiKey::new(SECRET));
    ArchiveClient::new(Scripted::new(), config).expect("normalized host builds a client");
}

#[tokio::test(start_paused = true)]
async fn mapped_download_preserves_prefix_failure_and_cancellation_contracts() {
    use shrike::jetstream::download_segment_mapped;
    let blocks = vec![vec![row(1), row(2)], vec![row(3)]];
    let (mut bytes, checksum) = seal(&blocks);
    let reader = SegmentReader::open(&bytes).unwrap();
    let off = reader.blocks()[1].offset as usize + 8;
    bytes[off..off + 4].fill(0);
    let t = Scripted::new();
    t.push("seg:probe", Resp::ok(200, bytes));
    let c = client(t);
    let seg = whole_segment("s0.jss", checksum);
    assert!(
        download_segment_mapped(&c, &seg, 0, 100, &Filter::new(), &CancelToken::new(), |e| e
            .to_owned()
            .unwrap())
        .await
        .is_err()
    );

    let t = Scripted::new();
    t.push("block:0", Resp::ok(200, block_frame(&blocks[0])));
    t.push("block:1", Resp::ok(200, vec![0; 8]));
    let c = client(t);
    let mut seg = seg;
    seg.mode = SegmentMode::Blocks(vec![BlockSpan { first: 0, last: 1 }]);
    let out = download_segment_mapped(&c, &seg, 1, 100, &Filter::new(), &CancelToken::new(), |e| {
        e.to_owned().unwrap()
    })
    .await
    .unwrap();
    assert_eq!(
        out.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![2]
    );
    assert_eq!(out.events[0].value.seq, 2);
    assert!(out.failure.is_some());
    assert!(out.dropped.is_empty());

    let t = Scripted::new();
    t.push("block:0", Resp::ok(200, block_frame(&blocks[0])));
    seg.mode = SegmentMode::Blocks(vec![BlockSpan { first: 0, last: 0 }]);
    let c = client(t);
    let cancel = CancelToken::new();
    let stop = cancel.clone();
    let result = download_segment_mapped(&c, &seg, 0, 100, &Filter::new(), &cancel, move |_| {
        stop.cancel()
    })
    .await;
    assert!(matches!(result, Err(Error::Canceled)));
}

#[tokio::test(start_paused = true)]
async fn mapped_snapshot_retains_outputs_and_reports_only_delivered_progress() {
    use shrike::jetstream::{
        ClientArchive, Delivery, Engine, EngineConfig, EngineSink, Event, LiveConfig, MappedEvent,
    };
    struct Sink {
        events: Vec<Event>,
        stop_after: usize,
    }
    impl EngineSink<MappedEvent<Event>> for Sink {
        async fn deliver(&mut self, item: Delivery<MappedEvent<Event>>) -> bool {
            if let Delivery::Batch(batch) = item {
                self.events
                    .extend(batch.into_events().into_iter().map(|e| e.value));
            }
            self.events.len() < self.stop_after
        }
        async fn recoverable(&mut self, error: Error) -> bool {
            panic!("unexpected error: {error}")
        }
    }
    for (stop_after, precancel) in [(usize::MAX, false), (2, false), (usize::MAX, true)] {
        let t = Scripted::new();
        t.push("plan", plan_page(4, 4, &seg_json("s0.jss", 0, 1, 5)));
        let (bytes, _) = seal(&[vec![row(1), row(2), row(3)], vec![row(4), row(5)]]);
        t.push("seg:probe", Resp::ok(200, bytes));
        let archive = ClientArchive::new(client(t.clone())).map(|e| e.to_owned().unwrap());
        let mut live = LiveConfig::new("archive.example.com", true);
        live.max_batch = 2;
        let mut config = EngineConfig::new(live);
        config.snapshot_only = true;
        config.after_seq = 1;
        config.before_seq = Some(4);
        let cancel = CancelToken::new();
        if precancel {
            cancel.cancel();
        }
        // Snapshot processing does not require live/dictionary transports.
        let engine = Engine::new(Some(archive), (), (), config, cancel);
        let stats = engine.stats();
        let mut sink = Sink {
            events: Vec::new(),
            stop_after,
        };
        engine.run_snapshot(&mut sink).await.unwrap();
        let expected = if precancel {
            vec![]
        } else if stop_after == 2 {
            vec![2, 3]
        } else {
            vec![2, 3, 4]
        };
        assert_eq!(
            sink.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            expected
        );
        let stats = stats.snapshot();
        assert_eq!(stats.delivered_events, expected.len() as u64);
        assert_eq!(
            stats.last_processed_seq,
            expected.last().copied().unwrap_or(1)
        );
        assert_eq!(stats.pages, u64::from(!precancel && stop_after != 2));
        if precancel {
            assert!(t.log().is_empty());
        }
    }
}

#[test]
fn bulk_metadata_checks_each_utf8_boundary_and_rejected_row() {
    use shrike::jetstream::{decode_block_frame_filtered, decode_block_frame_mapped};
    // The complete metadata region is valid UTF-8, but each of these two
    // collection fields holds half of one code point. Neither may become a str.
    let mut rows = vec![row(1), row(2), row(3)];
    rows[0].collection = vec![0xc3];
    rows[1].collection = vec![0xa9];
    for filter in [
        Filter::new(),
        Filter::new().collection("app.bsky.feed.post").unwrap(),
    ] {
        let frame = block_frame(&rows);
        let owned = decode_block_frame_filtered(&frame, &filter).unwrap();
        let mapped =
            decode_block_frame_mapped(&frame, &filter, &|e| e.to_owned().unwrap()).unwrap();
        assert_eq!(
            owned.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(
            mapped.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            vec![3]
        );
        assert_eq!(owned.dropped.len(), 2);
        assert_eq!(
            mapped
                .dropped
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            owned
                .dropped
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
        );
    }
    // One malformed byte makes the bulk scan fall back; valid sibling rows
    // still succeed, and every selected column still receives syntax checks.
    rows[0].collection = b"app.bsky.feed.post".to_vec();
    rows[0].did = vec![0xff];
    rows[1].collection = b"APP.BSKY.FEED.post".to_vec();
    let frame = block_frame(&rows);
    let filter = Filter::new().collection("app.bsky.feed.post").unwrap();
    let mapped = decode_block_frame_mapped(&frame, &filter, &|e| e.to_owned().unwrap()).unwrap();
    assert_eq!(
        mapped.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
        vec![2, 3]
    );
    assert_eq!(mapped.dropped.len(), 1);
}

#[tokio::test]
async fn sparse_block_mapping_can_progress_while_an_earlier_block_decodes() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::time::{Duration, Instant};
    let t = Scripted::new();
    t.push("block:0", Resp::ok(200, block_frame(&[row(1)])));
    t.push("block:1", Resp::ok(200, block_frame(&[row(2)])));
    let c = client(t);
    let mut seg = whole_segment("s0.jss", "0000000000000000".into());
    seg.mode = SegmentMode::Blocks(vec![BlockSpan { first: 0, last: 1 }]);
    let later_started = Arc::new(AtomicBool::new(false));
    let observed_overlap = Arc::new(AtomicBool::new(false));
    let started = later_started.clone();
    let observed = observed_overlap.clone();
    let out = shrike::jetstream::download_segment_mapped(
        &c,
        &seg,
        0,
        10,
        &Filter::new(),
        &CancelToken::new(),
        move |event| {
            if event.seq == 1 {
                let deadline = Instant::now() + Duration::from_secs(2);
                while !started.load(Ordering::Acquire) && Instant::now() < deadline {
                    std::thread::yield_now();
                }
                observed.store(started.load(Ordering::Acquire), Ordering::Release);
            } else {
                started.store(true, Ordering::Release);
            }
            event.seq
        },
    )
    .await
    .unwrap();
    assert!(
        observed_overlap.load(Ordering::Acquire),
        "later decoding was blocked behind the earlier callback"
    );
    assert_eq!(
        out.events
            .iter()
            .map(|e| (e.seq, e.value))
            .collect::<Vec<_>>(),
        vec![(1, 1), (2, 2)]
    );
    assert!(out.failure.is_none());
}
