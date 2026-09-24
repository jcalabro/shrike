//! The archive downloader: fetch a planned segment's bytes, verify integrity,
//! decode with the caller's filter, and apply the snapshot window.
//!
//! Two download shapes, chosen by the plan:
//!
//! - **`blocks` mode** ([`SegmentMode::Blocks`]) fetches the listed block frames
//!   with `getBlock` under bounded concurrency and reassembles them in block
//!   order. Ordering is preserved by [`futures::stream::StreamExt::buffered`], so
//!   no OS threads are required and the path is identical on native and wasm.
//! - **`segment` mode** ([`SegmentMode::Whole`]) streams the whole `.jss` file
//!   with `getSegment`. It probes for byte-range support, and when the server
//!   supports ranges and exposes a generation tag it stripes the file across
//!   bounded-concurrency range requests pinned with `If-Range`. A generation
//!   change mid-download (an `If-Range` miss, a changed `ETag`, or a shrunk
//!   object) triggers a clean whole-download restart rather than splicing two
//!   generations together; the restart budget is bounded.
//!
//! Integrity is enforced per mode, matching the sealed format: the xxh3 checksum
//! covers `header[12..256] ++ footer`, not the compressed block region in
//! between, so only a download that fetches the header and footer can recompute
//! it.
//!
//! - **`segment` mode** re-verifies the whole object before it is trusted:
//!   [`SegmentReader`] re-reads the sealed header, recomputes the xxh3 checksum,
//!   and validates the block index, so a truncated or corrupted object is
//!   redownloaded (within the bounded restart budget) rather than decoded. The
//!   plan's checksum is a generation identity, not an integrity bind: a segment
//!   rewritten between planning and download is accepted as a consistent new
//!   generation, as in Go, with the snapshot window still clipping its rows.
//! - **`blocks` mode** fetches only the requested block frames, so it never
//!   retrieves the header or footer the checksum covers and does not recompute it
//!   — pulling them would defeat the point of a sparse download, and the plan
//!   carries no per-block metadata to cross-check a lone frame against. Each
//!   frame is still fully validated on decode (bounded decompression, checked
//!   columnar layout, capped counts), and only rows inside the snapshot window
//!   are kept; the path relies on the authenticated plan and the transport (TLS
//!   plus a bearer key to a first-party origin) for object authenticity. Note
//!   the format carries no per-block content hash, so neither mode detects a
//!   same-shape re-encoding substituted by a hostile origin.
//!
//! Sizes are capped at every step; a truncated, oversized, or inconsistent body
//! is a bounded [`Error::DownloadFailed`], never an unbounded allocation.
//!
//! After decoding, the snapshot window `(after_seq, before_seq]` is applied to
//! every row: a segment that straddles the window boundary contributes only the
//! rows inside it, so overlapping plan segments never double-count.

use bytes::Bytes;
use futures::stream::{self, StreamExt, TryStreamExt};
use std::sync::Arc;

use super::archive::{
    ArchiveClient, BodyReadError, SendError, now_unix_secs, parse_xrpc_error, read_body_bounded,
    read_body_bounded_hint, read_body_exact,
};
use super::cancel::CancelToken;
use super::decode::{Decoded, decode_block_frame_filtered, decode_segment_cancellable};
use super::error::{Error, Result};
use super::event::{Event, Sequenced};
use super::filter::Filter;
use super::planner::{PlanSegment, SegmentMode};
use super::retry::{Attempt, with_retry};
use super::segment::SegmentReader;
use super::transport::{HttpRequest, HttpResponse, HttpTransport, ResponseHeaders};

/// The XRPC method id for whole-segment downloads.
const GET_SEGMENT_METHOD: &str = "network.bsky.jetstream.getSegment";
/// The XRPC method id for single-block downloads.
const GET_BLOCK_METHOD: &str = "network.bsky.jetstream.getBlock";

/// A downloaded, decoded, and windowed segment.
#[derive(Debug)]
pub struct DownloadedSegment<E = Event> {
    /// The events inside the snapshot window, in sequence order.
    pub events: Vec<E>,
    /// Row-level decode failures (invalid siblings), preserved for reporting.
    pub dropped: Vec<Error>,
    /// A per-entry failure that stopped this segment partway: in blocks mode the
    /// decoded prefix in `events` is still valid and deliverable, and the error
    /// follows it in order (the Go client's emit-prefix-then-error contract).
    pub failure: Option<Error>,
}

impl<E> Default for DownloadedSegment<E> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            dropped: Vec::new(),
            failure: None,
        }
    }
}

trait ArchiveDecode: Send + Sync + 'static {
    type Item: Sequenced + Send + 'static;
    fn decode(
        &self,
        bytes: &[u8],
        filter: &Filter,
        whole: bool,
        cancelled: impl Fn() -> bool + Sync,
    ) -> Result<Decoded<Self::Item>>;
}

struct OwnedDecode;
impl ArchiveDecode for OwnedDecode {
    type Item = Event;
    fn decode(
        &self,
        bytes: &[u8],
        filter: &Filter,
        whole: bool,
        cancelled: impl Fn() -> bool + Sync,
    ) -> Result<Decoded<Event>> {
        if whole {
            decode_segment_cancellable(bytes, filter, cancelled)
        } else {
            decode_block_frame_filtered(bytes, filter)
        }
    }
}

struct ViewDecode<F> {
    map: F,
    workers: usize,
}
impl<T, F> ArchiveDecode for ViewDecode<F>
where
    T: Send + 'static,
    F: Fn(super::view::EventView<'_>) -> T + Send + Sync + 'static,
{
    type Item = super::view::MappedEvent<T>;
    fn decode(
        &self,
        bytes: &[u8],
        filter: &Filter,
        whole: bool,
        cancelled: impl Fn() -> bool + Sync,
    ) -> Result<Decoded<Self::Item>> {
        if whole {
            super::view::decode_segment_workers(bytes, filter, &self.map, cancelled, self.workers)
        } else {
            super::view::decode_block_frame_mapped(bytes, filter, &self.map)
        }
    }
}

/// Transform validated borrowed archive rows into caller-owned results. The
/// transform may run concurrently and before a later failure invalidates its
/// output. Only returned events should produce externally visible side effects.
pub async fn download_segment_mapped<T, U, F>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    after: u64,
    before: u64,
    filter: &Filter,
    cancel: &CancelToken,
    map: F,
) -> Result<DownloadedSegment<super::view::MappedEvent<U>>>
where
    T: HttpTransport,
    U: Send + 'static,
    F: Fn(super::view::EventView<'_>) -> U + Send + Sync + 'static,
{
    download_segment_mapped_workers(client, segment, after, before, filter, cancel, map, 1).await
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn download_segment_mapped_workers<T, U, F>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    after: u64,
    before: u64,
    filter: &Filter,
    cancel: &CancelToken,
    map: F,
    workers: usize,
) -> Result<DownloadedSegment<super::view::MappedEvent<U>>>
where
    T: HttpTransport,
    U: Send + 'static,
    F: Fn(super::view::EventView<'_>) -> U + Send + Sync + 'static,
{
    download_segment_with(
        client,
        segment,
        after,
        before,
        filter,
        cancel,
        Arc::new(ViewDecode { map, workers }),
    )
    .await
}

/// Download one planned segment and return its windowed events.
///
/// `after_seq`/`before_seq` are the snapshot window (`(after_seq, before_seq]`),
/// normally [`super::planner::SnapshotPlan::after_seq`] and
/// [`super::planner::SnapshotPlan::before_seq`]. Returns [`Error::Canceled`] on
/// cancellation, a bounded [`Error::DownloadFailed`] on an integrity, size, or
/// generation failure, or a transport/protocol error surfaced by the fetch.
pub async fn download_segment<T: HttpTransport>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    after_seq: u64,
    before_seq: u64,
    filter: &Filter,
    cancel: &CancelToken,
) -> Result<DownloadedSegment> {
    download_segment_with(
        client,
        segment,
        after_seq,
        before_seq,
        filter,
        cancel,
        Arc::new(OwnedDecode),
    )
    .await
}

/// Validate the complete whole-segment structure before exposing any chunks.
/// Only decompressed columnar storage is retained during preparation; full
/// owned events are constructed in a bounded pipeline during consumption.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn prepare_segment<'a, T: HttpTransport>(
    client: &'a ArchiveClient<T>,
    segment: &'a PlanSegment,
    after: u64,
    before: u64,
    filter: &'a Filter,
    cancel: &'a CancelToken,
    max_batch: usize,
    budget: Arc<tokio::sync::Semaphore>,
) -> Result<super::engine::ArchiveStream<'a>> {
    let concurrency = client.limits().concurrency.clamp(1, 32);
    let filter = Arc::new(filter.clone());
    let chunks = match &segment.mode {
        SegmentMode::Whole => {
            let bytes = Bytes::from(download_whole(client, segment, cancel).await?);
            let frames = {
                let reader = SegmentReader::open(&bytes)?;
                (0..reader.block_count())
                    .map(|idx| reader.block_frame(idx).map(|f| bytes.slice_ref(f)))
                    .collect::<Result<Vec<_>>>()?
            };
            drop(bytes);
            let mut decoded = stream::iter(frames)
                .map(|frame| {
                    super::decode_task::bounded(budget.clone(), cancel.clone(), move || {
                        let body = super::compression::decompress_bounded(
                            &frame,
                            super::compression::MAX_DECODED_BLOCK_BYTES,
                            None,
                        )?;
                        Ok((frame, super::block::ValidatedBlock::new(body)?))
                    })
                })
                .buffered(concurrency);
            // Compressed input is already capped. Keep at most one segment-size
            // budget of decompressed storage, plus the bounded in-flight blocks.
            // Highly compressed segments retain compressed frames beyond that
            // budget and decompress them again during consumption. Every frame
            // is still fully validated before any event becomes visible.
            let keep_limit = client.limits().max_segment_bytes;
            let mut kept = 0u64;
            let mut blocks = Vec::new();
            while let Some((frame, block)) = decoded.try_next().await? {
                let size = block.body().len() as u64;
                if size <= keep_limit.saturating_sub(kept) {
                    kept += size;
                    blocks.push(PreparedBlock::Decoded(block));
                } else {
                    blocks.push(PreparedBlock::Compressed(frame));
                }
            }
            drop(decoded);
            if cancel.is_cancelled() {
                return Err(Error::Canceled);
            }
            stream::iter(blocks)
                .map(move |block| {
                    let filter = filter.clone();
                    super::decode_task::bounded(budget.clone(), cancel.clone(), move || {
                        super::decode::convert_validated_block(block.decode()?, &filter, max_batch)
                    })
                })
                .buffered(concurrency)
                .map_ok(|chunks| stream::iter(chunks.into_iter().map(Ok)))
                .try_flatten()
                .boxed_local()
        }
        SegmentMode::Blocks(spans) => {
            let indices = spans.iter().flat_map(|s| s.first..=s.last);
            stream::iter(indices)
                .map(move |idx| {
                    let filter = filter.clone();
                    let budget = budget.clone();
                    async move {
                        let url = client.xrpc_url(
                            GET_BLOCK_METHOD,
                            Some(&format!("segment={}&blockIndex={idx}", segment.name,)),
                        );
                        let response = download_fetch(
                            client,
                            cancel,
                            client.limits().max_block_frame_bytes,
                            None,
                            || {
                                HttpRequest::get(url.clone())
                                    .header("accept", "application/octet-stream")
                            },
                        )
                        .await?;
                        if response.status != 200 {
                            return Err(Error::DownloadFailed(
                                "getBlock returned an unexpected status",
                            ));
                        }
                        super::decode_task::bounded(budget, cancel.clone(), move || {
                            let body = super::compression::decompress_bounded(
                                &response.body,
                                super::compression::MAX_DECODED_BLOCK_BYTES,
                                None,
                            )?;
                            super::decode::convert_validated_block(
                                super::block::ValidatedBlock::new(body)?,
                                &filter,
                                max_batch,
                            )
                        })
                        .await
                    }
                })
                .buffered(concurrency)
                .map_ok(|chunks| stream::iter(chunks.into_iter().map(Ok)))
                .try_flatten()
                .boxed_local()
        }
    };
    // Preserve the existing entry-level row-error order: valid events first,
    // followed by row errors in block order, then a sparse-entry failure.
    Ok(stream::unfold(
        (chunks, Vec::new(), false),
        move |(mut chunks, mut dropped, done)| async move {
            if done {
                return None;
            }
            if cancel.is_cancelled() {
                return Some((Err(Error::Canceled), (chunks, dropped, true)));
            }
            match chunks.next().await {
                Some(Ok(mut decoded)) => {
                    dropped.append(&mut decoded.dropped);
                    Some((Ok(window(decoded, after, before)), (chunks, dropped, false)))
                }
                Some(Err(Error::Canceled)) => Some((Err(Error::Canceled), (chunks, dropped, true))),
                failure => {
                    let failure = failure.and_then(Result::err);
                    if dropped.is_empty() && failure.is_none() {
                        return None;
                    }
                    Some((
                        Ok(DownloadedSegment {
                            events: Vec::new(),
                            dropped,
                            failure,
                        }),
                        (chunks, Vec::new(), true),
                    ))
                }
            }
        },
    )
    .boxed_local())
}

enum PreparedBlock {
    Decoded(super::block::ValidatedBlock),
    Compressed(Bytes),
}

impl PreparedBlock {
    fn decode(self) -> Result<super::block::ValidatedBlock> {
        match self {
            Self::Decoded(block) => Ok(block),
            Self::Compressed(frame) => {
                let body = super::compression::decompress_bounded(
                    &frame,
                    super::compression::MAX_DECODED_BLOCK_BYTES,
                    None,
                )?;
                super::block::ValidatedBlock::new(body)
            }
        }
    }
}

async fn download_segment_with<T: HttpTransport, D: ArchiveDecode>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    after_seq: u64,
    before_seq: u64,
    filter: &Filter,
    cancel: &CancelToken,
    decoder: Arc<D>,
) -> Result<DownloadedSegment<D::Item>> {
    match &segment.mode {
        SegmentMode::Whole => {
            // `download_whole` returns bytes that already passed structural
            // self-verification (header, xxh3, block index). The plan checksum
            // is deliberately *not* required to match: it is a generation
            // identity, not an integrity bind — a segment rewritten by
            // compaction between planning and download is fetched as a
            // consistent new generation and delivered, as in Go; the snapshot
            // window still clips its rows.
            let bytes = download_whole(client, segment, cancel).await?;
            let decoded = decode_archive(
                bytes,
                Arc::new(filter.clone()),
                true,
                cancel.clone(),
                decoder,
            )
            .await?;
            Ok(window(decoded, after_seq, before_seq))
        }
        SegmentMode::Blocks(spans) => {
            download_blocks(
                client,
                &segment.name,
                spans,
                after_seq,
                before_seq,
                filter,
                cancel,
                decoder,
            )
            .await
        }
    }
}

async fn decode_archive<D: ArchiveDecode>(
    bytes: Vec<u8>,
    filter: Arc<Filter>,
    whole_segment: bool,
    cancel: CancelToken,
    decoder: Arc<D>,
) -> Result<Decoded<D::Item>> {
    super::decode_task::run(move |stop| {
        let cancelled = || cancel.is_cancelled() || stop.is_cancelled();
        if cancelled() {
            return Err(Error::Canceled);
        }
        let decoded = decoder.decode(&bytes, &filter, whole_segment, cancelled)?;
        if cancelled() {
            return Err(Error::Canceled);
        }
        Ok(decoded)
    })
    .await
}

/// Apply the snapshot window `(after, before]` to a decoded segment's events,
/// keeping row-level drops.
fn window<E: Sequenced>(mut decoded: Decoded<E>, after: u64, before: u64) -> DownloadedSegment<E> {
    decoded
        .events
        .retain(|event| event.sequence() > after && event.sequence() <= before);
    DownloadedSegment {
        events: decoded.events,
        dropped: decoded.dropped,
        failure: None,
    }
}

/// Fetch and reassemble a `blocks`-mode segment under bounded concurrency.
#[allow(clippy::too_many_arguments)]
async fn download_blocks<T: HttpTransport, D: ArchiveDecode>(
    client: &ArchiveClient<T>,
    name: &str,
    spans: &[super::planner::BlockSpan],
    after: u64,
    before: u64,
    filter: &Filter,
    cancel: &CancelToken,
    decoder: Arc<D>,
) -> Result<DownloadedSegment<D::Item>> {
    let indices: Vec<u32> = spans.iter().flat_map(|s| s.first..=s.last).collect();
    let concurrency = client.limits().concurrency.max(1);
    let frame_limit = client.limits().max_block_frame_bytes;
    let filter = Arc::new(filter.clone());

    // Each bounded job fetches and decodes its block. Keeping both stages in
    // the stream lets HTTP reads continue while native CPU work runs, and lets
    // independent blocks use available cores. `buffered` retains block order;
    // completed results still occupy slots until consumed.
    let mut blocks = stream::iter(indices.into_iter().map(|idx| {
        let url = client.xrpc_url(
            GET_BLOCK_METHOD,
            Some(&format!("segment={name}&blockIndex={idx}")),
        );
        let filter = filter.clone();
        let decoder = decoder.clone();
        async move {
            let result = download_fetch(client, cancel, frame_limit, None, || {
                HttpRequest::get(url.clone()).header("accept", "application/octet-stream")
            })
            .await?;
            if result.status != 200 {
                return Err(Error::DownloadFailed(
                    "getBlock returned an unexpected status",
                ));
            }
            // Only owned bytes, filters and results cross the CPU task boundary;
            // the HTTP transport remains on its original executor.
            decode_archive(result.body, filter, false, cancel.clone(), decoder).await
        }
    }))
    .buffered(concurrency);

    let mut out = DownloadedSegment::default();
    while let Some(decoded) = blocks.next().await {
        // Preserve the decoded prefix followed by the first ordered block
        // failure. Dropping the stream cancels pending decoder jobs. Explicit
        // cancellation still aborts the entire download, as before.
        let decoded = match decoded {
            Ok(decoded) => decoded,
            Err(Error::Canceled) => return Err(Error::Canceled),
            Err(err) => {
                out.failure = Some(err);
                return Ok(out);
            }
        };
        for event in decoded.events {
            if event.sequence() > after && event.sequence() <= before {
                out.events.push(event);
            }
        }
        out.dropped.extend(decoded.dropped);
    }
    Ok(out)
}

/// Download a whole segment, restarting cleanly (up to the configured budget) if
/// the object's generation changes mid-download or the assembled bytes fail
/// structural self-verification (a truncated or torn object is redownloaded,
/// not misclassified as permanent).
async fn download_whole<T: HttpTransport>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    cancel: &CancelToken,
) -> Result<Vec<u8>> {
    let mut restarts: u32 = 0;
    let mut last_failure;
    loop {
        match try_download_whole(client, segment, cancel).await? {
            WholeOutcome::Done(bytes) => {
                // Structural self-verification: sealed header, xxh3 over
                // header[12..256] ++ footer, and a consistent block index. HTTP
                // success does not prove integrity; a failure here means a
                // corrupt or torn object, so redownload within the same bounded
                // budget as a generation change.
                if SegmentReader::open(&bytes).is_ok() {
                    return Ok(bytes);
                }
                last_failure = "downloaded segment failed integrity validation";
            }
            WholeOutcome::Restart => {
                last_failure =
                    "segment was rewritten during download and the restart budget was exhausted";
            }
        }
        restarts += 1;
        if restarts > client.limits().max_generation_restarts {
            return Err(Error::DownloadFailed(last_failure));
        }
    }
}

/// The result of one whole-download attempt.
enum WholeOutcome {
    /// The full segment bytes were assembled.
    Done(Vec<u8>),
    /// The object changed generation; the caller should restart.
    Restart,
}

/// A single whole-download attempt: probe, then stripe or fetch whole.
async fn try_download_whole<T: HttpTransport>(
    client: &ArchiveClient<T>,
    segment: &PlanSegment,
    cancel: &CancelToken,
) -> Result<WholeOutcome> {
    let cap = client.limits().max_segment_bytes;
    let name = &segment.name;
    let url = client.xrpc_url(GET_SEGMENT_METHOD, Some(&format!("name={name}")));

    // Probe with a one-byte range. A server that ignores ranges answers 200 with
    // the whole body (which we accept directly); a range-capable server answers
    // 206 with a Content-Range that reveals the total length.
    let probe = download_fetch(client, cancel, cap.saturating_add(1), None, || {
        HttpRequest::get(url.clone())
            .header("range", "bytes=0-0")
            .header("accept", "application/octet-stream")
    })
    .await?;

    if probe.status == 200 {
        if probe.body.len() as u64 > cap {
            return Err(Error::DownloadFailed("segment exceeded the size cap"));
        }
        return Ok(WholeOutcome::Done(probe.body));
    }
    if probe.status == 416 {
        // The server cannot satisfy the probe range; fall back to a whole GET.
        return Ok(WholeOutcome::Done(
            fetch_whole_body(client, &url, cap, cancel).await?,
        ));
    }

    // 206: a ranged response. Learn the total from Content-Range.
    let (_, _, total) = probe
        .headers
        .content_range
        .as_deref()
        .and_then(parse_content_range)
        .ok_or(Error::DownloadFailed(
            "ranged response lacked a valid Content-Range",
        ))?;
    if total == 0 {
        return Err(Error::DownloadFailed("segment reported a zero length"));
    }
    if total > cap {
        return Err(Error::DownloadFailed("segment exceeded the size cap"));
    }

    let stripe = client.limits().stripe_bytes.max(1);
    // Without a generation tag we cannot pin the object across requests, and a
    // small object is cheaper to fetch whole; both take the single-GET path.
    let etag = match probe.headers.etag.clone() {
        Some(etag) if total > stripe => etag,
        _ => {
            return Ok(WholeOutcome::Done(
                fetch_whole_body(client, &url, cap, cancel).await?,
            ));
        }
    };

    let ranges = compute_stripes(total, stripe);
    let concurrency = client.limits().concurrency.max(1);
    let outcomes = stream::iter(ranges.into_iter().map(|(start, end)| {
        let url = url.clone();
        let etag = etag.clone();
        async move {
            let len = end - start + 1;
            let result = download_fetch(client, cancel, len, Some(len), || {
                HttpRequest::get(url.clone())
                    .header("range", format!("bytes={start}-{end}"))
                    .header("if-range", etag.clone())
                    .header("accept", "application/octet-stream")
            })
            .await?;
            Ok::<_, Error>(classify_stripe(result, start, end, total, &etag))
        }
    }))
    .buffered(concurrency);

    // `total` is bounded by the segment cap, but the cap is caller-configurable
    // and `usize` is 32-bit on wasm; convert fallibly so an out-of-range length
    // is a bounded error rather than a truncating cast and a later slice panic.
    let total_len = usize::try_from(total)
        .map_err(|_| Error::DownloadFailed("segment length does not fit the address space"))?;
    // Consume in range order, releasing each part after its single copy. The
    // output is not exposed until every stripe and the sealed object validate.
    let mut buf = Vec::with_capacity(total_len);
    let mut failure = None;
    futures::pin_mut!(outcomes);
    while let Some(outcome) = outcomes.next().await {
        // Drain this generation's requests before restarting, retaining the
        // first failure in range order, but release all later response buffers.
        if failure.is_some() {
            continue;
        }
        match outcome {
            Ok(StripeOutcome::Restart) => failure = Some(Ok(WholeOutcome::Restart)),
            Err(err) | Ok(StripeOutcome::Error(err)) => failure = Some(Err(err)),
            Ok(StripeOutcome::Data { start, bytes }) => {
                if start != buf.len() as u64 || bytes.len() > total_len - buf.len() {
                    failure = Some(Err(Error::DownloadFailed(
                        "stripe did not extend the segment",
                    )));
                    continue;
                }
                buf.extend_from_slice(&bytes);
            }
        }
    }
    if let Some(outcome) = failure {
        return outcome;
    }
    if buf.len() != total_len {
        return Err(Error::DownloadFailed("stripes did not fill the segment"));
    }
    Ok(WholeOutcome::Done(buf))
}

/// The result of one stripe request.
enum StripeOutcome {
    /// The stripe's bytes at their absolute offset.
    Data { start: u64, bytes: Bytes },
    /// The object's generation changed; the whole download must restart.
    Restart,
    /// A fatal inconsistency in the stripe response.
    Error(Error),
}

/// Classify a stripe response against the pinned generation and expected range.
fn classify_stripe(
    result: FetchResult,
    start: u64,
    end: u64,
    total: u64,
    etag: &str,
) -> StripeOutcome {
    // 200 means the server ignored If-Range (generation changed); 416 means the
    // object shrank. Either way, restart against a fresh probe.
    if result.status == 200 || result.status == 416 {
        return StripeOutcome::Restart;
    }
    // A changed ETag on the part is a generation change — and so is a *missing*
    // one, as in Go: unverifiable bytes (e.g. from a proxy that honors Range but
    // strips the validator) must never be spliced into the buffer.
    if result.headers.etag.as_deref() != Some(etag) {
        return StripeOutcome::Restart;
    }
    match result
        .headers
        .content_range
        .as_deref()
        .and_then(parse_content_range)
    {
        Some((rs, re, rt)) => {
            if rt != total {
                // The object's size changed under us.
                return StripeOutcome::Restart;
            }
            if rs != start || re != end {
                return StripeOutcome::Error(Error::DownloadFailed(
                    "stripe Content-Range did not match the requested range",
                ));
            }
        }
        None => {
            return StripeOutcome::Error(Error::DownloadFailed(
                "stripe response lacked a valid Content-Range",
            ));
        }
    }
    let expected = (end - start + 1) as usize;
    if result.body.len() != expected {
        return StripeOutcome::Error(Error::DownloadFailed("stripe body had the wrong length"));
    }
    StripeOutcome::Data {
        start,
        bytes: Bytes::from(result.body),
    }
}

/// Fetch a whole object body with a single un-ranged GET, capping the size.
async fn fetch_whole_body<T: HttpTransport>(
    client: &ArchiveClient<T>,
    url: &str,
    cap: u64,
    cancel: &CancelToken,
) -> Result<Vec<u8>> {
    let result = download_fetch(client, cancel, cap.saturating_add(1), None, || {
        HttpRequest::get(url.to_owned()).header("accept", "application/octet-stream")
    })
    .await?;
    if result.status == 416 {
        return Err(Error::DownloadFailed(
            "server could not satisfy a whole-segment GET",
        ));
    }
    if result.body.len() as u64 > cap {
        return Err(Error::DownloadFailed("segment exceeded the size cap"));
    }
    Ok(result.body)
}

/// Compute inclusive `[start, end]` stripe ranges tiling `[0, total)`.
///
/// `stripe` is caller-configurable and can be near `u64::MAX`, so the endpoint
/// is computed with saturating arithmetic: `start + stripe - 1` would otherwise
/// overflow (a panic in debug builds). Saturating keeps the final `end` clamped
/// to `total - 1`, so progress is preserved and the loop always terminates.
fn compute_stripes(total: u64, stripe: u64) -> Vec<(u64, u64)> {
    let mut ranges = Vec::new();
    let mut start = 0u64;
    while start < total {
        let end = start.saturating_add(stripe - 1).min(total - 1);
        ranges.push((start, end));
        start = end + 1;
    }
    ranges
}

/// Parse a `Content-Range: bytes start-end/total` value into `(start, end, total)`.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.trim().strip_prefix("bytes ")?;
    let (range, total) = rest.split_once('/')?;
    let total = total.trim().parse::<u64>().ok()?;
    let (start, end) = range.split_once('-')?;
    let start = start.trim().parse::<u64>().ok()?;
    let end = end.trim().parse::<u64>().ok()?;
    Some((start, end, total))
}

/// A successful download fetch: a status the caller interprets (`2xx` or `416`),
/// the response headers, and the fully-read body.
struct FetchResult {
    status: u16,
    headers: ResponseHeaders,
    body: Vec<u8>,
}

/// How a download HTTP status is handled.
enum DownloadStatus {
    /// A 2xx status whose body should be read.
    Read,
    /// `416 Range Not Satisfiable`: read/discard the small body, return to caller.
    RangeNotSatisfiable,
    /// A status a bounded retry may clear.
    Retryable,
    /// A terminal client error.
    Terminal,
}

/// Classify a download status. Only `429` and `5xx` retry, matching the Go
/// client's `retryableStatus`; every other non-2xx (including `408`) is
/// terminal.
fn classify_download_status(status: u16) -> DownloadStatus {
    match status {
        200..=299 => DownloadStatus::Read,
        416 => DownloadStatus::RangeNotSatisfiable,
        429 => DownloadStatus::Retryable,
        500..=599 => DownloadStatus::Retryable,
        _ => DownloadStatus::Terminal,
    }
}

/// Send a download request under the download retry policy, reading the body.
///
/// `exact` requires the success body to be exactly that many bytes (a stripe);
/// otherwise the body is read up to `read_limit`. A `2xx` or `416` resolves to a
/// [`FetchResult`]; `408`/`429`/`5xx` retry with the rate-limit hint as a floor;
/// other `4xx` become a fatal [`Error::Protocol`]; cancellation short-circuits.
async fn download_fetch<T: HttpTransport, F>(
    client: &ArchiveClient<T>,
    cancel: &CancelToken,
    read_limit: u64,
    exact: Option<u64>,
    make: F,
) -> Result<FetchResult>
where
    F: Fn() -> HttpRequest,
{
    with_retry(&client.download_retry, cancel, |_attempt| {
        let make = &make;
        async move {
            let resp = match client.send(client.authorized(make()), cancel).await {
                Ok(resp) => resp,
                Err(SendError::Canceled) => return Attempt::Fatal(Error::Canceled),
                Err(SendError::Transport(err)) => return transport_attempt(err),
            };
            handle_download_response(resp, read_limit, exact, cancel).await
        }
    })
    .await
}

/// Turn a transport error into a retry-or-fatal attempt.
fn transport_attempt<T>(err: super::transport::TransportError) -> Attempt<T> {
    let retryable = err.is_retryable();
    let err = Error::from(err);
    if retryable {
        Attempt::Retry {
            delay_hint: None,
            err,
        }
    } else {
        Attempt::Fatal(err)
    }
}

/// Interpret a download response: read the body per the status class.
async fn handle_download_response<B: super::transport::HttpBody>(
    resp: HttpResponse<B>,
    read_limit: u64,
    exact: Option<u64>,
    cancel: &CancelToken,
) -> Attempt<FetchResult> {
    let status = resp.status;
    let hint = resp.headers.retry_hint(now_unix_secs());
    match classify_download_status(status) {
        DownloadStatus::Read => {
            let headers = resp.headers.clone();
            // A ranged request (`exact`) answered with anything but 206 means the
            // server ignored the Range header — the object's generation changed
            // and this response carries the whole object, not the stripe. Reading
            // it as a stripe would spuriously fail on length; instead surface the
            // status (body discarded) so the caller restarts against a fresh probe.
            if exact.is_some() && status != 206 {
                return Attempt::Ok(FetchResult {
                    status,
                    headers,
                    body: Vec::new(),
                });
            }
            let read = match exact {
                Some(n) => read_body_exact(resp.body, n, cancel).await,
                None => {
                    read_body_bounded_hint(resp.body, read_limit, headers.content_length, cancel)
                        .await
                }
            };
            match read {
                Ok(body) => Attempt::Ok(FetchResult {
                    status,
                    headers,
                    body,
                }),
                Err(BodyReadError::Canceled) => Attempt::Fatal(Error::Canceled),
                Err(BodyReadError::TooLarge) => Attempt::Fatal(Error::DownloadFailed(
                    "response body exceeded the size limit",
                )),
                // A clean EOF short of the expected length is a transient
                // truncation, retried like any read error (Go's io.ReadFull
                // path) — never misclassified as permanent.
                Err(BodyReadError::Truncated) => Attempt::Retry {
                    delay_hint: None,
                    err: Error::DownloadFailed("response body was truncated"),
                },
                Err(BodyReadError::Transport(err)) => transport_attempt(err),
            }
        }
        DownloadStatus::RangeNotSatisfiable => {
            let headers = resp.headers.clone();
            // Drain the small error body so the connection can be reused.
            match read_body_bounded(resp.body, 4096, cancel).await {
                Err(BodyReadError::Canceled) => Attempt::Fatal(Error::Canceled),
                _ => Attempt::Ok(FetchResult {
                    status,
                    headers,
                    body: Vec::new(),
                }),
            }
        }
        DownloadStatus::Retryable => {
            let body = match read_body_bounded(resp.body, 64 * 1024, cancel).await {
                Ok(body) => body,
                Err(BodyReadError::Canceled) => return Attempt::Fatal(Error::Canceled),
                Err(_) => Vec::new(),
            };
            Attempt::Retry {
                delay_hint: hint,
                err: parse_xrpc_error(&body, status),
            }
        }
        DownloadStatus::Terminal => {
            let body = match read_body_bounded(resp.body, 64 * 1024, cancel).await {
                Ok(body) => body,
                Err(BodyReadError::Canceled) => return Attempt::Fatal(Error::Canceled),
                Err(_) => Vec::new(),
            };
            Attempt::Fatal(parse_xrpc_error(&body, status))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn content_range_parsing() {
        assert_eq!(parse_content_range("bytes 0-0/12345"), Some((0, 0, 12345)));
        assert_eq!(
            parse_content_range("bytes 8388608-16777215/20000000"),
            Some((8388608, 16777215, 20000000))
        );
        // Unsatisfiable form and garbage read as absent.
        assert_eq!(parse_content_range("bytes */12345"), None);
        assert_eq!(parse_content_range("12-34/56"), None);
        assert_eq!(parse_content_range(""), None);
    }

    #[test]
    fn stripe_tiling_is_exact_and_covers_total() {
        let ranges = compute_stripes(10, 4);
        assert_eq!(ranges, vec![(0, 3), (4, 7), (8, 9)]);
        // Exact multiple.
        assert_eq!(compute_stripes(8, 4), vec![(0, 3), (4, 7)]);
        // Single stripe larger than total.
        assert_eq!(compute_stripes(3, 8), vec![(0, 2)]);
        // Total of one.
        assert_eq!(compute_stripes(1, 8), vec![(0, 0)]);
        // The ranges tile [0, total) with no gaps or overlaps.
        let total = 100u64;
        let ranges = compute_stripes(total, 7);
        let mut next = 0u64;
        for (s, e) in &ranges {
            assert_eq!(*s, next);
            assert!(e >= s);
            next = e + 1;
        }
        assert_eq!(next, total);
    }

    #[test]
    fn stripe_tiling_does_not_overflow_on_huge_stripe() {
        // Regression: `start + stripe - 1` overflowed u64 (a debug-build panic)
        // when a caller-configured stripe was near u64::MAX. Saturating keeps
        // the endpoint clamped to `total - 1`, producing a single stripe.
        assert_eq!(compute_stripes(10, u64::MAX), vec![(0, 9)]);
        // A stripe just under the max still tiles a small total in one range.
        assert_eq!(compute_stripes(5, u64::MAX - 1), vec![(0, 4)]);
    }

    #[test]
    fn download_status_classification() {
        assert!(matches!(
            classify_download_status(200),
            DownloadStatus::Read
        ));
        assert!(matches!(
            classify_download_status(206),
            DownloadStatus::Read
        ));
        assert!(matches!(
            classify_download_status(416),
            DownloadStatus::RangeNotSatisfiable
        ));
        assert!(matches!(
            classify_download_status(429),
            DownloadStatus::Retryable
        ));
        assert!(matches!(
            classify_download_status(503),
            DownloadStatus::Retryable
        ));
        assert!(matches!(
            classify_download_status(404),
            DownloadStatus::Terminal
        ));
    }
}
