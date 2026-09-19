//! The snapshot planner: turn a filter and a sequence window into a validated,
//! stable download plan by paging `network.bsky.jetstream.planSnapshot`.
//!
//! # The stability contract
//!
//! An archive is append-only, but its sealed tip advances while a download runs.
//! To download a *consistent* snapshot the planner pins the sealed tip reported
//! by the first page — call it `S` — and freezes every later page against it:
//!
//! - the first page carries the caller's exact bounds (`afterSeq`,
//!   `beforeSeq`), so the server caps `S` at the caller's `beforeSeq` when one
//!   was given (that capping is what [`JetstreamPlanSnapshotOutput::sealed_tip_seq`]
//!   documents);
//! - every later page sends `afterSeq = plannedThroughSeq` (the coverage cursor)
//!   and `beforeSeq = S`, so a growing archive cannot extend the plan mid-run;
//! - `plannedThroughSeq` is treated as *coverage*, not as "segments present":
//!   an empty or sparse page still advances the cursor, so a filter that matches
//!   nothing in a stretch of the archive still terminates;
//! - planning finishes when `plannedThroughSeq >= S`.
//!
//! # Strict validation
//!
//! Every field the downloader will act on is validated before it is trusted: a
//! later page whose `sealedTipSeq` drifted from `S`, a `plannedThroughSeq` past
//! `S` or that fails to advance, a bad segment name, a non-16-hex checksum, an
//! inverted or out-of-range sequence span, an unknown mode, or block ranges that
//! are empty, inverted, or not strictly increasing all abort planning with a
//! fatal [`Error::PlanInvalid`]. There is no safe way to download against a plan
//! that cannot be trusted, so the planner refuses rather than guess.

use crate::api::network::bsky::{
    JetstreamPlanSnapshotBlockRange, JetstreamPlanSnapshotInput, JetstreamPlanSnapshotOutput,
    JetstreamPlanSnapshotSegment,
};
use crate::syntax::Did;

use super::archive::{ArchiveClient, json_body};
use super::cancel::CancelToken;
use super::error::{Error, Result};
use super::filter::Filter;
use super::segment::MAX_BLOCK_COUNT;
use super::transport::{HttpRequest, HttpTransport};

/// The XRPC method id for the planner endpoint.
const PLAN_SNAPSHOT_METHOD: &str = "network.bsky.jetstream.planSnapshot";

/// An inclusive `[first, last]` range of block indices within a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockSpan {
    /// The first block index in the range (inclusive).
    pub first: u32,
    /// The last block index in the range (inclusive).
    pub last: u32,
}

/// How a planned segment is to be downloaded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SegmentMode {
    /// Download the whole `.jss` file with `getSegment`.
    Whole,
    /// Download the listed block ranges with `getBlock`. Always non-empty and in
    /// strictly increasing, non-overlapping order.
    Blocks(Vec<BlockSpan>),
}

/// One validated segment in a [`SnapshotPlan`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlanSegment {
    /// The segment filename to pass to `getSegment`/`getBlock`. Validated to be a
    /// safe, single-path-component name.
    pub name: String,
    /// The zero-based segment index.
    pub index: u64,
    /// The minimum sequence the segment covers (1-based).
    pub min_seq: u64,
    /// The maximum sequence the segment covers (1-based), never above the pinned
    /// sealed tip.
    pub max_seq: u64,
    /// The segment's xxh3 metadata checksum, exactly 16 lowercase hex digits.
    pub checksum: String,
    /// How to download the segment.
    pub mode: SegmentMode,
}

/// A validated, stable snapshot download plan.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SnapshotPlan {
    /// The pinned sealed tip `S`: the inclusive upper sequence bound of the
    /// snapshot for its whole lifetime.
    pub sealed_tip_seq: u64,
    /// The caller's exclusive lower sequence bound. The download applies the
    /// window `(after_seq, sealed_tip_seq]` to every decoded row.
    pub after_seq: u64,
    /// The inclusive upper sequence bound applied to decoded rows. Equal to
    /// [`sealed_tip_seq`](Self::sealed_tip_seq).
    pub before_seq: u64,
    /// The segments to download, in plan order.
    pub segments: Vec<PlanSegment>,
}

/// Build a validated, stable snapshot plan for `filter` over the window
/// `(after_seq, before_seq]` (an open `before_seq` means up to the sealed tip).
///
/// See the module docs for the stability and validation contract. Returns a
/// fatal [`Error::PlanInvalid`] on any untrustworthy response, [`Error::Canceled`]
/// if cancelled, or a transport/protocol error surfaced by the control request.
pub async fn plan_snapshot<T: HttpTransport>(
    client: &ArchiveClient<T>,
    filter: &Filter,
    after_seq: u64,
    before_seq: Option<u64>,
    cancel: &CancelToken,
) -> Result<SnapshotPlan> {
    let base_input = build_base_input(filter, before_seq)?;

    let mut segments: Vec<PlanSegment> = Vec::new();
    let mut pinned_tip: Option<u64> = None;
    // Coverage starts at the caller's exclusive lower bound: everything at or
    // below `after_seq` is out of scope before any page is fetched.
    let mut planned_through: u64 = after_seq;
    let mut pages: u32 = 0;

    loop {
        if cancel.is_cancelled() {
            return Err(Error::Canceled);
        }
        pages += 1;
        if pages > client.limits().max_plan_pages {
            return Err(Error::PlanInvalid(
                "planSnapshot exceeded the maximum page count",
            ));
        }

        // First page: caller's exact bounds. Later pages: pinned freeze.
        let (page_after, page_before) = match pinned_tip {
            None => (
                (after_seq > 0).then_some(seq_to_wire(after_seq)?),
                before_seq.map(seq_to_wire).transpose()?,
            ),
            Some(tip) => (Some(seq_to_wire(planned_through)?), Some(seq_to_wire(tip)?)),
        };

        let body = {
            let mut input = base_input.clone();
            input.after_seq = page_after;
            input.before_seq = page_before;
            json_body(&input)?
        };
        let url = client.xrpc_url(PLAN_SNAPSHOT_METHOD, None);
        let bytes = client
            .control_request(cancel, || {
                HttpRequest::post(url.clone())
                    .header("content-type", "application/json")
                    .header("accept", "application/json")
                    .with_body(body.clone())
            })
            .await?;

        let output: JetstreamPlanSnapshotOutput = serde_json::from_slice(&bytes)
            .map_err(|_| Error::PlanInvalid("planSnapshot response was not valid JSON"))?;

        let tip = nonneg(output.sealed_tip_seq, "sealedTipSeq was negative")?;
        match pinned_tip {
            None => pinned_tip = Some(tip),
            Some(pinned) if tip != pinned => {
                return Err(Error::PlanInvalid("sealedTipSeq drifted between pages"));
            }
            Some(_) => {}
        }

        let pts = nonneg(output.planned_through_seq, "plannedThroughSeq was negative")?;
        if pts > tip {
            return Err(Error::PlanInvalid(
                "plannedThroughSeq exceeded the pinned sealed tip",
            ));
        }

        for raw in output.segments {
            if segments.len() >= client.limits().max_plan_segments {
                return Err(Error::PlanInvalid(
                    "planSnapshot returned too many segments",
                ));
            }
            segments.push(validate_segment(raw, tip)?);
        }

        // Coverage must strictly advance unless the page already reaches the tip.
        if pts <= planned_through && pts < tip {
            return Err(Error::PlanInvalid(
                "planSnapshot page did not advance coverage",
            ));
        }
        planned_through = planned_through.max(pts);

        if planned_through >= tip {
            let tip = pinned_tip.unwrap_or(tip);
            return Ok(SnapshotPlan {
                sealed_tip_seq: tip,
                after_seq,
                before_seq: tip,
                segments,
            });
        }
    }
}

/// Build the filter-derived input fields (the bounds are filled in per page).
fn build_base_input(
    filter: &Filter,
    _before_seq: Option<u64>,
) -> Result<JetstreamPlanSnapshotInput> {
    let mut dids: Vec<Did> = Vec::new();
    for token in filter.did_wire_tokens() {
        // Tokens come from already-validated DIDs, so this cannot fail; treat a
        // failure defensively as a configuration error rather than panicking.
        let did =
            Did::try_from(token).map_err(|_| Error::InvalidConfig("filter DID is not valid"))?;
        dids.push(did);
    }
    Ok(JetstreamPlanSnapshotInput {
        after_seq: None,
        before_seq: None,
        collections: filter.collection_wire_tokens().collect(),
        dids,
        kinds: filter.kind_wire_tokens().map(|k| k.to_owned()).collect(),
        extra: std::collections::HashMap::new(),
    })
}

/// Validate one raw plan segment against the pinned tip, converting it into a
/// trusted [`PlanSegment`].
fn validate_segment(raw: JetstreamPlanSnapshotSegment, sealed_tip: u64) -> Result<PlanSegment> {
    validate_segment_name(&raw.name)?;
    validate_checksum(&raw.checksum)?;

    let index = nonneg(raw.index, "segment index was negative")?;
    let min_seq = nonneg(raw.min_seq, "segment minSeq was negative")?;
    let max_seq = nonneg(raw.max_seq, "segment maxSeq was negative")?;
    if min_seq == 0 || min_seq > max_seq {
        return Err(Error::PlanInvalid(
            "segment sequence span is empty or inverted",
        ));
    }
    if max_seq > sealed_tip {
        return Err(Error::PlanInvalid(
            "segment maxSeq exceeded the pinned sealed tip",
        ));
    }

    let mode = match raw.mode.as_str() {
        "segment" => {
            if !raw.blocks.is_empty() {
                return Err(Error::PlanInvalid(
                    "whole-segment plan entry carried block ranges",
                ));
            }
            SegmentMode::Whole
        }
        "blocks" => SegmentMode::Blocks(validate_block_spans(&raw.blocks)?),
        _ => {
            return Err(Error::PlanInvalid(
                "segment mode was neither 'segment' nor 'blocks'",
            ));
        }
    };

    Ok(PlanSegment {
        name: raw.name,
        index,
        min_seq,
        max_seq,
        checksum: raw.checksum,
        mode,
    })
}

/// Validate a `blocks`-mode segment's block ranges: non-empty, each `first<=last`,
/// each index below [`MAX_BLOCK_COUNT`], and the whole list strictly increasing
/// with no overlap.
fn validate_block_spans(raw: &[JetstreamPlanSnapshotBlockRange]) -> Result<Vec<BlockSpan>> {
    if raw.is_empty() {
        return Err(Error::PlanInvalid(
            "blocks-mode segment listed no block ranges",
        ));
    }
    let mut spans: Vec<BlockSpan> = Vec::with_capacity(raw.len());
    let mut prev_last: Option<u32> = None;
    for range in raw {
        let first = block_index(range.first)?;
        let last = block_index(range.last)?;
        if first > last {
            return Err(Error::PlanInvalid("block range is inverted"));
        }
        if let Some(prev) = prev_last
            && first <= prev
        {
            return Err(Error::PlanInvalid(
                "block ranges are not strictly increasing",
            ));
        }
        prev_last = Some(last);
        spans.push(BlockSpan { first, last });
    }
    Ok(spans)
}

/// Convert a wire block index to a bounded `u32`.
fn block_index(value: i64) -> Result<u32> {
    if !(0..MAX_BLOCK_COUNT as i64).contains(&value) {
        return Err(Error::PlanInvalid("block index is out of range"));
    }
    Ok(value as u32)
}

/// Validate a segment filename: a single path component of a bounded length,
/// drawn from a conservative alphabet, with no traversal or separators. The name
/// is placed into a request query string, so it must not smuggle a path or a
/// control character.
fn validate_segment_name(name: &str) -> Result<()> {
    const MAX_NAME_LEN: usize = 255;
    if name.is_empty() || name.len() > MAX_NAME_LEN {
        return Err(Error::PlanInvalid("segment name is empty or too long"));
    }
    if name == "." || name == ".." || name.contains("..") {
        return Err(Error::PlanInvalid("segment name contains a path traversal"));
    }
    for b in name.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_');
        if !ok {
            return Err(Error::PlanInvalid(
                "segment name has a disallowed character",
            ));
        }
    }
    Ok(())
}

/// Validate a segment checksum: exactly 16 lowercase hexadecimal digits (the
/// hex encoding of the segment's `u64` xxh3 metadata checksum).
fn validate_checksum(checksum: &str) -> Result<()> {
    if checksum.len() != 16
        || !checksum
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(Error::PlanInvalid(
            "segment checksum is not 16 lowercase hex digits",
        ));
    }
    Ok(())
}

/// Coerce a non-negative wire integer into a `u64`, or a plan error.
fn nonneg(value: i64, message: &'static str) -> Result<u64> {
    if value < 0 {
        return Err(Error::PlanInvalid(message));
    }
    Ok(value as u64)
}

/// Convert a `u64` sequence to the wire `i64`, rejecting an out-of-range value.
fn seq_to_wire(seq: u64) -> Result<i64> {
    i64::try_from(seq).map_err(|_| Error::InvalidConfig("sequence exceeds the wire integer range"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn seg(
        name: &str,
        index: i64,
        min: i64,
        max: i64,
        checksum: &str,
        mode: &str,
        blocks: Vec<(i64, i64)>,
    ) -> JetstreamPlanSnapshotSegment {
        JetstreamPlanSnapshotSegment {
            blocks: blocks
                .into_iter()
                .map(|(first, last)| JetstreamPlanSnapshotBlockRange {
                    first,
                    last,
                    extra: std::collections::HashMap::new(),
                    extra_cbor: Vec::new(),
                })
                .collect(),
            checksum: checksum.to_owned(),
            index,
            max_seq: max,
            min_seq: min,
            mode: mode.to_owned(),
            name: name.to_owned(),
            extra: std::collections::HashMap::new(),
            extra_cbor: Vec::new(),
        }
    }

    const CK: &str = "0123456789abcdef";

    #[test]
    fn accepts_whole_and_blocks_modes() {
        let whole = validate_segment(seg("s0.jss", 0, 1, 10, CK, "segment", vec![]), 10)
            .expect("valid whole");
        assert_eq!(whole.mode, SegmentMode::Whole);
        assert_eq!(whole.name, "s0.jss");
        assert_eq!(whole.min_seq, 1);
        assert_eq!(whole.max_seq, 10);

        let blocks = validate_segment(
            seg(
                "s1.jss",
                1,
                11,
                20,
                CK,
                "blocks",
                vec![(0, 2), (4, 4), (7, 9)],
            ),
            20,
        )
        .expect("valid blocks");
        assert_eq!(
            blocks.mode,
            SegmentMode::Blocks(vec![
                BlockSpan { first: 0, last: 2 },
                BlockSpan { first: 4, last: 4 },
                BlockSpan { first: 7, last: 9 },
            ])
        );
    }

    #[test]
    fn rejects_bad_checksums() {
        for bad in [
            "0123",
            "0123456789ABCDEF",
            "0123456789abcdeg",
            "0123456789abcdef0",
        ] {
            assert!(matches!(
                validate_segment(seg("s.jss", 0, 1, 2, bad, "segment", vec![]), 2),
                Err(Error::PlanInvalid(_))
            ));
        }
    }

    #[test]
    fn rejects_bad_names() {
        for bad in ["", "../etc", "a/b", "a b", "seg\u{0000}", ".", ".."] {
            assert!(matches!(
                validate_segment(seg(bad, 0, 1, 2, CK, "segment", vec![]), 2),
                Err(Error::PlanInvalid(_))
            ));
        }
    }

    #[test]
    fn rejects_inverted_or_out_of_range_spans() {
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 5, 4, CK, "segment", vec![]), 10),
            Err(Error::PlanInvalid(_))
        ));
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 0, 4, CK, "segment", vec![]), 10),
            Err(Error::PlanInvalid(_))
        ));
        // maxSeq beyond the pinned tip.
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 11, CK, "segment", vec![]), 10),
            Err(Error::PlanInvalid(_))
        ));
    }

    #[test]
    fn rejects_unknown_mode_and_mismatched_blocks() {
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 2, CK, "elsewhere", vec![]), 2),
            Err(Error::PlanInvalid(_))
        ));
        // segment mode must not carry blocks.
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 2, CK, "segment", vec![(0, 1)]), 2),
            Err(Error::PlanInvalid(_))
        ));
        // blocks mode must carry blocks.
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 2, CK, "blocks", vec![]), 2),
            Err(Error::PlanInvalid(_))
        ));
    }

    #[test]
    fn rejects_non_increasing_block_ranges() {
        // Overlapping (4 <= 4).
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 9, CK, "blocks", vec![(0, 4), (4, 6)]), 9),
            Err(Error::PlanInvalid(_))
        ));
        // Out of order.
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 9, CK, "blocks", vec![(5, 6), (0, 1)]), 9),
            Err(Error::PlanInvalid(_))
        ));
        // Inverted single range.
        assert!(matches!(
            validate_segment(seg("s.jss", 0, 1, 9, CK, "blocks", vec![(6, 5)]), 9),
            Err(Error::PlanInvalid(_))
        ));
    }
}
