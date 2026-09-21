//! Archive row conversion: decoded columnar [`RawEvent`] rows into validated,
//! transport-independent [`Event`]s, with a filter applied and valid sibling
//! rows preserved around recoverable row failures.
//!
//! Structural corruption of a block (a bad column layout, an oversized count,
//! an out-of-bounds offset) fails the whole block — such a buffer cannot be
//! trusted at all. A single *row* that fails conversion (a column that is not
//! valid UTF-8, a DID/NSID/rkey/rev that is not valid atproto syntax, or a
//! DID-level payload that is not valid CBOR) is dropped and its error collected
//! in [`Decoded::dropped`], so one malformed upstream record cannot cost the
//! consumer the rest of the block. This mirrors the Go downloader, which joins
//! per-row decode errors alongside the valid events it recovered.
//!
//! Filtering happens on the raw columns *before* conversion (see
//! [`Filter::matches_segment`]), so a row the subscription does not want is
//! skipped without paying for its typed conversion.

use bytes::Bytes;

use super::block::{Columns, RawEvent, SegmentKind, TextColumn, visit_block};
use super::compression::{MAX_DECODED_BLOCK_BYTES, decompress_bounded};
use super::error::{Error, Result};
use super::event::{Commit, Event, EventPayload, Operation};
use super::filter::Filter;
use super::record::Record;
use super::segment::SegmentReader;
use crate::api::com::atproto::{
    SyncSubscribeReposAccount, SyncSubscribeReposIdentity, SyncSubscribeReposSync,
};
use crate::syntax::{Did, Nsid, RecordKey, Tid};

/// The outcome of decoding a filtered block or segment: the events that passed
/// the filter and converted successfully, plus the recoverable per-row errors
/// whose rows were dropped so their valid siblings could still be delivered.
///
/// `dropped` is empty for a clean, well-formed block. A non-empty `dropped`
/// means some rows carried malformed content the segment writer let through; the
/// consumer may log or count them but the surrounding events are still valid.
#[derive(Debug)]
pub struct Decoded<E = Event> {
    /// Successfully converted events that passed the filter, in row order.
    pub events: Vec<E>,
    /// Recoverable per-row conversion errors whose rows were dropped.
    pub dropped: Vec<Error>,
}

impl<E> Default for Decoded<E> {
    fn default() -> Self {
        Self {
            events: Vec::new(),
            dropped: Vec::new(),
        }
    }
}

/// Convert one decoded columnar row into a validated [`Event`].
///
/// Consumes `raw` so a commit's payload bytes move into the [`Record`] without a
/// copy. Every metadata column is validated by its typed conversion (`Did`,
/// `Nsid`, `RecordKey`, `Tid`); a create/update commit's record body is stored
/// lazily (its CBOR is decoded only on demand), while identity/account/sync
/// payloads are eagerly decoded from their upstream CBOR here.
pub fn raw_event_to_event(raw: RawEvent) -> Result<Event> {
    let columns = Columns {
        seq: raw.seq,
        witnessed_at: raw.witnessed_at,
        indexed_at: raw.indexed_at,
        kind: raw.kind,
        collection: TextColumn::Raw(&raw.collection),
        did: TextColumn::Raw(&raw.did),
        rkey: TextColumn::Raw(&raw.rkey),
        rev: TextColumn::Raw(&raw.rev),
    };
    convert_row(columns, raw.payload)
}

fn convert_row(raw: Columns<'_>, payload: impl AsRef<[u8]> + Into<Bytes>) -> Result<Event> {
    // Segment sequences are 1-based; a zero seq would corrupt the dedup cursor.
    if raw.seq == 0 {
        return Err(Error::MalformedEvent("segment row seq must be positive"));
    }
    let seq = raw.seq;
    let time_us = if raw.indexed_at != 0 {
        raw.indexed_at
    } else {
        raw.witnessed_at
    };
    let did = Did::try_from(str_col(raw.did)?)
        .map_err(|_| Error::MalformedEvent("segment row did is not a valid DID"))?;

    let Columns {
        kind,
        collection,
        rkey,
        rev,
        ..
    } = raw;

    let payload = match kind {
        SegmentKind::Create
        | SegmentKind::Update
        | SegmentKind::Delete
        | SegmentKind::CreateResync => {
            // Infallible for these variants, but treat `None` as corruption
            // rather than unwrapping.
            let operation = kind.to_operation().ok_or(Error::MalformedEvent(
                "segment commit kind has no operation",
            ))?;
            let collection = Nsid::try_from(str_col(collection)?)
                .map_err(|_| Error::MalformedEvent("segment row collection is not a valid NSID"))?;
            let rkey = RecordKey::try_from(str_col(rkey)?)
                .map_err(|_| Error::MalformedEvent("segment row rkey is not a valid record key"))?;
            let rev = Tid::try_from(str_col(rev)?)
                .map_err(|_| Error::MalformedEvent("segment row rev is not a valid TID"))?;
            // A delete carries no record body; a create/update stores its
            // canonical CBOR lazily. The segment never stores a CID, so the CID
            // is computed from the record bytes on demand.
            let record = match operation {
                Operation::Delete => None,
                Operation::Create | Operation::Update => Some(Record::from_canonical_cbor(payload)),
            };
            EventPayload::Commit(Commit {
                operation,
                collection,
                rkey,
                rev,
                record,
            })
        }
        SegmentKind::Identity => EventPayload::Identity(
            SyncSubscribeReposIdentity::from_cbor(payload.as_ref())
                .map_err(|_| Error::MalformedEvent("segment identity payload is not valid CBOR"))?,
        ),
        SegmentKind::Account => EventPayload::Account(
            SyncSubscribeReposAccount::from_cbor(payload.as_ref())
                .map_err(|_| Error::MalformedEvent("segment account payload is not valid CBOR"))?,
        ),
        SegmentKind::Sync => EventPayload::Sync(
            SyncSubscribeReposSync::from_cbor(payload.as_ref())
                .map_err(|_| Error::MalformedEvent("segment sync payload is not valid CBOR"))?,
        ),
    };

    Ok(Event {
        seq,
        did,
        time_us,
        payload,
    })
}

/// Decode a raw `getBlock` zstd frame into filtered, validated events.
///
/// Structural block corruption fails the whole call; a single row that fails to
/// convert is dropped with its error collected (see [`Decoded`]).
pub fn decode_block_frame_filtered(frame: &[u8], filter: &Filter) -> Result<Decoded> {
    let body = decompress_bounded(frame, MAX_DECODED_BLOCK_BYTES, None)?;
    let mut out = Decoded::default();
    convert_block_into(&body, filter, &mut out)?;
    Ok(out)
}

/// Decode an entire sealed segment into filtered, validated events, in segment
/// (ascending-sequence) order.
///
/// The header checksum, block index, and block layout are validated up front
/// (see [`SegmentReader::open`]); each block is then decoded in order. A
/// structurally corrupt block fails the whole call, while recoverable per-row
/// failures are collected across all blocks into [`Decoded::dropped`].
pub fn decode_segment_filtered(segment: &[u8], filter: &Filter) -> Result<Decoded> {
    decode_segment_cancellable(segment, filter, || false)
}

pub(crate) fn decode_segment_cancellable(
    segment: &[u8],
    filter: &Filter,
    cancelled: impl Fn() -> bool,
) -> Result<Decoded> {
    let reader = SegmentReader::open(segment)?;
    let mut out = Decoded::default();
    for idx in 0..reader.block_count() {
        if cancelled() {
            return Err(Error::Canceled);
        }
        let frame = reader.block_frame(idx)?;
        let body = decompress_bounded(frame, MAX_DECODED_BLOCK_BYTES, None)?;
        // Materialize directly in segment order, avoiding a temporary event
        // vector and a second move of every event at each block boundary.
        convert_block_into(&body, filter, &mut out)?;
    }
    if cancelled() {
        return Err(Error::Canceled);
    }
    Ok(out)
}

/// Filter and convert a block's rows, preserving valid siblings around
/// recoverable per-row failures.
fn convert_block_into(body: &[u8], filter: &Filter, out: &mut Decoded) -> Result<()> {
    visit_block(body, |_, raw, payload| {
        // Filter on the raw columns first; a non-UTF-8 column reads as "" so a
        // constrained DID/collection predicate rejects it, while an unfiltered
        // dimension still admits the row (its typed conversion then drops it).
        let did = raw.did.text().unwrap_or("");
        let collection = raw.collection.text().unwrap_or("");
        if !filter.matches_segment(raw.kind.public_kind(), did, collection) {
            return;
        }
        // Independent storage lets a consumer retain one small record without
        // pinning the entire decompressed block (including rejected rows).
        match convert_row(raw, Bytes::copy_from_slice(payload)) {
            Ok(event) => out.events.push(event),
            Err(err) => out.dropped.push(err),
        }
    })
}

/// Reinterpret a raw column as UTF-8, or report it as malformed.
fn str_col(bytes: TextColumn<'_>) -> Result<&str> {
    bytes
        .text()
        .map_err(|_| Error::MalformedEvent("segment row column is not valid UTF-8"))
}
