//! Experimental scoped archive processing. The transform sees a validated
//! envelope and opaque record borrowing the current decompressed block. Its output
//! must own anything it keeps; Rust prevents borrowed data escaping the callback.
//! A transform can run before a later structural failure, so it must not be used
//! as a delivery/commit callback. Only a successful returned result is deliverable.

use std::borrow::Cow;

use super::block::{Columns, SegmentKind, TextColumn, visit_block};
use super::compression::{MAX_DECODED_BLOCK_BYTES, decompress_bounded};
use super::error::{Error, Result};
use super::event::{Event, EventPayload, Operation};
use super::filter::Filter;
use super::segment::SegmentReader;
use crate::api::com::atproto::{
    SyncSubscribeReposAccount, SyncSubscribeReposIdentity, SyncSubscribeReposSync,
};
use crate::syntax::{Did, Nsid, RecordKey, Tid};

/// An event with validated envelope syntax and scoped record storage.
#[derive(Debug)]
pub struct EventView<'a> {
    pub seq: u64,
    pub did: &'a str,
    pub time_us: i64,
    pub payload: EventPayloadView<'a>,
}

#[derive(Debug)]
pub enum EventPayloadView<'a> {
    Commit(CommitView<'a>),
    Identity(SyncSubscribeReposIdentity),
    Account(SyncSubscribeReposAccount),
    Sync(SyncSubscribeReposSync),
}

#[derive(Debug)]
pub struct CommitView<'a> {
    pub operation: Operation,
    pub collection: Cow<'a, str>,
    pub rkey: &'a str,
    pub rev: Tid,
    pub record: Option<&'a [u8]>,
}

impl EventView<'_> {
    /// Explicitly retain an independently owned event beyond this callback.
    pub fn to_owned(&self) -> Result<Event> {
        use super::{Commit, Record};
        Ok(Event {
            seq: self.seq,
            did: Did::try_from(self.did).map_err(|_| Error::MalformedEvent("invalid view DID"))?,
            time_us: self.time_us,
            payload: match &self.payload {
                EventPayloadView::Commit(c) => EventPayload::Commit(Commit {
                    operation: c.operation,
                    collection: Nsid::try_from(c.collection.as_ref())
                        .map_err(|_| Error::MalformedEvent("invalid view collection"))?,
                    rkey: RecordKey::try_from(c.rkey)
                        .map_err(|_| Error::MalformedEvent("invalid view record key"))?,
                    rev: c.rev,
                    record: c.record.map(|r| Record::from_canonical_cbor(r.to_vec())),
                }),
                EventPayloadView::Identity(v) => EventPayload::Identity(v.clone()),
                EventPayloadView::Account(v) => EventPayload::Account(v.clone()),
                EventPayloadView::Sync(v) => EventPayload::Sync(v.clone()),
            },
        })
    }
}

/// A transform output carrying the original cursor for ordered delivery.
#[derive(Debug)]
pub struct MappedEvent<T> {
    pub seq: u64,
    pub value: T,
}

pub type MappedDecoded<T> = super::decode::Decoded<MappedEvent<T>>;

impl<T> super::event::Sequenced for MappedEvent<T> {
    fn sequence(&self) -> u64 {
        self.seq
    }
}

fn text(bytes: TextColumn<'_>) -> Result<&str> {
    bytes
        .text()
        .map_err(|_| Error::MalformedEvent("segment row column is not valid UTF-8"))
}

fn event_view<'a>(
    raw: Columns<'a>,
    payload: &'a [u8],
    selected: super::filter::SegmentSelection<'a>,
) -> Result<EventView<'a>> {
    if raw.seq == 0 {
        return Err(Error::MalformedEvent("segment row seq must be positive"));
    }
    let did = text(raw.did)?;
    if !selected.did_validated {
        Did::validate(did)
            .map_err(|_| Error::MalformedEvent("segment row did is not a valid DID"))?;
    }
    let data = match raw.kind {
        SegmentKind::Create
        | SegmentKind::Update
        | SegmentKind::Delete
        | SegmentKind::CreateResync => {
            let operation = raw.kind.to_operation().ok_or(Error::MalformedEvent(
                "segment commit kind has no operation",
            ))?;
            let collection = text(raw.collection)?;
            let collection = if let Some(known) = selected.collection {
                Cow::Borrowed(known.as_str())
            } else {
                let last_dot = Nsid::validate(collection).map_err(|_| {
                    Error::MalformedEvent("segment row collection is not a valid NSID")
                })?;
                if collection.as_bytes()[..last_dot]
                    .iter()
                    .any(u8::is_ascii_uppercase)
                {
                    let mut normalized = collection[..last_dot].to_ascii_lowercase();
                    normalized.push_str(&collection[last_dot..]);
                    Cow::Owned(normalized)
                } else {
                    Cow::Borrowed(collection)
                }
            };
            let rkey = text(raw.rkey)?;
            RecordKey::validate(rkey)
                .map_err(|_| Error::MalformedEvent("segment row rkey is not a valid record key"))?;
            let rev = Tid::try_from(text(raw.rev)?)
                .map_err(|_| Error::MalformedEvent("segment row rev is not a valid TID"))?;
            EventPayloadView::Commit(CommitView {
                operation,
                collection,
                rkey,
                rev,
                record: (operation != Operation::Delete).then_some(payload),
            })
        }
        SegmentKind::Identity => EventPayloadView::Identity(
            SyncSubscribeReposIdentity::from_cbor(payload)
                .map_err(|_| Error::MalformedEvent("segment identity payload is not valid CBOR"))?,
        ),
        SegmentKind::Account => EventPayloadView::Account(
            SyncSubscribeReposAccount::from_cbor(payload)
                .map_err(|_| Error::MalformedEvent("segment account payload is not valid CBOR"))?,
        ),
        SegmentKind::Sync => EventPayloadView::Sync(
            SyncSubscribeReposSync::from_cbor(payload)
                .map_err(|_| Error::MalformedEvent("segment sync payload is not valid CBOR"))?,
        ),
    };
    Ok(EventView {
        seq: raw.seq,
        did,
        time_us: if raw.indexed_at == 0 {
            raw.witnessed_at
        } else {
            raw.indexed_at
        },
        payload: data,
    })
}

pub fn decode_block_frame_mapped<T>(
    frame: &[u8],
    filter: &Filter,
    map: &impl Fn(EventView<'_>) -> T,
) -> Result<MappedDecoded<T>> {
    let body = decompress_bounded(frame, MAX_DECODED_BLOCK_BYTES, None)?;
    let mut out = MappedDecoded::default();
    convert_block(&body, filter, map, &mut out)?;
    Ok(out)
}

pub fn decode_segment_mapped<T>(
    segment: &[u8],
    filter: &Filter,
    map: &impl Fn(EventView<'_>) -> T,
) -> Result<MappedDecoded<T>> {
    decode_segment_mapped_cancellable(segment, filter, map, || false)
}

pub(crate) fn decode_segment_mapped_cancellable<T>(
    segment: &[u8],
    filter: &Filter,
    map: &impl Fn(EventView<'_>) -> T,
    cancelled: impl Fn() -> bool,
) -> Result<MappedDecoded<T>> {
    let reader = SegmentReader::open(segment)?;
    decode_range(&reader, filter, map, &cancelled, 0..reader.block_count())
}

fn decode_range<T>(
    reader: &SegmentReader<'_>,
    filter: &Filter,
    map: &impl Fn(EventView<'_>) -> T,
    cancelled: &impl Fn() -> bool,
    range: std::ops::Range<usize>,
) -> Result<MappedDecoded<T>> {
    let mut out = MappedDecoded::default();
    for index in range {
        if cancelled() {
            return Err(Error::Canceled);
        }
        let body = decompress_bounded(reader.block_frame(index)?, MAX_DECODED_BLOCK_BYTES, None)?;
        convert_block(&body, filter, map, &mut out)?;
    }
    if cancelled() {
        return Err(Error::Canceled);
    }
    Ok(out)
}

/// Native workers share immutable compressed input and return independently
/// owned chunks. All workers join before any chunk is delivered; a structural
/// failure anywhere still invalidates the entire segment, in block order.
pub(crate) fn decode_segment_workers<T: Send>(
    segment: &[u8],
    filter: &Filter,
    map: &(impl Fn(EventView<'_>) -> T + Sync),
    cancelled: impl Fn() -> bool + Sync,
    workers: usize,
) -> Result<MappedDecoded<T>> {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    if workers > 1 {
        let reader = SegmentReader::open(segment)?;
        let count = reader.block_count();
        if count == 0 {
            return if cancelled() {
                Err(Error::Canceled)
            } else {
                Ok(MappedDecoded::default())
            };
        }
        let chunk = count.div_ceil(workers.min(count));
        return std::thread::scope(|scope| {
            let mut jobs = Vec::new();
            for start in (chunk..count).step_by(chunk) {
                let reader = &reader;
                let cancelled = &cancelled;
                jobs.push(
                    std::thread::Builder::new()
                        .name("shrike-decode".into())
                        .spawn_scoped(scope, move || {
                            decode_range(
                                reader,
                                filter,
                                map,
                                cancelled,
                                start..(start + chunk).min(count),
                            )
                        })
                        .map_err(|_| {
                            Error::DownloadFailed("could not start archive decode worker")
                        })?,
                );
            }
            let first = decode_range(&reader, filter, map, &cancelled, 0..chunk.min(count));
            // Join all workers even when an earlier chunk failed. No detached
            // decoder may outlive the borrowed input.
            let mut rest = Vec::new();
            for job in jobs {
                rest.push(job.join().unwrap_or_else(|_| {
                    Err(Error::DownloadFailed("archive decode worker failed"))
                }));
            }
            let mut out = first?;
            for part in rest {
                let mut part = part?;
                out.events.append(&mut part.events);
                out.dropped.append(&mut part.dropped);
            }
            Ok(out)
        });
    }
    let _ = workers;
    decode_segment_mapped_cancellable(segment, filter, map, cancelled)
}

fn convert_block<T>(
    body: &[u8],
    filter: &Filter,
    map: &impl Fn(EventView<'_>) -> T,
    out: &mut MappedDecoded<T>,
) -> Result<()> {
    visit_block(body, |_, raw, payload| {
        let did = raw.did.text().unwrap_or("");
        let collection = raw.collection.text().unwrap_or("");
        let Some(selected) = filter.select_segment(raw.kind.public_kind(), did, collection) else {
            return;
        };
        match event_view(raw, payload, selected) {
            Ok(event) => out.events.push(MappedEvent {
                seq: event.seq,
                value: map(event),
            }),
            Err(err) => out.dropped.push(err),
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    #[allow(dead_code)]
    mod fixture {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/support/jetstream_segment.rs"
        ));
    }
    fn valid_segment() -> Vec<u8> {
        fixture::seal(
            &(0..5)
                .map(|b| ((b * 8 + 1)..=(b * 8 + 8)).map(fixture::row).collect())
                .collect::<Vec<_>>(),
        )
        .0
    }

    #[test]
    fn later_corruption_invalidates_the_whole_segment() {
        let data = valid_segment();
        let map = |event: EventView<'_>| event.to_owned().unwrap();
        let serial = decode_segment_mapped(&data, &Filter::new(), &map).unwrap();
        assert_eq!(
            serial.events.iter().map(|e| e.seq).collect::<Vec<_>>(),
            (1..=40).collect::<Vec<_>>()
        );
        assert!(serial.dropped.is_empty());
        let reader = SegmentReader::open(&data).unwrap();
        let last = reader.blocks().last().unwrap().offset as usize + 8;
        let mut corrupt = data;
        corrupt[last..last + 4].fill(0);
        assert!(decode_segment_mapped(&corrupt, &Filter::new(), &map).is_err());
    }

    #[test]
    fn cancellation_returns_without_deliverable_prefix() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = AtomicBool::new(false);
        let data = valid_segment();
        let bytes = data.as_slice();
        let result = decode_segment_mapped_cancellable(
            bytes,
            &Filter::new(),
            &|_| {
                stop.store(true, Ordering::Relaxed);
            },
            || stop.load(Ordering::Relaxed),
        );
        assert!(matches!(result, Err(Error::Canceled)));
    }
    #[test]
    fn worker_partitions_preserve_order_values_and_whole_segment_failure() {
        let mut blocks: Vec<Vec<_>> = (0..5)
            .map(|b| ((b * 8 + 1)..=(b * 8 + 8)).map(fixture::row).collect())
            .collect();
        blocks[1][2].did = b"invalid".to_vec();
        blocks[3][0].rev = b"invalid".to_vec();
        let data = fixture::seal(&blocks).0;
        let bytes = data.as_slice();
        let map = |event: EventView<'_>| format!("{:?}", event.to_owned().unwrap());
        let serial = decode_segment_mapped(bytes, &Filter::new(), &map).unwrap();
        assert_eq!(serial.events.len(), 38);
        assert_eq!(serial.dropped.len(), 2);
        let expected: Vec<_> = serial.events.iter().map(|e| (e.seq, &e.value)).collect();
        for workers in [1, 2, 3, 32] {
            let parallel =
                decode_segment_workers(bytes, &Filter::new(), &map, || false, workers).unwrap();
            assert_eq!(
                serial
                    .dropped
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>(),
                parallel
                    .dropped
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                expected,
                parallel
                    .events
                    .iter()
                    .map(|e| (e.seq, &e.value))
                    .collect::<Vec<_>>()
            );
        }
        let reader = SegmentReader::open(bytes).unwrap();
        let last = reader.blocks().last().unwrap().offset as usize + 8;
        let mut corrupt = bytes.to_vec();
        corrupt[last..last + 4].fill(0);
        let error = decode_segment_mapped(&corrupt, &Filter::new(), &map)
            .unwrap_err()
            .to_string();
        for workers in [2, 3, 32] {
            assert_eq!(
                decode_segment_workers(&corrupt, &Filter::new(), &map, || false, workers)
                    .unwrap_err()
                    .to_string(),
                error
            );
        }
    }

    #[test]
    fn worker_cancellation_returns_without_deliverable_prefix() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let stop = AtomicBool::new(false);
        let data = valid_segment();
        let bytes = data.as_slice();
        let result = decode_segment_workers(
            bytes,
            &Filter::new(),
            &|_| {
                stop.store(true, Ordering::Relaxed);
            },
            || stop.load(Ordering::Relaxed),
            2,
        );
        assert!(matches!(result, Err(Error::Canceled)));
    }
    #[test]
    fn empty_parallel_segment_observes_cancellation() {
        let data = fixture::seal(&[]).0;
        for workers in [1, 2, 32] {
            assert!(
                decode_segment_workers(&data, &Filter::new(), &|_| (), || false, workers)
                    .unwrap()
                    .events
                    .is_empty()
            );
            assert!(matches!(
                decode_segment_workers(&data, &Filter::new(), &|_| (), || true, workers),
                Err(Error::Canceled)
            ));
        }
    }
}
