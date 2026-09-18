#![no_main]
//! Typed-event conversion (`raw_event_to_event`) runs on decoded segment rows
//! whose every column is attacker-controlled: it validates DID/collection/rkey
//! syntax, parses the payload as record or upstream-event CBOR per kind, and
//! rejects zero seqs. Feeding it arbitrary columns must never panic — only ever
//! yield an `Event` or an `Error`.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{RawEvent, SegmentKind, raw_event_to_event};

#[derive(Arbitrary, Debug)]
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

fuzz_target!(|row: Row| {
    // Map the byte into a valid wire code (1..=7); an out-of-range kind is a
    // decode-layer concern already covered by the block-body target.
    let Ok(kind) = SegmentKind::from_u8((row.kind % 7) + 1) else {
        return;
    };
    let raw = RawEvent {
        seq: row.seq,
        witnessed_at: row.witnessed_at,
        indexed_at: row.indexed_at,
        kind,
        collection: row.collection,
        did: row.did,
        rkey: row.rkey,
        rev: row.rev,
        payload: row.payload,
    };
    let _ = raw_event_to_event(raw);
});
