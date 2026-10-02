#![no_main]
//! The firehose frame parsers must never panic on arbitrary bytes. Exercises
//! both the typed event parser (`parse_firehose_frame`, which also decodes the
//! embedded CAR of blocks and verifies block CIDs) and the lower-level raw
//! parser (`parse_raw_sync_frame`).
//!
//! A commit the typed parser accepts must carry only records that hash to
//! their CIDs, and must agree with the raw parser's reading of the frame.

use libfuzzer_sys::fuzz_target;
use shrike::cbor::Cid;
use shrike::streaming::{Event, Operation, parse_firehose_frame, parse_raw_sync_frame};
use shrike::sync::RawSyncEvent;
use shrike::syntax::Nsid;

fuzz_target!(|data: &[u8]| {
    let event = parse_firehose_frame(data);
    let raw = parse_raw_sync_frame(data);
    let Ok(Event::Commit {
        did,
        rev,
        seq,
        operations,
    }) = event
    else {
        return;
    };
    for op in &operations {
        if let Operation::Create { cid, record, .. } | Operation::Update { cid, record, .. } = op {
            assert_eq!(
                Cid::compute(cid.codec(), record),
                *cid,
                "record does not hash to its CID"
            );
        }
    }

    let Ok(RawSyncEvent::Commit(raw)) = raw else {
        return;
    };
    assert_eq!((&raw.repo, raw.rev, raw.seq), (&did, rev, seq));
    assert_eq!(raw.ops.len(), operations.len());
    let (_, blocks) = shrike::car::read_all(&raw.blocks[..]).expect("typed parser read this CAR");
    for (raw_op, op) in raw.ops.iter().zip(&operations) {
        let (action, collection, rkey, record) = match op {
            Operation::Create {
                collection,
                rkey,
                cid,
                record,
            } => ("create", collection, rkey, Some((cid, record))),
            Operation::Update {
                collection,
                rkey,
                cid,
                record,
            } => ("update", collection, rkey, Some((cid, record))),
            Operation::Delete { collection, rkey } => ("delete", collection, rkey, None),
            Operation::Resync { .. } => panic!("firehose commits carry no resync ops"),
        };
        assert_eq!(raw_op.action, action);
        let (raw_collection, raw_rkey) =
            raw_op.path.split_once('/').expect("typed parser split it");
        assert_eq!(
            Nsid::try_from(raw_collection).ok().as_ref(),
            Some(collection)
        );
        assert_eq!(raw_rkey, rkey.as_str());
        if let Some((cid, record)) = record {
            assert_eq!(raw_op.cid.as_ref(), Some(cid));
            assert!(
                blocks.iter().any(|b| b.cid == *cid && b.data == *record),
                "record is not the block its CID names"
            );
        }
    }
});
