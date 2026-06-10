#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)]

mod support;

use shrike::cbor::{Cid, Codec};
use shrike::sync::raw::parse_raw_sync_frame;

#[test]
fn raw_commit_preserves_sync_1_1_fields() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let commit_cid = Cid::compute(Codec::Drisl, b"commit");
    let record_cid = Cid::compute(Codec::Drisl, b"record");
    let prev_cid = Cid::compute(Codec::Drisl, b"prev-record");
    let prev_data = Cid::compute(Codec::Drisl, b"prev-data");
    let blob_cid = Cid::compute(Codec::Drisl, b"blob");
    let frame = support::sync1::commit_frame_with_since_and_flags(
        &did,
        "3zzzzzzzzzzzz",
        "3yyyyyyyyyyyy",
        42,
        commit_cid,
        prev_data,
        b"fake-car",
        true,
        true,
        vec![support::sync1::raw_op(
            "update",
            "app.bsky.feed.post/abc",
            Some(record_cid),
            Some(prev_cid),
        )],
    );

    let event = parse_raw_sync_frame(&frame).unwrap();
    let commit = event.into_commit().unwrap();

    assert_eq!(commit.repo, did);
    assert_eq!(commit.rev.to_string(), "3zzzzzzzzzzzz");
    assert_eq!(commit.seq, 42);
    assert_eq!(commit.time, "2026-06-09T15:00:00.000Z");
    assert_eq!(
        commit.since.as_ref().map(ToString::to_string).as_deref(),
        Some("3yyyyyyyyyyyy")
    );
    assert_eq!(commit.commit, commit_cid);
    assert_eq!(commit.prev_data, Some(prev_data));
    assert_eq!(commit.blocks, b"fake-car");
    assert_eq!(commit.blobs, vec![blob_cid]);
    assert!(commit.too_big);
    assert!(commit.rebase);
    assert_eq!(commit.ops.len(), 1);
    assert_eq!(commit.ops[0].action, "update");
    assert_eq!(commit.ops[0].path, "app.bsky.feed.post/abc");
    assert_eq!(commit.ops[0].cid, Some(record_cid));
    assert_eq!(commit.ops[0].prev, Some(prev_cid));
}

#[test]
fn raw_sync_preserves_commit_car_bytes() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::sync_frame(&did, "3zzzzzzzzzzzz", 77, b"sync-car");

    let event = parse_raw_sync_frame(&frame).unwrap();
    let sync = event.into_sync().unwrap();

    assert_eq!(sync.did, did);
    assert_eq!(sync.rev, "3zzzzzzzzzzzz");
    assert_eq!(sync.seq, 77);
    assert_eq!(sync.blocks, b"sync-car");
}

#[test]
fn raw_account_preserves_status_and_time() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::account_frame(
        &did,
        88,
        false,
        Some("takendown"),
        "2026-06-09T15:00:00.000Z",
    );

    let event = parse_raw_sync_frame(&frame).unwrap();
    let account = event.into_account().unwrap();

    assert_eq!(account.did, did);
    assert_eq!(account.seq, 88);
    assert!(!account.active);
    assert_eq!(account.status.as_deref(), Some("takendown"));
    assert_eq!(account.time, "2026-06-09T15:00:00.000Z");
}

#[test]
fn raw_identity_preserves_handle_and_time() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame =
        support::sync1::identity_frame(&did, 89, Some("example.com"), "2026-06-09T15:01:00.000Z");

    let event = parse_raw_sync_frame(&frame).unwrap();
    assert!(matches!(event, shrike::sync::RawSyncEvent::Identity(_)));
    let shrike::sync::RawSyncEvent::Identity(identity) = event else {
        return;
    };

    assert_eq!(identity.did, did);
    assert_eq!(identity.seq, 89);
    assert_eq!(
        identity.handle.as_ref().map(|h| h.as_str()),
        Some("example.com")
    );
    assert_eq!(identity.time, "2026-06-09T15:01:00.000Z");
}

#[test]
fn raw_commit_treats_missing_optional_links_as_absent() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_without_optional_links(&did, false);

    let commit = parse_raw_sync_frame(&frame).unwrap().into_commit().unwrap();

    assert_eq!(commit.since, None);
    assert_eq!(commit.prev_data, None);
    assert_eq!(commit.ops.len(), 1);
    assert_eq!(commit.ops[0].prev, None);
}

#[test]
fn raw_commit_treats_null_optional_links_as_absent() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_without_optional_links(&did, true);

    let commit = parse_raw_sync_frame(&frame).unwrap().into_commit().unwrap();

    assert_eq!(commit.since, None);
    assert_eq!(commit.prev_data, None);
    assert_eq!(commit.ops.len(), 1);
    assert_eq!(commit.ops[0].prev, None);
}

#[test]
fn raw_parser_ignores_unknown_fields() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_with_unknown_fields(&did);

    let commit = parse_raw_sync_frame(&frame).unwrap().into_commit().unwrap();

    assert_eq!(commit.repo, did);
    assert_eq!(commit.ops.len(), 1);
    assert_eq!(commit.ops[0].path, "app.bsky.feed.post/abc");
}

#[test]
fn raw_parser_ignores_unknown_fields_on_non_commit_events() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();

    assert!(matches!(
        parse_raw_sync_frame(&support::sync1::sync_frame_with_unknown(&did)).unwrap(),
        shrike::sync::RawSyncEvent::Sync(_)
    ));
    assert!(matches!(
        parse_raw_sync_frame(&support::sync1::account_frame_with_unknown(&did)).unwrap(),
        shrike::sync::RawSyncEvent::Account(_)
    ));
    assert!(matches!(
        parse_raw_sync_frame(&support::sync1::identity_frame_with_unknown(&did)).unwrap(),
        shrike::sync::RawSyncEvent::Identity(_)
    ));
    assert_eq!(
        parse_raw_sync_frame(&support::sync1::info_frame_with_unknown()).unwrap(),
        shrike::sync::RawSyncEvent::Info
    );
}

#[test]
fn raw_identity_rejects_invalid_handle() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame =
        support::sync1::identity_frame(&did, 90, Some("not a handle"), "2026-06-09T15:01:00.000Z");

    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("handle"));
}

#[test]
fn raw_commit_rejects_wrong_since_type() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_with_bad_since_type(&did);
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("since"));
}

#[test]
fn raw_commit_rejects_wrong_prev_data_type() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_with_bad_prev_data_type(&did);
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("prevData"));
}

#[test]
fn raw_commit_rejects_wrong_op_prev_type() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let frame = support::sync1::commit_frame_with_bad_op_prev_type(&did);
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("prev"));
}

#[test]
fn raw_commit_rejects_wrong_blocks_type() {
    let frame = support::sync1::commit_frame_with_bad_blocks_type();
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("blocks"));
}

#[test]
fn raw_commit_rejects_missing_commit_cid() {
    let frame = support::sync1::commit_frame_without_commit();
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("commit"));
}

#[test]
fn raw_commit_rejects_missing_too_big() {
    let frame = support::sync1::commit_frame_without_bool("tooBig");
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("tooBig"));
}

#[test]
fn raw_commit_rejects_null_too_big() {
    let frame = support::sync1::commit_frame_with_null_bool("tooBig");
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("tooBig"));
}

#[test]
fn raw_commit_rejects_missing_rebase() {
    let frame = support::sync1::commit_frame_without_bool("rebase");
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("rebase"));
}

#[test]
fn raw_commit_rejects_null_rebase() {
    let frame = support::sync1::commit_frame_with_null_bool("rebase");
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("rebase"));
}

#[test]
fn raw_frame_rejects_trailing_garbage() {
    let mut frame = support::sync1::info_frame();
    frame.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let err = parse_raw_sync_frame(&frame).unwrap_err();
    assert!(err.to_string().contains("trailing"));
}

#[cfg(feature = "streaming")]
#[test]
fn streaming_reexports_raw_parser() {
    let frame = support::sync1::info_frame();
    let event = shrike::streaming::parse_raw_sync_frame(&frame).unwrap();
    assert_eq!(event, shrike::sync::RawSyncEvent::Info);
}
