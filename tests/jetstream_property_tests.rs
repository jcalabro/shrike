//! Property tests for the Jetstream v2 segment codec.
//!
//! Two invariants matter enough to fuzz across many random inputs:
//!
//! 1. **Overflow-free layout.** The block-index decode and layout/geometry
//!    validators use checked arithmetic throughout; no combination of header
//!    offsets, block counts, or index entries — however hostile — may panic.
//!    They must always return a `Result`.
//! 2. **Filter equivalence.** Filtering on the raw columns before conversion
//!    (`Filter::matches_segment`, the fast path the decoder takes) must select
//!    exactly the same events, in the same order, as converting every row and
//!    then filtering the typed events (`Filter::matches`). The two filter
//!    surfaces must never disagree.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;

use shrike::api::com::atproto::SyncSubscribeReposIdentity;
use shrike::jetstream::{
    BlockIndexEntry, Event, Filter, Kind, RawEvent, SealedHeader, SegmentKind, decode_block_index,
    raw_event_to_event, record_json_to_dag_cbor, validate_block_offsets,
};
use shrike::syntax::{Datetime, Did, Handle};

const DID_A: &str = "did:plc:abcdefghijklmnopqrstuvwx";
const DID_B: &str = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz";
const REV: &str = "3l3qo2vutsw2b";
const RKEY: &str = "3l3qo2vuowo2b";
const TIME: &str = "2024-01-01T00:00:00.000000Z";

// A pool of DID column values, mixing valid and invalid so both the
// filter-admits and conversion-drops branches are exercised.
const DIDS: &[&str] = &[DID_A, DID_B, "not-a-did", ""];
// A pool of collection column values, mixing valid NSIDs, an empty column
// (DID-level / v1-parity bypass), and a syntactically invalid value.
const COLLECTIONS: &[&str] = &[
    "app.bsky.feed.post",
    "app.bsky.feed.like",
    "APP.BSKY.FEED.post",
    "app.bsky.feed.Post",
    "app.bsky.graph.follow",
    "",
    "not an nsid",
];

fn feed_post_cbor() -> Vec<u8> {
    record_json_to_dag_cbor(&serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "hello",
        "createdAt": TIME,
    }))
    .expect("canonicalize record")
}

fn identity_cbor() -> Vec<u8> {
    SyncSubscribeReposIdentity {
        did: Did::try_from(DID_A).unwrap(),
        handle: Some(Handle::try_from("alice.test").unwrap()),
        seq: 1,
        time: Datetime::try_from(TIME).unwrap(),
        extra: std::collections::HashMap::new(),
        extra_cbor: Vec::new(),
    }
    .to_cbor()
    .expect("encode identity")
}

/// Build a `RawEvent` from column choices. Commit kinds get a valid record
/// payload (create) or empty (delete); the identity kind gets a valid CBOR body.
fn make_row(seq: u64, kind: u8, did: &str, collection: &str) -> RawEvent {
    let segment_kind = SegmentKind::from_u8(kind).expect("valid kind");
    let (rkey, rev, payload) = match segment_kind {
        SegmentKind::Delete => (
            RKEY.as_bytes().to_vec(),
            REV.as_bytes().to_vec(),
            Vec::new(),
        ),
        SegmentKind::Create | SegmentKind::Update | SegmentKind::CreateResync => (
            RKEY.as_bytes().to_vec(),
            REV.as_bytes().to_vec(),
            feed_post_cbor(),
        ),
        // DID-level kinds carry no commit columns.
        SegmentKind::Identity | SegmentKind::Account | SegmentKind::Sync => {
            (Vec::new(), Vec::new(), identity_cbor())
        }
    };
    // DID-level rows never carry a collection.
    let collection = match segment_kind {
        SegmentKind::Identity | SegmentKind::Account | SegmentKind::Sync => Vec::new(),
        _ => collection.as_bytes().to_vec(),
    };
    RawEvent {
        seq,
        witnessed_at: seq as i64 * 100,
        indexed_at: 0,
        kind: segment_kind,
        collection,
        did: did.as_bytes().to_vec(),
        rkey,
        rev,
        payload,
    }
}

/// A projection that identifies an event for order-sensitive comparison without
/// requiring `Event: PartialEq`.
fn project(e: &Event) -> (u64, u8, String) {
    let kind = match e.kind() {
        Kind::Commit => 0,
        Kind::Identity => 1,
        Kind::Account => 2,
        Kind::Sync => 3,
    };
    (e.seq, kind, e.did.as_str().to_owned())
}

// Strategy: a row spec is (kind-choice, did-index, collection-index). Only the
// three filter-distinct kinds are generated (create commit with a record, delete
// commit without one, and a DID-level identity).
fn row_spec() -> impl Strategy<Value = (u8, usize, usize)> {
    (
        prop_oneof![Just(1u8), Just(3u8), Just(4u8)],
        0..DIDS.len(),
        0..COLLECTIONS.len(),
    )
}

// Strategy: an arbitrary filter over the same DID/collection pools.
fn filter_strategy() -> impl Strategy<Value = Filter> {
    (
        any::<bool>(), // want commit
        any::<bool>(), // want identity
        any::<bool>(), // constrain to DID_A
        prop_oneof![
            Just(None),
            Just(Some("app.bsky.feed.post")),
            Just(Some("app.bsky.feed.*")),
            Just(Some("app.bsky.graph.follow")),
        ],
    )
        .prop_map(|(commit, identity, did_a, collection)| {
            let mut kinds = Vec::new();
            if commit {
                kinds.push(Kind::Commit);
            }
            if identity {
                kinds.push(Kind::Identity);
            }
            let mut f = Filter::new();
            if !kinds.is_empty() {
                f = f.kinds(kinds);
            }
            if did_a {
                f = f.did(DID_A).expect("valid did");
            }
            if let Some(c) = collection {
                f = f.collection(c).expect("valid collection");
            }
            f
        })
}

proptest! {
    #[test]
    fn raw_exact_collections_agree_with_validating_parser(
        raw in prop_oneof![
            ".{0,350}",
            "[aA][pP][pP]\\.[bB][sS][kK][yY]\\.[fF][eE][eE][dD]\\.(like|Like|post|POST)",
        ],
    ) {
        let filter = Filter::new().collections(["app.bsky.feed.like", "app.bsky.feed.post"]).unwrap();
        let expected = raw.is_empty() || shrike::syntax::Nsid::try_from(raw.as_str())
            .is_ok_and(|n| matches!(n.as_str(), "app.bsky.feed.like" | "app.bsky.feed.post"));
        prop_assert_eq!(filter.matches_segment(Kind::Commit, DID_A, &raw), expected);
    }

    /// Layout/geometry validation and block-index decode never panic, whatever
    /// the header offsets, declared block count, or raw footer bytes.
    #[test]
    fn layout_validation_never_panics(
        block_count in any::<u32>(),
        footer_offset in any::<u64>(),
        did_bloom_offset in any::<u64>(),
        block_did_bloom_offset in any::<u64>(),
        collection_index_offset in any::<u64>(),
        block_index_offset in any::<u64>(),
        file_len in any::<usize>(),
        footer in proptest::collection::vec(any::<u8>(), 0..512),
    ) {
        let header = SealedHeader {
            checksum: 1,
            version: 1,
            block_count,
            event_count: 0,
            unique_did_count: 0,
            min_seq: 0,
            max_seq: 0,
            min_witnessed_at: 0,
            max_witnessed_at: 0,
            footer_offset,
            did_bloom_offset,
            block_did_bloom_offset,
            collection_index_offset,
            block_index_offset,
        };
        // Must return, never panic (checked arithmetic throughout).
        let _ = header.validate_layout(file_len);
        let _ = decode_block_index(&header, &footer);
    }

    /// Block-offset validation never panics on arbitrary index entries — the
    /// frame-end and monotonicity checks are all overflow-safe.
    #[test]
    fn block_offset_validation_never_panics(
        footer_offset in any::<u64>(),
        entries in proptest::collection::vec(
            (any::<u64>(), any::<u32>(), any::<u32>(), any::<u64>(), any::<u64>()),
            0..32,
        ),
    ) {
        let header = SealedHeader {
            checksum: 1,
            version: 1,
            block_count: entries.len() as u32,
            event_count: 0,
            unique_did_count: 0,
            min_seq: 0,
            max_seq: 0,
            min_witnessed_at: 0,
            max_witnessed_at: 0,
            footer_offset,
            did_bloom_offset: footer_offset,
            block_did_bloom_offset: footer_offset,
            collection_index_offset: footer_offset,
            block_index_offset: footer_offset,
        };
        let blocks: Vec<BlockIndexEntry> = entries
            .into_iter()
            .map(|(offset, compressed, events, min_seq, max_seq)| BlockIndexEntry {
                offset,
                compressed_size: compressed,
                uncompressed_size: compressed,
                event_count: events,
                min_seq,
                max_seq,
                min_witnessed_at: 0,
                max_witnessed_at: 0,
            })
            .collect();
        let _ = validate_block_offsets(&header, &blocks);
    }

    /// Pre-conversion row filtering selects exactly the same events, in the same
    /// order, as converting all rows and then filtering the typed events.
    #[test]
    fn row_filter_equals_event_filter(
        specs in proptest::collection::vec(row_spec(), 0..24),
        filter in filter_strategy(),
    ) {
        let rows: Vec<RawEvent> = specs
            .iter()
            .enumerate()
            .map(|(i, &(kind, di, ci))| make_row(i as u64 + 1, kind, DIDS[di], COLLECTIONS[ci]))
            .collect();

        // Subject: mirror `convert_rows` — filter on raw columns, then convert.
        let got: Vec<(u64, u8, String)> = rows
            .iter()
            .filter(|r| {
                let did = std::str::from_utf8(&r.did).unwrap_or("");
                let collection = std::str::from_utf8(&r.collection).unwrap_or("");
                filter.matches_segment(r.kind.public_kind(), did, collection)
            })
            .cloned()
            .filter_map(|r| raw_event_to_event(r).ok())
            .map(|e| project(&e))
            .collect();

        // Reference: convert everything, then filter the typed events.
        let want: Vec<(u64, u8, String)> = rows
            .iter()
            .cloned()
            .filter_map(|r| raw_event_to_event(r).ok())
            .filter(|e| filter.matches(e))
            .map(|e| project(&e))
            .collect();

        prop_assert_eq!(got, want);
    }
}
