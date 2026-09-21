#![no_main]
//! Full sealed-segment decode over arbitrary bytes must never panic. This is
//! the top-level replay entry point: header parse, checksum, block-index decode
//! and offset validation, per-block decompression, columnar decode, and typed
//! event conversion — all driven from one hostile buffer under a filter.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{
    Event, EventPayload, Filter, decode_segment_filtered, decode_segment_mapped,
};

fn signature(event: &Event) -> (String, Option<Vec<u8>>) {
    let bytes = match &event.payload {
        EventPayload::Commit(c) => c.record.as_ref().map(|r| r.as_cbor().to_vec()),
        _ => None,
    };
    (format!("{event:?}"), bytes)
}

fn compare(data: &[u8]) {
    for filter in [
        Filter::new(),
        Filter::new().collection("app.bsky.feed.like").unwrap(),
    ] {
        let owned = decode_segment_filtered(data, &filter);
        let mapped = decode_segment_mapped(data, &filter, &|e| e.to_owned().unwrap());
        match (owned, mapped) {
            (Ok(owned), Ok(mapped)) => {
                assert_eq!(
                    owned.events.iter().map(signature).collect::<Vec<_>>(),
                    mapped
                        .events
                        .iter()
                        .map(|e| signature(&e.value))
                        .collect::<Vec<_>>()
                );
                assert_eq!(
                    owned
                        .dropped
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>(),
                    mapped
                        .dropped
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                );
            }
            (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
            _ => panic!("owned and scoped segment decoders disagree"),
        }
    }
}

fuzz_target!(|data: &[u8]| {
    compare(data);
    // Also reach footer/index/row validation after mutations covered by the
    // checksum. The original bytes above still exercise checksum rejection.
    if let Ok(header) = shrike::jetstream::SealedHeader::parse(data)
        && let Err(shrike::jetstream::Error::ChecksumMismatch { computed, .. }) =
            header.verify_checksum(data)
    {
        let mut repaired = data.to_vec();
        repaired[4..12].copy_from_slice(&computed.to_le_bytes());
        compare(&repaired);
    }
});
