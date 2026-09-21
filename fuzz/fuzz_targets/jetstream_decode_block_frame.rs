#![no_main]
//! Decoding a raw `getBlock` zstd frame (no length prefix) over arbitrary bytes
//! must never panic: the bounded decompressor and the columnar block decoder
//! that runs on its output must both stay total. Also exercises the filtered
//! frame path, which folds the same decode into a filter+convert step.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{
    Event, EventPayload, Filter, decode_block_frame, decode_block_frame_filtered,
    raw_event_to_event,
};

fn signature(event: &Event) -> (String, Option<Vec<u8>>) {
    let bytes = match &event.payload {
        EventPayload::Commit(c) => c.record.as_ref().map(|r| r.as_cbor().to_vec()),
        _ => None,
    };
    (format!("{event:?}"), bytes)
}

fuzz_target!(|data: &[u8]| {
    let owned = decode_block_frame(data);
    let borrowed = decode_block_frame_filtered(data, &Filter::new());
    match (owned, borrowed) {
        (Ok(rows), Ok(decoded)) => {
            let mut events = Vec::new();
            let mut dropped = Vec::new();
            for row in rows {
                match raw_event_to_event(row) {
                    Ok(event) => events.push(signature(&event)),
                    Err(err) => dropped.push(err.to_string()),
                }
            }
            assert_eq!(
                events,
                decoded.events.iter().map(signature).collect::<Vec<_>>()
            );
            assert_eq!(
                dropped,
                decoded
                    .dropped
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("owned and borrowed decoders disagree on structural validity"),
    }
});
