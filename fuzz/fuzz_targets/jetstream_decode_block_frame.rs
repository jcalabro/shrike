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
    let mapped = shrike::jetstream::decode_block_frame_mapped(data, &Filter::new(), &|event| {
        event.to_owned().unwrap()
    });
    match (&borrowed, &mapped) {
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
        _ => panic!("scoped and owned disagree"),
    }
    // Exercise exact-filter validation proofs against fully decoded raw rows.
    // Unlike a comparison of two filtered visitors, this oracle reads every
    // column and validates selected identifiers independently.
    let filter = Filter::new().collection("app.bsky.feed.like").unwrap();
    let selected =
        shrike::jetstream::decode_block_frame_mapped(data, &filter, &|e| e.to_owned().unwrap());
    match (&owned, selected) {
        (Ok(rows), Ok(selected)) => {
            let mut events = Vec::new();
            let mut errors = Vec::new();
            for row in rows {
                if !filter.matches_segment(
                    row.kind.public_kind(),
                    core::str::from_utf8(&row.did).unwrap_or(""),
                    core::str::from_utf8(&row.collection).unwrap_or(""),
                ) {
                    continue;
                }
                match raw_event_to_event(row.clone()) {
                    Ok(event) => events.push(signature(&event)),
                    Err(error) => errors.push(error.to_string()),
                }
            }
            assert_eq!(
                events,
                selected
                    .events
                    .iter()
                    .map(|e| signature(&e.value))
                    .collect::<Vec<_>>()
            );
            assert_eq!(
                errors,
                selected
                    .dropped
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
            );
        }
        (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string()),
        _ => panic!("selected and fully read rows disagree"),
    }
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
