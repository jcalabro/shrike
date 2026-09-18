#![no_main]
//! Full sealed-segment decode over arbitrary bytes must never panic. This is
//! the top-level replay entry point: header parse, checksum, block-index decode
//! and offset validation, per-block decompression, columnar decode, and typed
//! event conversion — all driven from one hostile buffer under a filter.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{Filter, decode_segment_filtered};

fuzz_target!(|data: &[u8]| {
    let filter = Filter::new();
    let _ = decode_segment_filtered(data, &filter);
});
