#![no_main]
//! Decoding a raw `getBlock` zstd frame (no length prefix) over arbitrary bytes
//! must never panic: the bounded decompressor and the columnar block decoder
//! that runs on its output must both stay total. Also exercises the filtered
//! frame path, which folds the same decode into a filter+convert step.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{Filter, decode_block_frame, decode_block_frame_filtered};

fuzz_target!(|data: &[u8]| {
    let _ = decode_block_frame(data);
    let _ = decode_block_frame_filtered(data, &Filter::new());
});
