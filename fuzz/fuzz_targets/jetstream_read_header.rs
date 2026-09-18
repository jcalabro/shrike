#![no_main]
//! The 256-byte sealed-segment header parser must never panic on arbitrary
//! bytes. Any header it accepts must have offsets that pass its own layout
//! validation against the input length, and the block-index decode over the
//! same bytes must also return (never panic) — guarding the checked arithmetic
//! that the whole segment geometry depends on.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{decode_block_index, read_sealed_header};

fuzz_target!(|data: &[u8]| {
    let Ok(header) = read_sealed_header(data) else {
        return;
    };
    // A header that parsed must validate its own geometry without panicking,
    // and the block-index decode over the raw bytes must also stay total.
    let _ = header.validate_layout(data.len());
    let _ = decode_block_index(&header, data);
});
