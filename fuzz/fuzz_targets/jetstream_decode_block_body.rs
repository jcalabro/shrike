#![no_main]
//! The columnar block-body decoder runs directly on attacker-controlled,
//! already-decompressed bytes (the count header, the per-event fixed columns,
//! and the variable-length blob region). It must never panic on any of them —
//! every length and offset is derived from the input, so the checked arithmetic
//! and bounds guards are what this target stresses.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::decode_block;

fuzz_target!(|data: &[u8]| {
    let _ = decode_block(data);
});
