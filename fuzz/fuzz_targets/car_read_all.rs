#![no_main]
//! The CAR v1 reader must never panic on arbitrary input (truncated frames,
//! oversized/non-minimal varints, malformed headers/CIDs) — only return Ok or
//! Err, with bounded memory.

use libfuzzer_sys::fuzz_target;
use shrike::car::read_all;

fuzz_target!(|data: &[u8]| {
    let _ = read_all(data);
});
