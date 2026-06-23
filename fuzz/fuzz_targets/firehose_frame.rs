#![no_main]
//! The firehose frame parsers must never panic on arbitrary bytes. Exercises
//! both the typed event parser (`parse_firehose_frame`, which also decodes the
//! embedded CAR of blocks and verifies block CIDs) and the lower-level raw
//! parser (`parse_raw_sync_frame`).

use libfuzzer_sys::fuzz_target;
use shrike::streaming::{parse_firehose_frame, parse_raw_sync_frame};

fuzz_target!(|data: &[u8]| {
    let _ = parse_firehose_frame(data);
    let _ = parse_raw_sync_frame(data);
});
