#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the CAR v1 reader with arbitrary binary input.
//
// This is a high-value target: CAR data arrives over the network from untrusted
// sources during repo sync. The reader must never panic on malformed input.
fuzz_target!(|data: &[u8]| {
    // Attempt to parse as a CAR file and read all blocks.
    // Any error is expected; panics are bugs.
    let _ = shrike_car::read_all(data);
});
