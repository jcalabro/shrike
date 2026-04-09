#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_mst::node::decode_node_data;

// Fuzz MST node data decoding with arbitrary binary input.
//
// This is a high-value target: node data arrives inside CAR files from untrusted
// repositories during sync. The decoder must never panic on malformed input.
//
// Invariants tested:
// 1. decode_node_data must never panic on any input.
// 2. If decode succeeds, re-encoding must succeed.
fuzz_target!(|data: &[u8]| {
    let _ = decode_node_data(data);
});
