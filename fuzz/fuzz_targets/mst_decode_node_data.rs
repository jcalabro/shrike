#![no_main]
//! Fuzz the specialized MST node decoder: `decode_node_data` must never panic
//! on arbitrary input — it may only return Ok or Err.

use libfuzzer_sys::fuzz_target;
use shrike::mst::node::decode_node_data;

fuzz_target!(|data: &[u8]| {
    let _ = decode_node_data(data);
});
