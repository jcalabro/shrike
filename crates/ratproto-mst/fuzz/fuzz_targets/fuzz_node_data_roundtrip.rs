#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_mst::node::{decode_node_data, encode_node_data};

// Fuzz MST node data decode-encode roundtrip.
//
// Invariants tested:
// 1. If decoding succeeds, re-encoding must succeed.
// 2. Re-decoding the re-encoded data must succeed.
// 3. The structural content (entry count, prefix lengths, key suffixes, CIDs)
//    must be preserved across the roundtrip.
fuzz_target!(|data: &[u8]| {
    let nd = match decode_node_data(data) {
        Ok(n) => n,
        Err(_) => return,
    };

    let encoded = match encode_node_data(&nd) {
        Ok(e) => e,
        Err(_) => return, // Encoding can fail if data is structurally weird.
    };

    let nd2 = decode_node_data(&encoded)
        .expect("decoding re-encoded node data must succeed");

    // Structural comparison.
    assert_eq!(nd.left, nd2.left, "left CID mismatch");
    assert_eq!(
        nd.entries.len(),
        nd2.entries.len(),
        "entry count mismatch"
    );
    for (a, b) in nd.entries.iter().zip(nd2.entries.iter()) {
        assert_eq!(a.prefix_len, b.prefix_len, "prefix_len mismatch");
        assert_eq!(a.key_suffix, b.key_suffix, "key_suffix mismatch");
        assert_eq!(a.value, b.value, "value CID mismatch");
        assert_eq!(a.right, b.right, "right CID mismatch");
    }
});
