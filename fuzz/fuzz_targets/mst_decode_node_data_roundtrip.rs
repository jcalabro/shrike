#![no_main]
//! Any block that `decode_node_data` accepts must re-encode and re-decode to a
//! structurally identical node (decode → encode → decode is stable). Catches
//! canonicalization drift in the node codec.

use libfuzzer_sys::fuzz_target;
use shrike::mst::node::{decode_node_data, encode_node_data};

fuzz_target!(|data: &[u8]| {
    let Ok(nd) = decode_node_data(data) else {
        return;
    };
    let encoded = encode_node_data(&nd).expect("re-encode of a decoded node must succeed");
    let nd2 = decode_node_data(&encoded).expect("re-decode of re-encoded node must succeed");

    assert_eq!(nd.left, nd2.left, "left CID mismatch after round-trip");
    assert_eq!(
        nd.entries.len(),
        nd2.entries.len(),
        "entry count mismatch after round-trip"
    );
    for (e1, e2) in nd.entries.iter().zip(nd2.entries.iter()) {
        assert_eq!(e1.prefix_len, e2.prefix_len, "prefix_len mismatch");
        assert_eq!(e1.key_suffix, e2.key_suffix, "key_suffix mismatch");
        assert_eq!(e1.value, e2.value, "value CID mismatch");
        assert_eq!(e1.right, e2.right, "right CID mismatch");
    }
});
