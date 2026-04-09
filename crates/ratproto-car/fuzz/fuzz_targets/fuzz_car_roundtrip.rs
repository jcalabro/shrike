#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz CAR read-write roundtrip.
//
// Invariants tested:
// 1. read_all must never panic on any input.
// 2. If read_all succeeds, write_all -> read_all must produce identical blocks.
// 3. The second roundtrip (write -> read -> write) must be byte-identical.
fuzz_target!(|data: &[u8]| {
    let (roots, blocks) = match ratproto_car::read_all(data) {
        Ok(r) => r,
        Err(_) => return,
    };

    // Re-write the parsed blocks.
    let written = ratproto_car::write_all(&roots, &blocks)
        .expect("writing successfully-read blocks must not fail");

    // Re-read from the written bytes.
    let (roots2, blocks2) = ratproto_car::read_all(&written[..])
        .expect("reading re-written CAR must succeed");

    assert_eq!(roots.len(), roots2.len(), "root count mismatch");
    for (a, b) in roots.iter().zip(roots2.iter()) {
        assert_eq!(a, b, "root CID mismatch");
    }

    assert_eq!(blocks.len(), blocks2.len(), "block count mismatch");
    for (a, b) in blocks.iter().zip(blocks2.iter()) {
        assert_eq!(a.cid, b.cid, "block CID mismatch");
        assert_eq!(a.data, b.data, "block data mismatch");
    }

    // Second write must be byte-identical to the first.
    let written2 = ratproto_car::write_all(&roots2, &blocks2)
        .expect("second write must not fail");
    assert_eq!(
        written, written2,
        "CAR write stability violation: second write produced different bytes"
    );
});
