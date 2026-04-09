#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_cbor::varint;

// Fuzz unsigned varint decoding with arbitrary bytes.
//
// Invariants tested:
// 1. decode_varint must never panic on any input.
// 2. If decode succeeds, encode -> decode must produce the same value.
// 3. Bytes consumed must not exceed input length.
fuzz_target!(|data: &[u8]| {
    let (value, consumed) = match varint::decode_varint(data) {
        Ok(r) => r,
        Err(_) => return,
    };

    assert!(
        consumed <= data.len(),
        "varint consumed {consumed} bytes but input is only {} bytes",
        data.len()
    );

    // Roundtrip: encode the decoded value, then decode again.
    let mut buf = Vec::new();
    varint::encode_varint(value, &mut buf);
    let (roundtripped, consumed2) = varint::decode_varint(&buf)
        .expect("decoding re-encoded varint must succeed");
    assert_eq!(value, roundtripped, "varint roundtrip value mismatch");
    assert_eq!(
        consumed2,
        buf.len(),
        "varint roundtrip consumed wrong number of bytes"
    );
});
