//! `decode_label` must never panic on arbitrary bytes. Any label it accepts
//! must re-encode (`encode_label`) and re-decode to an equal label, and its
//! `unsigned_label_bytes` must be deterministic — guarding the label CBOR
//! field-ordering / `ver`/`neg`/`cid` encoding that interop depends on.
#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike::labeling::{decode_label, encode_label, unsigned_label_bytes};

fuzz_target!(|data: &[u8]| {
    let Ok(label) = decode_label(data) else {
        return;
    };

    // unsigned bytes must be deterministic.
    let u1 = unsigned_label_bytes(&label).expect("unsigned_label_bytes");
    let u2 = unsigned_label_bytes(&label).expect("unsigned_label_bytes");
    assert_eq!(u1, u2, "unsigned_label_bytes is non-deterministic");

    // Full encode → decode → encode is a fixed point.
    let encoded = encode_label(&label).expect("encode_label of a decoded label");
    let label2 = decode_label(&encoded).expect("re-decode of encoded label");
    let encoded2 = encode_label(&label2).expect("re-encode");
    assert_eq!(
        encoded, encoded2,
        "label encode/decode is not a fixed point"
    );
});
