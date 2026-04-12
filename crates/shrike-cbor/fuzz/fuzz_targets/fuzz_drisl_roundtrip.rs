#![no_main]

use libfuzzer_sys::fuzz_target;

// Fuzz the DRISL CBOR codec with arbitrary binary input.
//
// Invariants tested:
// 1. Decode must never panic on any input.
// 2. If decode succeeds, re-encoding must produce identical bytes (deterministic).
// 3. Re-decoding the re-encoded bytes must also succeed.
fuzz_target!(|data: &[u8]| {
    let val = match shrike_cbor::decode(data) {
        Ok(v) => v,
        Err(_) => return, // Parse errors are expected on arbitrary input.
    };

    // Re-encode the decoded value.
    let encoded = shrike_cbor::encode_value(&val)
        .expect("re-encoding a successfully decoded value must not fail");

    // DRISL is deterministic: decode(data) -> encode -> must equal data.
    assert_eq!(
        data, &encoded[..],
        "DRISL determinism violation: decode + re-encode produced different bytes"
    );

    // Decode the re-encoded bytes — must also succeed and produce identical encoding.
    let val2 = shrike_cbor::decode(&encoded)
        .expect("decoding re-encoded DRISL must succeed");
    let encoded2 = shrike_cbor::encode_value(&val2)
        .expect("re-encoding round 2 must not fail");
    assert_eq!(
        encoded, encoded2,
        "DRISL stability violation: second roundtrip produced different bytes"
    );
});
