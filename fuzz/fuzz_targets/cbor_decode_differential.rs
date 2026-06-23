#![no_main]
//! Differential oracle: the two DRISL decode paths — the standard
//! `decode` (heap `Value`) and the bump-allocated `decode_bump` (the path the
//! firehose hot loop uses) — MUST agree on every input: both accept with an
//! identical structure, or both reject. A divergence is a real bug (this is
//! exactly the class of the H1 silent-truncation defect).

use bumpalo::Bump;
use libfuzzer_sys::fuzz_target;
use shrike::cbor::value::Value;
use shrike::cbor::{BumpValue, Decoder};

/// Structural equality between a heap `Value` and a bump `BumpValue`.
fn eq(v: &Value, b: &BumpValue) -> bool {
    match (v, b) {
        (Value::Unsigned(a), BumpValue::Unsigned(c)) => a == c,
        (Value::Signed(a), BumpValue::Signed(c)) => a == c,
        // Compare floats by bit pattern (NaN is rejected by the decoder, but be
        // exact regardless).
        (Value::Float(a), BumpValue::Float(c)) => a.to_bits() == c.to_bits(),
        (Value::Bool(a), BumpValue::Bool(c)) => a == c,
        (Value::Null, BumpValue::Null) => true,
        (Value::Text(a), BumpValue::Text(c)) => a == c,
        (Value::Bytes(a), BumpValue::Bytes(c)) => a == c,
        (Value::Cid(a), BumpValue::Cid(c)) => a == c,
        (Value::Array(a), BumpValue::Array(c)) => {
            a.len() == c.len() && a.iter().zip(c.iter()).all(|(x, y)| eq(x, y))
        }
        (Value::Map(a), BumpValue::Map(c)) => {
            a.len() == c.len()
                && a.iter()
                    .zip(c.iter())
                    .all(|((ka, va), (kb, vb))| ka == kb && eq(va, vb))
        }
        _ => false,
    }
}

fn decode_std(data: &[u8]) -> Option<Value<'_>> {
    let mut dec = Decoder::new(data);
    let v = dec.decode().ok()?;
    // Require full consumption to match the top-level `decode()` contract.
    if dec.is_empty() { Some(v) } else { None }
}

fuzz_target!(|data: &[u8]| {
    let std = decode_std(data);

    let bump = Bump::new();
    let mut dec = Decoder::new(data);
    let bump_val = dec
        .decode_bump(&bump)
        .ok()
        .and_then(|v| if dec.is_empty() { Some(v) } else { None });

    match (&std, &bump_val) {
        (Some(v), Some(b)) => {
            assert!(
                eq(v, b),
                "decode and decode_bump produced different structures for the same input"
            );
        }
        (None, None) => {}
        (s, _) => panic!(
            "decode/decode_bump disagree on acceptance: standard_ok={}, bump_ok={}",
            s.is_some(),
            bump_val.is_some()
        ),
    }
});
