#![no_main]
//! Encoder/decoder agreement on STRUCTURED input. We build an arbitrary value
//! tree, encode it, and require:
//!   1. `encode_value` and `encode_value_into` agree with a reference encoder
//!      built on `Encoder` (the same bytes, or the same error),
//!   2. when the tree is DRISL-legal (finite floats), encode succeeds,
//!   3. decoding the bytes succeeds,
//!   4. re-encoding the decoded value reproduces identical bytes (the encoding
//!      is canonical and the decode→encode round-trip is a fixed point).
//!
//! Maps come in canonical key order or in arbitrary order, and floats may be
//! NaN or infinite, so both of `encode_value`'s passes run.
//!
//! Using structured generation (instead of random bytes) means the fuzzer
//! spends its budget exploring real value shapes — deep nesting, many map keys,
//! boundary integers/strings — rather than bouncing off the decoder's header
//! checks. This is the strongest oracle for the encoder.
//!
//! `Value<'a>` borrows its text/bytes, so we own all leaf data in a `bumpalo`
//! arena that lives for the whole call (no leaks — important under
//! LeakSanitizer).

use arbitrary::Arbitrary;
use bumpalo::Bump;
use libfuzzer_sys::fuzz_target;
use shrike::cbor::value::Value;
use shrike::cbor::{
    CborError, Codec, Encoder, cbor_key_cmp, decode, encode_value, encode_value_into,
};

#[derive(Arbitrary, Debug)]
enum Gen {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Bool(bool),
    Null,
    Text(String),
    Bytes(Vec<u8>),
    Cid(bool, Vec<u8>),
    Array(Vec<Gen>),
    /// Entries, and whether to put them in canonical key order.
    Map(Vec<(String, Gen)>, bool),
}

fn build<'a>(g: &Gen, arena: &'a Bump, depth: usize) -> Value<'a> {
    if depth > 30 {
        return Value::Null;
    }
    match g {
        // AT Protocol integers are signed 64-bit (decoder rejects u64 > i64::MAX).
        Gen::Unsigned(n) => Value::Unsigned(n & (i64::MAX as u64)),
        Gen::Signed(n) => {
            if *n >= 0 {
                Value::Unsigned(*n as u64)
            } else {
                Value::Signed(*n)
            }
        }
        Gen::Float(f) => Value::Float(*f),
        Gen::Bool(b) => Value::Bool(*b),
        Gen::Null => Value::Null,
        Gen::Text(s) => Value::Text(arena.alloc_str(s)),
        Gen::Bytes(b) => Value::Bytes(arena.alloc_slice_copy(b)),
        Gen::Cid(raw, content) => {
            let codec = if *raw { Codec::Raw } else { Codec::Drisl };
            Value::Cid(shrike::cbor::Cid::compute(codec, content))
        }
        Gen::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(build(it, arena, depth + 1));
            }
            Value::Array(out)
        }
        Gen::Map(entries, canonical) => {
            let mut seen = std::collections::HashSet::new();
            let mut out: Vec<(&'a str, Value<'a>)> = Vec::new();
            for (k, v) in entries {
                if !seen.insert(k.clone()) {
                    continue;
                }
                let key: &'a str = arena.alloc_str(k);
                out.push((key, build(v, arena, depth + 1)));
            }
            if *canonical {
                out.sort_by(|a, b| cbor_key_cmp(a.0, b.0));
            }
            Value::Map(out)
        }
    }
}

/// Encode through `Encoder`, each map's keys sorted: what `encode_value`
/// must produce.
fn reference(enc: &mut Encoder<&mut Vec<u8>>, value: &Value) -> Result<(), CborError> {
    match value {
        Value::Unsigned(n) => enc.encode_u64(*n),
        Value::Signed(n) => enc.encode_i64(*n),
        Value::Float(f) => enc.encode_f64(*f),
        Value::Bool(b) => enc.encode_bool(*b),
        Value::Null => enc.encode_null(),
        Value::Text(s) => enc.encode_text(s),
        Value::Bytes(b) => enc.encode_bytes(b),
        Value::Cid(c) => enc.encode_cid(c),
        Value::Array(items) => {
            enc.encode_array_header(items.len() as u64)?;
            items.iter().try_for_each(|item| reference(enc, item))
        }
        Value::Map(entries) => {
            enc.encode_map_header(entries.len() as u64)?;
            let mut sorted: Vec<_> = entries.iter().collect();
            sorted.sort_by(|a, b| cbor_key_cmp(a.0, b.0));
            for (key, value) in sorted {
                enc.encode_text(key)?;
                reference(enc, value)?;
            }
            Ok(())
        }
    }
}

fn has_non_finite(value: &Value) -> bool {
    match value {
        Value::Float(f) => !f.is_finite(),
        Value::Array(items) => items.iter().any(has_non_finite),
        Value::Map(entries) => entries.iter().any(|(_, v)| has_non_finite(v)),
        _ => false,
    }
}

fuzz_target!(|g: Gen| {
    let arena = Bump::new();
    let value = build(&g, &arena, 0);

    let mut want = vec![0xaa];
    let want_result = reference(&mut Encoder::new(&mut want), &value).map_err(|e| e.to_string());
    let mut buf = vec![0xaa];
    let result = encode_value_into(&value, &mut buf).map_err(|e| e.to_string());
    assert_eq!(
        result, want_result,
        "encode_value_into and the reference disagree"
    );
    assert_eq!(
        buf, want,
        "encode_value_into and the reference wrote different bytes"
    );
    let encoded = encode_value(&value).map_err(|e| e.to_string());
    assert_eq!(
        encoded.as_ref().map(|_| ()),
        want_result.as_ref().map(|_| ())
    );
    assert_eq!(
        encoded.is_err(),
        has_non_finite(&value),
        "only non-finite floats fail"
    );
    let Ok(encoded) = encoded else {
        return;
    };
    assert_eq!(
        encoded,
        want[1..],
        "encode_value and the reference disagree"
    );
    let decoded = decode(&encoded).expect("encoder output must be decodable");
    let re_encoded = encode_value(&decoded).expect("re-encode must succeed");
    assert_eq!(
        encoded, re_encoded,
        "decode→encode is not a fixed point (non-canonical encoding)"
    );
});
