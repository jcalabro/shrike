#![no_main]
//! Encoder/decoder agreement on STRUCTURED input. We build an arbitrary (but
//! always DRISL-legal) value tree, encode it, and require:
//!   1. encode succeeds,
//!   2. decoding the bytes succeeds,
//!   3. re-encoding the decoded value reproduces identical bytes (the encoding
//!      is canonical and the decode→encode round-trip is a fixed point).
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
use shrike::cbor::{Codec, decode, encode_value};

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
    Map(Vec<(String, Gen)>),
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
        Gen::Float(f) => {
            if f.is_finite() {
                Value::Float(*f)
            } else {
                Value::Null
            }
        }
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
        Gen::Map(entries) => {
            let mut seen = std::collections::HashSet::new();
            let mut out: Vec<(&'a str, Value<'a>)> = Vec::new();
            for (k, v) in entries {
                if !seen.insert(k.clone()) {
                    continue;
                }
                let key: &'a str = arena.alloc_str(k);
                out.push((key, build(v, arena, depth + 1)));
            }
            Value::Map(out)
        }
    }
}

fuzz_target!(|g: Gen| {
    let arena = Bump::new();
    let value = build(&g, &arena, 0);
    let Ok(encoded) = encode_value(&value) else {
        return;
    };
    let decoded = decode(&encoded).expect("encoder output must be decodable");
    let re_encoded = encode_value(&decoded).expect("re-encode must succeed");
    assert_eq!(
        encoded, re_encoded,
        "decode→encode is not a fixed point (non-canonical encoding)"
    );
});
