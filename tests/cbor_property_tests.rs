#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use data_encoding::BASE64_NOPAD;
use proptest::prelude::*;
use shrike::cbor::json::decode_base64;
use shrike::cbor::{
    CborError, Cid, Codec, Encoder, Value, cbor_key_cmp, decode, encode_value, encode_value_into,
};
use std::cmp::Ordering;

/// An owned value tree for `Value`s to borrow from.
#[derive(Debug, Clone)]
enum Tree {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Bool(bool),
    Null,
    Text(String),
    Bytes(Vec<u8>),
    Cid(Cid),
    Array(Vec<Tree>),
    Map(Vec<(String, Tree)>),
}

fn value(tree: &Tree) -> Value<'_> {
    match tree {
        Tree::Unsigned(n) => Value::Unsigned(*n),
        Tree::Signed(n) => Value::Signed(*n),
        Tree::Float(f) => Value::Float(*f),
        Tree::Bool(b) => Value::Bool(*b),
        Tree::Null => Value::Null,
        Tree::Text(s) => Value::Text(s),
        Tree::Bytes(b) => Value::Bytes(b),
        Tree::Cid(c) => Value::Cid(*c),
        Tree::Array(items) => Value::Array(items.iter().map(value).collect()),
        Tree::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, v)| (k.as_str(), value(v)))
                .collect(),
        ),
    }
}

/// Map keys that collide, share prefixes and lengths, cross the 24-byte
/// head boundary, and hold multi-byte UTF-8.
fn key() -> impl Strategy<Value = String> {
    prop_oneof![
        "[ab]{0,3}",
        "[a-z$]{1,12}",
        "app\\.bsky\\.[a-z]{1,3}",
        "x{20,28}[ab]?",
        "[aé☃]{1,4}",
    ]
}

/// Value trees whose maps are in canonical order about half the time, the
/// common case for decoded values, and otherwise in any order, perhaps
/// with duplicate keys. Some floats are not finite.
fn tree() -> impl Strategy<Value = Tree> {
    let float = prop_oneof![
        30 => any::<f64>().prop_filter("finite", |f| f.is_finite()),
        1 => prop_oneof![Just(f64::NAN), Just(f64::INFINITY), Just(f64::NEG_INFINITY)],
    ];
    let leaf = prop_oneof![
        any::<u64>().prop_map(Tree::Unsigned),
        any::<i64>().prop_map(Tree::Signed),
        float.prop_map(Tree::Float),
        any::<bool>().prop_map(Tree::Bool),
        Just(Tree::Null),
        ".{0,30}".prop_map(Tree::Text),
        prop::collection::vec(any::<u8>(), 0..300).prop_map(Tree::Bytes),
        (any::<bool>(), any::<[u8; 4]>()).prop_map(|(raw, data)| {
            Tree::Cid(Cid::compute(
                if raw { Codec::Raw } else { Codec::Drisl },
                &data,
            ))
        }),
    ];
    leaf.prop_recursive(5, 96, 10, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..10).prop_map(Tree::Array),
            (prop::collection::vec((key(), inner), 0..10), any::<bool>()).prop_map(
                |(mut entries, canonical)| {
                    if canonical {
                        entries.sort_by(|a, b| reference_key_cmp(&a.0, &b.0));
                        entries.dedup_by(|a, b| a.0 == b.0);
                    }
                    Tree::Map(entries)
                }
            ),
        ]
    })
}

/// The encoder as it was before `encode_value` wrote straight into a `Vec`,
/// through [`Encoder`], as an oracle.
fn reference_encode(enc: &mut Encoder<&mut Vec<u8>>, value: &Value) -> Result<(), CborError> {
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
            for item in items {
                reference_encode(enc, item)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            enc.encode_map_header(entries.len() as u64)?;
            let mut sorted: Vec<_> = entries.iter().collect();
            if !entries
                .windows(2)
                .all(|w| reference_key_cmp(w[0].0, w[1].0) == Ordering::Less)
            {
                sorted.sort_by(|a, b| reference_key_cmp(a.0, b.0));
            }
            for (key, value) in sorted {
                enc.encode_text(key)?;
                reference_encode(enc, value)?;
            }
            Ok(())
        }
    }
}

/// `cbor_key_cmp` as it was, comparing encoded lengths.
fn reference_key_cmp(a: &str, b: &str) -> Ordering {
    fn head_len(n: usize) -> usize {
        match n {
            0..24 => 1,
            24..256 => 2,
            256..65536 => 3,
            _ if n <= u32::MAX as usize => 5,
            _ => 9,
        }
    }
    (head_len(a.len()) + a.len())
        .cmp(&(head_len(b.len()) + b.len()))
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Append `value` to a copy of `prefix` with the reference encoder.
fn reference_into(value: &Value, prefix: &[u8]) -> (Result<(), String>, Vec<u8>) {
    let mut buf = prefix.to_vec();
    let result = reference_encode(&mut Encoder::new(&mut buf), value);
    (result.map_err(|e| e.to_string()), buf)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    // `encode_value` writes what the reference encoder writes, or fails
    // with the same error.
    #[test]
    fn encode_value_matches_reference(tree in tree()) {
        let value = value(&tree);
        let (want, want_bytes) = reference_into(&value, &[]);
        match encode_value(&value) {
            Ok(bytes) => {
                prop_assert_eq!(want, Ok(()));
                prop_assert_eq!(bytes, want_bytes);
            }
            Err(e) => prop_assert_eq!(want, Err(e.to_string())),
        }
    }

    // `encode_value_into` leaves the buffer exactly as the reference encoder
    // does, partial output from a failure included.
    #[test]
    fn encode_value_into_matches_reference(
        tree in tree(),
        prefix in prop::collection::vec(any::<u8>(), 0..8),
    ) {
        let value = value(&tree);
        let (want, want_bytes) = reference_into(&value, &prefix);
        let mut buf = prefix.clone();
        let got = encode_value_into(&value, &mut buf).map_err(|e| e.to_string());
        prop_assert_eq!(got, want);
        prop_assert_eq!(buf, want_bytes);
    }

    #[test]
    fn cbor_key_cmp_matches_reference(
        (a, b) in (".{0,30}", "[ab]{0,10}", "[ab]{0,10}")
            .prop_map(|(prefix, x, y)| (prefix.clone() + &x, prefix + &y)),
    ) {
        prop_assert_eq!(cbor_key_cmp(&a, &b), reference_key_cmp(&a, &b));
    }
}

proptest! {
    // AT Protocol integers are signed 64-bit, so the valid unsigned domain is
    // [0, i64::MAX]. Values in range must round-trip exactly.
    #[test]
    fn encode_decode_roundtrip_unsigned(n in 0u64..=(i64::MAX as u64)) {
        let val = Value::Unsigned(n);
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
        prop_assert_eq!(decoded, Value::Unsigned(n));
    }

    // Unsigned values above i64::MAX are out of the signed-64-bit domain and
    // MUST be rejected on decode (not silently round-tripped / wrapped).
    #[test]
    fn decode_rejects_unsigned_above_i64_max(n in (i64::MAX as u64 + 1)..=u64::MAX) {
        let encoded = encode_value(&Value::Unsigned(n)).unwrap();
        prop_assert!(decode(&encoded).is_err());
    }

    #[test]
    fn encode_decode_roundtrip_signed(n in i64::MIN..0i64) {
        let val = Value::Signed(n);
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn encode_decode_roundtrip_float(f in any::<f64>().prop_filter("no NaN/Inf", |f| f.is_finite())) {
        let val = Value::Float(f);
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn encode_decode_roundtrip_bool(b in any::<bool>()) {
        let val = Value::Bool(b);
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn encode_decode_roundtrip_null(_dummy in Just(())) {
        let val = Value::Null;
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn encode_decode_roundtrip_array_of_ints(
        nums in prop::collection::vec(0u64..=(i64::MAX as u64), 0..50)
    ) {
        let val = Value::Array(nums.iter().map(|n| Value::Unsigned(*n)).collect());
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn encode_decode_roundtrip_map(
        keys in prop::collection::hash_set("[a-z]{1,10}", 1..20)
    ) {
        let val = Value::Map(
            keys.iter().enumerate().map(|(i, k)| {
                // We need &'static str for Value::Map keys.
                // Leak the string — proptest will generate new ones each run.
                let leaked: &'static str = Box::leak(k.clone().into_boxed_str());
                (leaked, Value::Unsigned(i as u64))
            }).collect()
        );
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
    }

    #[test]
    fn cid_binary_roundtrip(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let cid = Cid::compute(Codec::Drisl, &data);
        let bytes = cid.to_bytes();
        let parsed = Cid::from_bytes(&bytes).unwrap();
        prop_assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_string_roundtrip(data in prop::collection::vec(any::<u8>(), 1..100)) {
        let cid = Cid::compute(Codec::Drisl, &data);
        let s = cid.to_string();
        let parsed: Cid = s.parse().unwrap();
        prop_assert_eq!(cid, parsed);
    }

    // `$bytes` takes padding from none up to the full final group, as the
    // reference does, and nothing past it.
    #[test]
    fn bytes_base64_accepts_padding_within_the_final_group(
        data in prop::collection::vec(any::<u8>(), 0..64),
        pad in 0usize..4,
    ) {
        let unpadded = BASE64_NOPAD.encode(&data);
        let full = unpadded.len().next_multiple_of(4) - unpadded.len();
        let s = format!("{unpadded}{}", "=".repeat(pad));
        let want = (pad <= full).then_some(data);
        prop_assert_eq!(decode_base64(&s), want, "{}", s);
    }
}
