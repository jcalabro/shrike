#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use shrike::cbor::{Cid, Codec, Value, decode, encode_value};

proptest! {
    #[test]
    fn encode_decode_roundtrip_unsigned(n in any::<u64>()) {
        let val = Value::Unsigned(n);
        let encoded = encode_value(&val).unwrap();
        let decoded = decode(&encoded).unwrap();
        let re_encoded = encode_value(&decoded).unwrap();
        prop_assert_eq!(&encoded, &re_encoded);
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
    fn encode_decode_roundtrip_array_of_ints(nums in prop::collection::vec(any::<u64>(), 0..50)) {
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
}
