#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use data_encoding::BASE64_NOPAD;
use proptest::prelude::*;
use shrike::cbor::json::decode_base64;
use shrike::cbor::{Cid, Codec, Value, decode, encode_value};

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
