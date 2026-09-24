#![no_main]
//! Record JSON conversion must accept exactly the strict materialized CBOR
//! decoder's float-free values and preserve every field, scalar and link.

use libfuzzer_sys::fuzz_target;
use serde_json::Value as Json;
use shrike::cbor::Value;

fn has_float(value: &Value<'_>) -> bool {
    match value {
        Value::Float(_) => true,
        Value::Array(items) => items.iter().any(has_float),
        Value::Map(entries) => entries.iter().any(|(_, v)| has_float(v)),
        _ => false,
    }
}

fn equivalent(value: &Value<'_>, json: &Json) {
    match value {
        Value::Unsigned(n) => assert_eq!(json.as_u64(), Some(*n)),
        Value::Signed(n) => assert_eq!(json.as_i64(), Some(*n)),
        Value::Bool(b) => assert_eq!(json.as_bool(), Some(*b)),
        Value::Null => assert!(json.is_null()),
        Value::Text(s) => assert_eq!(json.as_str(), Some(*s)),
        Value::Bytes(_) | Value::Cid(_) => assert_eq!(
            shrike::jetstream::record_json_to_dag_cbor(json).unwrap(),
            shrike::cbor::encode_value(value).unwrap()
        ),
        Value::Array(items) => {
            let array = json.as_array().unwrap();
            assert_eq!(items.len(), array.len());
            for (value, json) in items.iter().zip(array) {
                equivalent(value, json);
            }
        }
        Value::Map(entries) => {
            let object = json.as_object().unwrap();
            assert_eq!(entries.len(), object.len());
            for (key, value) in entries {
                equivalent(value, object.get(*key).unwrap());
            }
        }
        Value::Float(_) => panic!("float must be rejected"),
    }
}

fuzz_target!(|data: &[u8]| {
    let reference = shrike::cbor::decode(data);
    let actual = shrike::jetstream::record_cbor_to_json(data);
    match reference {
        Ok(value) if !has_float(&value) => equivalent(&value, &actual.unwrap()),
        _ => assert!(actual.is_err()),
    }
});
