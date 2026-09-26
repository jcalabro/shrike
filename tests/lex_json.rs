//! Differential vectors ported from the reference `@atproto/lex-json`
//! (`testdata/lex_json_vectors.json`), run through `shrike::cbor::json`.
#![allow(clippy::unwrap_used, clippy::panic)]
#![cfg(feature = "cbor")]

use serde::Deserialize;
use serde_json::Value as Json;
use shrike::cbor::json::{Integers, drisl_to_json, json_to_drisl};
use shrike::cbor::{CborError, Value, decode};

#[derive(Deserialize)]
struct Vector {
    note: String,
    json: Json,
    /// The DRISL->JSON result when it differs from `json`.
    roundtrip: Option<Json>,
}

#[derive(Deserialize)]
struct Vectors {
    special: Vec<Vector>,
    plain: Vec<Vector>,
    rejected: Vec<Vector>,
}

fn load() -> Vectors {
    let raw = std::fs::read_to_string("testdata/lex_json_vectors.json").unwrap();
    serde_json::from_str(&raw).unwrap()
}

/// Maps in the JSON keyed `$link` or `$bytes`.
fn json_special_keys(json: &Json) -> usize {
    match json {
        Json::Array(items) => items.iter().map(json_special_keys).sum(),
        Json::Object(map) => {
            let own = map
                .keys()
                .filter(|k| *k == "$link" || *k == "$bytes")
                .count();
            own + map.values().map(json_special_keys).sum::<usize>()
        }
        _ => 0,
    }
}

/// (map keys named `$link` or `$bytes`, CID and byte values) in decoded DRISL.
fn drisl_counts(value: &Value<'_>) -> (usize, usize) {
    match value {
        Value::Cid(_) | Value::Bytes(_) => (0, 1),
        Value::Array(items) => items.iter().map(drisl_counts).fold((0, 0), add),
        Value::Map(entries) => entries.iter().fold((0, 0), |acc, (k, v)| {
            let own = usize::from(*k == "$link" || *k == "$bytes");
            add(add(acc, (own, 0)), drisl_counts(v))
        }),
        _ => (0, 0),
    }
}

fn add(a: (usize, usize), b: (usize, usize)) -> (usize, usize) {
    (a.0 + b.0, a.1 + b.1)
}

#[test]
fn special_forms_become_cids_and_bytes() {
    for v in load().special {
        let bytes = json_to_drisl(&v.json, Integers::Safe).unwrap();
        let counts = drisl_counts(&decode(&bytes).unwrap());
        assert_eq!(counts, (0, json_special_keys(&v.json)), "{}", v.note);
        assert_eq!(drisl_to_json(&bytes).unwrap(), v.json, "{}", v.note);
    }
}

#[test]
fn malformed_special_forms_stay_plain_maps() {
    for v in load().plain {
        let bytes =
            json_to_drisl(&v.json, Integers::Safe).unwrap_or_else(|e| panic!("{}: {e}", v.note));
        let (maps, values) = drisl_counts(&decode(&bytes).unwrap());
        let keys = json_special_keys(&v.json);
        // Some vectors nest a well-formed link inside an invalid blob.
        assert_eq!(maps + values, keys, "{}", v.note);
        // Converting a malformed form would lose or rewrite it, so an exact
        // round trip shows each one stayed a plain map.
        let back = drisl_to_json(&bytes).unwrap();
        assert_eq!(&back, v.roundtrip.as_ref().unwrap_or(&v.json), "{}", v.note);
    }
}

#[test]
fn floats_are_rejected() {
    for v in load().rejected {
        let err = json_to_drisl(&v.json, Integers::Any).unwrap_err();
        assert!(matches!(err, CborError::DataModel(_)), "{}: {err}", v.note);
    }
}
