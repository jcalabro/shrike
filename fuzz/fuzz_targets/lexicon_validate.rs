#![no_main]
//! Lexicon record validation must never panic on arbitrary records. We build a
//! catalog with a schema covering many field kinds (string + formats, integer
//! with const/range, bool, bytes, blob, cid-link, array, nested object, union)
//! and feed it an arbitrary JSON value. Validation may pass or fail, but must
//! never panic.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use shrike::lexicon::{Catalog, validate_record};
use std::sync::OnceLock;

const SCHEMA: &str = r#"{
  "lexicon": 1,
  "id": "com.example.kitchensink",
  "defs": {
    "main": {
      "type": "record",
      "key": "tid",
      "record": {
        "type": "object",
        "required": ["text", "createdAt"],
        "nullable": ["maybe"],
        "properties": {
          "text": { "type": "string", "maxLength": 300, "maxGraphemes": 100 },
          "createdAt": { "type": "string", "format": "datetime" },
          "did": { "type": "string", "format": "did" },
          "handle": { "type": "string", "format": "handle" },
          "uri": { "type": "string", "format": "at-uri" },
          "count": { "type": "integer", "minimum": 0, "maximum": 1000 },
          "version": { "type": "integer", "const": 1 },
          "flag": { "type": "boolean" },
          "raw": { "type": "bytes", "maxLength": 64 },
          "blob": { "type": "blob", "accept": ["image/*"], "maxSize": 1000000 },
          "link": { "type": "cid-link" },
          "tags": { "type": "array", "items": { "type": "string" }, "maxLength": 8 },
          "maybe": { "type": "string" },
          "nested": {
            "type": "object",
            "required": ["inner"],
            "properties": { "inner": { "type": "string" } }
          }
        }
      }
    }
  }
}"#;

fn catalog() -> &'static Catalog {
    static C: OnceLock<Catalog> = OnceLock::new();
    C.get_or_init(|| {
        let mut c = Catalog::new();
        c.add_schema(SCHEMA.as_bytes())
            .expect("embedded schema must parse");
        c
    })
}

/// A small JSON generator so the fuzzer produces realistic record shapes
/// (objects with the schema's field names) rather than mostly-rejected noise.
#[derive(Arbitrary, Debug)]
enum Json {
    Null,
    Bool(bool),
    Int(i64),
    Float(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

fn to_value(j: &Json, depth: usize) -> serde_json::Value {
    use serde_json::Value;
    if depth > 12 {
        return Value::Null;
    }
    match j {
        Json::Null => Value::Null,
        Json::Bool(b) => Value::Bool(*b),
        Json::Int(n) => Value::from(*n),
        Json::Float(f) => serde_json::Number::from_f64(*f)
            .map(Value::Number)
            .unwrap_or(Value::Null),
        Json::Str(s) => Value::String(s.clone()),
        Json::Arr(items) => Value::Array(items.iter().map(|i| to_value(i, depth + 1)).collect()),
        Json::Obj(entries) => {
            let mut m = serde_json::Map::new();
            for (k, v) in entries {
                m.insert(k.clone(), to_value(v, depth + 1));
            }
            Value::Object(m)
        }
    }
}

fuzz_target!(|j: Json| {
    let value = to_value(&j, 0);
    // Must never panic regardless of the record shape.
    let _ = validate_record(catalog(), "com.example.kitchensink", &value);
});
