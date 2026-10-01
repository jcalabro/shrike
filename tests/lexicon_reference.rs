//! Port of the reference `@atproto/lexicon` validation suite
//! (`packages/lexicon/tests/general.test.ts`), run against the scaffold
//! lexicons in `testdata/lexicon/reference/`.
//!
//! The 'Lexicons collection' block is not ported: it tests TS-specific
//! collection APIs. JS `undefined` object values are translated as absent
//! keys, `Uint8Array` as `$bytes`, and `CID` as `$link`.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde_json::{Map, Value as Json, json};
use shrike::lexicon::{
    Catalog, FieldSchema, LexiconError, ValidationError, validate_input, validate_output,
    validate_params, validate_record, validate_value,
};

const CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    for entry in std::fs::read_dir("testdata/lexicon/reference").unwrap() {
        let path = entry.unwrap().path();
        let raw = std::fs::read(&path).unwrap();
        catalog
            .add_schema(&raw)
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    catalog
}

fn add(catalog: &mut Catalog, doc: Json) -> Result<(), LexiconError> {
    catalog.add_schema(doc.to_string().as_bytes())
}

/// Validate `value` against the def named by `uri`, like the reference
/// `lex.validate('nsid#def', value)`. Errors are rooted at `value`.
fn validate_def(catalog: &Catalog, uri: &str, value: &Json) -> Result<(), ValidationError> {
    let field: FieldSchema = serde_json::from_value(json!({"type": "ref", "ref": uri})).unwrap();
    validate_value(catalog, "", &field, value)
}

/// `{"$type": nsid, field: value}` validated as a record of `nsid`.
fn rec(catalog: &Catalog, nsid: &str, field: &str, value: Json) -> Result<(), ValidationError> {
    validate_record(catalog, nsid, &json!({"$type": nsid, field: value}))
}

fn collect_paths(err: &ValidationError, out: &mut Vec<String>) {
    match err {
        ValidationError::Field { path, .. } => out.push(path.clone()),
        ValidationError::Multiple(errs) => errs.iter().for_each(|e| collect_paths(e, out)),
        _ => {}
    }
}

#[track_caller]
fn assert_err_at(res: Result<(), ValidationError>, path: &str) {
    let err = match res {
        Ok(()) => panic!("expected an error at {path}, got Ok"),
        Err(e) => e,
    };
    let mut paths = Vec::new();
    collect_paths(&err, &mut paths);
    assert!(
        paths.iter().any(|p| p == path),
        "expected an error at {path}, got: {err}"
    );
}

#[track_caller]
fn assert_ok(res: Result<(), ValidationError>, what: &str) {
    if let Err(e) = res {
        panic!("{what}: unexpected error: {e}");
    }
}

fn object(value: Json) -> Map<String, Json> {
    match value {
        Json::Object(m) => m,
        other => panic!("not an object: {other}"),
    }
}

fn passing_sink() -> Json {
    json!({
        "$type": "com.example.kitchenSink",
        "object": {
            "object": {"boolean": true},
            "array": ["one", "two"],
            "boolean": true,
            "integer": 123,
            "string": "string",
        },
        "array": ["one", "two"],
        "boolean": true,
        "integer": 123,
        "string": "string",
        "bytes": {"$bytes": "AAECAw"},
        "cidLink": {"$link": CID},
    })
}

fn sink_with(key: &str, value: Json) -> Json {
    let mut sink = passing_sink();
    sink[key] = value;
    sink
}

fn kitchen_sink_object() -> Json {
    json!({
        "object": {"boolean": true},
        "array": ["one", "two"],
        "boolean": true,
        "float": 123.45,
        "integer": 123,
        "string": "string",
    })
}

// --- General validation ---

#[test]
fn general_validates_records() {
    let cat = catalog();
    let res = validate_record(
        &cat,
        "com.example.kitchenSink",
        &json!({
            "$type": "com.example.kitchenSink",
            "object": {
                "object": {"boolean": true},
                "array": ["one", "two"],
                "boolean": true,
                "integer": 123,
                "string": "string",
            },
            "array": ["one", "two"],
            "boolean": true,
            "integer": 123,
            "string": "string",
            "datetime": "2022-12-12T00:50:36.809Z",
            "atUri": "at://did:web:example.com/com.example.test/self",
            "did": "did:web:example.com",
            "cid": CID,
            "bytes": {"$bytes": "AAECAw"},
            "cidLink": {"$link": CID},
        }),
    );
    assert_ok(res, "kitchenSink");
    assert_err_at(
        validate_record(&cat, "com.example.kitchenSink", &json!({})),
        "record.object",
    );
}

#[test]
fn general_validates_objects() {
    let cat = catalog();
    let value = json!({
        "object": {"boolean": true},
        "array": ["one", "two"],
        "boolean": true,
        "integer": 123,
        "string": "string",
    });
    assert_ok(
        validate_def(&cat, "com.example.kitchenSink#object", &value),
        "kitchenSink#object",
    );
    assert_err_at(
        validate_def(&cat, "com.example.kitchenSink#object", &json!({})),
        "value.object",
    );
}

#[test]
fn general_fails_when_required_property_is_not_defined() {
    let doc = json!({
        "lexicon": 1,
        "id": "com.example.kitchenSink",
        "defs": {"test": {"type": "object", "required": ["foo"], "properties": {}}},
    });
    assert!(add(&mut Catalog::new(), doc).is_err());
}

#[test]
fn general_allows_unknown_schema_fields() {
    let doc = json!({
        "lexicon": 1,
        "id": "com.example.unknownFields",
        "defs": {"test": {"type": "object", "properties": {}, "foo": 3}},
    });
    add(&mut Catalog::new(), doc).unwrap();
}

// Deviation: the reference parser requires `properties` on objects, but
// indigo's interop catalog (`minimal-procedure.json`) relies on omitting it,
// so shrike accepts it as an empty object.
#[test]
fn general_accepts_object_without_properties() {
    let doc = json!({
        "lexicon": 1,
        "id": "blog.pckt.block.horizontalRule",
        "description": "Horizontal line that visually separates sections of content.",
        "defs": {"main": {"type": "object"}},
    });
    add(&mut Catalog::new(), doc).unwrap();
}

#[test]
fn general_rejects_ref_with_multiple_hash_segments() {
    let doc = json!({
        "lexicon": 1,
        "id": "com.example.invalidUri",
        "defs": {
            "main": {
                "type": "object",
                "properties": {"test": {"type": "ref", "ref": "com.example.invalid#test#test"}},
            },
        },
    });
    assert!(add(&mut Catalog::new(), doc).is_err());
}

#[test]
fn general_rejects_union_type_with_multiple_hash_segments() {
    let mut cat = Catalog::new();
    let doc = json!({
        "lexicon": 1,
        "id": "com.example.invalidUri",
        "defs": {
            "main": {"type": "object", "properties": {"test": {"type": "integer"}}},
            "object": {
                "type": "object",
                "required": ["test"],
                "properties": {"test": {"type": "union", "refs": ["com.example.invalidUri"]}},
            },
        },
    });
    add(&mut cat, doc).unwrap();
    let value = json!({"test": {"$type": "com.example.invalidUri#main#main", "test": 123}});
    assert!(validate_def(&cat, "com.example.invalidUri#object", &value).is_err());
}

#[test]
fn general_union_handles_implicit_and_explicit_main() {
    let mut cat = Catalog::new();
    add(
        &mut cat,
        json!({
            "lexicon": 1,
            "id": "com.example.implicitMain",
            "defs": {
                "main": {
                    "type": "object",
                    "required": ["test"],
                    "properties": {"test": {"type": "string"}},
                },
            },
        }),
    )
    .unwrap();
    for (id, union_ref) in [
        ("com.example.testImplicitMain", "com.example.implicitMain"),
        (
            "com.example.testExplicitMain",
            "com.example.implicitMain#main",
        ),
    ] {
        add(
            &mut cat,
            json!({
                "lexicon": 1,
                "id": id,
                "defs": {
                    "main": {
                        "type": "object",
                        "required": ["union"],
                        "properties": {"union": {"type": "union", "refs": [union_ref]}},
                    },
                },
            }),
        )
        .unwrap();
    }

    for uri in [
        "com.example.testImplicitMain",
        "com.example.testExplicitMain",
    ] {
        for type_name in ["com.example.implicitMain", "com.example.implicitMain#main"] {
            let value = json!({"union": {"$type": type_name, "test": 123}});
            let res = validate_def(&cat, uri, &value);
            assert!(res.is_err(), "{uri} with $type {type_name}: expected error");
            assert_err_at(res, "value.union.test");
        }
    }
}

// --- Record validation ---

#[test]
fn record_passes_valid_schemas() {
    let cat = catalog();
    assert_ok(
        validate_record(&cat, "com.example.kitchenSink", &passing_sink()),
        "passingSink",
    );
}

#[test]
fn record_fails_invalid_input_types() {
    let cat = catalog();
    for value in [Json::Null, json!(1234), json!("string")] {
        assert_err_at(
            validate_record(&cat, "com.example.kitchenSink", &value),
            "record",
        );
    }
}

#[test]
fn record_fails_incorrect_type() {
    let cat = catalog();
    assert_err_at(
        validate_record(&cat, "com.example.kitchenSink", &json!({"$type": "foo"})),
        "$type",
    );
    // Deviation: the reference `assertValidRecord` requires `$type`;
    // `validate_record` takes the collection explicitly and checks `$type`
    // only when present, so `{}` fails on required fields instead.
    let res = validate_record(&cat, "com.example.kitchenSink", &json!({}));
    assert!(res.is_err());
}

#[test]
fn record_fails_missing_required() {
    let cat = catalog();
    let res = validate_record(
        &cat,
        "com.example.kitchenSink",
        &json!({
            "$type": "com.example.kitchenSink",
            "array": ["one", "two"],
            "boolean": true,
            "integer": 123,
            "string": "string",
            "datetime": "2022-12-12T00:50:36.809Z",
            "atUri": "at://did:web:example.com/com.example.test/self",
            "did": "did:web:example.com",
            "cid": CID,
            "bytes": {"$bytes": "AAECAw"},
            "cidLink": {"$link": CID},
        }),
    );
    assert_err_at(res, "record.object");

    let mut sink = passing_sink();
    sink.as_object_mut().unwrap().remove("object");
    assert_err_at(
        validate_record(&cat, "com.example.kitchenSink", &sink),
        "record.object",
    );
}

#[test]
fn record_fails_incorrect_types() {
    let cat = catalog();
    let mut inner = passing_sink()["object"].clone();
    inner["object"] = json!({"boolean": "1234"});
    for (key, value, path) in [
        ("object", inner, "record.object.object.boolean"),
        ("object", json!(true), "record.object"),
        ("array", json!(1234), "record.array"),
        ("integer", json!(true), "record.integer"),
        ("string", json!({}), "record.string"),
        ("bytes", json!(1234), "record.bytes"),
        ("cidLink", json!(CID), "record.cidLink"),
    ] {
        assert_err_at(
            validate_record(&cat, "com.example.kitchenSink", &sink_with(key, value)),
            path,
        );
    }
}

#[test]
fn record_handles_optional_properties() {
    let cat = catalog();
    let value = json!({"$type": "com.example.optional"});
    assert_ok(
        validate_record(&cat, "com.example.optional", &value),
        "optional",
    );
}

#[test]
fn record_handles_default_properties() {
    let cat = catalog();
    let value = json!({"$type": "com.example.default", "object": {}});
    // The reference also returns the record with defaults filled in;
    // validate_record does not apply defaults, so only validity is checked.
    assert_ok(
        validate_record(&cat, "com.example.default", &value),
        "default",
    );
}

#[test]
fn record_handles_unions() {
    let cat = catalog();
    let closed = json!({"$type": "com.example.kitchenSink#subobject", "boolean": true});
    let value = json!({
        "$type": "com.example.union",
        "unionOpen": {
            "$type": "com.example.kitchenSink#object",
            "object": {"boolean": true},
            "array": ["one", "two"],
            "boolean": true,
            "integer": 123,
            "string": "string",
        },
        "unionClosed": closed,
    });
    assert_ok(validate_record(&cat, "com.example.union", &value), "known");
    let value = json!({
        "$type": "com.example.union",
        "unionOpen": {"$type": "com.example.other"},
        "unionClosed": closed,
    });
    assert_ok(
        validate_record(&cat, "com.example.union", &value),
        "open union",
    );
    let value = json!({"$type": "com.example.union", "unionOpen": {}, "unionClosed": {}});
    assert_err_at(
        validate_record(&cat, "com.example.union", &value),
        "record.unionOpen",
    );
    let value = json!({
        "$type": "com.example.union",
        "unionOpen": {"$type": "com.example.other"},
        "unionClosed": {"$type": "com.example.other", "boolean": true},
    });
    assert_err_at(
        validate_record(&cat, "com.example.union", &value),
        "record.unionClosed",
    );
}

#[test]
fn record_handles_unknowns() {
    let cat = catalog();
    assert_ok(
        rec(
            &cat,
            "com.example.unknown",
            "unknown",
            json!({"foo": "bar"}),
        ),
        "unknown",
    );
    assert_err_at(
        validate_record(
            &cat,
            "com.example.unknown",
            &json!({"$type": "com.example.unknown"}),
        ),
        "record.unknown",
    );
}

#[test]
fn record_applies_array_length_constraints() {
    let cat = catalog();
    let nsid = "com.example.arrayLength";
    assert_ok(rec(&cat, nsid, "array", json!([1, 2, 3])), "[1, 2, 3]");
    assert_err_at(rec(&cat, nsid, "array", json!([1])), "record.array");
    assert_err_at(
        rec(&cat, nsid, "array", json!([1, 2, 3, 4, 5])),
        "record.array",
    );
}

#[test]
fn record_applies_array_item_constraints() {
    let cat = catalog();
    let nsid = "com.example.arrayLength";
    assert_err_at(
        rec(&cat, nsid, "array", json!([1, "2", 3])),
        "record.array[1]",
    );
    // JS `undefined` inside an array has no JSON form; null is the nearest.
    assert_err_at(
        rec(&cat, nsid, "array", json!([1, null, 3])),
        "record.array[1]",
    );
}

#[test]
fn record_applies_boolean_const_constraint() {
    let cat = catalog();
    let nsid = "com.example.boolConst";
    assert_ok(rec(&cat, nsid, "boolean", json!(false)), "false");
    assert_err_at(rec(&cat, nsid, "boolean", json!(true)), "record.boolean");
}

#[test]
fn record_applies_integer_range_constraint() {
    let cat = catalog();
    let nsid = "com.example.integerRange";
    assert_ok(rec(&cat, nsid, "integer", json!(2)), "2");
    assert_err_at(rec(&cat, nsid, "integer", json!(1)), "record.integer");
    assert_err_at(rec(&cat, nsid, "integer", json!(5)), "record.integer");
}

#[test]
fn record_applies_integer_enum_constraint() {
    let cat = catalog();
    let nsid = "com.example.integerEnum";
    assert_ok(rec(&cat, nsid, "integer", json!(2)), "2");
    assert_err_at(rec(&cat, nsid, "integer", json!(0)), "record.integer");
}

#[test]
fn record_applies_integer_const_constraint() {
    let cat = catalog();
    let nsid = "com.example.integerConst";
    assert_ok(rec(&cat, nsid, "integer", json!(0)), "0");
    assert_err_at(rec(&cat, nsid, "integer", json!(1)), "record.integer");
}

#[test]
fn record_applies_integer_whole_number_constraint() {
    let cat = catalog();
    assert_err_at(
        rec(&cat, "com.example.integerRange", "integer", json!(2.5)),
        "record.integer",
    );
}

// JS strings may hold unpaired surrogates, which the reference measures as
// their UTF-8 replacement (U+FFFD, 3 bytes); Rust strings cannot, so those
// cases use U+FFFD directly.
const FAMILY: &str = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}\u{200D}\u{1F467}";

const UTF8_TWO_TO_FOUR_BYTES: &[&str] = &[
    "ab", "\u{301}", "a\u{301}", "aé", "abc", "一", "\u{FFFD}", "abcd", "éé", "aaé", "👋",
];

const UTF8_OVER_FOUR_BYTES: &[&str] = &[
    "abcde",
    "a\u{301}\u{301}",
    "\u{FFFD}\u{FFFD}",
    "ééé",
    "👋a",
    "👨👨",
    FAMILY,
];

#[test]
fn record_applies_string_length_constraint() {
    let cat = catalog();
    let nsid = "com.example.stringLength";
    for s in ["", "a"] {
        assert_err_at(rec(&cat, nsid, "string", json!(s)), "record.string");
    }
    for s in UTF8_TWO_TO_FOUR_BYTES {
        assert_ok(rec(&cat, nsid, "string", json!(s)), s);
    }
    for s in UTF8_OVER_FOUR_BYTES {
        assert_err_at(rec(&cat, nsid, "string", json!(s)), "record.string");
    }
}

#[test]
fn record_applies_string_length_constraint_no_min_length() {
    let cat = catalog();
    let nsid = "com.example.stringLengthNoMinLength";
    for s in ["", "a"].iter().chain(UTF8_TWO_TO_FOUR_BYTES) {
        assert_ok(rec(&cat, nsid, "string", json!(s)), s);
    }
    for s in UTF8_OVER_FOUR_BYTES {
        assert_err_at(rec(&cat, nsid, "string", json!(s)), "record.string");
    }
}

#[test]
fn record_applies_grapheme_string_length_constraint() {
    let cat = catalog();
    let nsid = "com.example.stringLengthGrapheme";
    for s in [
        "",
        "\u{301}\u{301}\u{301}",
        "a",
        "a\u{301}\u{301}\u{301}\u{301}",
        "5\u{FE0F}",
        FAMILY,
    ] {
        assert_err_at(rec(&cat, nsid, "string", json!(s)), "record.string");
    }
    let family_suffix = format!("12{FAMILY}");
    for s in [
        "ab",
        "a\u{301}b",
        "a\u{301}b\u{301}",
        "😀😀",
        &family_suffix,
        "abcd",
        "a\u{301}b\u{301}c\u{301}d\u{301}",
    ] {
        assert_ok(rec(&cat, nsid, "string", json!(s)), s);
    }
    for s in [
        "abcde",
        "a\u{301}b\u{301}c\u{301}d\u{301}e\u{301}",
        "😀😀😀😀😀",
        "ab😀de",
    ] {
        assert_err_at(rec(&cat, nsid, "string", json!(s)), "record.string");
    }
}

#[test]
fn record_applies_string_enum_constraint() {
    let cat = catalog();
    let nsid = "com.example.stringEnum";
    assert_ok(rec(&cat, nsid, "string", json!("a")), "a");
    assert_err_at(rec(&cat, nsid, "string", json!("c")), "record.string");
}

#[test]
fn record_applies_string_const_constraint() {
    let cat = catalog();
    let nsid = "com.example.stringConst";
    assert_ok(rec(&cat, nsid, "string", json!("a")), "a");
    assert_err_at(rec(&cat, nsid, "string", json!("b")), "record.string");
}

#[test]
fn record_applies_datetime_format() {
    let cat = catalog();
    let nsid = "com.example.datetime";
    for s in [
        "2022-12-12T00:50:36.809Z",
        "2022-12-12T00:50:36Z",
        "2022-12-12T00:50:36.8Z",
        "2022-12-12T00:50:36.80Z",
        "2022-12-12T00:50:36+00:00",
        "2022-12-12T00:50:36.8+00:00",
        "2022-12-11T19:50:36-05:00",
        "2022-12-11T19:50:36.8-05:00",
        "2022-12-11T19:50:36.80-05:00",
        "2022-12-11T19:50:36.809-05:00",
    ] {
        assert_ok(rec(&cat, nsid, "datetime", json!(s)), s);
    }
    assert_err_at(
        rec(&cat, nsid, "datetime", json!("bad date")),
        "record.datetime",
    );
}

#[test]
fn record_applies_uri_format() {
    let cat = catalog();
    let nsid = "com.example.uri";
    for s in [
        "https://example.com",
        "https://example.com/with/path",
        "https://example.com/with/path?and=query",
        "at://bsky.social",
        "did:example:test",
    ] {
        assert_ok(rec(&cat, nsid, "uri", json!(s)), s);
    }
    assert_err_at(rec(&cat, nsid, "uri", json!("not a uri")), "record.uri");
}

#[test]
fn record_applies_at_uri_format() {
    let cat = catalog();
    let nsid = "com.example.atUri";
    let uri = "at://did:web:example.com/com.example.test/self";
    assert_ok(rec(&cat, nsid, "atUri", json!(uri)), uri);
    assert_err_at(
        rec(&cat, nsid, "atUri", json!("http://not-atproto.com")),
        "record.atUri",
    );
}

#[test]
fn record_applies_did_format() {
    let cat = catalog();
    let nsid = "com.example.did";
    for s in ["did:web:example.com", "did:plc:12345678abcdefghijklmnop"] {
        assert_ok(rec(&cat, nsid, "did", json!(s)), s);
    }
    for s in ["bad did", "did:short"] {
        assert_err_at(rec(&cat, nsid, "did", json!(s)), "record.did");
    }
}

#[test]
fn record_applies_handle_format() {
    let cat = catalog();
    let nsid = "com.example.handle";
    for s in ["test.bsky.social", "bsky.test"] {
        assert_ok(rec(&cat, nsid, "handle", json!(s)), s);
    }
    for s in ["bad handle", "-bad-.test"] {
        assert_err_at(rec(&cat, nsid, "handle", json!(s)), "record.handle");
    }
}

#[test]
fn record_applies_at_identifier_format() {
    let cat = catalog();
    let nsid = "com.example.atIdentifier";
    for s in ["bsky.test", "did:plc:12345678abcdefghijklmnop"] {
        assert_ok(rec(&cat, nsid, "atIdentifier", json!(s)), s);
    }
    for s in ["bad id", "-bad-.test"] {
        assert_err_at(
            rec(&cat, nsid, "atIdentifier", json!(s)),
            "record.atIdentifier",
        );
    }
}

#[test]
fn record_applies_nsid_format() {
    let cat = catalog();
    let nsid = "com.example.nsid";
    for s in ["com.atproto.test", "app.bsky.nested.test"] {
        assert_ok(rec(&cat, nsid, "nsid", json!(s)), s);
    }
    for s in ["bad nsid", "com.bad-.foo"] {
        assert_err_at(rec(&cat, nsid, "nsid", json!(s)), "record.nsid");
    }
}

#[test]
fn record_applies_cid_format() {
    let cat = catalog();
    let nsid = "com.example.cid";
    assert_ok(rec(&cat, nsid, "cid", json!(CID)), CID);
    assert_err_at(
        rec(&cat, nsid, "cid", json!("abapsdofiuwrpoiasdfuaspdfoiu")),
        "record.cid",
    );
}

#[test]
fn record_applies_language_format() {
    let cat = catalog();
    let nsid = "com.example.language";
    assert_ok(
        rec(&cat, nsid, "language", json!("en-US-boont")),
        "en-US-boont",
    );
    assert_err_at(
        rec(&cat, nsid, "language", json!("not-a-language-")),
        "record.language",
    );
}

#[test]
fn record_applies_bytes_length_constraints() {
    let cat = catalog();
    let nsid = "com.example.byteLength";
    assert_ok(
        rec(&cat, nsid, "bytes", json!({"$bytes": "AQID"})),
        "[1, 2, 3]",
    );
    assert_err_at(
        rec(&cat, nsid, "bytes", json!({"$bytes": "AQ"})),
        "record.bytes",
    );
    assert_err_at(
        rec(&cat, nsid, "bytes", json!({"$bytes": "AQIDBAU"})),
        "record.bytes",
    );
}

// --- XRPC parameter validation ---

#[test]
fn params_pass_valid_parameters() {
    let cat = catalog();
    let mut params = object(json!({
        "boolean": true,
        "integer": 123,
        "string": "string",
        "array": ["x", "y"],
    }));
    validate_params(&cat, "com.example.query", &mut params).unwrap();
    assert_eq!(
        Json::Object(params),
        json!({
            "boolean": true,
            "integer": 123,
            "string": "string",
            "array": ["x", "y"],
            "def": 0,
        })
    );

    let expected = json!({
        "boolean": true,
        "integer": 123,
        "string": "string",
        "array": ["x", "y"],
        "def": 1,
    });
    let mut params = object(expected.clone());
    validate_params(&cat, "com.example.procedure", &mut params).unwrap();
    assert_eq!(Json::Object(params), expected);
}

#[test]
fn params_handle_required() {
    let cat = catalog();
    let mut params = object(json!({"boolean": true, "integer": 123}));
    validate_params(&cat, "com.example.query", &mut params).unwrap();
    let mut params = object(json!({"boolean": true}));
    assert_err_at(
        validate_params(&cat, "com.example.query", &mut params),
        "integer",
    );
}

#[test]
fn params_validate_types() {
    let cat = catalog();
    let mut params = object(json!({"boolean": "string", "integer": 123, "string": "string"}));
    assert_err_at(
        validate_params(&cat, "com.example.query", &mut params),
        "boolean",
    );
    let mut params = object(json!({
        "boolean": true,
        "float": 123.45,
        "integer": 123,
        "string": "string",
        "array": "x",
    }));
    assert_err_at(
        validate_params(&cat, "com.example.query", &mut params),
        "array",
    );
}

// --- XRPC input validation ---

#[test]
fn input_passes_valid_inputs() {
    let cat = catalog();
    let mut input = kitchen_sink_object();
    assert_ok(
        validate_input(&cat, "com.example.procedure", &mut input),
        "procedure input",
    );
}

#[test]
fn input_validates_the_input() {
    let cat = catalog();
    let mut input = kitchen_sink_object();
    input["object"] = json!({"boolean": "string"});
    assert_err_at(
        validate_input(&cat, "com.example.procedure", &mut input),
        "input.object.boolean",
    );
    assert_err_at(
        validate_input(&cat, "com.example.procedure", &mut json!({})),
        "input.object",
    );
}

// --- XRPC output validation ---

#[test]
fn output_passes_valid_outputs() {
    let cat = catalog();
    for nsid in ["com.example.query", "com.example.procedure"] {
        assert_ok(validate_output(&cat, nsid, &kitchen_sink_object()), nsid);
    }
}

#[test]
fn output_validates_the_output() {
    let cat = catalog();
    let mut output = kitchen_sink_object();
    output["object"] = json!({"boolean": "string"});
    assert_err_at(
        validate_output(&cat, "com.example.query", &output),
        "output.object.boolean",
    );
    assert_err_at(
        validate_output(&cat, "com.example.procedure", &json!({})),
        "output.object",
    );
}
