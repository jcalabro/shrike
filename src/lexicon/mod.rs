//! Lexicon schema loading and validation for AT Protocol.
//!
//! Lexicons define the structure of XRPC methods and record types. The
//! Catalog type loads JSON schema definitions and validates records against
//! them. Use validate_record to check that a record conforms to its schema.
//!
//! Schemas define object shapes, string formats, integer ranges, array
//! constraints, and type references. The validator checks required fields,
//! types, and constraints but allows extra fields not in the schema.
//!
//! With the `lexicon-resolver` feature, [`resolver::LexiconResolver`] fetches
//! and verifies published schemas from the network by NSID.

mod catalog;
mod error;
#[cfg(all(
    feature = "lexicon-resolver",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
pub mod resolver;
mod schema;
mod validate;

pub use catalog::Catalog;
pub use error::{LexiconError, ValidationError, ValidationErrorKind};
pub use schema::{
    ArrayTypeDef, BodyDef, BooleanTypeDef, BytesTypeDef, Def, ErrorDef, FieldSchema,
    IntegerTypeDef, MessageDef, ObjectDef, ParamsDef, ProcedureDef, QueryDef, RecordDef, Schema,
    StringTypeDef, SubscriptionDef, TokenDef, split_ref,
};
pub use validate::{
    validate_input, validate_message, validate_output, validate_params, validate_record,
    validate_value,
};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::lexicon::*;

    const POST_SCHEMA: &str = r#"{
        "lexicon": 1,
        "id": "app.bsky.feed.post",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["text", "createdAt"],
                    "properties": {
                        "text": { "type": "string", "maxLength": 300 },
                        "createdAt": { "type": "string", "format": "datetime" }
                    }
                }
            }
        }
    }"#;

    #[test]
    fn parse_schema() {
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        let schema = catalog.get("app.bsky.feed.post").unwrap();
        assert_eq!(schema.id, "app.bsky.feed.post");
    }

    #[test]
    fn validate_valid_record() {
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello world",
            "createdAt": "2024-01-01T00:00:00Z"
        });
        validate_record(&catalog, "app.bsky.feed.post", &record).unwrap();
    }

    #[test]
    fn validate_missing_required_field() {
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello"
        });
        let err = validate_record(&catalog, "app.bsky.feed.post", &record);
        assert!(err.is_err());
        assert!(err.unwrap_err().to_string().contains("createdAt"));
    }

    #[test]
    fn validate_string_too_long() {
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "x".repeat(301),
            "createdAt": "2024-01-01T00:00:00Z"
        });
        assert!(validate_record(&catalog, "app.bsky.feed.post", &record).is_err());
    }

    #[test]
    fn validate_integer_range() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.counter",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["count"],
                        "properties": {
                            "count": { "type": "integer", "minimum": 0, "maximum": 100 }
                        }
                    }
                }
            }
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"count": 50});
        validate_record(&catalog, "com.example.counter", &valid).unwrap();

        let too_high = serde_json::json!({"count": 101});
        assert!(validate_record(&catalog, "com.example.counter", &too_high).is_err());

        let too_low = serde_json::json!({"count": -1});
        assert!(validate_record(&catalog, "com.example.counter", &too_low).is_err());
    }

    #[test]
    fn validate_array() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.tags",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["tags"],
                        "properties": {
                            "tags": { "type": "array", "items": { "type": "string" }, "maxLength": 3 }
                        }
                    }
                }
            }
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"tags": ["a", "b"]});
        validate_record(&catalog, "com.example.tags", &valid).unwrap();

        let too_many = serde_json::json!({"tags": ["a", "b", "c", "d"]});
        assert!(validate_record(&catalog, "com.example.tags", &too_many).is_err());
    }

    #[test]
    fn validate_unknown_collection() {
        let catalog = Catalog::new();
        let record = serde_json::json!({"text": "hello"});
        assert!(validate_record(&catalog, "com.nonexistent.type", &record).is_err());
    }

    #[test]
    fn validate_extra_fields_allowed() {
        // AT Protocol allows extra fields not in schema.
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        let record = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "Hello",
            "createdAt": "2024-01-01T00:00:00Z",
            "extraField": "should be fine"
        });
        validate_record(&catalog, "app.bsky.feed.post", &record).unwrap();
    }

    #[test]
    fn validate_boolean_type() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.flag",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["enabled"],
                        "properties": {
                            "enabled": { "type": "boolean" }
                        }
                    }
                }
            }
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"enabled": true});
        validate_record(&catalog, "com.example.flag", &valid).unwrap();

        let invalid = serde_json::json!({"enabled": "yes"});
        assert!(validate_record(&catalog, "com.example.flag", &invalid).is_err());
    }

    #[test]
    fn validate_string_enum() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.status",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["status"],
                        "properties": {
                            "status": { "type": "string", "enum": ["active", "inactive"] }
                        }
                    }
                }
            }
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"status": "active"});
        validate_record(&catalog, "com.example.status", &valid).unwrap();

        let invalid = serde_json::json!({"status": "pending"});
        assert!(validate_record(&catalog, "com.example.status", &invalid).is_err());
    }

    #[test]
    fn validate_cid_link_field() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.linked",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["root"],
                        "properties": {
                            "root": { "type": "cid-link" }
                        }
                    }
                }
            }
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"root": {"$link": "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgz7soitae"}});
        validate_record(&catalog, "com.example.linked", &valid).unwrap();

        // Regression: the $link value itself was not checked.
        for invalid in [
            serde_json::json!({"root": "not-an-object"}),
            serde_json::json!({"root": {"$link": "notacid"}}),
            serde_json::json!({"root": {"$link": 5}}),
            serde_json::json!({"root": {"$link": "bafyreib2rxk3rybk3aobmv5cjuql3bm2twh4jo5uxgf5kpqcsgz7soitae", "x": 1}}),
        ] {
            assert!(
                validate_record(&catalog, "com.example.linked", &invalid).is_err(),
                "{invalid}"
            );
        }
    }

    #[test]
    fn validate_blob_ref_cid() {
        let schema_json = r#"{
            "lexicon": 1,
            "id": "com.example.blobby",
            "defs": {"main": {"type": "record", "record": {
                "type": "object", "required": ["b"],
                "properties": {"b": {"type": "blob"}}
            }}}
        }"#;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();
        let blob = |link: &str| {
            serde_json::json!({"b": {
                "$type": "blob", "ref": {"$link": link}, "mimeType": "image/png", "size": 1
            }})
        };
        let cid = "bafkreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454";
        validate_record(&catalog, "com.example.blobby", &blob(cid)).unwrap();
        assert!(validate_record(&catalog, "com.example.blobby", &blob("notacid")).is_err());
    }

    #[test]
    fn validate_datetime_format() {
        let mut catalog = Catalog::new();
        catalog.add_schema(POST_SCHEMA.as_bytes()).unwrap();

        let invalid = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello",
            "createdAt": "not-a-datetime"
        });
        assert!(validate_record(&catalog, "app.bsky.feed.post", &invalid).is_err());
    }

    #[test]
    fn validate_ref_inline() {
        let schema_json = r##"{
            "lexicon": 1,
            "id": "com.example.outer",
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": ["inner"],
                        "properties": {
                            "inner": { "type": "ref", "ref": "#innerDef" }
                        }
                    }
                },
                "innerDef": {
                    "type": "object",
                    "required": ["value"],
                    "properties": {
                        "value": { "type": "string" }
                    }
                }
            }
        }"##;
        let mut catalog = Catalog::new();
        catalog.add_schema(schema_json.as_bytes()).unwrap();

        let valid = serde_json::json!({"inner": {"value": "hello"}});
        validate_record(&catalog, "com.example.outer", &valid).unwrap();

        let missing = serde_json::json!({"inner": {}});
        assert!(validate_record(&catalog, "com.example.outer", &missing).is_err());
    }

    // --- Validator hardening (M19-M22) ---

    fn single_field_catalog(id: &str, field: &str, schema: serde_json::Value) -> Catalog {
        let doc = serde_json::json!({
            "lexicon": 1,
            "id": id,
            "defs": {
                "main": {
                    "type": "record",
                    "record": {
                        "type": "object",
                        "required": [field],
                        "properties": { field: schema }
                    }
                }
            }
        });
        let mut catalog = Catalog::new();
        catalog.add_schema(doc.to_string().as_bytes()).unwrap();
        catalog
    }

    #[test]
    fn validate_integer_rejects_out_of_range_float() {
        // M19: a whole-valued float outside i64 range must be rejected, not
        // saturated to i64::MAX.
        let catalog =
            single_field_catalog("com.example.n", "n", serde_json::json!({"type": "integer"}));
        let big = serde_json::json!({"n": 1e30});
        assert!(validate_record(&catalog, "com.example.n", &big).is_err());
        let ok = serde_json::json!({"n": 5});
        validate_record(&catalog, "com.example.n", &ok).unwrap();
    }

    #[test]
    fn validate_integer_const() {
        // M21: const integer.
        let catalog = single_field_catalog(
            "com.example.c",
            "c",
            serde_json::json!({"type": "integer", "const": 1}),
        );
        validate_record(&catalog, "com.example.c", &serde_json::json!({"c": 1})).unwrap();
        assert!(validate_record(&catalog, "com.example.c", &serde_json::json!({"c": 2})).is_err());
    }

    #[test]
    fn validate_boolean_const() {
        // M21: const boolean.
        let catalog = single_field_catalog(
            "com.example.b",
            "b",
            serde_json::json!({"type": "boolean", "const": true}),
        );
        validate_record(&catalog, "com.example.b", &serde_json::json!({"b": true})).unwrap();
        assert!(
            validate_record(&catalog, "com.example.b", &serde_json::json!({"b": false})).is_err()
        );
    }

    #[test]
    fn validate_blob_requires_fields() {
        // M20: blob must have ref/mimeType/size.
        let catalog =
            single_field_catalog("com.example.bl", "bl", serde_json::json!({"type": "blob"}));
        // Bare $type only → invalid.
        let bare = serde_json::json!({"bl": {"$type": "blob"}});
        assert!(validate_record(&catalog, "com.example.bl", &bare).is_err());
        // Full, well-formed blob → valid.
        let full = serde_json::json!({"bl": {
            "$type": "blob",
            "ref": {"$link": "bafyreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454"},
            "mimeType": "image/png",
            "size": 1234
        }});
        validate_record(&catalog, "com.example.bl", &full).unwrap();
    }

    #[test]
    fn validate_bytes_length_uses_decoded_len() {
        // M22: $bytes length is the decoded byte count, and invalid base64 is
        // rejected. "AAA=" decodes to 2 bytes.
        let catalog = single_field_catalog(
            "com.example.by",
            "by",
            serde_json::json!({"type": "bytes", "maxLength": 2}),
        );
        // 2 decoded bytes, within maxLength 2.
        let ok = serde_json::json!({"by": {"$bytes": "AAA="}});
        validate_record(&catalog, "com.example.by", &ok).unwrap();
        // 3 decoded bytes, over maxLength 2.
        let too_long = serde_json::json!({"by": {"$bytes": "AAAA"}});
        assert!(validate_record(&catalog, "com.example.by", &too_long).is_err());
        // Not valid base64.
        let bad = serde_json::json!({"by": {"$bytes": "!!!!"}});
        assert!(validate_record(&catalog, "com.example.by", &bad).is_err());
        // Unpadded base64 counts the same.
        let unpadded = serde_json::json!({"by": {"$bytes": "AAA"}});
        validate_record(&catalog, "com.example.by", &unpadded).unwrap();
        // A bare string is not bytes.
        let bare = serde_json::json!({"by": "AA"});
        assert!(validate_record(&catalog, "com.example.by", &bare).is_err());
    }

    fn string_catalog(schema: serde_json::Value) -> Catalog {
        single_field_catalog("com.example.s", "s", schema)
    }

    fn check_string(catalog: &Catalog, s: &str) -> bool {
        validate_record(catalog, "com.example.s", &serde_json::json!({ "s": s })).is_ok()
    }

    #[test]
    fn graphemes_count_extended_clusters() {
        let catalog = string_catalog(
            serde_json::json!({"type": "string", "minGraphemes": 2, "maxGraphemes": 3}),
        );
        // Family emoji (ZWJ sequence): one grapheme, seven code points.
        let family = "\u{1F469}\u{200D}\u{1F469}\u{200D}\u{1F466}\u{200D}\u{1F466}";
        // Flag (regional indicator pair): one grapheme, two code points.
        let flag = "\u{1F1E9}\u{1F1EA}";
        // "e" + combining acute: one grapheme.
        let accent = "e\u{0301}";
        assert!(!check_string(&catalog, family));
        assert!(check_string(&catalog, &family.repeat(2)));
        assert!(check_string(&catalog, &format!("{flag}{family}{accent}")));
        assert!(!check_string(&catalog, &flag.repeat(4)));
        assert!(!check_string(&catalog, "a"));
        assert!(!check_string(&catalog, "abcd"));
        assert!(check_string(&catalog, "abc"));
    }

    #[test]
    fn uri_format() {
        let catalog = string_catalog(serde_json::json!({"type": "string", "format": "uri"}));
        for ok in [
            "https://example.com",
            "https://example.com/path?q=1#frag",
            "at://did:plc:abc/app.bsky.feed.post/1",
            "did:plc:abc",
            "mailto:a@b.c",
            "a_b:c",
            "x://y",
        ] {
            assert!(check_string(&catalog, ok), "{ok}");
        }
        for bad in [
            "123",
            "",
            ":nope",
            "https:",
            "https://",
            "https:///x",
            "https:/x",
            "https://exa mple.com",
            "https://example.com\n",
            "ht-tp://example.com",
            "https://\u{feff}x",
        ] {
            assert!(!check_string(&catalog, bad), "{bad:?}");
        }
    }

    #[test]
    fn cid_format() {
        let catalog = string_catalog(serde_json::json!({"type": "string", "format": "cid"}));
        for ok in [
            // CIDv1 DRISL, base32.
            "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq",
            // CIDv1 raw.
            "bafkreie5cvv4h45feadgeuwhbcutmh6t2ceseocckahdoe6uat64zmz454",
            // CIDv0.
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            // CIDv1 dag-pb, which DRISL links cannot hold but the format allows.
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        ] {
            assert!(check_string(&catalog, ok), "{ok}");
        }
        for bad in [
            "123",
            "",
            "bafyrei",
            "Bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabwq",
            "bafyreiclp443lavogvhj3d2ob2cxbfuscni2k5jk7bebjzg7khl3esabw",
        ] {
            assert!(!check_string(&catalog, bad), "{bad:?}");
        }
    }

    #[test]
    fn required_field_satisfied_by_default() {
        let doc = serde_json::json!({
            "lexicon": 1,
            "id": "com.example.d",
            "defs": {"main": {"type": "record", "record": {
                "type": "object",
                "required": ["flag", "name"],
                "properties": {
                    "flag": {"type": "boolean", "default": false},
                    "name": {"type": "string"}
                }
            }}}
        });
        let mut catalog = Catalog::new();
        catalog.add_schema(doc.to_string().as_bytes()).unwrap();
        validate_record(&catalog, "com.example.d", &serde_json::json!({"name": "x"})).unwrap();
        let err = validate_record(
            &catalog,
            "com.example.d",
            &serde_json::json!({"flag": true}),
        )
        .unwrap_err();
        assert!(err.to_string().contains("name"), "{err}");
    }

    fn xrpc_catalog() -> Catalog {
        let docs = [
            serde_json::json!({
                "lexicon": 1,
                "id": "com.example.query",
                "defs": {
                    "main": {
                        "type": "query",
                        "parameters": {
                            "type": "params",
                            "required": ["str", "arr"],
                            "properties": {
                                "str": {"type": "string", "minLength": 2},
                                "int": {"type": "integer", "minimum": 0, "default": 7},
                                "flag": {"type": "boolean"},
                                "arr": {"type": "array", "maxLength": 2, "items": {"type": "integer"}},
                                "handle": {"type": "string", "format": "handle"}
                            }
                        },
                        "output": {
                            "encoding": "application/json",
                            "schema": {"type": "ref", "ref": "#out"}
                        }
                    },
                    "out": {
                        "type": "object",
                        "required": ["n"],
                        "properties": {"n": {"type": "integer"}}
                    }
                }
            }),
            serde_json::json!({
                "lexicon": 1,
                "id": "com.example.procedure",
                "defs": {
                    "main": {
                        "type": "procedure",
                        "parameters": {
                            "type": "params",
                            "properties": {"mode": {"type": "string", "default": "fast"}}
                        },
                        "input": {
                            "encoding": "application/json",
                            "schema": {
                                "type": "object",
                                "required": ["inner"],
                                "properties": {
                                    "inner": {"type": "ref", "ref": "#inner"},
                                    "items": {"type": "array", "items": {"type": "ref", "ref": "#inner"}},
                                    "choice": {"type": "union", "refs": ["#inner"]},
                                    "top": {"type": "integer", "default": 1}
                                }
                            }
                        }
                    },
                    "inner": {
                        "type": "object",
                        "properties": {
                            "on": {"type": "boolean", "default": true},
                            "label": {"type": "string"}
                        }
                    }
                }
            }),
            serde_json::json!({
                "lexicon": 1,
                "id": "com.example.blobs",
                "defs": {"main": {"type": "procedure", "input": {"encoding": "*/*"}}}
            }),
            serde_json::json!({
                "lexicon": 1,
                "id": "com.example.subscribe",
                "defs": {
                    "main": {
                        "type": "subscription",
                        "parameters": {"type": "params", "properties": {"cursor": {"type": "integer"}}},
                        "message": {"schema": {"type": "union", "refs": ["#tick"], "closed": true}}
                    },
                    "tick": {
                        "type": "object",
                        "required": ["seq"],
                        "properties": {"seq": {"type": "integer"}}
                    }
                }
            }),
        ];
        let mut catalog = Catalog::new();
        for doc in docs {
            catalog.add_schema(doc.to_string().as_bytes()).unwrap();
        }
        catalog
    }

    fn params(v: serde_json::Value) -> serde_json::Map<String, serde_json::Value> {
        v.as_object().unwrap().clone()
    }

    #[test]
    fn params_apply_defaults_and_keep_unknown_keys() {
        let catalog = xrpc_catalog();
        let mut p = params(serde_json::json!({"str": "ab", "arr": [1, 2], "extra": "x"}));
        validate_params(&catalog, "com.example.query", &mut p).unwrap();
        assert_eq!(
            serde_json::Value::Object(p),
            serde_json::json!({"str": "ab", "arr": [1, 2], "extra": "x", "int": 7})
        );

        // An explicit value is kept.
        let mut p = params(serde_json::json!({"str": "ab", "arr": [], "int": 3}));
        validate_params(&catalog, "com.example.query", &mut p).unwrap();
        assert_eq!(p["int"], 3);

        let mut p = serde_json::Map::new();
        validate_params(&catalog, "com.example.procedure", &mut p).unwrap();
        assert_eq!(p["mode"], "fast");
    }

    #[test]
    fn params_reject_invalid_values() {
        let catalog = xrpc_catalog();
        let cases = [
            (serde_json::json!({"arr": []}), "str"),
            (serde_json::json!({"str": "ab"}), "arr"),
            (serde_json::json!({"str": "a", "arr": []}), "str"),
            (serde_json::json!({"str": "ab", "arr": [1, 2, 3]}), "arr"),
            (serde_json::json!({"str": "ab", "arr": ["x"]}), "arr[0]"),
            (serde_json::json!({"str": "ab", "arr": 1}), "arr"),
            (
                serde_json::json!({"str": "ab", "arr": [], "int": -1}),
                "int",
            ),
            (
                serde_json::json!({"str": "ab", "arr": [], "flag": "true"}),
                "flag",
            ),
            (
                serde_json::json!({"str": "ab", "arr": [], "handle": "not a handle"}),
                "handle",
            ),
        ];
        for (value, field) in cases {
            let mut p = params(value.clone());
            let err = validate_params(&catalog, "com.example.query", &mut p).unwrap_err();
            assert!(err.to_string().contains(field), "{value}: {err}");
        }
    }

    #[test]
    fn params_reject_non_methods_and_unknown_lexicons() {
        let catalog = xrpc_catalog();
        assert!(
            validate_params(&catalog, "com.example.missing", &mut serde_json::Map::new()).is_err()
        );
        let mut records = Catalog::new();
        records.add_schema(POST_SCHEMA.as_bytes()).unwrap();
        assert!(
            validate_params(&records, "app.bsky.feed.post", &mut serde_json::Map::new()).is_err()
        );
    }

    #[test]
    fn input_validates_and_fills_nested_defaults() {
        let catalog = xrpc_catalog();
        let mut input = serde_json::json!({
            "inner": {"label": "a"},
            "items": [{}, {"on": false}],
            "choice": {"$type": "com.example.procedure#inner"}
        });
        validate_input(&catalog, "com.example.procedure", &mut input).unwrap();
        assert_eq!(
            input,
            serde_json::json!({
                "inner": {"label": "a", "on": true},
                "items": [{"on": true}, {"on": false}],
                "choice": {"$type": "com.example.procedure#inner", "on": true},
                "top": 1
            })
        );

        let mut missing = serde_json::json!({});
        let err = validate_input(&catalog, "com.example.procedure", &mut missing).unwrap_err();
        assert!(err.to_string().contains("input.inner"), "{err}");
        // A failed validation leaves the value untouched.
        assert_eq!(missing, serde_json::json!({}));

        let mut bad = serde_json::json!({"inner": {"on": "yes"}});
        let err = validate_input(&catalog, "com.example.procedure", &mut bad).unwrap_err();
        assert!(err.to_string().contains("input.inner.on"), "{err}");

        // No input schema: anything passes.
        validate_input(&catalog, "com.example.blobs", &mut serde_json::json!("x")).unwrap();
        // Queries have no input.
        assert!(validate_input(&catalog, "com.example.query", &mut serde_json::json!({})).is_err());
    }

    #[test]
    fn output_and_message_validation() {
        let catalog = xrpc_catalog();
        validate_output(&catalog, "com.example.query", &serde_json::json!({"n": 1})).unwrap();
        let err =
            validate_output(&catalog, "com.example.query", &serde_json::json!({})).unwrap_err();
        assert!(err.to_string().contains("output.n"), "{err}");
        // A procedure without an output schema passes anything.
        validate_output(&catalog, "com.example.procedure", &serde_json::json!(1)).unwrap();

        let ok = serde_json::json!({"$type": "com.example.subscribe#tick", "seq": 1});
        validate_message(&catalog, "com.example.subscribe", &ok).unwrap();
        for bad in [
            serde_json::json!({"$type": "com.example.subscribe#tick"}),
            serde_json::json!({"$type": "com.example.subscribe#other", "seq": 1}),
            serde_json::json!({"seq": 1}),
        ] {
            assert!(
                validate_message(&catalog, "com.example.subscribe", &bad).is_err(),
                "{bad}"
            );
        }
        assert!(validate_message(&catalog, "com.example.query", &ok).is_err());
    }
}
