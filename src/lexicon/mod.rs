mod catalog;
mod error;
mod schema;
mod validate;

pub use catalog::Catalog;
pub use error::{LexiconError, ValidationError, ValidationErrorKind};
pub use schema::{
    ArrayTypeDef, BodyDef, BooleanTypeDef, BytesTypeDef, Def, ErrorDef, FieldSchema,
    IntegerTypeDef, MessageDef, ObjectDef, ParamsDef, ProcedureDef, QueryDef, RecordDef, Schema,
    StringTypeDef, SubscriptionDef, TokenDef, split_ref,
};
pub use validate::{validate_record, validate_value};

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

        let invalid = serde_json::json!({"root": "not-an-object"});
        assert!(validate_record(&catalog, "com.example.linked", &invalid).is_err());
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
}
