#![no_main]

use libfuzzer_sys::fuzz_target;
use ratproto_lexicon::{Catalog, validate_record};

// Fuzz record validation against a known schema with arbitrary JSON input.
//
// Uses a fixed Lexicon schema (app.bsky.feed.post) and feeds arbitrary bytes
// as the record to validate. This exercises the validation code paths that
// handle malformed or unexpected record structures.
fuzz_target!(|data: &[u8]| {
    // Parse the fuzz input as JSON. If it's not valid JSON, skip.
    let record: serde_json::Value = match serde_json::from_slice(data) {
        Ok(v) => v,
        Err(_) => return,
    };

    // Use a fixed schema so the fuzzer focuses on the validation paths.
    let schema_json = r##"{
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
                        "createdAt": { "type": "string", "format": "datetime" },
                        "reply": { "type": "ref", "ref": "#replyRef" },
                        "langs": { "type": "array", "items": { "type": "string" }, "maxLength": 3 }
                    }
                }
            },
            "replyRef": {
                "type": "object",
                "required": ["root", "parent"],
                "properties": {
                    "root": { "type": "string" },
                    "parent": { "type": "string" }
                }
            }
        }
    }"##;

    let mut catalog = Catalog::new();
    // This should always succeed since the schema is hardcoded and valid.
    if catalog.add_schema(schema_json.as_bytes()).is_err() {
        return;
    }

    // Validate — any error is expected; panics are bugs.
    let _ = validate_record(&catalog, "app.bsky.feed.post", &record);
});
