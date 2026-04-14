use std::collections::HashMap;

use serde::Deserialize;

/// A parsed Lexicon schema document.
#[derive(Debug, Deserialize)]
pub struct Schema {
    pub lexicon: u32,
    pub id: String,
    #[serde(default)]
    pub revision: Option<u32>,
    #[serde(default)]
    pub description: Option<String>,
    pub defs: HashMap<String, Def>,
}

/// A single named definition within a schema.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[allow(clippy::enum_variant_names)]
pub enum Def {
    #[serde(rename = "record")]
    Record(RecordDef),
    #[serde(rename = "query")]
    Query(QueryDef),
    #[serde(rename = "procedure")]
    Procedure(ProcedureDef),
    #[serde(rename = "subscription")]
    Subscription(SubscriptionDef),
    #[serde(rename = "object")]
    Object(ObjectDef),
    #[serde(rename = "token")]
    Token(TokenDef),
    #[serde(rename = "string")]
    StringDef(StringTypeDef),
    #[serde(rename = "boolean")]
    BooleanDef(BooleanTypeDef),
    #[serde(rename = "integer")]
    IntegerDef(IntegerTypeDef),
    #[serde(rename = "bytes")]
    BytesDef(BytesTypeDef),
    #[serde(rename = "array")]
    ArrayDef(ArrayTypeDef),
    /// A definition type not yet modelled (e.g. future lexicon extensions).
    #[serde(other)]
    Unknown,
}

/// A record definition — the main type for AT Protocol records.
#[derive(Debug, Deserialize)]
pub struct RecordDef {
    #[serde(default)]
    pub key: Option<String>,
    pub record: ObjectDef,
    #[serde(default)]
    pub description: Option<String>,
}

/// An object definition with named properties.
#[derive(Debug, Deserialize)]
pub struct ObjectDef {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub nullable: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, FieldSchema>,
    #[serde(default)]
    pub description: Option<String>,
}

/// The schema for a single field within an object or array.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
pub enum FieldSchema {
    #[serde(rename = "string")]
    String {
        #[serde(default, rename = "minLength")]
        min_length: Option<u64>,
        #[serde(default, rename = "maxLength")]
        max_length: Option<u64>,
        #[serde(default, rename = "maxGraphemes")]
        max_graphemes: Option<u64>,
        #[serde(default, rename = "knownValues")]
        known_values: Vec<String>,
        #[serde(default)]
        r#enum: Option<Vec<String>>,
        #[serde(default)]
        format: Option<String>,
        #[serde(default)]
        description: Option<String>,
        #[serde(default)]
        default: Option<String>,
        #[serde(default, rename = "const")]
        const_val: Option<String>,
    },
    #[serde(rename = "integer")]
    Integer {
        #[serde(default)]
        minimum: Option<i64>,
        #[serde(default)]
        maximum: Option<i64>,
        #[serde(default)]
        r#enum: Option<Vec<i64>>,
        #[serde(default)]
        default: Option<i64>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "boolean")]
    Boolean {
        #[serde(default)]
        default: Option<bool>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "bytes")]
    Bytes {
        #[serde(default, rename = "minLength")]
        min_length: Option<u64>,
        #[serde(default, rename = "maxLength")]
        max_length: Option<u64>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "cid-link")]
    CidLink {
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "blob")]
    Blob {
        #[serde(default)]
        accept: Option<Vec<String>>,
        #[serde(default, rename = "maxSize")]
        max_size: Option<u64>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "array")]
    Array {
        items: Box<FieldSchema>,
        #[serde(default, rename = "minLength")]
        min_length: Option<u64>,
        #[serde(default, rename = "maxLength")]
        max_length: Option<u64>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "object")]
    Object(ObjectDef),
    #[serde(rename = "ref")]
    Ref {
        #[serde(rename = "ref")]
        reference: String,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "union")]
    Union {
        refs: Vec<String>,
        #[serde(default)]
        closed: Option<bool>,
        #[serde(default)]
        description: Option<String>,
    },
    #[serde(rename = "unknown")]
    Unknown {
        #[serde(default)]
        description: Option<String>,
    },
}

impl FieldSchema {
    /// Returns the description field if present on this schema variant.
    pub fn description(&self) -> Option<&str> {
        match self {
            FieldSchema::String { description, .. }
            | FieldSchema::Integer { description, .. }
            | FieldSchema::Boolean { description, .. }
            | FieldSchema::Bytes { description, .. }
            | FieldSchema::CidLink { description, .. }
            | FieldSchema::Blob { description, .. }
            | FieldSchema::Array { description, .. }
            | FieldSchema::Ref { description, .. }
            | FieldSchema::Union { description, .. }
            | FieldSchema::Unknown { description, .. } => description.as_deref(),
            FieldSchema::Object(_) => None,
        }
    }
}

/// A query (XRPC GET) definition.
#[derive(Debug, Deserialize)]
pub struct QueryDef {
    #[serde(default)]
    pub parameters: Option<ParamsDef>,
    #[serde(default)]
    pub output: Option<BodyDef>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub errors: Vec<ErrorDef>,
}

/// A procedure (XRPC POST) definition.
#[derive(Debug, Deserialize)]
pub struct ProcedureDef {
    #[serde(default)]
    pub input: Option<BodyDef>,
    #[serde(default)]
    pub output: Option<BodyDef>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub errors: Vec<ErrorDef>,
}

/// A subscription definition.
#[derive(Debug, Deserialize)]
pub struct SubscriptionDef {
    #[serde(default)]
    pub parameters: Option<ParamsDef>,
    #[serde(default)]
    pub message: Option<MessageDef>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub errors: Vec<ErrorDef>,
}

/// A request or response body.
#[derive(Debug, Deserialize)]
pub struct BodyDef {
    pub encoding: String,
    #[serde(default)]
    pub schema: Option<FieldSchema>,
    #[serde(default)]
    pub description: Option<String>,
}

/// Query/subscription parameter definitions.
///
/// These have `"type": "params"` in the JSON but are structurally similar to
/// objects with `properties` and `required`.
#[derive(Debug, Deserialize)]
pub struct ParamsDef {
    #[serde(default)]
    pub required: Vec<String>,
    #[serde(default)]
    pub properties: HashMap<String, FieldSchema>,
    #[serde(default)]
    pub description: Option<String>,
}

/// A subscription message definition.
#[derive(Debug, Deserialize)]
pub struct MessageDef {
    #[serde(default)]
    pub schema: Option<FieldSchema>,
    #[serde(default)]
    pub description: Option<String>,
}

/// An error that an endpoint can return.
#[derive(Debug, Deserialize)]
pub struct ErrorDef {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
}

/// A token definition (an opaque string constant).
#[derive(Debug, Deserialize)]
pub struct TokenDef {
    #[serde(default)]
    pub description: Option<String>,
}

/// A top-level string type definition.
#[derive(Debug, Deserialize)]
pub struct StringTypeDef {
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default, rename = "knownValues")]
    pub known_values: Vec<String>,
}

/// A top-level boolean type definition.
#[derive(Debug, Deserialize)]
pub struct BooleanTypeDef {
    #[serde(default)]
    pub description: Option<String>,
}

/// A top-level integer type definition.
#[derive(Debug, Deserialize)]
pub struct IntegerTypeDef {
    #[serde(default)]
    pub description: Option<String>,
}

/// A top-level bytes type definition.
#[derive(Debug, Deserialize)]
pub struct BytesTypeDef {
    #[serde(default)]
    pub description: Option<String>,
}

/// A top-level array type definition.
#[derive(Debug, Deserialize)]
pub struct ArrayTypeDef {
    pub items: FieldSchema,
    #[serde(default)]
    pub description: Option<String>,
}

/// Split a ref string into (target_nsid, def_name), resolving relative refs against
/// the given context NSID.
///
/// Examples:
/// - `"#replyRef"` with context `"app.bsky.feed.post"` → `("app.bsky.feed.post", "replyRef")`
/// - `"com.atproto.repo.defs#commitMeta"` → `("com.atproto.repo.defs", "commitMeta")`
/// - `"com.atproto.repo.strongRef"` → `("com.atproto.repo.strongRef", "main")`
pub fn split_ref<'a>(context_nsid: &str, reference: &'a str) -> (String, &'a str) {
    if let Some(def_name) = reference.strip_prefix('#') {
        (context_nsid.to_owned(), def_name)
    } else if let Some(hash_pos) = reference.rfind('#') {
        (reference[..hash_pos].to_owned(), &reference[hash_pos + 1..])
    } else {
        (reference.to_owned(), "main")
    }
}
