# lexgen — AT Protocol Code Generator for Rust

**Date:** 2026-04-05
**Status:** Draft

## Goal

Generate Rust types and XRPC endpoint functions from AT Protocol Lexicon JSON schemas, producing the `ratproto-api` crate.

## Pipeline

```
lexicons/*.json → ratproto-lexicon (parse) → lexgen (generate) → crates/ratproto-api/src/**/*.rs
```

1. `just update-lexicons` copies JSON schemas from local `bluesky-social/atproto` checkout into `lexicons/`
2. `just lexgen` runs the generator binary
3. Generated code depends on `ratproto-syntax`, `ratproto-cbor`, `ratproto-xrpc`, `serde`, `serde_json`

## Config

`lexgen.json`:
```json
{
    "packages": [
        {"prefix": "app.bsky", "module": "app::bsky", "out_dir": "crates/ratproto-api/src/app/bsky"},
        {"prefix": "com.atproto", "module": "com::atproto", "out_dir": "crates/ratproto-api/src/com/atproto"},
        {"prefix": "chat.bsky", "module": "chat::bsky", "out_dir": "crates/ratproto-api/src/chat/bsky"},
        {"prefix": "tools.ozone", "module": "tools::ozone", "out_dir": "crates/ratproto-api/src/tools/ozone"}
    ]
}
```

## Lexicon → Rust Type Mapping

| Lexicon Type | Rust Output |
|---|---|
| `record` | Struct with `NSID` constant, serde derives, `to_cbor()`/`from_cbor()`, extras |
| `object` | Struct with serde derives, `to_cbor()`/`from_cbor()`, extras |
| `query` | Params struct + Output struct + async endpoint function |
| `procedure` | Input struct + Output struct + async endpoint function |
| `subscription` | Params struct |
| `union` | Enum with typed variants + `Unknown` for open unions |
| `string` (known_values) | Type alias + constants |
| `token` | String constant |
| `array` (top-level) | Type alias to `Vec<T>` |

### Field Type Mapping

| Lexicon Field | Rust Type |
|---|---|
| `string` | `String` |
| `string` format=datetime | `Datetime` |
| `string` format=did | `Did` |
| `string` format=handle | `Handle` |
| `string` format=at-uri | `AtUri` |
| `string` format=nsid | `Nsid` |
| `string` format=tid | `Tid` |
| `string` format=language | `Language` |
| `string` format=record-key | `RecordKey` |
| `string` format=uri | `String` |
| `integer` | `i64` |
| `boolean` | `bool` |
| `bytes` | `Vec<u8>` |
| `cid-link` | `Cid` |
| `blob` | `LexBlob` |
| `ref` | Resolved Rust type name |
| `union` | Generated enum |
| `unknown` | `UnknownValue` |

Required fields are bare types. Optional fields are `Option<T>`.

### Naming Convention

- `app.bsky.feed.post` + def `main` → `FeedPost`
- `app.bsky.feed.post` + def `replyRef` → `FeedPostReplyRef`
- `app.bsky.actor.defs` + def `profileViewBasic` → `ActorDefsProfileViewBasic`

## Generated Struct Shape

```rust
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FeedPost {
    pub text: String,
    pub created_at: Datetime,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reply: Option<FeedPostReplyRef>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub embed: Option<FeedPostEmbed>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub langs: Vec<Language>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,

    /// Unknown fields for JSON round-trip fidelity.
    #[serde(flatten)]
    #[serde(default)]
    #[serde(skip_serializing_if = "HashMap::is_empty")]
    pub extra: HashMap<String, serde_json::Value>,

    /// Unknown fields for CBOR round-trip fidelity.
    #[serde(skip)]
    pub extra_cbor: Vec<(String, Vec<u8>)>,
}
```

### CBOR Encoding

`to_cbor()` has two paths:
- **Fast path** (no extras): emit pre-sorted known fields with pre-computed DRISL key bytes. Zero allocation for key encoding.
- **Slow path** (has extras): merge-sort known + unknown fields in canonical DRISL order.

`from_cbor()` dispatches by key byte length then name comparison against pre-computed key slices. Unknown keys stored as raw bytes in `extra_cbor`. No String allocation for known keys.

### Ergonomics

- `Default` derive on all structs so users can `FeedPost { text: "hi".into(), ..Default::default() }`
- `$type` field not stored on records — the NSID constant is emitted on CBOR serialization automatically
- `#[serde(rename_all = "camelCase")]` handles JSON field name conversion

## Union Shape

### Open Unions

```rust
#[derive(Debug, Clone)]
pub enum FeedPostEmbed {
    Images(EmbedImages),
    External(EmbedExternal),
    Record(EmbedRecord),
    RecordWithMedia(EmbedRecordWithMedia),
    Unknown(UnknownUnionVariant),
}
```

Custom `Serialize`/`Deserialize` — no serde derives. JSON deserialization peeks `$type` from the raw value, dispatches in one shot (no trial-and-error). CBOR deserialization peeks `$type` from the CBOR map, dispatches to the correct variant's `from_cbor()`.

### Closed Unions

Same enum but without the `Unknown` variant. Unrecognized `$type` returns an error.

## XRPC Endpoint Functions

Query endpoints:
```rust
pub async fn get_timeline(
    client: &ratproto_xrpc::Client,
    params: &GetTimelineParams,
) -> Result<GetTimelineOutput, ratproto_xrpc::Error> {
    client.query("app.bsky.feed.getTimeline", params).await
}
```

Procedure endpoints:
```rust
pub async fn create_record(
    client: &ratproto_xrpc::Client,
    input: &RepoCreateRecordInput,
) -> Result<RepoCreateRecordOutput, ratproto_xrpc::Error> {
    client.procedure("com.atproto.repo.createRecord", input).await
}
```

Params/Output structs only get serde derives (no CBOR) — XRPC is JSON over HTTP.

## Shared Types

```rust
/// Blob reference
pub struct LexBlob {
    pub r#ref: LexCidLink,
    pub mime_type: String,
    pub size: i64,
}

/// CID link in JSON ({"$link": "bafy..."})
pub struct LexCidLink {
    pub link: String,
}

/// Unknown union variant (open unions)
pub struct UnknownUnionVariant {
    pub r#type: String,
    pub json: Option<serde_json::Value>,
    pub cbor: Option<Vec<u8>>,
}

/// Unknown field value
pub enum UnknownValue {
    Json(serde_json::Value),
    Cbor(Vec<u8>),
}
```

## Generated File Structure

```
crates/ratproto-api/src/
├── lib.rs              # Shared types, re-exports
├── app/
│   ├── mod.rs
│   └── bsky/
│       ├── mod.rs
│       ├── actor_defs.rs
│       ├── feed_post.rs
│       ├── feed_get_timeline.rs
│       └── ...
├── com/
│   ├── mod.rs
│   └── atproto/
│       ├── mod.rs
│       ├── repo_create_record.rs
│       └── ...
├── chat/
│   └── bsky/ ...
└── tools/
    └── ozone/ ...
```

Cross-module refs resolve to `crate::com::atproto::RepoStrongRef` etc.

## Lexicon Syncing

`just update-lexicons` copies from `../../bluesky-social/atproto/lexicons/` (relative to repo root, matching the Go path layout). Vendored into `lexicons/` in the rat repo.

## Justfile Recipes

```just
# Copy lexicons from local atproto checkout
update-lexicons:
    rm -rf lexicons/*
    cp -r ../../bluesky-social/atproto/lexicons/* lexicons

# Run the code generator
lexgen:
    cargo run --bin lexgen -- --lexdir lexicons --config lexgen.json

# Update lexicons and regenerate
update-api: update-lexicons lexgen
```

## Testing Strategy

- **Generator unit tests**: Parse a small schema, generate code, verify the output string contains expected structs/fields/derives
- **Roundtrip tests**: Generate types, compile them, serialize → deserialize and verify equality (JSON and CBOR)
- **Snapshot tests**: Compare generated output against known-good snapshots for a subset of schemas
- **Integration**: Run the full generator against the vendored lexicons and verify `cargo build -p ratproto-api` compiles
