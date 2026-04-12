# lexgen Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a code generator that reads AT Protocol Lexicon JSON schemas and produces the `shrike-api` crate — typed Rust structs with serde JSON + hand-rolled DRISL CBOR encoding, union dispatch, extra field preservation, and XRPC endpoint functions.

**Architecture:** The `lexgen` binary reads `lexgen.json` config + `lexicons/**/*.json` schemas, resolves cross-schema references, and emits `.rs` files into `crates/shrike-api/src/`. The generator is structured as a pipeline: parse → resolve → generate structs → generate CBOR → generate unions → generate endpoints → write files. Each stage is independently testable.

**Tech Stack:** Rust, serde_json (for schema parsing), shrike-lexicon (schema types), string-based code generation (no proc macros)

**Design spec:** `docs/superpowers/specs/2026-04-05-lexgen-design.md`
**Reference implementation:** `/home/jcalabro/go/src/github.com/jcalabro/atmos/lexgen/`

---

## File Structure

```
tools/lexgen/
  Cargo.toml                    # Already exists (modify)
  src/
    main.rs                     # CLI: parse args, load config, run pipeline
    config.rs                   # Config types (lexgen.json)
    loader.rs                   # Recursively load + parse lexicon JSON files
    resolver.rs                 # Cross-schema ref resolution, type name generation
    gen_struct.rs               # Generate struct definitions
    gen_cbor.rs                 # Generate to_cbor/from_cbor methods
    gen_union.rs                # Generate union enums with custom serde
    gen_endpoint.rs             # Generate XRPC query/procedure functions
    gen_module.rs               # Generate mod.rs files and file organization
    gen_shared.rs               # Generate shared types (LexBlob, etc.)
    codegen.rs                  # Orchestrator: ties all generators together
    util.rs                     # String helpers (snake_case, type names, etc.)

lexgen.json                     # Config file (create)
lexicons/                       # Vendored lexicon JSON schemas (copy from atproto)
justfile                        # Add update-lexicons and lexgen recipes (modify)

crates/shrike-api/
  Cargo.toml                    # Already exists (modify deps)
  src/lib.rs                    # Generated: shared types + module re-exports
  src/app/bsky/*.rs             # Generated
  src/com/atproto/*.rs          # Generated
  src/chat/bsky/*.rs            # Generated
  src/tools/ozone/*.rs          # Generated
```

---

## Task 1: Infrastructure — Config, Justfile, Lexicon Sync

**Files:**
- Create: `lexgen.json`
- Modify: `justfile`
- Modify: `tools/lexgen/Cargo.toml`
- Create: `tools/lexgen/src/config.rs`
- Create: `tools/lexgen/src/util.rs`
- Modify: `tools/lexgen/src/main.rs`

- [ ] **Step 1: Create lexgen.json config**

```json
{
    "packages": [
        {"prefix": "app.bsky", "module": "app::bsky", "out_dir": "crates/shrike-api/src/app/bsky"},
        {"prefix": "com.atproto", "module": "com::atproto", "out_dir": "crates/shrike-api/src/com/atproto"},
        {"prefix": "chat.bsky", "module": "chat::bsky", "out_dir": "crates/shrike-api/src/chat/bsky"},
        {"prefix": "tools.ozone", "module": "tools::ozone", "out_dir": "crates/shrike-api/src/tools/ozone"}
    ]
}
```

- [ ] **Step 2: Update justfile with lexicon recipes**

Add to the existing justfile:
```just
# Copy lexicons from local atproto checkout
update-lexicons:
    rm -rf lexicons/*
    cp -r ../../../bluesky-social/atproto/lexicons/* lexicons

# Run the code generator
lexgen:
    cargo run --bin lexgen -- --lexdir lexicons --config lexgen.json

# Update lexicons and regenerate
update-api: update-lexicons lexgen
```

- [ ] **Step 3: Copy lexicons**

```bash
mkdir -p lexicons
cp -r /home/jcalabro/go/src/github.com/bluesky-social/atproto/lexicons/* lexicons/
```

- [ ] **Step 4: Implement config.rs and util.rs**

`tools/lexgen/src/config.rs`:
```rust
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub packages: Vec<PackageConfig>,
}

#[derive(Debug, Deserialize)]
pub struct PackageConfig {
    pub prefix: String,
    pub module: String,
    pub out_dir: String,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self, Box<dyn std::error::Error>> {
        let data = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data)?)
    }

    /// Find the package config for a given NSID (longest prefix match).
    pub fn find_package(&self, nsid: &str) -> Option<&PackageConfig> {
        self.packages.iter()
            .filter(|p| nsid.starts_with(&p.prefix))
            .max_by_key(|p| p.prefix.len())
    }
}
```

`tools/lexgen/src/util.rs`:
```rust
/// Convert an NSID + def name to a Rust type name.
/// "app.bsky.feed.post" + "main" → "FeedPost"
/// "app.bsky.feed.post" + "replyRef" → "FeedPostReplyRef"
/// "app.bsky.actor.defs" + "profileViewBasic" → "ActorDefsProfileViewBasic"
pub fn type_name(nsid: &str, def_name: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    let base = if parts.len() >= 2 {
        format!("{}{}", capitalize(parts[parts.len() - 2]), capitalize(parts[parts.len() - 1]))
    } else {
        capitalize(nsid)
    };
    if def_name == "main" {
        base
    } else {
        format!("{}{}", base, capitalize(def_name))
    }
}

/// Convert a JSON camelCase field name to Rust snake_case.
pub fn to_snake_case(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() {
            if i > 0 { result.push('_'); }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    // Handle $ prefix (e.g. "$type" -> "r#type")
    result
}

/// Sanitize a field name for Rust (handle reserved words and $-prefixed names)
pub fn rust_field_name(json_name: &str) -> String {
    if json_name == "$type" {
        return "r#type".to_string();
    }
    let snake = to_snake_case(json_name);
    match snake.as_str() {
        "type" | "ref" | "self" | "mod" | "use" | "fn" | "struct" | "enum"
        | "impl" | "trait" | "pub" | "let" | "mut" | "const" | "static"
        | "match" | "if" | "else" | "for" | "while" | "loop" | "return"
        | "break" | "continue" | "move" | "box" | "where" | "async"
        | "await" | "dyn" | "abstract" | "become" | "do" | "final"
        | "macro" | "override" | "priv" | "typeof" | "unsized" | "virtual"
        | "yield" | "try" => format!("r#{snake}"),
        _ => snake,
    }
}

pub fn capitalize(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().to_string() + chars.as_str(),
    }
}

/// NSID → file name: "app.bsky.feed.post" → "feed_post.rs"
pub fn schema_file_name(nsid: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() >= 2 {
        let name = format!("{}_{}", parts[parts.len() - 2], parts[parts.len() - 1]);
        format!("{}.rs", to_snake_case(&name))
    } else {
        format!("{}.rs", to_snake_case(nsid))
    }
}
```

- [ ] **Step 5: Update lexgen Cargo.toml**

Add dependencies:
```toml
[dependencies]
shrike-lexicon = { path = "../../crates/shrike-lexicon" }
shrike-syntax = { path = "../../crates/shrike-syntax" }
serde.workspace = true
serde_json.workspace = true
```

- [ ] **Step 6: Write tests for util.rs**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_type_name() {
        assert_eq!(type_name("app.bsky.feed.post", "main"), "FeedPost");
        assert_eq!(type_name("app.bsky.feed.post", "replyRef"), "FeedPostReplyRef");
        assert_eq!(type_name("app.bsky.actor.defs", "profileViewBasic"), "ActorDefsProfileViewBasic");
        assert_eq!(type_name("com.atproto.repo.strongRef", "main"), "RepoStrongRef");
    }

    #[test]
    fn test_to_snake_case() {
        assert_eq!(to_snake_case("createdAt"), "created_at");
        assert_eq!(to_snake_case("displayName"), "display_name");
        assert_eq!(to_snake_case("text"), "text");
        assert_eq!(to_snake_case("mimeType"), "mime_type");
    }

    #[test]
    fn test_rust_field_name() {
        assert_eq!(rust_field_name("$type"), "r#type");
        assert_eq!(rust_field_name("type"), "r#type");
        assert_eq!(rust_field_name("ref"), "r#ref");
        assert_eq!(rust_field_name("text"), "text");
        assert_eq!(rust_field_name("createdAt"), "created_at");
    }

    #[test]
    fn test_schema_file_name() {
        assert_eq!(schema_file_name("app.bsky.feed.post"), "feed_post.rs");
        assert_eq!(schema_file_name("app.bsky.actor.defs"), "actor_defs.rs");
        assert_eq!(schema_file_name("com.atproto.repo.createRecord"), "repo_create_record.rs");
    }
}
```

- [ ] **Step 7: Stub main.rs with arg parsing**

```rust
use std::path::PathBuf;

mod config;
mod util;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (lexdir, config_path) = parse_args(&args);
    let cfg = config::Config::load(&config_path).expect("failed to load config");
    eprintln!("Loaded config with {} packages", cfg.packages.len());
    eprintln!("Lexicon dir: {}", lexdir.display());
    // Pipeline stages will be added in subsequent tasks
}

fn parse_args(args: &[String]) -> (PathBuf, PathBuf) {
    let mut lexdir = None;
    let mut config = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--lexdir" => { i += 1; lexdir = Some(PathBuf::from(&args[i])); }
            "--config" => { i += 1; config = Some(PathBuf::from(&args[i])); }
            _ => { eprintln!("Unknown arg: {}", args[i]); std::process::exit(1); }
        }
        i += 1;
    }
    (
        lexdir.unwrap_or_else(|| { eprintln!("--lexdir required"); std::process::exit(1); }),
        config.unwrap_or_else(|| { eprintln!("--config required"); std::process::exit(1); }),
    )
}
```

- [ ] **Step 8: Verify and commit**

Run: `cargo build --bin lexgen && cargo test --bin lexgen`
Commit: `git commit -m "feat(lexgen): add config, util, justfile recipes, vendor lexicons"`

---

## Task 2: Schema Loader

**Files:**
- Create: `tools/lexgen/src/loader.rs`
- Modify: `tools/lexgen/src/main.rs`

- [ ] **Step 1: Implement loader.rs**

Recursively find all `.json` files in the lexicons directory, parse each as a `shrike_lexicon::Schema`:

```rust
use shrike_lexicon::Schema;
use std::path::Path;
use std::collections::HashMap;

/// Load all lexicon schemas from a directory tree.
pub fn load_schemas(dir: &Path) -> Result<HashMap<String, Schema>, Box<dyn std::error::Error>> {
    let mut schemas = HashMap::new();
    load_dir(dir, &mut schemas)?;
    Ok(schemas)
}

fn load_dir(dir: &Path, schemas: &mut HashMap<String, Schema>) -> Result<(), Box<dyn std::error::Error>> {
    for entry in std::fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            load_dir(&path, schemas)?;
        } else if path.extension().map_or(false, |e| e == "json") {
            let data = std::fs::read(&path)?;
            let schema: Schema = serde_json::from_slice(&data)
                .map_err(|e| format!("{}: {e}", path.display()))?;
            schemas.insert(schema.id.clone(), schema);
        }
    }
    Ok(())
}
```

- [ ] **Step 2: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn load_real_lexicons() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        assert!(schemas.len() > 300, "expected 300+ schemas, got {}", schemas.len());
        assert!(schemas.contains_key("app.bsky.feed.post"));
        assert!(schemas.contains_key("com.atproto.repo.createRecord"));
    }

    #[test]
    fn schema_has_expected_defs() {
        let schemas = load_schemas(Path::new("../../lexicons")).unwrap();
        let post = schemas.get("app.bsky.feed.post").unwrap();
        assert!(post.defs.contains_key("main"));
        assert!(post.defs.contains_key("replyRef"));
    }
}
```

- [ ] **Step 3: Wire into main.rs and commit**

Add `mod loader;` and call `loader::load_schemas()` in main. Print the count.
Commit: `git commit -m "feat(lexgen): implement schema loader with recursive directory walking"`

---

## Task 3: Reference Resolver and Type Name Resolution

**Files:**
- Create: `tools/lexgen/src/resolver.rs`

- [ ] **Step 1: Implement resolver.rs**

The resolver takes the loaded schemas + config and produces:
- A mapping from ref string → resolved Rust type path (e.g. `"com.atproto.repo.strongRef"` → `"crate::com::atproto::RepoStrongRef"`)
- A function to resolve any ref from any context schema

```rust
use crate::config::Config;
use crate::util;
use shrike_lexicon::schema::split_ref;
use std::collections::HashMap;

/// Resolved reference target
pub struct ResolvedRef {
    /// Rust type name (unqualified, e.g. "RepoStrongRef")
    pub type_name: String,
    /// Module path (e.g. "crate::com::atproto")
    pub module_path: String,
    /// The target NSID
    pub nsid: String,
    /// The def name within the schema
    pub def_name: String,
}

/// Resolve a ref string from the context of a given schema to a Rust type path.
pub fn resolve_ref(
    cfg: &Config,
    context_nsid: &str,
    reference: &str,
    schemas: &HashMap<String, shrike_lexicon::Schema>,
) -> Result<ResolvedRef, String> {
    let (target_nsid, def_name) = split_ref(context_nsid, reference);
    
    // Verify the target exists
    let target_schema = schemas.get(&target_nsid)
        .ok_or_else(|| format!("ref target not found: {target_nsid}"))?;
    if !target_schema.defs.contains_key(def_name) {
        return Err(format!("def not found: {target_nsid}#{def_name}"));
    }
    
    let type_name = util::type_name(&target_nsid, def_name);
    
    // Determine the module path based on config
    let pkg = cfg.find_package(&target_nsid)
        .ok_or_else(|| format!("no package config for: {target_nsid}"))?;
    let module_path = format!("crate::{}", pkg.module);
    
    Ok(ResolvedRef { type_name, module_path, nsid: target_nsid, def_name: def_name.to_string() })
}

/// Get the fully qualified Rust type for a ref, relative to the calling module.
pub fn qualified_type(
    resolved: &ResolvedRef,
    caller_module: &str,
) -> String {
    if resolved.module_path == caller_module {
        // Same module — use unqualified name
        resolved.type_name.clone()
    } else {
        format!("{}::{}", resolved.module_path, resolved.type_name)
    }
}
```

- [ ] **Step 2: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> Config {
        Config { packages: vec![
            crate::config::PackageConfig { prefix: "app.bsky".into(), module: "app::bsky".into(), out_dir: "".into() },
            crate::config::PackageConfig { prefix: "com.atproto".into(), module: "com::atproto".into(), out_dir: "".into() },
        ]}
    }

    #[test]
    fn resolve_local_ref() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let resolved = resolve_ref(&cfg, "app.bsky.feed.post", "#replyRef", &schemas).unwrap();
        assert_eq!(resolved.type_name, "FeedPostReplyRef");
        assert_eq!(resolved.module_path, "crate::app::bsky");
    }

    #[test]
    fn resolve_cross_schema_ref() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let resolved = resolve_ref(&cfg, "app.bsky.feed.post", "com.atproto.repo.strongRef", &schemas).unwrap();
        assert_eq!(resolved.type_name, "RepoStrongRef");
        assert_eq!(resolved.module_path, "crate::com::atproto");
    }

    #[test]
    fn resolve_with_hash() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let resolved = resolve_ref(&cfg, "app.bsky.feed.post", "com.atproto.label.defs#selfLabels", &schemas).unwrap();
        assert_eq!(resolved.type_name, "LabelDefsSelfLabels");
        assert_eq!(resolved.module_path, "crate::com::atproto");
    }

    #[test]
    fn qualified_type_same_module() {
        let resolved = ResolvedRef {
            type_name: "FeedPostReplyRef".into(),
            module_path: "crate::app::bsky".into(),
            nsid: "app.bsky.feed.post".into(),
            def_name: "replyRef".into(),
        };
        assert_eq!(qualified_type(&resolved, "crate::app::bsky"), "FeedPostReplyRef");
    }

    #[test]
    fn qualified_type_cross_module() {
        let resolved = ResolvedRef {
            type_name: "RepoStrongRef".into(),
            module_path: "crate::com::atproto".into(),
            nsid: "com.atproto.repo.strongRef".into(),
            def_name: "main".into(),
        };
        assert_eq!(qualified_type(&resolved, "crate::app::bsky"), "crate::com::atproto::RepoStrongRef");
    }
}
```

- [ ] **Step 3: Commit**

`git commit -m "feat(lexgen): implement reference resolver and type name resolution"`

---

## Task 4: Struct Generation (Objects and Records)

**Files:**
- Create: `tools/lexgen/src/gen_struct.rs`

This is the core generator — it takes an object/record def and produces a Rust struct definition with serde derives.

- [ ] **Step 1: Implement gen_struct.rs**

The function takes a schema def and produces a Rust source code string:

```rust
use shrike_lexicon::schema::*;
use crate::config::Config;
use crate::resolver;
use crate::util;
use std::collections::HashMap;

/// Generate a Rust struct definition for an object or record def.
pub fn gen_struct(
    cfg: &Config,
    nsid: &str,
    def_name: &str,
    obj: &ObjectDef,
    is_record: bool,
    schemas: &HashMap<String, Schema>,
) -> String {
    let struct_name = util::type_name(nsid, def_name);
    let caller_module = cfg.find_package(nsid)
        .map(|p| format!("crate::{}", p.module))
        .unwrap_or_default();

    let mut out = String::new();

    // NSID constant for records
    if is_record && def_name == "main" {
        let const_name = nsid_const_name(nsid);
        out.push_str(&format!("pub const {const_name}: &str = \"{nsid}\";\n\n"));
    }

    // Struct definition
    out.push_str("#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]\n");
    out.push_str("#[serde(rename_all = \"camelCase\")]\n");
    out.push_str(&format!("pub struct {struct_name} {{\n"));

    // Sort fields for deterministic output
    let mut field_names: Vec<&String> = obj.properties.keys().collect();
    field_names.sort();

    for field_name in &field_names {
        let field_schema = &obj.properties[*field_name];
        let is_required = obj.required.contains(field_name);
        let rust_name = util::rust_field_name(field_name);
        let rust_type = field_type(cfg, nsid, field_schema, schemas, &caller_module);

        // serde attributes
        if !is_required {
            if is_vec_type(&rust_type) {
                out.push_str("    #[serde(default, skip_serializing_if = \"Vec::is_empty\")]\n");
            } else {
                out.push_str("    #[serde(skip_serializing_if = \"Option::is_none\")]\n");
            }
        }

        // Field with type
        if is_required {
            out.push_str(&format!("    pub {rust_name}: {rust_type},\n"));
        } else if is_vec_type(&rust_type) {
            out.push_str(&format!("    pub {rust_name}: {rust_type},\n"));
        } else {
            out.push_str(&format!("    pub {rust_name}: Option<{rust_type}>,\n"));
        }
    }

    // Extra fields for JSON round-trip
    out.push_str("    #[serde(flatten)]\n");
    out.push_str("    #[serde(default)]\n");
    out.push_str("    #[serde(skip_serializing_if = \"std::collections::HashMap::is_empty\")]\n");
    out.push_str("    pub extra: std::collections::HashMap<String, serde_json::Value>,\n");

    // Extra fields for CBOR round-trip
    out.push_str("    #[serde(skip)]\n");
    out.push_str("    pub extra_cbor: Vec<(String, Vec<u8>)>,\n");

    out.push_str("}\n");
    out
}

/// Determine the Rust type for a field schema.
pub fn field_type(
    cfg: &Config,
    context_nsid: &str,
    field: &FieldSchema,
    schemas: &HashMap<String, Schema>,
    caller_module: &str,
) -> String {
    match field {
        FieldSchema::String { format, .. } => {
            match format.as_deref() {
                Some("datetime") => "shrike_syntax::Datetime".to_string(),
                Some("did") => "shrike_syntax::Did".to_string(),
                Some("handle") => "shrike_syntax::Handle".to_string(),
                Some("at-uri") => "shrike_syntax::AtUri".to_string(),
                Some("nsid") => "shrike_syntax::Nsid".to_string(),
                Some("tid") => "shrike_syntax::Tid".to_string(),
                Some("language") => "shrike_syntax::Language".to_string(),
                Some("record-key") => "shrike_syntax::RecordKey".to_string(),
                Some("at-identifier") => "String".to_string(), // AtIdentifier deserializes from string
                Some("cid") => "String".to_string(), // CID in JSON is a string
                Some("uri") => "String".to_string(),
                _ => "String".to_string(),
            }
        }
        FieldSchema::Integer { .. } => "i64".to_string(),
        FieldSchema::Boolean { .. } => "bool".to_string(),
        FieldSchema::Bytes { .. } => "Vec<u8>".to_string(),
        FieldSchema::CidLink { .. } => "crate::LexCidLink".to_string(),
        FieldSchema::Blob { .. } => "crate::LexBlob".to_string(),
        FieldSchema::Array { items, .. } => {
            let inner = field_type(cfg, context_nsid, items, schemas, caller_module);
            format!("Vec<{inner}>")
        }
        FieldSchema::Object(obj) => {
            // Inline objects should have been extracted as separate defs by the generator
            "serde_json::Value".to_string()
        }
        FieldSchema::Ref { reference, .. } => {
            match resolver::resolve_ref(cfg, context_nsid, reference, schemas) {
                Ok(resolved) => resolver::qualified_type(&resolved, caller_module),
                Err(_) => "serde_json::Value".to_string(), // fallback
            }
        }
        FieldSchema::Union { refs, closed, .. } => {
            // Union fields get their own generated enum type
            // For now, use serde_json::Value as placeholder — gen_union handles the real type
            "serde_json::Value".to_string()
        }
        FieldSchema::Unknown { .. } => "serde_json::Value".to_string(),
    }
}

fn is_vec_type(ty: &str) -> bool {
    ty.starts_with("Vec<")
}

fn nsid_const_name(nsid: &str) -> String {
    let parts: Vec<&str> = nsid.split('.').collect();
    if parts.len() >= 2 {
        format!("NSID_{}_{}", parts[parts.len()-2].to_uppercase(), parts[parts.len()-1].to_uppercase())
    } else {
        format!("NSID_{}", nsid.to_uppercase())
    }
}
```

- [ ] **Step 2: Write tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;

    fn test_config() -> Config {
        serde_json::from_str(r#"{"packages":[
            {"prefix":"app.bsky","module":"app::bsky","out_dir":""},
            {"prefix":"com.atproto","module":"com::atproto","out_dir":""}
        ]}"#).unwrap()
    }

    #[test]
    fn gen_simple_struct() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let schema = schemas.get("com.atproto.repo.strongRef").unwrap();
        if let Def::Object(obj) = schema.defs.get("main").unwrap() {
            let code = gen_struct(&cfg, "com.atproto.repo.strongRef", "main", obj, false, &schemas);
            assert!(code.contains("pub struct RepoStrongRef"));
            assert!(code.contains("pub uri:"));
            assert!(code.contains("pub cid:"));
            assert!(code.contains("#[derive(Debug, Clone, Default"));
            assert!(code.contains("extra:"));
        }
    }

    #[test]
    fn gen_record_has_nsid_const() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        if let Def::Record(rec) = schema.defs.get("main").unwrap() {
            let code = gen_struct(&cfg, "app.bsky.feed.post", "main", &rec.record, true, &schemas);
            assert!(code.contains("NSID_FEED_POST"));
            assert!(code.contains("\"app.bsky.feed.post\""));
        }
    }

    #[test]
    fn gen_struct_optional_fields() {
        let schemas = crate::loader::load_schemas(std::path::Path::new("../../lexicons")).unwrap();
        let cfg = test_config();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        if let Def::Record(rec) = schema.defs.get("main").unwrap() {
            let code = gen_struct(&cfg, "app.bsky.feed.post", "main", &rec.record, true, &schemas);
            // text is required
            assert!(code.contains("pub text: String,"));
            // reply is optional
            assert!(code.contains("pub reply: Option<"));
        }
    }

    #[test]
    fn field_type_formats() {
        let cfg = test_config();
        let schemas = HashMap::new();
        let module = "crate::app::bsky";

        let dt = FieldSchema::String { format: Some("datetime".into()), min_length: None, max_length: None, max_graphemes: None, known_values: vec![], r#enum: None, description: None, default: None, const_val: None };
        assert_eq!(field_type(&cfg, "test", &dt, &schemas, module), "shrike_syntax::Datetime");

        let did = FieldSchema::String { format: Some("did".into()), min_length: None, max_length: None, max_graphemes: None, known_values: vec![], r#enum: None, description: None, default: None, const_val: None };
        assert_eq!(field_type(&cfg, "test", &did, &schemas, module), "shrike_syntax::Did");

        let int = FieldSchema::Integer { minimum: None, maximum: None, r#enum: None, default: None, description: None };
        assert_eq!(field_type(&cfg, "test", &int, &schemas, module), "i64");

        let bool_f = FieldSchema::Boolean { default: None, description: None };
        assert_eq!(field_type(&cfg, "test", &bool_f, &schemas, module), "bool");
    }
}
```

- [ ] **Step 3: Commit**

`git commit -m "feat(lexgen): implement struct generation for objects and records"`

---

## Task 5: Union Generation

**Files:**
- Create: `tools/lexgen/src/gen_union.rs`

- [ ] **Step 1: Implement gen_union.rs**

Generate Rust enum types for union fields. Each union gets:
- An enum with one variant per ref + an Unknown variant (for open unions)
- Custom Serialize impl that sets $type and delegates
- Custom Deserialize impl that peeks $type and dispatches

```rust
/// Generate a union enum for an inline union field.
/// `union_type_name` is the Rust type name for this union.
/// `refs` is the list of ref strings from the schema.
/// `closed` is whether the union is closed (no Unknown variant).
pub fn gen_union(
    cfg: &Config,
    context_nsid: &str,
    union_type_name: &str,
    refs: &[String],
    closed: bool,
    schemas: &HashMap<String, Schema>,
    caller_module: &str,
) -> String {
    // Generate enum definition
    // Generate Serialize impl (set $type, delegate to inner)
    // Generate Deserialize impl (peek $type, dispatch)
    // ...
}
```

The Deserialize impl should peek `$type` from the JSON:
```rust
impl<'de> serde::Deserialize<'de> for {UnionName} {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let raw = serde_json::Value::deserialize(deserializer)?;
        let type_str = raw.get("$type")
            .and_then(|v| v.as_str())
            .ok_or_else(|| serde::de::Error::missing_field("$type"))?;
        match type_str {
            "{nsid1}" => Ok(Self::Variant1(serde_json::from_value(raw).map_err(serde::de::Error::custom)?)),
            // ...
            _ if !CLOSED => Ok(Self::Unknown(crate::UnknownUnionVariant {
                r#type: type_str.to_string(),
                json: Some(raw),
                cbor: None,
            })),
            other => Err(serde::de::Error::unknown_variant(other, &[...])),
        }
    }
}
```

- [ ] **Step 2: Write tests against real lexicon schemas**

Test with `app.bsky.feed.post` embed union and `com.atproto.label.defs#selfLabels` union.

- [ ] **Step 3: Commit**

`git commit -m "feat(lexgen): implement union enum generation with custom serde"`

---

## Task 6: Endpoint Generation

**Files:**
- Create: `tools/lexgen/src/gen_endpoint.rs`

- [ ] **Step 1: Implement gen_endpoint.rs**

Generate async functions for query and procedure defs:

```rust
pub fn gen_query(
    cfg: &Config,
    nsid: &str,
    def: &QueryDef,
    schemas: &HashMap<String, Schema>,
    caller_module: &str,
) -> String {
    // Generate params struct (if parameters defined)
    // Generate output struct (if output schema defined)
    // Generate async fn that calls client.query()
}

pub fn gen_procedure(
    cfg: &Config,
    nsid: &str,
    def: &ProcedureDef,
    schemas: &HashMap<String, Schema>,
    caller_module: &str,
) -> String {
    // Generate input struct (if input schema defined)
    // Generate output struct (if output schema defined)
    // Generate async fn that calls client.procedure()
}
```

- [ ] **Step 2: Write tests**

Test against `com.atproto.repo.createRecord` (procedure) and a query endpoint.

- [ ] **Step 3: Commit**

`git commit -m "feat(lexgen): implement XRPC endpoint function generation"`

---

## Task 7: Shared Types and Module Structure

**Files:**
- Create: `tools/lexgen/src/gen_shared.rs`
- Create: `tools/lexgen/src/gen_module.rs`

- [ ] **Step 1: Implement gen_shared.rs**

Generate `lib.rs` with shared types (LexBlob, LexCidLink, UnknownUnionVariant, UnknownValue) and module re-exports.

- [ ] **Step 2: Implement gen_module.rs**

Generate `mod.rs` files for each package directory and the nested module structure.

- [ ] **Step 3: Write tests and commit**

`git commit -m "feat(lexgen): implement shared types and module structure generation"`

---

## Task 8: Orchestrator and Full Pipeline

**Files:**
- Create: `tools/lexgen/src/codegen.rs`
- Modify: `tools/lexgen/src/main.rs`

- [ ] **Step 1: Implement codegen.rs**

Ties all generators together:

```rust
pub fn generate(cfg: &Config, schemas: &HashMap<String, Schema>) -> Result<HashMap<String, String>, Box<dyn std::error::Error>> {
    let mut files: HashMap<String, String> = HashMap::new();

    // 1. Generate shared types (lib.rs)
    // 2. For each schema, find its package and generate:
    //    - Struct defs for objects/records
    //    - Union enums for inline unions
    //    - Endpoint functions for queries/procedures
    //    - Token constants, string type aliases
    // 3. Generate mod.rs files for directory structure
    // 4. Return map of file_path → file_content

    Ok(files)
}
```

- [ ] **Step 2: Wire into main.rs**

```rust
fn main() {
    let (lexdir, config_path) = parse_args(&std::env::args().collect::<Vec<_>>());
    let cfg = config::Config::load(&config_path).expect("failed to load config");
    let schemas = loader::load_schemas(&lexdir).expect("failed to load schemas");
    let files = codegen::generate(&cfg, &schemas).expect("code generation failed");

    for (path, content) in &files {
        let dir = std::path::Path::new(path).parent().unwrap();
        std::fs::create_dir_all(dir).unwrap();
        std::fs::write(path, content).unwrap();
    }

    eprintln!("Generated {} files from {} schemas", files.len(), schemas.len());
}
```

- [ ] **Step 3: Run the generator against real lexicons**

```bash
just lexgen
```

Verify it produces files in `crates/shrike-api/src/`.

- [ ] **Step 4: Verify generated code compiles**

```bash
cargo build -p shrike-api
```

- [ ] **Step 5: Commit**

`git commit -m "feat(lexgen): implement full pipeline, generate shrike-api from lexicons"`

---

## Task 9: CBOR Generation (to_cbor / from_cbor)

**Files:**
- Create: `tools/lexgen/src/gen_cbor.rs`
- Modify: `tools/lexgen/src/gen_struct.rs` (call gen_cbor)

- [ ] **Step 1: Implement gen_cbor.rs**

Generate `to_cbor()` and `from_cbor()` methods for structs:

```rust
/// Generate to_cbor() impl for a struct
pub fn gen_to_cbor(struct_name: &str, fields: &[(String, String, bool)]) -> String {
    // fields: (json_name, rust_type, is_required)
    // Pre-sort fields by DRISL key order
    // Generate fast path (no extras): write pre-sorted keys with pre-computed bytes
    // Generate slow path (has extras): merge-sort known + unknown
}

/// Generate from_cbor() impl for a struct
pub fn gen_from_cbor(struct_name: &str, fields: &[(String, String, bool)]) -> String {
    // Dispatch by key byte length, then name comparison
    // Unknown keys → extra_cbor
}
```

- [ ] **Step 2: Write tests that verify roundtrip**

Generate a struct, compile it (as a string check), verify the generated to_cbor/from_cbor code is syntactically correct.

- [ ] **Step 3: Commit**

`git commit -m "feat(lexgen): implement DRISL CBOR encoding generation"`

---

## Task 10: Integration Test — Full Generation + Compile + Test

**Files:**
- Modify: `crates/shrike-api/Cargo.toml`
- Modify various generated files if needed

- [ ] **Step 1: Run full generation**

```bash
just lexgen
```

- [ ] **Step 2: Verify shrike-api compiles**

```bash
cargo build -p shrike-api
```

Fix any compilation errors in the generator.

- [ ] **Step 3: Add integration tests in shrike-api**

Add tests that exercise the generated types:
```rust
#[test]
fn feed_post_serde_roundtrip() {
    let post = app::bsky::FeedPost {
        text: "Hello world".into(),
        created_at: shrike_syntax::Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
        ..Default::default()
    };
    let json = serde_json::to_string(&post).unwrap();
    let parsed: app::bsky::FeedPost = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed.text, "Hello world");
}

#[test]
fn strong_ref_serde_roundtrip() {
    let sr = com::atproto::RepoStrongRef {
        uri: shrike_syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyreihffx5a2e4gzlcbsuaamgoxwaqlodtip3r5ln4vpqwlpz6ji7ydnm".into(),
        ..Default::default()
    };
    let json = serde_json::to_string(&sr).unwrap();
    assert!(json.contains("uri"));
    assert!(json.contains("cid"));
}
```

- [ ] **Step 4: Full workspace check**

```bash
just check
```

- [ ] **Step 5: Commit**

```bash
git add -A
git commit -m "feat: generate shrike-api from lexicons, full integration"
```
