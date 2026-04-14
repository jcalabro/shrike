use std::collections::{HashMap, HashSet};
use std::fmt::Write;

use shrike::lexicon::{FieldSchema, ObjectDef, Schema};

use crate::config::Config;
use crate::gen_cbor;
use crate::gen_union;
use crate::resolver;
use crate::util;

/// Context for generating code within a single schema file.
#[allow(dead_code)]
pub struct GenContext<'a> {
    pub schema: &'a Schema,
    pub cfg: &'a Config,
    pub schemas: &'a HashMap<String, Schema>,
    pub caller_module: &'a str,
}

/// Generate a struct for a top-level `object` def.
pub fn gen_object(ctx: &GenContext<'_>, def_name: &str, obj: &ObjectDef) -> Result<String, String> {
    let type_name = util::type_name(&ctx.schema.id, def_name);
    let mut out = String::new();

    let comment = if let Some(desc) = &obj.description {
        format!("/// {} — {}\n", type_name, single_line(desc))
    } else if let Some(desc) = &ctx.schema.description {
        format!("/// {} — {}\n", type_name, single_line(desc))
    } else {
        format!("/// {} object from {}.\n", type_name, ctx.schema.id)
    };
    out.push_str(&comment);

    let (struct_code, extras) = gen_struct_body(ctx, &type_name, obj, false)?;
    out.push_str(&struct_code);
    for extra in extras {
        out.push_str("\n\n");
        out.push_str(&extra);
    }

    // Generate CBOR encode/decode impl.
    let cbor_impl = gen_cbor::gen_cbor_impl(ctx, &type_name, obj)?;
    out.push_str("\n\n");
    out.push_str(&cbor_impl);

    Ok(out)
}

/// Generate a struct for a `record` def.
pub fn gen_record(
    ctx: &GenContext<'_>,
    def_name: &str,
    record_obj: &ObjectDef,
    record_description: Option<&str>,
) -> Result<String, String> {
    let type_name = util::type_name(&ctx.schema.id, def_name);
    let nsid_const = util::nsid_const_name(&ctx.schema.id);
    let mut out = String::new();

    writeln!(out, "/// NSID for the {} record.", type_name).ok();
    writeln!(out, "pub const {nsid_const}: &str = {:?};", ctx.schema.id).ok();
    out.push('\n');

    if let Some(desc) = record_description {
        writeln!(out, "/// {} — {}", type_name, single_line(desc)).ok();
    } else {
        writeln!(out, "/// {} record from {}.", type_name, ctx.schema.id).ok();
    }

    let (struct_code, extras) = gen_struct_body(ctx, &type_name, record_obj, true)?;
    out.push_str(&struct_code);
    for extra in extras {
        out.push_str("\n\n");
        out.push_str(&extra);
    }

    // Generate CBOR encode/decode impl.
    let cbor_impl = gen_cbor::gen_cbor_impl(ctx, &type_name, record_obj)?;
    out.push_str("\n\n");
    out.push_str(&cbor_impl);

    Ok(out)
}

/// Generate a type alias for a top-level `string` def.
pub fn gen_string_def(nsid: &str, def_name: &str, description: Option<&str>) -> String {
    let type_name = util::type_name(nsid, def_name);
    if let Some(desc) = description {
        format!(
            "/// {}\npub type {type_name} = String;\n",
            single_line(desc)
        )
    } else {
        format!("/// {type_name} is a string type from {nsid}.\npub type {type_name} = String;\n")
    }
}

/// Generate a constant for a `token` def.
pub fn gen_token(nsid: &str, def_name: &str, description: Option<&str>) -> String {
    let type_name = util::type_name(nsid, def_name);
    let const_name = to_upper_snake(&type_name);
    let full_ref = if def_name == "main" {
        nsid.to_string()
    } else {
        format!("{nsid}#{def_name}")
    };
    if let Some(desc) = description {
        format!(
            "/// {}\npub const {const_name}: &str = {full_ref:?};\n",
            single_line(desc)
        )
    } else {
        format!("/// Token constant.\npub const {const_name}: &str = {full_ref:?};\n")
    }
}

/// Convert a PascalCase name to UPPER_SNAKE_CASE.
fn to_upper_snake(s: &str) -> String {
    let mut result = String::new();
    for (i, c) in s.chars().enumerate() {
        if c.is_uppercase() && i > 0 {
            result.push('_');
        }
        result.push(c.to_ascii_uppercase());
    }
    result
}

// ─── Internal ───────────────────────────────────────────────────────

/// Generate the struct body and any extra types (inline unions, etc).
fn gen_struct_body(
    ctx: &GenContext<'_>,
    type_name: &str,
    obj: &ObjectDef,
    _is_record: bool,
) -> Result<(String, Vec<String>), String> {
    let required: HashSet<&str> = obj.required.iter().map(|s| s.as_str()).collect();
    let nullable: HashSet<&str> = obj.nullable.iter().map(|s| s.as_str()).collect();

    let mut field_names: Vec<&String> = obj.properties.keys().collect();
    field_names.sort();

    let mut out = String::new();
    let mut extras: Vec<String> = Vec::new();

    writeln!(
        out,
        "#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]"
    )
    .ok();
    writeln!(out, "#[serde(rename_all = \"camelCase\")]").ok();
    writeln!(out, "pub struct {type_name} {{").ok();

    for json_name in &field_names {
        let json_name_str: &str = json_name;
        let field_schema = &obj.properties[json_name_str];
        let is_required = required.contains(json_name_str) && !nullable.contains(json_name_str);

        let rust_field = util::rust_field_name(json_name_str);
        let (rust_type, field_extras) =
            resolve_field_type(ctx, type_name, json_name_str, field_schema, is_required)?;
        extras.extend(field_extras);

        // Serde attributes
        let is_vec = rust_type.starts_with("Vec<");
        let is_option = rust_type.starts_with("Option<");

        // If the snake_case Rust name differs from the JSON name, we need
        // #[serde(rename = "jsonName")]. But since we have rename_all = "camelCase",
        // serde will automatically convert snake_case to camelCase. However,
        // some field names like "$type" or names that don't follow camelCase
        // conventions need explicit rename.
        let needs_rename = needs_explicit_rename(json_name_str, &rust_field);

        // Emit field-level doc comment from lexicon description (before serde attrs).
        if let Some(desc) = field_schema.description() {
            writeln!(out, "    /// {}", single_line(desc)).ok();
        }

        if is_vec {
            write!(
                out,
                "    #[serde(default, skip_serializing_if = \"Vec::is_empty\""
            )
            .ok();
            if needs_rename {
                write!(out, ", rename = {json_name_str:?}").ok();
            }
            writeln!(out, ")]").ok();
        } else if is_option {
            write!(
                out,
                "    #[serde(default, skip_serializing_if = \"Option::is_none\""
            )
            .ok();
            if needs_rename {
                write!(out, ", rename = {json_name_str:?}").ok();
            }
            writeln!(out, ")]").ok();
        } else if needs_rename {
            writeln!(out, "    #[serde(rename = {json_name_str:?})]").ok();
        }

        writeln!(out, "    pub {rust_field}: {rust_type},").ok();
    }

    // Extra fields for round-trip preservation
    writeln!(
        out,
        "    /// Extra fields not defined in the schema (JSON)."
    )
    .ok();
    writeln!(out, "    #[serde(flatten)]").ok();
    writeln!(
        out,
        "    pub extra: std::collections::HashMap<String, serde_json::Value>,"
    )
    .ok();
    writeln!(
        out,
        "    /// Extra fields not defined in the schema (CBOR)."
    )
    .ok();
    writeln!(out, "    #[serde(skip)]").ok();
    writeln!(out, "    pub extra_cbor: Vec<(String, Vec<u8>)>,").ok();

    writeln!(out, "}}").ok();

    Ok((out, extras))
}

/// Determine if a field needs an explicit #[serde(rename = "...")].
///
/// Since we use `rename_all = "camelCase"`, serde will transform `snake_case`
/// field names to `camelCase`. We only need explicit rename when:
/// - The field starts with `$` (like `$type`)
/// - The camelCase form of the Rust name doesn't match the JSON name
fn needs_explicit_rename(json_name: &str, rust_field: &str) -> bool {
    if json_name.starts_with('$') {
        return true;
    }
    // Strip the r# prefix if present
    let clean_rust = rust_field.strip_prefix("r#").unwrap_or(rust_field);
    // Convert our snake_case back to camelCase and compare
    let reconstructed = snake_to_camel(clean_rust);
    reconstructed != json_name
}

/// Convert snake_case to camelCase (the inverse of what serde does).
fn snake_to_camel(s: &str) -> String {
    let mut result = String::new();
    let mut capitalize_next = false;
    for c in s.chars() {
        if c == '_' {
            capitalize_next = true;
        } else if capitalize_next {
            result.push(c.to_ascii_uppercase());
            capitalize_next = false;
        } else {
            result.push(c);
        }
    }
    result
}

/// Resolve a FieldSchema to a Rust type string, producing extra types if needed.
pub fn resolve_field_type(
    ctx: &GenContext<'_>,
    parent_type: &str,
    field_name: &str,
    field: &FieldSchema,
    required: bool,
) -> Result<(String, Vec<String>), String> {
    let mut extras = Vec::new();

    let base_type = match field {
        FieldSchema::String { format, .. } => match format.as_deref() {
            Some("datetime") => "crate::syntax::Datetime".to_string(),
            Some("did") => "crate::syntax::Did".to_string(),
            Some("handle") => "crate::syntax::Handle".to_string(),
            Some("at-uri") => "crate::syntax::AtUri".to_string(),
            Some("nsid") => "crate::syntax::Nsid".to_string(),
            Some("tid") => "crate::syntax::Tid".to_string(),
            Some("language") => "crate::syntax::Language".to_string(),
            Some("record-key") => "crate::syntax::RecordKey".to_string(),
            Some("at-identifier") => "crate::syntax::AtIdentifier".to_string(),
            _ => "String".to_string(),
        },
        FieldSchema::Integer { .. } => "i64".to_string(),
        FieldSchema::Boolean { .. } => "bool".to_string(),
        FieldSchema::Bytes { .. } => "String".to_string(), // Base64 in JSON
        FieldSchema::CidLink { .. } => "crate::api::CidLink".to_string(),
        FieldSchema::Blob { .. } => "crate::api::Blob".to_string(),
        FieldSchema::Unknown { .. } => "serde_json::Value".to_string(),
        FieldSchema::Object(_) => "serde_json::Value".to_string(), // Inline objects → Value
        FieldSchema::Ref { reference, .. } => resolve_ref_type(ctx, reference)?,
        FieldSchema::Array { items, .. } => {
            let (inner, inner_extras) =
                resolve_field_type(ctx, parent_type, field_name, items, true)?;
            extras.extend(inner_extras);
            format!("Vec<{inner}>")
        }
        FieldSchema::Union {
            refs,
            closed,
            description,
            ..
        } => {
            let union_name = format!("{parent_type}{}Union", util::capitalize(field_name));
            let union_code =
                gen_union::gen_union(ctx, &union_name, refs, *closed, description.as_deref())?;
            extras.push(union_code);
            union_name
        }
    };

    // Wrap in Option if not required (except Vec/Value types)
    let final_type =
        if !required && !base_type.starts_with("Vec<") && base_type != "serde_json::Value" {
            format!("Option<{base_type}>")
        } else {
            base_type
        };

    Ok((final_type, extras))
}

/// Resolve a `$ref` string to a qualified Rust type name.
pub fn resolve_ref_type(ctx: &GenContext<'_>, reference: &str) -> Result<String, String> {
    let resolved = resolver::resolve_ref(ctx.cfg, &ctx.schema.id, reference, ctx.schemas)?;

    // For refs that target the SAME schema (local refs like #replyRef), use bare name.
    // For refs that target a DIFFERENT schema (even in the same module), always qualify.
    if resolved.nsid == ctx.schema.id {
        Ok(resolved.type_name.clone())
    } else {
        // Always use fully qualified path for cross-schema refs.
        Ok(format!("{}::{}", resolved.module_path, resolved.type_name))
    }
}

/// Flatten a description to a single line and escape characters that would
/// confuse rustdoc (angle brackets that look like HTML tags, bare URLs).
fn single_line(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for word in s.replace('\n', " ").split_whitespace() {
        if !result.is_empty() {
            result.push(' ');
        }
        if word.starts_with("http://") || word.starts_with("https://") {
            // Wrap bare URLs in angle brackets so rustdoc renders them as links.
            result.push('<');
            result.push_str(word);
            result.push('>');
        } else {
            // Escape angle brackets that would look like HTML tags.
            for ch in word.chars() {
                match ch {
                    '<' => result.push_str("&lt;"),
                    '>' => result.push_str("&gt;"),
                    _ => result.push(ch),
                }
            }
        }
    }
    result
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::loader;
    use std::path::Path;

    fn test_ctx() -> (Config, HashMap<String, Schema>) {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        let schemas = loader::load_schemas(Path::new("../../lexicons")).unwrap();
        (cfg, schemas)
    }

    #[test]
    fn gen_strong_ref_struct() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("com.atproto.repo.strongRef").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::api::com::atproto",
        };
        if let shrike::lexicon::Def::Object(obj) = &schema.defs["main"] {
            let code = gen_object(&ctx, "main", obj).unwrap();
            assert!(code.contains("pub struct RepoStrongRef"), "code:\n{code}");
            assert!(code.contains("pub uri:"), "code:\n{code}");
            assert!(code.contains("pub cid:"), "code:\n{code}");
        } else {
            panic!("expected Object def");
        }
    }

    #[test]
    fn gen_post_record() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::api::app::bsky",
        };
        if let shrike::lexicon::Def::Record(rec) = &schema.defs["main"] {
            let code = gen_record(&ctx, "main", &rec.record, rec.description.as_deref()).unwrap();
            assert!(code.contains("pub struct FeedPost"), "code:\n{code}");
            assert!(code.contains("pub text:"), "code:\n{code}");
            assert!(code.contains("NSID_FEED_POST"), "code:\n{code}");
        } else {
            panic!("expected Record def");
        }
    }

    #[test]
    fn gen_actor_defs_profile_view_basic() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.actor.defs").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::api::app::bsky",
        };
        if let shrike::lexicon::Def::Object(obj) = &schema.defs["profileViewBasic"] {
            let code = gen_object(&ctx, "profileViewBasic", obj).unwrap();
            assert!(
                code.contains("pub struct ActorDefsProfileViewBasic"),
                "code:\n{code}"
            );
            assert!(code.contains("pub did:"), "code:\n{code}");
            assert!(code.contains("pub handle:"), "code:\n{code}");
        } else {
            panic!("expected Object def");
        }
    }

    #[test]
    fn snake_to_camel_roundtrip() {
        assert_eq!(snake_to_camel("created_at"), "createdAt");
        assert_eq!(snake_to_camel("display_name"), "displayName");
        assert_eq!(snake_to_camel("text"), "text");
        assert_eq!(snake_to_camel("uri"), "uri");
    }

    #[test]
    fn needs_rename_special_chars() {
        assert!(needs_explicit_rename("$type", "r#type"));
    }

    #[test]
    fn no_rename_standard_camel() {
        assert!(!needs_explicit_rename("createdAt", "created_at"));
        assert!(!needs_explicit_rename("text", "text"));
    }
}
