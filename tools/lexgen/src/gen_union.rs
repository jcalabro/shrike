use std::fmt::Write;

use shrike::lexicon::split_ref;

use crate::gen_cbor;
use crate::gen_struct::GenContext;
use crate::resolver;
use crate::util;

/// Generate a union enum type for a set of refs.
///
/// Uses custom Serialize/Deserialize that dispatches on the `$type` field.
pub fn gen_union(
    ctx: &GenContext<'_>,
    type_name: &str,
    refs: &[String],
    closed: Option<bool>,
    description: Option<&str>,
) -> Result<String, String> {
    let is_closed = closed.unwrap_or(false);

    let mut variants = Vec::new();
    for ref_str in refs {
        let (target_nsid, def_name) = split_ref(&ctx.schema.id, ref_str);
        let type_id = if def_name == "main" {
            target_nsid.clone()
        } else {
            format!("{target_nsid}#{def_name}")
        };

        let resolved = resolver::resolve_ref(ctx.cfg, &ctx.schema.id, ref_str, ctx.schemas)?;
        // For refs that target the same schema, use bare name.
        // For cross-schema refs, always fully qualify.
        let qualified = if resolved.nsid == ctx.schema.id {
            resolved.type_name.clone()
        } else {
            format!("{}::{}", resolved.module_path, resolved.type_name)
        };

        // Variant name: short name from the ref
        let variant_name = variant_short_name(&ctx.schema.id, ref_str);

        variants.push(UnionVariant {
            variant_name,
            type_id,
            rust_type: qualified,
        });
    }

    let mut out = String::new();

    // Enum definition
    if let Some(desc) = description {
        writeln!(out, "/// {}", single_line(desc)).ok();
    } else {
        writeln!(out, "/// {type_name} is a union type.").ok();
    }
    writeln!(out, "#[derive(Debug, Clone)]").ok();
    writeln!(out, "pub enum {type_name} {{").ok();
    for v in &variants {
        writeln!(out, "    {}(Box<{}>),", v.variant_name, v.rust_type).ok();
    }
    if !is_closed {
        writeln!(out, "    Unknown(crate::api::UnknownUnionVariant),").ok();
    }
    writeln!(out, "}}").ok();
    out.push('\n');

    // Serialize impl
    gen_serialize(&mut out, type_name, &variants, is_closed);
    out.push('\n');

    // Deserialize impl
    gen_deserialize(&mut out, type_name, &variants, is_closed);
    out.push('\n');

    // CBOR impl
    let cbor_code = gen_cbor::gen_union_cbor(ctx, type_name, refs, closed)?;
    out.push_str(&cbor_code);

    Ok(out)
}

struct UnionVariant {
    variant_name: String,
    type_id: String,
    rust_type: String,
}

fn gen_serialize(out: &mut String, type_name: &str, variants: &[UnionVariant], is_closed: bool) {
    writeln!(out, "impl serde::Serialize for {type_name} {{").ok();
    writeln!(
        out,
        "    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {{"
    )
    .ok();
    writeln!(out, "        match self {{").ok();
    for v in variants {
        writeln!(
            out,
            "            {type_name}::{}(inner) => {{",
            v.variant_name
        )
        .ok();
        writeln!(out, "                let mut map = serde_json::to_value(inner.as_ref()).map_err(serde::ser::Error::custom)?;").ok();
        writeln!(
            out,
            "                if let serde_json::Value::Object(ref mut m) = map {{"
        )
        .ok();
        writeln!(
            out,
            "                    m.insert(\"$type\".to_string(), serde_json::Value::String({:?}.to_string()));",
            v.type_id
        )
        .ok();
        writeln!(out, "                }}").ok();
        writeln!(out, "                map.serialize(serializer)").ok();
        writeln!(out, "            }}").ok();
    }
    if !is_closed {
        writeln!(out, "            {type_name}::Unknown(v) => {{").ok();
        writeln!(out, "                if let Some(ref j) = v.json {{").ok();
        writeln!(out, "                    j.serialize(serializer)").ok();
        writeln!(out, "                }} else {{").ok();
        writeln!(
            out,
            "                    Err(serde::ser::Error::custom(\"no JSON data for unknown union variant\"))"
        )
        .ok();
        writeln!(out, "                }}").ok();
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
}

fn gen_deserialize(out: &mut String, type_name: &str, variants: &[UnionVariant], is_closed: bool) {
    writeln!(out, "impl<'de> serde::Deserialize<'de> for {type_name} {{").ok();
    writeln!(
        out,
        "    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {{"
    )
    .ok();
    writeln!(
        out,
        "        let value = serde_json::Value::deserialize(deserializer)?;"
    )
    .ok();
    writeln!(
        out,
        "        let type_str = value.get(\"$type\").and_then(|v| v.as_str()).unwrap_or_default();"
    )
    .ok();
    writeln!(out, "        match type_str {{").ok();
    for v in variants {
        writeln!(out, "            {:?} => {{", v.type_id).ok();
        writeln!(
            out,
            "                let inner: {} = serde_json::from_value(value).map_err(serde::de::Error::custom)?;",
            v.rust_type
        )
        .ok();
        writeln!(
            out,
            "                Ok({type_name}::{}(Box::new(inner)))",
            v.variant_name
        )
        .ok();
        writeln!(out, "            }}").ok();
    }
    if is_closed {
        writeln!(
            out,
            "            other => Err(serde::de::Error::custom(format!(\"unknown type {{:?}} in closed union {type_name}\", other))),"
        )
        .ok();
    } else {
        writeln!(out, "            _ => {{").ok();
        writeln!(
            out,
            "                Ok({type_name}::Unknown(crate::api::UnknownUnionVariant {{"
        )
        .ok();
        writeln!(out, "                    r#type: type_str.to_string(),").ok();
        writeln!(out, "                    json: Some(value),").ok();
        writeln!(out, "                    cbor: None,").ok();
        writeln!(out, "                }}))").ok();
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();
}

/// Derive a short variant name from a ref, e.g.:
/// - `"app.bsky.embed.images"` → `EmbedImages`
/// - `"#replyRef"` → `FeedPostReplyRef` (uses type_name logic)
/// - `"com.atproto.label.defs#selfLabels"` → `LabelDefsSelfLabels`
pub fn variant_short_name(context_nsid: &str, ref_str: &str) -> String {
    let (target_nsid, def_name) = split_ref(context_nsid, ref_str);
    util::type_name(&target_nsid, def_name)
}

fn single_line(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    for word in s.replace('\n', " ").split_whitespace() {
        if !result.is_empty() {
            result.push(' ');
        }
        if word.starts_with("http://") || word.starts_with("https://") {
            result.push('<');
            result.push_str(word);
            result.push('>');
        } else {
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
    use std::collections::HashMap;
    use std::path::Path;

    fn test_ctx() -> (Config, HashMap<String, shrike::lexicon::Schema>) {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        let schemas = loader::load_schemas(Path::new("../../lexicons")).unwrap();
        (cfg, schemas)
    }

    #[test]
    fn gen_embed_union() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::api::app::bsky",
        };
        let refs = vec![
            "app.bsky.embed.images".to_string(),
            "app.bsky.embed.external".to_string(),
        ];
        let code = gen_union(&ctx, "FeedPostEmbed", &refs, None, None).unwrap();
        assert!(code.contains("pub enum FeedPostEmbed"), "code:\n{code}");
        assert!(code.contains("EmbedImages("), "code:\n{code}");
        assert!(code.contains("EmbedExternal("), "code:\n{code}");
        assert!(code.contains("Unknown("), "code:\n{code}");
        assert!(code.contains("impl serde::Serialize"), "code:\n{code}");
        assert!(
            code.contains("impl<'de> serde::Deserialize"),
            "code:\n{code}"
        );
    }

    #[test]
    fn gen_closed_union_no_unknown() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::api::app::bsky",
        };
        let refs = vec!["app.bsky.embed.images".to_string()];
        let code = gen_union(&ctx, "TestClosed", &refs, Some(true), None).unwrap();
        assert!(
            !code.contains("Unknown("),
            "closed union should not have Unknown: {code}"
        );
    }

    #[test]
    fn variant_short_name_main_ref() {
        assert_eq!(
            variant_short_name("app.bsky.feed.post", "app.bsky.embed.images"),
            "EmbedImages"
        );
    }

    #[test]
    fn variant_short_name_hash_ref() {
        assert_eq!(
            variant_short_name("app.bsky.feed.post", "#replyRef"),
            "FeedPostReplyRef"
        );
    }

    #[test]
    fn variant_short_name_cross_hash_ref() {
        assert_eq!(
            variant_short_name("app.bsky.feed.post", "com.atproto.label.defs#selfLabels"),
            "LabelDefsSelfLabels"
        );
    }
}
