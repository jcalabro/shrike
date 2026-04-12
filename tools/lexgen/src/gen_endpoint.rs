use std::fmt::Write;

use shrike_lexicon::{BodyDef, FieldSchema, ParamsDef, ProcedureDef, QueryDef};

use crate::gen_struct::{self, GenContext};
use crate::gen_union;
use crate::util;

/// Generate code for a `query` (XRPC GET) def.
pub fn gen_query(ctx: &GenContext<'_>, def_name: &str, query: &QueryDef) -> Result<String, String> {
    let type_name = util::type_name(&ctx.schema.id, def_name);
    let mut out = String::new();
    let mut extras = Vec::new();

    // Params struct
    if let Some(params) = &query.parameters {
        let params_code = gen_params_struct(ctx, &type_name, params)?;
        extras.push(params_code);
    }

    // Output type
    if let Some(output) = &query.output {
        let output_extras = gen_body_type(ctx, &type_name, "Output", output)?;
        extras.extend(output_extras);
    }

    // The async function
    let has_params = query.parameters.is_some();
    let has_output = query.output.as_ref().is_some_and(|o| o.schema.is_some());
    let has_binary_output = query
        .output
        .as_ref()
        .is_some_and(|o| o.schema.is_none() && !o.encoding.is_empty());

    if let Some(desc) = &query.description {
        writeln!(out, "/// {} — {}", type_name, single_line(desc)).ok();
    } else {
        writeln!(out, "/// {} XRPC query.", type_name).ok();
    }

    let params_arg = if has_params {
        format!(", params: &{type_name}Params")
    } else {
        String::new()
    };

    let return_type = if has_output {
        format!("Result<{type_name}Output, shrike_xrpc::Error>")
    } else if has_binary_output {
        "Result<Vec<u8>, shrike_xrpc::Error>".to_string()
    } else {
        "Result<(), shrike_xrpc::Error>".to_string()
    };

    writeln!(
        out,
        "pub async fn {fn_name}(client: &shrike_xrpc::Client{params_arg}) -> {return_type} {{",
        fn_name = util::to_snake_case(&type_name),
    )
    .ok();

    let params_val = if has_params { "params" } else { "&()" };

    if has_output {
        writeln!(
            out,
            "    client.query({:?}, {params_val}).await",
            ctx.schema.id
        )
        .ok();
    } else if has_binary_output {
        writeln!(
            out,
            "    client.query_raw({:?}, {params_val}).await",
            ctx.schema.id
        )
        .ok();
    } else {
        writeln!(
            out,
            "    let _: serde_json::Value = client.query({:?}, {params_val}).await?;",
            ctx.schema.id
        )
        .ok();
        writeln!(out, "    Ok(())").ok();
    }
    writeln!(out, "}}").ok();

    // Put extras before the function
    let mut result = String::new();
    for extra in extras {
        result.push_str(&extra);
        result.push_str("\n\n");
    }
    result.push_str(&out);
    Ok(result)
}

/// Generate code for a `procedure` (XRPC POST) def.
pub fn gen_procedure(
    ctx: &GenContext<'_>,
    def_name: &str,
    proc: &ProcedureDef,
) -> Result<String, String> {
    let type_name = util::type_name(&ctx.schema.id, def_name);
    let mut out = String::new();
    let mut extras = Vec::new();

    // Input type
    let has_input = proc.input.as_ref().is_some_and(|i| i.schema.is_some());
    let is_blob_input = proc
        .input
        .as_ref()
        .is_some_and(|i| i.schema.is_none() && !i.encoding.is_empty());

    if let Some(input) = &proc.input {
        let input_extras = gen_body_type(ctx, &type_name, "Input", input)?;
        extras.extend(input_extras);
    }

    // Output type
    let has_output = proc.output.as_ref().is_some_and(|o| o.schema.is_some());

    if let Some(output) = &proc.output {
        let output_extras = gen_body_type(ctx, &type_name, "Output", output)?;
        extras.extend(output_extras);
    }

    if let Some(desc) = &proc.description {
        writeln!(out, "/// {} — {}", type_name, single_line(desc)).ok();
    } else {
        writeln!(out, "/// {} XRPC procedure.", type_name).ok();
    }

    let mut args = String::from("client: &shrike_xrpc::Client");
    if has_input {
        write!(args, ", input: &{type_name}Input").ok();
    } else if is_blob_input {
        args.push_str(", body: Vec<u8>, content_type: &str");
    }

    let return_type = if has_output {
        format!("Result<{type_name}Output, shrike_xrpc::Error>")
    } else {
        "Result<(), shrike_xrpc::Error>".to_string()
    };

    writeln!(
        out,
        "pub async fn {fn_name}({args}) -> {return_type} {{",
        fn_name = util::to_snake_case(&type_name),
    )
    .ok();

    if is_blob_input {
        if has_output {
            writeln!(
                out,
                "    let v = client.procedure_raw({:?}, body, content_type).await?;",
                ctx.schema.id
            )
            .ok();
            writeln!(
                out,
                "    serde_json::from_value(v).map_err(|e| shrike_xrpc::Error::Xrpc {{ status: 0, error: \"DeserializationError\".to_string(), message: e.to_string() }})"
            )
            .ok();
        } else {
            writeln!(
                out,
                "    let _ = client.procedure_raw({:?}, body, content_type).await?;",
                ctx.schema.id
            )
            .ok();
            writeln!(out, "    Ok(())").ok();
        }
    } else {
        let input_val = if has_input { "input" } else { "&()" };
        if has_output {
            writeln!(
                out,
                "    client.procedure({:?}, {input_val}).await",
                ctx.schema.id
            )
            .ok();
        } else {
            writeln!(
                out,
                "    let _: serde_json::Value = client.procedure({:?}, {input_val}).await?;",
                ctx.schema.id
            )
            .ok();
            writeln!(out, "    Ok(())").ok();
        }
    }
    writeln!(out, "}}").ok();

    // Put extras before the function
    let mut result = String::new();
    for extra in extras {
        result.push_str(&extra);
        result.push_str("\n\n");
    }
    result.push_str(&out);
    Ok(result)
}

/// Generate a params struct for query parameters.
fn gen_params_struct(
    _ctx: &GenContext<'_>,
    base_type_name: &str,
    params: &ParamsDef,
) -> Result<String, String> {
    let struct_name = format!("{base_type_name}Params");
    let required: std::collections::HashSet<&str> =
        params.required.iter().map(|s| s.as_str()).collect();

    let mut field_names: Vec<&String> = params.properties.keys().collect();
    field_names.sort();

    let mut out = String::new();
    writeln!(
        out,
        "#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]"
    )
    .ok();
    writeln!(out, "#[serde(rename_all = \"camelCase\")]").ok();
    writeln!(out, "pub struct {struct_name} {{").ok();

    for json_name in &field_names {
        let json_name_str: &str = json_name;
        let field_schema = &params.properties[json_name_str];
        let is_required = required.contains(json_name_str);

        let rust_field = util::rust_field_name(json_name_str);
        let rust_type = param_type(field_schema, is_required);

        let is_option = rust_type.starts_with("Option<");
        let is_vec = rust_type.starts_with("Vec<");
        if is_vec {
            writeln!(
                out,
                "    #[serde(default, skip_serializing_if = \"Vec::is_empty\")]"
            )
            .ok();
        } else if is_option {
            writeln!(
                out,
                "    #[serde(default, skip_serializing_if = \"Option::is_none\")]"
            )
            .ok();
        }

        writeln!(out, "    pub {rust_field}: {rust_type},").ok();
    }

    writeln!(out, "}}").ok();
    Ok(out)
}

/// Simple type mapping for query parameters (always scalar types).
fn param_type(field: &FieldSchema, required: bool) -> String {
    let base = match field {
        FieldSchema::String { .. } => "String".to_string(),
        FieldSchema::Integer { .. } => "i64".to_string(),
        FieldSchema::Boolean { .. } => "bool".to_string(),
        FieldSchema::Array { items, .. } => {
            let inner = param_type(items, true);
            return format!("Vec<{inner}>");
        }
        _ => "String".to_string(),
    };
    if required {
        base
    } else {
        format!("Option<{base}>")
    }
}

/// Generate types for an endpoint body (input or output).
fn gen_body_type(
    ctx: &GenContext<'_>,
    base_type_name: &str,
    suffix: &str,
    body: &BodyDef,
) -> Result<Vec<String>, String> {
    let schema = match &body.schema {
        Some(s) => s,
        None => return Ok(Vec::new()),
    };

    let out_name = format!("{base_type_name}{suffix}");

    match schema {
        FieldSchema::Ref { reference, .. } => {
            let resolved = gen_struct::resolve_ref_type(ctx, reference)?;
            Ok(vec![format!(
                "/// {out_name} is an alias.\npub type {out_name} = {resolved};\n"
            )])
        }
        FieldSchema::Object(obj) => {
            // Generate a struct with the specific endpoint name.
            let mut result = Vec::new();
            let (struct_code, extras) = gen_endpoint_object(ctx, &out_name, obj)?;
            result.push(struct_code);
            result.extend(extras);
            Ok(result)
        }
        FieldSchema::Union { refs, closed, .. } => {
            let union_code = gen_union::gen_union(ctx, &out_name, refs, *closed)?;
            Ok(vec![union_code])
        }
        _ => Ok(Vec::new()),
    }
}

/// Generate a struct for an endpoint object (input/output).
fn gen_endpoint_object(
    ctx: &GenContext<'_>,
    type_name: &str,
    obj: &shrike_lexicon::ObjectDef,
) -> Result<(String, Vec<String>), String> {
    let required: std::collections::HashSet<&str> =
        obj.required.iter().map(|s| s.as_str()).collect();
    let nullable: std::collections::HashSet<&str> =
        obj.nullable.iter().map(|s| s.as_str()).collect();

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
        let (rust_type, field_extras) = gen_struct::resolve_field_type(
            ctx,
            type_name,
            json_name_str,
            field_schema,
            is_required,
        )?;
        extras.extend(field_extras);

        let is_vec = rust_type.starts_with("Vec<");
        let is_option = rust_type.starts_with("Option<");

        let needs_rename = needs_explicit_rename_simple(json_name_str, &rust_field);

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
    writeln!(out, "    /// Extra fields not defined in the schema.").ok();
    writeln!(out, "    #[serde(flatten)]").ok();
    writeln!(
        out,
        "    pub extra: std::collections::HashMap<String, serde_json::Value>,"
    )
    .ok();

    writeln!(out, "}}").ok();
    Ok((out, extras))
}

fn needs_explicit_rename_simple(json_name: &str, rust_field: &str) -> bool {
    if json_name.starts_with('$') {
        return true;
    }
    let clean_rust = rust_field.strip_prefix("r#").unwrap_or(rust_field);
    let reconstructed = snake_to_camel(clean_rust);
    reconstructed != json_name
}

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

fn single_line(s: &str) -> String {
    let s = s.replace('\n', " ");
    if s.len() > 100 {
        format!("{}...", &s[..97])
    } else {
        s
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::loader;
    use std::collections::HashMap;
    use std::path::Path;

    fn test_ctx() -> (Config, HashMap<String, shrike_lexicon::Schema>) {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        let schemas = loader::load_schemas(Path::new("../../lexicons")).unwrap();
        (cfg, schemas)
    }

    #[test]
    fn gen_get_profile_query() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.actor.getProfile").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::app::bsky",
        };
        if let shrike_lexicon::Def::Query(q) = &schema.defs["main"] {
            let code = gen_query(&ctx, "main", q).unwrap();
            assert!(code.contains("pub async fn"), "code:\n{code}");
            assert!(code.contains("ActorGetProfileParams"), "code:\n{code}");
        } else {
            panic!("expected Query def");
        }
    }

    #[test]
    fn gen_create_record_procedure() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("com.atproto.repo.createRecord").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::com::atproto",
        };
        if let shrike_lexicon::Def::Procedure(p) = &schema.defs["main"] {
            let code = gen_procedure(&ctx, "main", p).unwrap();
            assert!(code.contains("RepoCreateRecordInput"), "code:\n{code}");
            assert!(code.contains("RepoCreateRecordOutput"), "code:\n{code}");
            assert!(code.contains("pub async fn"), "code:\n{code}");
        } else {
            panic!("expected Procedure def");
        }
    }
}
