use std::collections::HashSet;
use std::fmt::Write;

use shrike_lexicon::{FieldSchema, ObjectDef};

use crate::gen_struct::GenContext;
use crate::gen_union;
use crate::util;

/// Info about a struct field needed for CBOR code generation.
struct CborField {
    /// The JSON/CBOR map key name (e.g. "createdAt").
    json_name: String,
    /// The Rust field name (e.g. "created_at").
    rust_field: String,
    /// The Rust type string (e.g. "String", "Option<i64>", "Vec<String>").
    rust_type: String,
    /// The kind of encoding needed.
    kind: FieldKind,
    /// Whether this field is required (not optional).
    required: bool,
}

/// Classification of field types for encoding/decoding dispatch.
enum FieldKind {
    /// String field: encode as CBOR text.
    Text,
    /// Typed syntax field (e.g. shrike_syntax::Datetime): encode as CBOR text via `.as_str()` / `.to_string()`.
    /// The String is the fully-qualified Rust type (e.g. "shrike_syntax::Datetime").
    SyntaxText(String),
    /// Integer field: encode as CBOR i64.
    Integer,
    /// Boolean field: encode as CBOR bool.
    Bool,
    /// Bytes field (base64 in JSON, raw bytes in CBOR) -- stored as String in Rust.
    Bytes,
    /// CidLink: encode as CBOR CID (tag 42).
    CidLink,
    /// Blob: encode as nested struct.
    Blob,
    /// Nested struct with its own encode_cbor/decode_cbor.
    Struct,
    /// Union type with its own encode_cbor/decode_cbor.
    Union,
    /// Vec<T> where T is some inner type.
    Array(Box<FieldKind>),
    /// serde_json::Value -- skip in CBOR for now.
    JsonValue,
}

/// Generate `to_cbor`, `encode_cbor`, `from_cbor`, and `decode_cbor` impl block
/// for a struct. Returns the generated code as a string.
pub fn gen_cbor_impl(
    ctx: &GenContext<'_>,
    type_name: &str,
    obj: &ObjectDef,
) -> Result<String, String> {
    let required: HashSet<&str> = obj.required.iter().map(|s| s.as_str()).collect();
    let nullable: HashSet<&str> = obj.nullable.iter().map(|s| s.as_str()).collect();

    let mut field_names: Vec<&String> = obj.properties.keys().collect();
    field_names.sort();

    // Build field info.
    let mut fields: Vec<CborField> = Vec::new();
    for json_name in &field_names {
        let json_name_str: &str = json_name;
        let field_schema = &obj.properties[json_name_str];
        let is_required = required.contains(json_name_str) && !nullable.contains(json_name_str);

        let rust_field = util::rust_field_name(json_name_str);
        let (rust_type, _) = crate::gen_struct::resolve_field_type(
            ctx,
            type_name,
            json_name_str,
            field_schema,
            is_required,
        )?;
        let kind = classify_field(ctx, field_schema, &rust_type);

        fields.push(CborField {
            json_name: json_name_str.to_string(),
            rust_field,
            rust_type,
            kind,
            required: is_required,
        });
    }

    // Sort fields by CBOR key order (pre-sorted at code-gen time).
    fields.sort_by(|a, b| cbor_key_cmp(&a.json_name, &b.json_name));

    let mut out = String::new();
    writeln!(out, "impl {type_name} {{").ok();
    gen_to_cbor(&mut out, &fields);
    out.push('\n');
    gen_from_cbor(&mut out, type_name, &fields);
    writeln!(out, "}}").ok();
    Ok(out)
}

/// Generate CBOR encode/decode methods for a union enum type.
pub fn gen_union_cbor(
    ctx: &GenContext<'_>,
    type_name: &str,
    refs: &[String],
    closed: Option<bool>,
) -> Result<String, String> {
    let is_closed = closed.unwrap_or(false);

    // Gather variant info.
    let mut variant_names = Vec::new();
    let mut type_ids = Vec::new();
    let mut qualified_types = Vec::new();

    for ref_str in refs {
        let variant_name = gen_union::variant_short_name(&ctx.schema.id, ref_str);
        let (target_nsid, def_name) = shrike_lexicon::split_ref(&ctx.schema.id, ref_str);
        let type_id = if def_name == "main" {
            target_nsid.clone()
        } else {
            format!("{target_nsid}#{def_name}")
        };
        let resolved = crate::resolver::resolve_ref(ctx.cfg, &ctx.schema.id, ref_str, ctx.schemas)?;
        let qualified = if resolved.nsid == ctx.schema.id {
            resolved.type_name.clone()
        } else {
            format!("{}::{}", resolved.module_path, resolved.type_name)
        };
        variant_names.push(variant_name);
        type_ids.push(type_id);
        qualified_types.push(qualified);
    }

    let mut out = String::new();
    writeln!(out, "impl {type_name} {{").ok();

    // to_cbor
    writeln!(
        out,
        "    pub fn to_cbor(&self) -> Result<Vec<u8>, shrike_cbor::CborError> {{"
    )
    .ok();
    writeln!(out, "        let mut buf = Vec::new();").ok();
    writeln!(out, "        self.encode_cbor(&mut buf)?;").ok();
    writeln!(out, "        Ok(buf)").ok();
    writeln!(out, "    }}").ok();
    out.push('\n');

    // encode_cbor
    writeln!(
        out,
        "    pub fn encode_cbor(&self, buf: &mut Vec<u8>) -> Result<(), shrike_cbor::CborError> {{"
    )
    .ok();
    writeln!(out, "        match self {{").ok();
    for v in &variant_names {
        writeln!(
            out,
            "            {type_name}::{v}(inner) => inner.encode_cbor(buf),"
        )
        .ok();
    }
    if !is_closed {
        writeln!(out, "            {type_name}::Unknown(v) => {{").ok();
        writeln!(out, "                if let Some(ref data) = v.cbor {{").ok();
        writeln!(out, "                    buf.extend_from_slice(data);").ok();
        writeln!(out, "                    Ok(())").ok();
        writeln!(out, "                }} else {{").ok();
        writeln!(out, "                    Err(shrike_cbor::CborError::InvalidCbor(\"no CBOR data for unknown union variant\".into()))").ok();
        writeln!(out, "                }}").ok();
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    out.push('\n');

    // from_cbor
    writeln!(
        out,
        "    pub fn from_cbor(data: &[u8]) -> Result<Self, shrike_cbor::CborError> {{"
    )
    .ok();
    writeln!(
        out,
        "        let mut decoder = shrike_cbor::Decoder::new(data);"
    )
    .ok();
    writeln!(
        out,
        "        let result = Self::decode_cbor(&mut decoder)?;"
    )
    .ok();
    writeln!(out, "        if !decoder.is_empty() {{").ok();
    writeln!(
        out,
        "            return Err(shrike_cbor::CborError::InvalidCbor(\"trailing data\".into()));"
    )
    .ok();
    writeln!(out, "        }}").ok();
    writeln!(out, "        Ok(result)").ok();
    writeln!(out, "    }}").ok();
    out.push('\n');

    // decode_cbor
    writeln!(out, "    pub fn decode_cbor(decoder: &mut shrike_cbor::Decoder) -> Result<Self, shrike_cbor::CborError> {{").ok();
    writeln!(
        out,
        "        // Save position, decode the value, look for $type key."
    )
    .ok();
    writeln!(out, "        let start = decoder.position();").ok();
    writeln!(out, "        let val = decoder.decode()?;").ok();
    writeln!(out, "        let end = decoder.position();").ok();
    writeln!(out, "        let raw = &decoder.raw_input()[start..end];").ok();
    writeln!(out, "        let entries = match val {{").ok();
    writeln!(
        out,
        "            shrike_cbor::Value::Map(entries) => entries,"
    )
    .ok();
    writeln!(out, "            _ => return Err(shrike_cbor::CborError::InvalidCbor(\"expected map for union\".into())),").ok();
    writeln!(out, "        }};").ok();
    writeln!(out, "        let type_str = entries.iter()").ok();
    writeln!(out, "            .find(|(k, _)| *k == \"$type\")").ok();
    writeln!(out, "            .and_then(|(_, v)| match v {{").ok();
    writeln!(
        out,
        "                shrike_cbor::Value::Text(s) => Some(*s),"
    )
    .ok();
    writeln!(out, "                _ => None,").ok();
    writeln!(out, "            }})").ok();
    writeln!(out, "            .unwrap_or_default();").ok();
    writeln!(out, "        match type_str {{").ok();

    for (i, v) in variant_names.iter().enumerate() {
        let type_id = &type_ids[i];
        let qualified = &qualified_types[i];
        writeln!(out, "            {type_id:?} => {{").ok();
        writeln!(
            out,
            "                let mut dec = shrike_cbor::Decoder::new(raw);"
        )
        .ok();
        writeln!(
            out,
            "                let inner = {qualified}::decode_cbor(&mut dec)?;"
        )
        .ok();
        writeln!(out, "                Ok({type_name}::{v}(Box::new(inner)))").ok();
        writeln!(out, "            }}").ok();
    }
    if is_closed {
        writeln!(out, "            other => Err(shrike_cbor::CborError::InvalidCbor(format!(\"unknown type {{:?}} in closed union {type_name}\", other))),").ok();
    } else {
        writeln!(out, "            _ => {{").ok();
        writeln!(
            out,
            "                Ok({type_name}::Unknown(crate::UnknownUnionVariant {{"
        )
        .ok();
        writeln!(out, "                    r#type: type_str.to_string(),").ok();
        writeln!(out, "                    json: None,").ok();
        writeln!(out, "                    cbor: Some(raw.to_vec()),").ok();
        writeln!(out, "                }}))").ok();
        writeln!(out, "            }}").ok();
    }
    writeln!(out, "        }}").ok();
    writeln!(out, "    }}").ok();
    writeln!(out, "}}").ok();

    Ok(out)
}

// ─── to_cbor / encode_cbor ─────────────────────────────────────────

fn gen_to_cbor(out: &mut String, fields: &[CborField]) {
    // to_cbor: convenience wrapper
    writeln!(
        out,
        "    pub fn to_cbor(&self) -> Result<Vec<u8>, shrike_cbor::CborError> {{"
    )
    .ok();
    writeln!(out, "        let mut buf = Vec::new();").ok();
    writeln!(out, "        self.encode_cbor(&mut buf)?;").ok();
    writeln!(out, "        Ok(buf)").ok();
    writeln!(out, "    }}").ok();
    out.push('\n');

    // encode_cbor: write directly to buf (no Encoder wrapper needed for nested calls)
    writeln!(
        out,
        "    pub fn encode_cbor(&self, buf: &mut Vec<u8>) -> Result<(), shrike_cbor::CborError> {{"
    )
    .ok();

    // Filter out JSON-only fields.
    let cbor_fields: Vec<&CborField> = fields.iter().filter(|f| !is_json_only(&f.kind)).collect();

    let required_count = cbor_fields.iter().filter(|f| f.required).count();
    let optional_fields: Vec<&&CborField> = cbor_fields.iter().filter(|f| !f.required).collect();

    writeln!(out, "        if self.extra_cbor.is_empty() {{").ok();
    writeln!(out, "            // Fast path: no extra fields to merge.").ok();

    // Count the map size.
    if optional_fields.is_empty() {
        writeln!(out, "            let count = {required_count}u64;").ok();
    } else {
        writeln!(out, "            let mut count = {required_count}u64;").ok();
        for f in &optional_fields {
            let check = option_check(f);
            writeln!(out, "            if {check} {{ count += 1; }}").ok();
        }
    }
    writeln!(
        out,
        "            shrike_cbor::Encoder::new(&mut *buf).encode_map_header(count)?;"
    )
    .ok();

    // Emit fields in pre-sorted order.
    for f in &cbor_fields {
        let key = &f.json_name;
        if f.required {
            writeln!(
                out,
                "            shrike_cbor::Encoder::new(&mut *buf).encode_text({key:?})?;"
            )
            .ok();
            gen_encode_field(out, f, "            ");
        } else {
            let check = option_check(f);
            writeln!(out, "            if {check} {{").ok();
            writeln!(
                out,
                "                shrike_cbor::Encoder::new(&mut *buf).encode_text({key:?})?;"
            )
            .ok();
            gen_encode_field(out, f, "                ");
            writeln!(out, "            }}").ok();
        }
    }

    writeln!(out, "        }} else {{").ok();
    writeln!(
        out,
        "            // Slow path: merge known fields with extra_cbor, sort, encode."
    )
    .ok();
    writeln!(
        out,
        "            let mut pairs: Vec<(&str, Vec<u8>)> = Vec::new();"
    )
    .ok();

    // Encode each known field into a temporary buffer.
    for f in &cbor_fields {
        let key = &f.json_name;
        if f.required {
            writeln!(out, "            {{").ok();
            writeln!(out, "                let mut vbuf = Vec::new();").ok();
            gen_encode_field_vbuf(out, f, "                ");
            writeln!(out, "                pairs.push(({key:?}, vbuf));").ok();
            writeln!(out, "            }}").ok();
        } else {
            let check = option_check(f);
            writeln!(out, "            if {check} {{").ok();
            writeln!(out, "                let mut vbuf = Vec::new();").ok();
            gen_encode_field_vbuf(out, f, "                ");
            writeln!(out, "                pairs.push(({key:?}, vbuf));").ok();
            writeln!(out, "            }}").ok();
        }
    }

    // Merge extras.
    writeln!(out, "            for (k, v) in &self.extra_cbor {{").ok();
    writeln!(out, "                pairs.push((k.as_str(), v.clone()));").ok();
    writeln!(out, "            }}").ok();
    writeln!(
        out,
        "            pairs.sort_by(|a, b| shrike_cbor::cbor_key_cmp(a.0, b.0));"
    )
    .ok();
    writeln!(
        out,
        "            shrike_cbor::Encoder::new(&mut *buf).encode_map_header(pairs.len() as u64)?;"
    )
    .ok();
    writeln!(out, "            for (k, v) in &pairs {{").ok();
    writeln!(
        out,
        "                shrike_cbor::Encoder::new(&mut *buf).encode_text(k)?;"
    )
    .ok();
    writeln!(out, "                buf.extend_from_slice(v);").ok();
    writeln!(out, "            }}").ok();

    writeln!(out, "        }}").ok();
    writeln!(out, "        Ok(())").ok();
    writeln!(out, "    }}").ok();
}

fn gen_from_cbor(out: &mut String, type_name: &str, fields: &[CborField]) {
    // Filter out JSON-only fields.
    let cbor_fields: Vec<&CborField> = fields.iter().filter(|f| !is_json_only(&f.kind)).collect();

    // from_cbor: convenience wrapper
    writeln!(
        out,
        "    pub fn from_cbor(data: &[u8]) -> Result<Self, shrike_cbor::CborError> {{"
    )
    .ok();
    writeln!(
        out,
        "        let mut decoder = shrike_cbor::Decoder::new(data);"
    )
    .ok();
    writeln!(
        out,
        "        let result = Self::decode_cbor(&mut decoder)?;"
    )
    .ok();
    writeln!(out, "        if !decoder.is_empty() {{").ok();
    writeln!(
        out,
        "            return Err(shrike_cbor::CborError::InvalidCbor(\"trailing data\".into()));"
    )
    .ok();
    writeln!(out, "        }}").ok();
    writeln!(out, "        Ok(result)").ok();
    writeln!(out, "    }}").ok();
    out.push('\n');

    // decode_cbor
    writeln!(out, "    pub fn decode_cbor(decoder: &mut shrike_cbor::Decoder) -> Result<Self, shrike_cbor::CborError> {{").ok();
    writeln!(out, "        let val = decoder.decode()?;").ok();
    writeln!(out, "        let entries = match val {{").ok();
    writeln!(
        out,
        "            shrike_cbor::Value::Map(entries) => entries,"
    )
    .ok();
    writeln!(
        out,
        "            _ => return Err(shrike_cbor::CborError::InvalidCbor(\"expected map\".into())),"
    )
    .ok();
    writeln!(out, "        }};").ok();
    out.push('\n');

    // Declare variables for each field.
    for f in &cbor_fields {
        let clean_var = clean_field_name(&f.rust_field);
        if f.rust_type.starts_with("Vec<") {
            writeln!(
                out,
                "        let mut field_{clean_var}: {} = Vec::new();",
                f.rust_type
            )
            .ok();
        } else if f.rust_type.starts_with("Option<") {
            writeln!(
                out,
                "        let mut field_{clean_var}: {} = None;",
                f.rust_type
            )
            .ok();
        } else {
            writeln!(
                out,
                "        let mut field_{clean_var}: Option<{}> = None;",
                f.rust_type
            )
            .ok();
        }
    }
    writeln!(
        out,
        "        let mut extra_cbor: Vec<(String, Vec<u8>)> = Vec::new();"
    )
    .ok();
    out.push('\n');

    writeln!(out, "        for (key, value) in entries {{").ok();
    writeln!(out, "            match key {{").ok();

    for f in &cbor_fields {
        let key = &f.json_name;
        let clean_var = clean_field_name(&f.rust_field);
        writeln!(out, "                {key:?} => {{").ok();
        gen_decode_field(out, f, &clean_var, "                    ");
        writeln!(out, "                }}").ok();
    }

    // Unknown keys go to extra_cbor.
    writeln!(out, "                _ => {{").ok();
    writeln!(
        out,
        "                    let raw = shrike_cbor::encode_value(&value)?;"
    )
    .ok();
    writeln!(
        out,
        "                    extra_cbor.push((key.to_string(), raw));"
    )
    .ok();
    writeln!(out, "                }}").ok();
    writeln!(out, "            }}").ok();
    writeln!(out, "        }}").ok();
    out.push('\n');

    // Build the struct, verifying required fields.
    writeln!(out, "        Ok({type_name} {{").ok();
    for f in fields {
        let rust_field = &f.rust_field;
        if is_json_only(&f.kind) {
            // JSON-only fields get their default value.
            writeln!(out, "            {rust_field}: Default::default(),").ok();
            continue;
        }
        let clean_var = clean_field_name(&f.rust_field);
        if f.rust_type.starts_with("Vec<") || f.rust_type.starts_with("Option<") {
            writeln!(out, "            {rust_field}: field_{clean_var},").ok();
        } else {
            // Required field -- must be present.
            let key = &f.json_name;
            writeln!(out, "            {rust_field}: field_{clean_var}.ok_or_else(|| shrike_cbor::CborError::InvalidCbor(\"missing required field '{key}'\".into()))?,").ok();
        }
    }
    writeln!(out, "            extra: std::collections::HashMap::new(),").ok();
    writeln!(out, "            extra_cbor,").ok();
    writeln!(out, "        }})").ok();
    writeln!(out, "    }}").ok();
}

// ─── Encoding helpers ──────────────────────────────────────────────

/// Generate code to encode a field value using fresh `Encoder::new(&mut *buf)` calls.
/// The `buf` variable must be a `&mut Vec<u8>` in scope.
fn gen_encode_field(out: &mut String, f: &CborField, indent: &str) {
    let access = format!("self.{}", f.rust_field);

    if f.rust_type.starts_with("Option<") && !f.required {
        // We're inside an `if self.field.is_some()` check already.
        writeln!(out, "{indent}if let Some(ref val) = {access} {{").ok();
        gen_encode_value(out, &f.kind, "val", &format!("{indent}    "), true);
        writeln!(out, "{indent}}}").ok();
        return;
    }
    gen_encode_value(out, &f.kind, &access, indent, false);
}

fn gen_encode_value(out: &mut String, kind: &FieldKind, access: &str, indent: &str, is_ref: bool) {
    match kind {
        FieldKind::Text => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text(&{access})?;"
                )
                .ok();
            }
        }
        FieldKind::SyntaxText(ty) => {
            if syntax_has_as_str(ty) {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access}.as_str())?;"
                )
                .ok();
            } else {
                writeln!(out, "{indent}{{ let __s = {access}.to_string(); shrike_cbor::Encoder::new(&mut *buf).encode_text(&__s)?; }}").ok();
            }
        }
        FieldKind::Integer => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_i64(*{access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_i64({access})?;"
                )
                .ok();
            }
        }
        FieldKind::Bool => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_bool(*{access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_bool({access})?;"
                )
                .ok();
            }
        }
        FieldKind::Bytes => {
            // Stored as String in Rust. Encode as text for now.
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text(&{access})?;"
                )
                .ok();
            }
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}let cid = {access}.link.parse::<shrike_cbor::Cid>().map_err(|e| shrike_cbor::CborError::InvalidCbor(format!(\"invalid CID: {{e}}\")))?;").ok();
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_cid(&cid)?;"
            )
            .ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}{access}.encode_cbor(buf)?;").ok();
        }
        FieldKind::Array(inner_kind) => {
            if is_ref {
                writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_array_header({access}.len() as u64)?;").ok();
                writeln!(out, "{indent}for item in {access}.iter() {{").ok();
            } else {
                writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_array_header({access}.len() as u64)?;").ok();
                writeln!(out, "{indent}for item in &{access} {{").ok();
            }
            gen_encode_array_item(out, inner_kind, "item", &format!("{indent}    "));
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::JsonValue => {}
    }
}

fn gen_encode_array_item(out: &mut String, kind: &FieldKind, access: &str, indent: &str) {
    match kind {
        FieldKind::Text => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access})?;"
            )
            .ok();
        }
        FieldKind::SyntaxText(ty) => {
            if syntax_has_as_str(ty) {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access}.as_str())?;"
                )
                .ok();
            } else {
                writeln!(out, "{indent}{{ let __s = {access}.to_string(); shrike_cbor::Encoder::new(&mut *buf).encode_text(&__s)?; }}").ok();
            }
        }
        FieldKind::Integer => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_i64(*{access})?;"
            )
            .ok();
        }
        FieldKind::Bool => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_bool(*{access})?;"
            )
            .ok();
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}let cid = {access}.link.parse::<shrike_cbor::Cid>().map_err(|e| shrike_cbor::CborError::InvalidCbor(format!(\"invalid CID: {{e}}\")))?;").ok();
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_cid(&cid)?;"
            )
            .ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}{access}.encode_cbor(buf)?;").ok();
        }
        FieldKind::Bytes => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_text({access})?;"
            )
            .ok();
        }
        FieldKind::Array(inner) => {
            writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut *buf).encode_array_header({access}.len() as u64)?;").ok();
            writeln!(out, "{indent}for inner_item in {access} {{").ok();
            gen_encode_array_item(out, inner, "inner_item", &format!("{indent}    "));
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::JsonValue => {}
    }
}

/// Generate code to encode a field value into `vbuf: Vec<u8>` (slow path).
fn gen_encode_field_vbuf(out: &mut String, f: &CborField, indent: &str) {
    let access = format!("self.{}", f.rust_field);

    if f.rust_type.starts_with("Option<") && !f.required {
        writeln!(out, "{indent}if let Some(ref val) = {access} {{").ok();
        gen_encode_value_vbuf(out, &f.kind, "val", &format!("{indent}    "), true);
        writeln!(out, "{indent}}}").ok();
        return;
    }
    gen_encode_value_vbuf(out, &f.kind, &access, indent, false);
}

fn gen_encode_value_vbuf(
    out: &mut String,
    kind: &FieldKind,
    access: &str,
    indent: &str,
    is_ref: bool,
) {
    match kind {
        FieldKind::Text => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text(&{access})?;"
                )
                .ok();
            }
        }
        FieldKind::SyntaxText(ty) => {
            if syntax_has_as_str(ty) {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access}.as_str())?;"
                )
                .ok();
            } else {
                writeln!(out, "{indent}{{ let __s = {access}.to_string(); shrike_cbor::Encoder::new(&mut vbuf).encode_text(&__s)?; }}").ok();
            }
        }
        FieldKind::Integer => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_i64(*{access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_i64({access})?;"
                )
                .ok();
            }
        }
        FieldKind::Bool => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_bool(*{access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_bool({access})?;"
                )
                .ok();
            }
        }
        FieldKind::Bytes => {
            if is_ref {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access})?;"
                )
                .ok();
            } else {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text(&{access})?;"
                )
                .ok();
            }
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}let cid = {access}.link.parse::<shrike_cbor::Cid>().map_err(|e| shrike_cbor::CborError::InvalidCbor(format!(\"invalid CID: {{e}}\")))?;").ok();
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_cid(&cid)?;"
            )
            .ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}{access}.encode_cbor(&mut vbuf)?;").ok();
        }
        FieldKind::Array(inner_kind) => {
            if is_ref {
                writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_array_header({access}.len() as u64)?;").ok();
                writeln!(out, "{indent}for item in {access}.iter() {{").ok();
            } else {
                writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_array_header({access}.len() as u64)?;").ok();
                writeln!(out, "{indent}for item in &{access} {{").ok();
            }
            gen_encode_array_item_vbuf(out, inner_kind, "item", &format!("{indent}    "));
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::JsonValue => {}
    }
}

fn gen_encode_array_item_vbuf(out: &mut String, kind: &FieldKind, access: &str, indent: &str) {
    match kind {
        FieldKind::Text => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access})?;"
            )
            .ok();
        }
        FieldKind::SyntaxText(ty) => {
            if syntax_has_as_str(ty) {
                writeln!(
                    out,
                    "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access}.as_str())?;"
                )
                .ok();
            } else {
                writeln!(out, "{indent}{{ let __s = {access}.to_string(); shrike_cbor::Encoder::new(&mut vbuf).encode_text(&__s)?; }}").ok();
            }
        }
        FieldKind::Integer => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_i64(*{access})?;"
            )
            .ok();
        }
        FieldKind::Bool => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_bool(*{access})?;"
            )
            .ok();
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}let cid = {access}.link.parse::<shrike_cbor::Cid>().map_err(|e| shrike_cbor::CborError::InvalidCbor(format!(\"invalid CID: {{e}}\")))?;").ok();
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_cid(&cid)?;"
            )
            .ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}{access}.encode_cbor(&mut vbuf)?;").ok();
        }
        FieldKind::Bytes => {
            writeln!(
                out,
                "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_text({access})?;"
            )
            .ok();
        }
        FieldKind::Array(inner) => {
            writeln!(out, "{indent}shrike_cbor::Encoder::new(&mut vbuf).encode_array_header({access}.len() as u64)?;").ok();
            writeln!(out, "{indent}for inner_item in {access} {{").ok();
            gen_encode_array_item_vbuf(out, inner, "inner_item", &format!("{indent}    "));
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::JsonValue => {}
    }
}

// ─── Decoding helpers ──────────────────────────────────────────────

fn gen_decode_field(out: &mut String, f: &CborField, clean_var: &str, indent: &str) {
    let is_vec = f.rust_type.starts_with("Vec<");

    if is_vec {
        gen_decode_vec(out, f, clean_var, indent);
    } else if f.rust_type.starts_with("Option<") {
        // Inner type for Option<T>
        let inner_type = &f.rust_type[7..f.rust_type.len() - 1];
        gen_decode_single(out, &f.kind, clean_var, inner_type, indent, true);
    } else {
        gen_decode_single(out, &f.kind, clean_var, &f.rust_type, indent, false);
    }
}

fn gen_decode_single(
    out: &mut String,
    kind: &FieldKind,
    var: &str,
    rust_type: &str,
    indent: &str,
    _is_option: bool,
) {
    // All fields are stored as Option during decode, so always assign with Some().
    let assign_pre = format!("field_{var} = Some(");
    let assign_post = ");";

    match kind {
        FieldKind::Text => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = value {{").ok();
            writeln!(out, "{indent}    {assign_pre}s.to_string(){assign_post}").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::SyntaxText(ty) => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = value {{").ok();
            writeln!(out, "{indent}    {assign_pre}{ty}::try_from(s).map_err(|e| shrike_cbor::CborError::InvalidCbor(e.to_string()))?{assign_post}").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Integer => {
            writeln!(out, "{indent}match value {{").ok();
            writeln!(out, "{indent}    shrike_cbor::Value::Unsigned(n) => {{ {assign_pre}n as i64{assign_post} }}").ok();
            writeln!(
                out,
                "{indent}    shrike_cbor::Value::Signed(n) => {{ {assign_pre}n{assign_post} }}"
            )
            .ok();
            writeln!(out, "{indent}    _ => return Err(shrike_cbor::CborError::InvalidCbor(\"expected integer\".into())),").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Bool => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Bool(b) = value {{").ok();
            writeln!(out, "{indent}    {assign_pre}b{assign_post}").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected bool\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Bytes => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = value {{").ok();
            writeln!(out, "{indent}    {assign_pre}s.to_string(){assign_post}").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text for bytes field\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Cid(c) = value {{").ok();
            writeln!(
                out,
                "{indent}    {assign_pre}crate::CidLink {{ link: c.to_string() }}{assign_post}"
            )
            .ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected CID\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}let raw = shrike_cbor::encode_value(&value)?;").ok();
            writeln!(
                out,
                "{indent}let mut dec = shrike_cbor::Decoder::new(&raw);"
            )
            .ok();
            writeln!(
                out,
                "{indent}{assign_pre}{rust_type}::decode_cbor(&mut dec)?{assign_post}"
            )
            .ok();
        }
        FieldKind::Array(_) => {
            // Arrays are handled by gen_decode_vec, shouldn't reach here.
        }
        FieldKind::JsonValue => {}
    }
}

fn gen_decode_vec(out: &mut String, f: &CborField, var: &str, indent: &str) {
    // Extract inner type from Vec<T>.
    let inner_type = &f.rust_type[4..f.rust_type.len() - 1];
    let inner_kind = match &f.kind {
        FieldKind::Array(inner) => inner.as_ref(),
        _ => return,
    };

    writeln!(
        out,
        "{indent}if let shrike_cbor::Value::Array(items) = value {{"
    )
    .ok();
    writeln!(out, "{indent}    for item in items {{").ok();
    gen_decode_array_item(
        out,
        inner_kind,
        var,
        inner_type,
        &format!("{indent}        "),
    );
    writeln!(out, "{indent}    }}").ok();
    writeln!(out, "{indent}}} else {{").ok();
    writeln!(
        out,
        "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected array\".into()));"
    )
    .ok();
    writeln!(out, "{indent}}}").ok();
}

fn gen_decode_array_item(
    out: &mut String,
    kind: &FieldKind,
    var: &str,
    inner_type: &str,
    indent: &str,
) {
    match kind {
        FieldKind::Text => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = item {{").ok();
            writeln!(out, "{indent}    field_{var}.push(s.to_string());").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text in array\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::SyntaxText(ty) => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = item {{").ok();
            writeln!(out, "{indent}    field_{var}.push({ty}::try_from(s).map_err(|e| shrike_cbor::CborError::InvalidCbor(e.to_string()))?);").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text in array\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Integer => {
            writeln!(out, "{indent}match item {{").ok();
            writeln!(
                out,
                "{indent}    shrike_cbor::Value::Unsigned(n) => field_{var}.push(n as i64),"
            )
            .ok();
            writeln!(
                out,
                "{indent}    shrike_cbor::Value::Signed(n) => field_{var}.push(n),"
            )
            .ok();
            writeln!(out, "{indent}    _ => return Err(shrike_cbor::CborError::InvalidCbor(\"expected integer in array\".into())),").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Bool => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Bool(b) = item {{").ok();
            writeln!(out, "{indent}    field_{var}.push(b);").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected bool in array\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::CidLink => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Cid(c) = item {{").ok();
            writeln!(
                out,
                "{indent}    field_{var}.push(crate::CidLink {{ link: c.to_string() }});"
            )
            .ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected CID in array\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Blob | FieldKind::Struct | FieldKind::Union => {
            writeln!(out, "{indent}let raw = shrike_cbor::encode_value(&item)?;").ok();
            writeln!(
                out,
                "{indent}let mut dec = shrike_cbor::Decoder::new(&raw);"
            )
            .ok();
            writeln!(
                out,
                "{indent}field_{var}.push({inner_type}::decode_cbor(&mut dec)?);"
            )
            .ok();
        }
        FieldKind::Bytes => {
            writeln!(out, "{indent}if let shrike_cbor::Value::Text(s) = item {{").ok();
            writeln!(out, "{indent}    field_{var}.push(s.to_string());").ok();
            writeln!(out, "{indent}}} else {{").ok();
            writeln!(out, "{indent}    return Err(shrike_cbor::CborError::InvalidCbor(\"expected text in array\".into()));").ok();
            writeln!(out, "{indent}}}").ok();
        }
        FieldKind::Array(_) | FieldKind::JsonValue => {}
    }
}

// ─── Field classification ──────────────────────────────────────────

/// Classify a field's CBOR encoding kind based on the field schema and context.
///
/// For `Ref` fields, this resolves the target def to determine whether it's a
/// string/integer type alias (encoded as text/integer) vs a struct (encoded as map).
fn classify_field(ctx: &GenContext<'_>, field: &FieldSchema, rust_type: &str) -> FieldKind {
    match field {
        FieldSchema::String { format, .. } => match format.as_deref() {
            Some("datetime") => FieldKind::SyntaxText("shrike_syntax::Datetime".into()),
            Some("did") => FieldKind::SyntaxText("shrike_syntax::Did".into()),
            Some("handle") => FieldKind::SyntaxText("shrike_syntax::Handle".into()),
            Some("at-uri") => FieldKind::SyntaxText("shrike_syntax::AtUri".into()),
            Some("nsid") => FieldKind::SyntaxText("shrike_syntax::Nsid".into()),
            Some("tid") => FieldKind::SyntaxText("shrike_syntax::Tid".into()),
            Some("language") => FieldKind::SyntaxText("shrike_syntax::Language".into()),
            Some("record-key") => FieldKind::SyntaxText("shrike_syntax::RecordKey".into()),
            Some("at-identifier") => FieldKind::SyntaxText("shrike_syntax::AtIdentifier".into()),
            _ => FieldKind::Text,
        },
        FieldSchema::Integer { .. } => FieldKind::Integer,
        FieldSchema::Boolean { .. } => FieldKind::Bool,
        FieldSchema::Bytes { .. } => FieldKind::Bytes,
        FieldSchema::CidLink { .. } => FieldKind::CidLink,
        FieldSchema::Blob { .. } => FieldKind::Blob,
        FieldSchema::Unknown { .. } => FieldKind::JsonValue,
        FieldSchema::Object(_) => FieldKind::JsonValue,
        FieldSchema::Ref { reference, .. } => classify_ref(ctx, reference, rust_type),
        FieldSchema::Array { items, .. } => {
            let inner = classify_field(ctx, items, rust_type);
            FieldKind::Array(Box::new(inner))
        }
        FieldSchema::Union { .. } => FieldKind::Union,
    }
}

/// Classify a $ref to determine if the target is a text alias, integer alias,
/// blob, CID link, or a full struct.
fn classify_ref(ctx: &GenContext<'_>, reference: &str, _rust_type: &str) -> FieldKind {
    let (target_nsid, def_name) = shrike_lexicon::split_ref(&ctx.schema.id, reference);

    // Look up the target def.
    if let Some(schema) = ctx.schemas.get(&target_nsid)
        && let Some(def) = schema.defs.get(def_name)
    {
        return match def {
            shrike_lexicon::Def::StringDef(_) => FieldKind::Text,
            shrike_lexicon::Def::IntegerDef(_) => FieldKind::Integer,
            shrike_lexicon::Def::BooleanDef(_) => FieldKind::Bool,
            shrike_lexicon::Def::BytesDef(_) => FieldKind::Bytes,
            _ => FieldKind::Struct,
        };
    }
    // Fallback: treat as struct.
    FieldKind::Struct
}

/// Returns true if the given syntax type has an `as_str()` method.
/// Types backed by a `String` (not `u64` or enum) have `as_str()`.
/// `Tid` (u64) and `AtIdentifier` (enum) do not — use `.to_string()` instead.
fn syntax_has_as_str(ty: &str) -> bool {
    !matches!(ty, "shrike_syntax::Tid" | "shrike_syntax::AtIdentifier")
}

/// Strip `r#` prefix from a Rust field name for use as a variable name.
fn clean_field_name(name: &str) -> String {
    name.strip_prefix("r#").unwrap_or(name).to_string()
}

/// Returns true if this field kind should be skipped entirely in CBOR encoding.
fn is_json_only(kind: &FieldKind) -> bool {
    match kind {
        FieldKind::JsonValue => true,
        FieldKind::Array(inner) => is_json_only(inner),
        _ => false,
    }
}

/// Return the check expression for whether an optional field should be emitted.
fn option_check(f: &CborField) -> String {
    let access = format!("self.{}", f.rust_field);
    if f.rust_type.starts_with("Vec<") {
        format!("!{access}.is_empty()")
    } else if f.rust_type.starts_with("Option<") {
        format!("{access}.is_some()")
    } else {
        "true".to_string()
    }
}

/// Compare two string keys by CBOR encoding order (same as shrike_cbor::encode::cbor_key_cmp).
fn cbor_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_len = cbor_header_len(a.len() as u64) + a.len();
    let b_len = cbor_header_len(b.len() as u64) + b.len();
    a_len
        .cmp(&b_len)
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

fn cbor_header_len(value: u64) -> usize {
    if value < 24 {
        1
    } else if value <= u8::MAX as u64 {
        2
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::gen_struct::GenContext;
    use crate::loader;
    use std::collections::HashMap;
    use std::path::Path;

    fn test_ctx() -> (Config, HashMap<String, shrike_lexicon::Schema>) {
        let cfg = Config::load(Path::new("../../lexgen.json")).unwrap();
        let schemas = loader::load_schemas(Path::new("../../lexicons")).unwrap();
        (cfg, schemas)
    }

    #[test]
    fn gen_strong_ref_cbor() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("com.atproto.repo.strongRef").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::com::atproto",
        };
        if let shrike_lexicon::Def::Object(obj) = &schema.defs["main"] {
            let code = gen_cbor_impl(&ctx, "RepoStrongRef", obj).unwrap();
            assert!(code.contains("pub fn to_cbor(&self)"), "code:\n{code}");
            assert!(code.contains("pub fn encode_cbor(&self"), "code:\n{code}");
            assert!(
                code.contains("pub fn from_cbor(data: &[u8])"),
                "code:\n{code}"
            );
            assert!(
                code.contains("pub fn decode_cbor(decoder:"),
                "code:\n{code}"
            );
            // Fields should be in CBOR key order: "cid" (3 bytes) before "uri" (3 bytes),
            // then sorted lexicographically: "cid" < "uri"
            let cid_pos = code.find("\"cid\"").unwrap();
            let uri_pos = code.find("\"uri\"").unwrap();
            assert!(
                cid_pos < uri_pos,
                "cid should come before uri in CBOR order"
            );
        } else {
            panic!("expected Object def");
        }
    }

    #[test]
    fn gen_feed_post_cbor() {
        let (cfg, schemas) = test_ctx();
        let schema = schemas.get("app.bsky.feed.post").unwrap();
        let ctx = GenContext {
            schema,
            cfg: &cfg,
            schemas: &schemas,
            caller_module: "crate::app::bsky",
        };
        if let shrike_lexicon::Def::Record(rec) = &schema.defs["main"] {
            let code = gen_cbor_impl(&ctx, "FeedPost", &rec.record).unwrap();
            assert!(code.contains("pub fn to_cbor(&self)"), "code:\n{code}");
            assert!(
                code.contains("pub fn from_cbor(data: &[u8])"),
                "code:\n{code}"
            );
            // "text" (4 bytes) should come before "embed" (5 bytes) in CBOR order
            // because shorter keys sort first
            let text_pos = code.find("encode_text(\"text\")").unwrap();
            let embed_pos = code.find("\"embed\"").unwrap();
            assert!(
                text_pos < embed_pos,
                "text (4 chars) should come before embed (5 chars) in CBOR key order"
            );
        } else {
            panic!("expected Record def");
        }
    }

    #[test]
    fn cbor_key_order_sorts_by_length_then_lex() {
        use std::cmp::Ordering;
        // Same length, lex order
        assert_eq!(cbor_key_cmp("cid", "uri"), Ordering::Less);
        // Shorter first
        assert_eq!(cbor_key_cmp("text", "embed"), Ordering::Less);
        assert_eq!(cbor_key_cmp("a", "bb"), Ordering::Less);
    }
}
