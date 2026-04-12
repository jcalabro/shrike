use serde_json::Value;

use crate::catalog::Catalog;
use crate::error::{ValidationError, ValidationErrorKind};
use crate::schema::{Def, FieldSchema, ObjectDef, RecordDef, split_ref};

// ---------------------------------------------------------------------------
// Public entry points
// ---------------------------------------------------------------------------

/// Validate a record value against the schema for `collection`.
///
/// `record` is expected to be a JSON object (as produced by `serde_json`).
/// Extra fields not declared in the schema are silently accepted (forward
/// compatibility per AT Protocol spec).
pub fn validate_record(
    catalog: &Catalog,
    collection: &str,
    record: &Value,
) -> Result<(), ValidationError> {
    let schema = catalog
        .get(collection)
        .ok_or_else(|| ValidationError::UnknownCollection(collection.to_owned()))?;

    let def = schema
        .defs
        .get("main")
        .ok_or_else(|| ValidationError::Schema(format!("schema {collection} has no main def")))?;

    let record_def = match def {
        Def::Record(r) => r,
        _ => {
            return Err(ValidationError::Schema(format!(
                "main def in {collection} is not a record"
            )));
        }
    };

    // If $type is present it must match the collection.
    if let Some(obj) = record.as_object()
        && let Some(t) = obj.get("$type")
        && t.as_str() != Some(collection)
    {
        return Err(ValidationError::Field {
            path: "$type".to_owned(),
            kind: ValidationErrorKind::TypeMismatch {
                expected: collection.to_owned(),
                got: t.to_string(),
            },
        });
    }

    let mut errors: Vec<ValidationError> = Vec::new();
    validate_object_inner(
        catalog,
        collection,
        "record",
        &record_def.record,
        record,
        &mut errors,
    );
    finalize(errors)
}

/// Validate a single `value` against `field` schema.
pub fn validate_value(
    catalog: &Catalog,
    context_nsid: &str,
    field: &FieldSchema,
    value: &Value,
) -> Result<(), ValidationError> {
    let mut errors: Vec<ValidationError> = Vec::new();
    validate_field(
        catalog,
        context_nsid,
        "value",
        field,
        value,
        false,
        &mut errors,
    );
    finalize(errors)
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn finalize(mut errors: Vec<ValidationError>) -> Result<(), ValidationError> {
    match errors.len() {
        0 => Ok(()),
        1 => Err(errors.remove(0)),
        _ => Err(ValidationError::Multiple(errors)),
    }
}

fn field_err(path: &str, kind: ValidationErrorKind, errors: &mut Vec<ValidationError>) {
    errors.push(ValidationError::Field {
        path: path.to_owned(),
        kind,
    });
}

fn other_err(path: &str, msg: impl Into<String>, errors: &mut Vec<ValidationError>) {
    field_err(path, ValidationErrorKind::Other(msg.into()), errors);
}

fn child_path(parent: &str, field: &str) -> String {
    if parent.is_empty() {
        field.to_owned()
    } else {
        format!("{parent}.{field}")
    }
}

fn index_path(parent: &str, i: usize) -> String {
    format!("{parent}[{i}]")
}

fn json_type_name(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

// ---------------------------------------------------------------------------
// validate_field — dispatch to type-specific validators
// ---------------------------------------------------------------------------

fn validate_field(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    field: &FieldSchema,
    value: &Value,
    nullable: bool,
    errors: &mut Vec<ValidationError>,
) {
    if value.is_null() {
        if nullable {
            return;
        }
        other_err(path, "value is required (got null)", errors);
        return;
    }

    match field {
        FieldSchema::String {
            min_length,
            max_length,
            max_graphemes,
            r#enum,
            format,
            const_val,
            ..
        } => validate_string(
            path,
            value,
            StringConstraints {
                min_length: *min_length,
                max_length: *max_length,
                max_graphemes: *max_graphemes,
                enum_vals: r#enum.as_deref(),
                format: format.as_deref(),
                const_val: const_val.as_deref(),
            },
            errors,
        ),

        FieldSchema::Integer {
            minimum,
            maximum,
            r#enum,
            ..
        } => validate_integer(path, value, *minimum, *maximum, r#enum.as_deref(), errors),

        FieldSchema::Boolean { .. } => validate_boolean(path, value, errors),

        FieldSchema::Bytes {
            min_length,
            max_length,
            ..
        } => validate_bytes(path, value, *min_length, *max_length, errors),

        FieldSchema::CidLink { .. } => validate_cid_link(path, value, errors),

        FieldSchema::Blob {
            accept, max_size, ..
        } => validate_blob(path, value, accept.as_deref(), *max_size, errors),

        FieldSchema::Array {
            items,
            min_length,
            max_length,
            ..
        } => validate_array(
            catalog,
            nsid,
            path,
            value,
            items,
            *min_length,
            *max_length,
            errors,
        ),

        FieldSchema::Object(obj_def) => {
            validate_object_inner(catalog, nsid, path, obj_def, value, errors)
        }

        FieldSchema::Ref { reference, .. } => {
            validate_ref(catalog, nsid, path, reference, value, errors);
        }

        FieldSchema::Union { refs, closed, .. } => {
            validate_union(
                catalog,
                nsid,
                path,
                refs,
                closed.unwrap_or(false),
                value,
                errors,
            );
        }

        FieldSchema::Unknown { .. } => {
            // Accept any non-null value; just require it to be an object.
            if !value.is_object() {
                field_err(
                    path,
                    ValidationErrorKind::TypeMismatch {
                        expected: "object".to_owned(),
                        got: json_type_name(value).to_owned(),
                    },
                    errors,
                );
            }
        }
    }
}

// ---------------------------------------------------------------------------
// String
// ---------------------------------------------------------------------------

/// Holds the constraints for string validation to avoid too-many-arguments.
struct StringConstraints<'a> {
    min_length: Option<u64>,
    max_length: Option<u64>,
    max_graphemes: Option<u64>,
    enum_vals: Option<&'a [String]>,
    format: Option<&'a str>,
    const_val: Option<&'a str>,
}

fn validate_string(
    path: &str,
    value: &Value,
    constraints: StringConstraints<'_>,
    errors: &mut Vec<ValidationError>,
) {
    let s = match value.as_str() {
        Some(s) => s,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "string".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    check_string_constraints(path, s, &constraints, errors);
}

fn check_string_constraints(
    path: &str,
    s: &str,
    c: &StringConstraints<'_>,
    errors: &mut Vec<ValidationError>,
) {
    if let Some(cv) = c.const_val
        && s != cv
    {
        other_err(path, format!("expected const {cv:?}"), errors);
    }

    if let Some(vals) = c.enum_vals
        && !vals.iter().any(|e| e == s)
    {
        field_err(
            path,
            ValidationErrorKind::InvalidEnum { got: s.to_owned() },
            errors,
        );
    }

    let byte_len = s.len() as u64;
    if let Some(min) = c.min_length
        && byte_len < min
    {
        field_err(
            path,
            ValidationErrorKind::TooShort { min, got: byte_len },
            errors,
        );
    }
    if let Some(max) = c.max_length
        && byte_len > max
    {
        field_err(
            path,
            ValidationErrorKind::TooLong { max, got: byte_len },
            errors,
        );
    }

    if let Some(max_g) = c.max_graphemes {
        let gc = grapheme_count(s) as u64;
        if gc > max_g {
            field_err(
                path,
                ValidationErrorKind::TooLong {
                    max: max_g,
                    got: gc,
                },
                errors,
            );
        }
    }

    if let Some(fmt) = c.format {
        validate_string_format(path, fmt, s, errors);
    }
}

/// Count Unicode scalar values as a proxy for grapheme clusters.
/// Good enough for AT Protocol limits without pulling in a heavy dependency.
fn grapheme_count(s: &str) -> usize {
    s.chars().count()
}

fn validate_string_format(path: &str, format: &str, s: &str, errors: &mut Vec<ValidationError>) {
    use shrike_syntax::{
        AtIdentifier, AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid,
    };

    let valid = match format {
        "did" => Did::try_from(s).is_ok(),
        "handle" => Handle::try_from(s).is_ok(),
        "at-uri" => AtUri::try_from(s).is_ok(),
        "at-identifier" => AtIdentifier::try_from(s).is_ok(),
        "nsid" => Nsid::try_from(s).is_ok(),
        "datetime" => Datetime::parse(s).is_ok(),
        "tid" => Tid::try_from(s).is_ok(),
        "record-key" => RecordKey::try_from(s).is_ok(),
        "language" => Language::try_from(s).is_ok(),
        // "cid" and "uri" are valid but we don't have parsers for them yet —
        // skip for forward compatibility.
        _ => return,
    };

    if !valid {
        other_err(path, format!("invalid {format} format: {s:?}"), errors);
    }
}

// ---------------------------------------------------------------------------
// Integer
// ---------------------------------------------------------------------------

fn validate_integer(
    path: &str,
    value: &Value,
    minimum: Option<i64>,
    maximum: Option<i64>,
    enum_vals: Option<&[i64]>,
    errors: &mut Vec<ValidationError>,
) {
    let n = match value {
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                i
            } else if let Some(f) = n.as_f64() {
                if f.fract() != 0.0 {
                    other_err(path, format!("float {f} is not a valid integer"), errors);
                    return;
                }
                f as i64
            } else {
                other_err(path, "number out of i64 range", errors);
                return;
            }
        }
        _ => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "integer".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    if let Some(min) = minimum
        && n < min
    {
        field_err(path, ValidationErrorKind::OutOfRange, errors);
    }
    if let Some(max) = maximum
        && n > max
    {
        field_err(path, ValidationErrorKind::OutOfRange, errors);
    }

    if let Some(vals) = enum_vals
        && !vals.contains(&n)
    {
        field_err(
            path,
            ValidationErrorKind::InvalidEnum { got: n.to_string() },
            errors,
        );
    }
}

// ---------------------------------------------------------------------------
// Boolean
// ---------------------------------------------------------------------------

fn validate_boolean(path: &str, value: &Value, errors: &mut Vec<ValidationError>) {
    if !value.is_boolean() {
        field_err(
            path,
            ValidationErrorKind::TypeMismatch {
                expected: "boolean".to_owned(),
                got: json_type_name(value).to_owned(),
            },
            errors,
        );
    }
}

// ---------------------------------------------------------------------------
// Bytes
// ---------------------------------------------------------------------------

fn validate_bytes(
    path: &str,
    value: &Value,
    min_length: Option<u64>,
    max_length: Option<u64>,
    errors: &mut Vec<ValidationError>,
) {
    // In JSON, bytes are represented as objects with a "$bytes" key (base64).
    // We accept either that form or a plain string (unusual but permitted for
    // forward compat).
    let byte_len: u64 = match value {
        Value::Object(m) => {
            if let Some(b64) = m.get("$bytes").and_then(|v| v.as_str()) {
                // base64-encoded length → approximate raw byte count
                (b64.len() as u64 * 3) / 4
            } else {
                other_err(path, "bytes object missing $bytes key", errors);
                return;
            }
        }
        Value::String(s) => s.len() as u64,
        _ => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "bytes".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    if let Some(min) = min_length
        && byte_len < min
    {
        field_err(
            path,
            ValidationErrorKind::TooShort { min, got: byte_len },
            errors,
        );
    }
    if let Some(max) = max_length
        && byte_len > max
    {
        field_err(
            path,
            ValidationErrorKind::TooLong { max, got: byte_len },
            errors,
        );
    }
}

// ---------------------------------------------------------------------------
// CID-link
// ---------------------------------------------------------------------------

fn validate_cid_link(path: &str, value: &Value, errors: &mut Vec<ValidationError>) {
    // JSON representation: {"$link": "bafyrei..."}
    match value {
        Value::Object(m) => {
            if !m.contains_key("$link") {
                other_err(path, "cid-link object missing $link key", errors);
            }
        }
        _ => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "cid-link object".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
        }
    }
}

// ---------------------------------------------------------------------------
// Blob
// ---------------------------------------------------------------------------

fn validate_blob(
    path: &str,
    value: &Value,
    accept: Option<&[String]>,
    max_size: Option<u64>,
    errors: &mut Vec<ValidationError>,
) {
    let m = match value.as_object() {
        Some(m) => m,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "blob object".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    match m.get("$type").and_then(|v| v.as_str()) {
        Some("blob") => {}
        _ => other_err(path, "blob missing or wrong $type", errors),
    }

    if let Some(accept_types) = accept
        && let Some(mime) = m.get("mimeType").and_then(|v| v.as_str())
        && !match_mime(accept_types, mime)
    {
        other_err(path, format!("blob mimeType {mime:?} not accepted"), errors);
    }

    if let Some(max) = max_size
        && let Some(size) = m.get("size").and_then(|v| v.as_u64())
        && size > max
    {
        field_err(
            path,
            ValidationErrorKind::TooLong { max, got: size },
            errors,
        );
    }
}

fn match_mime(accept: &[String], mime_type: &str) -> bool {
    accept.iter().any(|pattern| {
        if pattern == "*/*" {
            true
        } else if let Some(prefix) = pattern.strip_suffix("/*") {
            mime_type.starts_with(&format!("{prefix}/"))
        } else {
            pattern == mime_type
        }
    })
}

// ---------------------------------------------------------------------------
// Array
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
fn validate_array(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    value: &Value,
    items: &FieldSchema,
    min_length: Option<u64>,
    max_length: Option<u64>,
    errors: &mut Vec<ValidationError>,
) {
    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "array".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    let len = arr.len() as u64;
    if let Some(min) = min_length
        && len < min
    {
        field_err(
            path,
            ValidationErrorKind::TooShort { min, got: len },
            errors,
        );
    }
    if let Some(max) = max_length
        && len > max
    {
        field_err(path, ValidationErrorKind::TooLong { max, got: len }, errors);
    }

    for (i, elem) in arr.iter().enumerate() {
        let elem_path = index_path(path, i);
        validate_field(catalog, nsid, &elem_path, items, elem, false, errors);
    }
}

// ---------------------------------------------------------------------------
// Object
// ---------------------------------------------------------------------------

fn validate_object_inner(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    obj: &ObjectDef,
    value: &Value,
    errors: &mut Vec<ValidationError>,
) {
    let map = match value.as_object() {
        Some(m) => m,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "object".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    let nullable_set: std::collections::HashSet<&str> =
        obj.nullable.iter().map(String::as_str).collect();

    // Check required fields.
    for req in &obj.required {
        match map.get(req.as_str()) {
            None => {
                let field_path = child_path(path, req);
                field_err(&field_path, ValidationErrorKind::Required, errors);
            }
            Some(Value::Null) if !nullable_set.contains(req.as_str()) => {
                let field_path = child_path(path, req);
                other_err(&field_path, "required field is null", errors);
            }
            _ => {}
        }
    }

    // Validate each declared property that exists in the data.
    for (name, field_schema) in &obj.properties {
        if let Some(field_val) = map.get(name.as_str()) {
            let field_path = child_path(path, name);
            let is_nullable = nullable_set.contains(name.as_str());
            validate_field(
                catalog,
                nsid,
                &field_path,
                field_schema,
                field_val,
                is_nullable,
                errors,
            );
        }
        // Extra / unknown keys: silently accepted per AT Protocol spec.
    }
}

// ---------------------------------------------------------------------------
// Ref
// ---------------------------------------------------------------------------

fn validate_ref(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    reference: &str,
    value: &Value,
    errors: &mut Vec<ValidationError>,
) {
    let (target_nsid, def_name) = split_ref(nsid, reference);

    let schema = match catalog.get(&target_nsid) {
        Some(s) => s,
        None => {
            other_err(
                path,
                format!("unresolved ref: schema {target_nsid} not found"),
                errors,
            );
            return;
        }
    };

    let def = match schema.defs.get(def_name) {
        Some(d) => d,
        None => {
            other_err(
                path,
                format!("unresolved ref: def {def_name} not found in {target_nsid}"),
                errors,
            );
            return;
        }
    };

    validate_def(catalog, &target_nsid, path, def, value, errors);
}

fn validate_def(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    def: &Def,
    value: &Value,
    errors: &mut Vec<ValidationError>,
) {
    match def {
        Def::Object(obj) => {
            validate_object_inner(catalog, nsid, path, obj, value, errors);
        }

        Def::Record(RecordDef { record, .. }) => {
            validate_object_inner(catalog, nsid, path, record, value, errors);
        }

        Def::StringDef(_) => {
            if !value.is_string() {
                field_err(
                    path,
                    ValidationErrorKind::TypeMismatch {
                        expected: "string".to_owned(),
                        got: json_type_name(value).to_owned(),
                    },
                    errors,
                );
            }
        }

        Def::BooleanDef(_) => validate_boolean(path, value, errors),

        Def::IntegerDef(_) => validate_integer(path, value, None, None, None, errors),

        Def::BytesDef(_) => validate_bytes(path, value, None, None, errors),

        Def::Token(_) => {
            if !value.is_string() {
                field_err(
                    path,
                    ValidationErrorKind::TypeMismatch {
                        expected: "string".to_owned(),
                        got: json_type_name(value).to_owned(),
                    },
                    errors,
                );
            }
        }

        Def::ArrayDef(_) => {
            if !value.is_array() {
                field_err(
                    path,
                    ValidationErrorKind::TypeMismatch {
                        expected: "array".to_owned(),
                        got: json_type_name(value).to_owned(),
                    },
                    errors,
                );
            }
        }

        Def::Query(_) | Def::Procedure(_) | Def::Subscription(_) => {
            other_err(
                path,
                "cannot validate against query/procedure/subscription def",
                errors,
            );
        }

        Def::Unknown => {
            other_err(path, "cannot validate against unknown def type", errors);
        }
    }
}

// ---------------------------------------------------------------------------
// Union
// ---------------------------------------------------------------------------

fn validate_union(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    refs: &[String],
    closed: bool,
    value: &Value,
    errors: &mut Vec<ValidationError>,
) {
    let map = match value.as_object() {
        Some(m) => m,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "union object".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    let type_val = match map.get("$type") {
        Some(v) => v,
        None => {
            other_err(path, "union missing $type", errors);
            return;
        }
    };

    let type_name = match type_val.as_str() {
        Some(s) => s,
        None => {
            other_err(path, "union $type is not a string", errors);
            return;
        }
    };

    // Try each ref to find a match.
    for reference in refs {
        let (target_nsid, def_name) = split_ref(nsid, reference);

        let full_ref = if def_name == "main" {
            target_nsid.clone()
        } else {
            format!("{target_nsid}#{def_name}")
        };

        if type_name != full_ref {
            continue;
        }

        // Found a matching type — validate.
        let schema = match catalog.get(&target_nsid) {
            Some(s) => s,
            None => {
                other_err(
                    path,
                    format!("unresolved union ref: schema {target_nsid} not found"),
                    errors,
                );
                return;
            }
        };

        let def = match schema.defs.get(def_name) {
            Some(d) => d,
            None => {
                other_err(
                    path,
                    format!("unresolved union ref: def {def_name} not found in {target_nsid}"),
                    errors,
                );
                return;
            }
        };

        validate_def(catalog, &target_nsid, path, def, value, errors);
        return;
    }

    // No match found.
    if closed {
        other_err(
            path,
            format!("union $type {type_name:?} not in closed union"),
            errors,
        );
    }
    // Open union: silently accept unknown types.
}
