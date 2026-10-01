use serde_json::Value;

use crate::lexicon::catalog::Catalog;
use crate::lexicon::error::{ValidationError, ValidationErrorKind};
use crate::lexicon::schema::{Def, FieldSchema, ObjectDef, RecordDef, split_ref};

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

/// Validate a single JSON value against a field schema.
///
/// Useful for validating individual fields outside the context of a full
/// record (e.g., testing a string against format or length constraints).
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

/// Validate XRPC parameters against the `parameters` of the query, procedure
/// or subscription `nsid`, filling in declared defaults.
///
/// `params` holds already-decoded values (integers, booleans, strings and
/// arrays of them). Keys not declared by the schema are left untouched. As in
/// the reference, a missing required parameter with a default is satisfied by
/// the default.
pub fn validate_params(
    catalog: &Catalog,
    nsid: &str,
    params: &mut serde_json::Map<String, Value>,
) -> Result<(), ValidationError> {
    let def = method_def(catalog, nsid)?;
    let Some(params_def) = (match def {
        Def::Query(q) => q.parameters.as_ref(),
        Def::Procedure(p) => p.parameters.as_ref(),
        Def::Subscription(s) => s.parameters.as_ref(),
        _ => return Err(not_a_method(nsid)),
    }) else {
        return Ok(());
    };

    let mut errors = Vec::new();
    // Deterministic error order regardless of HashMap iteration order.
    let mut names: Vec<&String> = params_def.properties.keys().collect();
    names.sort();
    for name in names {
        let Some(field) = params_def.properties.get(name) else {
            continue;
        };
        match params.get(name.as_str()) {
            Some(value) => {
                validate_field(catalog, nsid, name, field, value, false, &mut errors);
            }
            None => {
                if let Some(default) = field.default_value() {
                    params.insert(name.clone(), default);
                } else if params_def.required.contains(name) {
                    field_err(name, ValidationErrorKind::Required, &mut errors);
                }
            }
        }
    }
    finalize(errors)
}

/// Validate a procedure's JSON input body, filling in declared defaults.
///
/// Passes if the procedure declares no input schema (the reference does the
/// same; encoding checks are the server's job).
pub fn validate_input(
    catalog: &Catalog,
    nsid: &str,
    value: &mut Value,
) -> Result<(), ValidationError> {
    let schema = match method_def(catalog, nsid)? {
        Def::Procedure(p) => p.input.as_ref().and_then(|b| b.schema.as_ref()),
        _ => return Err(not_a_method(nsid)),
    };
    let Some(schema) = schema else {
        return Ok(());
    };
    validate_value_at(catalog, nsid, "input", schema, value)?;
    apply_defaults(catalog, nsid, schema, value);
    Ok(())
}

/// Validate a query's or procedure's JSON output body.
pub fn validate_output(
    catalog: &Catalog,
    nsid: &str,
    value: &Value,
) -> Result<(), ValidationError> {
    let schema = match method_def(catalog, nsid)? {
        Def::Query(q) => q.output.as_ref(),
        Def::Procedure(p) => p.output.as_ref(),
        _ => return Err(not_a_method(nsid)),
    }
    .and_then(|b| b.schema.as_ref());
    match schema {
        Some(schema) => validate_value_at(catalog, nsid, "output", schema, value),
        None => Ok(()),
    }
}

/// Validate a subscription message (including its `$type`).
pub fn validate_message(
    catalog: &Catalog,
    nsid: &str,
    value: &Value,
) -> Result<(), ValidationError> {
    let schema = match method_def(catalog, nsid)? {
        Def::Subscription(s) => s.message.as_ref().and_then(|m| m.schema.as_ref()),
        _ => return Err(not_a_method(nsid)),
    };
    match schema {
        Some(schema) => validate_value_at(catalog, nsid, "message", schema, value),
        None => Ok(()),
    }
}

fn method_def<'a>(catalog: &'a Catalog, nsid: &str) -> Result<&'a Def, ValidationError> {
    catalog
        .main_def(nsid)
        .ok_or_else(|| ValidationError::Schema(format!("no lexicon for {nsid}")))
}

fn not_a_method(nsid: &str) -> ValidationError {
    ValidationError::Schema(format!("lexicon {nsid} is not a matching XRPC method"))
}

fn validate_value_at(
    catalog: &Catalog,
    nsid: &str,
    path: &str,
    field: &FieldSchema,
    value: &Value,
) -> Result<(), ValidationError> {
    let mut errors = Vec::new();
    validate_field(catalog, nsid, path, field, value, false, &mut errors);
    finalize(errors)
}

/// Bound on ref/union indirection while filling defaults; data depth bounds
/// everything else.
const MAX_DEFAULT_REF_DEPTH: usize = 64;

/// Insert declared defaults for missing object properties, recursing into
/// present nested objects, arrays, refs and unions. Call only on a value that
/// has already validated.
fn apply_defaults(catalog: &Catalog, nsid: &str, field: &FieldSchema, value: &mut Value) {
    apply_defaults_inner(catalog, nsid, field, value, 0);
}

fn apply_defaults_inner(
    catalog: &Catalog,
    nsid: &str,
    field: &FieldSchema,
    value: &mut Value,
    depth: usize,
) {
    if depth > MAX_DEFAULT_REF_DEPTH {
        return;
    }
    match field {
        FieldSchema::Object(obj) => apply_object_defaults(catalog, nsid, obj, value, depth),
        FieldSchema::Array { items, .. } => {
            if let Value::Array(elems) = value {
                for elem in elems {
                    apply_defaults_inner(catalog, nsid, items, elem, depth);
                }
            }
        }
        FieldSchema::Ref { reference, .. } => {
            let (target, def_name) = split_ref(nsid, reference);
            apply_def_defaults(catalog, &target, def_name, value, depth + 1);
        }
        FieldSchema::Union { refs, .. } => {
            let Some(type_name) = value.get("$type").and_then(Value::as_str) else {
                return;
            };
            let Some((target, def_name)) = refs
                .iter()
                .find_map(|r| union_ref_match(nsid, r, type_name))
            else {
                return;
            };
            apply_def_defaults(catalog, &target, def_name, value, depth + 1);
        }
        _ => {}
    }
}

fn apply_def_defaults(
    catalog: &Catalog,
    nsid: &str,
    def_name: &str,
    value: &mut Value,
    depth: usize,
) {
    match catalog.get(nsid).and_then(|s| s.defs.get(def_name)) {
        Some(Def::Object(obj)) => apply_object_defaults(catalog, nsid, obj, value, depth),
        Some(Def::Record(RecordDef { record, .. })) => {
            apply_object_defaults(catalog, nsid, record, value, depth)
        }
        _ => {}
    }
}

fn apply_object_defaults(
    catalog: &Catalog,
    nsid: &str,
    obj: &ObjectDef,
    value: &mut Value,
    depth: usize,
) {
    let Value::Object(map) = value else {
        return;
    };
    for (name, field) in &obj.properties {
        match map.get_mut(name.as_str()) {
            Some(Value::Null) => {}
            Some(child) => apply_defaults_inner(catalog, nsid, field, child, depth),
            None => {
                if let Some(default) = field.default_value() {
                    map.insert(name.clone(), default);
                }
            }
        }
    }
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
            min_graphemes,
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
                min_graphemes: *min_graphemes,
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
            const_val,
            ..
        } => validate_integer(
            path,
            value,
            *minimum,
            *maximum,
            r#enum.as_deref(),
            *const_val,
            errors,
        ),

        FieldSchema::Boolean { const_val, .. } => validate_boolean(path, value, *const_val, errors),

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
    min_graphemes: Option<u64>,
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

    if c.min_graphemes.is_some() || c.max_graphemes.is_some() {
        let gc = grapheme_count(s) as u64;
        if let Some(min) = c.min_graphemes
            && gc < min
        {
            field_err(path, ValidationErrorKind::TooShort { min, got: gc }, errors);
        }
        if let Some(max) = c.max_graphemes
            && gc > max
        {
            field_err(path, ValidationErrorKind::TooLong { max, got: gc }, errors);
        }
    }

    if let Some(fmt) = c.format {
        validate_string_format(path, fmt, s, errors);
    }
}

/// Count extended grapheme clusters (UAX #29), as the reference does.
fn grapheme_count(s: &str) -> usize {
    use unicode_segmentation::UnicodeSegmentation;
    s.graphemes(true).count()
}

/// The reference `isValidUri`: `/^\w+:(?:\/\/)?[^\s/][^\s]*$/`.
fn is_valid_uri(s: &str) -> bool {
    // JavaScript's `\s` also matches U+FEFF, which Rust does not count as
    // whitespace.
    let is_space = |c: char| c.is_whitespace() || c == '\u{feff}';
    let Some((scheme, rest)) = s.split_once(':') else {
        return false;
    };
    if scheme.is_empty()
        || !scheme
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return false;
    }
    let rest = rest.strip_prefix("//").unwrap_or(rest);
    let mut chars = rest.chars();
    match chars.next() {
        Some(c) if c != '/' && !is_space(c) => chars.all(|c| !is_space(c)),
        _ => false,
    }
}

fn validate_string_format(path: &str, format: &str, s: &str, errors: &mut Vec<ValidationError>) {
    use crate::syntax::{
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
        "cid" => crate::cbor::json::is_cid_string(s),
        "uri" => is_valid_uri(s),
        // Unknown formats are accepted for forward compatibility.
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
    const_val: Option<i64>,
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
                // A whole-valued float outside i64 range must be rejected, not
                // saturated (`f as i64` clamps to i64::MAX/MIN, silently
                // corrupting the value). AT Protocol integers are signed 64-bit.
                if f < i64::MIN as f64 || f > i64::MAX as f64 {
                    other_err(path, format!("integer {f} out of i64 range"), errors);
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

    // `const`: the value must equal the fixed constant.
    if let Some(c) = const_val
        && n != c
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

fn validate_boolean(
    path: &str,
    value: &Value,
    const_val: Option<bool>,
    errors: &mut Vec<ValidationError>,
) {
    let b = match value.as_bool() {
        Some(b) => b,
        None => {
            field_err(
                path,
                ValidationErrorKind::TypeMismatch {
                    expected: "boolean".to_owned(),
                    got: json_type_name(value).to_owned(),
                },
                errors,
            );
            return;
        }
    };

    // `const`: the value must equal the fixed constant.
    if let Some(c) = const_val
        && b != c
    {
        field_err(
            path,
            ValidationErrorKind::InvalidEnum { got: b.to_string() },
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
    // In JSON, bytes are an object with a "$bytes" key holding base64. The
    // length limits apply to the decoded bytes.
    let byte_len: u64 = match value {
        Value::Object(m) => {
            if let Some(b64) = m.get("$bytes").and_then(|v| v.as_str()) {
                match crate::base64::decode(b64) {
                    Some(raw) => raw.len() as u64,
                    None => {
                        other_err(path, "$bytes is not valid base64", errors);
                        return;
                    }
                }
            } else {
                other_err(path, "bytes object missing $bytes key", errors);
                return;
            }
        }
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
            } else if !is_link(m) {
                other_err(path, "cid-link $link is not a valid CID", errors);
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

/// Whether `m` is exactly `{"$link": "<cid>"}`; anything else is a plain
/// object in the JSON data model, not a link.
fn is_link(m: &serde_json::Map<String, Value>) -> bool {
    m.len() == 1
        && m.get("$link")
            .and_then(Value::as_str)
            .is_some_and(crate::cbor::json::is_cid_string)
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

    // `ref` is required and must be a cid-link object ({"$link": "<cid>"}).
    match m.get("ref") {
        None => other_err(path, "blob missing ref", errors),
        Some(Value::Object(r)) => {
            if !r.get("$link").map(|v| v.is_string()).unwrap_or(false) {
                other_err(path, "blob ref missing $link string", errors);
            } else if !is_link(r) {
                other_err(path, "blob ref $link is not a valid CID", errors);
            }
        }
        Some(other) => other_err(
            path,
            format!("blob ref expected object, got {}", json_type_name(other)),
            errors,
        ),
    }

    // `mimeType` is required and must be a (non-empty) string.
    match m.get("mimeType") {
        None => other_err(path, "blob missing mimeType", errors),
        Some(Value::String(mime)) => {
            if mime.is_empty() {
                other_err(path, "blob mimeType must not be empty", errors);
            } else if let Some(accept_types) = accept
                && !match_mime(accept_types, mime)
            {
                other_err(path, format!("blob mimeType {mime:?} not accepted"), errors);
            }
        }
        Some(other) => other_err(
            path,
            format!(
                "blob mimeType expected string, got {}",
                json_type_name(other)
            ),
            errors,
        ),
    }

    // `size` is required and must be a non-negative integer.
    match m.get("size") {
        None => other_err(path, "blob missing size", errors),
        Some(Value::Number(_)) => {
            if let Some(size) = m.get("size").and_then(|v| v.as_u64())
                && let Some(max) = max_size
                && size > max
            {
                field_err(
                    path,
                    ValidationErrorKind::TooLong { max, got: size },
                    errors,
                );
            }
        }
        Some(other) => other_err(
            path,
            format!("blob size expected number, got {}", json_type_name(other)),
            errors,
        ),
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

    // Check required fields. A missing field with a declared default is
    // satisfied by that default, as in the reference.
    for req in &obj.required {
        match map.get(req.as_str()) {
            None if obj
                .properties
                .get(req)
                .is_some_and(|f| f.default_value().is_some()) => {}
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

        Def::BooleanDef(_) => validate_boolean(path, value, None, errors),

        Def::IntegerDef(_) => validate_integer(path, value, None, None, None, None, errors),

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

/// If the union ref `reference` (relative to `nsid`) names the type
/// `type_name`, return its target NSID and def name. `nsid` and `nsid#main`
/// are the same type on both sides.
fn union_ref_match<'a>(
    nsid: &str,
    reference: &'a str,
    type_name: &str,
) -> Option<(String, &'a str)> {
    let (target, def_name) = split_ref(nsid, reference);
    let (type_nsid, type_def) = type_name.split_once('#').unwrap_or((type_name, "main"));
    (type_nsid == target && type_def == def_name).then_some((target, def_name))
}

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
    if type_name.matches('#').count() > 1 {
        other_err(
            path,
            format!("union $type {type_name:?} has more than one #"),
            errors,
        );
        return;
    }

    // Try each ref to find a match.
    for reference in refs {
        let Some((target_nsid, def_name)) = union_ref_match(nsid, reference, type_name) else {
            continue;
        };

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
