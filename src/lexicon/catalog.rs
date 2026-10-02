use std::collections::HashMap;

use crate::lexicon::error::LexiconError;
use crate::lexicon::schema::{Def, FieldSchema, ObjectDef, ParamsDef, Schema};

/// A collection of parsed Lexicon schemas, keyed by NSID.
pub struct Catalog {
    schemas: HashMap<String, Schema, crate::cbor::cid::FastHashState>,
}

impl Catalog {
    /// Create a new, empty catalog.
    pub fn new() -> Self {
        Catalog {
            schemas: HashMap::default(),
        }
    }

    /// Parse a Lexicon JSON document and add it to the catalog.
    ///
    /// Returns an error if the JSON is invalid, the document has an unsupported
    /// lexicon version, or is missing required fields.
    pub fn add_schema(&mut self, json: &[u8]) -> Result<(), LexiconError> {
        let schema = check_schema(serde_json::from_slice(json)?)?;
        self.schemas.insert(schema.id.clone(), schema);
        Ok(())
    }

    /// Look up a schema by its NSID.
    pub fn get(&self, nsid: &str) -> Option<&Schema> {
        self.schemas.get(nsid)
    }

    /// Look up the `main` definition of the schema with the given NSID.
    pub fn main_def(&self, nsid: &str) -> Option<&Def> {
        self.get(nsid)?.defs.get("main")
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}

/// Check a parsed Lexicon document the way [`Catalog::add_schema`] does.
pub(crate) fn check_schema(schema: Schema) -> Result<Schema, LexiconError> {
    if schema.lexicon != 1 {
        return Err(LexiconError::InvalidSchema(format!(
            "unsupported lexicon version {}",
            schema.lexicon
        )));
    }
    if schema.id.is_empty() {
        return Err(LexiconError::InvalidSchema("missing id".to_owned()));
    }
    for def in schema.defs.values() {
        check_def(def)?;
    }
    Ok(schema)
}

/// Structural checks the reference parser makes beyond the JSON shape.
fn check_def(def: &Def) -> Result<(), LexiconError> {
    match def {
        Def::Record(r) => check_object(&r.record),
        Def::Object(o) => check_object(o),
        Def::Query(q) => {
            check_params(q.parameters.as_ref())?;
            check_body(q.output.as_ref().and_then(|b| b.schema.as_ref()))
        }
        Def::Procedure(p) => {
            check_params(p.parameters.as_ref())?;
            check_body(p.input.as_ref().and_then(|b| b.schema.as_ref()))?;
            check_body(p.output.as_ref().and_then(|b| b.schema.as_ref()))
        }
        Def::Subscription(s) => {
            check_params(s.parameters.as_ref())?;
            check_body(s.message.as_ref().and_then(|m| m.schema.as_ref()))
        }
        Def::ArrayDef(a) => check_field(&a.items),
        _ => Ok(()),
    }
}

fn check_body(schema: Option<&FieldSchema>) -> Result<(), LexiconError> {
    schema.map_or(Ok(()), check_field)
}

fn check_params(params: Option<&ParamsDef>) -> Result<(), LexiconError> {
    let Some(params) = params else {
        return Ok(());
    };
    check_required(&params.required, |name| {
        params.properties.contains_key(name)
    })?;
    params.properties.values().try_for_each(check_field)
}

fn check_object(obj: &ObjectDef) -> Result<(), LexiconError> {
    check_required(&obj.required, |name| obj.properties.contains_key(name))?;
    obj.properties.values().try_for_each(check_field)
}

fn check_required(
    required: &[String],
    declared: impl Fn(&str) -> bool,
) -> Result<(), LexiconError> {
    match required.iter().find(|name| !declared(name)) {
        Some(name) => Err(LexiconError::InvalidSchema(format!(
            "Required field \"{name}\" not defined"
        ))),
        None => Ok(()),
    }
}

fn check_field(field: &FieldSchema) -> Result<(), LexiconError> {
    match field {
        FieldSchema::Object(o) => check_object(o),
        FieldSchema::Array { items, .. } => check_field(items),
        FieldSchema::Ref { reference, .. } => check_ref(reference),
        FieldSchema::Union { refs, .. } => refs.iter().try_for_each(|r| check_ref(r)),
        _ => Ok(()),
    }
}

fn check_ref(reference: &str) -> Result<(), LexiconError> {
    if reference.matches('#').count() > 1 {
        return Err(LexiconError::InvalidSchema(format!(
            "ref {reference:?} can only have one hash segment"
        )));
    }
    Ok(())
}
