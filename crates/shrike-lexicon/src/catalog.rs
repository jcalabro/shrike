use std::collections::HashMap;

use crate::error::LexiconError;
use crate::schema::Schema;

/// A collection of parsed Lexicon schemas, keyed by NSID.
pub struct Catalog {
    schemas: HashMap<String, Schema>,
}

impl Catalog {
    /// Create a new, empty catalog.
    pub fn new() -> Self {
        Catalog {
            schemas: HashMap::new(),
        }
    }

    /// Parse a Lexicon JSON document and add it to the catalog.
    ///
    /// Returns an error if the JSON is invalid, the document has an unsupported
    /// lexicon version, or is missing required fields.
    pub fn add_schema(&mut self, json: &[u8]) -> Result<(), LexiconError> {
        let schema: Schema = serde_json::from_slice(json)?;
        if schema.lexicon != 1 {
            return Err(LexiconError::InvalidSchema(format!(
                "unsupported lexicon version {}",
                schema.lexicon
            )));
        }
        if schema.id.is_empty() {
            return Err(LexiconError::InvalidSchema("missing id".to_owned()));
        }
        self.schemas.insert(schema.id.clone(), schema);
        Ok(())
    }

    /// Look up a schema by its NSID.
    pub fn get(&self, nsid: &str) -> Option<&Schema> {
        self.schemas.get(nsid)
    }
}

impl Default for Catalog {
    fn default() -> Self {
        Self::new()
    }
}
