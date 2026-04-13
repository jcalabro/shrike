use std::fmt;

/// Errors that can occur when parsing or managing Lexicon schemas.
#[derive(Debug, thiserror::Error)]
pub enum LexiconError {
    #[error("invalid schema: {0}")]
    InvalidSchema(String),

    #[error("JSON parse error: {0}")]
    Json(#[from] serde_json::Error),
}

/// Top-level validation error.
#[derive(Debug)]
pub enum ValidationError {
    /// A field-level error with a path into the document.
    Field {
        path: String,
        kind: ValidationErrorKind,
    },

    /// The collection NSID was not found in the catalog.
    UnknownCollection(String),

    /// A schema-level inconsistency prevented validation.
    Schema(String),

    /// Multiple validation errors were found.
    Multiple(Vec<ValidationError>),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Field { path, kind } => write!(f, "at {path}: {kind}"),
            ValidationError::UnknownCollection(nsid) => write!(f, "unknown collection: {nsid}"),
            ValidationError::Schema(msg) => write!(f, "schema error: {msg}"),
            ValidationError::Multiple(errs) => {
                for (i, e) in errs.iter().enumerate() {
                    if i > 0 {
                        writeln!(f)?;
                    }
                    write!(f, "{e}")?;
                }
                Ok(())
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// The specific kind of a field validation failure.
#[derive(Debug, thiserror::Error)]
pub enum ValidationErrorKind {
    #[error("required field missing")]
    Required,

    #[error("expected {expected}, got {got}")]
    TypeMismatch { expected: String, got: String },

    #[error("string too short: min {min}, got {got}")]
    TooShort { min: u64, got: u64 },

    #[error("string too long: max {max}, got {got}")]
    TooLong { max: u64, got: u64 },

    #[error("integer out of range")]
    OutOfRange,

    #[error("value not in enum: {got}")]
    InvalidEnum { got: String },

    #[error("{0}")]
    Other(String),
}
