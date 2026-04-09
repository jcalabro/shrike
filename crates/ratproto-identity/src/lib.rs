pub mod did_web;
pub mod directory;
pub mod identity;
pub mod plc;

pub use directory::Directory;
pub use identity::{DidDocument, Identity, Service, ServiceEndpoint, VerificationMethod};
pub use plc::PlcClient;

/// Errors that can occur during identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("invalid DID document: {0}")]
    InvalidDocument(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("handle verification failed: {0}")]
    HandleMismatch(String),
    #[error("syntax error: {0}")]
    Syntax(#[from] ratproto_syntax::SyntaxError),
}
