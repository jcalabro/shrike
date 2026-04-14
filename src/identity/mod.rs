//! DID and handle resolution for AT Protocol identities.
//!
//! The Directory type resolves DIDs and handles to DID documents. Supports
//! both did:plc (via PlcClient) and did:web. DID documents contain public
//! keys and service endpoints used for authentication and communication.
//!
//! Use Directory::resolve_did to fetch a DID document or
//! Directory::resolve_handle to look up a DID from a handle.

pub mod did_web;
pub mod directory;
#[allow(clippy::module_inception)]
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
    Syntax(#[from] crate::syntax::SyntaxError),
}
