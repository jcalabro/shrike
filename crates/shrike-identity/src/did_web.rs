use shrike_syntax::Did;

use crate::IdentityError;
use crate::identity::DidDocument;

/// Resolve a `did:web` DID to its DID document.
///
/// - `did:web:example.com` → `https://example.com/.well-known/did.json`
/// - `did:web:example.com:path:to` → `https://example.com/path/to/did.json`
pub async fn resolve_did_web(
    did: &Did,
    http: &reqwest::Client,
) -> Result<DidDocument, IdentityError> {
    let identifier = did.identifier();
    let parts: Vec<&str> = identifier.split(':').collect();
    let url = if parts.len() == 1 {
        format!("https://{}/.well-known/did.json", parts[0])
    } else {
        format!("https://{}/{}/did.json", parts[0], parts[1..].join("/"))
    };
    let resp = http
        .get(&url)
        .send()
        .await
        .map_err(|e| IdentityError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(IdentityError::NotFound(did.to_string()));
    }
    resp.json()
        .await
        .map_err(|e| IdentityError::InvalidDocument(e.to_string()))
}
