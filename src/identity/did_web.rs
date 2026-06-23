use crate::syntax::Did;

use crate::identity::DidDocument;
use crate::identity::IdentityError;

/// Resolve a `did:web` DID to its DID document.
///
/// Only hostname-level `did:web` is supported, per the AT Protocol spec:
/// `did:web:example.com` → `https://example.com/.well-known/did.json`.
/// Path-based did:web (`did:web:example.com:path:to`) and embedded ports
/// (`did:web:example.com%3A3000`) are **rejected**, matching atproto/atmos.
pub async fn resolve_did_web(
    did: &Did,
    http: &reqwest::Client,
) -> Result<DidDocument, IdentityError> {
    let identifier = did.identifier();

    // The AT Protocol only supports hostname did:web. A ':' in the
    // method-specific id encodes additional path segments (or a port, via
    // percent-encoding the colon), which we do not support — reject rather than
    // silently turning a port into a path segment.
    if identifier.contains(':') {
        return Err(IdentityError::NotFound(format!(
            "path-based or ported did:web is not supported: {did}"
        )));
    }

    let url = format!("https://{identifier}/.well-known/did.json");
    let resp = crate::outbound::apply_user_agent(http.get(&url))
        .send()
        .await
        .map_err(|e| IdentityError::Network(e.to_string()))?;
    if !resp.status().is_success() {
        return Err(IdentityError::NotFound(did.to_string()));
    }
    crate::identity::fetch_did_document(resp, did).await
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn rejects_path_based_did_web() {
        // Path-based did:web must be rejected before any network call.
        let did = Did::try_from("did:web:example.com:user:alice").unwrap();
        let http = reqwest::Client::new();
        let err = resolve_did_web(&did, &http).await.unwrap_err();
        assert!(
            matches!(err, IdentityError::NotFound(_)),
            "path-based did:web must be rejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn rejects_ported_did_web() {
        // did:web:example.com:3000 (a port reinterpreted as a path) must reject.
        let did = Did::try_from("did:web:example.com:3000").unwrap();
        let http = reqwest::Client::new();
        let err = resolve_did_web(&did, &http).await.unwrap_err();
        assert!(matches!(err, IdentityError::NotFound(_)));
    }
}
