use crate::syntax::Did;

use crate::identity::DidDocument;
use crate::identity::IdentityError;
use crate::outbound::AddressPolicy;

/// Resolve a `did:web` DID to its DID document.
///
/// Only hostname-level `did:web` is supported, per the AT Protocol spec:
/// `did:web:example.com` → `https://example.com/.well-known/did.json`.
/// Path-based did:web (`did:web:example.com:path:to`) and embedded ports
/// (`did:web:example.com%3A3000`) are **rejected**, matching atproto/atmos.
///
/// Under [`AddressPolicy::DenyLocal`] a `did:web` whose host is a local/private
/// IP literal (e.g. `did:web:127.0.0.1`) is rejected before any fetch — hyper
/// skips the connect-time DNS filter for literal-IP hosts, so this guard is
/// what closes that bypass. Hostname hosts that resolve inward are caught by
/// the client's filtering resolver instead.
pub async fn resolve_did_web(
    did: &Did,
    http: &reqwest::Client,
    policy: AddressPolicy,
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

    if crate::outbound::host_is_blocked_literal_ip(identifier, policy) {
        return Err(IdentityError::NotFound(format!(
            "refusing to resolve did:web at local/private address {identifier} \
             (use AddressPolicy::AllowLocal to permit): {did}"
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
        let err = resolve_did_web(&did, &http, AddressPolicy::DenyLocal)
            .await
            .unwrap_err();
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
        let err = resolve_did_web(&did, &http, AddressPolicy::DenyLocal)
            .await
            .unwrap_err();
        assert!(matches!(err, IdentityError::NotFound(_)));
    }

    #[tokio::test]
    async fn rejects_local_ip_literal_did_web_under_deny() {
        // H11 follow-up: did:web at a loopback/metadata IP literal must be
        // refused before any fetch (the resolver filter is bypassed for
        // literal IPs).
        for s in [
            "did:web:127.0.0.1",
            "did:web:169.254.169.254",
            "did:web:10.0.0.1",
        ] {
            let did = Did::try_from(s).unwrap();
            let http = reqwest::Client::new();
            let err = resolve_did_web(&did, &http, AddressPolicy::DenyLocal)
                .await
                .unwrap_err();
            assert!(
                matches!(err, IdentityError::NotFound(_)),
                "{s} must be refused under DenyLocal, got {err:?}"
            );
        }
    }

    #[tokio::test]
    async fn allow_local_permits_local_ip_literal_past_guard() {
        // Under AllowLocal the literal-IP guard is a no-op; the call proceeds to
        // the network and fails for an ordinary connection reason (nothing
        // listening), NOT the pre-flight refusal. We assert it is not the guard
        // by checking the error message does not mention the refusal text.
        let did = Did::try_from("did:web:127.0.0.1").unwrap();
        let http = crate::outbound::hardened_client(AddressPolicy::AllowLocal);
        let err = resolve_did_web(&did, &http, AddressPolicy::AllowLocal)
            .await
            .unwrap_err();
        let msg = format!("{err:?}");
        assert!(
            !msg.contains("refusing to resolve"),
            "AllowLocal must not pre-reject the literal IP, got {msg}"
        );
    }
}
