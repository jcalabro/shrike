pub(crate) fn apply_user_agent(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header(reqwest::header::USER_AGENT, crate::USER_AGENT)
}

/// Default total-request timeout for outbound fetches.
#[cfg(any(feature = "identity", feature = "oauth"))]
const OUTBOUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default connection-establishment timeout for outbound fetches.
#[cfg(any(feature = "identity", feature = "oauth"))]
const OUTBOUND_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Build a hardened `reqwest::Client` for fetches whose target host is
/// influenced by untrusted input (DID/handle resolution: did:web, PLC, the
/// `/.well-known/atproto-did` and `_atproto` handle lookups).
///
/// Hardening applied:
/// - **No redirects** (`Policy::none()`): a resolved host cannot 30x-redirect
///   shrike to an internal address (e.g. `169.254.169.254`, loopback,
///   RFC1918). This matches the OAuth metadata client and atproto's
///   `redirect: 'error'`.
/// - **Bounded timeouts**: a slow or hung server cannot stall a resolution
///   indefinitely.
///
/// This closes the redirect-based SSRF vector. It does **not** filter the
/// *initial* resolved IP — a did:web/handle host that directly resolves to an
/// internal address is still reachable, as is DNS rebinding. Deployments that
/// resolve untrusted identities should additionally restrict egress at the
/// network layer (or enable IP-range filtering once shrike offers it). See the
/// `identity` module docs.
#[cfg(any(feature = "identity", feature = "oauth"))]
pub(crate) fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(OUTBOUND_TIMEOUT)
        .connect_timeout(OUTBOUND_CONNECT_TIMEOUT)
        .build()
        // build() only fails if the TLS backend can't initialize, which
        // Client::new() also requires; fall back to preserve the existing
        // failure mode without an unwrap/expect (denied workspace-wide).
        .unwrap_or_else(|_| reqwest::Client::new())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn apply_user_agent_sets_shrike_user_agent() {
        let request = apply_user_agent(reqwest::Client::new().get("https://example.com"))
            .build()
            .unwrap();
        assert_eq!(
            request
                .headers()
                .get(reqwest::header::USER_AGENT)
                .and_then(|value| value.to_str().ok()),
            Some(crate::USER_AGENT)
        );
    }
}
