pub(crate) fn apply_user_agent(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header(reqwest::header::USER_AGENT, crate::USER_AGENT)
}

/// Default total-request timeout for outbound fetches.
#[cfg(any(feature = "identity", feature = "oauth"))]
const OUTBOUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default connection-establishment timeout for outbound fetches.
#[cfg(any(feature = "identity", feature = "oauth"))]
const OUTBOUND_CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// Whether outbound fetches whose target host is influenced by untrusted input
/// (did:web / handle resolution) may connect to local or private address
/// ranges.
///
/// The default ([`AddressPolicy::DenyLocal`]) refuses connections that resolve
/// to loopback, private (RFC1918), carrier-grade-NAT (RFC6598), link-local,
/// IPv6 unique-local (ULA), or unspecified addresses. This closes the
/// connect-time SSRF vector that survives the redirect hardening: a hostile
/// `did:web` host (or a handle whose DNS record points inward, including a
/// DNS-rebinding flip) can otherwise steer shrike at `169.254.169.254`,
/// `127.0.0.1`, or an RFC1918 service.
///
/// [`AddressPolicy::AllowLocal`] is the explicit opt-in for deployments that
/// legitimately resolve identities hosted on localhost or private
/// infrastructure (local dev, self-hosted PDS on a private network). It is a
/// deliberate, named choice — never the default.
#[cfg(any(feature = "identity", feature = "oauth"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AddressPolicy {
    /// Refuse connections to local/private address ranges (the secure default).
    #[default]
    DenyLocal,
    /// Permit connections to any address, including local/private ranges.
    AllowLocal,
}

/// Build a hardened `reqwest::Client` for fetches whose target host is
/// influenced by untrusted input (DID/handle resolution: did:web, the
/// `/.well-known/atproto-did` and `_atproto` handle lookups).
///
/// Hardening applied:
/// - **No redirects** (`Policy::none()`): a resolved host cannot 30x-redirect
///   shrike to an internal address (e.g. `169.254.169.254`, loopback,
///   RFC1918). This matches the OAuth metadata client and atproto's
///   `redirect: 'error'`.
/// - **Bounded timeouts**: a slow or hung server cannot stall a resolution
///   indefinitely.
/// - **Connect-time address filtering** when `policy` is
///   [`AddressPolicy::DenyLocal`]: a custom DNS resolver drops any resolved
///   address in a local/private range, so a hostname that resolves inward
///   (statically or via DNS rebinding) cannot be connected to. Literal-IP
///   hosts bypass the resolver in hyper, so callers that build URLs from
///   untrusted hosts must *also* reject local literal IPs up front (see
///   [`host_is_blocked_literal_ip`]).
///
/// This closes both the redirect-based and the resolve-based SSRF vectors. It
/// cannot defend against a malicious *recursive DNS server* colluding to return
/// a global address that routes to an internal host, nor against egress that is
/// not address-scoped — deployments resolving fully untrusted identities should
/// still restrict egress at the network layer. See the `identity` module docs.
#[cfg(any(feature = "identity", feature = "oauth"))]
pub(crate) fn hardened_client(policy: AddressPolicy) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(OUTBOUND_TIMEOUT)
        .connect_timeout(OUTBOUND_CONNECT_TIMEOUT);

    if policy == AddressPolicy::DenyLocal {
        builder = builder.dns_resolver(std::sync::Arc::new(LocalFilteringResolver));
    }

    builder
        .build()
        // build() only fails if the TLS backend can't initialize, which
        // Client::new() also requires; fall back to preserve the existing
        // failure mode without an unwrap/expect (denied workspace-wide). The
        // fallback drops the resolver, so callers that depend on filtering for
        // SSRF safety also rely on the literal-IP guard at the URL layer.
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Report whether `host` is a literal IP address in a blocked local/private
/// range under `policy`. Returns `false` for hostnames (which are filtered at
/// connect time by [`hardened_client`]'s resolver instead) and for any host
/// when `policy` is [`AddressPolicy::AllowLocal`].
///
/// hyper skips the custom DNS resolver entirely when the URL host is already an
/// IP literal, so a caller that interpolates an untrusted host into a URL (e.g.
/// `did:web:127.0.0.1` → `https://127.0.0.1/.well-known/did.json`) must call
/// this before fetching, or the resolver-based filter would be bypassed.
#[cfg(any(feature = "identity", feature = "oauth"))]
pub(crate) fn host_is_blocked_literal_ip(host: &str, policy: AddressPolicy) -> bool {
    if policy == AddressPolicy::AllowLocal {
        return false;
    }
    // Accept both bare IPv6 and the bracketed `[::1]` URL form.
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    match trimmed.parse::<std::net::IpAddr>() {
        Ok(ip) => is_local_addr(&ip),
        // Not a literal IP — a hostname; the connect-time resolver handles it.
        Err(_) => false,
    }
}

/// Whether an IP address falls in a range we refuse to connect to under
/// [`AddressPolicy::DenyLocal`]. Covers loopback, private (RFC1918),
/// carrier-grade-NAT (RFC6598 100.64.0.0/10), link-local, broadcast,
/// "this host" (0.0.0.0/8), IPv6 unique-local (fc00::/7), IPv6 link-local
/// (fe80::/10), the unspecified address, and IPv4-mapped IPv6 forms of any of
/// these.
///
/// `Ipv4Addr::is_global` / `is_shared` / `Ipv6Addr::is_unique_local` are still
/// unstable, so the ranges are composed from stable predicates plus explicit
/// bit checks for the few that lack one.
#[cfg(any(feature = "identity", feature = "oauth"))]
fn is_local_addr(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => is_local_v4(v4),
        IpAddr::V6(v6) => {
            // An IPv4-mapped address (::ffff:a.b.c.d) reaches the same host as
            // the bare IPv4 address, so apply the v4 rules to it.
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_local_v4(&mapped);
            }
            let seg = v6.segments();
            v6.is_loopback()
                || v6.is_unspecified()
                // Unique-local fc00::/7.
                || (seg[0] & 0xfe00) == 0xfc00
                // Link-local unicast fe80::/10.
                || (seg[0] & 0xffc0) == 0xfe80
        }
    }
}

#[cfg(any(feature = "identity", feature = "oauth"))]
fn is_local_v4(v4: &std::net::Ipv4Addr) -> bool {
    let [a, b, ..] = v4.octets();
    v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_documentation()
        // "This host on this network" 0.0.0.0/8 (only 0.0.0.0 is_unspecified).
        || a == 0
        // Carrier-grade NAT 100.64.0.0/10 (RFC6598).
        || (a == 100 && (64..=127).contains(&b))
}

/// A [`reqwest::dns::Resolve`] implementation that resolves names with the
/// system resolver and then drops any address in a local/private range, so a
/// hostname pointing inward cannot be connected to. Used only under
/// [`AddressPolicy::DenyLocal`].
#[cfg(any(feature = "identity", feature = "oauth"))]
#[derive(Debug)]
struct LocalFilteringResolver;

#[cfg(any(feature = "identity", feature = "oauth"))]
impl reqwest::dns::Resolve for LocalFilteringResolver {
    fn resolve(&self, name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let host = name.as_str().to_owned();
        Box::pin(async move {
            // Port 0 is a placeholder; reqwest overrides it with the URL's port.
            let resolved = tokio::net::lookup_host((host.as_str(), 0)).await?;
            let allowed: Vec<std::net::SocketAddr> =
                resolved.filter(|addr| !is_local_addr(&addr.ip())).collect();

            if allowed.is_empty() {
                // Either the name did not resolve, or every address it
                // resolved to was local/private and was filtered out. Fail the
                // connection rather than silently falling back.
                return Err(Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    format!(
                        "refusing to connect to {host:?}: resolved only to \
                         local/private addresses (set AddressPolicy::AllowLocal \
                         to permit)"
                    ),
                ))
                    as Box<dyn std::error::Error + Send + Sync>);
            }

            Ok(Box::new(allowed.into_iter()) as reqwest::dns::Addrs)
        })
    }
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

    #[cfg(any(feature = "identity", feature = "oauth"))]
    mod address_policy {
        use super::super::*;
        use std::net::IpAddr;

        fn ip(s: &str) -> IpAddr {
            s.parse().unwrap()
        }

        #[test]
        fn v4_local_ranges_are_blocked() {
            for s in [
                "127.0.0.1",       // loopback
                "10.0.0.1",        // RFC1918
                "172.16.5.4",      // RFC1918
                "172.31.255.255",  // RFC1918 upper bound
                "192.168.1.1",     // RFC1918
                "169.254.169.254", // link-local (cloud metadata)
                "0.0.0.0",         // unspecified / this-host
                "0.1.2.3",         // 0.0.0.0/8
                "255.255.255.255", // broadcast
                "100.64.0.1",      // CGNAT lower bound
                "100.127.255.255", // CGNAT upper bound
            ] {
                assert!(is_local_addr(&ip(s)), "{s} must be treated as local");
            }
        }

        #[test]
        fn v4_global_addresses_are_allowed() {
            for s in [
                "8.8.8.8",
                "1.1.1.1",
                "93.184.216.34",  // example.com
                "172.15.0.1",     // just below RFC1918 172.16/12
                "172.32.0.1",     // just above RFC1918 172.16/12
                "100.63.255.255", // just below CGNAT
                "100.128.0.0",    // just above CGNAT
                "11.0.0.1",       // just above 10/8
            ] {
                assert!(!is_local_addr(&ip(s)), "{s} must be treated as global");
            }
        }

        #[test]
        fn v6_local_ranges_are_blocked() {
            for s in [
                "::1",                    // loopback
                "::",                     // unspecified
                "fc00::1",                // ULA lower
                "fdff:ffff::1",           // ULA upper
                "fe80::1",                // link-local
                "febf:ffff::1",           // link-local upper
                "::ffff:127.0.0.1",       // v4-mapped loopback
                "::ffff:10.0.0.1",        // v4-mapped RFC1918
                "::ffff:169.254.169.254", // v4-mapped link-local
            ] {
                assert!(is_local_addr(&ip(s)), "{s} must be treated as local");
            }
        }

        #[test]
        fn v6_global_addresses_are_allowed() {
            for s in [
                "2001:4860:4860::8888", // Google DNS
                "2606:2800:220:1::1",   // example.com
                "::ffff:8.8.8.8",       // v4-mapped global
            ] {
                assert!(!is_local_addr(&ip(s)), "{s} must be treated as global");
            }
        }

        #[test]
        fn literal_ip_guard_blocks_local_only_under_deny() {
            // DenyLocal: local literals are blocked, global literals and
            // hostnames are not.
            assert!(host_is_blocked_literal_ip(
                "127.0.0.1",
                AddressPolicy::DenyLocal
            ));
            assert!(host_is_blocked_literal_ip(
                "169.254.169.254",
                AddressPolicy::DenyLocal
            ));
            assert!(host_is_blocked_literal_ip(
                "[::1]",
                AddressPolicy::DenyLocal
            ));
            assert!(host_is_blocked_literal_ip("::1", AddressPolicy::DenyLocal));
            assert!(!host_is_blocked_literal_ip(
                "8.8.8.8",
                AddressPolicy::DenyLocal
            ));
            // Hostnames are not literal IPs — handled by the resolver instead.
            assert!(!host_is_blocked_literal_ip(
                "example.com",
                AddressPolicy::DenyLocal
            ));
        }

        #[test]
        fn literal_ip_guard_is_noop_under_allow_local() {
            assert!(!host_is_blocked_literal_ip(
                "127.0.0.1",
                AddressPolicy::AllowLocal
            ));
            assert!(!host_is_blocked_literal_ip(
                "[::1]",
                AddressPolicy::AllowLocal
            ));
        }

        #[tokio::test]
        async fn deny_local_client_refuses_loopback_literal_via_resolver_fallback() {
            // A hostname that resolves to loopback must be refused. We use
            // "localhost" which resolves to 127.0.0.1/::1 on every platform.
            use reqwest::dns::Resolve;
            let resolver = LocalFilteringResolver;
            let name: reqwest::dns::Name = "localhost".parse().unwrap();
            let result = resolver.resolve(name).await;
            assert!(
                result.is_err(),
                "localhost resolves only to loopback and must be refused"
            );
        }
    }
}
