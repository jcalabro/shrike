#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn apply_user_agent(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb.header(reqwest::header::USER_AGENT, crate::USER_AGENT)
}

// Browsers reject attempts to set User-Agent. The Fetch implementation still
// supplies the browser's own user agent.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn apply_user_agent(rb: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    rb
}

/// Encode XRPC query parameters: arrays become repeated keys, `null` and
/// `None` are omitted, and booleans and numbers use their JSON spelling.
/// `serde_urlencoded` (used by `RequestBuilder::query`) rejects sequences, so
/// array parameters such as `app.bsky.feed.getPosts`'s `uris` need this.
#[cfg(any(feature = "xrpc", feature = "oauth"))]
pub(crate) fn query_pairs<P: serde::Serialize + ?Sized>(
    params: &P,
) -> Result<Vec<(String, String)>, serde_json::Error> {
    use serde::ser::Error as _;
    use serde_json::Value;

    fn scalar(key: &str, value: Value) -> Result<Option<String>, serde_json::Error> {
        match value {
            Value::Null => Ok(None),
            Value::Bool(b) => Ok(Some(b.to_string())),
            Value::Number(n) => Ok(Some(n.to_string())),
            Value::String(s) => Ok(Some(s)),
            Value::Array(_) | Value::Object(_) => Err(serde_json::Error::custom(format!(
                "query parameter {key:?} must be a scalar or an array of scalars"
            ))),
        }
    }

    let map = match serde_json::to_value(params)? {
        Value::Object(map) => map,
        Value::Null => return Ok(Vec::new()),
        _ => {
            return Err(serde_json::Error::custom(
                "query parameters must serialize to a map",
            ));
        }
    };
    let mut pairs = Vec::new();
    for (key, value) in map {
        match value {
            Value::Array(items) => {
                for item in items {
                    if let Some(v) = scalar(&key, item)? {
                        pairs.push((key.clone(), v));
                    }
                }
            }
            other => {
                if let Some(v) = scalar(&key, other)? {
                    pairs.push((key, v));
                }
            }
        }
    }
    Ok(pairs)
}

/// Default total-request timeout for outbound fetches.
#[cfg(all(
    any(feature = "identity", feature = "oauth"),
    not(all(target_family = "wasm", target_os = "unknown"))
))]
const OUTBOUND_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Default connection-establishment timeout for outbound fetches.
#[cfg(all(
    any(feature = "identity", feature = "oauth"),
    not(all(target_family = "wasm", target_os = "unknown"))
))]
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
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn hardened_client(policy: AddressPolicy) -> reqwest::Client {
    hardened_client_with_timeout(policy, OUTBOUND_TIMEOUT)
}

/// [`hardened_client`] with a caller-chosen total-request timeout. The connect
/// timeout is the smaller of `timeout` and the default.
#[cfg(any(feature = "identity", feature = "oauth"))]
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn hardened_client_with_timeout(
    policy: AddressPolicy,
    timeout: std::time::Duration,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(timeout)
        .connect_timeout(timeout.min(OUTBOUND_CONNECT_TIMEOUT));

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

/// Build the browser Fetch-backed client. Browser networking is constrained by
/// CORS and Private Network Access rather than native DNS/socket policy; Fetch
/// does not expose reqwest's resolver, connect timeout, or redirect policy.
#[cfg(all(
    any(feature = "identity", feature = "oauth"),
    target_family = "wasm",
    target_os = "unknown"
))]
pub(crate) fn hardened_client(_policy: AddressPolicy) -> reqwest::Client {
    reqwest::Client::new()
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
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[derive(Debug)]
struct LocalFilteringResolver;

#[cfg(any(feature = "identity", feature = "oauth"))]
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
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

/// Read a response body of at most `limit` bytes. Returns `Ok(None)` if it is
/// larger, having buffered no more than `limit` bytes of it.
///
/// `Content-Length` only short-circuits an honest oversized response; the cap
/// is enforced on the bytes as they arrive, so a chunked or lying server
/// cannot exhaust memory. This holds in browsers too, where the body streams
/// from the `fetch` response.
#[cfg(feature = "identity")]
pub(crate) async fn read_capped(
    resp: reqwest::Response,
    limit: usize,
) -> Result<Option<Vec<u8>>, reqwest::Error> {
    use futures::StreamExt;

    if resp.content_length().is_some_and(|len| len > limit as u64) {
        return Ok(None);
    }
    let mut stream = std::pin::pin!(resp.bytes_stream());
    let mut body = Vec::new();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if body.len() + chunk.len() > limit {
            return Ok(None);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Some(body))
}

/// A one-shot HTTP server for testing body caps.
#[cfg(all(
    test,
    feature = "identity",
    not(all(target_family = "wasm", target_os = "unknown"))
))]
#[allow(clippy::unwrap_used)]
pub(crate) mod test_server {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// How the served body is framed.
    #[derive(Clone, Copy)]
    pub(crate) enum Body {
        /// `Content-Length: <declared>`, followed by `len` bytes.
        Length { declared: usize, len: usize },
        /// Chunked encoding, `len` bytes in total.
        Chunked { len: usize },
        /// Chunked encoding that never ends.
        Endless,
    }

    /// Serve one `200 OK` response with a body of `x` bytes, then return the
    /// URL to GET. Writing stops early if the client hangs up.
    pub(crate) async fn serve(body: Body) -> String {
        const CHUNK: usize = 16 * 1024;
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let (head, len, chunked) = match body {
                Body::Length { declared, len } => {
                    (format!("Content-Length: {declared}"), Some(len), false)
                }
                Body::Chunked { len } => ("Transfer-Encoding: chunked".into(), Some(len), true),
                Body::Endless => ("Transfer-Encoding: chunked".into(), None, true),
            };
            let head = format!("HTTP/1.1 200 OK\r\n{head}\r\nConnection: close\r\n\r\n");
            if sock.write_all(head.as_bytes()).await.is_err() {
                return;
            }
            let mut left = len;
            while left != Some(0) {
                let n = left.map_or(CHUNK, |l| l.min(CHUNK));
                let mut frame = Vec::with_capacity(n + 16);
                if chunked {
                    frame.extend_from_slice(format!("{n:x}\r\n").as_bytes());
                }
                frame.resize(frame.len() + n, b'x');
                if chunked {
                    frame.extend_from_slice(b"\r\n");
                }
                if sock.write_all(&frame).await.is_err() {
                    return;
                }
                left = left.map(|l| l - n);
            }
            if chunked {
                let _ = sock.write_all(b"0\r\n\r\n").await;
            }
            let _ = sock.shutdown().await;
        });
        format!("http://{addr}/")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
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

    #[cfg(all(
        feature = "identity",
        not(all(target_family = "wasm", target_os = "unknown"))
    ))]
    #[allow(clippy::expect_used)]
    mod read_capped {
        use super::super::test_server::{Body, serve};
        use super::super::*;

        const LIMIT: usize = 64 * 1024;

        async fn read(body: Body) -> Option<Vec<u8>> {
            let resp = reqwest::get(serve(body).await).await.unwrap();
            tokio::time::timeout(std::time::Duration::from_secs(10), read_capped(resp, LIMIT))
                .await
                .expect("read_capped must stop at the cap, not drain the body")
                .unwrap()
        }

        #[tokio::test]
        async fn accepts_bodies_up_to_the_limit() {
            for len in [0, 1, LIMIT - 1, LIMIT] {
                let body = read(Body::Chunked { len }).await.unwrap();
                assert_eq!(body, vec![b'x'; len]);
                let body = read(Body::Length { declared: len, len }).await.unwrap();
                assert_eq!(body, vec![b'x'; len]);
            }
        }

        #[tokio::test]
        async fn rejects_chunked_bodies_over_the_limit() {
            assert_eq!(read(Body::Chunked { len: LIMIT + 1 }).await, None);
            assert_eq!(read(Body::Chunked { len: 4 * LIMIT }).await, None);
        }

        #[tokio::test]
        async fn rejects_endless_chunked_body() {
            // Regression: buffering the whole body before checking its size
            // never returns here.
            assert_eq!(read(Body::Endless).await, None);
        }

        #[tokio::test]
        async fn rejects_oversized_content_length_without_reading() {
            let body = Body::Length {
                declared: LIMIT + 1,
                len: 0,
            };
            assert_eq!(read(body).await, None);
        }
    }

    #[cfg(any(feature = "xrpc", feature = "oauth"))]
    #[test]
    fn query_pairs_repeat_arrays_and_skip_nulls() {
        #[derive(serde::Serialize)]
        #[serde(rename_all = "camelCase")]
        struct P {
            uris: Vec<String>,
            limit: Option<i64>,
            cursor: Option<String>,
            include_pins: bool,
            empty: Vec<String>,
        }
        let pairs = query_pairs(&P {
            uris: vec!["at://a".into(), "at://b".into()],
            limit: Some(-5),
            cursor: None,
            include_pins: true,
            empty: vec![],
        })
        .unwrap();
        let pairs: Vec<(&str, &str)> = pairs
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        assert_eq!(
            pairs,
            [
                ("includePins", "true"),
                ("limit", "-5"),
                ("uris", "at://a"),
                ("uris", "at://b"),
            ]
        );
    }

    #[cfg(any(feature = "xrpc", feature = "oauth"))]
    #[test]
    fn query_pairs_reject_nested_values() {
        assert!(query_pairs(&serde_json::json!({"a": {"b": 1}})).is_err());
        assert!(query_pairs(&serde_json::json!({"a": [[1]]})).is_err());
        assert!(query_pairs(&serde_json::json!([1, 2])).is_err());
        assert!(query_pairs(&()).unwrap().is_empty());
        assert!(
            query_pairs(&serde_json::json!({"a": [null, 1]})).unwrap()
                == [("a".to_owned(), "1".to_owned())]
        );
    }
}
