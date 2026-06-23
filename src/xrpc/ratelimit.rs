//! Proactive rate-limit tracking from AT Protocol `RateLimit-*` response
//! headers.
//!
//! AT Protocol servers advertise their rate-limit state on every response (not
//! just 429s) via the IETF draft headers `ratelimit-limit`,
//! `ratelimit-remaining`, `ratelimit-reset`, and the proprietary
//! `ratelimit-policy`. Capturing the most recent snapshot lets a caller pace
//! itself *before* hitting a 429, matching the reference clients
//! (indigo `errorFromHTTPResponse`, the TS `xrpc` package).

/// A snapshot of the rate-limit state advertised by the server on a response.
///
/// Mirrors the `RateLimit-*` headers. All fields are best-effort: a server may
/// omit any of them, in which case the corresponding field is `None`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RateLimit {
    /// `ratelimit-limit`: the request ceiling for the current window.
    pub limit: Option<i64>,
    /// `ratelimit-remaining`: requests left in the current window.
    pub remaining: Option<i64>,
    /// `ratelimit-reset`: Unix timestamp (seconds) when the window resets.
    pub reset: Option<i64>,
    /// `ratelimit-policy`: the server's opaque policy descriptor.
    pub policy: Option<String>,
}

impl RateLimit {
    /// Parse a [`RateLimit`] from response headers, or `None` if the server
    /// advertised no `ratelimit-limit` header (the presence sentinel the
    /// reference uses to decide whether rate-limit info is available).
    pub fn from_headers(headers: &reqwest::header::HeaderMap) -> Option<Self> {
        // Gate on `ratelimit-limit` like the reference: without it there is no
        // meaningful rate-limit snapshot to report.
        if !headers.contains_key("ratelimit-limit") {
            return None;
        }
        Some(RateLimit {
            limit: parse_int(headers, "ratelimit-limit"),
            remaining: parse_int(headers, "ratelimit-remaining"),
            reset: parse_int(headers, "ratelimit-reset"),
            policy: headers
                .get("ratelimit-policy")
                .and_then(|v| v.to_str().ok())
                .map(str::to_owned),
        })
    }

    /// Whether the server has reported zero remaining requests in the current
    /// window (so the next request is likely to be throttled).
    pub fn is_exhausted(&self) -> bool {
        self.remaining == Some(0)
    }
}

fn parse_int(headers: &reqwest::header::HeaderMap, name: &str) -> Option<i64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<i64>().ok())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use reqwest::header::{HeaderMap, HeaderName, HeaderValue};

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.insert(
                HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn parses_full_header_set() {
        let h = headers(&[
            ("ratelimit-limit", "3000"),
            ("ratelimit-remaining", "2999"),
            ("ratelimit-reset", "1700000000"),
            ("ratelimit-policy", "3000;w=300"),
        ]);
        let rl = RateLimit::from_headers(&h).unwrap();
        assert_eq!(rl.limit, Some(3000));
        assert_eq!(rl.remaining, Some(2999));
        assert_eq!(rl.reset, Some(1_700_000_000));
        assert_eq!(rl.policy.as_deref(), Some("3000;w=300"));
        assert!(!rl.is_exhausted());
    }

    #[test]
    fn none_without_limit_header() {
        // Without ratelimit-limit there is no snapshot, even if other headers
        // are present.
        let h = headers(&[("ratelimit-remaining", "5")]);
        assert_eq!(RateLimit::from_headers(&h), None);
    }

    #[test]
    fn partial_headers_leave_missing_fields_none() {
        let h = headers(&[("ratelimit-limit", "100")]);
        let rl = RateLimit::from_headers(&h).unwrap();
        assert_eq!(rl.limit, Some(100));
        assert_eq!(rl.remaining, None);
        assert_eq!(rl.reset, None);
        assert_eq!(rl.policy, None);
    }

    #[test]
    fn exhausted_when_remaining_zero() {
        let h = headers(&[("ratelimit-limit", "100"), ("ratelimit-remaining", "0")]);
        let rl = RateLimit::from_headers(&h).unwrap();
        assert!(rl.is_exhausted());
    }

    #[test]
    fn ignores_unparseable_values() {
        let h = headers(&[
            ("ratelimit-limit", "100"),
            ("ratelimit-remaining", "not-a-number"),
        ]);
        let rl = RateLimit::from_headers(&h).unwrap();
        assert_eq!(rl.limit, Some(100));
        assert_eq!(rl.remaining, None);
    }
}
