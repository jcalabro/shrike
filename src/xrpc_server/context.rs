use http::{HeaderMap, Method, Uri};

use crate::xrpc_server::params::Params;
use crate::xrpc_server::rate_limit::RouteLimiter;

/// Context available to every XRPC handler.
///
/// `A` is the credential type produced by the route's
/// [`AuthVerifier`](crate::xrpc_server::AuthVerifier); `()` for
/// unauthenticated routes.
pub struct RequestContext<A = ()> {
    /// The authenticated credentials.
    pub auth: A,
    /// The method NSID.
    pub nsid: String,
    /// The query parameters (validated, with defaults, when the server has a
    /// lexicon for the method).
    pub params: Params,
    /// Raw HTTP headers from the request.
    pub headers: HeaderMap,
    pub(crate) limiter: Option<RouteLimiter>,
}

impl<A> RequestContext<A> {
    /// Reset this request's rate-limit counters on every limiter that applies
    /// to the route (route, shared and global), as the reference
    /// `resetRouteRateLimits` does. For example, clear a failed-login counter
    /// after a successful login.
    pub async fn reset_route_rate_limits(&self) {
        if let Some(limiter) = &self.limiter {
            limiter.reset().await;
        }
    }
}

/// What an [`AuthVerifier`](crate::xrpc_server::AuthVerifier) sees: the
/// request line, headers and validated parameters, before the body is read.
#[derive(Debug, Clone)]
pub struct AuthContext {
    /// The method NSID.
    pub nsid: String,
    /// The HTTP method.
    pub method: Method,
    /// The request URI.
    pub uri: Uri,
    /// The request headers.
    pub headers: HeaderMap,
    /// The query parameters.
    pub params: Params,
}

impl AuthContext {
    /// The bearer token from `Authorization: Bearer <token>`, if any.
    pub fn bearer_token(&self) -> Option<&str> {
        bearer_token(&self.headers)
    }
}

pub(crate) fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    let value = headers.get(http::header::AUTHORIZATION)?.to_str().ok()?;
    let token = value.strip_prefix("Bearer ")?.trim();
    (!token.is_empty()).then_some(token)
}
