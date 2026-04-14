use crate::syntax::Did;

/// Context available to every XRPC handler.
pub struct RequestContext {
    /// Authenticated DID from the bearer token, if present.
    pub auth: Option<Did>,
    /// Raw HTTP headers from the request.
    pub headers: http::HeaderMap,
}
