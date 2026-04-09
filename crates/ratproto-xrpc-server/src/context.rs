use ratproto_syntax::Did;

/// Context available to every XRPC handler
pub struct RequestContext {
    /// Authenticated DID from bearer token, if present
    pub auth: Option<Did>,
    /// Raw HTTP headers
    pub headers: http::HeaderMap,
}
