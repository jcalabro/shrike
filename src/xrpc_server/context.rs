use crate::syntax::Did;

/// Context available to every XRPC handler.
pub struct RequestContext {
    /// Authenticated DID, if the application has performed authentication.
    ///
    /// This framework does not itself verify bearer tokens or service auth; it
    /// is always `None` as populated by the built-in handlers. Authenticate in
    /// your handler (the raw `headers` are available here) — a future revision
    /// may add an auth-verifier hook that populates this field.
    pub auth: Option<Did>,
    /// Raw HTTP headers from the request.
    pub headers: http::HeaderMap,
}
