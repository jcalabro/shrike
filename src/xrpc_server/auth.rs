//! Per-route authentication hooks.

use std::future::Future;

use crate::service_auth::{BoxFuture, ServiceJwtClaims, ServiceJwtVerifier, SigningKeyResolver};
use crate::xrpc_server::context::AuthContext;
use crate::xrpc_server::error::ServerError;

/// Authenticates a request before its body is read.
///
/// Runs after parameter validation and before input parsing, so a request
/// with bad credentials is rejected without reading its body. The returned
/// credentials become [`RequestContext::auth`](crate::xrpc_server::RequestContext).
/// Return [`ServerError::auth_required`] (401) or
/// [`ServerError::forbidden`] (403) to reject.
///
/// Implemented for closures `Fn(AuthContext) -> impl Future<Output =
/// Result<C, ServerError>>`.
pub trait AuthVerifier: Send + Sync + 'static {
    /// What a successful verification produces.
    type Credentials: Send + 'static;

    /// Verify the request.
    fn verify<'a>(
        &'a self,
        ctx: &'a AuthContext,
    ) -> BoxFuture<'a, Result<Self::Credentials, ServerError>>;
}

impl<F, Fut, C> AuthVerifier for F
where
    F: Fn(AuthContext) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<C, ServerError>> + Send + 'static,
    C: Send + 'static,
{
    type Credentials = C;

    fn verify<'a>(&'a self, ctx: &'a AuthContext) -> BoxFuture<'a, Result<C, ServerError>> {
        Box::pin(self(ctx.clone()))
    }
}

/// No authentication; credentials are `()`.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoAuth;

impl AuthVerifier for NoAuth {
    type Credentials = ();

    fn verify<'a>(&'a self, _ctx: &'a AuthContext) -> BoxFuture<'a, Result<(), ServerError>> {
        Box::pin(async { Ok(()) })
    }
}

/// Makes a verifier optional: a request without an `Authorization` header
/// gets `None`; one with a header must pass the inner verifier.
#[derive(Debug, Clone, Copy, Default)]
pub struct Optional<V>(pub V);

impl<V: AuthVerifier> AuthVerifier for Optional<V> {
    type Credentials = Option<V::Credentials>;

    fn verify<'a>(
        &'a self,
        ctx: &'a AuthContext,
    ) -> BoxFuture<'a, Result<Self::Credentials, ServerError>> {
        Box::pin(async move {
            if ctx.headers.contains_key(http::header::AUTHORIZATION) {
                self.0.verify(ctx).await.map(Some)
            } else {
                Ok(None)
            }
        })
    }
}

/// Inter-service auth: verifies `Authorization: Bearer <service JWT>` with a
/// [`ServiceJwtVerifier`], requiring the token's `lxm` to be the called
/// method (unless disabled with [`ServiceAuth::any_method`]).
pub struct ServiceAuth<R> {
    verifier: ServiceJwtVerifier<R>,
    check_lxm: bool,
}

impl<R: SigningKeyResolver> ServiceAuth<R> {
    /// Verify tokens addressed to `audience` (this service's DID; `None` to
    /// accept any audience).
    pub fn new(audience: Option<&str>, resolver: R) -> Self {
        ServiceAuth::from_verifier(ServiceJwtVerifier::new(audience, resolver))
    }

    /// Wrap an existing verifier.
    pub fn from_verifier(verifier: ServiceJwtVerifier<R>) -> Self {
        ServiceAuth {
            verifier,
            check_lxm: true,
        }
    }

    /// Accept tokens bound to any method, or to none.
    pub fn any_method(mut self) -> Self {
        self.check_lxm = false;
        self
    }
}

impl<R: SigningKeyResolver + 'static> AuthVerifier for ServiceAuth<R> {
    type Credentials = ServiceJwtClaims;

    fn verify<'a>(
        &'a self,
        ctx: &'a AuthContext,
    ) -> BoxFuture<'a, Result<ServiceJwtClaims, ServerError>> {
        Box::pin(async move {
            let jwt = ctx
                .bearer_token()
                .ok_or_else(|| ServerError::auth_required("missing jwt").with_name("MissingJwt"))?;
            let lxm = self.check_lxm.then_some(ctx.nsid.as_str());
            Ok(self.verifier.verify(jwt, lxm).await?)
        })
    }
}
