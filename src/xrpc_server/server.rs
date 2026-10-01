use std::collections::HashMap;
use std::future::Future;
use std::marker::PhantomData;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{FromRequestParts, State};
use axum::response::{IntoResponse, Response};
use futures::stream::BoxStream;
use futures::{FutureExt, Stream, StreamExt};
use http::request::Parts;
use http::{HeaderMap, Method, Request};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::lexicon::{
    BodyDef, Catalog, Def, ParamsDef, validate_input, validate_message, validate_output,
    validate_params,
};
use crate::service_auth::BoxFuture;
use crate::xrpc_server::auth::{AuthVerifier, NoAuth};
use crate::xrpc_server::body::{self, Input, InputBody, PayloadLimits, Presence};
use crate::xrpc_server::context::{AuthContext, RequestContext};
use crate::xrpc_server::error::ServerError;
use crate::xrpc_server::output::Output;
use crate::xrpc_server::params::Params;
use crate::xrpc_server::rate_limit::{
    self, Limiter, RateLimitContext, RateLimits, RouteLimiter, RouteRateLimit,
};
use crate::xrpc_server::stream::Frame;

type Catchall = Arc<dyn Fn(Request<Body>) -> BoxFuture<'static, Response> + Send + Sync>;
type ErrorHook = Arc<dyn Fn(&str, &ServerError) + Send + Sync>;

/// XRPC HTTP server framework built on axum.
///
/// Register query, procedure and subscription handlers with the builder
/// methods, then call [`Server::into_router`] to compose with other axum
/// routes or [`Server::serve`] to start listening. Use [`Server::route`] to
/// configure a method's authentication, payload limits and rate limits.
///
/// ```no_run
/// use shrike::xrpc_server::{Server, RequestContext, ServerError};
/// use serde::{Deserialize, Serialize};
///
/// #[derive(Deserialize)]
/// struct PingParams {}
///
/// #[derive(Serialize)]
/// struct PingResponse { message: String }
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let server = Server::new()
///     .query("com.example.ping", |_params: PingParams, _ctx: RequestContext| async {
///         Ok::<_, ServerError>(PingResponse { message: "pong".into() })
///     });
/// # Ok(())
/// # }
/// ```
pub struct Server {
    routes: HashMap<String, Slots>,
    catalog: Option<Arc<Catalog>>,
    limits: PayloadLimits,
    validate_response: bool,
    catchall: Option<Catchall>,
    on_error: Option<ErrorHook>,
    rate_limits: Option<RateLimits>,
}

#[derive(Default, Clone)]
struct Slots {
    query: Option<Arc<dyn Route>>,
    procedure: Option<Arc<dyn Route>>,
    subscription: Option<Arc<dyn Route>>,
}

/// Runtime configuration shared by every request.
pub(crate) struct Shared {
    routes: HashMap<String, Slots>,
    catalog: Option<Arc<Catalog>>,
    limits: PayloadLimits,
    validate_response: bool,
    catchall: Option<Catchall>,
    on_error: Option<ErrorHook>,
    rate_limits: Option<RateLimits>,
}

impl Shared {
    fn report(&self, nsid: &str, err: &ServerError) {
        if let Some(hook) = &self.on_error {
            hook(nsid, err);
        }
    }

    fn error_response(&self, nsid: &str, err: ServerError) -> Response {
        self.report(nsid, &err);
        err.into_response()
    }

    fn def(&self, nsid: &str) -> Option<(&Catalog, &Def)> {
        let catalog = self.catalog.as_deref()?;
        Some((catalog, catalog.main_def(nsid)?))
    }
}

impl Server {
    /// Create an empty server with no registered handlers.
    pub fn new() -> Self {
        Server {
            routes: HashMap::new(),
            catalog: None,
            limits: PayloadLimits::default(),
            validate_response: true,
            catchall: None,
            on_error: None,
            rate_limits: None,
        }
    }

    /// Validate requests and responses against these lexicons.
    ///
    /// For methods the catalog defines, query parameters are decoded by their
    /// declared types and validated (with defaults applied), the request
    /// body's presence and encoding are checked against the declared input,
    /// JSON input is validated (with defaults), and outputs and subscription
    /// messages are validated unless [`Server::validate_response`] is off.
    /// A call with the wrong HTTP method for a defined method is a 400.
    pub fn catalog(mut self, catalog: impl Into<Arc<Catalog>>) -> Self {
        self.catalog = Some(catalog.into());
        self
    }

    /// Default request body limits (see [`PayloadLimits`]).
    pub fn payload_limits(mut self, limits: PayloadLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Whether to validate handler outputs and subscription messages against
    /// the catalog (default: on). An invalid output is a 500.
    pub fn validate_response(mut self, validate: bool) -> Self {
        self.validate_response = validate;
        self
    }

    /// Rate limits (see [`RateLimits`]).
    pub fn rate_limits(mut self, limits: RateLimits) -> Self {
        self.rate_limits = Some(limits);
        self
    }

    /// Handle requests for methods with no registered handler, e.g. to proxy
    /// them. Runs after the global rate limits and the HTTP method check.
    /// Without one, such requests get 501 `MethodNotImplemented`.
    pub fn catchall<F, Fut>(mut self, handler: F) -> Self
    where
        F: Fn(Request<Body>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Response> + Send + 'static,
    {
        self.catchall = Some(Arc::new(move |req| Box::pin(handler(req))));
        self
    }

    /// Observe every error response (method NSID, error), e.g. for logging.
    /// For a 500 the error carries the detail that is not sent.
    pub fn on_error(mut self, hook: impl Fn(&str, &ServerError) + Send + Sync + 'static) -> Self {
        self.on_error = Some(Arc::new(hook));
        self
    }

    /// Configure the method `nsid`; finish with one of the
    /// [`RouteBuilder`] handler methods.
    pub fn route(self, nsid: &str) -> RouteBuilder<NoAuth> {
        RouteBuilder {
            server: self,
            nsid: nsid.to_owned(),
            auth: NoAuth,
            limits: None,
            rate_limits: Vec::new(),
        }
    }

    /// Register a query (GET) handler that takes deserialized parameters and
    /// returns a JSON-serializable output (`()` for an empty response).
    pub fn query<P, O, F, Fut>(self, nsid: &str, handler: F) -> Self
    where
        P: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(P, RequestContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
    {
        self.route(nsid).query(handler)
    }

    /// Register a procedure (POST) handler that takes a deserialized JSON
    /// body and returns a JSON-serializable output (`()` for an empty
    /// response). Without a body, the input is deserialized from `null`, so
    /// use `()` or an `Option` for procedures without input.
    pub fn procedure<I, O, F, Fut>(self, nsid: &str, handler: F) -> Self
    where
        I: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(I, RequestContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
    {
        self.route(nsid).procedure(handler)
    }

    /// Register a subscription (WebSocket) handler. See
    /// [`RouteBuilder::subscription`].
    pub fn subscription<P, S, F, Fut>(self, nsid: &str, handler: F) -> Self
    where
        P: DeserializeOwned + Send + 'static,
        F: Fn(P, RequestContext) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S, ServerError>> + Send + 'static,
        S: Stream<Item = Result<Frame, ServerError>> + Send + 'static,
    {
        self.route(nsid).subscription(handler)
    }

    /// Build into an axum Router serving `/xrpc/*`, for composition with
    /// other routes. Serve it with
    /// `into_make_service_with_connect_info::<SocketAddr>()` if any rate
    /// limit is keyed by client IP (the default); otherwise those limits
    /// reject requests with a 500.
    pub fn into_router(self) -> Router {
        let shared = Arc::new(Shared {
            routes: self.routes,
            catalog: self.catalog,
            limits: self.limits,
            validate_response: self.validate_response,
            catchall: self.catchall,
            on_error: self.on_error,
            rate_limits: self.rate_limits,
        });
        Router::new()
            .route("/xrpc/", axum::routing::any(invalid_path))
            .route("/xrpc/{*nsid}", axum::routing::any(dispatch))
            .with_state(shared)
    }

    /// Serve on a TCP listener, with client addresses available for rate
    /// limiting.
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), std::io::Error> {
        axum::serve(
            listener,
            self.into_router()
                .into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
    }

    fn insert(&mut self, nsid: String, kind: Kind, route: Arc<dyn Route>) {
        let slots = self.routes.entry(nsid).or_default();
        match kind {
            Kind::Query => slots.query = Some(route),
            Kind::Procedure => slots.procedure = Some(route),
            Kind::Subscription => slots.subscription = Some(route),
        }
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}

/// Configuration for one method, from [`Server::route`].
pub struct RouteBuilder<V = NoAuth> {
    server: Server,
    nsid: String,
    auth: V,
    limits: Option<PayloadLimits>,
    rate_limits: Vec<RouteRateLimit>,
}

impl<V: AuthVerifier> RouteBuilder<V> {
    /// Authenticate requests with `verifier`; handlers receive its
    /// credentials in [`RequestContext::auth`].
    pub fn auth<V2: AuthVerifier>(self, verifier: V2) -> RouteBuilder<V2> {
        RouteBuilder {
            server: self.server,
            nsid: self.nsid,
            auth: verifier,
            limits: self.limits,
            rate_limits: self.rate_limits,
        }
    }

    /// Body limits for this method, instead of the server's.
    pub fn payload_limits(mut self, limits: PayloadLimits) -> Self {
        self.limits = Some(limits);
        self
    }

    /// Add a rate limit (requires [`Server::rate_limits`]).
    pub fn rate_limit(mut self, limit: RouteRateLimit) -> Self {
        self.rate_limits.push(limit);
        self
    }

    /// A query handler; see [`Server::query`].
    pub fn query<P, O, F, Fut>(self, handler: F) -> Server
    where
        P: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(P, RequestContext<V::Credentials>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
    {
        self.method(Kind::Query, TypedQuery(handler, PhantomData))
    }

    /// A procedure handler; see [`Server::procedure`].
    pub fn procedure<I, O, F, Fut>(self, handler: F) -> Server
    where
        I: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(I, RequestContext<V::Credentials>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
    {
        self.method(Kind::Procedure, TypedProcedure(handler, PhantomData))
    }

    /// A query handler that returns any [`Output`], e.g. a blob or a
    /// streamed CAR file.
    pub fn query_raw<F, Fut>(self, handler: F) -> Server
    where
        F: Fn(RequestContext<V::Credentials>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output, ServerError>> + Send + 'static,
    {
        self.method(Kind::Query, RawQuery(handler))
    }

    /// A procedure handler that takes the raw [`Input`] (`None` without a
    /// body) and returns any [`Output`].
    ///
    /// Without a lexicon, any body is streamed. With one, a JSON or text
    /// input is read and validated, and anything else (including every body
    /// for a `*/*` input) is streamed.
    pub fn procedure_raw<F, Fut>(self, handler: F) -> Server
    where
        F: Fn(RequestContext<V::Credentials>, Option<Input>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Output, ServerError>> + Send + 'static,
    {
        self.method(Kind::Procedure, RawProcedure(handler))
    }

    /// A subscription handler.
    ///
    /// The handler gets the deserialized parameters and returns the message
    /// stream. Rate limits are charged once per connection, after
    /// authentication. Parameter, authentication, rate-limit and handler
    /// errors, and any `Err` item, are sent as an error frame after the
    /// upgrade, and the socket is then closed with code 1008 and the error
    /// name as the reason. A [`Frame::Error`] item closes the stream the
    /// same way. The end of the stream closes with 1000. Each frame is sent
    /// before the next is polled, and the stream is dropped when the client
    /// disconnects.
    pub fn subscription<P, S, F, Fut>(self, handler: F) -> Server
    where
        P: DeserializeOwned + Send + 'static,
        F: Fn(P, RequestContext<V::Credentials>) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<S, ServerError>> + Send + 'static,
        S: Stream<Item = Result<Frame, ServerError>> + Send + 'static,
    {
        let route = SubscriptionRoute {
            nsid: self.nsid.clone(),
            auth: self.auth,
            rate_limits: RouteLimits::new(self.rate_limits),
            handler: move |params: Params,
                           ctx|
                  -> BoxFuture<'static, Result<FrameStream, ServerError>> {
                match params.deserialize::<P>() {
                    Ok(p) => {
                        let fut = handler(p, ctx);
                        Box::pin(async move { Ok(fut.await?.boxed()) })
                    }
                    Err(e) => Box::pin(async move { Err(e) }),
                }
            },
        };
        let mut server = self.server;
        server.insert(self.nsid, Kind::Subscription, Arc::new(route));
        server
    }

    fn method<H: Invoke<V::Credentials>>(self, kind: Kind, handler: H) -> Server {
        let route = MethodRoute {
            nsid: self.nsid.clone(),
            kind,
            auth: self.auth,
            limits: self.limits,
            rate_limits: RouteLimits::new(self.rate_limits),
            handler,
        };
        let mut server = self.server;
        server.insert(self.nsid, kind, Arc::new(route));
        server
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Kind {
    Query,
    Procedure,
    Subscription,
}

impl Kind {
    fn http_method(self) -> &'static str {
        match self {
            Kind::Procedure => "POST",
            Kind::Query | Kind::Subscription => "GET",
        }
    }
}

async fn invalid_path(State(shared): State<Arc<Shared>>) -> Response {
    shared.error_response("", ServerError::invalid_request("invalid xrpc path"))
}

/// The NSID in an `/xrpc/<nsid>` path, by the reference's rules: ASCII
/// letters and digits separated by single `.` or `-`, at least two
/// characters, and at most one trailing `/`.
pub(crate) fn parse_xrpc_path(path: &str) -> Option<&str> {
    let rest = path.strip_prefix("/xrpc/")?;
    let nsid = rest.strip_suffix('/').unwrap_or(rest);
    if nsid.len() < 2 {
        return None;
    }
    let mut prev_sep = true;
    for b in nsid.bytes() {
        match b {
            b'.' | b'-' if prev_sep => return None,
            b'.' | b'-' => prev_sep = true,
            b if b.is_ascii_alphanumeric() => prev_sep = false,
            _ => return None,
        }
    }
    (!prev_sep).then_some(nsid)
}

fn is_websocket_upgrade(headers: &HeaderMap) -> bool {
    headers
        .get(http::header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.eq_ignore_ascii_case("websocket"))
}

async fn dispatch(State(shared): State<Arc<Shared>>, req: Request<Body>) -> Response {
    let Some(nsid) = parse_xrpc_path(req.uri().path()).map(str::to_owned) else {
        return shared.error_response("", ServerError::invalid_request("invalid xrpc path"));
    };
    let slots = shared.routes.get(&nsid).cloned().unwrap_or_default();
    let method = req.method();
    let route = if method == Method::GET || method == Method::HEAD {
        match (&slots.subscription, &slots.query) {
            (Some(sub), Some(_)) if is_websocket_upgrade(req.headers()) => Some(sub),
            (_, Some(query)) => Some(query),
            (Some(sub), None) => Some(sub),
            (None, None) => None,
        }
    } else if method == Method::POST {
        slots.procedure.as_ref()
    } else {
        None
    };
    match route {
        Some(route) => Arc::clone(route).call(Arc::clone(&shared), req).await,
        None => fallback(shared, &nsid, &slots, req).await,
    }
}

/// Requests with no matching handler: global rate limits, the HTTP method
/// check, then the catchall or 501.
async fn fallback(shared: Arc<Shared>, nsid: &str, slots: &Slots, req: Request<Body>) -> Response {
    let mut extra = HeaderMap::new();
    if let Some(limits) = &shared.rate_limits {
        let limiters: Vec<Limiter> = limits.global_limiters().collect();
        let params = Params::default();
        let plan = rate_limit::plan(
            limits,
            &limiters,
            &RateLimitContext {
                nsid,
                headers: req.headers(),
                ip: rate_limit::client_ip(&req),
                params: &params,
                input: None,
                auth: None,
            },
        );
        let charged = match plan {
            Ok(plan) => rate_limit::charge(limits, plan).await,
            Err(e) => Err(e),
        };
        match charged {
            Ok((headers, _)) => extra = headers,
            Err(e) => return shared.error_response(nsid, e),
        }
    }

    let expected = match shared.def(nsid) {
        Some((_, Def::Query(_))) => Some("GET"),
        Some((_, Def::Procedure(_))) => Some("POST"),
        Some(_) => None,
        None => [
            (&slots.query, Kind::Query),
            (&slots.procedure, Kind::Procedure),
            (&slots.subscription, Kind::Subscription),
        ]
        .into_iter()
        .find_map(|(slot, kind)| slot.as_ref().map(|_| kind.http_method())),
    };
    let method = req.method().as_str();
    let mut response = match expected {
        Some(expected) if method != expected && !(expected == "GET" && method == "HEAD") => shared
            .error_response(
                nsid,
                ServerError::invalid_request(format!(
                    "Incorrect HTTP method ({method}) expected {expected}"
                )),
            ),
        _ => match &shared.catchall {
            Some(catchall) => catchall(req).await,
            None => shared.error_response(nsid, ServerError::method_not_implemented()),
        },
    };
    append_headers(response.headers_mut(), extra);
    response
}

fn append_headers(headers: &mut HeaderMap, extra: HeaderMap) {
    let mut name = None;
    for (key, value) in extra {
        if key.is_some() {
            name = key;
        }
        if let Some(name) = &name {
            headers.append(name.clone(), value);
        }
    }
}

trait Route: Send + Sync + 'static {
    fn call(
        self: Arc<Self>,
        shared: Arc<Shared>,
        req: Request<Body>,
    ) -> BoxFuture<'static, Response>;
}

/// How a handler wants its body.
#[derive(Clone, Copy, PartialEq, Eq)]
enum InputMode {
    /// Parsed JSON (typed procedures).
    Json,
    /// Whatever the lexicon calls for, streamed otherwise.
    Raw,
}

trait Invoke<C>: Send + Sync + 'static {
    const MODE: InputMode;
    fn invoke(
        &self,
        ctx: RequestContext<C>,
        input: Option<Input>,
    ) -> BoxFuture<'static, Result<Output, ServerError>>;
}

struct TypedQuery<F, P, O>(F, PhantomData<fn(P) -> O>);

impl<C, F, P, O, Fut> Invoke<C> for TypedQuery<F, P, O>
where
    C: Send + 'static,
    P: DeserializeOwned + Send + 'static,
    O: Serialize + Send + 'static,
    F: Fn(P, RequestContext<C>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
{
    const MODE: InputMode = InputMode::Raw;

    fn invoke(
        &self,
        ctx: RequestContext<C>,
        _input: Option<Input>,
    ) -> BoxFuture<'static, Result<Output, ServerError>> {
        match ctx.params.deserialize::<P>() {
            Ok(params) => {
                let fut = (self.0)(params, ctx);
                Box::pin(async move { Output::from_serialize(&fut.await?) })
            }
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }
}

struct TypedProcedure<F, I, O>(F, PhantomData<fn(I) -> O>);

impl<C, F, I, O, Fut> Invoke<C> for TypedProcedure<F, I, O>
where
    C: Send + 'static,
    I: DeserializeOwned + Send + 'static,
    O: Serialize + Send + 'static,
    F: Fn(I, RequestContext<C>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<O, ServerError>> + Send + 'static,
{
    const MODE: InputMode = InputMode::Json;

    fn invoke(
        &self,
        ctx: RequestContext<C>,
        input: Option<Input>,
    ) -> BoxFuture<'static, Result<Output, ServerError>> {
        let input = match input {
            Some(Input {
                body: InputBody::Json(value),
                ..
            }) => serde_json::from_value::<I>(value)
                .map_err(|e| ServerError::invalid_request(format!("Invalid request body: {e}"))),
            Some(other) => Err(unexpected_body(other)),
            None => I::deserialize(Value::Null).map_err(|_| {
                ServerError::invalid_request("A request body is expected but none was provided")
            }),
        };
        match input {
            Ok(input) => {
                let fut = (self.0)(input, ctx);
                Box::pin(async move { Output::from_serialize(&fut.await?) })
            }
            Err(e) => Box::pin(async move { Err(e) }),
        }
    }
}

fn unexpected_body(input: Input) -> ServerError {
    ServerError::invalid_request(format!(
        "Wrong request encoding (Content-Type): {}",
        input.encoding
    ))
}

struct RawQuery<F>(F);

impl<C, F, Fut> Invoke<C> for RawQuery<F>
where
    C: Send + 'static,
    F: Fn(RequestContext<C>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Output, ServerError>> + Send + 'static,
{
    const MODE: InputMode = InputMode::Raw;

    fn invoke(
        &self,
        ctx: RequestContext<C>,
        _input: Option<Input>,
    ) -> BoxFuture<'static, Result<Output, ServerError>> {
        Box::pin((self.0)(ctx))
    }
}

struct RawProcedure<F>(F);

impl<C, F, Fut> Invoke<C> for RawProcedure<F>
where
    C: Send + 'static,
    F: Fn(RequestContext<C>, Option<Input>) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<Output, ServerError>> + Send + 'static,
{
    const MODE: InputMode = InputMode::Raw;

    fn invoke(
        &self,
        ctx: RequestContext<C>,
        input: Option<Input>,
    ) -> BoxFuture<'static, Result<Output, ServerError>> {
        Box::pin((self.0)(ctx, input))
    }
}

/// A route's rate limits, resolved against the server's on first use.
struct RouteLimits {
    limits: Vec<RouteRateLimit>,
    limiters: OnceLock<Result<Vec<Limiter>, String>>,
}

impl RouteLimits {
    fn new(limits: Vec<RouteRateLimit>) -> Self {
        Self {
            limits,
            limiters: OnceLock::new(),
        }
    }

    /// Plan the global, shared and route limits that apply to a request;
    /// charge them with [`charge_rate_limits`]. Planning is synchronous
    /// because the context is not `Send`.
    fn plan<'a>(
        &self,
        shared: &'a Shared,
        ctx: &RateLimitContext<'_>,
    ) -> Result<Option<(&'a RateLimits, rate_limit::Plan)>, ServerError> {
        let Some(limits) = &shared.rate_limits else {
            if self.limits.is_empty() {
                return Ok(None);
            }
            return Err(ServerError::internal(
                "route rate limits require Server::rate_limits",
            ));
        };
        let limiters = self
            .limiters
            .get_or_init(|| limits.for_route(ctx.nsid, &self.limits))
            .as_ref()
            .map_err(ServerError::internal)?;
        Ok(Some((limits, rate_limit::plan(limits, limiters, ctx)?)))
    }
}

/// Charge a plan from [`RouteLimits::plan`]. Returns the headers to add to
/// the response and the handle for [`RequestContext::reset_route_rate_limits`].
async fn charge_rate_limits(
    planned: Option<(&RateLimits, rate_limit::Plan)>,
) -> Result<(HeaderMap, Option<RouteLimiter>), ServerError> {
    let Some((limits, plan)) = planned else {
        return Ok((HeaderMap::new(), None));
    };
    let (headers, handle) = rate_limit::charge(limits, plan).await?;
    Ok((headers, Some(handle)))
}

struct MethodRoute<V, H> {
    nsid: String,
    kind: Kind,
    auth: V,
    limits: Option<PayloadLimits>,
    rate_limits: RouteLimits,
    handler: H,
}

impl<V, H> Route for MethodRoute<V, H>
where
    V: AuthVerifier,
    H: Invoke<V::Credentials>,
{
    fn call(
        self: Arc<Self>,
        shared: Arc<Shared>,
        req: Request<Body>,
    ) -> BoxFuture<'static, Response> {
        let procedure = self.kind == Kind::Procedure;
        let nsid = self.nsid.clone();
        let hook = Arc::clone(&shared);
        let panicked =
            move || hook.error_response(&nsid, ServerError::internal("handler panicked"));
        let fut = async move { self.run(shared, req).await };
        if procedure {
            // A procedure runs to completion even if the client goes away, so
            // a write is never abandoned halfway. Queries are cancelled.
            Box::pin(async move { tokio::spawn(fut).await.unwrap_or_else(|_| panicked()) })
        } else {
            Box::pin(async move {
                std::panic::AssertUnwindSafe(fut)
                    .catch_unwind()
                    .await
                    .unwrap_or_else(|_| panicked())
            })
        }
    }
}

impl<V, H> MethodRoute<V, H>
where
    V: AuthVerifier,
    H: Invoke<V::Credentials>,
{
    async fn run(&self, shared: Arc<Shared>, req: Request<Body>) -> Response {
        let mut extra = HeaderMap::new();
        let result = self.pipeline(&shared, req, &mut extra).await;
        let mut response = match result {
            Ok(output) => output.into_response(),
            Err(err) => shared.error_response(&self.nsid, err),
        };
        append_headers(response.headers_mut(), extra);
        response
    }

    async fn pipeline(
        &self,
        shared: &Shared,
        req: Request<Body>,
        extra: &mut HeaderMap,
    ) -> Result<Output, ServerError> {
        let ip = rate_limit::client_ip(&req);
        let (parts, body) = req.into_parts();
        let def = shared.def(&self.nsid).filter(|(_, def)| {
            matches!(
                (self.kind, def),
                (Kind::Query, Def::Query(_)) | (Kind::Procedure, Def::Procedure(_))
            )
        });

        let params = decode_params(&self.nsid, &parts, def)?;
        let auth_ctx = AuthContext {
            nsid: self.nsid.clone(),
            method: parts.method.clone(),
            uri: parts.uri.clone(),
            headers: parts.headers.clone(),
            params,
        };
        let auth = self.auth.verify(&auth_ctx).await?;
        let params = auth_ctx.params;

        let limits = self.limits.unwrap_or(shared.limits);
        let input = match self.kind {
            Kind::Procedure => {
                let lex_input = def.map(|(_, def)| match def {
                    Def::Procedure(p) => p.input.as_ref(),
                    _ => None,
                });
                read_input(
                    &self.nsid,
                    &parts.headers,
                    body,
                    def.map(|(c, _)| c),
                    lex_input,
                    H::MODE,
                    limits,
                )
                .await?
            }
            _ => {
                body::expect_no_body(body::presence(&parts.headers, &body)?, body).await?;
                None
            }
        };

        let planned = self.rate_limits.plan(
            shared,
            &RateLimitContext {
                nsid: &self.nsid,
                headers: &parts.headers,
                ip,
                params: &params,
                input: input.as_ref().and_then(|i| match &i.body {
                    InputBody::Json(v) => Some(v),
                    _ => None,
                }),
                auth: Some(&auth),
            },
        )?;
        let (headers, limiter) = charge_rate_limits(planned).await?;
        *extra = headers;

        let ctx = RequestContext {
            auth,
            nsid: self.nsid.clone(),
            params,
            headers: parts.headers,
            limiter,
        };
        let output = self.handler.invoke(ctx, input).await?;
        if shared.validate_response
            && let Some((catalog, def)) = def
        {
            check_output(catalog, &self.nsid, def, &output)?;
        }
        Ok(output)
    }
}

fn params_def(def: &Def) -> Option<&ParamsDef> {
    match def {
        Def::Query(q) => q.parameters.as_ref(),
        Def::Procedure(p) => p.parameters.as_ref(),
        Def::Subscription(s) => s.parameters.as_ref(),
        _ => None,
    }
}

fn decode_params(
    nsid: &str,
    parts: &Parts,
    def: Option<(&Catalog, &Def)>,
) -> Result<Params, ServerError> {
    let mut params = Params::from_query(parts.uri.query().unwrap_or(""));
    if let Some((catalog, def)) = def {
        let invalid = |e: String| ServerError::invalid_request(format!("Invalid params: {e}"));
        let mut json = params.decode(params_def(def)).map_err(invalid)?;
        validate_params(catalog, nsid, &mut json).map_err(|e| invalid(e.to_string()))?;
        params.set_json(json);
    }
    Ok(params)
}

/// Read a procedure's body, following the lexicon's input declaration if
/// there is one (`lex_input` is `Some(None)` for a lexicon without input).
async fn read_input(
    nsid: &str,
    headers: &HeaderMap,
    body: Body,
    catalog: Option<&Catalog>,
    lex_input: Option<Option<&BodyDef>>,
    mode: InputMode,
    limits: PayloadLimits,
) -> Result<Option<Input>, ServerError> {
    let presence = body::presence(headers, &body)?;
    let declared = match lex_input {
        Some(None) => {
            body::expect_no_body(presence, body).await?;
            return Ok(None);
        }
        Some(Some(def)) => Some(def),
        None if matches!(presence, Presence::Missing | Presence::Empty) => return Ok(None),
        None => None,
    };
    if presence == Presence::Missing {
        return Err(ServerError::invalid_request(
            "A request body is expected but none was provided",
        ));
    }
    let (mime, charset) = body::content_type(headers).ok_or_else(|| {
        ServerError::invalid_request("Request encoding (Content-Type) required but not provided")
    })?;
    let allowed = match declared {
        Some(def) => def.encoding.as_str(),
        None if mode == InputMode::Json => "application/json",
        None => "*/*",
    };
    if !body::encoding_matches(allowed, &mime) {
        return Err(ServerError::invalid_request(format!(
            "Wrong request encoding (Content-Type): {mime}"
        )));
    }
    let decoder = body::decoder(headers)?;
    let stream_all = declared.is_none_or(|def| def.encoding.trim() == "*/*");

    let body = if mime == "application/json" && !(stream_all && mode == InputMode::Raw) {
        body::check_charset(charset.as_deref())?;
        body::check_length(presence, Some(limits.json))?;
        let mut value = body::parse_json(&body::read_limited(body, decoder, limits.json).await?)?;
        if let (Some(catalog), Some(_)) = (catalog, declared) {
            validate_input(catalog, nsid, &mut value)
                .map_err(|e| ServerError::invalid_request(e.to_string()))?;
        }
        InputBody::Json(value)
    } else if mime == "text/plain" && !stream_all {
        body::check_charset(charset.as_deref())?;
        body::check_length(presence, Some(limits.text))?;
        InputBody::Text(body::parse_text(
            body::read_limited(body, decoder, limits.text).await?,
        )?)
    } else {
        body::check_length(presence, limits.blob)?;
        InputBody::Stream(body::BodyStream::new(body, decoder, limits.blob))
    };
    Ok(Some(Input {
        encoding: mime,
        body,
    }))
}

fn check_output(
    catalog: &Catalog,
    nsid: &str,
    def: &Def,
    output: &Output,
) -> Result<(), ServerError> {
    let declared = match def {
        Def::Query(q) => q.output.as_ref(),
        Def::Procedure(p) => p.output.as_ref(),
        _ => return Ok(()),
    };
    match (declared, output.encoding()) {
        (None, None) => Ok(()),
        (None, Some(_)) => Err(ServerError::internal(
            "A response body was provided when none was expected",
        )),
        (Some(_), None) => Err(ServerError::internal(
            "A response body is expected but none was provided",
        )),
        (Some(declared), Some(encoding)) => {
            if !body::encoding_matches(&declared.encoding, encoding) {
                return Err(ServerError::internal(format!(
                    "Invalid response encoding: {encoding}"
                )));
            }
            match output.json_body() {
                Some(json) => validate_output(catalog, nsid, json)
                    .map_err(|e| ServerError::internal(format!("Invalid output: {e}"))),
                None => Ok(()),
            }
        }
    }
}

type FrameStream = BoxStream<'static, Result<Frame, ServerError>>;

struct SubscriptionRoute<V, H> {
    nsid: String,
    auth: V,
    rate_limits: RouteLimits,
    handler: H,
}

impl<V, H> Route for SubscriptionRoute<V, H>
where
    V: AuthVerifier,
    H: Fn(
            Params,
            RequestContext<V::Credentials>,
        ) -> BoxFuture<'static, Result<FrameStream, ServerError>>
        + Send
        + Sync
        + 'static,
{
    fn call(
        self: Arc<Self>,
        shared: Arc<Shared>,
        req: Request<Body>,
    ) -> BoxFuture<'static, Response> {
        Box::pin(async move {
            let ip = rate_limit::client_ip(&req);
            let (mut parts, _body) = req.into_parts();
            match WebSocketUpgrade::from_request_parts(&mut parts, &()).await {
                Ok(ws) => ws.on_upgrade(move |socket| self.run(shared, parts, ip, socket)),
                Err(rejection) => shared.error_response(
                    &self.nsid,
                    ServerError::invalid_request(format!(
                        "Expected a WebSocket upgrade: {}",
                        rejection.body_text()
                    )),
                ),
            }
        })
    }
}

/// WebSocket close codes.
const CLOSE_NORMAL: u16 = 1000;
const CLOSE_POLICY: u16 = 1008;

impl<V, H> SubscriptionRoute<V, H>
where
    V: AuthVerifier,
    H: Fn(
            Params,
            RequestContext<V::Credentials>,
        ) -> BoxFuture<'static, Result<FrameStream, ServerError>>
        + Send
        + Sync
        + 'static,
{
    async fn open(
        &self,
        shared: &Shared,
        parts: Parts,
        ip: Option<IpAddr>,
    ) -> Result<FrameStream, ServerError> {
        let def = shared
            .def(&self.nsid)
            .filter(|(_, def)| matches!(def, Def::Subscription(_)));
        let params = decode_params(&self.nsid, &parts, def)?;
        let auth_ctx = AuthContext {
            nsid: self.nsid.clone(),
            method: parts.method,
            uri: parts.uri,
            headers: parts.headers,
            params,
        };
        let auth = self.auth.verify(&auth_ctx).await?;
        // Charged once per connection. The upgrade response has already been
        // sent, so the rate-limit headers are not.
        let planned = self.rate_limits.plan(
            shared,
            &RateLimitContext {
                nsid: &self.nsid,
                headers: &auth_ctx.headers,
                ip,
                params: &auth_ctx.params,
                input: None,
                auth: Some(&auth),
            },
        )?;
        let (_, limiter) = charge_rate_limits(planned).await?;
        let ctx = RequestContext {
            auth,
            nsid: self.nsid.clone(),
            params: auth_ctx.params.clone(),
            headers: auth_ctx.headers,
            limiter,
        };
        (self.handler)(auth_ctx.params, ctx).await
    }

    async fn run(
        self: Arc<Self>,
        shared: Arc<Shared>,
        parts: Parts,
        ip: Option<IpAddr>,
        mut socket: WebSocket,
    ) {
        let mut frames = match self.open(&shared, parts, ip).await {
            Ok(frames) => frames,
            Err(err) => return self.close_with_error(&shared, &mut socket, err).await,
        };
        let validate = shared.validate_response
            && shared
                .def(&self.nsid)
                .is_some_and(|(_, def)| matches!(def, Def::Subscription(_)));
        loop {
            tokio::select! {
                incoming = socket.recv() => match incoming {
                    // Clients have nothing to send; only watch for them leaving.
                    Some(Ok(Message::Close(_))) | Some(Err(_)) | None => return,
                    Some(Ok(_)) => {}
                },
                next = frames.next() => {
                    let frame = match next {
                        None => {
                            let _ = socket.send(close(CLOSE_NORMAL, "")).await;
                            return;
                        }
                        Some(Err(err)) => return self.close_with_error(&shared, &mut socket, err).await,
                        Some(Ok(frame)) => frame,
                    };
                    if validate
                        && let Err(err) = self.check_message(&shared, &frame)
                    {
                        return self.close_with_error(&shared, &mut socket, err).await;
                    }
                    let bytes = match frame.encode() {
                        Ok(bytes) => bytes,
                        Err(e) => {
                            let err = ServerError::internal(format!("failed to encode frame: {e}"));
                            return self.close_with_error(&shared, &mut socket, err).await;
                        }
                    };
                    if socket.send(Message::Binary(bytes.into())).await.is_err() {
                        return;
                    }
                    if let Frame::Error { error, .. } = &frame {
                        let _ = socket.send(close(CLOSE_POLICY, error)).await;
                        return;
                    }
                }
            }
        }
    }

    fn check_message(&self, shared: &Shared, frame: &Frame) -> Result<(), ServerError> {
        let Some(catalog) = shared.catalog.as_deref() else {
            return Ok(());
        };
        match frame.to_json(&self.nsid) {
            Ok(Some(json)) => validate_message(catalog, &self.nsid, &json)
                .map_err(|e| ServerError::internal(format!("Invalid message: {e}"))),
            Ok(None) => Ok(()),
            Err(e) => Err(ServerError::internal(format!("Invalid message: {e}"))),
        }
    }

    async fn close_with_error(&self, shared: &Shared, socket: &mut WebSocket, err: ServerError) {
        shared.report(&self.nsid, &err);
        let frame = Frame::from_server_error(&err);
        if let Ok(bytes) = frame.encode()
            && socket.send(Message::Binary(bytes.into())).await.is_ok()
            && let Frame::Error { error, .. } = &frame
        {
            let _ = socket.send(close(CLOSE_POLICY, error)).await;
        }
    }
}

/// A close message. The reason is truncated to the 123 bytes a close frame
/// allows.
fn close(code: u16, reason: &str) -> Message {
    let mut end = reason.len().min(123);
    while !reason.is_char_boundary(end) {
        end -= 1;
    }
    Message::Close(Some(CloseFrame {
        code,
        reason: reason[..end].into(),
    }))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    // Vectors from the reference parsing.test.ts. The router strips the query
    // string before calling `parse_xrpc_path`, so `?...` suffixes are removed.
    fn path(url: &str) -> &str {
        url.split_once('?').map_or(url, |(p, _)| p)
    }

    #[test]
    fn parse_xrpc_path_valid() {
        let cases = [
            ("/xrpc/blee.blah.bloo", "blee.blah.bloo"),
            ("/xrpc/blee.blah.bloo?foo[]", "blee.blah.bloo"),
            ("/xrpc/blee.blah.bloo?foo=bar", "blee.blah.bloo"),
            ("/xrpc/com.example.nsid", "com.example.nsid"),
            ("/xrpc/com.example.nsid?foo=bar", "com.example.nsid"),
            ("/xrpc/com.example-domain.nsid", "com.example-domain.nsid"),
            ("/xrpc/blee.blah.bloo/?", "blee.blah.bloo"),
            ("/xrpc/blee.blah.bloo/?foo=", "blee.blah.bloo"),
            ("/xrpc/blee.blah.bloo/?bool", "blee.blah.bloo"),
            ("/xrpc/com.example.nsid/", "com.example.nsid"),
            ("/xrpc/ab", "ab"),
            ("/xrpc/A1.b-2.C3", "A1.b-2.C3"),
        ];
        for (url, nsid) in cases {
            assert_eq!(parse_xrpc_path(path(url)), Some(nsid), "{url}");
        }
    }

    #[test]
    fn parse_xrpc_path_invalid() {
        let cases = [
            "/xrpc/a",
            "/xrpc/a/",
            "",
            "/xrpc/",
            "/xrpc/?",
            "/xrpc/?foo=bar",
            "/xrpc",
            "/xrpc//",
            "/xrpc/123/extra",
            "/xrpc/123/extra?foo=bar",
            "/xrpc/com.example.nsid//",
            "/foo/123",
            "/foo/com.example.nsid",
            "xrpc/com.example.nsid",
            "/XRPC/com.example.nsid",
            "/xrpc/.",
            "/xrpc/..",
            "/xrpc/....",
            "/xrpc/.com.example.nsid",
            "/xrpc/com..example.nsid",
            "/xrpc/com.example..nsid",
            "/xrpc/com.example.nsid.",
            "/xrpc/com.example.nsid./",
            "/xrpc/com.example.nsid.?foo=bar",
            "/xrpc/com.example.nsid./?foo=bar",
            "/xrpc/-",
            "/xrpc/com.example.-nsid",
            "/xrpc/com.example-.nsid",
            "/xrpc/com.-example.nsid",
            "/xrpc/com.-example-.nsid",
            "/xrpc/com.example.nsid-",
            "/xrpc/-com.example.nsid",
            "/xrpc/com.example--domain.nsid",
            " /xrpc/com.example.nsid",
            "/xrpc/com.example.nsid#",
            "/xrpc/com.example.nsid!",
            "/xrpc/com.example#?nsid",
            "/xrpc/!com.example.nsid",
            "/xrpc/com.example.nsid ",
            "/xrpc/ com.example.nsid",
            "/xrpc/com. example.nsid",
            "/xrpc/com.example_nsid",
            "/xrpc/com.example.ns%69d",
            "/xrpc/com.example.nsid\u{e9}",
        ];
        for url in cases {
            assert_eq!(parse_xrpc_path(path(url)), None, "{url:?}");
        }
    }
}
