//! Rate limiting, following the reference `xrpc-server`.
//!
//! [`RateLimits`] holds a store, global limits (applied to every request,
//! including unknown methods), and named shared limits that routes opt into.
//! Routes add their own with [`RouteRateLimit`]. Every applicable limit is
//! charged on each request (even when another one rejects it), and the
//! tightest one is reported in `RateLimit-*` headers.
//!
//! Limits run after authentication and input parsing, so key and point
//! functions can use the credentials, parameters and JSON input. The default
//! key is the client IP, available when serving with connect info (as
//! [`Server::serve`](crate::xrpc_server::Server::serve) does); without one,
//! limits whose key cannot be computed are skipped.
//!
//! A store failure fails open for global and shared limits (unless
//! [`RateLimit::fail_closed`]) and closed (500) for route limits.

use std::any::Any;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use http::header::{HeaderName, HeaderValue, RETRY_AFTER};
use http::{HeaderMap, Request};
use serde_json::Value;

use crate::service_auth::BoxFuture;
use crate::xrpc_server::error::ServerError;
use crate::xrpc_server::params::Params;

/// The result of charging a key.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimitStatus {
    /// Points allowed per window.
    pub limit: u64,
    /// Window length.
    pub duration: Duration,
    /// Points left in the current window.
    pub remaining_points: u64,
    /// Time until the window resets.
    pub ms_before_next: u64,
    /// Points used in the current window, including this request.
    pub consumed_points: u64,
    /// Whether this request opened the window.
    pub is_first_in_duration: bool,
    /// Whether this request went over the limit.
    pub exceeded: bool,
}

/// A rate-limit store failure.
#[derive(Debug, Clone, thiserror::Error)]
#[error("rate limit store error: {0}")]
pub struct RateLimitStoreError(pub String);

/// Backing storage for rate-limit counters, e.g. in memory or in Redis.
pub trait RateLimitStore: Send + Sync + 'static {
    /// Charge `points` to `key`, in fixed windows of `duration` allowing
    /// `limit` points each. Points are charged even when over the limit.
    fn consume<'a>(
        &'a self,
        key: &'a str,
        points: u64,
        limit: u64,
        duration: Duration,
    ) -> BoxFuture<'a, Result<RateLimitStatus, RateLimitStoreError>>;

    /// Forget `key`'s counter.
    fn reset<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), RateLimitStoreError>>;
}

/// An in-process [`RateLimitStore`] with fixed windows that start at a key's
/// first request.
#[derive(Debug, Default)]
pub struct MemoryStore {
    windows: Mutex<HashMap<String, Window>>,
}

#[derive(Debug)]
struct Window {
    ends: tokio::time::Instant,
    consumed: u64,
}

/// Sweep expired windows once the map grows past this many keys.
const SWEEP_THRESHOLD: usize = 10_000;

impl MemoryStore {
    /// An empty store.
    pub fn new() -> Self {
        MemoryStore::default()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, Window>> {
        self.windows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl RateLimitStore for MemoryStore {
    fn consume<'a>(
        &'a self,
        key: &'a str,
        points: u64,
        limit: u64,
        duration: Duration,
    ) -> BoxFuture<'a, Result<RateLimitStatus, RateLimitStoreError>> {
        let now = tokio::time::Instant::now();
        let mut windows = self.lock();
        if windows.len() >= SWEEP_THRESHOLD {
            windows.retain(|_, w| w.ends > now);
        }
        let window = windows
            .entry(key.to_owned())
            .and_modify(|w| {
                if w.ends <= now {
                    *w = Window {
                        ends: now + duration,
                        consumed: 0,
                    };
                }
            })
            .or_insert(Window {
                ends: now + duration,
                consumed: 0,
            });
        let is_first_in_duration = window.consumed == 0;
        window.consumed = window.consumed.saturating_add(points);
        let status = RateLimitStatus {
            limit,
            duration,
            remaining_points: limit.saturating_sub(window.consumed),
            ms_before_next: u64::try_from(window.ends.saturating_duration_since(now).as_millis())
                .unwrap_or(u64::MAX),
            consumed_points: window.consumed,
            is_first_in_duration,
            exceeded: window.consumed > limit,
        };
        Box::pin(async move { Ok(status) })
    }

    fn reset<'a>(&'a self, key: &'a str) -> BoxFuture<'a, Result<(), RateLimitStoreError>> {
        self.lock().remove(key);
        Box::pin(async { Ok(()) })
    }
}

/// What key and point functions see.
pub struct RateLimitContext<'a> {
    /// The method NSID.
    pub nsid: &'a str,
    /// The request headers.
    pub headers: &'a HeaderMap,
    /// The client address, when serving with connect info.
    pub ip: Option<IpAddr>,
    /// The query parameters (empty for unknown methods).
    pub params: &'a Params,
    /// A parsed JSON request body, if any.
    pub input: Option<&'a Value>,
    pub(crate) auth: Option<&'a (dyn Any + Send)>,
}

impl RateLimitContext<'_> {
    /// The route's credentials, if they are a `T` (the route verifier's
    /// `Credentials` type).
    pub fn auth<T: 'static>(&self) -> Option<&T> {
        self.auth?.downcast_ref()
    }
}

type KeyFn = Arc<dyn Fn(&RateLimitContext<'_>) -> Option<String> + Send + Sync>;
type PointsFn = Arc<dyn Fn(&RateLimitContext<'_>) -> u64 + Send + Sync>;
type BypassFn = Arc<dyn Fn(&RateLimitContext<'_>) -> bool + Send + Sync>;

/// A named limit: `points` per `duration`, used as a global or shared limit.
#[derive(Clone)]
pub struct RateLimit {
    name: String,
    duration: Duration,
    points: u64,
    calc_key: Option<KeyFn>,
    calc_points: Option<PointsFn>,
    fail_closed: bool,
}

impl RateLimit {
    /// A limit of `points` per `duration` (whole seconds; the reference
    /// truncates to seconds too).
    pub fn new(name: impl Into<String>, duration: Duration, points: u64) -> Self {
        RateLimit {
            name: name.into(),
            duration: Duration::from_secs(duration.as_secs()),
            points,
            calc_key: None,
            calc_points: None,
            fail_closed: false,
        }
    }

    /// How to key requests (default: client IP). `None` skips the limit.
    ///
    /// The client IP is the TCP peer, which is only known when serving with
    /// [`Server::serve`](crate::xrpc_server::Server::serve) or axum's
    /// `into_make_service_with_connect_info::<SocketAddr>()`; without it, an
    /// IP-keyed limit rejects requests with a 500. Behind a reverse proxy
    /// every client shares the proxy's address, so key on the header the
    /// proxy sets instead, e.g.
    /// `.calc_key(|ctx| ctx.headers.get("x-real-ip")?.to_str().ok().map(str::to_owned))`.
    pub fn calc_key(
        mut self,
        f: impl Fn(&RateLimitContext<'_>) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.calc_key = Some(Arc::new(f));
        self
    }

    /// How many points a request costs (default: 1). Zero skips the limit.
    pub fn calc_points(
        mut self,
        f: impl Fn(&RateLimitContext<'_>) -> u64 + Send + Sync + 'static,
    ) -> Self {
        self.calc_points = Some(Arc::new(f));
        self
    }

    /// Reject requests (500) when the store fails, instead of allowing them.
    pub fn fail_closed(mut self) -> Self {
        self.fail_closed = true;
        self
    }
}

/// A route's own limit, or a reference to a shared one.
#[derive(Clone)]
pub struct RouteRateLimit {
    kind: RouteKind,
    calc_key: Option<KeyFn>,
    calc_points: Option<PointsFn>,
}

#[derive(Clone)]
enum RouteKind {
    Shared(String),
    Own { duration: Duration, points: u64 },
}

impl RouteRateLimit {
    /// A limit of `points` per `duration` for this route alone.
    pub fn new(duration: Duration, points: u64) -> Self {
        RouteRateLimit {
            kind: RouteKind::Own {
                duration: Duration::from_secs(duration.as_secs()),
                points,
            },
            calc_key: None,
            calc_points: None,
        }
    }

    /// Use the shared limit `name` (registered with [`RateLimits::shared`]).
    pub fn shared(name: impl Into<String>) -> Self {
        RouteRateLimit {
            kind: RouteKind::Shared(name.into()),
            calc_key: None,
            calc_points: None,
        }
    }

    /// Override how requests are keyed.
    pub fn calc_key(
        mut self,
        f: impl Fn(&RateLimitContext<'_>) -> Option<String> + Send + Sync + 'static,
    ) -> Self {
        self.calc_key = Some(Arc::new(f));
        self
    }

    /// Override how many points a request costs.
    pub fn calc_points(
        mut self,
        f: impl Fn(&RateLimitContext<'_>) -> u64 + Send + Sync + 'static,
    ) -> Self {
        self.calc_points = Some(Arc::new(f));
        self
    }
}

/// Server-wide rate-limit configuration.
#[derive(Clone)]
pub struct RateLimits {
    store: Arc<dyn RateLimitStore>,
    global: Vec<RateLimit>,
    shared: Vec<RateLimit>,
    bypass: Option<BypassFn>,
}

impl RateLimits {
    /// Limits backed by `store`.
    pub fn new(store: impl RateLimitStore) -> Self {
        RateLimits {
            store: Arc::new(store),
            global: Vec::new(),
            shared: Vec::new(),
            bypass: None,
        }
    }

    /// Limits backed by a [`MemoryStore`].
    pub fn memory() -> Self {
        RateLimits::new(MemoryStore::new())
    }

    /// Apply `limit` to every request.
    pub fn global(mut self, limit: RateLimit) -> Self {
        self.global.push(limit);
        self
    }

    /// Register a named limit routes can share with [`RouteRateLimit::shared`].
    pub fn shared(mut self, limit: RateLimit) -> Self {
        self.shared.push(limit);
        self
    }

    /// Skip all limits for requests where `f` is true (e.g. trusted callers).
    pub fn bypass(
        mut self,
        f: impl Fn(&RateLimitContext<'_>) -> bool + Send + Sync + 'static,
    ) -> Self {
        self.bypass = Some(Arc::new(f));
        self
    }

    /// The limiters for a route: its own and shared limits, then the global
    /// ones. Fails if a shared limit is not registered.
    pub(crate) fn for_route(
        &self,
        nsid: &str,
        route: &[RouteRateLimit],
    ) -> Result<Vec<Limiter>, String> {
        let mut limiters = Vec::with_capacity(route.len() + self.global.len());
        for (i, r) in route.iter().enumerate() {
            limiters.push(match &r.kind {
                RouteKind::Shared(name) => {
                    let shared = self
                        .shared
                        .iter()
                        .find(|s| &s.name == name)
                        .ok_or_else(|| format!("shared rate limit {name:?} not defined"))?;
                    Limiter {
                        prefix: format!("rl-{name}"),
                        duration: shared.duration,
                        points: shared.points,
                        calc_key: r.calc_key.clone().or_else(|| shared.calc_key.clone()),
                        calc_points: r.calc_points.clone().or_else(|| shared.calc_points.clone()),
                        fail_closed: shared.fail_closed,
                    }
                }
                RouteKind::Own { duration, points } => Limiter {
                    prefix: format!("{nsid}-{i}"),
                    duration: *duration,
                    points: *points,
                    calc_key: r.calc_key.clone(),
                    calc_points: r.calc_points.clone(),
                    fail_closed: true,
                },
            });
        }
        limiters.extend(self.global_limiters());
        Ok(limiters)
    }

    pub(crate) fn global_limiters(&self) -> impl Iterator<Item = Limiter> + '_ {
        self.global.iter().map(|g| Limiter {
            prefix: format!("rl-{}", g.name),
            duration: g.duration,
            points: g.points,
            calc_key: g.calc_key.clone(),
            calc_points: g.calc_points.clone(),
            fail_closed: g.fail_closed,
        })
    }

    pub(crate) fn store(&self) -> &Arc<dyn RateLimitStore> {
        &self.store
    }

    pub(crate) fn bypassed(&self, ctx: &RateLimitContext<'_>) -> bool {
        self.bypass.as_ref().is_some_and(|f| f(ctx))
    }
}

#[derive(Clone)]
pub(crate) struct Limiter {
    prefix: String,
    duration: Duration,
    points: u64,
    calc_key: Option<KeyFn>,
    calc_points: Option<PointsFn>,
    fail_closed: bool,
}

impl Limiter {
    /// The store key, or `None` if `calc_key` skips this request. A limit
    /// keyed by client IP fails when there is no IP rather than silently not
    /// applying.
    fn key(&self, ctx: &RateLimitContext<'_>) -> Result<Option<String>, ServerError> {
        let key = match (&self.calc_key, ctx.ip) {
            (Some(f), _) => f(ctx),
            (None, Some(ip)) => Some(ip.to_string()),
            (None, None) => {
                return Err(ServerError::internal(format!(
                    "rate limit {:?} is keyed by client IP, but the request has none: \
                     serve with Server::serve or \
                     into_make_service_with_connect_info::<SocketAddr>(), or set calc_key",
                    self.prefix
                )));
            }
        };
        Ok(key.map(|key| format!("{}:{key}", self.prefix)))
    }
}

/// The limiters charged for one request, kept for
/// [`RequestContext::reset_route_rate_limits`](crate::xrpc_server::RequestContext::reset_route_rate_limits).
#[derive(Clone)]
pub(crate) struct RouteLimiter {
    store: Arc<dyn RateLimitStore>,
    keys: Arc<Vec<String>>,
}

impl RouteLimiter {
    pub(crate) async fn reset(&self) {
        for key in self.keys.iter() {
            // Best effort, like a reset racing a store outage in the reference.
            let _ = self.store.reset(key).await;
        }
    }
}

/// The charges for one request, computed from its context.
pub(crate) struct Plan {
    keys: Vec<String>,
    charges: Vec<Charge>,
}

struct Charge {
    key: String,
    points: u64,
    limit: u64,
    duration: Duration,
    fail_closed: bool,
}

/// Compute each limiter's key and cost. Limiters without a key, or costing
/// nothing, are skipped.
pub(crate) fn plan(
    limits: &RateLimits,
    limiters: &[Limiter],
    ctx: &RateLimitContext<'_>,
) -> Result<Plan, ServerError> {
    let mut plan = Plan {
        keys: Vec::new(),
        charges: Vec::new(),
    };
    if limits.bypassed(ctx) {
        return Ok(plan);
    }
    for limiter in limiters {
        let Some(key) = limiter.key(ctx)? else {
            continue;
        };
        let points = limiter.calc_points.as_ref().map_or(1, |f| f(ctx));
        plan.keys.push(key.clone());
        if points >= 1 {
            plan.charges.push(Charge {
                key,
                points,
                limit: limiter.points,
                duration: limiter.duration,
                fail_closed: limiter.fail_closed,
            });
        }
    }
    Ok(plan)
}

/// Charge every limiter in the plan. On success, returns the headers to add
/// to the response and a handle for resets; over a limit, a 429 with the
/// headers.
pub(crate) async fn charge(
    limits: &RateLimits,
    plan: Plan,
) -> Result<(HeaderMap, RouteLimiter), ServerError> {
    let store = limits.store();
    let results = futures::future::join_all(
        plan.charges
            .iter()
            .map(|c| store.consume(&c.key, c.points, c.limit, c.duration)),
    )
    .await;

    let mut tightest: Option<RateLimitStatus> = None;
    let mut exceeded: Option<RateLimitStatus> = None;
    for (charge, result) in plan.charges.iter().zip(results) {
        let status = match result {
            Ok(status) => status,
            Err(e) if charge.fail_closed => return Err(ServerError::internal(e.to_string())),
            Err(_) => continue,
        };
        if status.exceeded && exceeded.is_none() {
            exceeded = Some(status);
        }
        if tightest.is_none_or(|t| status.remaining_points < t.remaining_points) {
            tightest = Some(status);
        }
    }

    if let Some(status) = exceeded {
        let mut err = ServerError::rate_limited(None);
        for (name, value) in status_headers(&status, true) {
            err = err.with_header(name, value);
        }
        return Err(err.with_header(
            RETRY_AFTER,
            HeaderValue::from(status.ms_before_next.div_ceil(1000)),
        ));
    }
    let mut headers = HeaderMap::new();
    if let Some(status) = tightest {
        for (name, value) in status_headers(&status, false) {
            headers.append(name, value);
        }
    }
    let handle = RouteLimiter {
        store: Arc::clone(store),
        keys: Arc::new(plan.keys),
    };
    Ok((headers, handle))
}

const EXPOSE: HeaderName = http::header::ACCESS_CONTROL_EXPOSE_HEADERS;

fn status_headers(status: &RateLimitStatus, exceeded: bool) -> [(HeaderName, HeaderValue); 5] {
    let now_ms = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    let reset_at = now_ms.saturating_add(status.ms_before_next) / 1000;
    let secs = status.duration.as_secs();
    [
        (
            HeaderName::from_static("ratelimit-limit"),
            status.limit.into(),
        ),
        (HeaderName::from_static("ratelimit-reset"), reset_at.into()),
        (
            HeaderName::from_static("ratelimit-remaining"),
            status.remaining_points.into(),
        ),
        (
            HeaderName::from_static("ratelimit-policy"),
            HeaderValue::try_from(format!("{};w={secs}", status.limit))
                .unwrap_or_else(|_| HeaderValue::from_static("")),
        ),
        (
            EXPOSE,
            HeaderValue::from_static(if exceeded {
                "RateLimit-Limit, RateLimit-Reset, RateLimit-Remaining, RateLimit-Policy, Retry-After"
            } else {
                "RateLimit-Limit, RateLimit-Reset, RateLimit-Remaining, RateLimit-Policy"
            }),
        ),
    ]
}

/// The client IP from axum's connect info, if the server was started with it.
pub(crate) fn client_ip<B>(req: &Request<B>) -> Option<IpAddr> {
    req.extensions()
        .get::<axum::extract::ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use http::StatusCode;

    const SECS_10: Duration = Duration::from_secs(10);
    const LIST: &str = "RateLimit-Limit, RateLimit-Reset, RateLimit-Remaining, RateLimit-Policy";

    struct FailingStore;

    impl RateLimitStore for FailingStore {
        fn consume<'a>(
            &'a self,
            _key: &'a str,
            _points: u64,
            _limit: u64,
            _duration: Duration,
        ) -> BoxFuture<'a, Result<RateLimitStatus, RateLimitStoreError>> {
            Box::pin(async { Err(RateLimitStoreError("store down".into())) })
        }

        fn reset<'a>(&'a self, _key: &'a str) -> BoxFuture<'a, Result<(), RateLimitStoreError>> {
            Box::pin(async { Err(RateLimitStoreError("store down".into())) })
        }
    }

    struct Fixture {
        headers: HeaderMap,
        params: Params,
    }

    impl Fixture {
        fn new() -> Self {
            Fixture {
                headers: HeaderMap::new(),
                params: Params::from_query("user=alice&cost=3"),
            }
        }

        fn ctx(&self, ip: Option<&str>) -> RateLimitContext<'_> {
            RateLimitContext {
                nsid: "io.example.test",
                headers: &self.headers,
                ip: ip.map(|s| s.parse().unwrap()),
                params: &self.params,
                input: None,
                auth: None,
            }
        }
    }

    async fn run(
        limits: &RateLimits,
        route: &[RouteRateLimit],
        ctx: &RateLimitContext<'_>,
    ) -> Result<(HeaderMap, RouteLimiter), ServerError> {
        let limiters = limits.for_route(ctx.nsid, route).unwrap();
        charge(limits, plan(limits, &limiters, ctx)?).await
    }

    fn header<'a>(h: &'a HeaderMap, name: &str) -> &'a str {
        h.get(name)
            .unwrap_or_else(|| panic!("missing {name}"))
            .to_str()
            .unwrap()
    }

    fn expose(h: &HeaderMap) -> Vec<&str> {
        h.get_all(EXPOSE)
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect()
    }

    fn now_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    async fn peek(limits: &RateLimits, key: &str) -> u64 {
        limits
            .store()
            .consume(key, 0, u64::MAX, SECS_10)
            .await
            .unwrap()
            .consumed_points
    }

    #[tokio::test(start_paused = true)]
    async fn memory_store_fixed_window() {
        let store = MemoryStore::new();
        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert_eq!(
            s,
            RateLimitStatus {
                limit: 3,
                duration: SECS_10,
                remaining_points: 2,
                ms_before_next: 10_000,
                consumed_points: 1,
                is_first_in_duration: true,
                exceeded: false,
            }
        );

        tokio::time::advance(Duration::from_millis(4_000)).await;
        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert!(!s.is_first_in_duration);
        assert_eq!(
            (s.consumed_points, s.remaining_points, s.ms_before_next),
            (2, 1, 6_000)
        );
        assert!(!s.exceeded);

        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert_eq!((s.consumed_points, s.remaining_points), (3, 0));
        assert!(!s.exceeded);

        let s = store.consume("k", 2, 3, SECS_10).await.unwrap();
        assert_eq!((s.consumed_points, s.remaining_points), (5, 0));
        assert!(s.exceeded);

        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert_eq!(s.consumed_points, 6);
        assert!(s.exceeded);

        let other = store.consume("other", 1, 3, SECS_10).await.unwrap();
        assert!(other.is_first_in_duration);
        assert_eq!(other.consumed_points, 1);

        tokio::time::advance(Duration::from_millis(5_999)).await;
        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert_eq!((s.consumed_points, s.ms_before_next), (7, 1));

        tokio::time::advance(Duration::from_millis(1)).await;
        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert!(s.is_first_in_duration);
        assert!(!s.exceeded);
        assert_eq!(
            (s.consumed_points, s.remaining_points, s.ms_before_next),
            (1, 2, 10_000)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn memory_store_over_limit_on_first_request() {
        let store = MemoryStore::new();
        let s = store.consume("k", 5, 3, SECS_10).await.unwrap();
        assert!(s.is_first_in_duration);
        assert!(s.exceeded);
        assert_eq!((s.consumed_points, s.remaining_points), (5, 0));
    }

    #[tokio::test(start_paused = true)]
    async fn memory_store_reset() {
        let store = MemoryStore::new();
        store.consume("k", 3, 3, SECS_10).await.unwrap();
        store.consume("k2", 1, 3, SECS_10).await.unwrap();
        tokio::time::advance(Duration::from_secs(2)).await;
        store.reset("k").await.unwrap();
        let s = store.consume("k", 1, 3, SECS_10).await.unwrap();
        assert!(s.is_first_in_duration);
        assert_eq!((s.consumed_points, s.ms_before_next), (1, 10_000));
        let s = store.consume("k2", 1, 3, SECS_10).await.unwrap();
        assert_eq!(s.consumed_points, 2);
        store.reset("never-seen").await.unwrap();
    }

    #[test]
    fn durations_truncate_to_seconds() {
        let limits = RateLimits::memory()
            .global(RateLimit::new("a", Duration::from_millis(1_999), 5))
            .shared(RateLimit::new("s", Duration::from_millis(60_500), 7));
        let limiters = limits
            .for_route(
                "io.example.test",
                &[
                    RouteRateLimit::new(Duration::from_millis(300_900), 2),
                    RouteRateLimit::shared("s"),
                ],
            )
            .unwrap();
        let summary: Vec<_> = limiters
            .iter()
            .map(|l| (l.prefix.as_str(), l.duration, l.points))
            .collect();
        assert_eq!(
            summary,
            vec![
                ("io.example.test-0", Duration::from_secs(300), 2),
                ("rl-s", Duration::from_secs(60), 7),
                ("rl-a", Duration::from_secs(1), 5),
            ]
        );
    }

    #[test]
    fn undefined_shared_limit_fails() {
        let limits = RateLimits::memory().shared(RateLimit::new("known", SECS_10, 1));
        let err = limits
            .for_route("io.example.test", &[RouteRateLimit::shared("nope")])
            .err()
            .unwrap();
        assert!(err.contains("\"nope\""), "{err}");
        assert!(err.contains("not defined"), "{err}");
    }

    #[test]
    fn plan_default_key_requires_ip() {
        let f = Fixture::new();
        let limits = RateLimits::memory().global(RateLimit::new("g", SECS_10, 5));
        let limiters = limits.for_route("io.example.test", &[]).unwrap();

        // Regression: this used to skip the limit silently.
        let err = plan(&limits, &limiters, &f.ctx(None)).err().unwrap();
        assert_eq!(err.status_code(), http::StatusCode::INTERNAL_SERVER_ERROR);
        assert!(
            err.message()
                .unwrap()
                .contains("\"rl-g\" is keyed by client IP")
        );

        // A custom key needs no IP, and a bypass skips the check.
        let keyed = RateLimits::memory()
            .global(RateLimit::new("g", SECS_10, 5).calc_key(|_| Some("k".into())));
        let keyed_limiters = keyed.for_route("io.example.test", &[]).unwrap();
        let p = plan(&keyed, &keyed_limiters, &f.ctx(None)).unwrap();
        assert_eq!(p.keys, ["rl-g:k"]);
        let bypassed = limits.clone().bypass(|_| true);
        assert!(plan(&bypassed, &limiters, &f.ctx(None)).is_ok());

        let p = plan(&limits, &limiters, &f.ctx(Some("10.0.0.1"))).unwrap();
        assert_eq!(p.keys, ["rl-g:10.0.0.1"]);
        assert_eq!(p.charges.len(), 1);
        assert_eq!(p.charges[0].points, 1);
        assert_eq!(p.charges[0].limit, 5);
        assert_eq!(p.charges[0].duration, SECS_10);
        assert!(!p.charges[0].fail_closed);
    }

    #[test]
    fn plan_route_keys_and_overrides() {
        let f = Fixture::new();
        let limits = RateLimits::memory()
            .shared(RateLimit::new("s", SECS_10, 5).calc_key(|_| Some("shared-key".into())))
            .global(RateLimit::new("g", SECS_10, 5));
        let route = [
            RouteRateLimit::new(SECS_10, 2)
                .calc_key(|ctx| ctx.params.get("user").map(str::to_owned))
                .calc_points(|ctx| ctx.params.get("cost").unwrap().parse().unwrap()),
            RouteRateLimit::shared("s"),
            RouteRateLimit::shared("s").calc_key(|_| Some("override".into())),
        ];
        let limiters = limits.for_route("io.example.test", &route).unwrap();
        let p = plan(&limits, &limiters, &f.ctx(Some("::1"))).unwrap();
        assert_eq!(
            p.keys,
            [
                "io.example.test-0:alice",
                "rl-s:shared-key",
                "rl-s:override",
                "rl-g:::1"
            ]
        );
        let charges: Vec<_> = p
            .charges
            .iter()
            .map(|c| (c.points, c.fail_closed))
            .collect();
        assert_eq!(charges, [(3, true), (1, false), (1, false), (1, false)]);
    }

    #[test]
    fn plan_skips_none_key_zero_points_and_bypass() {
        let f = Fixture::new();
        let limits = RateLimits::memory()
            .global(RateLimit::new("nokey", SECS_10, 5).calc_key(|_| None))
            .global(RateLimit::new("free", SECS_10, 5).calc_points(|_| 0))
            .global(RateLimit::new("paid", SECS_10, 5));
        let limiters = limits.for_route("io.example.test", &[]).unwrap();
        let p = plan(&limits, &limiters, &f.ctx(Some("10.0.0.1"))).unwrap();
        assert_eq!(p.keys, ["rl-free:10.0.0.1", "rl-paid:10.0.0.1"]);
        let keys: Vec<_> = p.charges.iter().map(|c| c.key.as_str()).collect();
        assert_eq!(keys, ["rl-paid:10.0.0.1"]);

        let limits = limits.bypass(|ctx| ctx.ip.is_some_and(|ip| ip.is_loopback()));
        let p = plan(&limits, &limiters, &f.ctx(Some("127.0.0.1"))).unwrap();
        assert!(p.keys.is_empty() && p.charges.is_empty());
        let p = plan(&limits, &limiters, &f.ctx(Some("10.0.0.1"))).unwrap();
        assert_eq!(p.charges.len(), 1);
    }

    #[tokio::test]
    async fn charge_reports_tightest_status() {
        let f = Fixture::new();
        let limits = RateLimits::memory().global(RateLimit::new("g", Duration::from_secs(60), 100));
        let route = [RouteRateLimit::new(Duration::from_secs(300), 5)];
        let ctx = f.ctx(Some("10.0.0.1"));
        let before = now_secs();
        let (h, _) = run(&limits, &route, &ctx).await.unwrap();
        assert_eq!(header(&h, "ratelimit-limit"), "5");
        assert_eq!(header(&h, "ratelimit-remaining"), "4");
        assert_eq!(header(&h, "ratelimit-policy"), "5;w=300");
        let reset: u64 = header(&h, "ratelimit-reset").parse().unwrap();
        assert!(
            (before + 299..=now_secs() + 300).contains(&reset),
            "{reset}"
        );
        assert_eq!(expose(&h).join(", "), LIST);
        assert!(h.get(RETRY_AFTER).is_none());
        assert_eq!(h.len(), 5);
    }

    #[tokio::test]
    async fn charge_without_applicable_limits_adds_no_headers() {
        let f = Fixture::new();
        let limits =
            RateLimits::memory().global(RateLimit::new("g", SECS_10, 5).calc_key(|_| None));
        let (h, _) = run(&limits, &[], &f.ctx(None)).await.unwrap();
        assert!(h.is_empty());
    }

    #[tokio::test(start_paused = true)]
    async fn charge_exceeded_is_429_with_headers() {
        let f = Fixture::new();
        let limits = RateLimits::memory().global(RateLimit::new("g", Duration::from_secs(60), 100));
        let route = [RouteRateLimit::new(SECS_10, 2)];
        let ctx = f.ctx(Some("10.0.0.1"));
        run(&limits, &route, &ctx).await.unwrap();
        run(&limits, &route, &ctx).await.unwrap();
        tokio::time::advance(Duration::from_millis(1_500)).await;
        let err = run(&limits, &route, &ctx).await.err().unwrap();
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.error_name(), Some("RateLimitExceeded"));
        assert_eq!(err.public_message(), Some("Rate Limit Exceeded"));
        let h = err.headers();
        assert_eq!(header(h, "ratelimit-limit"), "2");
        assert_eq!(header(h, "ratelimit-remaining"), "0");
        assert_eq!(header(h, "ratelimit-policy"), "2;w=10");
        assert!(h.get("ratelimit-reset").is_some());
        assert_eq!(header(h, "retry-after"), "9");
        assert_eq!(h.get_all(RETRY_AFTER).iter().count(), 1);
        assert_eq!(expose(h).join(", "), format!("{LIST}, Retry-After"));

        // Every limit is charged, even the one that did not reject.
        assert_eq!(peek(&limits, "rl-g:10.0.0.1").await, 3);
        assert_eq!(peek(&limits, "io.example.test-0:10.0.0.1").await, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn retry_after_rounds_up() {
        let f = Fixture::new();
        let limits = RateLimits::memory().global(RateLimit::new("g", SECS_10, 1));
        let ctx = f.ctx(Some("10.0.0.1"));
        run(&limits, &[], &ctx).await.unwrap();
        tokio::time::advance(Duration::from_millis(1)).await;
        let err = run(&limits, &[], &ctx).await.err().unwrap();
        assert_eq!(header(err.headers(), "retry-after"), "10");
        tokio::time::advance(Duration::from_millis(8_999)).await;
        let err = run(&limits, &[], &ctx).await.err().unwrap();
        assert_eq!(header(err.headers(), "retry-after"), "1");
        tokio::time::advance(Duration::from_millis(1_000)).await;
        assert!(run(&limits, &[], &ctx).await.is_ok());
    }

    #[tokio::test]
    async fn exceeded_limit_reported_over_tighter_ones() {
        let f = Fixture::new();
        let limits = RateLimits::memory()
            .global(RateLimit::new("tight", SECS_10, 3).calc_points(|_| 3))
            .global(RateLimit::new("big", SECS_10, 1).calc_points(|_| 2));
        let err = run(&limits, &[], &f.ctx(Some("10.0.0.1")))
            .await
            .err()
            .unwrap();
        assert_eq!(header(err.headers(), "ratelimit-limit"), "1");
    }

    #[tokio::test]
    async fn shared_limit_spans_routes() {
        let f = Fixture::new();
        let limits = RateLimits::memory().shared(RateLimit::new("s", SECS_10, 5));
        let one = limits
            .for_route(
                "io.example.one",
                &[RouteRateLimit::shared("s").calc_points(|_| 2)],
            )
            .unwrap();
        let two = limits
            .for_route(
                "io.example.two",
                &[RouteRateLimit::shared("s").calc_points(|_| 2)],
            )
            .unwrap();
        let ctx = f.ctx(Some("10.0.0.1"));
        charge(&limits, plan(&limits, &one, &ctx).unwrap())
            .await
            .unwrap();
        let (h, _) = charge(&limits, plan(&limits, &two, &ctx).unwrap())
            .await
            .unwrap();
        assert_eq!(header(&h, "ratelimit-remaining"), "1");
        assert!(
            charge(&limits, plan(&limits, &one, &ctx).unwrap())
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn route_limiter_reset_clears_keys() {
        let f = Fixture::new();
        let limits = RateLimits::memory();
        let route = [RouteRateLimit::new(SECS_10, 1)];
        let ctx = f.ctx(Some("10.0.0.1"));
        let (_, handle) = run(&limits, &route, &ctx).await.unwrap();
        assert!(run(&limits, &route, &ctx).await.is_err());
        handle.reset().await;
        let (h, _) = run(&limits, &route, &ctx).await.unwrap();
        assert_eq!(header(&h, "ratelimit-remaining"), "0");
    }

    #[tokio::test]
    async fn failing_store_fails_open_for_global_and_shared() {
        let f = Fixture::new();
        let limits = RateLimits::new(FailingStore)
            .global(RateLimit::new("g", SECS_10, 1))
            .shared(RateLimit::new("s", SECS_10, 1));
        let ctx = f.ctx(Some("10.0.0.1"));
        let (h, handle) = run(&limits, &[RouteRateLimit::shared("s")], &ctx)
            .await
            .unwrap();
        assert!(h.is_empty());
        handle.reset().await;
    }

    #[tokio::test]
    async fn failing_store_fails_closed() {
        let f = Fixture::new();
        let ctx = f.ctx(Some("10.0.0.1"));

        let limits = RateLimits::new(FailingStore);
        let err = run(&limits, &[RouteRateLimit::new(SECS_10, 1)], &ctx)
            .await
            .err()
            .unwrap();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.public_message(), Some("Internal Server Error"));

        let limits =
            RateLimits::new(FailingStore).global(RateLimit::new("g", SECS_10, 1).fail_closed());
        let err = run(&limits, &[], &ctx).await.err().unwrap();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);

        let limits =
            RateLimits::new(FailingStore).shared(RateLimit::new("s", SECS_10, 1).fail_closed());
        let err = run(&limits, &[RouteRateLimit::shared("s")], &ctx)
            .await
            .err()
            .unwrap();
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[test]
    fn auth_downcast() {
        let f = Fixture::new();
        let creds: Box<dyn Any + Send> = Box::new(String::from("did:example:alice"));
        let ctx = RateLimitContext {
            auth: Some(creds.as_ref()),
            ..f.ctx(None)
        };
        assert_eq!(
            ctx.auth::<String>().map(String::as_str),
            Some("did:example:alice")
        );
        assert_eq!(ctx.auth::<u32>(), None);
        assert_eq!(f.ctx(None).auth::<String>(), None);
    }

    #[test]
    fn client_ip_from_connect_info() {
        let mut req = Request::new(());
        assert_eq!(client_ip(&req), None);
        let addr: SocketAddr = "192.0.2.7:4321".parse().unwrap();
        req.extensions_mut()
            .insert(axum::extract::ConnectInfo(addr));
        assert_eq!(client_ip(&req), Some("192.0.2.7".parse().unwrap()));
    }
}
