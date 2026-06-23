use axum::extract::Query;
use axum::extract::rejection::{JsonRejection, QueryRejection};
use axum::response::{IntoResponse, Response};
use axum::{Json, Router};
use http::{HeaderMap, StatusCode};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;
use std::future::Future;

use crate::xrpc_server::context::RequestContext;
use crate::xrpc_server::error::ServerError;

/// Build an XRPC-shaped error response (`{"error","message"}`) for an extractor
/// rejection (malformed params/body), so clients always get the spec envelope
/// instead of axum's default plain-text body.
fn invalid_request(message: String) -> Response {
    (
        StatusCode::BAD_REQUEST,
        Json(json!({"error": "InvalidRequest", "message": message})),
    )
        .into_response()
}

/// Fallback handler for requests to unregistered routes/NSIDs: returns the XRPC
/// `MethodNotImplemented` envelope instead of an empty 404 body.
async fn method_not_implemented() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({
            "error": "MethodNotImplemented",
            "message": "unknown XRPC method"
        })),
    )
        .into_response()
}

/// XRPC HTTP server framework built on axum.
///
/// Register query and procedure handlers using the builder pattern, then call
/// `into_router` to compose with other axum routes or `serve` to start listening.
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
    router: Router,
}

impl Server {
    /// Create an empty server with no registered handlers.
    pub fn new() -> Self {
        Server {
            router: Router::new().fallback(method_not_implemented),
        }
    }

    /// Register a query (GET) handler for the given NSID.
    pub fn query<P, O, F, Fut>(mut self, nsid: &str, handler: F) -> Self
    where
        P: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(P, RequestContext) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send,
    {
        let path = format!("/xrpc/{nsid}");
        self.router = self.router.route(
            &path,
            axum::routing::get(
                move |params: Result<Query<P>, QueryRejection>, headers: HeaderMap| {
                    let handler = handler.clone();
                    async move {
                        let params = match params {
                            Ok(Query(p)) => p,
                            Err(rej) => return invalid_request(rej.body_text()),
                        };
                        let ctx = RequestContext {
                            auth: None,
                            headers,
                        };
                        match handler(params, ctx).await {
                            Ok(output) => Json(output).into_response(),
                            Err(e) => e.into_response(),
                        }
                    }
                },
            ),
        );
        self
    }

    /// Register a procedure (POST) handler for the given NSID.
    pub fn procedure<I, O, F, Fut>(mut self, nsid: &str, handler: F) -> Self
    where
        I: DeserializeOwned + Send + 'static,
        O: Serialize + Send + 'static,
        F: Fn(I, RequestContext) -> Fut + Clone + Send + Sync + 'static,
        Fut: Future<Output = Result<O, ServerError>> + Send,
    {
        let path = format!("/xrpc/{nsid}");
        self.router = self.router.route(
            &path,
            axum::routing::post(
                move |headers: HeaderMap, input: Result<Json<I>, JsonRejection>| {
                    let handler = handler.clone();
                    async move {
                        let input = match input {
                            Ok(Json(i)) => i,
                            Err(rej) => return invalid_request(rej.body_text()),
                        };
                        let ctx = RequestContext {
                            auth: None,
                            headers,
                        };
                        match handler(input, ctx).await {
                            Ok(output) => Json(output).into_response(),
                            Err(e) => e.into_response(),
                        }
                    }
                },
            ),
        );
        self
    }

    /// Build into an axum Router for composition with other routes.
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Serve on a TCP listener.
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), std::io::Error> {
        axum::serve(listener, self.router).await
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}
