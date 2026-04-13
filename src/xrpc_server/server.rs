use axum::extract::Query;
use axum::response::IntoResponse;
use axum::{Json, Router};
use http::HeaderMap;
use serde::Serialize;
use serde::de::DeserializeOwned;
use std::future::Future;

use crate::xrpc_server::context::RequestContext;
use crate::xrpc_server::error::ServerError;

/// XRPC HTTP server framework built on axum.
pub struct Server {
    router: Router,
}

impl Server {
    pub fn new() -> Self {
        Server {
            router: Router::new(),
        }
    }

    /// Register a query (GET) handler
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
            axum::routing::get(move |Query(params): Query<P>, headers: HeaderMap| {
                let handler = handler.clone();
                async move {
                    let ctx = RequestContext {
                        auth: None,
                        headers,
                    };
                    match handler(params, ctx).await {
                        Ok(output) => Json(output).into_response(),
                        Err(e) => e.into_response(),
                    }
                }
            }),
        );
        self
    }

    /// Register a procedure (POST) handler
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
            axum::routing::post(move |headers: HeaderMap, Json(input): Json<I>| {
                let handler = handler.clone();
                async move {
                    let ctx = RequestContext {
                        auth: None,
                        headers,
                    };
                    match handler(input, ctx).await {
                        Ok(output) => Json(output).into_response(),
                        Err(e) => e.into_response(),
                    }
                }
            }),
        );
        self
    }

    /// Build into an axum Router for composition
    pub fn into_router(self) -> Router {
        self.router
    }

    /// Serve on a TCP listener
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<(), std::io::Error> {
        axum::serve(listener, self.router).await
    }
}

impl Default for Server {
    fn default() -> Self {
        Self::new()
    }
}
