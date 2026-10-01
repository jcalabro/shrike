//! Axum-based XRPC server for implementing AT Protocol services.
//!
//! [`Server`] routes `/xrpc/<nsid>` requests to registered handlers and
//! follows the reference `@atproto/xrpc-server` for request handling, error
//! names and statuses:
//!
//! - Queries are `GET` (and `HEAD`), procedures `POST`, subscriptions
//!   WebSocket upgrades. Unknown methods are 501 `MethodNotImplemented`
//!   (or go to a [`Server::catchall`]); a known method called with the
//!   wrong HTTP method is 400 `Incorrect HTTP method (GET) expected POST`.
//! - Errors are `{"error": ..., "message": ...}` ([`ServerError`]); a 500
//!   never sends its detail.
//! - Query parameters support repeated keys for arrays ([`Params`]).
//! - Request bodies may be gzip, deflate or brotli encoded (stacked too) and
//!   are size-limited after decoding ([`PayloadLimits`]).
//! - With a lexicon [`Catalog`](crate::lexicon::Catalog)
//!   ([`Server::catalog`]), parameters, inputs, outputs and subscription
//!   messages are validated.
//! - Each route can authenticate requests ([`AuthVerifier`], e.g.
//!   [`ServiceAuth`] for inter-service JWTs) and be rate limited
//!   ([`RateLimits`]).
//!
//! Typed handlers take deserialized parameters or a JSON body and return a
//! serializable output; raw handlers take the [`Input`] stream and return any
//! [`Output`], such as a blob or a CAR file. Subscriptions return a stream of
//! [`Frame`]s.
//!
//! ```
//! use serde::{Deserialize, Serialize};
//! use shrike::xrpc_server::{Output, RequestContext, Server, ServerError};
//!
//! #[derive(Deserialize)]
//! struct PingParams;
//!
//! #[derive(Serialize)]
//! struct PingOutput {
//!     message: String,
//! }
//!
//! #[derive(Deserialize)]
//! struct EchoInput {
//!     text: String,
//! }
//!
//! #[derive(Serialize)]
//! struct EchoOutput {
//!     text: String,
//! }
//!
//! let server = Server::new()
//!     .query("com.example.ping",
//!         |_params: PingParams, _ctx: RequestContext| async move {
//!             Ok(PingOutput { message: "pong".into() })
//!         })
//!     .procedure("com.example.echo",
//!         |input: EchoInput, _ctx: RequestContext| async move {
//!             Ok(EchoOutput { text: input.text })
//!         })
//!     .route("com.example.blob")
//!     .query_raw(|_ctx: RequestContext| async move {
//!         Ok::<_, ServerError>(Output::bytes("application/octet-stream", vec![1, 2, 3]))
//!     });
//!
//! let _app = server.into_router();
//! // Serve with axum
//! ```

mod auth;
mod body;
mod context;
mod error;
mod output;
mod params;
mod rate_limit;
mod server;
mod stream;

pub use auth::{AuthVerifier, NoAuth, Optional, ServiceAuth};
pub use axum::body::Bytes;
pub use body::{BodyStream, DECODE_CHUNK, Input, InputBody, PayloadLimits};
pub use context::{AuthContext, RequestContext};
pub use error::{ResponseType, ServerError};
pub use output::{Output, OutputStream};
pub use params::Params;
pub use rate_limit::{
    MemoryStore, RateLimit, RateLimitContext, RateLimitStatus, RateLimitStore, RateLimitStoreError,
    RateLimits, RouteRateLimit,
};
pub use server::{RouteBuilder, Server};
pub use stream::{Frame, FrameError};

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use crate::xrpc_server::*;

    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use http_body_util::BodyExt;
    use tower::ServiceExt;

    #[derive(serde::Deserialize)]
    struct PingParams {
        name: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct PingOutput {
        message: String,
    }

    #[derive(serde::Deserialize)]
    struct EchoInput {
        text: String,
    }

    #[derive(serde::Serialize)]
    struct EchoOutput {
        echoed: String,
    }

    #[tokio::test]
    async fn query_handler_returns_json() {
        let server =
            Server::new().query("com.example.ping", |params: PingParams, _ctx| async move {
                Ok(PingOutput {
                    message: format!("pong {}", params.name.unwrap_or_default()),
                })
            });

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.ping?name=test")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "pong test");
    }

    #[tokio::test]
    async fn procedure_handler_accepts_post() {
        let server = Server::new()
            .procedure("com.example.echo", |input: EchoInput, _ctx| async move {
                Ok(EchoOutput { echoed: input.text })
            });

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.echo")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"text":"hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["echoed"], "hello");
    }

    #[tokio::test]
    async fn error_returns_xrpc_envelope() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.fail",
            |_params, _ctx| async move {
                Err(ServerError::invalid_request("Record not found").with_name("RecordNotFound"))
            },
        );

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.fail")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "RecordNotFound");
        assert_eq!(json["message"], "Record not found");
    }

    #[tokio::test]
    async fn unknown_route_returns_xrpc_envelope() {
        // Unknown NSID must yield the XRPC 501 {error,message} envelope, not
        // an empty 404 body.
        let server = Server::new();
        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.nonexistent")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "MethodNotImplemented");
        assert_eq!(json["message"], "Method Not Implemented");
        assert!(json.get("message").is_some());
    }

    #[tokio::test]
    async fn malformed_body_returns_xrpc_envelope() {
        // A malformed JSON body must produce the XRPC {error,message} envelope,
        // not axum's default plain-text 422.
        let server = Server::new()
            .procedure("com.example.echo", |input: EchoInput, _ctx| async move {
                Ok(EchoOutput { echoed: input.text })
            });
        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.echo")
                    .header("content-type", "application/json")
                    .body(Body::from("not json{"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "InvalidRequest");
        assert!(json.get("message").is_some());
    }

    // --- Server builder: multiple routes ---

    #[tokio::test]
    async fn server_builder_multiple_routes() {
        let server = Server::new()
            .query("com.example.alpha", |_: PingParams, _ctx| async move {
                Ok(PingOutput {
                    message: "alpha".to_owned(),
                })
            })
            .query("com.example.beta", |_: PingParams, _ctx| async move {
                Ok(PingOutput {
                    message: "beta".to_owned(),
                })
            });

        let app = server.into_router();

        let resp_alpha = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.alpha")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_alpha.status(), StatusCode::OK);
        let body = resp_alpha.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "alpha");

        let resp_beta = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.beta")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(resp_beta.status(), StatusCode::OK);
        let body = resp_beta.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "beta");
    }

    // --- Server builder: same nsid different methods (query + procedure) ---

    #[tokio::test]
    async fn server_same_nsid_query_and_procedure() {
        let server = Server::new()
            .query("com.example.op", |_: PingParams, _ctx| async move {
                Ok(PingOutput {
                    message: "from GET".to_owned(),
                })
            })
            .procedure("com.example.op", |input: EchoInput, _ctx| async move {
                Ok(EchoOutput { echoed: input.text })
            });

        let app = server.into_router();

        let get_resp = app
            .clone()
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.op")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(get_resp.status(), StatusCode::OK);
        let body = get_resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "from GET");

        let post_resp = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.op")
                    .header("content-type", "application/json")
                    .body(Body::from(r#"{"text":"posted"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(post_resp.status(), StatusCode::OK);
        let body = post_resp.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["echoed"], "posted");
    }

    // --- Error responses: each ServerError variant ---

    async fn assert_error_response(
        app: axum::Router,
        expected_status: StatusCode,
        expected_error: &str,
        expected_message: &str,
    ) {
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.err")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(response.status(), expected_status);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], expected_error);
        assert_eq!(json["message"], expected_message);
    }

    #[tokio::test]
    async fn error_constructors_map_to_reference_names() {
        let cases: Vec<(ServerError, StatusCode, &str, &str)> = vec![
            (
                ServerError::invalid_request("bad"),
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "bad",
            ),
            (
                ServerError::auth_required(""),
                StatusCode::UNAUTHORIZED,
                "AuthenticationRequired",
                "Authentication Required",
            ),
            (
                ServerError::forbidden("no"),
                StatusCode::FORBIDDEN,
                "Forbidden",
                "no",
            ),
            (
                ServerError::payload_too_large("big"),
                StatusCode::PAYLOAD_TOO_LARGE,
                "PayloadTooLarge",
                "big",
            ),
            (
                ServerError::rate_limited(Some(std::time::Duration::from_secs(10))),
                StatusCode::TOO_MANY_REQUESTS,
                "RateLimitExceeded",
                "Rate Limit Exceeded",
            ),
            // A 500 never leaks its detail.
            (
                ServerError::internal("oops: secret"),
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalServerError",
                "Internal Server Error",
            ),
            (
                ServerError::method_not_implemented(),
                StatusCode::NOT_IMPLEMENTED,
                "MethodNotImplemented",
                "Method Not Implemented",
            ),
        ];
        for (err, status, name, message) in cases {
            let retry = err.headers().get("retry-after").cloned();
            let server = Server::new()
                .query::<std::collections::HashMap<String, String>, (), _, _>(
                    "com.example.err",
                    move |_, _| {
                        let err = err.clone();
                        async move { Err(err) }
                    },
                );
            assert_error_response(server.into_router(), status, name, message).await;
            if status == StatusCode::TOO_MANY_REQUESTS {
                assert_eq!(retry.unwrap(), "10");
            }
        }
    }

    // --- Procedure with complex JSON: nested objects and arrays ---

    #[derive(serde::Deserialize, serde::Serialize)]
    struct ComplexInput {
        name: String,
        tags: Vec<String>,
        meta: std::collections::HashMap<String, serde_json::Value>,
    }

    #[derive(serde::Serialize)]
    struct ComplexOutput {
        name: String,
        tag_count: usize,
        meta_keys: Vec<String>,
    }

    #[tokio::test]
    async fn procedure_with_complex_json() {
        let server = Server::new().procedure(
            "com.example.complex",
            |input: ComplexInput, _ctx| async move {
                let mut meta_keys: Vec<String> = input.meta.keys().cloned().collect();
                meta_keys.sort();
                Ok(ComplexOutput {
                    name: input.name,
                    tag_count: input.tags.len(),
                    meta_keys,
                })
            },
        );

        let body = serde_json::json!({
            "name": "test",
            "tags": ["a", "b", "c"],
            "meta": {
                "region": "us-east",
                "version": 2
            }
        });

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.complex")
                    .header("content-type", "application/json")
                    .body(Body::from(serde_json::to_vec(&body).unwrap()))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let resp_body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&resp_body).unwrap();
        assert_eq!(json["name"], "test");
        assert_eq!(json["tag_count"], 3);
        let keys = json["meta_keys"].as_array().unwrap();
        assert_eq!(keys.len(), 2);
        assert_eq!(keys[0], "region");
        assert_eq!(keys[1], "version");
    }

    // --- Query with multiple params ---

    #[derive(serde::Deserialize)]
    struct MultiQueryParams {
        page: u32,
        limit: u32,
        filter: Option<String>,
    }

    #[derive(serde::Serialize)]
    struct MultiQueryOutput {
        page: u32,
        limit: u32,
        filter: String,
    }

    #[tokio::test]
    async fn query_with_multiple_params() {
        let server = Server::new().query(
            "com.example.list",
            |params: MultiQueryParams, _ctx| async move {
                Ok(MultiQueryOutput {
                    page: params.page,
                    limit: params.limit,
                    filter: params.filter.unwrap_or_default(),
                })
            },
        );

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.list?page=2&limit=50&filter=active")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["page"], 2);
        assert_eq!(json["limit"], 50);
        assert_eq!(json["filter"], "active");
    }

    // --- Empty query params ---

    #[tokio::test]
    async fn query_empty_params() {
        let server =
            Server::new().query("com.example.ping", |params: PingParams, _ctx| async move {
                Ok(PingOutput {
                    message: format!("pong {}", params.name.unwrap_or_else(|| "world".to_owned())),
                })
            });

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/xrpc/com.example.ping")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::OK);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["message"], "pong world");
    }

    // --- Missing content-type on POST ---

    #[tokio::test]
    async fn post_missing_content_type_returns_error() {
        let server = Server::new()
            .procedure("com.example.echo", |input: EchoInput, _ctx| async move {
                Ok(EchoOutput { echoed: input.text })
            });

        let app = server.into_router();
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/xrpc/com.example.echo")
                    // No content-type header
                    .body(Body::from(r#"{"text":"hello"}"#))
                    .unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(
            json["message"],
            "Request encoding (Content-Type) required but not provided"
        );
    }
}
