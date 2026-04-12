mod context;
mod error;
mod server;

pub use context::RequestContext;
pub use error::ServerError;
pub use server::Server;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
            |_params, _ctx| async move { Err(ServerError::NotFound) },
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

        assert_eq!(response.status(), StatusCode::NOT_FOUND);
        let body = response.into_body().collect().await.unwrap().to_bytes();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["error"], "NotFound");
    }

    #[tokio::test]
    async fn unknown_route_returns_404() {
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
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
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
        assert!(json["message"].is_string());
    }

    #[tokio::test]
    async fn error_auth_required_is_401() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::AuthRequired) },
        );
        assert_error_response(
            server.into_router(),
            StatusCode::UNAUTHORIZED,
            "AuthRequired",
        )
        .await;
    }

    #[tokio::test]
    async fn error_forbidden_is_403() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::Forbidden) },
        );
        assert_error_response(server.into_router(), StatusCode::FORBIDDEN, "Forbidden").await;
    }

    #[tokio::test]
    async fn error_not_found_is_404() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::NotFound) },
        );
        assert_error_response(server.into_router(), StatusCode::NOT_FOUND, "NotFound").await;
    }

    #[tokio::test]
    async fn error_method_not_allowed_is_405() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::MethodNotAllowed) },
        );
        assert_error_response(
            server.into_router(),
            StatusCode::METHOD_NOT_ALLOWED,
            "MethodNotAllowed",
        )
        .await;
    }

    #[tokio::test]
    async fn error_too_large_is_413() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::TooLarge) },
        );
        assert_error_response(
            server.into_router(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "TooLarge",
        )
        .await;
    }

    #[tokio::test]
    async fn error_rate_limited_is_429() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async {
                Err(ServerError::RateLimited {
                    retry_after: Some(std::time::Duration::from_secs(10)),
                })
            },
        );
        assert_error_response(
            server.into_router(),
            StatusCode::TOO_MANY_REQUESTS,
            "RateLimited",
        )
        .await;
    }

    #[tokio::test]
    async fn error_internal_is_500() {
        let server = Server::new().query::<std::collections::HashMap<String, String>, (), _, _>(
            "com.example.err",
            |_, _| async { Err(ServerError::Internal("oops".to_owned())) },
        );
        assert_error_response(
            server.into_router(),
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalError",
        )
        .await;
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

        // axum rejects requests with missing content-type for JSON extractor
        assert!(
            response.status().is_client_error(),
            "expected 4xx, got {}",
            response.status()
        );
    }
}
