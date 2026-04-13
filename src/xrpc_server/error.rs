use axum::Json;
use axum::response::{IntoResponse, Response};
use http::StatusCode;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum ServerError {
    #[error("auth required")]
    AuthRequired,
    #[error("forbidden")]
    Forbidden,
    #[error("not found")]
    NotFound,
    #[error("method not allowed")]
    MethodNotAllowed,
    #[error("payload too large")]
    TooLarge,
    #[error("rate limited")]
    RateLimited {
        retry_after: Option<std::time::Duration>,
    },
    #[error("internal error: {0}")]
    Internal(String),
}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let (status, error_name) = match &self {
            ServerError::AuthRequired => (StatusCode::UNAUTHORIZED, "AuthRequired"),
            ServerError::Forbidden => (StatusCode::FORBIDDEN, "Forbidden"),
            ServerError::NotFound => (StatusCode::NOT_FOUND, "NotFound"),
            ServerError::MethodNotAllowed => (StatusCode::METHOD_NOT_ALLOWED, "MethodNotAllowed"),
            ServerError::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "TooLarge"),
            ServerError::RateLimited { .. } => (StatusCode::TOO_MANY_REQUESTS, "RateLimited"),
            ServerError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "InternalError"),
        };
        let body = json!({"error": error_name, "message": self.to_string()});
        (status, Json(body)).into_response()
    }
}
