use axum::response::{IntoResponse, Response};
use http::header::{HeaderName, HeaderValue, RETRY_AFTER};
use http::{HeaderMap, StatusCode};

/// The standard XRPC error types, with their HTTP statuses, as in the
/// reference `@atproto/xrpc` `ResponseType`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ResponseType {
    InvalidRequest,
    AuthenticationRequired,
    Forbidden,
    XrpcNotSupported,
    NotAcceptable,
    PayloadTooLarge,
    UnsupportedMediaType,
    RateLimitExceeded,
    InternalServerError,
    MethodNotImplemented,
    UpstreamFailure,
    NotEnoughResources,
    UpstreamTimeout,
}

impl ResponseType {
    const ALL: [ResponseType; 13] = [
        ResponseType::InvalidRequest,
        ResponseType::AuthenticationRequired,
        ResponseType::Forbidden,
        ResponseType::XrpcNotSupported,
        ResponseType::NotAcceptable,
        ResponseType::PayloadTooLarge,
        ResponseType::UnsupportedMediaType,
        ResponseType::RateLimitExceeded,
        ResponseType::InternalServerError,
        ResponseType::MethodNotImplemented,
        ResponseType::UpstreamFailure,
        ResponseType::NotEnoughResources,
        ResponseType::UpstreamTimeout,
    ];

    /// The HTTP status code.
    pub fn status(self) -> StatusCode {
        match self {
            ResponseType::InvalidRequest => StatusCode::BAD_REQUEST,
            ResponseType::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            ResponseType::Forbidden => StatusCode::FORBIDDEN,
            ResponseType::XrpcNotSupported => StatusCode::NOT_FOUND,
            ResponseType::NotAcceptable => StatusCode::NOT_ACCEPTABLE,
            ResponseType::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            ResponseType::UnsupportedMediaType => StatusCode::UNSUPPORTED_MEDIA_TYPE,
            ResponseType::RateLimitExceeded => StatusCode::TOO_MANY_REQUESTS,
            ResponseType::InternalServerError => StatusCode::INTERNAL_SERVER_ERROR,
            ResponseType::MethodNotImplemented => StatusCode::NOT_IMPLEMENTED,
            ResponseType::UpstreamFailure => StatusCode::BAD_GATEWAY,
            ResponseType::NotEnoughResources => StatusCode::SERVICE_UNAVAILABLE,
            ResponseType::UpstreamTimeout => StatusCode::GATEWAY_TIMEOUT,
        }
    }

    /// The XRPC `error` name, e.g. `InvalidRequest`.
    pub fn name(self) -> &'static str {
        match self {
            ResponseType::InvalidRequest => "InvalidRequest",
            ResponseType::AuthenticationRequired => "AuthenticationRequired",
            ResponseType::Forbidden => "Forbidden",
            ResponseType::XrpcNotSupported => "XRPCNotSupported",
            ResponseType::NotAcceptable => "NotAcceptable",
            ResponseType::PayloadTooLarge => "PayloadTooLarge",
            ResponseType::UnsupportedMediaType => "UnsupportedMediaType",
            ResponseType::RateLimitExceeded => "RateLimitExceeded",
            ResponseType::InternalServerError => "InternalServerError",
            ResponseType::MethodNotImplemented => "MethodNotImplemented",
            ResponseType::UpstreamFailure => "UpstreamFailure",
            ResponseType::NotEnoughResources => "NotEnoughResources",
            ResponseType::UpstreamTimeout => "UpstreamTimeout",
        }
    }

    /// The default `message`, e.g. `Invalid Request`.
    pub fn default_message(self) -> &'static str {
        match self {
            ResponseType::InvalidRequest => "Invalid Request",
            ResponseType::AuthenticationRequired => "Authentication Required",
            ResponseType::Forbidden => "Forbidden",
            ResponseType::XrpcNotSupported => "XRPC Not Supported",
            ResponseType::NotAcceptable => "Not Acceptable",
            ResponseType::PayloadTooLarge => "Payload Too Large",
            ResponseType::UnsupportedMediaType => "Unsupported Media Type",
            ResponseType::RateLimitExceeded => "Rate Limit Exceeded",
            ResponseType::InternalServerError => "Internal Server Error",
            ResponseType::MethodNotImplemented => "Method Not Implemented",
            ResponseType::UpstreamFailure => "Upstream Failure",
            ResponseType::NotEnoughResources => "Not Enough Resources",
            ResponseType::UpstreamTimeout => "Upstream Timeout",
        }
    }

    /// The type for an HTTP status, if it is one of the standard ones.
    pub fn from_status(status: StatusCode) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.status() == status)
    }
}

/// An XRPC error response: `{"error": ..., "message": ...}` with an HTTP
/// status.
///
/// The `error` name defaults to the [`ResponseType`] name for the status and
/// can be replaced with a method-specific name (e.g. `RecordNotFound`). A 500
/// never sends its message: the client sees `Internal Server Error`, while
/// [`ServerError::message`] keeps the detail for logging. Statuses outside
/// 400–599 are sent as 500.
#[derive(Debug, Clone)]
pub struct ServerError {
    status: StatusCode,
    error: Option<String>,
    message: Option<String>,
    // Boxed to keep `Result<_, ServerError>` small.
    headers: Box<HeaderMap>,
}

impl ServerError {
    /// An error with an explicit status, name and message.
    pub fn new(status: StatusCode, error: impl Into<String>, message: impl Into<String>) -> Self {
        ServerError::from_status(status)
            .with_name(error)
            .with_message(message)
    }

    /// An error with the given status and its default name and message.
    pub fn from_status(status: StatusCode) -> Self {
        let status = if status.is_client_error() || status.is_server_error() {
            status
        } else {
            StatusCode::INTERNAL_SERVER_ERROR
        };
        ServerError {
            status,
            error: None,
            message: None,
            headers: Box::default(),
        }
    }

    /// An error of a standard type with a message.
    pub fn from_type(kind: ResponseType, message: impl Into<String>) -> Self {
        ServerError::from_status(kind.status()).with_message(message)
    }

    /// 400 `InvalidRequest`.
    pub fn invalid_request(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::InvalidRequest, message)
    }

    /// 401 `AuthenticationRequired`.
    pub fn auth_required(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::AuthenticationRequired, message)
    }

    /// 403 `Forbidden`.
    pub fn forbidden(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::Forbidden, message)
    }

    /// 413 `PayloadTooLarge`.
    pub fn payload_too_large(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::PayloadTooLarge, message)
    }

    /// 415 `UnsupportedMediaType`.
    pub fn unsupported_media_type(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::UnsupportedMediaType, message)
    }

    /// 429 `RateLimitExceeded`, with `Retry-After` if known.
    pub fn rate_limited(retry_after: Option<std::time::Duration>) -> Self {
        let err = ServerError::from_status(StatusCode::TOO_MANY_REQUESTS);
        match retry_after {
            Some(d) => err.with_header(RETRY_AFTER, HeaderValue::from(d.as_secs())),
            None => err,
        }
    }

    /// 500 `InternalServerError`. `detail` is kept for logging but never sent.
    pub fn internal(detail: impl Into<String>) -> Self {
        Self::from_type(ResponseType::InternalServerError, detail)
    }

    /// 501 `MethodNotImplemented`.
    pub fn method_not_implemented() -> Self {
        ServerError::from_status(StatusCode::NOT_IMPLEMENTED)
    }

    /// 502 `UpstreamFailure`.
    pub fn upstream_failure(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::UpstreamFailure, message)
    }

    /// 503 `NotEnoughResources`.
    pub fn not_enough_resources(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::NotEnoughResources, message)
    }

    /// 504 `UpstreamTimeout`.
    pub fn upstream_timeout(message: impl Into<String>) -> Self {
        Self::from_type(ResponseType::UpstreamTimeout, message)
    }

    /// Replace the `error` name.
    pub fn with_name(mut self, error: impl Into<String>) -> Self {
        self.error = Some(error.into());
        self
    }

    /// Replace the message. An empty message means the default one.
    pub fn with_message(mut self, message: impl Into<String>) -> Self {
        let message = message.into();
        self.message = (!message.is_empty()).then_some(message);
        self
    }

    /// Add a response header.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// The HTTP status.
    pub fn status_code(&self) -> StatusCode {
        self.status
    }

    /// The `error` name sent to the client, if any. Non-standard statuses
    /// have none unless one was set.
    pub fn error_name(&self) -> Option<&str> {
        self.error
            .as_deref()
            .or_else(|| ResponseType::from_status(self.status).map(ResponseType::name))
    }

    /// The message as given, including a 500's hidden detail.
    pub fn message(&self) -> Option<&str> {
        self.message.as_deref()
    }

    /// The `message` sent to the client.
    pub fn public_message(&self) -> Option<&str> {
        let default = ResponseType::from_status(self.status).map(ResponseType::default_message);
        if self.status == StatusCode::INTERNAL_SERVER_ERROR {
            default
        } else {
            self.message.as_deref().or(default)
        }
    }

    /// Extra response headers.
    pub fn headers(&self) -> &HeaderMap {
        &self.headers
    }

    /// The JSON body sent to the client.
    pub fn body(&self) -> serde_json::Value {
        let mut body = serde_json::Map::new();
        if let Some(error) = self.error_name() {
            body.insert("error".into(), error.into());
        }
        if let Some(message) = self.public_message() {
            body.insert("message".into(), message.into());
        }
        serde_json::Value::Object(body)
    }
}

impl std::fmt::Display for ServerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.status.as_u16())?;
        if let Some(error) = self.error_name() {
            write!(f, " {error}")?;
        }
        if let Some(message) = self.message.as_deref().or(self.public_message()) {
            write!(f, ": {message}")?;
        }
        Ok(())
    }
}

impl std::error::Error for ServerError {}

impl IntoResponse for ServerError {
    fn into_response(self) -> Response {
        let body = serde_json::to_vec(&self.body()).unwrap_or_default();
        let mut response = (
            self.status,
            [(http::header::CONTENT_TYPE, super::output::JSON_CONTENT_TYPE)],
            body,
        )
            .into_response();
        response.headers_mut().extend(*self.headers);
        response
    }
}

impl From<crate::service_auth::ServiceAuthError> for ServerError {
    fn from(err: crate::service_auth::ServiceAuthError) -> Self {
        match err {
            crate::service_auth::ServiceAuthError::Signing(detail) => ServerError::internal(detail),
            err => ServerError::auth_required(err.to_string()).with_name(err.error_name()),
        }
    }
}

/// A request beyond the token's OAuth scope is a 403 `ScopeMissingError`, as
/// in the reference PDS.
#[cfg(feature = "oauth")]
impl From<crate::oauth::scopes::ScopeMissingError> for ServerError {
    fn from(err: crate::oauth::scopes::ScopeMissingError) -> Self {
        ServerError::new(StatusCode::FORBIDDEN, "ScopeMissingError", err.to_string())
    }
}

/// Upstream XRPC errors pass through with their status, name and message,
/// except that an upstream 500 becomes a 502 (keeping its name and message).
/// As in the reference `lex-client`, an unusable response is a 502
/// `InvalidResponse`, and a failed request is a 502 `InternalServerError`
/// that does not expose the cause.
#[cfg(feature = "xrpc")]
impl From<crate::xrpc::Error> for ServerError {
    fn from(err: crate::xrpc::Error) -> Self {
        use crate::xrpc::Error;
        let invalid =
            |message: String| ServerError::new(StatusCode::BAD_GATEWAY, "InvalidResponse", message);
        match err {
            Error::Xrpc {
                status,
                error,
                message,
            } => match StatusCode::from_u16(status) {
                Ok(StatusCode::INTERNAL_SERVER_ERROR) => {
                    ServerError::new(StatusCode::BAD_GATEWAY, error, message)
                }
                Ok(s) if s.is_client_error() || s.is_server_error() => {
                    ServerError::new(s, error, message)
                }
                _ => invalid(format!("Unexpected upstream status {status}")),
            },
            Error::RateLimited { retry_after } => ServerError::rate_limited(retry_after),
            Error::Json(e) => invalid(format!("Invalid response payload: {e}")),
            err @ Error::ResponseTooLarge { .. } => invalid(err.to_string()),
            Error::Network(_) => ServerError::new(
                StatusCode::BAD_GATEWAY,
                "InternalServerError",
                "Failed to perform upstream request",
            ),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn response_type_table() {
        let table = [
            (
                ResponseType::InvalidRequest,
                400,
                "InvalidRequest",
                "Invalid Request",
            ),
            (
                ResponseType::AuthenticationRequired,
                401,
                "AuthenticationRequired",
                "Authentication Required",
            ),
            (ResponseType::Forbidden, 403, "Forbidden", "Forbidden"),
            (
                ResponseType::XrpcNotSupported,
                404,
                "XRPCNotSupported",
                "XRPC Not Supported",
            ),
            (
                ResponseType::NotAcceptable,
                406,
                "NotAcceptable",
                "Not Acceptable",
            ),
            (
                ResponseType::PayloadTooLarge,
                413,
                "PayloadTooLarge",
                "Payload Too Large",
            ),
            (
                ResponseType::UnsupportedMediaType,
                415,
                "UnsupportedMediaType",
                "Unsupported Media Type",
            ),
            (
                ResponseType::RateLimitExceeded,
                429,
                "RateLimitExceeded",
                "Rate Limit Exceeded",
            ),
            (
                ResponseType::InternalServerError,
                500,
                "InternalServerError",
                "Internal Server Error",
            ),
            (
                ResponseType::MethodNotImplemented,
                501,
                "MethodNotImplemented",
                "Method Not Implemented",
            ),
            (
                ResponseType::UpstreamFailure,
                502,
                "UpstreamFailure",
                "Upstream Failure",
            ),
            (
                ResponseType::NotEnoughResources,
                503,
                "NotEnoughResources",
                "Not Enough Resources",
            ),
            (
                ResponseType::UpstreamTimeout,
                504,
                "UpstreamTimeout",
                "Upstream Timeout",
            ),
        ];
        assert_eq!(table.len(), ResponseType::ALL.len());
        for (kind, status, name, message) in table {
            let status = StatusCode::from_u16(status).unwrap();
            assert_eq!(kind.status(), status);
            assert_eq!(kind.name(), name);
            assert_eq!(kind.default_message(), message);
            assert_eq!(ResponseType::from_status(status), Some(kind));
            assert_eq!(
                ServerError::from_status(status).body(),
                json!({"error": name, "message": message})
            );
        }
        for status in [200, 302, 402, 405, 418, 422, 505] {
            assert_eq!(
                ResponseType::from_status(StatusCode::from_u16(status).unwrap()),
                None
            );
        }
    }

    #[test]
    fn body_uses_message_and_custom_name() {
        let err = ServerError::invalid_request("bad cursor");
        assert_eq!(
            err.body(),
            json!({"error": "InvalidRequest", "message": "bad cursor"})
        );

        let err = ServerError::invalid_request("no such record").with_name("RecordNotFound");
        assert_eq!(
            err.body(),
            json!({"error": "RecordNotFound", "message": "no such record"})
        );
        assert_eq!(err.error_name(), Some("RecordNotFound"));

        let err = ServerError::new(StatusCode::FORBIDDEN, "AccountTakedown", "taken down");
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(
            err.body(),
            json!({"error": "AccountTakedown", "message": "taken down"})
        );
    }

    #[test]
    fn internal_error_hides_message() {
        let err = ServerError::internal("db password is hunter2");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.message(), Some("db password is hunter2"));
        assert_eq!(err.public_message(), Some("Internal Server Error"));
        assert_eq!(
            err.body(),
            json!({"error": "InternalServerError", "message": "Internal Server Error"})
        );

        let err = ServerError::internal("detail").with_name("CustomFailure");
        assert_eq!(
            err.body(),
            json!({"error": "CustomFailure", "message": "Internal Server Error"})
        );
    }

    #[test]
    fn other_5xx_keep_message() {
        assert_eq!(
            ServerError::upstream_failure("pds down").body(),
            json!({"error": "UpstreamFailure", "message": "pds down"})
        );
        assert_eq!(
            ServerError::not_enough_resources("busy").body(),
            json!({"error": "NotEnoughResources", "message": "busy"})
        );
        assert_eq!(
            ServerError::upstream_timeout("slow").body(),
            json!({"error": "UpstreamTimeout", "message": "slow"})
        );
        assert_eq!(
            ServerError::method_not_implemented().body(),
            json!({"error": "MethodNotImplemented", "message": "Method Not Implemented"})
        );
    }

    #[test]
    fn empty_message_means_default() {
        assert_eq!(
            ServerError::invalid_request("").body(),
            json!({"error": "InvalidRequest", "message": "Invalid Request"})
        );
        assert_eq!(ServerError::forbidden("").message(), None);
        assert_eq!(
            ServerError::auth_required("x").with_message("").body(),
            json!({"error": "AuthenticationRequired", "message": "Authentication Required"})
        );
    }

    #[test]
    fn constructors_map_to_types() {
        let cases = [
            (ServerError::invalid_request("m"), 400, "InvalidRequest"),
            (
                ServerError::auth_required("m"),
                401,
                "AuthenticationRequired",
            ),
            (ServerError::forbidden("m"), 403, "Forbidden"),
            (ServerError::payload_too_large("m"), 413, "PayloadTooLarge"),
            (
                ServerError::unsupported_media_type("m"),
                415,
                "UnsupportedMediaType",
            ),
            (ServerError::rate_limited(None), 429, "RateLimitExceeded"),
            (ServerError::internal("m"), 500, "InternalServerError"),
            (
                ServerError::method_not_implemented(),
                501,
                "MethodNotImplemented",
            ),
            (ServerError::upstream_failure("m"), 502, "UpstreamFailure"),
            (
                ServerError::not_enough_resources("m"),
                503,
                "NotEnoughResources",
            ),
            (ServerError::upstream_timeout("m"), 504, "UpstreamTimeout"),
            (
                ServerError::from_type(ResponseType::NotAcceptable, "m"),
                406,
                "NotAcceptable",
            ),
        ];
        for (err, status, name) in cases {
            assert_eq!(err.status_code().as_u16(), status, "{name}");
            assert_eq!(err.error_name(), Some(name));
        }
    }

    #[test]
    fn non_standard_status_has_no_defaults() {
        let err = ServerError::from_status(StatusCode::IM_A_TEAPOT);
        assert_eq!(err.status_code(), StatusCode::IM_A_TEAPOT);
        assert_eq!(err.error_name(), None);
        assert_eq!(err.public_message(), None);
        assert_eq!(err.body(), json!({}));

        let err = ServerError::from_status(StatusCode::IM_A_TEAPOT).with_message("short and stout");
        assert_eq!(err.body(), json!({"message": "short and stout"}));

        let err = ServerError::new(StatusCode::IM_A_TEAPOT, "Teapot", "");
        assert_eq!(err.body(), json!({"error": "Teapot"}));
    }

    #[test]
    fn out_of_range_status_is_500() {
        for status in [100, 200, 204, 301, 304] {
            let err = ServerError::from_status(StatusCode::from_u16(status).unwrap());
            assert_eq!(
                err.status_code(),
                StatusCode::INTERNAL_SERVER_ERROR,
                "{status}"
            );
        }
        let err = ServerError::new(StatusCode::OK, "Weird", "detail");
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(err.error_name(), Some("Weird"));
    }

    #[test]
    fn display() {
        assert_eq!(
            ServerError::invalid_request("bad cursor").to_string(),
            "400 InvalidRequest: bad cursor"
        );
        assert_eq!(
            ServerError::internal("secret").to_string(),
            "500 InternalServerError: secret"
        );
        assert_eq!(
            ServerError::forbidden("").to_string(),
            "403 Forbidden: Forbidden"
        );
        assert_eq!(
            ServerError::from_status(StatusCode::IM_A_TEAPOT).to_string(),
            "418"
        );
    }

    #[tokio::test]
    async fn into_response() {
        let err = ServerError::invalid_request("bad")
            .with_name("BadThing")
            .with_header(
                HeaderName::from_static("x-extra"),
                HeaderValue::from_static("1"),
            )
            .with_header(
                HeaderName::from_static("x-extra"),
                HeaderValue::from_static("2"),
            );
        let res = err.into_response();
        assert_eq!(res.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            res.headers()[http::header::CONTENT_TYPE],
            "application/json; charset=utf-8"
        );
        let extra: Vec<_> = res.headers().get_all("x-extra").iter().collect();
        assert_eq!(extra, ["1", "2"]);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        let body: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(body, json!({"error": "BadThing", "message": "bad"}));
    }

    #[tokio::test]
    async fn into_response_internal_hides_detail() {
        let res = ServerError::internal("secret detail").into_response();
        assert_eq!(res.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let body = axum::body::to_bytes(res.into_body(), usize::MAX)
            .await
            .unwrap();
        assert!(!String::from_utf8_lossy(&body).contains("secret"));
    }

    #[test]
    fn rate_limited_retry_after() {
        let err = ServerError::rate_limited(Some(std::time::Duration::from_secs(30)));
        assert_eq!(err.headers()[RETRY_AFTER], "30");
        assert_eq!(
            err.body(),
            json!({"error": "RateLimitExceeded", "message": "Rate Limit Exceeded"})
        );
        assert!(
            ServerError::rate_limited(None)
                .headers()
                .get(RETRY_AFTER)
                .is_none()
        );
    }

    #[test]
    fn from_service_auth_error() {
        use crate::service_auth::ServiceAuthError;

        let err = ServerError::from(ServiceAuthError::BadJwt);
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            err.body(),
            json!({"error": "BadJwt", "message": "poorly formatted jwt"})
        );

        let err = ServerError::from(ServiceAuthError::JwtExpired);
        assert_eq!(
            err.body(),
            json!({"error": "JwtExpired", "message": "jwt expired"})
        );

        let err = ServerError::from(ServiceAuthError::BadSignature);
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(err.error_name(), Some("BadJwtSignature"));

        let err = ServerError::from(ServiceAuthError::key_resolution("UntrustedIss", "nope"));
        assert_eq!(err.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            err.body(),
            json!({"error": "UntrustedIss", "message": "nope"})
        );

        let err = ServerError::from(ServiceAuthError::Signing("key gone".into()));
        assert_eq!(err.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
        assert_eq!(
            err.body(),
            json!({"error": "InternalServerError", "message": "Internal Server Error"})
        );
    }

    #[cfg(feature = "xrpc")]
    #[test]
    fn from_xrpc_error() {
        use crate::xrpc::Error;

        let xrpc = |status: u16| Error::Xrpc {
            status,
            error: "RecordNotFound".into(),
            message: "not here".into(),
        };

        let err = ServerError::from(xrpc(400));
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(
            err.body(),
            json!({"error": "RecordNotFound", "message": "not here"})
        );

        let err = ServerError::from(xrpc(404));
        assert_eq!(err.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(err.error_name(), Some("RecordNotFound"));

        let err = ServerError::from(Error::Xrpc {
            status: 500,
            error: "InternalServerError".into(),
            message: "upstream broke".into(),
        });
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            err.body(),
            json!({"error": "InternalServerError", "message": "upstream broke"})
        );

        let err = ServerError::from(Error::Xrpc {
            status: 302,
            error: "Found".into(),
            message: "elsewhere".into(),
        });
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(err.error_name(), Some("InvalidResponse"));
        assert_eq!(err.message(), Some("Unexpected upstream status 302"));

        let err = ServerError::from(Error::RateLimited {
            retry_after: Some(std::time::Duration::from_secs(7)),
        });
        assert_eq!(err.status_code(), StatusCode::TOO_MANY_REQUESTS);
        assert_eq!(err.headers()[RETRY_AFTER], "7");

        let json_err = serde_json::from_str::<serde_json::Value>("{").unwrap_err();
        let err = ServerError::from(Error::Json(json_err));
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(err.error_name(), Some("InvalidResponse"));
        assert!(
            err.message()
                .unwrap()
                .starts_with("Invalid response payload: ")
        );

        let err = ServerError::from(Error::ResponseTooLarge { size: 10, limit: 5 });
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(err.error_name(), Some("InvalidResponse"));
    }

    #[cfg(feature = "xrpc")]
    #[tokio::test]
    async fn from_xrpc_network_error_hides_the_cause() {
        // Nothing listens on port 1.
        let network = reqwest::Client::new()
            .get("http://127.0.0.1:1/secret-internal-path")
            .send()
            .await
            .unwrap_err();
        let err = ServerError::from(crate::xrpc::Error::Network(network));
        assert_eq!(err.status_code(), StatusCode::BAD_GATEWAY);
        assert_eq!(
            err.body(),
            json!({"error": "InternalServerError", "message": "Failed to perform upstream request"})
        );
    }

    #[cfg(feature = "xrpc")]
    #[test]
    fn from_xrpc_error_non_500_upstream_status_passes_through() {
        let err = ServerError::from(crate::xrpc::Error::Xrpc {
            status: 503,
            error: "NotEnoughResources".into(),
            message: "busy".into(),
        });
        assert_eq!(err.status_code(), StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(
            err.body(),
            json!({"error": "NotEnoughResources", "message": "busy"})
        );
    }

    #[cfg(feature = "oauth")]
    #[test]
    fn scope_missing_is_forbidden() {
        use crate::oauth::scopes::{RepoAction, ScopePermissions};
        let missing = ScopePermissions::new("atproto")
            .assert_repo("app.bsky.feed.post", RepoAction::Create)
            .unwrap_err();
        let err = ServerError::from(missing);
        assert_eq!(err.status_code(), StatusCode::FORBIDDEN);
        assert_eq!(
            err.body(),
            json!({
                "error": "ScopeMissingError",
                "message": "Missing required scope \"repo:app.bsky.feed.post?action=create\"",
            })
        );
    }
}
