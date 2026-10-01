use std::pin::Pin;

use axum::body::{Body, Bytes};
use axum::response::{IntoResponse, Response};
use futures::{Stream, StreamExt};
use http::header::{CONTENT_TYPE, HeaderName, HeaderValue};
use http::{HeaderMap, StatusCode};
use serde::Serialize;
use serde_json::Value;

use crate::xrpc_server::error::ServerError;

pub(crate) const JSON_CONTENT_TYPE: &str = "application/json; charset=utf-8";

/// A streamed response body.
pub type OutputStream = Pin<Box<dyn Stream<Item = Result<Bytes, std::io::Error>> + Send>>;

/// A handler's successful response.
///
/// JSON bodies are sent as `application/json; charset=utf-8` and text bodies
/// with `; charset=utf-8` appended to their encoding; bytes and streams are
/// sent with their encoding as the `Content-Type`. Headers are applied first,
/// so the encoding always wins over a `content-type` header.
pub struct Output {
    pub(crate) body: OutputBody,
    pub(crate) headers: HeaderMap,
}

pub(crate) enum OutputBody {
    Empty,
    Json(Value),
    Text {
        encoding: String,
        text: String,
    },
    Bytes {
        encoding: String,
        bytes: Bytes,
    },
    Stream {
        encoding: String,
        stream: OutputStream,
    },
}

impl std::fmt::Debug for Output {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut s = f.debug_struct("Output");
        s.field("encoding", &self.encoding());
        if let OutputBody::Json(v) = &self.body {
            s.field("json", v);
        }
        s.field("headers", &self.headers).finish_non_exhaustive()
    }
}

impl Output {
    /// A 200 with no body.
    pub fn empty() -> Self {
        Output::from_body(OutputBody::Empty)
    }

    /// A JSON body. Fails (500) if `value` cannot be serialized.
    pub fn json<T: Serialize + ?Sized>(value: &T) -> Result<Self, ServerError> {
        serde_json::to_value(value)
            .map(Output::json_value)
            .map_err(|e| ServerError::internal(format!("failed to serialize output: {e}")))
    }

    /// A JSON body from a value.
    pub fn json_value(value: Value) -> Self {
        Output::from_body(OutputBody::Json(value))
    }

    /// A text body, e.g. `text/plain`.
    pub fn text(encoding: impl Into<String>, text: impl Into<String>) -> Self {
        Output::from_body(OutputBody::Text {
            encoding: encoding.into(),
            text: text.into(),
        })
    }

    /// A binary body, e.g. a blob or a CAR file.
    pub fn bytes(encoding: impl Into<String>, bytes: impl Into<Bytes>) -> Self {
        Output::from_body(OutputBody::Bytes {
            encoding: encoding.into(),
            bytes: bytes.into(),
        })
    }

    /// A streamed binary body, sent chunked. A stream error after the
    /// response has started aborts the connection.
    pub fn stream<S>(encoding: impl Into<String>, stream: S) -> Self
    where
        S: Stream<Item = Result<Bytes, std::io::Error>> + Send + 'static,
    {
        Output::from_body(OutputBody::Stream {
            encoding: encoding.into(),
            stream: stream.boxed(),
        })
    }

    /// Add a response header.
    pub fn with_header(mut self, name: HeaderName, value: HeaderValue) -> Self {
        self.headers.append(name, value);
        self
    }

    /// The response media type, if there is a body.
    pub fn encoding(&self) -> Option<&str> {
        match &self.body {
            OutputBody::Empty => None,
            OutputBody::Json(_) => Some("application/json"),
            OutputBody::Text { encoding, .. }
            | OutputBody::Bytes { encoding, .. }
            | OutputBody::Stream { encoding, .. } => Some(encoding),
        }
    }

    /// The JSON body, if this is one.
    pub fn json_body(&self) -> Option<&Value> {
        match &self.body {
            OutputBody::Json(v) => Some(v),
            _ => None,
        }
    }

    fn from_body(body: OutputBody) -> Self {
        Output {
            body,
            headers: HeaderMap::new(),
        }
    }

    /// The JSON output of a typed handler: `null` (e.g. from `()`) is an
    /// empty response.
    pub(crate) fn from_serialize<T: Serialize>(value: &T) -> Result<Self, ServerError> {
        match Output::json(value)? {
            Output {
                body: OutputBody::Json(Value::Null),
                ..
            } => Ok(Output::empty()),
            output => Ok(output),
        }
    }
}

impl IntoResponse for Output {
    fn into_response(self) -> Response {
        let (content_type, body) = match self.body {
            OutputBody::Empty => (None, Body::empty()),
            OutputBody::Json(value) => match serde_json::to_vec(&value) {
                Ok(bytes) => (Some(JSON_CONTENT_TYPE.to_owned()), Body::from(bytes)),
                Err(e) => {
                    return ServerError::internal(format!("failed to serialize output: {e}"))
                        .into_response();
                }
            },
            OutputBody::Text { encoding, text } => {
                (Some(format!("{encoding}; charset=utf-8")), Body::from(text))
            }
            OutputBody::Bytes { encoding, bytes } => (Some(encoding), Body::from(bytes)),
            OutputBody::Stream { encoding, stream } => (Some(encoding), Body::from_stream(stream)),
        };
        let mut response = (StatusCode::OK, body).into_response();
        *response.headers_mut() = self.headers;
        if let Some(content_type) = content_type {
            match HeaderValue::try_from(content_type) {
                Ok(v) => {
                    response.headers_mut().insert(CONTENT_TYPE, v);
                }
                Err(_) => {
                    return ServerError::internal("invalid response encoding").into_response();
                }
            }
        }
        response
    }
}
