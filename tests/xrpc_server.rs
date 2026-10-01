//! End-to-end XRPC server tests over real HTTP and WebSocket connections,
//! ported from the reference `@atproto/xrpc-server` test suite
//! (`packages/xrpc-server/tests`). Deliberate deviations are noted inline.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::io::Write as _;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use serde_json::{Value, json};
use shrike::lexicon::Catalog;
use shrike::xrpc_server::{
    AuthContext, Frame, Input, InputBody, Output, PayloadLimits, RequestContext, Server,
    ServerError,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_tungstenite::tungstenite;

async fn serve(server: Server) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(server.serve(listener));
    format!("http://{addr}")
}

fn catalog(docs: &[Value]) -> Catalog {
    let mut catalog = Catalog::new();
    for doc in docs {
        catalog.add_schema(doc.to_string().as_bytes()).unwrap();
    }
    catalog
}

fn query_lex(id: &str, params: Value, output: Value) -> Value {
    let mut main = json!({"type": "query", "parameters": {"type": "params", "properties": {}}});
    if !params.is_null() {
        main["parameters"] = params;
    }
    if !output.is_null() {
        main["output"] = output;
    }
    json!({"lexicon": 1, "id": id, "defs": {"main": main}})
}

fn procedure_lex(id: &str, input: Value, output: Value) -> Value {
    let mut main = json!({"type": "procedure"});
    if !input.is_null() {
        main["input"] = input;
    }
    if !output.is_null() {
        main["output"] = output;
    }
    json!({"lexicon": 1, "id": id, "defs": {"main": main}})
}

fn client() -> reqwest::Client {
    reqwest::Client::new()
}

#[track_caller]
fn assert_status(resp: &reqwest::Response, status: u16) {
    assert_eq!(resp.status().as_u16(), status, "{resp:?}");
}

async fn error_body(resp: reqwest::Response, status: u16) -> (String, String) {
    assert_status(&resp, status);
    assert_eq!(
        resp.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    let body: Value = resp.json().await.unwrap();
    (
        body["error"].as_str().unwrap_or_default().to_owned(),
        body["message"].as_str().unwrap_or_default().to_owned(),
    )
}

async fn expect_error(resp: reqwest::Response, status: u16, error: &str, message: &str) {
    let (got_error, got_message) = error_body(resp, status).await;
    assert_eq!(got_error, error);
    assert_eq!(got_message, message);
}

/// Send a raw HTTP/1.1 request and return the full response text.
async fn raw_request(base: &str, request: &[u8]) -> String {
    let addr = base.trim_start_matches("http://");
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream.write_all(request).await.unwrap();
    let mut out = Vec::new();
    stream.read_to_end(&mut out).await.unwrap();
    String::from_utf8_lossy(&out).into_owned()
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn response_body(response: &str) -> &str {
    response.split_once("\r\n\r\n").map_or("", |(_, b)| b)
}

// ---------------------------------------------------------------------------
// queries.test.ts and procedures.test.ts
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
struct MessageParams {
    message: Option<String>,
}

fn ping_lexicons() -> Catalog {
    let message = json!({"type": "params", "properties": {"message": {"type": "string"}}});
    catalog(&[
        query_lex(
            "io.example.pingOne",
            message.clone(),
            json!({"encoding": "text/plain"}),
        ),
        query_lex(
            "io.example.pingTwo",
            message.clone(),
            json!({"encoding": "application/octet-stream"}),
        ),
        query_lex(
            "io.example.pingThree",
            message.clone(),
            json!({"encoding": "application/json", "schema": {
                "type": "object", "required": ["message"],
                "properties": {"message": {"type": "string"}}
            }}),
        ),
        {
            let mut doc = procedure_lex(
                "io.example.postPingOne",
                Value::Null,
                json!({"encoding": "text/plain"}),
            );
            doc["defs"]["main"]["parameters"] = message;
            doc
        },
        procedure_lex(
            "io.example.postPingTwo",
            json!({"encoding": "text/plain"}),
            json!({"encoding": "text/plain"}),
        ),
        procedure_lex(
            "io.example.postPingThree",
            json!({"encoding": "application/octet-stream"}),
            json!({"encoding": "application/octet-stream"}),
        ),
        procedure_lex(
            "io.example.postPingFour",
            json!({"encoding": "application/json", "schema": {
                "type": "object", "required": ["message"],
                "properties": {"message": {"type": "string"}}
            }}),
            json!({"encoding": "application/json", "schema": {
                "type": "object", "required": ["message"],
                "properties": {"message": {"type": "string"}}
            }}),
        ),
    ])
}

async fn ping_server() -> String {
    let server = Server::new()
        .catalog(ping_lexicons())
        .route("io.example.pingOne")
        .query_raw(|ctx: RequestContext| async move {
            let message = ctx.params.get("message").unwrap_or_default().to_owned();
            Ok(Output::text("text/plain", message))
        })
        .route("io.example.pingTwo")
        .query_raw(|ctx: RequestContext| async move {
            let message = ctx.params.get("message").unwrap_or_default().to_owned();
            Ok(Output::bytes(
                "application/octet-stream",
                message.into_bytes(),
            ))
        })
        .route("io.example.pingThree")
        .query_raw(|ctx: RequestContext| async move {
            let p: MessageParams = ctx.params.deserialize()?;
            Ok(Output::json(&json!({"message": p.message}))?.with_header(
                axum::http::HeaderName::from_static("x-test-header-name"),
                axum::http::HeaderValue::from_static("test-value"),
            ))
        })
        .route("io.example.postPingOne")
        .procedure_raw(|ctx: RequestContext, input: Option<Input>| async move {
            assert!(input.is_none());
            Ok(Output::text(
                "text/plain",
                ctx.params.get("message").unwrap_or_default(),
            ))
        })
        .route("io.example.postPingTwo")
        .procedure_raw(|_ctx: RequestContext, input: Option<Input>| async move {
            match input.unwrap().body {
                InputBody::Text(text) => Ok(Output::text("text/plain", text)),
                other => panic!("expected text, got {other:?}"),
            }
        })
        .route("io.example.postPingThree")
        .procedure_raw(|_ctx: RequestContext, input: Option<Input>| async move {
            let input = input.unwrap();
            assert!(matches!(input.body, InputBody::Stream(_)));
            Ok(Output::bytes(
                "application/octet-stream",
                input.bytes().await?,
            ))
        })
        .route("io.example.postPingFour")
        .procedure_raw(|_ctx: RequestContext, input: Option<Input>| async move {
            match input.unwrap().body {
                InputBody::Json(value) => Output::json(&value),
                other => panic!("expected json, got {other:?}"),
            }
        });
    serve(server).await
}

#[tokio::test]
async fn queries_text_bytes_and_json_outputs() {
    let base = ping_server().await;
    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.pingOne?message=hello%20world"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(resp.text().await.unwrap(), "hello world");

    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.pingTwo?message=hello+world"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(resp.headers()["content-length"], "11");
    assert_eq!(&resp.bytes().await.unwrap()[..], b"hello world");

    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.pingThree?message=hello%20world"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(resp.headers()["x-test-header-name"], "test-value");
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body, json!({"message": "hello world"}));
}

#[tokio::test]
async fn head_requests_run_queries_without_a_body() {
    let base = ping_server().await;
    let resp = client()
        .head(format!("{base}/xrpc/io.example.pingTwo?message=abc"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert!(resp.bytes().await.unwrap().is_empty());
}

#[tokio::test]
async fn trailing_slash_is_allowed() {
    let base = ping_server().await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.pingOne/?message=x"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.text().await.unwrap(), "x");
}

#[tokio::test]
async fn procedures_text_bytes_and_json() {
    let base = ping_server().await;
    let resp = client()
        .post(format!(
            "{base}/xrpc/io.example.postPingOne?message=hello%20world"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "text/plain; charset=utf-8");
    assert_eq!(resp.text().await.unwrap(), "hello world");

    let resp = client()
        .post(format!("{base}/xrpc/io.example.postPingTwo"))
        .header("content-type", "text/plain")
        .body("hello world")
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.text().await.unwrap(), "hello world");

    let resp = client()
        .post(format!("{base}/xrpc/io.example.postPingThree"))
        .header("content-type", "application/octet-stream")
        .body(b"hello world".to_vec())
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "application/octet-stream");
    assert_eq!(&resp.bytes().await.unwrap()[..], b"hello world");

    let resp = client()
        .post(format!("{base}/xrpc/io.example.postPingFour"))
        .json(&json!({"message": "hello world"}))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"message": "hello world"})
    );
}

/// Sets a flag when dropped, to observe handler cancellation.
struct DropFlag(Arc<AtomicBool>);

impl Drop for DropFlag {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

async fn wait_for(flag: &AtomicBool) -> bool {
    for _ in 0..200 {
        if flag.load(Ordering::SeqCst) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

#[tokio::test]
async fn queries_are_cancelled_when_the_client_disconnects() {
    let started = Arc::new(AtomicBool::new(false));
    let dropped = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let (s, d, f) = (started.clone(), dropped.clone(), finished.clone());
    let server = Server::new().query("io.example.slow", move |_: Value, _ctx| {
        let (s, d, f) = (s.clone(), d.clone(), f.clone());
        async move {
            let _guard = DropFlag(d);
            s.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_secs(5)).await;
            f.store(true, Ordering::SeqCst);
            Ok(())
        }
    });
    let base = serve(server).await;
    let addr = base.trim_start_matches("http://").to_owned();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(b"GET /xrpc/io.example.slow HTTP/1.1\r\nhost: x\r\n\r\n")
        .await
        .unwrap();
    assert!(wait_for(&started).await);
    drop(stream);
    assert!(wait_for(&dropped).await, "query handler was not cancelled");
    assert!(!finished.load(Ordering::SeqCst));
}

#[tokio::test]
async fn procedures_complete_when_the_client_disconnects() {
    let started = Arc::new(AtomicBool::new(false));
    let finished = Arc::new(AtomicBool::new(false));
    let (s, f) = (started.clone(), finished.clone());
    let server = Server::new().procedure("io.example.write", move |_: Value, _ctx| {
        let (s, f) = (s.clone(), f.clone());
        async move {
            s.store(true, Ordering::SeqCst);
            tokio::time::sleep(Duration::from_millis(200)).await;
            f.store(true, Ordering::SeqCst);
            Ok(())
        }
    });
    let base = serve(server).await;
    let addr = base.trim_start_matches("http://").to_owned();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /xrpc/io.example.write HTTP/1.1\r\nhost: x\r\ncontent-type: application/json\r\ncontent-length: 2\r\n\r\n{}",
        )
        .await
        .unwrap();
    assert!(wait_for(&started).await);
    drop(stream);
    assert!(wait_for(&finished).await, "procedure was abandoned");
}

// ---------------------------------------------------------------------------
// responses.test.ts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn streamed_outputs() {
    #[derive(serde::Deserialize)]
    struct P {
        #[serde(rename = "shouldErr")]
        should_err: Option<bool>,
    }
    let lex = catalog(&[query_lex(
        "io.example.readableStream",
        json!({"type": "params", "properties": {"shouldErr": {"type": "boolean"}}}),
        json!({"encoding": "application/vnd.ipld.car"}),
    )]);
    let server = Server::new()
        .catalog(lex)
        .route("io.example.readableStream")
        .query_raw(|ctx: RequestContext| async move {
            let p: P = ctx.params.deserialize()?;
            let fail = p.should_err.unwrap_or(false);
            let chunks = futures::stream::iter(0u8..5)
                .map(|i| Ok(shrike::xrpc_server::Bytes::from(vec![i])))
                .chain(futures::stream::iter(
                    fail.then(|| Err(std::io::Error::other("Oops!"))),
                ));
            Ok(Output::stream("application/vnd.ipld.car", chunks))
        });
    let base = serve(server).await;

    let resp = client()
        .get(format!("{base}/xrpc/io.example.readableStream"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(resp.headers()["content-type"], "application/vnd.ipld.car");
    assert!(resp.headers().get("content-length").is_none());
    assert_eq!(&resp.bytes().await.unwrap()[..], &[0, 1, 2, 3, 4]);

    // A stream error aborts the connection, so the client sees a failed
    // response (before or after the headers, depending on buffering) rather
    // than a complete one.
    let result = client()
        .get(format!(
            "{base}/xrpc/io.example.readableStream?shouldErr=true"
        ))
        .send()
        .await;
    match result {
        Ok(resp) => {
            assert_status(&resp, 200);
            assert!(resp.bytes().await.is_err());
        }
        Err(e) => assert!(e.is_request(), "{e:?}"),
    }
}

// ---------------------------------------------------------------------------
// bodies.test.ts
// ---------------------------------------------------------------------------

fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::Digest;
    data_encoding::HEXLOWER.encode(&sha2::Sha256::digest(bytes))
}

const BLOB_LIMIT: u64 = 5000;

fn bodies_lexicons() -> Catalog {
    let foo_bar = json!({"encoding": "application/json", "schema": {
        "type": "object",
        "required": ["foo"],
        "properties": {"foo": {"type": "string"}, "bar": {"type": "integer"}}
    }});
    catalog(&[
        procedure_lex(
            "io.example.validationTest",
            foo_bar.clone(),
            foo_bar.clone(),
        ),
        query_lex("io.example.validationTestTwo", Value::Null, foo_bar),
        procedure_lex(
            "io.example.blobTest",
            json!({"encoding": "*/*"}),
            json!({"encoding": "application/json", "schema": {
                "type": "object", "required": ["hash"], "properties": {"hash": {"type": "string"}}
            }}),
        ),
        procedure_lex("io.example.noInput", Value::Null, Value::Null),
    ])
}

async fn bodies_server(errors: Arc<Mutex<Vec<String>>>) -> String {
    let server = Server::new()
        .catalog(bodies_lexicons())
        .payload_limits(PayloadLimits {
            blob: Some(BLOB_LIMIT),
            ..PayloadLimits::default()
        })
        .on_error(move |nsid, err| {
            errors
                .lock()
                .unwrap()
                .push(format!("{nsid}: {}", err.message().unwrap_or_default()));
        })
        .procedure(
            "io.example.validationTest",
            |input: Value, _ctx| async move { Ok(input) },
        )
        .query(
            "io.example.validationTestTwo",
            |_: Value, _ctx| async move { Ok(json!({"wrong": "data"})) },
        )
        .route("io.example.blobTest")
        .procedure_raw(|_ctx: RequestContext, input: Option<Input>| async move {
            let input = input.ok_or_else(|| ServerError::invalid_request("no input"))?;
            let bytes = match input.body {
                InputBody::Stream(stream) => stream.collect().await.map_err(|e| {
                    // The reference test maps decode failures to this message;
                    // size errors pass through.
                    if e.status_code() == 413 {
                        e
                    } else {
                        ServerError::invalid_request("unable to read input")
                    }
                })?,
                other => panic!("blob input must stream, got {other:?}"),
            };
            Output::json(&json!({"hash": sha256_hex(&bytes)}))
        })
        .procedure("io.example.noInput", |_: (), _ctx| async move { Ok(()) });
    serve(server).await
}

async fn blob_hash(base: &str, req: reqwest::RequestBuilder) -> Result<String, (String, String)> {
    let _ = base;
    let resp = req.send().await.unwrap();
    if resp.status() == 200 {
        let body: Value = resp.json().await.unwrap();
        Ok(body["hash"].as_str().unwrap().to_owned())
    } else {
        let status = resp.status().as_u16();
        Err(error_body(resp, status).await)
    }
}

#[tokio::test]
async fn bodies_validate_json_input() {
    let base = bodies_server(Arc::default()).await;
    let url = format!("{base}/xrpc/io.example.validationTest");
    let resp = client()
        .post(&url)
        .json(&json!({"foo": "hello", "bar": 123}))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"foo": "hello", "bar": 123})
    );

    for bad in [json!({}), json!({"foo": 123})] {
        let resp = client().post(&url).json(&bad).send().await.unwrap();
        let (error, message) = error_body(resp, 400).await;
        assert_eq!(error, "InvalidRequest");
        assert!(message.contains("foo"), "{message}");
    }

    // An empty JSON body is `{}`, which then fails validation.
    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .send()
        .await
        .unwrap();
    let (_, message) = error_body(resp, 400).await;
    assert!(message.contains("foo"), "{message}");

    let resp = client()
        .post(&url)
        .header("content-type", "application/json")
        .body("{not json")
        .send()
        .await
        .unwrap();
    let (error, message) = error_body(resp, 400).await;
    assert_eq!(error, "InvalidRequest");
    assert!(message.starts_with("Invalid JSON body"), "{message}");

    // Media type parameters and case are ignored; only UTF-8 is accepted.
    let resp = client()
        .post(&url)
        .header("content-type", "Application/JSON; charset=UTF-8")
        .body(r#"{"foo":"x"}"#)
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    let resp = client()
        .post(&url)
        .header("content-type", "application/json; charset=latin1")
        .body(r#"{"foo":"x"}"#)
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        415,
        "UnsupportedMediaType",
        "unsupported charset \"LATIN1\"",
    )
    .await;
}

#[tokio::test]
async fn bodies_require_content_type() {
    let base = bodies_server(Arc::default()).await;
    // fetch sends `Content-Length: 0` for a bodiless POST.
    let resp = client()
        .post(format!("{base}/xrpc/io.example.validationTest"))
        .header("content-length", "0")
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Request encoding (Content-Type) required but not provided",
    )
    .await;

    let resp = client()
        .post(format!("{base}/xrpc/io.example.blobTest"))
        .header("content-type", "")
        .body("hi")
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Request encoding (Content-Type) required but not provided",
    )
    .await;

    // No framing at all means no body was sent.
    let response = raw_request(
        &base,
        b"POST /xrpc/io.example.validationTest HTTP/1.1\r\nhost: x\r\nconnection: close\r\n\r\n",
    )
    .await;
    assert!(status_line(&response).contains("400"), "{response}");
    assert!(
        response_body(&response).contains("A request body is expected but none was provided"),
        "{response}"
    );
}

#[tokio::test]
async fn bodies_reject_unexpected_input() {
    let base = bodies_server(Arc::default()).await;
    let url = format!("{base}/xrpc/io.example.noInput");
    let resp = client().post(&url).send().await.unwrap();
    assert_status(&resp, 200);
    assert!(resp.bytes().await.unwrap().is_empty());

    // An empty chunked body is fine; a non-empty one is not.
    let response = raw_request(
        &base,
        b"POST /xrpc/io.example.noInput HTTP/1.1\r\nhost: x\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\n0\r\n\r\n",
    )
    .await;
    assert!(status_line(&response).contains("200"), "{response}");

    let response = raw_request(
        &base,
        b"POST /xrpc/io.example.noInput HTTP/1.1\r\nhost: x\r\nconnection: close\r\ntransfer-encoding: chunked\r\n\r\na\r\nunexpected\r\n0\r\n\r\n",
    )
    .await;
    assert!(status_line(&response).contains("400"), "{response}");
    let body: Value = serde_json::from_str(response_body(&response)).unwrap();
    assert_eq!(
        body,
        json!({"error": "InvalidRequest", "message": "A request body was provided when none was expected"})
    );

    let resp = client()
        .post(&url)
        .header("content-type", "text/plain")
        .body("unexpected")
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "A request body was provided when none was expected",
    )
    .await;

    // Queries never take a body.
    let resp = client()
        .get(format!("{base}/xrpc/io.example.validationTestTwo"))
        .body("x")
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "A request body was provided when none was expected",
    )
    .await;
}

#[tokio::test]
async fn bodies_reject_wrong_encodings() {
    let base = bodies_server(Arc::default()).await;
    for content_type in [
        "image/jpeg",
        "multipart/form-data",
        "application/x-www-form-urlencoded",
        "application/octet-stream",
        "text/plain",
    ] {
        let resp = client()
            .post(format!("{base}/xrpc/io.example.validationTest"))
            .header("content-type", content_type)
            .body("{}")
            .send()
            .await
            .unwrap();
        expect_error(
            resp,
            400,
            "InvalidRequest",
            &format!("Wrong request encoding (Content-Type): {content_type}"),
        )
        .await;
    }
}

#[tokio::test]
async fn bodies_validate_output() {
    let errors = Arc::new(Mutex::new(Vec::new()));
    let base = bodies_server(errors.clone()).await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.validationTestTwo"))
        .send()
        .await
        .unwrap();
    expect_error(resp, 500, "InternalServerError", "Internal Server Error").await;
    let errors = errors.lock().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(
        errors[0].starts_with("io.example.validationTestTwo:"),
        "{errors:?}"
    );
    assert!(errors[0].contains("foo"), "{errors:?}");
}

#[tokio::test]
async fn bodies_stream_blobs_of_any_type() {
    let base = bodies_server(Arc::default()).await;
    let url = format!("{base}/xrpc/io.example.blobTest");
    let bytes: Vec<u8> = (0..4000u32).map(|i| (i * 7 % 256) as u8).collect();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("application/octet-stream", bytes.clone()),
        ("some/thing", bytes.clone()),
        ("text/plain", Vec::new()),
        ("application/octet-stream", Vec::new()),
        // JSON sent to a `*/*` input stays raw bytes.
        (
            "application/json",
            br#"{"foo":"bar","baz":[3, null]}"#.to_vec(),
        ),
        ("text/plain", b"hello".to_vec()),
    ];
    for (content_type, body) in cases {
        let hash = blob_hash(
            &base,
            client()
                .post(&url)
                .header("content-type", content_type)
                .body(body.clone()),
        )
        .await
        .unwrap();
        assert_eq!(hash, sha256_hex(&body), "{content_type}");
    }

    // Streamed without a Content-Length.
    let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
        bytes.chunks(100).map(|c| Ok(c.to_vec())).collect();
    let hash = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(reqwest::Body::wrap_stream(futures::stream::iter(chunks))),
    )
    .await
    .unwrap();
    assert_eq!(hash, sha256_hex(&bytes));
}

fn gzip(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn deflate(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn brotli(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    {
        let mut w = brotli::CompressorWriter::new(&mut out, 4096, 5, 22);
        w.write_all(data).unwrap();
    }
    out
}

#[tokio::test]
async fn bodies_decode_content_encodings() {
    let base = bodies_server(Arc::default()).await;
    let url = format!("{base}/xrpc/io.example.blobTest");
    let bytes: Vec<u8> = (0..4500u32).map(|i| (i % 13) as u8).collect();
    let expected = sha256_hex(&bytes);
    let cases = [
        ("identity", bytes.clone()),
        ("gzip", gzip(&bytes)),
        ("deflate", deflate(&bytes)),
        ("br", brotli(&bytes)),
        (
            "gzip, identity, deflate, identity, br, identity",
            brotli(&deflate(&gzip(&bytes))),
        ),
    ];
    for (encoding, body) in cases {
        let hash = blob_hash(
            &base,
            client()
                .post(&url)
                .header("content-type", "application/octet-stream")
                .header("content-encoding", encoding)
                .body(body),
        )
        .await;
        assert_eq!(hash, Ok(expected.clone()), "{encoding}");
    }

    // A brotli body labelled gzip fails to decode while the handler reads it.
    let got = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .header("content-encoding", "gzip")
            .body(brotli(&bytes)),
    )
    .await;
    assert_eq!(
        got,
        Err(("InvalidRequest".into(), "unable to read input".into()))
    );

    let resp = client()
        .post(&url)
        .header("content-type", "application/octet-stream")
        .header("content-encoding", "compress")
        .body(bytes.clone())
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        415,
        "UnsupportedMediaType",
        "unsupported content-encoding",
    )
    .await;

    // JSON bodies are decoded too.
    let resp = client()
        .post(format!("{base}/xrpc/io.example.validationTest"))
        .header("content-type", "application/json")
        .header("content-encoding", "gzip")
        .body(gzip(br#"{"foo":"zipped"}"#))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"foo": "zipped"})
    );
}

#[tokio::test]
async fn bodies_enforce_blob_limits() {
    let base = bodies_server(Arc::default()).await;
    let url = format!("{base}/xrpc/io.example.blobTest");
    let at_limit = vec![7u8; BLOB_LIMIT as usize];
    let over = vec![7u8; BLOB_LIMIT as usize + 1];

    // By Content-Length.
    let ok = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(at_limit.clone()),
    )
    .await;
    assert_eq!(ok, Ok(sha256_hex(&at_limit)));
    let resp = client()
        .post(&url)
        .header("content-type", "application/octet-stream")
        .body(over.clone())
        .send()
        .await
        .unwrap();
    expect_error(resp, 413, "PayloadTooLarge", "request entity too large").await;

    // Streamed, without a Content-Length.
    let stream = |data: Vec<u8>| {
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> =
            data.chunks(1000).map(|c| Ok(c.to_vec())).collect();
        reqwest::Body::wrap_stream(futures::stream::iter(chunks))
    };
    let ok = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(stream(at_limit.clone())),
    )
    .await;
    assert_eq!(ok, Ok(sha256_hex(&at_limit)));
    let got = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .body(stream(over.clone())),
    )
    .await;
    assert_eq!(
        got,
        Err(("PayloadTooLarge".into(), "request entity too large".into()))
    );

    // The limit applies to decoded bytes: a small compressed body that
    // expands past it is rejected.
    let bomb = gzip(&vec![0u8; 1 << 20]);
    assert!(bomb.len() < BLOB_LIMIT as usize);
    let got = blob_hash(
        &base,
        client()
            .post(&url)
            .header("content-type", "application/octet-stream")
            .header("content-encoding", "gzip")
            .body(bomb),
    )
    .await;
    assert_eq!(
        got,
        Err(("PayloadTooLarge".into(), "request entity too large".into()))
    );
}

#[tokio::test]
async fn json_bodies_have_a_default_limit() {
    let server =
        Server::new().procedure(
            "io.example.echo",
            |input: Value, _ctx| async move { Ok(input) },
        );
    let base = serve(server).await;
    let url = format!("{base}/xrpc/io.example.echo");
    let small = json!({"s": "x".repeat(100 * 1024 - 20)});
    let resp = client().post(&url).json(&small).send().await.unwrap();
    assert_status(&resp, 200);
    let big = json!({"s": "x".repeat(100 * 1024)});
    let resp = client().post(&url).json(&big).send().await.unwrap();
    expect_error(resp, 413, "PayloadTooLarge", "request entity too large").await;
}

/// Regression: binary bodies used to be unlimited by default.
#[tokio::test]
async fn blob_bodies_have_a_default_limit() {
    let echo_len = |_ctx: RequestContext, input: Option<Input>| async move {
        let len = match input {
            Some(input) => input.bytes().await?.len(),
            None => 0,
        };
        Output::json(&json!({"len": len}))
    };
    let server = Server::new()
        .route("io.example.upload")
        .procedure_raw(echo_len)
        .route("io.example.unlimited")
        .payload_limits(PayloadLimits {
            blob: None,
            ..PayloadLimits::default()
        })
        .procedure_raw(echo_len);
    let base = serve(server).await;
    let limit = PayloadLimits::DEFAULT_BLOB as usize;
    assert_eq!(limit, 5 * 1024 * 1024);
    let post = |path: &str, body: reqwest::Body| {
        client()
            .post(format!("{base}/xrpc/{path}"))
            .header("content-type", "application/octet-stream")
            .body(body)
            .send()
    };
    let streamed = |len: usize| {
        let chunks: Vec<Result<Vec<u8>, std::io::Error>> = (0..len.div_ceil(65536))
            .map(|i| Ok(vec![1u8; 65536.min(len - i * 65536)]))
            .collect();
        reqwest::Body::wrap_stream(futures::stream::iter(chunks))
    };

    let resp = post("io.example.upload", vec![1u8; limit].into())
        .await
        .unwrap();
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({"len": limit}));
    let resp = post("io.example.upload", vec![1u8; limit + 1].into())
        .await
        .unwrap();
    expect_error(resp, 413, "PayloadTooLarge", "request entity too large").await;
    let resp = post("io.example.upload", streamed(limit + 1))
        .await
        .unwrap();
    expect_error(resp, 413, "PayloadTooLarge", "request entity too large").await;

    // `blob: None` opts out.
    let resp = post("io.example.unlimited", streamed(limit + 1))
        .await
        .unwrap();
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"len": limit + 1})
    );
}

#[tokio::test]
async fn route_payload_limits_override_the_server_defaults() {
    let server = Server::new()
        .route("io.example.tiny")
        .payload_limits(PayloadLimits {
            json: 10,
            ..PayloadLimits::default()
        })
        .procedure(|input: Value, _ctx: RequestContext| async move { Ok(input) })
        .procedure("io.example.normal", |input: Value, _ctx| async move {
            Ok(input)
        });
    let base = serve(server).await;
    let body = json!({"long": "enough to pass ten bytes"});
    let resp = client()
        .post(format!("{base}/xrpc/io.example.tiny"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_status(&resp, 413);
    let resp = client()
        .post(format!("{base}/xrpc/io.example.normal"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
}

// ---------------------------------------------------------------------------
// errors.test.ts
// ---------------------------------------------------------------------------

fn errors_lexicons() -> Catalog {
    let mut error = query_lex(
        "io.example.error",
        json!({"type": "params", "properties": {"which": {"type": "string", "default": "foo"}}}),
        Value::Null,
    );
    error["defs"]["main"]["errors"] = json!([{"name": "Foo"}, {"name": "Bar"}]);
    catalog(&[
        error,
        query_lex("io.example.panic", Value::Null, Value::Null),
        query_lex("io.example.query", Value::Null, Value::Null),
        procedure_lex("io.example.procedure", Value::Null, Value::Null),
        query_lex("io.example.unregistered", Value::Null, Value::Null),
    ])
}

async fn errors_server() -> String {
    #[derive(serde::Deserialize)]
    struct P {
        which: String,
    }
    let server = Server::new()
        .catalog(errors_lexicons())
        .query("io.example.error", |p: P, _ctx| async move {
            Err::<(), _>(match p.which.as_str() {
                "foo" => ServerError::invalid_request("It was this one!").with_name("Foo"),
                "bar" => ServerError::new(
                    axum::http::StatusCode::BAD_REQUEST,
                    "Bar",
                    "It was that one!",
                ),
                "teapot" => ServerError::from_status(axum::http::StatusCode::IM_A_TEAPOT),
                "internal" => ServerError::internal("secret detail").with_name("CustomName"),
                _ => ServerError::from_status(axum::http::StatusCode::BAD_REQUEST),
            })
        })
        .query("io.example.panic", |_: Value, _ctx| async move {
            if true {
                panic!("handler blew up");
            }
            Ok(())
        })
        .procedure("io.example.panicProcedure", |_: Value, _ctx| async move {
            if true {
                panic!("procedure blew up");
            }
            Ok(())
        })
        .query("io.example.query", |_: Value, _ctx| async move { Ok(()) })
        .procedure("io.example.procedure", |_: (), _ctx| async move { Ok(()) })
        .query("io.example.noCatalogQuery", |_: Value, _ctx| async move {
            Ok(())
        });
    serve(server).await
}

#[tokio::test]
async fn errors_carry_custom_names_and_default_messages() {
    let base = errors_server().await;
    let get = |which: &str| {
        client()
            .get(format!("{base}/xrpc/io.example.error?which={which}"))
            .send()
    };
    expect_error(get("foo").await.unwrap(), 400, "Foo", "It was this one!").await;
    expect_error(get("bar").await.unwrap(), 400, "Bar", "It was that one!").await;
    expect_error(
        get("other").await.unwrap(),
        400,
        "InvalidRequest",
        "Invalid Request",
    )
    .await;
    // A status the XRPC spec does not name keeps its status.
    let resp = get("teapot").await.unwrap();
    assert_status(&resp, 418);
    // A 500 hides its message but keeps a custom name.
    expect_error(
        get("internal").await.unwrap(),
        500,
        "CustomName",
        "Internal Server Error",
    )
    .await;
    // The default param applies.
    let resp = client()
        .get(format!("{base}/xrpc/io.example.error"))
        .send()
        .await
        .unwrap();
    expect_error(resp, 400, "Foo", "It was this one!").await;
}

#[tokio::test]
async fn errors_from_panicking_handlers_are_500s() {
    let base = errors_server().await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.panic"))
        .send()
        .await
        .unwrap();
    expect_error(resp, 500, "InternalServerError", "Internal Server Error").await;
    let resp = client()
        .post(format!("{base}/xrpc/io.example.panicProcedure"))
        .json(&json!({}))
        .send()
        .await
        .unwrap();
    expect_error(resp, 500, "InternalServerError", "Internal Server Error").await;
    // The server keeps serving.
    let resp = client()
        .get(format!("{base}/xrpc/io.example.query"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
}

#[tokio::test]
async fn errors_for_missing_and_mismatched_methods() {
    let base = errors_server().await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.query"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    let resp = client()
        .post(format!("{base}/xrpc/io.example.procedure"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);

    let resp = client()
        .post(format!("{base}/xrpc/io.example.query"))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Incorrect HTTP method (POST) expected GET",
    )
    .await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.procedure"))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Incorrect HTTP method (GET) expected POST",
    )
    .await;
    let resp = client()
        .delete(format!("{base}/xrpc/io.example.query"))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Incorrect HTTP method (DELETE) expected GET",
    )
    .await;
    // Defined in the catalog but without a handler.
    let resp = client()
        .get(format!("{base}/xrpc/io.example.unregistered"))
        .send()
        .await
        .unwrap();
    expect_error(resp, 501, "MethodNotImplemented", "Method Not Implemented").await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.doesNotExist"))
        .send()
        .await
        .unwrap();
    expect_error(resp, 501, "MethodNotImplemented", "Method Not Implemented").await;
    // Without a lexicon, the registered handlers decide the method.
    let resp = client()
        .post(format!("{base}/xrpc/io.example.noCatalogQuery"))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        400,
        "InvalidRequest",
        "Incorrect HTTP method (POST) expected GET",
    )
    .await;
}

#[tokio::test]
async fn errors_for_invalid_paths() {
    let base = errors_server().await;
    for path in [
        "/xrpc/",
        "/xrpc/a",
        "/xrpc/.io.example.query",
        "/xrpc/io..example",
        "/xrpc/io.example.query.",
        "/xrpc/io.example.query//",
        "/xrpc/io_example",
        "/xrpc/io.example/query",
    ] {
        let resp = client().get(format!("{base}{path}")).send().await.unwrap();
        expect_error(resp, 400, "InvalidRequest", "invalid xrpc path").await;
    }
    // Paths are case-sensitive: this is a different (unknown) method.
    let resp = client()
        .get(format!("{base}/xrpc/io.example.QUERY"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 501);
    // Outside /xrpc/ is not ours.
    let resp = client().get(format!("{base}/other")).send().await.unwrap();
    assert_status(&resp, 404);
}

#[tokio::test]
async fn catchall_handles_unregistered_methods() {
    let server = Server::new()
        .catalog(errors_lexicons())
        .catchall(|req: axum::http::Request<axum::body::Body>| async move {
            use axum::response::IntoResponse;
            format!("proxied {} {}", req.method(), req.uri().path()).into_response()
        })
        .query("io.example.query", |_: Value, _ctx| async move { Ok(()) });
    let base = serve(server).await;
    let resp = client()
        .get(format!("{base}/xrpc/io.example.doesNotExist"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.text().await.unwrap(),
        "proxied GET /xrpc/io.example.doesNotExist"
    );
    // The method check still runs first for catalog methods.
    let resp = client()
        .post(format!("{base}/xrpc/io.example.query"))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 400);
}

#[tokio::test]
async fn same_nsid_can_be_a_query_and_a_procedure() {
    let server = Server::new()
        .query("io.example.both", |_: Value, _ctx| async move {
            Ok(json!({"via": "get"}))
        })
        .procedure("io.example.both", |_: Value, _ctx| async move {
            Ok(json!({"via": "post"}))
        });
    let base = serve(server).await;
    let url = format!("{base}/xrpc/io.example.both");
    let resp = client().get(&url).send().await.unwrap();
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({"via": "get"}));
    let resp = client().post(&url).json(&json!({})).send().await.unwrap();
    assert_eq!(resp.json::<Value>().await.unwrap(), json!({"via": "post"}));
}

#[cfg(feature = "xrpc")]
#[tokio::test]
async fn upstream_xrpc_errors_pass_through() {
    use shrike::xrpc::{Client, RetryPolicy};

    #[derive(serde::Deserialize)]
    struct P {
        status: u16,
    }
    let upstream = Server::new().validate_response(false).query(
        "io.example.upstream",
        |p: P, _ctx| async move {
            if p.status == 200 {
                return Ok(json!({"something": "else"}));
            }
            let status = axum::http::StatusCode::from_u16(p.status).unwrap();
            Err(ServerError::new(status, "UpstreamName", "upstream message"))
        },
    );
    let upstream = serve(upstream).await;

    #[derive(serde::Deserialize, serde::Serialize)]
    struct Expected {
        #[serde(rename = "expectedValue")]
        expected_value: String,
    }
    let no_retry = RetryPolicy {
        max_retries: 0,
        ..RetryPolicy::default()
    };
    let upstream_client = Arc::new(Client::with_retry(&upstream, no_retry));
    let server = Server::new().query("io.example.proxy", move |p: P, _ctx| {
        let client = upstream_client.clone();
        async move {
            let out: Expected = client
                .query("io.example.upstream", &json!({"status": p.status}))
                .await?;
            Ok(out)
        }
    });
    let base = serve(server).await;
    let call = |status: u16| {
        client()
            .get(format!("{base}/xrpc/io.example.proxy?status={status}"))
            .send()
    };

    expect_error(
        call(404).await.unwrap(),
        404,
        "UpstreamName",
        "upstream message",
    )
    .await;
    expect_error(
        call(401).await.unwrap(),
        401,
        "UpstreamName",
        "upstream message",
    )
    .await;
    // An upstream 500 is a 502 here (the fault is theirs), with its body
    // (whose message the upstream already hid).
    expect_error(
        call(500).await.unwrap(),
        502,
        "UpstreamName",
        "Internal Server Error",
    )
    .await;
    // Other 5xx statuses pass through.
    expect_error(
        call(503).await.unwrap(),
        503,
        "UpstreamName",
        "upstream message",
    )
    .await;
    // A response that does not match what we expect is invalid.
    let (error, message) = error_body(call(200).await.unwrap(), 502).await;
    assert_eq!(error, "InvalidResponse");
    assert!(message.starts_with("Invalid response payload"), "{message}");
}

// ---------------------------------------------------------------------------
// parameters.test.ts
// ---------------------------------------------------------------------------

async fn params_echo_server(lexicons: Catalog, nsid: &str) -> String {
    let server =
        Server::new()
            .catalog(lexicons)
            .route(nsid)
            .query_raw(|ctx: RequestContext| async move {
                Ok(Output::json_value(Value::Object(
                    ctx.params.json().cloned().unwrap_or_default(),
                )))
            });
    serve(server).await
}

#[tokio::test]
async fn params_are_decoded_validated_and_defaulted() {
    let lex = catalog(&[query_lex(
        "io.example.paramTest",
        json!({
            "type": "params",
            "required": ["str", "int", "bool", "arr"],
            "properties": {
                "str": {"type": "string", "minLength": 2, "maxLength": 10},
                "int": {"type": "integer", "minimum": 2, "maximum": 10},
                "bool": {"type": "boolean"},
                "arr": {"type": "array", "items": {"type": "integer"}, "maxLength": 2},
                "def": {"type": "integer", "default": 0}
            }
        }),
        json!({"encoding": "application/json"}),
    )]);
    let base = params_echo_server(lex, "io.example.paramTest").await;
    let get = |query: &str| {
        client()
            .get(format!("{base}/xrpc/io.example.paramTest?{query}"))
            .send()
    };

    let resp = get("str=valid&int=5&bool=true&arr=1&arr=2&def=5")
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"str": "valid", "int": 5, "bool": true, "arr": [1, 2], "def": 5})
    );
    let resp = get("str=10&int=5&bool=false&arr=3").await.unwrap();
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"str": "10", "int": 5, "bool": false, "arr": [3], "def": 0})
    );
    // Unknown params are kept as strings, as lex-schema does.
    let resp = get("str=valid&int=5&bool=true&arr=1&extra=x&many=1&many=2")
        .await
        .unwrap();
    let body: Value = resp.json().await.unwrap();
    assert_eq!(body["extra"], "x");
    assert_eq!(body["many"], json!(["1", "2"]));

    // Messages use shrike's lexicon validator wording; each names the param.
    for (query, needle) in [
        ("str=n&int=5&bool=true&arr=1", "str"),
        ("str=loooooooooooooong&int=5&bool=true&arr=1", "str"),
        ("int=5&bool=true&arr=1", "str"),
        ("str=valid&int=-1&bool=true&arr=1", "int"),
        ("str=valid&int=11&bool=true&arr=1", "int"),
        ("str=valid&bool=true&arr=1", "int"),
        ("str=valid&int=5&arr=1", "bool"),
        ("str=valid&int=5&bool=true", "arr"),
        // An empty value is no value.
        ("str=valid&int=5&bool=true&arr=", "arr"),
        ("str=valid&int=5&bool=true&arr=1&arr=2&arr=3", "arr"),
        // Strict scalar decoding (the reference client coerces these before
        // sending; the server rejects them).
        ("str=valid&int=five&bool=true&arr=1", "int"),
        ("str=valid&int=5.5&bool=true&arr=1", "int"),
        ("str=valid&int=5&bool=foo&arr=1", "bool"),
        ("str=valid&int=5&bool=true&arr=x", "arr"),
        ("str=valid&int=5&int=6&bool=true&arr=1", "int"),
    ] {
        let resp = get(query).await.unwrap();
        let (error, message) = error_body(resp, 400).await;
        assert_eq!(error, "InvalidRequest", "{query}");
        assert!(message.starts_with("Invalid params"), "{query}: {message}");
        assert!(message.contains(needle), "{query}: {message}");
    }
}

#[tokio::test]
async fn params_accept_many_repeated_values() {
    let lex = catalog(&[query_lex(
        "io.example.repeatedArrayQueryTest",
        json!({
            "type": "params",
            "required": ["dids"],
            "properties": {
                "dids": {"type": "array", "items": {"type": "string", "format": "did"}, "maxLength": 100}
            }
        }),
        json!({"encoding": "application/json"}),
    )]);
    let base = params_echo_server(lex, "io.example.repeatedArrayQueryTest").await;
    let did = "did:plc:t76alsfrlr2zewmi2nsy6rls";
    let query = vec![format!("dids={did}"); 21].join("&");
    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.repeatedArrayQueryTest?{query}"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap()["dids"],
        json!(vec![did; 21])
    );

    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.repeatedArrayQueryTest?dids=notadid"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 400);
}

#[tokio::test]
async fn params_accept_bracket_array_syntax() {
    let lex = catalog(&[query_lex(
        "io.example.looseParamsTest",
        json!({
            "type": "params",
            "required": ["str"],
            "properties": {
                "str": {"type": "string"},
                "arr": {"type": "array", "items": {"type": "string"}}
            }
        }),
        json!({"encoding": "application/json"}),
    )]);
    let base = params_echo_server(lex, "io.example.looseParamsTest").await;
    for (query, arr) in [
        ("arr[]=one&arr[]=two", json!(["one", "two"])),
        ("arr[0]=one&arr[1]=two", json!(["one", "two"])),
        ("arr[4]=one&arr[9]=two", json!(["one", "two"])),
        ("arr=one&arr=two", json!(["one", "two"])),
        ("arr%5B%5D=one&arr%5B%5D=two", json!(["one", "two"])),
        ("arr[]=only", json!(["only"])),
        ("arr[0]=only", json!(["only"])),
        // Plain values come before bracketed ones.
        ("arr[]=b&arr=a", json!(["a", "b"])),
    ] {
        let resp = client()
            .get(format!(
                "{base}/xrpc/io.example.looseParamsTest?str=hello&{query}"
            ))
            .send()
            .await
            .unwrap();
        assert_status(&resp, 200);
        let body: Value = resp.json().await.unwrap();
        assert_eq!(body["str"], "hello", "{query}");
        assert_eq!(body["arr"], arr, "{query}");
    }
}

#[tokio::test]
async fn params_deserialize_without_a_lexicon() {
    #[derive(serde::Deserialize, serde::Serialize)]
    struct P {
        uris: Vec<String>,
        limit: Option<i64>,
        reverse: Option<bool>,
    }
    let server = Server::new().query("io.example.typed", |p: P, _ctx| async move { Ok(p) });
    let base = serve(server).await;
    let resp = client()
        .get(format!(
            "{base}/xrpc/io.example.typed?uris=a&uris=b%20c&limit=-3&reverse=true"
        ))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"uris": ["a", "b c"], "limit": -3, "reverse": true})
    );
    let resp = client()
        .get(format!("{base}/xrpc/io.example.typed?uris=a&limit=x"))
        .send()
        .await
        .unwrap();
    let (error, message) = error_body(resp, 400).await;
    assert_eq!(error, "InvalidRequest");
    assert!(message.starts_with("Invalid params"), "{message}");
}

// ---------------------------------------------------------------------------
// ipld.test.ts
// ---------------------------------------------------------------------------

#[tokio::test]
async fn ipld_values_round_trip_through_json() {
    let schema = json!({"encoding": "application/json", "schema": {
        "type": "object",
        "properties": {"cid": {"type": "cid-link"}, "bytes": {"type": "bytes"}}
    }});
    let lex = catalog(&[procedure_lex("io.example.ipld", schema.clone(), schema)]);
    let server =
        Server::new()
            .catalog(lex)
            .procedure("io.example.ipld", |input: Value, _ctx| async move {
                assert!(input["cid"]["$link"].is_string());
                assert!(input["bytes"]["$bytes"].is_string());
                Ok(input)
            });
    let base = serve(server).await;
    let body = json!({
        "cid": {"$link": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"},
        "bytes": {"$bytes": "AAECAw"}
    });
    let resp = client()
        .post(format!("{base}/xrpc/io.example.ipld"))
        .json(&body)
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.headers()["content-type"],
        "application/json; charset=utf-8"
    );
    assert_eq!(resp.json::<Value>().await.unwrap(), body);

    for bad in [
        json!({"cid": {"$link": "notacid"}}),
        json!({"cid": "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a"}),
        json!({"bytes": "AAECAw"}),
    ] {
        let resp = client()
            .post(format!("{base}/xrpc/io.example.ipld"))
            .json(&bad)
            .send()
            .await
            .unwrap();
        assert_status(&resp, 400);
    }
}

// ---------------------------------------------------------------------------
// auth.test.ts
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, serde::Serialize)]
struct BasicCredentials {
    username: String,
    original: String,
}

/// The reference tests' `createBasicAuth`.
fn basic_auth(
    username: &'static str,
    password: &'static str,
) -> impl Fn(AuthContext) -> futures::future::Ready<Result<BasicCredentials, ServerError>>
+ Send
+ Sync
+ 'static {
    move |ctx: AuthContext| {
        let original = ctx
            .headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Basic "))
            .map(str::to_owned);
        let ok = original.as_deref().and_then(|b64| {
            let decoded = data_encoding::BASE64.decode(b64.as_bytes()).ok()?;
            let decoded = String::from_utf8(decoded).ok()?;
            (decoded == format!("{username}:{password}")).then_some(())
        });
        futures::future::ready(match (ok, original) {
            (Some(()), Some(original)) => Ok(BasicCredentials {
                username: username.to_owned(),
                original,
            }),
            _ => Err(ServerError::auth_required("")),
        })
    }
}

fn basic_header(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        data_encoding::BASE64.encode(format!("{username}:{password}").as_bytes())
    )
}

#[tokio::test]
async fn auth_runs_before_input_validation() {
    let lex = catalog(&[procedure_lex(
        "io.example.authTest",
        json!({"encoding": "application/json", "schema": {
            "type": "object", "properties": {"present": {"type": "boolean", "const": true}}
        }}),
        json!({"encoding": "application/json", "schema": {
            "type": "object",
            "properties": {"username": {"type": "string"}, "original": {"type": "string"}}
        }}),
    )]);
    let server = Server::new()
        .catalog(lex)
        .route("io.example.authTest")
        .auth(basic_auth("admin", "password"))
        .procedure(|_: Value, ctx: RequestContext<BasicCredentials>| async move { Ok(ctx.auth) });
    let base = serve(server).await;
    let url = format!("{base}/xrpc/io.example.authTest");

    let resp = client()
        .post(&url)
        .header("authorization", basic_header("admin", "wrong"))
        .json(&json!({"present": false}))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        401,
        "AuthenticationRequired",
        "Authentication Required",
    )
    .await;

    let resp = client()
        .post(&url)
        .json(&json!({"present": true}))
        .send()
        .await
        .unwrap();
    expect_error(
        resp,
        401,
        "AuthenticationRequired",
        "Authentication Required",
    )
    .await;

    let resp = client()
        .post(&url)
        .header("authorization", basic_header("admin", "password"))
        .json(&json!({"present": false}))
        .send()
        .await
        .unwrap();
    let (error, message) = error_body(resp, 400).await;
    assert_eq!(error, "InvalidRequest");
    assert!(message.contains("present"), "{message}");

    let resp = client()
        .post(&url)
        .header("authorization", basic_header("admin", "password"))
        .json(&json!({"present": true}))
        .send()
        .await
        .unwrap();
    assert_status(&resp, 200);
    assert_eq!(
        resp.json::<Value>().await.unwrap(),
        json!({"username": "admin", "original": "YWRtaW46cGFzc3dvcmQ="})
    );
}

#[tokio::test]
async fn auth_rejects_without_reading_a_large_body() {
    let server = Server::new()
        .route("io.example.upload")
        .auth(basic_auth("admin", "password"))
        .procedure_raw(
            |_ctx: RequestContext<BasicCredentials>, _input| async move { Ok(Output::empty()) },
        );
    let base = serve(server).await;
    // Bad auth fails before the (oversized, never-sent) body matters.
    let addr = base.trim_start_matches("http://").to_owned();
    let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
    stream
        .write_all(
            b"POST /xrpc/io.example.upload HTTP/1.1\r\nhost: x\r\ncontent-type: application/octet-stream\r\ncontent-length: 100000000\r\n\r\npartial",
        )
        .await
        .unwrap();
    let mut buf = vec![0u8; 4096];
    let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
        .await
        .unwrap()
        .unwrap();
    let response = String::from_utf8_lossy(&buf[..n]);
    assert!(status_line(&response).contains("401"), "{response}");
}

mod service_auth {
    use super::*;
    use shrike::crypto::{K256SigningKey, P256SigningKey, SigningKey};
    use shrike::service_auth::{
        ServiceAuthError, ServiceJwtClaims, ServiceJwtParams, create_service_jwt,
    };
    use shrike::xrpc_server::{Optional, ServiceAuth};

    const AUD: &str = "did:example:bob";
    const ISS: &str = "did:example:alice";
    const NSID: &str = "io.example.serviceAuth";

    fn resolver(
        key: String,
    ) -> impl Fn(String, bool) -> futures::future::Ready<Result<String, ServiceAuthError>>
    + Send
    + Sync
    + 'static {
        move |iss: String, _refresh: bool| {
            futures::future::ready(if iss == ISS {
                Ok(key.clone())
            } else {
                Err(ServiceAuthError::key_resolution(
                    "UntrustedIss",
                    "unknown issuer",
                ))
            })
        }
    }

    fn now() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }

    fn token(key: &dyn SigningKey, edit: impl FnOnce(&mut ServiceJwtParams<'_>)) -> String {
        let mut params = ServiceJwtParams::new(ISS, AUD);
        params.lxm = Some(NSID);
        edit(&mut params);
        create_service_jwt(&params, key).unwrap()
    }

    async fn server(key: &dyn SigningKey) -> String {
        let did_key = key.public_key().did_key();
        let server = Server::new()
            .route(NSID)
            .auth(ServiceAuth::new(Some(AUD), resolver(did_key.clone())))
            .query(
                |_: Value, ctx: RequestContext<ServiceJwtClaims>| async move {
                    Ok(json!({"iss": ctx.auth.iss, "lxm": ctx.auth.lxm, "aud": ctx.auth.aud}))
                },
            )
            .route("io.example.anyMethod")
            .auth(ServiceAuth::new(Some(AUD), resolver(did_key.clone())).any_method())
            .query(
                |_: Value, ctx: RequestContext<ServiceJwtClaims>| async move {
                    Ok(json!({"lxm": ctx.auth.lxm}))
                },
            )
            .route("io.example.optional")
            .auth(Optional(ServiceAuth::new(Some(AUD), resolver(did_key))))
            .query(
                |_: Value, ctx: RequestContext<Option<ServiceJwtClaims>>| async move {
                    Ok(json!({"iss": ctx.auth.map(|c| c.iss)}))
                },
            );
        serve(server).await
    }

    async fn call(base: &str, nsid: &str, auth: Option<String>) -> reqwest::Response {
        let mut req = client().get(format!("{base}/xrpc/{nsid}"));
        if let Some(auth) = auth {
            req = req.header("authorization", auth);
        }
        req.send().await.unwrap()
    }

    #[tokio::test]
    async fn verifies_service_jwts_end_to_end() {
        for key in [
            Box::new(K256SigningKey::generate()) as Box<dyn SigningKey>,
            Box::new(P256SigningKey::generate()),
        ] {
            let base = server(key.as_ref()).await;
            let bearer = |t: String| Some(format!("Bearer {t}"));

            let resp = call(&base, NSID, bearer(token(key.as_ref(), |_| {}))).await;
            assert_status(&resp, 200);
            assert_eq!(
                resp.json::<Value>().await.unwrap(),
                json!({"iss": ISS, "lxm": NSID, "aud": AUD})
            );

            let other = K256SigningKey::generate();
            let cases: Vec<(Option<String>, &str)> = vec![
                (None, "MissingJwt"),
                (Some("Basic abc".into()), "MissingJwt"),
                (Some("Bearer ".into()), "MissingJwt"),
                (bearer("not.a.jwt".into()), "BadJwt"),
                (
                    bearer(token(key.as_ref(), |p| p.lxm = Some("io.example.other"))),
                    "BadJwtLexiconMethod",
                ),
                (
                    bearer(token(key.as_ref(), |p| p.lxm = None)),
                    "BadJwtLexiconMethod",
                ),
                (
                    bearer(token(key.as_ref(), |p| p.aud = "did:example:carol")),
                    "BadJwtAudience",
                ),
                (
                    bearer(token(key.as_ref(), |p| {
                        p.iat = Some(now() - 120);
                        p.exp = Some(now() - 60);
                    })),
                    "JwtExpired",
                ),
                (bearer(token(&other, |_| {})), "BadJwtSignature"),
                (
                    bearer(token(key.as_ref(), |p| p.iss = "did:example:mallory")),
                    "UntrustedIss",
                ),
            ];
            for (auth, name) in cases {
                let resp = call(&base, NSID, auth.clone()).await;
                let (error, _) = error_body(resp, 401).await;
                assert_eq!(error, name, "{auth:?}");
            }

            // any_method accepts tokens for other methods, or none.
            for lxm in [None, Some("io.example.other")] {
                let resp = call(
                    &base,
                    "io.example.anyMethod",
                    bearer(token(key.as_ref(), |p| p.lxm = lxm)),
                )
                .await;
                assert_status(&resp, 200);
                assert_eq!(resp.json::<Value>().await.unwrap(), json!({"lxm": lxm}));
            }

            // Optional: no header is anonymous; a bad header still fails.
            let resp = call(&base, "io.example.optional", None).await;
            assert_eq!(resp.json::<Value>().await.unwrap(), json!({"iss": null}));
            let resp = call(
                &base,
                "io.example.optional",
                bearer(token(key.as_ref(), |p| p.lxm = Some("io.example.optional"))),
            )
            .await;
            assert_eq!(resp.json::<Value>().await.unwrap(), json!({"iss": ISS}));
            let resp = call(&base, "io.example.optional", bearer("garbage".into())).await;
            assert_status(&resp, 401);
        }
    }

    #[cfg(feature = "identity")]
    #[tokio::test]
    async fn resolves_issuer_keys_through_a_directory_and_refreshes_on_rotation() {
        use axum::extract::{Path, State};
        use shrike::identity::Directory;
        use std::sync::atomic::AtomicUsize;

        const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";
        type Doc = Arc<Mutex<String>>;
        fn doc(multibase: &str) -> String {
            json!({
                "id": DID,
                "verificationMethod": [{
                    "id": format!("{DID}#atproto"),
                    "type": "Multikey",
                    "controller": DID,
                    "publicKeyMultibase": multibase
                }],
                "service": []
            })
            .to_string()
        }

        let key1 = K256SigningKey::generate();
        let key2 = P256SigningKey::generate();
        let current: Doc = Arc::new(Mutex::new(doc(&key1.public_key().multibase())));
        let fetches = Arc::new(AtomicUsize::new(0));
        let plc = axum::Router::new()
            .route(
                "/{did}",
                axum::routing::get(
                    |State((doc, fetches)): State<(Doc, Arc<AtomicUsize>)>,
                     Path(did): Path<String>| async move {
                        assert_eq!(did, DID);
                        fetches.fetch_add(1, Ordering::SeqCst);
                        doc.lock().unwrap().clone()
                    },
                ),
            )
            .with_state((current.clone(), fetches.clone()));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let plc_url = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, plc).await });

        let server = Server::new()
            .route(NSID)
            .auth(ServiceAuth::new(
                Some(AUD),
                Directory::with_plc_url(&plc_url),
            ))
            .query(
                |_: Value, ctx: RequestContext<ServiceJwtClaims>| async move {
                    Ok(json!({"did": ctx.auth.did.as_str()}))
                },
            );
        let base = serve(server).await;
        let token = |key: &dyn SigningKey, iss: &str| {
            let mut params = ServiceJwtParams::new(iss, AUD);
            params.lxm = Some(NSID);
            format!("Bearer {}", create_service_jwt(&params, key).unwrap())
        };

        let resp = call(&base, NSID, Some(token(&key1, DID))).await;
        assert_status(&resp, 200);
        let resp = call(&base, NSID, Some(token(&key1, DID))).await;
        assert_status(&resp, 200);
        assert_eq!(resp.json::<Value>().await.unwrap(), json!({"did": DID}));
        let resp = call(&base, NSID, Some(token(&key1, &format!("{DID}#atproto")))).await;
        assert_status(&resp, 200);
        assert_eq!(fetches.load(Ordering::SeqCst), 1, "the document is cached");

        // The key rotates (to another curve): the cached key fails, so the
        // verifier refreshes.
        *current.lock().unwrap() = doc(&key2.public_key().multibase());
        let resp = call(&base, NSID, Some(token(&key2, DID))).await;
        assert_status(&resp, 200);
        assert_eq!(fetches.load(Ordering::SeqCst), 2);
        let resp = call(&base, NSID, Some(token(&key1, DID))).await;
        let (error, _) = error_body(resp, 401).await;
        assert_eq!(error, "BadJwtSignature");

        // The labeler fragment wants a key the document does not have.
        let resp = call(
            &base,
            NSID,
            Some(token(&key2, &format!("{DID}#atproto_labeler"))),
        )
        .await;
        let (error, message) = error_body(resp, 401).await;
        assert_eq!(error, "AuthenticationRequired");
        assert_eq!(message, "missing or bad key in did doc");
    }
}

// ---------------------------------------------------------------------------
// rate-limiter.test.ts
// ---------------------------------------------------------------------------

mod rate_limits {
    use super::*;
    use shrike::xrpc_server::{RateLimit, RateLimits, RouteRateLimit};

    const FIVE_MINUTES: Duration = Duration::from_secs(300);

    fn int_param(ctx: &shrike::xrpc_server::RateLimitContext<'_>, name: &str) -> u64 {
        ctx.params
            .get(name)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0)
    }

    async fn server(global_points: u64) -> String {
        let limits = RateLimits::memory()
            .bypass(|ctx| {
                ctx.headers
                    .get("x-ratelimit-bypass")
                    .is_some_and(|v| v == "bypass")
            })
            .shared(RateLimit::new("shared-limit", FIVE_MINUTES, 6))
            .global(RateLimit::new("global-ip", FIVE_MINUTES, global_points));
        let echo = |_: Value, ctx: RequestContext| async move {
            Ok(Value::Object(
                ctx.params.json().cloned().unwrap_or_default(),
            ))
        };
        let server = Server::new()
            .rate_limits(limits)
            .route("io.example.routeLimit")
            .rate_limit(
                RouteRateLimit::new(FIVE_MINUTES, 5)
                    .calc_key(|ctx| ctx.params.get("str").map(str::to_owned)),
            )
            .query(echo)
            .route("io.example.routeLimitReset")
            .rate_limit(RouteRateLimit::new(FIVE_MINUTES, 2))
            .query(|_: Value, ctx: RequestContext| async move {
                if ctx.params.get("count") == Some("1") {
                    ctx.reset_route_rate_limits().await;
                }
                Ok(json!({}))
            })
            .route("io.example.sharedLimitOne")
            .rate_limit(
                RouteRateLimit::shared("shared-limit").calc_points(|ctx| int_param(ctx, "points")),
            )
            .query(echo)
            .route("io.example.sharedLimitTwo")
            .rate_limit(
                RouteRateLimit::shared("shared-limit").calc_points(|ctx| int_param(ctx, "points")),
            )
            .query(echo)
            .route("io.example.toggleLimit")
            .rate_limit(
                RouteRateLimit::new(FIVE_MINUTES, 5)
                    .calc_points(|ctx| u64::from(ctx.params.get("shouldCount") == Some("true"))),
            )
            .rate_limit(RouteRateLimit::new(FIVE_MINUTES, 10))
            .query(echo)
            .query("io.example.noLimit", |_: Value, _ctx| async move {
                Ok(json!({}))
            });
        serve(server).await
    }

    async fn get(base: &str, path_and_query: &str) -> reqwest::Response {
        client()
            .get(format!("{base}/xrpc/{path_and_query}"))
            .send()
            .await
            .unwrap()
    }

    async fn expect_limited(resp: reqwest::Response) {
        expect_error(resp, 429, "RateLimitExceeded", "Rate Limit Exceeded").await;
    }

    #[tokio::test]
    async fn limits_a_route() {
        let base = server(100).await;
        for _ in 0..5 {
            assert_status(&get(&base, "io.example.routeLimit?str=test").await, 200);
        }
        expect_limited(get(&base, "io.example.routeLimit?str=test").await).await;
        // Keyed by `str`: another key has its own budget.
        assert_status(&get(&base, "io.example.routeLimit?str=other").await, 200);
    }

    #[tokio::test]
    async fn exposes_rate_limit_headers() {
        let base = server(100).await;
        let path = "io.example.routeLimit?str=cors-headers";
        let resp = get(&base, path).await;
        assert_status(&resp, 200);
        let h = resp.headers();
        assert_eq!(h["ratelimit-limit"], "5");
        assert_eq!(h["ratelimit-remaining"], "4");
        assert_eq!(h["ratelimit-policy"], "5;w=300");
        let reset: u64 = h["ratelimit-reset"].to_str().unwrap().parse().unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(reset > now && reset <= now + 301, "{reset} vs {now}");
        assert_eq!(
            h["access-control-expose-headers"],
            "RateLimit-Limit, RateLimit-Reset, RateLimit-Remaining, RateLimit-Policy"
        );
        assert!(h.get("retry-after").is_none());

        for _ in 0..4 {
            assert_status(&get(&base, path).await, 200);
        }
        let resp = get(&base, path).await;
        assert_status(&resp, 429);
        let h = resp.headers();
        assert_eq!(h["ratelimit-remaining"], "0");
        let retry_after: u64 = h["retry-after"].to_str().unwrap().parse().unwrap();
        assert!((1..=300).contains(&retry_after), "{retry_after}");
        // One header, not one per name.
        assert_eq!(h.get_all("access-control-expose-headers").iter().count(), 1);
        assert_eq!(
            h["access-control-expose-headers"],
            "RateLimit-Limit, RateLimit-Reset, RateLimit-Remaining, RateLimit-Policy, Retry-After"
        );
    }

    #[tokio::test]
    async fn resets_route_limits() {
        let base = server(100).await;
        // Limit 2: call 1 resets the counter, so calls 0-3 succeed.
        for i in 0..4 {
            assert_status(
                &get(&base, &format!("io.example.routeLimitReset?count={i}")).await,
                200,
            );
        }
        expect_limited(get(&base, "io.example.routeLimitReset?count=4").await).await;
    }

    #[tokio::test]
    async fn shares_limits_across_routes() {
        let base = server(100).await;
        for path in [
            "io.example.sharedLimitOne?points=1",
            "io.example.sharedLimitTwo?points=1",
            "io.example.sharedLimitOne?points=2",
            "io.example.sharedLimitTwo?points=2",
        ] {
            assert_status(&get(&base, path).await, 200);
        }
        expect_limited(get(&base, "io.example.sharedLimitOne?points=1").await).await;
        expect_limited(get(&base, "io.example.sharedLimitTwo?points=1").await).await;
        // Zero points skips the limit.
        assert_status(&get(&base, "io.example.sharedLimitTwo?points=0").await, 200);
    }

    #[tokio::test]
    async fn applies_every_route_limit() {
        let base = server(100).await;
        for _ in 0..5 {
            assert_status(
                &get(&base, "io.example.toggleLimit?shouldCount=true").await,
                200,
            );
        }
        expect_limited(get(&base, "io.example.toggleLimit?shouldCount=true").await).await;
        // The rejected call still counted against the second limit (6/10).
        for _ in 0..4 {
            assert_status(
                &get(&base, "io.example.toggleLimit?shouldCount=false").await,
                200,
            );
        }
        expect_limited(get(&base, "io.example.toggleLimit?shouldCount=false").await).await;
    }

    async fn parallel(base: &str, n: usize, bypass: bool) -> (usize, usize) {
        let calls = (0..n).map(|_| {
            let mut req = client().get(format!("{base}/xrpc/io.example.noLimit"));
            if bypass {
                req = req.header("X-RateLimit-Bypass", "bypass");
            }
            req.send()
        });
        let results = futures::future::join_all(calls).await;
        let ok = results
            .iter()
            .filter(|r| r.as_ref().unwrap().status() == 200)
            .count();
        let limited = results
            .iter()
            .filter(|r| r.as_ref().unwrap().status() == 429)
            .count();
        (ok, limited)
    }

    #[tokio::test]
    async fn applies_global_limits() {
        let base = server(100).await;
        assert_eq!(parallel(&base, 110, false).await, (100, 10));
    }

    #[tokio::test]
    async fn applies_global_limits_to_unregistered_methods() {
        let base = server(1).await;
        let resp = get(&base, "io.example.nonExistent").await;
        assert_status(&resp, 501);
        assert_eq!(resp.headers()["ratelimit-remaining"], "0");
        expect_limited(get(&base, "io.example.nonExistent").await).await;
    }

    #[tokio::test]
    async fn bypasses_limits() {
        let base = server(100).await;
        assert_eq!(parallel(&base, 110, true).await, (110, 0));
    }

    #[tokio::test]
    async fn route_limits_require_server_limits() {
        let server = Server::new()
            .route("io.example.limited")
            .rate_limit(RouteRateLimit::new(FIVE_MINUTES, 1))
            .query(|_: Value, _ctx| async move { Ok(()) });
        let base = serve(server).await;
        expect_error(
            get(&base, "io.example.limited").await,
            500,
            "InternalServerError",
            "Internal Server Error",
        )
        .await;
    }

    #[tokio::test]
    async fn unknown_shared_limits_are_500s() {
        let server = Server::new()
            .rate_limits(RateLimits::memory())
            .route("io.example.limited")
            .rate_limit(RouteRateLimit::shared("nope"))
            .query(|_: Value, _ctx| async move { Ok(()) });
        let base = serve(server).await;
        assert_status(&get(&base, "io.example.limited").await, 500);
    }

    /// Regression: without connect info there is no client IP, and IP-keyed
    /// limits used to be skipped, so nothing was limited.
    #[tokio::test]
    async fn ip_keyed_limits_without_connect_info_fail_closed() {
        let errors = Arc::new(Mutex::new(Vec::new()));
        let limits = RateLimits::memory().global(RateLimit::new("global-ip", FIVE_MINUTES, 100));
        let router = Server::new()
            .rate_limits(limits)
            .on_error({
                let errors = errors.clone();
                move |_, err| {
                    errors
                        .lock()
                        .unwrap()
                        .push(err.message().unwrap_or_default().to_owned())
                }
            })
            .query("io.example.noLimit", |_: Value, _ctx| async move { Ok(()) })
            .into_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });

        for path in ["io.example.noLimit", "io.example.unregistered"] {
            expect_error(
                get(&base, path).await,
                500,
                "InternalServerError",
                "Internal Server Error",
            )
            .await;
        }
        let errors = errors.lock().unwrap().clone();
        assert_eq!(errors.len(), 2);
        assert!(
            errors[0].contains("\"rl-global-ip\" is keyed by client IP"),
            "{errors:?}"
        );

        // Keying on a proxy header works without connect info.
        let router = Server::new()
            .rate_limits(RateLimits::memory().global(
                RateLimit::new("proxied", FIVE_MINUTES, 1).calc_key(|ctx| {
                    ctx.headers
                        .get("x-real-ip")?
                        .to_str()
                        .ok()
                        .map(str::to_owned)
                }),
            ))
            .query("io.example.noLimit", |_: Value, _ctx| async move { Ok(()) })
            .into_router();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await });
        let call = |ip: &'static str| {
            client()
                .get(format!("{base}/xrpc/io.example.noLimit"))
                .header("x-real-ip", ip)
                .send()
        };
        assert_status(&call("1.1.1.1").await.unwrap(), 200);
        assert_status(&call("1.1.1.1").await.unwrap(), 429);
        assert_status(&call("2.2.2.2").await.unwrap(), 200);
    }
}

// ---------------------------------------------------------------------------
// subscriptions.test.ts
// ---------------------------------------------------------------------------

mod subscriptions {
    use super::*;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;

    fn lexicons() -> Catalog {
        let countdown = json!({
            "type": "params",
            "required": ["countdown"],
            "properties": {"countdown": {"type": "integer"}}
        });
        let count = json!({"type": "object", "required": ["count"], "properties": {"count": {"type": "integer"}}});
        catalog(&[
            json!({"lexicon": 1, "id": "io.example.streamOne", "defs": {
                "main": {"type": "subscription", "parameters": countdown,
                         "message": {"schema": {"type": "union", "refs": ["#countdownStatus"]}}},
                "countdownStatus": count
            }}),
            json!({"lexicon": 1, "id": "io.example.streamTwo", "defs": {
                "main": {"type": "subscription", "parameters": countdown,
                         "message": {"schema": {"type": "union", "refs": ["#even", "#odd"]}}},
                "even": count,
                "odd": count
            }}),
            json!({"lexicon": 1, "id": "io.example.streamAuth", "defs": {
                "main": {"type": "subscription",
                         "message": {"schema": {"type": "union", "refs": ["#auth"]}}},
                "auth": {"type": "object", "properties": {
                    "username": {"type": "string"}, "original": {"type": "string"}
                }}
            }}),
        ])
    }

    #[derive(serde::Deserialize)]
    struct Countdown {
        countdown: i64,
    }

    fn message(nsid: &str, value: Value) -> Result<Frame, ServerError> {
        Frame::from_json(nsid, &value).map_err(|e| ServerError::internal(e.to_string()))
    }

    #[derive(Default, Clone)]
    struct Probes {
        dropped: Arc<AtomicBool>,
        polled_after_error: Arc<AtomicBool>,
        errors: Arc<Mutex<Vec<String>>>,
    }

    async fn server(probes: Probes) -> String {
        let errors = probes.errors.clone();
        let server =
            Server::new()
                .catalog(lexicons())
                .on_error(move |nsid, err| {
                    errors
                        .lock()
                        .unwrap()
                        .push(format!("{nsid}: {}", err.message().unwrap_or_default()));
                })
                .subscription("io.example.streamOne", |p: Countdown, _ctx| async move {
                    Ok(futures::stream::iter((0..=p.countdown).rev()).then(|i| async move {
                    tokio::task::yield_now().await;
                    message(
                        "io.example.streamOne",
                        json!({"$type": "io.example.streamOne#countdownStatus", "count": i}),
                    )
                }))
                })
                .subscription("io.example.streamTwo", |p: Countdown, _ctx| async move {
                    let counts = futures::stream::iter((0..=p.countdown).rev()).map(|i| {
                        let def = if i % 2 == 0 { "even" } else { "odd" };
                        message(
                            "io.example.streamTwo",
                            json!({"$type": format!("io.example.streamTwo#{def}"), "count": i}),
                        )
                    });
                    let done = futures::stream::once(async {
                        message(
                            "io.example.streamTwo",
                            json!({"$type": "io.example.otherNsid#done"}),
                        )
                    });
                    Ok(counts.chain(done))
                })
                .route("io.example.streamAuth")
                .auth(basic_auth("admin", "password"))
                .subscription(
                    |_: Value, ctx: RequestContext<BasicCredentials>| async move {
                        let mut body = serde_json::to_value(&ctx.auth).unwrap();
                        body["$type"] = json!("io.example.streamAuth#auth");
                        Ok(futures::stream::iter([message(
                            "io.example.streamAuth",
                            body,
                        )]))
                    },
                )
                .subscription("io.example.forever", {
                    let dropped = probes.dropped.clone();
                    move |_: Value, _ctx| {
                        let guard = DropFlag(dropped.clone());
                        async move {
                            Ok(futures::stream::unfold(
                                (guard, 0u64),
                                |(guard, i)| async move {
                                    tokio::time::sleep(Duration::from_millis(5)).await;
                                    Some((
                                        Ok(Frame::message("#tick", Vec::from([0xa0]))),
                                        (guard, i + 1),
                                    ))
                                },
                            ))
                        }
                    }
                })
                .subscription("io.example.errorMidStream", {
                    let polled = probes.polled_after_error.clone();
                    move |_: Value, _ctx| {
                        let polled = polled.clone();
                        async move {
                            let items = futures::stream::iter([
                                Ok(Frame::message("#one", Vec::from([0xa0]))),
                                Ok(Frame::error("Boom", Some("it broke".into()))),
                            ]);
                            let after = futures::stream::once(async move {
                                polled.store(true, Ordering::SeqCst);
                                Ok(Frame::message("#never", Vec::from([0xa0])))
                            });
                            Ok(items.chain(after))
                        }
                    }
                })
                .subscription("io.example.errItem", |_: Value, _ctx| async move {
                    Ok(futures::stream::iter([
                        Ok(Frame::message("#one", Vec::from([0xa0]))),
                        Err(ServerError::new(
                            axum::http::StatusCode::BAD_REQUEST,
                            "FutureCursor",
                            "Cursor in the future.",
                        )),
                    ]))
                })
                .subscription("io.example.handlerError", |_: Value, _ctx| async move {
                    Err::<futures::stream::Empty<Result<Frame, ServerError>>, _>(ServerError::new(
                        axum::http::StatusCode::BAD_REQUEST,
                        "ConsumerTooSlow",
                        "slow",
                    ))
                })
                .subscription("io.example.streamOneInvalid", |_: Value, _ctx| async move {
                    Ok(futures::stream::iter([message(
                        "io.example.streamOne",
                        json!({"$type": "io.example.streamOne#countdownStatus", "count": 1}),
                    )]))
                });
        serve(server).await
    }

    /// Everything the server sent, decoded, plus the close frame.
    async fn collect(
        url: impl IntoClientRequest + Unpin,
        nsid: &str,
    ) -> (Vec<(Option<String>, Value)>, Option<(CloseCode, String)>) {
        let (mut ws, _) = tokio_tungstenite::connect_async(url).await.unwrap();
        let mut frames = Vec::new();
        let mut close = None;
        while let Some(msg) = ws.next().await {
            match msg.unwrap() {
                Message::Binary(bytes) => match Frame::decode(&bytes).unwrap() {
                    frame @ Frame::Message { .. } => {
                        let t = match &frame {
                            Frame::Message { t, .. } => t.clone(),
                            Frame::Error { .. } => None,
                        };
                        frames.push((t, frame.to_json(nsid).unwrap().unwrap()));
                    }
                    Frame::Error { error, message } => {
                        frames.push((None, json!({"error": error, "message": message})));
                    }
                },
                Message::Close(frame) => {
                    close = frame.map(|f| (f.code, f.reason.to_string()));
                }
                other => panic!("unexpected message {other:?}"),
            }
        }
        (frames, close)
    }

    fn ws_url(base: &str, path: &str) -> String {
        format!("{}/xrpc/{path}", base.replacen("http", "ws", 1))
    }

    #[tokio::test]
    async fn streams_messages() {
        let base = server(Probes::default()).await;
        let (frames, close) = collect(
            ws_url(&base, "io.example.streamOne?countdown=5"),
            "io.example.streamOne",
        )
        .await;
        let expected: Vec<_> = (0..=5)
            .rev()
            .map(|i| {
                (
                    Some("#countdownStatus".to_owned()),
                    json!({"$type": "io.example.streamOne#countdownStatus", "count": i}),
                )
            })
            .collect();
        assert_eq!(frames, expected);
        assert_eq!(close, Some((CloseCode::Normal, String::new())));
    }

    #[tokio::test]
    async fn streams_messages_in_a_union() {
        let base = server(Probes::default()).await;
        let (frames, _) = collect(
            ws_url(&base, "io.example.streamTwo?countdown=5"),
            "io.example.streamTwo",
        )
        .await;
        let types: Vec<_> = frames.iter().map(|(t, _)| t.clone().unwrap()).collect();
        assert_eq!(
            types,
            [
                "#odd",
                "#even",
                "#odd",
                "#even",
                "#odd",
                "#even",
                "io.example.otherNsid#done"
            ]
        );
        assert_eq!(
            frames[0].1,
            json!({"$type": "io.example.streamTwo#odd", "count": 5})
        );
        assert_eq!(frames[6].1, json!({"$type": "io.example.otherNsid#done"}));
    }

    #[tokio::test]
    async fn resolves_auth_into_the_handler() {
        let base = server(Probes::default()).await;
        let mut req = ws_url(&base, "io.example.streamAuth")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            "authorization",
            basic_header("admin", "password").parse().unwrap(),
        );
        let (frames, close) = collect(req, "io.example.streamAuth").await;
        assert_eq!(
            frames,
            [(
                Some("#auth".to_owned()),
                json!({
                    "$type": "io.example.streamAuth#auth",
                    "username": "admin",
                    "original": "YWRtaW46cGFzc3dvcmQ="
                })
            )]
        );
        assert_eq!(close.unwrap().0, CloseCode::Normal);
    }

    #[tokio::test]
    async fn errors_immediately_on_bad_params() {
        let base = server(Probes::default()).await;
        for query in ["", "?countdown=abc"] {
            let (frames, close) = collect(
                ws_url(&base, &format!("io.example.streamOne{query}")),
                "io.example.streamOne",
            )
            .await;
            assert_eq!(frames.len(), 1, "{query}");
            assert_eq!(frames[0].1["error"], "InvalidRequest");
            assert!(
                frames[0].1["message"]
                    .as_str()
                    .unwrap()
                    .contains("countdown"),
                "{frames:?}"
            );
            assert_eq!(
                close,
                Some((CloseCode::Policy, "InvalidRequest".to_owned()))
            );
        }
    }

    #[tokio::test]
    async fn errors_immediately_on_bad_auth() {
        let base = server(Probes::default()).await;
        let mut req = ws_url(&base, "io.example.streamAuth")
            .into_client_request()
            .unwrap();
        req.headers_mut().insert(
            "authorization",
            basic_header("bad", "wrong").parse().unwrap(),
        );
        let (frames, close) = collect(req, "io.example.streamAuth").await;
        assert_eq!(
            frames,
            [(
                None,
                json!({"error": "AuthenticationRequired", "message": "Authentication Required"})
            )]
        );
        assert_eq!(
            close,
            Some((CloseCode::Policy, "AuthenticationRequired".to_owned()))
        );
    }

    #[tokio::test]
    async fn handler_errors_become_error_frames() {
        let base = server(Probes::default()).await;
        let (frames, close) = collect(
            ws_url(&base, "io.example.handlerError"),
            "io.example.handlerError",
        )
        .await;
        assert_eq!(
            frames,
            [(None, json!({"error": "ConsumerTooSlow", "message": "slow"}))]
        );
        assert_eq!(
            close,
            Some((CloseCode::Policy, "ConsumerTooSlow".to_owned()))
        );

        let (frames, close) =
            collect(ws_url(&base, "io.example.errItem"), "io.example.errItem").await;
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[1].1,
            json!({"error": "FutureCursor", "message": "Cursor in the future."})
        );
        assert_eq!(close, Some((CloseCode::Policy, "FutureCursor".to_owned())));
    }

    #[tokio::test]
    async fn error_frames_end_the_stream() {
        let probes = Probes::default();
        let base = server(probes.clone()).await;
        let (frames, close) = collect(
            ws_url(&base, "io.example.errorMidStream"),
            "io.example.errorMidStream",
        )
        .await;
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].0.as_deref(), Some("#one"));
        assert_eq!(frames[1].1, json!({"error": "Boom", "message": "it broke"}));
        assert_eq!(close, Some((CloseCode::Policy, "Boom".to_owned())));
        assert!(!probes.polled_after_error.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn invalid_messages_end_the_stream_with_a_500() {
        let probes = Probes::default();
        let base = server(probes.clone()).await;
        // streamOneInvalid has no lexicon of its own, so register a broken
        // message under streamOne's schema via a server that lies.
        let server = Server::new()
            .catalog(lexicons())
            .on_error({
                let errors = probes.errors.clone();
                move |nsid, err| {
                    errors
                        .lock()
                        .unwrap()
                        .push(format!("{nsid}: {}", err.message().unwrap_or_default()));
                }
            })
            .subscription("io.example.streamOne", |_: Value, _ctx| async move {
                Ok(futures::stream::iter([
                    message(
                        "io.example.streamOne",
                        json!({"$type": "io.example.streamOne#countdownStatus", "count": 1}),
                    ),
                    message(
                        "io.example.streamOne",
                        json!({"$type": "io.example.streamOne#countdownStatus", "count": "one"}),
                    ),
                ]))
            });
        let _ = base;
        let base = serve(server).await;
        let (frames, close) = collect(
            ws_url(&base, "io.example.streamOne?countdown=1"),
            "io.example.streamOne",
        )
        .await;
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[1].1,
            json!({"error": "InternalServerError", "message": "Internal Server Error"})
        );
        assert_eq!(
            close,
            Some((CloseCode::Policy, "InternalServerError".to_owned()))
        );
        let errors = probes.errors.lock().unwrap();
        assert_eq!(errors.len(), 1, "{errors:?}");
        assert!(errors[0].contains("count"), "{errors:?}");
    }

    #[tokio::test]
    async fn unknown_methods_are_not_upgraded() {
        let base = server(Probes::default()).await;
        match tokio_tungstenite::connect_async(ws_url(&base, "does.not.exist")).await {
            Err(tungstenite::Error::Http(resp)) => assert_eq!(resp.status(), 501),
            other => panic!("expected an HTTP error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn plain_get_on_a_subscription_is_rejected() {
        let base = server(Probes::default()).await;
        let resp = client()
            .get(format!("{base}/xrpc/io.example.streamOne?countdown=1"))
            .send()
            .await
            .unwrap();
        let (error, message) = error_body(resp, 400).await;
        assert_eq!(error, "InvalidRequest");
        assert!(
            message.starts_with("Expected a WebSocket upgrade"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn client_disconnect_drops_the_stream() {
        let probes = Probes::default();
        let base = server(probes.clone()).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(ws_url(&base, "io.example.forever"))
            .await
            .unwrap();
        for _ in 0..3 {
            let msg = ws.next().await.unwrap().unwrap();
            assert!(matches!(msg, Message::Binary(_)));
        }
        assert!(!probes.dropped.load(Ordering::SeqCst));
        ws.close(None).await.unwrap();
        drop(ws);
        assert!(wait_for(&probes.dropped).await, "stream was not dropped");

        // An abrupt TCP drop (no close frame) is noticed too.
        let probes = Probes::default();
        let base = server(probes.clone()).await;
        let (mut ws, _) = tokio_tungstenite::connect_async(ws_url(&base, "io.example.forever"))
            .await
            .unwrap();
        ws.next().await.unwrap().unwrap();
        drop(ws);
        assert!(wait_for(&probes.dropped).await, "stream was not dropped");
    }

    #[tokio::test]
    async fn ignores_client_messages() {
        let base = server(Probes::default()).await;
        let (mut ws, _) =
            tokio_tungstenite::connect_async(ws_url(&base, "io.example.streamOne?countdown=2"))
                .await
                .unwrap();
        ws.send(Message::Text("hello".into())).await.unwrap();
        let mut count = 0;
        while let Some(Ok(msg)) = ws.next().await {
            if matches!(msg, Message::Binary(_)) {
                count += 1;
            }
        }
        assert_eq!(count, 3);
    }
}

// ---------------------------------------------------------------------------
// shrike's own client against the server
// ---------------------------------------------------------------------------

#[cfg(feature = "xrpc")]
mod client_e2e {
    use super::*;
    use shrike::xrpc::Client;

    /// Regression: array params were rejected by the client's URL encoder.
    #[tokio::test]
    async fn client_sends_array_params() {
        #[derive(serde::Serialize)]
        struct P<'a> {
            uris: Vec<&'a str>,
            limit: Option<u32>,
            missing: Option<u32>,
        }
        let lex = catalog(&[query_lex(
            "io.example.arrays",
            json!({"type": "params", "properties": {
                "uris": {"type": "array", "items": {"type": "string", "format": "at-uri"}},
                "limit": {"type": "integer"},
                "missing": {"type": "integer"}
            }}),
            json!({"encoding": "application/json"}),
        )]);
        let base = params_echo_server(lex, "io.example.arrays").await;
        let client = Client::new(&base);
        let uris = vec![
            "at://did:plc:abc/app.bsky.feed.post/1",
            "at://did:plc:abc/app.bsky.feed.post/2",
        ];
        let out: Value = client
            .query(
                "io.example.arrays",
                &P {
                    uris: uris.clone(),
                    limit: Some(3),
                    missing: None,
                },
            )
            .await
            .unwrap();
        assert_eq!(out, json!({"uris": uris, "limit": 3}));
    }

    #[tokio::test]
    async fn client_procedures_and_errors() {
        let server = Server::new()
            .procedure(
                "io.example.echo",
                |input: Value, _ctx| async move { Ok(input) },
            )
            .query("io.example.fail", |_: Value, _ctx| async move {
                Err::<(), _>(ServerError::invalid_request("nope").with_name("RecordNotFound"))
            });
        let base = serve(server).await;
        let client = Client::new(&base);
        let out: Value = client
            .procedure("io.example.echo", &json!({"a": [1, 2]}))
            .await
            .unwrap();
        assert_eq!(out, json!({"a": [1, 2]}));
        match client.query::<_, Value>("io.example.fail", &()).await {
            Err(shrike::xrpc::Error::Xrpc {
                status,
                error,
                message,
            }) => {
                assert_eq!(
                    (status, error.as_str(), message.as_str()),
                    (400, "RecordNotFound", "nope")
                );
            }
            other => panic!("expected an XRPC error, got {other:?}"),
        }
    }

    #[cfg(feature = "api")]
    #[tokio::test]
    async fn generated_bindings_round_trip() {
        use shrike::api::app::bsky::{FeedGetPostsParams, feed_get_posts};
        let server = Server::new().route("app.bsky.feed.getPosts").query_raw(
            |ctx: RequestContext| async move {
                assert_eq!(ctx.params.get_all("uris").len(), 2);
                Output::json(&json!({"posts": []}))
            },
        );
        let base = serve(server).await;
        let client = Client::new(&base);
        let out = feed_get_posts(
            &client,
            &FeedGetPostsParams {
                uris: vec![
                    "at://did:plc:a/app.bsky.feed.post/1".into(),
                    "at://did:plc:a/app.bsky.feed.post/2".into(),
                ],
            },
        )
        .await
        .unwrap();
        assert!(out.posts.is_empty());
    }
}
