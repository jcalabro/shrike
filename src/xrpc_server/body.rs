//! Request bodies: presence, content type, `Content-Encoding` decoding and
//! size limits.

use std::io::{ErrorKind, Read};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use axum::body::{Body, BodyDataStream, Bytes, HttpBody};
use futures::{Stream, StreamExt};
use http::HeaderMap;
use http::header::{CONTENT_ENCODING, CONTENT_LENGTH, CONTENT_TYPE, TRANSFER_ENCODING};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::xrpc_server::error::ServerError;

/// Request body size limits, in bytes after decoding.
///
/// A `Content-Length` over the limit is rejected before reading; the decoded
/// stream is counted as it is read. Defaults: 100 KiB for JSON and text
/// bodies, as in the reference, and 5 MiB for other (binary) bodies, the
/// reference PDS's blob upload limit. Unlike the reference server, binary
/// bodies are limited by default; set `blob: None` to stream without one.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PayloadLimits {
    /// Limit for `application/json` bodies.
    pub json: u64,
    /// Limit for `text/plain` bodies.
    pub text: u64,
    /// Limit for streamed bodies, e.g. blob uploads. `None` is unlimited.
    pub blob: Option<u64>,
}

impl PayloadLimits {
    /// The default limit for streamed bodies: 5 MiB.
    pub const DEFAULT_BLOB: u64 = 5 * 1024 * 1024;
}

impl Default for PayloadLimits {
    fn default() -> Self {
        PayloadLimits {
            json: 100 * 1024,
            text: 100 * 1024,
            blob: Some(Self::DEFAULT_BLOB),
        }
    }
}

/// A procedure's request body.
#[derive(Debug)]
pub struct Input {
    /// The request `Content-Type` media type, lowercased, without parameters.
    pub encoding: String,
    /// The body.
    pub body: InputBody,
}

/// The decoded form of a request body.
///
/// JSON and text bodies are read fully (and, with a lexicon, validated);
/// other bodies, and any body for a method whose lexicon input encoding is
/// `*/*`, are streamed.
#[derive(Debug)]
pub enum InputBody {
    /// A parsed (and validated, with defaults) `application/json` body.
    Json(Value),
    /// A `text/plain` body.
    Text(String),
    /// A decoded byte stream, size-limited as it is read.
    Stream(BodyStream),
}

impl Input {
    /// Deserialize a JSON body. A streamed body is read (up to the JSON limit
    /// in force for the method) and parsed.
    pub async fn json<T: DeserializeOwned>(self) -> Result<T, ServerError> {
        let value = match self.body {
            InputBody::Json(value) => value,
            InputBody::Text(text) => parse_json(text.as_bytes())?,
            InputBody::Stream(stream) => parse_json(&stream.collect().await?)?,
        };
        serde_json::from_value(value)
            .map_err(|e| ServerError::invalid_request(format!("Invalid request body: {e}")))
    }

    /// The body bytes. JSON bodies are re-serialized.
    pub async fn bytes(self) -> Result<Bytes, ServerError> {
        match self.body {
            InputBody::Json(value) => serde_json::to_vec(&value)
                .map(Bytes::from)
                .map_err(|e| ServerError::internal(e.to_string())),
            InputBody::Text(text) => Ok(Bytes::from(text)),
            InputBody::Stream(stream) => stream.collect().await,
        }
    }
}

/// A streamed request body, after `Content-Encoding` decoding.
///
/// Yields 413 `PayloadTooLarge` once more than the limit has been decoded, and
/// 400 `InvalidRequest` for a corrupt encoding or a broken connection.
/// Decoding is incremental and reads at most [`DECODE_CHUNK`] bytes at a time,
/// so a highly compressed body cannot balloon in memory.
pub struct BodyStream {
    inner: BodyDataStream,
    decoder: Option<Decoder>,
    limit: Option<u64>,
    seen: u64,
    done: bool,
}

/// The largest decoded chunk a [`BodyStream`] yields at once.
pub const DECODE_CHUNK: usize = 64 * 1024;

impl std::fmt::Debug for BodyStream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BodyStream")
            .field("limit", &self.limit)
            .field("seen", &self.seen)
            .finish_non_exhaustive()
    }
}

impl BodyStream {
    pub(crate) fn new(body: Body, decoder: Option<Decoder>, limit: Option<u64>) -> Self {
        BodyStream {
            inner: body.into_data_stream(),
            decoder,
            limit,
            seen: 0,
            done: false,
        }
    }

    /// Read the whole body.
    pub async fn collect(mut self) -> Result<Bytes, ServerError> {
        let mut out = Vec::new();
        while let Some(chunk) = self.next().await {
            out.extend_from_slice(&chunk?);
        }
        Ok(Bytes::from(out))
    }

    fn emit(&mut self, chunk: Bytes) -> Poll<Option<Result<Bytes, ServerError>>> {
        self.seen = self.seen.saturating_add(chunk.len() as u64);
        if self.limit.is_some_and(|limit| self.seen > limit) {
            return self.fail(too_large());
        }
        Poll::Ready(Some(Ok(chunk)))
    }

    fn fail(&mut self, err: ServerError) -> Poll<Option<Result<Bytes, ServerError>>> {
        self.done = true;
        Poll::Ready(Some(Err(err)))
    }
}

impl Stream for BodyStream {
    type Item = Result<Bytes, ServerError>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        loop {
            if self.done {
                return Poll::Ready(None);
            }
            // Drain decoded output before reading more of the body.
            if let Some(decoder) = &mut self.decoder {
                match decoder.read() {
                    Ok(Some(chunk)) if chunk.is_empty() => {
                        self.done = true;
                        return Poll::Ready(None);
                    }
                    Ok(Some(chunk)) => return self.emit(chunk),
                    Ok(None) => {}
                    Err(e) => return self.fail(decode_error(e)),
                }
            }
            match self.inner.poll_next_unpin(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(Some(Err(e))) => {
                    return self.fail(ServerError::invalid_request(format!(
                        "Failed to read request body: {e}"
                    )));
                }
                Poll::Ready(Some(Ok(chunk))) => match &mut self.decoder {
                    Some(decoder) => decoder.push(&chunk),
                    None if chunk.is_empty() => {}
                    None => return self.emit(chunk),
                },
                Poll::Ready(None) => match &mut self.decoder {
                    Some(decoder) => decoder.finish_input(),
                    None => {
                        self.done = true;
                        return Poll::Ready(None);
                    }
                },
            }
        }
    }
}

fn too_large() -> ServerError {
    ServerError::payload_too_large("request entity too large")
}

fn decode_error(e: std::io::Error) -> ServerError {
    ServerError::invalid_request(format!("Failed to decode request body: {e}"))
}

/// Encoded bytes received so far, read by the innermost decoder. Reading an
/// empty buffer before the body ends is `WouldBlock`, which the `flate2` and
/// `brotli` read decoders resume from once more input arrives.
#[derive(Default)]
struct Pending {
    buf: Vec<u8>,
    pos: usize,
    eof: bool,
}

#[derive(Clone, Default)]
struct PendingReader(Arc<Mutex<Pending>>);

impl PendingReader {
    fn lock(&self) -> std::sync::MutexGuard<'_, Pending> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

impl Read for PendingReader {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        let mut p = self.lock();
        if p.pos == p.buf.len() {
            return if p.eof {
                Ok(0)
            } else {
                Err(ErrorKind::WouldBlock.into())
            };
        }
        let n = out.len().min(p.buf.len() - p.pos);
        let start = p.pos;
        out[..n].copy_from_slice(&p.buf[start..start + n]);
        p.pos += n;
        Ok(n)
    }
}

/// A chain of `Content-Encoding` decoders over the received body bytes.
pub(crate) struct Decoder {
    input: PendingReader,
    reader: Box<dyn Read + Send>,
    buf: Vec<u8>,
}

impl Decoder {
    fn push(&mut self, chunk: &[u8]) {
        let mut p = self.input.lock();
        if p.pos == p.buf.len() {
            p.buf.clear();
            p.pos = 0;
        }
        p.buf.extend_from_slice(chunk);
    }

    fn finish_input(&mut self) {
        self.input.lock().eof = true;
    }

    /// `Some(empty)` at the end of the stream, `None` if more input is needed.
    fn read(&mut self) -> std::io::Result<Option<Bytes>> {
        match self.reader.read(&mut self.buf) {
            Ok(n) => Ok(Some(Bytes::copy_from_slice(&self.buf[..n]))),
            Err(e) if e.kind() == ErrorKind::WouldBlock => Ok(None),
            Err(e) if e.kind() == ErrorKind::Interrupted => Ok(None),
            Err(e) => Err(e),
        }
    }
}

/// Build the decoder chain for a `Content-Encoding` header: comma-separated,
/// case-insensitive, `identity` ignored, undone last to first. An empty
/// header is ignored, but an empty entry in a list is unsupported, as in the
/// reference. `None` if there is nothing to decode.
pub(crate) fn decoder(headers: &HeaderMap) -> Result<Option<Decoder>, ServerError> {
    let unsupported = || ServerError::unsupported_media_type("unsupported content-encoding");
    let mut codings = Vec::new();
    for value in headers.get_all(CONTENT_ENCODING) {
        if value.is_empty() {
            continue;
        }
        for coding in value.to_str().map_err(|_| unsupported())?.split(',') {
            match coding.trim().to_ascii_lowercase().as_str() {
                "identity" => {}
                "gzip" | "x-gzip" => codings.push(Coding::Gzip),
                "deflate" => codings.push(Coding::Deflate),
                "br" => codings.push(Coding::Brotli),
                _ => return Err(unsupported()),
            }
        }
    }
    if codings.is_empty() {
        return Ok(None);
    }
    let input = PendingReader::default();
    // The last coding applied is the first undone, so it reads the input.
    let mut reader: Box<dyn Read + Send> = Box::new(input.clone());
    for coding in codings.into_iter().rev() {
        reader = match coding {
            Coding::Gzip => Box::new(flate2::read::MultiGzDecoder::new(reader)),
            Coding::Deflate => Box::new(flate2::read::ZlibDecoder::new(reader)),
            Coding::Brotli => Box::new(brotli_decompressor::Decompressor::new(reader, 4096)),
        };
    }
    Ok(Some(Decoder {
        input,
        reader,
        buf: vec![0; DECODE_CHUNK],
    }))
}

enum Coding {
    Gzip,
    Deflate,
    Brotli,
}

/// Whether a request carries a body, following the reference: a
/// `Transfer-Encoding` means one is present, `Content-Length: 0` means it is
/// empty, and no framing header at all means none was sent. HTTP/2 bodies
/// have neither header, so a body stream that is not already finished also
/// counts as present. Unlike the reference, a `Content-Type` without framing
/// is an empty body rather than a missing one, since some clients (including
/// reqwest) omit `Content-Length: 0` for empty bodies.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Presence {
    Missing,
    Empty,
    /// A body with a known non-zero length.
    Sized(u64),
    /// A body of unknown length (chunked, or HTTP/2).
    Unsized,
}

pub(crate) fn presence(headers: &HeaderMap, body: &Body) -> Result<Presence, ServerError> {
    if headers.contains_key(TRANSFER_ENCODING) {
        return Ok(Presence::Unsized);
    }
    match headers.get(CONTENT_LENGTH) {
        Some(value) => {
            let len: u64 = value
                .to_str()
                .ok()
                .and_then(|s| s.trim().parse().ok())
                .ok_or_else(|| ServerError::invalid_request("invalid content-length"))?;
            Ok(if len == 0 {
                Presence::Empty
            } else {
                Presence::Sized(len)
            })
        }
        None if !body.is_end_stream() => Ok(Presence::Unsized),
        None if headers.contains_key(CONTENT_TYPE) => Ok(Presence::Empty),
        None => Ok(Presence::Missing),
    }
}

/// The request media type, lowercased, without parameters, and its
/// `charset` parameter. `None` if absent or not of the form `type/subtype`.
pub(crate) fn content_type(headers: &HeaderMap) -> Option<(String, Option<String>)> {
    let raw = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    let mut parts = raw.split(';');
    let mime = parts.next()?.trim().to_ascii_lowercase();
    let (kind, sub) = mime.split_once('/')?;
    if kind.is_empty() || sub.is_empty() || sub.contains('/') {
        return None;
    }
    let charset = parts.find_map(|p| {
        let (k, v) = p.split_once('=')?;
        k.trim()
            .eq_ignore_ascii_case("charset")
            .then(|| v.trim().trim_matches('"').to_ascii_lowercase())
    });
    Some((mime, charset))
}

/// Whether a lexicon encoding list (comma-separated) accepts `mime`:
/// `*/*` accepts anything, `type/*` a type prefix, anything else exactly.
pub(crate) fn encoding_matches(allowed: &str, mime: &str) -> bool {
    allowed.split(',').map(str::trim).any(|pattern| {
        if pattern == "*/*" {
            true
        } else if let Some(prefix) = pattern.strip_suffix("/*") {
            mime.strip_prefix(prefix)
                .is_some_and(|r| r.starts_with('/'))
        } else {
            pattern.eq_ignore_ascii_case(mime)
        }
    })
}

/// Read a whole body with a limit.
pub(crate) async fn read_limited(
    body: Body,
    decoder: Option<Decoder>,
    limit: u64,
) -> Result<Bytes, ServerError> {
    BodyStream::new(body, decoder, Some(limit)).collect().await
}

pub(crate) fn check_length(presence: Presence, limit: Option<u64>) -> Result<(), ServerError> {
    match (presence, limit) {
        (Presence::Sized(len), Some(limit)) if len > limit => Err(too_large()),
        _ => Ok(()),
    }
}

/// Only UTF-8 (the default) is accepted for JSON and text bodies.
pub(crate) fn check_charset(charset: Option<&str>) -> Result<(), ServerError> {
    match charset {
        None | Some("utf-8" | "utf8") => Ok(()),
        Some(other) => Err(ServerError::unsupported_media_type(format!(
            "unsupported charset \"{}\"",
            other.to_ascii_uppercase()
        ))),
    }
}

/// Parse a JSON body. An empty body is `{}`, as in the reference.
pub(crate) fn parse_json(bytes: &[u8]) -> Result<Value, ServerError> {
    if bytes.iter().all(u8::is_ascii_whitespace) {
        return Ok(Value::Object(Default::default()));
    }
    serde_json::from_slice(bytes)
        .map_err(|e| ServerError::invalid_request(format!("Invalid JSON body: {e}")))
}

pub(crate) fn parse_text(bytes: Bytes) -> Result<String, ServerError> {
    String::from_utf8(bytes.to_vec())
        .map_err(|_| ServerError::invalid_request("Request body is not valid UTF-8"))
}

/// Check that no body was sent. A chunked body is read and must turn out
/// empty.
pub(crate) async fn expect_no_body(presence: Presence, body: Body) -> Result<(), ServerError> {
    let unexpected =
        || ServerError::invalid_request("A request body was provided when none was expected");
    match presence {
        Presence::Missing | Presence::Empty => Ok(()),
        Presence::Sized(_) => Err(unexpected()),
        Presence::Unsized => {
            let mut stream = body.into_data_stream();
            while let Some(chunk) = stream.next().await {
                let chunk = chunk.map_err(|e| {
                    ServerError::invalid_request(format!(
                        "Failed to process unexpected request body: {e}"
                    ))
                })?;
                if !chunk.is_empty() {
                    return Err(unexpected());
                }
            }
            Ok(())
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::io::Write;

    use super::*;
    use http::{HeaderValue, StatusCode};
    use serde_json::json;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut h = HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                http::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    fn ct(value: &str) -> Option<(String, Option<String>)> {
        content_type(&headers(&[("content-type", value)]))
    }

    fn pseudo_random(len: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
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

    fn brotli(data: &[u8], quality: u32) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut w = ::brotli::CompressorWriter::new(&mut out, 4096, quality, 22);
            w.write_all(data).unwrap();
        }
        out
    }

    fn chunked_body(data: &[u8], chunk: usize) -> Body {
        let chunks: Vec<Result<Bytes, std::io::Error>> = data
            .chunks(chunk.max(1))
            .map(|c| Ok(Bytes::copy_from_slice(c)))
            .collect();
        Body::from_stream(futures::stream::iter(chunks))
    }

    fn stream(encoding: &str, data: &[u8], chunk: usize, limit: Option<u64>) -> BodyStream {
        let dec = decoder(&headers(&[("content-encoding", encoding)])).unwrap();
        BodyStream::new(chunked_body(data, chunk), dec, limit)
    }

    async fn decode(
        encoding: &str,
        data: &[u8],
        chunk: usize,
        limit: Option<u64>,
    ) -> Result<Bytes, ServerError> {
        stream(encoding, data, chunk, limit).collect().await
    }

    fn decoder_err(encoding: &str) -> ServerError {
        match decoder(&headers(&[("content-encoding", encoding)])) {
            Ok(_) => panic!("{encoding:?} accepted"),
            Err(e) => e,
        }
    }

    #[test]
    fn content_type_parsing() {
        assert_eq!(
            ct("application/json"),
            Some(("application/json".into(), None))
        );
        assert_eq!(
            ct("Application/JSON; Charset=UTF-8"),
            Some(("application/json".into(), Some("utf-8".into())))
        );
        assert_eq!(
            ct("text/plain; charset=\"utf-8\""),
            Some(("text/plain".into(), Some("utf-8".into())))
        );
        assert_eq!(
            ct("text/plain;foo=bar; charset=latin1"),
            Some(("text/plain".into(), Some("latin1".into())))
        );
        assert_eq!(ct("  image/png  ; q=1"), Some(("image/png".into(), None)));
        assert_eq!(ct("some/thing"), Some(("some/thing".into(), None)));
        for bad in [
            "",
            "json",
            "application",
            "/json",
            "application/",
            "/",
            "a/b/c",
            "; charset=utf-8",
        ] {
            assert_eq!(ct(bad), None, "{bad:?}");
        }
        assert_eq!(content_type(&HeaderMap::new()), None);
    }

    #[test]
    fn encoding_matching() {
        assert!(encoding_matches("image/*", "image/png"));
        assert!(encoding_matches("text/plain", "text/plain"));
        assert!(encoding_matches("*/*", "text/plain"));
        assert!(!encoding_matches("image/*", "text/plain"));
        assert!(!encoding_matches("text/plain", "image/png"));
        assert!(!encoding_matches("text/plain", ""));
        assert!(!encoding_matches("", "text/plain"));

        assert!(encoding_matches(
            "application/json, text/plain",
            "text/plain"
        ));
        assert!(encoding_matches("image/png,image/jpeg", "image/jpeg"));
        assert!(!encoding_matches("image/png, image/jpeg", "image/gif"));
        assert!(encoding_matches("text/plain, */*", "application/cbor"));
        assert!(encoding_matches("application/*", "application/json"));
        assert!(!encoding_matches("image/*", "imagex/png"));
        assert!(!encoding_matches("image/*", "image"));
        assert!(!encoding_matches(
            "application/json",
            "application/json+thing"
        ));
    }

    #[test]
    fn charset_check() {
        assert!(check_charset(None).is_ok());
        assert!(check_charset(Some("utf-8")).is_ok());
        let err = check_charset(Some("iso-8859-1")).unwrap_err();
        assert_eq!(err.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(err.message(), Some("unsupported charset \"ISO-8859-1\""));
    }

    #[test]
    fn json_parsing() {
        assert_eq!(parse_json(b"").unwrap(), json!({}));
        assert_eq!(
            parse_json(br#"{"foo":"bar","baz":[3,null]}"#).unwrap(),
            json!({"foo": "bar", "baz": [3, null]})
        );
        let err = parse_json(b"{nope").unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.error_name(), Some("InvalidRequest"));
    }

    #[test]
    fn text_parsing() {
        assert_eq!(parse_text(Bytes::from_static(b"hi")).unwrap(), "hi");
        assert_eq!(
            parse_text(Bytes::from_static(&[0xff, 0xfe]))
                .unwrap_err()
                .status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn body_presence() {
        let p = |h: &[(&str, &str)], body: Body| presence(&headers(h), &body).map_err(Box::new);
        assert_eq!(
            p(&[("transfer-encoding", "chunked")], Body::empty()).unwrap(),
            Presence::Unsized
        );
        assert_eq!(
            p(
                &[("transfer-encoding", "chunked"), ("content-length", "0")],
                Body::empty()
            )
            .unwrap(),
            Presence::Unsized
        );
        assert_eq!(
            p(&[("content-length", "0")], Body::empty()).unwrap(),
            Presence::Empty
        );
        assert_eq!(
            p(&[("content-length", "5")], Body::from("hello")).unwrap(),
            Presence::Sized(5)
        );
        assert_eq!(p(&[], Body::empty()).unwrap(), Presence::Missing);
        assert_eq!(p(&[], Body::from("abc")).unwrap(), Presence::Unsized);
        for bad in ["abc", "-1", "1.5", ""] {
            let err = p(&[("content-length", bad)], Body::empty()).unwrap_err();
            assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{bad:?}");
            assert_eq!(err.message(), Some("invalid content-length"));
        }
    }

    #[test]
    fn length_check() {
        let err = check_length(Presence::Sized(11), Some(10)).unwrap_err();
        assert_eq!(err.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.error_name(), Some("PayloadTooLarge"));
        assert_eq!(err.message(), Some("request entity too large"));
        assert!(check_length(Presence::Sized(10), Some(10)).is_ok());
        assert!(check_length(Presence::Sized(u64::MAX), None).is_ok());
        assert!(check_length(Presence::Unsized, Some(0)).is_ok());
        assert!(check_length(Presence::Empty, Some(0)).is_ok());
    }

    #[tokio::test]
    async fn no_body_expected() {
        let unexpected = "A request body was provided when none was expected";
        assert!(
            expect_no_body(Presence::Missing, Body::empty())
                .await
                .is_ok()
        );
        assert!(expect_no_body(Presence::Empty, Body::empty()).await.is_ok());
        let err = expect_no_body(Presence::Sized(3), Body::from("abc"))
            .await
            .unwrap_err();
        assert_eq!(err.message(), Some(unexpected));
        assert!(
            expect_no_body(Presence::Unsized, Body::empty())
                .await
                .is_ok()
        );
        let empty_chunks: Vec<Result<Bytes, std::io::Error>> =
            vec![Ok(Bytes::new()), Ok(Bytes::new())];
        assert!(
            expect_no_body(
                Presence::Unsized,
                Body::from_stream(futures::stream::iter(empty_chunks))
            )
            .await
            .is_ok()
        );
        let err = expect_no_body(Presence::Unsized, chunked_body(b"unexpected", 3))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(err.message(), Some(unexpected));

        let failing: Vec<Result<Bytes, std::io::Error>> =
            vec![Err(std::io::Error::other("read failed"))];
        let err = expect_no_body(
            Presence::Unsized,
            Body::from_stream(futures::stream::iter(failing)),
        )
        .await
        .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        assert!(
            err.message()
                .unwrap()
                .starts_with("Failed to process unexpected request body")
        );
    }

    #[test]
    fn decoder_selection() {
        assert!(decoder(&HeaderMap::new()).unwrap().is_none());
        assert!(
            decoder(&headers(&[("content-encoding", "identity")]))
                .unwrap()
                .is_none()
        );
        assert!(
            decoder(&headers(&[("content-encoding", "identity, IDENTITY")]))
                .unwrap()
                .is_none()
        );
        assert!(
            decoder(&headers(&[("content-encoding", "")]))
                .unwrap()
                .is_none()
        );
        for ok in [
            "gzip", "x-gzip", "deflate", "br", "GZIP", "Br", " gzip ", "gzip, br",
        ] {
            assert!(
                decoder(&headers(&[("content-encoding", ok)]))
                    .unwrap()
                    .is_some(),
                "{ok}"
            );
        }
    }

    #[test]
    fn unsupported_content_encoding() {
        for bad in ["compress", "zstd", "gzip, compress", "*", "gzip;q=1"] {
            let err = decoder_err(bad);
            assert_eq!(
                err.status_code(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{bad}"
            );
            assert_eq!(err.message(), Some("unsupported content-encoding"));
        }
    }

    #[test]
    fn empty_coding_in_list_is_unsupported() {
        for bad in ["gzip,", "gzip, , br", ",gzip"] {
            let err = decoder_err(bad);
            assert_eq!(
                err.status_code(),
                StatusCode::UNSUPPORTED_MEDIA_TYPE,
                "{bad}"
            );
        }
    }

    #[tokio::test]
    async fn decodes_each_coding() {
        let bytes = pseudo_random(1024);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("identity", bytes.clone()),
            ("gzip", gzip(&bytes)),
            ("x-gzip", gzip(&bytes)),
            ("GZIP", gzip(&bytes)),
            ("deflate", deflate(&bytes)),
            ("Deflate", deflate(&bytes)),
            ("br", brotli(&bytes, 11)),
            ("BR", brotli(&bytes, 11)),
        ];
        for (encoding, encoded) in cases {
            for chunk in [1, 7, usize::MAX] {
                let out = decode(encoding, &encoded, chunk, None).await.unwrap();
                assert_eq!(out.as_ref(), bytes.as_slice(), "{encoding} chunk={chunk}");
            }
        }
    }

    #[tokio::test]
    async fn decodes_stacked_codings() {
        let bytes = pseudo_random(1024);
        let encoded = brotli(&deflate(&gzip(&bytes)), 11);
        for chunk in [1, 13, usize::MAX] {
            let out = decode(
                "gzip, identity, deflate, identity, br, identity",
                &encoded,
                chunk,
                None,
            )
            .await
            .unwrap();
            assert_eq!(out.as_ref(), bytes.as_slice());
        }
    }

    #[tokio::test]
    async fn decodes_codings_across_header_lines() {
        let bytes = pseudo_random(512);
        let encoded = brotli(&gzip(&bytes), 5);
        let dec = decoder(&headers(&[
            ("content-encoding", "gzip"),
            ("content-encoding", "br"),
        ]))
        .unwrap();
        let out = BodyStream::new(chunked_body(&encoded, 5), dec, None)
            .collect()
            .await
            .unwrap();
        assert_eq!(out.as_ref(), bytes.as_slice());
    }

    #[tokio::test]
    async fn decodes_concatenated_gzip_members() {
        let mut encoded = gzip(b"hello ");
        encoded.extend(gzip(b"world"));
        assert_eq!(
            decode("gzip", &encoded, 3, None).await.unwrap().as_ref(),
            b"hello world"
        );
    }

    #[tokio::test]
    async fn decodes_empty_compressed_bodies() {
        for (encoding, encoded) in [
            ("gzip", gzip(b"")),
            ("deflate", deflate(b"")),
            ("br", brotli(b"", 11)),
        ] {
            for chunk in [1, usize::MAX] {
                let out = decode(encoding, &encoded, chunk, None).await.unwrap();
                assert!(out.is_empty(), "{encoding}");
            }
        }
        assert!(decode("identity", b"", 1, None).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn corrupt_data_is_invalid_request() {
        let bytes = pseudo_random(1024);
        let cases: Vec<(&str, Vec<u8>)> = vec![
            ("gzip", brotli(&bytes, 11)),
            ("deflate", gzip(&bytes)),
            ("br", gzip(&bytes)),
            ("gzip", b"definitely not gzip".to_vec()),
            ("deflate", b"definitely not zlib".to_vec()),
            ("br", vec![0xff; 64]),
        ];
        for (encoding, encoded) in cases {
            let err = decode(encoding, &encoded, 16, None).await.unwrap_err();
            assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{encoding}");
            assert_eq!(err.error_name(), Some("InvalidRequest"));
        }
    }

    #[tokio::test]
    async fn truncated_data_is_invalid_request() {
        let bytes = pseudo_random(4096);
        for (encoding, encoded) in [
            ("gzip", gzip(&bytes)),
            ("deflate", deflate(&bytes)),
            ("br", brotli(&bytes, 11)),
        ] {
            for cut in [1, 8, encoded.len() / 2] {
                let truncated = &encoded[..encoded.len() - cut];
                let result = decode(encoding, truncated, 64, None).await;
                let err = result.expect_err(&format!("{encoding} cut={cut} decoded"));
                assert_eq!(
                    err.status_code(),
                    StatusCode::BAD_REQUEST,
                    "{encoding} cut={cut}"
                );
            }
        }
    }

    #[tokio::test]
    async fn broken_connection_is_invalid_request() {
        let chunks: Vec<Result<Bytes, std::io::Error>> = vec![
            Ok(Bytes::from_static(b"abc")),
            Err(std::io::Error::other("connection reset")),
        ];
        let body = Body::from_stream(futures::stream::iter(chunks));
        let err = BodyStream::new(body, None, None)
            .collect()
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn limit_applies_to_raw_bodies() {
        let bytes = pseudo_random(5000);
        assert_eq!(
            decode("identity", &bytes, 999, Some(5000))
                .await
                .unwrap()
                .len(),
            5000
        );
        let err = decode("identity", &bytes, 999, Some(4999))
            .await
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
        assert_eq!(err.message(), Some("request entity too large"));
        assert_eq!(
            decode("identity", &bytes, usize::MAX, Some(5000))
                .await
                .unwrap()
                .len(),
            5000
        );
        assert!(
            decode("identity", &bytes, usize::MAX, Some(4999))
                .await
                .is_err()
        );
        assert!(
            decode("identity", b"", 1, Some(0))
                .await
                .unwrap()
                .is_empty()
        );
        assert!(decode("identity", b"x", 1, Some(0)).await.is_err());
    }

    #[tokio::test]
    async fn limit_applies_to_decoded_bytes() {
        let zeros = vec![0u8; 10_000];
        for (encoding, encoded) in [
            ("gzip", gzip(&zeros)),
            ("deflate", deflate(&zeros)),
            ("br", brotli(&zeros, 11)),
        ] {
            assert!(encoded.len() < 1000);
            for chunk in [1, usize::MAX] {
                let out = decode(encoding, &encoded, chunk, Some(10_000))
                    .await
                    .unwrap();
                assert_eq!(out.len(), 10_000, "{encoding}");
                let err = decode(encoding, &encoded, chunk, Some(9_999))
                    .await
                    .unwrap_err();
                assert_eq!(
                    err.status_code(),
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "{encoding}"
                );
                assert_eq!(err.message(), Some("request entity too large"));
            }
        }
    }

    #[tokio::test]
    async fn read_limited_reads_whole_body() {
        let dec = decoder(&headers(&[("content-encoding", "gzip")])).unwrap();
        let out = read_limited(chunked_body(&gzip(b"{\"a\":1}"), 2), dec, 7)
            .await
            .unwrap();
        assert_eq!(out.as_ref(), b"{\"a\":1}");
        let dec = decoder(&headers(&[("content-encoding", "gzip")])).unwrap();
        assert!(
            read_limited(chunked_body(&gzip(b"{\"a\":1}"), 2), dec, 6)
                .await
                .is_err()
        );
    }

    #[tokio::test]
    async fn decompression_bomb_is_bounded() {
        let zeros = vec![0u8; 64 * 1024 * 1024];
        let limit = 1024 * 1024;
        for (encoding, encoded) in [("gzip", gzip(&zeros)), ("br", brotli(&zeros, 1))] {
            assert!(encoded.len() < 1024 * 1024);
            let mut s = stream(encoding, &encoded, 1024, Some(limit));
            let mut total = 0u64;
            let mut failure = None;
            while let Some(item) = s.next().await {
                match item {
                    Ok(chunk) => {
                        assert!(chunk.len() <= DECODE_CHUNK, "{encoding}: {}", chunk.len());
                        total += chunk.len() as u64;
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
            let err = failure.unwrap_or_else(|| panic!("{encoding}: no error"));
            assert_eq!(err.status_code(), StatusCode::PAYLOAD_TOO_LARGE);
            assert!(total <= limit, "{encoding}: {total}");
            assert!(s.next().await.is_none());
        }
    }

    #[tokio::test]
    async fn decoded_chunks_are_bounded_without_limit() {
        let zeros = vec![0u8; 1024 * 1024];
        let encoded = gzip(&zeros);
        let mut s = stream("gzip", &encoded, usize::MAX, None);
        let mut total = 0;
        while let Some(chunk) = s.next().await {
            let chunk = chunk.unwrap();
            assert!(chunk.len() <= DECODE_CHUNK);
            total += chunk.len();
        }
        assert_eq!(total, zeros.len());
    }

    #[tokio::test]
    async fn input_accessors() {
        let input = Input {
            encoding: "application/json".into(),
            body: InputBody::Json(json!({"a": 1})),
        };
        assert_eq!(input.bytes().await.unwrap().as_ref(), br#"{"a":1}"#);

        let input = Input {
            encoding: "text/plain".into(),
            body: InputBody::Text("{\"a\":2}".into()),
        };
        assert_eq!(
            input.json::<serde_json::Value>().await.unwrap(),
            json!({"a": 2})
        );

        let dec = decoder(&headers(&[("content-encoding", "gzip")])).unwrap();
        let body = InputBody::Stream(BodyStream::new(
            chunked_body(&gzip(b"{\"a\":3}"), 1),
            dec,
            None,
        ));
        let input = Input {
            encoding: "application/json".into(),
            body,
        };
        assert_eq!(
            input.json::<serde_json::Value>().await.unwrap(),
            json!({"a": 3})
        );

        let input = Input {
            encoding: "application/json".into(),
            body: InputBody::Json(json!({"a": "x"})),
        };
        #[derive(Debug, serde::Deserialize)]
        struct A {
            #[allow(dead_code)]
            a: i64,
        }
        assert_eq!(
            input.json::<A>().await.unwrap_err().status_code(),
            StatusCode::BAD_REQUEST
        );
    }

    #[test]
    fn default_limits() {
        let l = PayloadLimits::default();
        assert_eq!(
            (l.json, l.text, l.blob),
            (100 * 1024, 100 * 1024, Some(5 * 1024 * 1024))
        );
    }
}
