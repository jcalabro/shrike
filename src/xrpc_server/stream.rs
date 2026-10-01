//! Event-stream frames for XRPC subscriptions.
//!
//! Each WebSocket binary message is two concatenated DAG-CBOR values: a
//! header (`{"t": "#commit", "op": 1}` for messages, `{"op": -1}` for errors)
//! and a body (the message, or `{"error", "message"?}`).

use serde_json::Value;

use crate::cbor::json::{Integers, json_to_drisl};
use crate::cbor::{CborError, Decoder, Encoder, Value as Cbor};
use crate::xrpc_server::error::ServerError;

/// One subscription frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// A message. `t` is its type: `#name` for a def of the subscription's
    /// own lexicon, or a full `nsid#name` otherwise. `body` is DAG-CBOR.
    Message {
        /// The message type.
        t: Option<String>,
        /// The DAG-CBOR message body, without `$type`.
        body: Vec<u8>,
    },
    /// An error. The server closes the stream after sending one.
    Error {
        /// The XRPC error name.
        error: String,
        /// A human-readable message.
        message: Option<String>,
    },
}

/// A frame that could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct FrameError(String);

impl Frame {
    /// A message of type `t` with a DAG-CBOR `body`, e.g. from a generated
    /// type's `to_cbor()`.
    pub fn message(t: impl Into<String>, body: Vec<u8>) -> Self {
        Frame::Message {
            t: Some(t.into()),
            body,
        }
    }

    /// A message from atproto JSON (`$link`, `$bytes`). Its `$type` becomes
    /// `t` (as `#name` when it names a def of `nsid`) and is removed from the
    /// body, as the reference `MessageFrame.fromLexValue` does.
    pub fn from_json(nsid: &str, value: &Value) -> Result<Self, CborError> {
        let mut value = value.clone();
        let mut t = None;
        if let Value::Object(map) = &mut value
            && let Some(Value::String(type_name)) = map.get("$type")
        {
            t = Some(match type_name.split_once('#') {
                Some((prefix, def))
                    if !def.contains('#') && (prefix.is_empty() || prefix == nsid) =>
                {
                    format!("#{def}")
                }
                _ => type_name.clone(),
            });
            map.remove("$type");
        }
        Ok(Frame::Message {
            t,
            body: json_to_drisl(&value, Integers::Any)?,
        })
    }

    /// An error frame.
    pub fn error(error: impl Into<String>, message: Option<String>) -> Self {
        Frame::Error {
            error: error.into(),
            message,
        }
    }

    /// The error frame for a [`ServerError`]: its name and public message,
    /// so a 500's detail is not sent.
    pub fn from_server_error(err: &ServerError) -> Self {
        Frame::error(
            err.error_name().unwrap_or("Unknown"),
            err.public_message().map(str::to_owned),
        )
    }

    /// Encode as one WebSocket message.
    pub fn encode(&self) -> Result<Vec<u8>, CborError> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        match self {
            Frame::Message { t, body } => {
                // Canonical key order: "t" sorts before "op".
                match t {
                    Some(t) => {
                        enc.encode_map_header(2)?;
                        enc.encode_text("t")?;
                        enc.encode_text(t)?;
                    }
                    None => enc.encode_map_header(1)?,
                }
                enc.encode_text("op")?;
                enc.encode_i64(1)?;
                buf.extend_from_slice(body);
            }
            Frame::Error { error, message } => {
                enc.encode_map_header(1)?;
                enc.encode_text("op")?;
                enc.encode_i64(-1)?;
                enc.encode_map_header(if message.is_some() { 2 } else { 1 })?;
                enc.encode_text("error")?;
                enc.encode_text(error)?;
                if let Some(message) = message {
                    enc.encode_text("message")?;
                    enc.encode_text(message)?;
                }
            }
        }
        Ok(buf)
    }

    /// Decode one WebSocket message.
    pub fn decode(bytes: &[u8]) -> Result<Self, FrameError> {
        let mut dec = Decoder::new(bytes);
        let header = dec
            .decode()
            .map_err(|e| FrameError(format!("Invalid frame header: {e}")))?;
        let body_start = dec.position();
        if dec.is_empty() {
            return Err(FrameError("Missing frame body".into()));
        }
        let body = dec
            .decode()
            .map_err(|e| FrameError(format!("Invalid frame body: {e}")))?;
        if !dec.is_empty() {
            return Err(FrameError("Too many CBOR data items in frame".into()));
        }

        let Cbor::Map(entries) = header else {
            return Err(FrameError("Invalid frame header: not a map".into()));
        };
        let mut op = None;
        let mut t = None;
        for (key, value) in entries {
            match (key, value) {
                ("op", Cbor::Unsigned(1)) => op = Some(1),
                ("op", Cbor::Signed(-1)) => op = Some(-1),
                ("op", _) => return Err(FrameError("Invalid frame header: bad op".into())),
                ("t", Cbor::Text(s)) => t = Some(s.to_owned()),
                ("t", _) => return Err(FrameError("Invalid frame header: bad t".into())),
                _ => {}
            }
        }
        match op {
            Some(1) => Ok(Frame::Message {
                t,
                body: bytes[body_start..].to_vec(),
            }),
            Some(_) => {
                let invalid = || FrameError("Invalid error frame body".into());
                let Cbor::Map(entries) = body else {
                    return Err(invalid());
                };
                let mut error = None;
                let mut message = None;
                for (key, value) in entries {
                    match (key, value) {
                        ("error", Cbor::Text(s)) => error = Some(s.to_owned()),
                        ("error", _) => return Err(invalid()),
                        ("message", Cbor::Text(s)) => message = Some(s.to_owned()),
                        ("message", _) => return Err(invalid()),
                        _ => {}
                    }
                }
                Ok(Frame::Error {
                    error: error.ok_or_else(invalid)?,
                    message,
                })
            }
            None => Err(FrameError("Invalid frame header: missing op".into())),
        }
    }

    /// A message body as atproto JSON, with `$type` restored from `t`
    /// (relative to `nsid`).
    pub fn to_json(&self, nsid: &str) -> Result<Option<Value>, CborError> {
        let Frame::Message { t, body } = self else {
            return Ok(None);
        };
        let mut value = crate::cbor::json::drisl_to_json(body)?;
        if let (Some(t), Value::Object(map)) = (t, &mut value) {
            let type_name = if t.starts_with('#') {
                format!("{nsid}{t}")
            } else {
                t.clone()
            };
            map.insert("$type".into(), Value::String(type_name));
        }
        Ok(Some(value))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use http::StatusCode;
    use serde_json::json;

    const MESSAGE_HEADER: [u8; 10] = [162, 97, 116, 98, 35, 100, 98, 111, 112, 1];
    const MESSAGE_BODY: [u8; 11] = [162, 97, 97, 97, 98, 97, 99, 131, 1, 2, 3];
    const ERROR_FRAME: &[u8] = &[
        161, 98, 111, 112, 32, 162, 101, 101, 114, 114, 111, 114, 103, 66, 105, 103, 79, 111, 112,
        115, 103, 109, 101, 115, 115, 97, 103, 101, 115, 83, 111, 109, 101, 116, 104, 105, 110,
        103, 32, 119, 101, 110, 116, 32, 97, 119, 114, 121,
    ];

    fn message_frame_bytes() -> Vec<u8> {
        [MESSAGE_HEADER.as_slice(), MESSAGE_BODY.as_slice()].concat()
    }

    fn decode_err(bytes: &[u8]) -> String {
        Frame::decode(bytes).unwrap_err().to_string()
    }

    #[test]
    fn message_frame_bytes_match_reference() {
        let body = json_to_drisl(&json!({"a": "b", "c": [1, 2, 3]}), Integers::Any).unwrap();
        assert_eq!(body, MESSAGE_BODY);
        let frame = Frame::message("#d", body);
        assert_eq!(frame.encode().unwrap(), message_frame_bytes());
    }

    #[test]
    fn message_frame_round_trip() {
        let frame = Frame::decode(&message_frame_bytes()).unwrap();
        assert_eq!(frame, Frame::message("#d", MESSAGE_BODY.to_vec()));
        assert_eq!(frame.encode().unwrap(), message_frame_bytes());
        assert_eq!(
            frame.to_json("com.example.sub").unwrap().unwrap(),
            json!({"$type": "com.example.sub#d", "a": "b", "c": [1, 2, 3]})
        );
    }

    #[test]
    fn message_frame_without_type() {
        let frame = Frame::Message {
            t: None,
            body: MESSAGE_BODY.to_vec(),
        };
        let bytes = frame.encode().unwrap();
        assert_eq!(&bytes[..5], &[161, 98, 111, 112, 1]);
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
        assert_eq!(
            frame.to_json("com.example.sub").unwrap().unwrap(),
            json!({"a": "b", "c": [1, 2, 3]})
        );
    }

    #[test]
    fn error_frame_bytes_match_reference() {
        let frame = Frame::error("BigOops", Some("Something went awry".into()));
        assert_eq!(frame.encode().unwrap(), ERROR_FRAME);
        assert_eq!(Frame::decode(ERROR_FRAME).unwrap(), frame);
        assert_eq!(frame.to_json("com.example.sub").unwrap(), None);
    }

    #[test]
    fn error_frame_without_message() {
        let frame = Frame::error("BigOops", None);
        let bytes = frame.encode().unwrap();
        let mut expected = vec![161, 98, 111, 112, 32, 161, 101];
        expected.extend_from_slice(b"error");
        expected.push(103);
        expected.extend_from_slice(b"BigOops");
        assert_eq!(bytes, expected);
        assert_eq!(Frame::decode(&bytes).unwrap(), frame);
    }

    #[test]
    fn decode_rejects_non_cbor_and_empty() {
        assert!(Frame::decode(b"some utf8 bytes").is_err());
        assert!(Frame::decode(&[]).is_err());
    }

    #[test]
    fn decode_rejects_unknown_op() {
        let mut bytes = vec![161, 98, 111, 112, 33];
        bytes.extend_from_slice(&MESSAGE_BODY);
        assert!(decode_err(&bytes).starts_with("Invalid frame header:"));

        let mut bytes = vec![161, 98, 111, 112, 2];
        bytes.extend_from_slice(&MESSAGE_BODY);
        assert!(decode_err(&bytes).starts_with("Invalid frame header:"));

        let mut bytes = vec![160];
        bytes.extend_from_slice(&MESSAGE_BODY);
        assert!(decode_err(&bytes).starts_with("Invalid frame header:"));

        let mut bytes = vec![131, 1, 2, 3];
        bytes.extend_from_slice(&MESSAGE_BODY);
        assert!(decode_err(&bytes).starts_with("Invalid frame header:"));
    }

    #[test]
    fn decode_rejects_non_string_type() {
        let mut bytes = vec![162, 97, 116, 1, 98, 111, 112, 1];
        bytes.extend_from_slice(&MESSAGE_BODY);
        assert!(decode_err(&bytes).starts_with("Invalid frame header:"));
    }

    #[test]
    fn decode_rejects_missing_body() {
        assert_eq!(decode_err(&MESSAGE_HEADER), "Missing frame body");
        assert_eq!(decode_err(&ERROR_FRAME[..5]), "Missing frame body");
    }

    #[test]
    fn decode_rejects_extra_items() {
        let mut bytes = message_frame_bytes();
        bytes.extend_from_slice(&[162, 97, 100, 97, 101, 97, 102, 131, 4, 5, 6]);
        assert_eq!(decode_err(&bytes), "Too many CBOR data items in frame");
    }

    #[test]
    fn decode_rejects_invalid_error_body() {
        let bytes = [161, 98, 111, 112, 32, 161, 100, 98, 108, 97, 104, 1];
        assert!(decode_err(&bytes).starts_with("Invalid error frame body"));

        let mut bytes = vec![161, 98, 111, 112, 32, 161, 101];
        bytes.extend_from_slice(b"error");
        bytes.push(1);
        assert!(decode_err(&bytes).starts_with("Invalid error frame body"));

        let mut bytes = vec![161, 98, 111, 112, 32, 162, 101];
        bytes.extend_from_slice(b"error");
        bytes.push(97);
        bytes.push(b'x');
        bytes.push(103);
        bytes.extend_from_slice(b"message");
        bytes.push(1);
        assert!(decode_err(&bytes).starts_with("Invalid error frame body"));

        let bytes = [161, 98, 111, 112, 32, 131, 1, 2, 3];
        assert!(decode_err(&bytes).starts_with("Invalid error frame body"));
    }

    #[test]
    fn from_json_type_mapping() {
        let nsid = "com.example.sub";
        let cases = [
            ("#commit", Some("#commit")),
            ("com.example.sub#commit", Some("#commit")),
            ("com.example.other#commit", Some("com.example.other#commit")),
            ("com.example.sub", Some("com.example.sub")),
            ("com.example.other", Some("com.example.other")),
            ("com.example.sub#a#b", Some("com.example.sub#a#b")),
            ("#a#b", Some("#a#b")),
        ];
        for (type_name, expected) in cases {
            let frame = Frame::from_json(nsid, &json!({"$type": type_name, "seq": 1})).unwrap();
            let Frame::Message { t, body } = &frame else {
                panic!()
            };
            assert_eq!(t.as_deref(), expected, "{type_name}");
            assert_eq!(
                crate::cbor::json::drisl_to_json(body).unwrap(),
                json!({"seq": 1}),
                "{type_name}"
            );
        }
    }

    #[test]
    fn from_json_without_string_type() {
        let nsid = "com.example.sub";
        for value in [
            json!({"seq": 1}),
            json!({"$type": 5, "seq": 1}),
            json!(5),
            json!([1, 2]),
            json!("s"),
        ] {
            let frame = Frame::from_json(nsid, &value).unwrap();
            let Frame::Message { t, body } = &frame else {
                panic!()
            };
            assert_eq!(*t, None, "{value}");
            assert_eq!(crate::cbor::json::drisl_to_json(body).unwrap(), value);
        }
    }

    #[test]
    fn from_json_to_json_round_trip() {
        let nsid = "com.example.sub";
        for value in [
            json!({"$type": "com.example.sub#commit", "seq": 1, "blocks": {"$bytes": "AAEC"}}),
            json!({"$type": "com.example.other#info", "name": "x"}),
            json!({"$type": "com.example.other", "name": "x"}),
        ] {
            let frame = Frame::from_json(nsid, &value).unwrap();
            let decoded = Frame::decode(&frame.encode().unwrap()).unwrap();
            assert_eq!(decoded, frame);
            assert_eq!(decoded.to_json(nsid).unwrap().unwrap(), value);
        }
        let frame = Frame::from_json(nsid, &json!({"$type": "#commit", "seq": 1})).unwrap();
        assert_eq!(
            frame.to_json(nsid).unwrap().unwrap(),
            json!({"$type": "com.example.sub#commit", "seq": 1})
        );
    }

    #[test]
    fn from_server_error() {
        let frame = Frame::from_server_error(&ServerError::internal("secret detail"));
        assert_eq!(
            frame,
            Frame::error("InternalServerError", Some("Internal Server Error".into()))
        );

        let frame = Frame::from_server_error(
            &ServerError::invalid_request("bad cursor").with_name("FutureCursor"),
        );
        assert_eq!(
            frame,
            Frame::error("FutureCursor", Some("bad cursor".into()))
        );

        let frame = Frame::from_server_error(&ServerError::from_status(StatusCode::IM_A_TEAPOT));
        assert_eq!(frame, Frame::error("Unknown", None));
    }
}
