//! Canonical DAG-CBOR encoding of atproto records delivered as JSON.
//!
//! The live Jetstream wire delivers each commit's `record` as atproto dag-json
//! (a [`serde_json::Value`]), whereas the archive delivers records already in
//! canonical DAG-CBOR. To give both transports one record representation — and
//! to recompute a record's CID when the wire did not carry one — we convert the
//! JSON form to the *same* canonical DAG-CBOR the archive would carry.
//!
//! The conversion follows the atproto data model and its dag-json conventions:
//!
//! - an object with the single key `$bytes` whose value is a base64 string is a
//!   byte string (CBOR major type 2);
//! - an object with the single key `$link` whose value is a CID string is a
//!   CID link (CBOR tag 42);
//! - every other object is a map, its keys emitted in canonical order
//!   (length-first, then bytewise), matching [`crate::cbor::encode_value`];
//! - numbers must be integers within the `i64`/`u64` range — the atproto data
//!   model has no floats, so a fractional or out-of-range number is rejected;
//! - strings, booleans, null, and arrays map directly.
//!
//! The output is byte-for-byte identical to what shrike's own canonical CBOR
//! encoder produces for the same logical value, so a CID computed over it
//! matches the CID the record was published under.

use super::error::{Error, Result};
use crate::cbor::{Cid, Encoder, cbor_key_cmp};
use serde_json::Value;

/// Convert an atproto record's dag-json [`Value`] to canonical DAG-CBOR bytes.
pub fn record_json_to_dag_cbor(value: &Value) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    encode(value, &mut buf)?;
    Ok(buf)
}

fn encode(value: &Value, buf: &mut Vec<u8>) -> Result<()> {
    match value {
        Value::Null => Encoder::new(&mut *buf)
            .encode_null()
            .map_err(|_| Error::InvalidRecord("cbor null"))?,
        Value::Bool(b) => Encoder::new(&mut *buf)
            .encode_bool(*b)
            .map_err(|_| Error::InvalidRecord("cbor bool"))?,
        Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                Encoder::new(&mut *buf)
                    .encode_i64(i)
                    .map_err(|_| Error::InvalidRecord("cbor int"))?;
            } else if let Some(u) = n.as_u64() {
                Encoder::new(&mut *buf)
                    .encode_u64(u)
                    .map_err(|_| Error::InvalidRecord("cbor uint"))?;
            } else {
                // A float or an integer outside [i64::MIN, u64::MAX]. The
                // atproto data model only permits integers in the signed 64-bit
                // range, so anything else is not a valid record value.
                return Err(Error::InvalidRecord("non-integer number"));
            }
        }
        Value::String(s) => Encoder::new(&mut *buf)
            .encode_text(s)
            .map_err(|_| Error::InvalidRecord("cbor text"))?,
        Value::Array(items) => {
            Encoder::new(&mut *buf)
                .encode_array_header(items.len() as u64)
                .map_err(|_| Error::InvalidRecord("cbor array header"))?;
            for item in items {
                encode(item, buf)?;
            }
        }
        Value::Object(map) => {
            // Special dag-json forms: a single-key `$bytes` or `$link` object.
            if map.len() == 1 {
                if let Some(v) = map.get("$bytes") {
                    let s = v
                        .as_str()
                        .ok_or(Error::InvalidRecord("$bytes value is not a string"))?;
                    let bytes = decode_base64(s)?;
                    Encoder::new(&mut *buf)
                        .encode_bytes(&bytes)
                        .map_err(|_| Error::InvalidRecord("cbor bytes"))?;
                    return Ok(());
                }
                if let Some(v) = map.get("$link") {
                    let s = v
                        .as_str()
                        .ok_or(Error::InvalidRecord("$link value is not a string"))?;
                    let cid: Cid = s
                        .parse()
                        .map_err(|_| Error::InvalidRecord("$link is not a valid CID"))?;
                    Encoder::new(&mut *buf)
                        .encode_cid(&cid)
                        .map_err(|_| Error::InvalidRecord("cbor cid"))?;
                    return Ok(());
                }
            }

            // A plain map. Emit keys in canonical DAG-CBOR order.
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_by(|a, b| cbor_key_cmp(a, b));
            Encoder::new(&mut *buf)
                .encode_map_header(keys.len() as u64)
                .map_err(|_| Error::InvalidRecord("cbor map header"))?;
            for key in keys {
                Encoder::new(&mut *buf)
                    .encode_text(key)
                    .map_err(|_| Error::InvalidRecord("cbor map key"))?;
                // `keys` came from `map`, so this lookup always succeeds.
                if let Some(v) = map.get(key) {
                    encode(v, buf)?;
                }
            }
        }
    }
    Ok(())
}

/// Decode a dag-json `$bytes` payload. The data model specifies standard base64
/// without padding (RFC 4648 §4); we also accept the padded alphabet for
/// robustness across producers, since either decodes to identical bytes.
fn decode_base64(s: &str) -> Result<Vec<u8>> {
    if let Ok(raw) = data_encoding::BASE64.decode(s.as_bytes()) {
        return Ok(raw);
    }
    data_encoding::BASE64_NOPAD
        .decode(s.as_bytes())
        .map_err(|_| Error::InvalidRecord("$bytes is not valid base64"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cbor::{Codec, Value as CborValue, encode_value};

    /// The conversion must be byte-for-byte identical to shrike's own canonical
    /// encoder for the same logical value, and CIDs computed over each must
    /// therefore match. Keys are supplied out of canonical order to prove the
    /// converter sorts them.
    #[test]
    fn json_and_cbor_encoders_agree_byte_for_byte() {
        // A CID string to exercise the `$link` form.
        let link = Cid::compute(Codec::Drisl, b"linked record");
        let json = serde_json::json!({
            "text": "hello",
            "count": 5,
            "negative": -3,
            "flag": true,
            "nothing": null,
            "nested": {"b": 2, "a": 1},
            "list": [1, 2, 3],
            "blob": {"$bytes": data_encoding::BASE64_NOPAD.encode(&[0xDE, 0xAD, 0xBE, 0xEF])},
            "ref": {"$link": link.to_string()},
        });

        // The same logical value expressed directly as a canonical CBOR tree.
        let value = CborValue::Map(vec![
            ("text", CborValue::Text("hello")),
            ("count", CborValue::Unsigned(5)),
            ("negative", CborValue::Signed(-3)),
            ("flag", CborValue::Bool(true)),
            ("nothing", CborValue::Null),
            (
                "nested",
                CborValue::Map(vec![
                    ("b", CborValue::Unsigned(2)),
                    ("a", CborValue::Unsigned(1)),
                ]),
            ),
            (
                "list",
                CborValue::Array(vec![
                    CborValue::Unsigned(1),
                    CborValue::Unsigned(2),
                    CborValue::Unsigned(3),
                ]),
            ),
            ("blob", CborValue::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])),
            ("ref", CborValue::Cid(link)),
        ]);

        let from_json = record_json_to_dag_cbor(&json).unwrap();
        let from_value = encode_value(&value).unwrap();
        assert_eq!(from_json, from_value, "canonical bytes must match");

        // CID parity follows from byte parity, but assert it explicitly.
        assert_eq!(
            Cid::compute(Codec::Drisl, &from_json),
            Cid::compute(Codec::Drisl, &from_value),
        );
    }

    /// Canonicalized bytes decode with a generated lexicon type, proving the
    /// live JSON path lands in the exact archive record representation.
    #[test]
    fn canonicalized_record_decodes_with_generated_api() {
        use crate::api::app::bsky::FeedPost;

        let json = serde_json::json!({
            "$type": "app.bsky.feed.post",
            "text": "hello world",
            "createdAt": "2024-01-01T00:00:00.000Z",
        });
        let cbor = record_json_to_dag_cbor(&json).unwrap();
        let post = FeedPost::from_cbor(&cbor).expect("decodes as FeedPost");
        assert_eq!(post.text, "hello world");
        assert_eq!(post.created_at.as_str(), "2024-01-01T00:00:00.000Z");
    }

    #[test]
    fn padded_and_unpadded_bytes_are_accepted() {
        let raw = [0x01, 0x02, 0x03];
        let padded = serde_json::json!({"$bytes": data_encoding::BASE64.encode(&raw)});
        let unpadded = serde_json::json!({"$bytes": data_encoding::BASE64_NOPAD.encode(&raw)});
        assert_eq!(
            record_json_to_dag_cbor(&padded).unwrap(),
            record_json_to_dag_cbor(&unpadded).unwrap(),
        );
    }

    #[test]
    fn rejects_floats_and_out_of_range_numbers() {
        assert!(matches!(
            record_json_to_dag_cbor(&serde_json::json!(1.5)),
            Err(Error::InvalidRecord(_))
        ));
        // Larger than u64::MAX: serde_json keeps it as an arbitrary-precision
        // number that is neither as_i64 nor as_u64.
        let huge: serde_json::Value =
            serde_json::from_str("18446744073709551616").expect("parses as number");
        assert!(matches!(
            record_json_to_dag_cbor(&huge),
            Err(Error::InvalidRecord(_))
        ));
    }

    #[test]
    fn rejects_invalid_link_and_bytes() {
        assert!(matches!(
            record_json_to_dag_cbor(&serde_json::json!({"$link": "not-a-cid"})),
            Err(Error::InvalidRecord(_))
        ));
        assert!(matches!(
            record_json_to_dag_cbor(&serde_json::json!({"$bytes": "!!!not base64!!!"})),
            Err(Error::InvalidRecord(_))
        ));
        assert!(matches!(
            record_json_to_dag_cbor(&serde_json::json!({"$bytes": 5})),
            Err(Error::InvalidRecord(_))
        ));
    }

    /// A map that merely *contains* `$bytes`/`$link` among other keys is a plain
    /// map, not the special form.
    #[test]
    fn multi_key_object_with_dollar_key_is_plain_map() {
        let link = Cid::compute(Codec::Drisl, b"x").to_string();
        let json = serde_json::json!({"$link": link, "extra": 1});
        let value = CborValue::Map(vec![
            ("$link", CborValue::Text(&link)),
            ("extra", CborValue::Unsigned(1)),
        ]);
        assert_eq!(
            record_json_to_dag_cbor(&json).unwrap(),
            encode_value(&value).unwrap(),
        );
    }
}
