//! Canonical DAG-CBOR encoding of atproto records delivered as JSON.
//!
//! The live Jetstream wire delivers each commit's `record` as atproto dag-json
//! (a [`serde_json::Value`]), whereas the archive delivers records already in
//! canonical DAG-CBOR. To give both transports one record representation — and
//! to recompute a record's CID when the wire did not carry one — we convert the
//! JSON form to the *same* canonical DAG-CBOR the archive would carry, using
//! [`crate::cbor::json::json_to_drisl`]. Any `i64` is accepted, since records
//! already on the network may predate the safe-integer rule.

use super::error::{Error, Result};
use crate::cbor::CborError;
use crate::cbor::json::{Integers, json_to_drisl};
use serde_json::Value;

/// Convert an atproto record's dag-json [`Value`] to canonical DAG-CBOR bytes.
pub fn record_json_to_dag_cbor(value: &Value) -> Result<Vec<u8>> {
    json_to_drisl(value, Integers::Any).map_err(|err| match err {
        CborError::DataModel(_) => {
            Error::InvalidRecord("record JSON is outside the atproto data model")
        }
        CborError::InvalidCid(_) => Error::InvalidRecord("record JSON links an unsupported CID"),
        CborError::InvalidCbor(_) | CborError::Io(_) => {
            Error::InvalidRecord("record JSON cannot be encoded")
        }
    })
}

/// Reject duplicate object keys anywhere inside a raw JSON value.
///
/// `serde_json::Value` resolves duplicate keys silently (last wins), so by the
/// time a record reaches [`record_json_to_dag_cbor`] a hostile duplicate has
/// already rewritten it — the canonical bytes (and any CID computed over them)
/// would silently differ from what the record was published under. The Go
/// client's `cbor.FromJSON` rejects such records outright; the live parser runs
/// this check over the record's raw text to match.
pub(crate) fn reject_duplicate_keys(raw: &str) -> Result<()> {
    let mut de = serde_json::Deserializer::from_str(raw);
    serde::de::DeserializeSeed::deserialize(DupCheck, &mut de)
        .map_err(|_| Error::InvalidRecord("record JSON has duplicate keys"))
}

/// A deserialize seed that walks any JSON value, erroring on a duplicate key
/// within any object. Values are otherwise discarded.
struct DupCheck;

impl<'de> serde::de::DeserializeSeed<'de> for DupCheck {
    type Value = ();

    fn deserialize<D: serde::Deserializer<'de>>(
        self,
        deserializer: D,
    ) -> core::result::Result<(), D::Error> {
        deserializer.deserialize_any(DupCheckVisitor)
    }
}

struct DupCheckVisitor;

impl<'de> serde::de::Visitor<'de> for DupCheckVisitor {
    type Value = ();

    fn expecting(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E>(self, _: bool) -> core::result::Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> core::result::Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> core::result::Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> core::result::Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> core::result::Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> core::result::Result<(), E> {
        Ok(())
    }

    fn visit_seq<A: serde::de::SeqAccess<'de>>(
        self,
        mut seq: A,
    ) -> core::result::Result<(), A::Error> {
        while seq.next_element_seed(DupCheck)?.is_some() {}
        Ok(())
    }

    fn visit_map<A: serde::de::MapAccess<'de>>(
        self,
        mut map: A,
    ) -> core::result::Result<(), A::Error> {
        let mut keys = std::collections::HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !keys.insert(key) {
                return Err(serde::de::Error::custom("duplicate object key"));
            }
            map.next_value_seed(DupCheck)?;
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

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
    fn accepts_any_i64() {
        for text in [
            "9223372036854775807",
            "-9223372036854775808",
            "9007199254740993",
        ] {
            let json: Value = serde_json::from_str(text).unwrap();
            assert!(record_json_to_dag_cbor(&json).is_ok(), "{text}");
        }
    }

    #[test]
    fn rejects_floats_out_of_range_numbers_and_unsupported_cids() {
        for text in [
            "1.5",
            "9223372036854775808",
            "18446744073709551616",
            r#"{"$link": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}"#,
        ] {
            let json: Value = serde_json::from_str(text).unwrap();
            assert!(
                matches!(record_json_to_dag_cbor(&json), Err(Error::InvalidRecord(_))),
                "{text}"
            );
        }
    }

    /// Malformed `$link` and `$bytes` objects are plain maps, as in the
    /// reference, so the record still round-trips.
    #[test]
    fn malformed_link_and_bytes_are_plain_maps() {
        for json in [
            serde_json::json!({"$link": "not-a-cid"}),
            serde_json::json!({"$bytes": "!!!not base64!!!"}),
            serde_json::json!({"$bytes": 5}),
        ] {
            let cbor = record_json_to_dag_cbor(&json).unwrap();
            assert_eq!(super::super::record_cbor_to_json(&cbor).unwrap(), json);
        }
    }

    #[test]
    fn duplicate_keys_are_rejected() {
        // Top level, nested, and inside arrays; unique keys pass.
        assert!(reject_duplicate_keys(r#"{"a":1,"a":2}"#).is_err());
        assert!(reject_duplicate_keys(r#"{"outer":{"a":1,"a":2}}"#).is_err());
        assert!(reject_duplicate_keys(r#"[{"a":1},{"a":1,"a":2}]"#).is_err());
        assert!(reject_duplicate_keys(r#"{"a":1,"b":{"a":1},"c":[1,"x",null]}"#).is_ok());
        assert!(reject_duplicate_keys(r#""just a string""#).is_ok());
    }
}
