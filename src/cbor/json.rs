//! Conversion between DRISL and the atproto JSON representation.
//!
//! JSON to DRISL follows the reference `@atproto/lex-json` parser in its
//! non-strict mode:
//!
//! - a map whose only key is `$link`, holding a CID string, is a CID link;
//! - a map whose only key is `$bytes`, holding base64 (padded or not), is a
//!   byte string;
//! - every other map, including a malformed `$link` or `$bytes`, stays a plain
//!   map, its keys in canonical order;
//! - numbers must be integers; see [`Integers`].
//!
//! `serde_json` keeps the last value of a duplicated key, as the reference does.
//!
//! DRISL to JSON writes bytes as unpadded `$bytes` and CIDs as base32 `$link`.
//! The data model has no floats, so both directions reject them.
//!
//! ```
//! use shrike::cbor::json::{Integers, drisl_to_json, json_to_drisl};
//!
//! let json = serde_json::json!({"text": "hi", "raw": {"$bytes": "aGk="}});
//! let bytes = json_to_drisl(&json, Integers::Safe)?;
//! let back = drisl_to_json(&bytes)?;
//! assert_eq!(back, serde_json::json!({"text": "hi", "raw": {"$bytes": "aGk"}}));
//! # Ok::<(), shrike::cbor::CborError>(())
//! ```

use std::io::Write;

use serde_json::{Map, Number, Value as Json};

use super::varint::decode_varint;
use super::{CborError, Cid, Encoder, Value, cbor_key_cmp};

/// The largest integer a JavaScript number holds exactly: 2^53 − 1.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// The longest `$link` string parsed as a CID. Longer ones stay plain maps.
pub const MAX_LINK_LEN: usize = 2048;

/// Which JSON integers [`json_to_drisl`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integers {
    /// Only |n| ≤ [`MAX_SAFE_INTEGER`], as the reference requires of records.
    Safe,
    /// Any `i64`.
    Any,
}

/// Convert atproto JSON to canonical DRISL bytes.
///
/// Fails on a float, an integer that `integers` does not allow, or a `$link`
/// holding a well-formed CID that [`Cid`] cannot represent (anything but
/// CIDv1, DRISL or raw, SHA-256).
pub fn json_to_drisl(json: &Json, integers: Integers) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    encode(&mut Encoder::new(&mut buf), json, integers)?;
    Ok(buf)
}

/// Decode DRISL bytes to atproto JSON.
pub fn drisl_to_json(bytes: &[u8]) -> Result<Json, CborError> {
    value_to_json(&super::decode(bytes)?)
}

/// Convert a decoded DRISL value to atproto JSON.
pub fn value_to_json(value: &Value<'_>) -> Result<Json, CborError> {
    Ok(match value {
        Value::Unsigned(n) if i64::try_from(*n).is_err() => {
            return Err(CborError::DataModel(format!("integer {n} exceeds i64")));
        }
        Value::Unsigned(n) => Json::Number((*n).into()),
        Value::Signed(n) => Json::Number((*n).into()),
        Value::Float(f) => return Err(CborError::DataModel(format!("float {f}"))),
        Value::Bool(b) => Json::Bool(*b),
        Value::Null => Json::Null,
        Value::Text(s) => Json::String((*s).to_owned()),
        Value::Bytes(b) => single("$bytes", data_encoding::BASE64_NOPAD.encode(b)),
        Value::Cid(cid) => single("$link", cid.to_string()),
        Value::Array(items) => {
            Json::Array(items.iter().map(value_to_json).collect::<Result<_, _>>()?)
        }
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| Ok(((*k).to_owned(), value_to_json(v)?)))
                .collect::<Result<_, CborError>>()?,
        ),
    })
}

/// Decode `$bytes` base64: the standard alphabet, padded or not.
pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    crate::base64::decode(s)
}

/// Parse a CID string as `$link` does: CIDv0 (`Q…`), or multibase base32
/// (`b`), base58btc (`z`) or base36 (`k`), at most [`MAX_LINK_LEN`] bytes.
///
/// Fails with [`CborError::InvalidCid`] if the string is malformed or the CID
/// is well-formed but not one [`Cid`] can represent.
pub fn parse_cid(s: &str) -> Result<Cid, CborError> {
    parse_link(s)?.ok_or_else(|| CborError::InvalidCid(format!("malformed CID string {s:?}")))
}

fn single(key: &str, value: String) -> Json {
    let mut map = Map::with_capacity(1);
    map.insert(key.to_owned(), Json::String(value));
    Json::Object(map)
}

fn encode<W: Write>(
    enc: &mut Encoder<W>,
    json: &Json,
    integers: Integers,
) -> Result<(), CborError> {
    match json {
        Json::Null => enc.encode_null(),
        Json::Bool(b) => enc.encode_bool(*b),
        Json::Number(n) => enc.encode_i64(integer(n, integers)?),
        Json::String(s) => enc.encode_text(s),
        Json::Array(items) => {
            enc.encode_array_header(items.len() as u64)?;
            items
                .iter()
                .try_for_each(|item| encode(enc, item, integers))
        }
        Json::Object(map) => match special(map)? {
            Some(Special::Cid(cid)) => enc.encode_cid(&cid),
            Some(Special::Bytes(bytes)) => enc.encode_bytes(&bytes),
            None => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| cbor_key_cmp(a.0, b.0));
                enc.encode_map_header(entries.len() as u64)?;
                for (key, value) in entries {
                    enc.encode_text(key)?;
                    encode(enc, value, integers)?;
                }
                Ok(())
            }
        },
    }
}

fn integer(n: &Number, integers: Integers) -> Result<i64, CborError> {
    // JSON has one number type, so `123.0` and `1e10` are integers by value.
    let value = n.as_i64().or_else(|| {
        n.as_f64()
            .filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64)
            .map(|f| f as i64)
    });
    match (value, integers) {
        (Some(v), Integers::Any) => Ok(v),
        (Some(v), Integers::Safe) if v.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() => Ok(v),
        (Some(_), Integers::Safe) => Err(CborError::DataModel(format!(
            "{n} is outside the safe integer range"
        ))),
        (None, _) => Err(CborError::DataModel(format!(
            "{n} is not a signed 64-bit integer"
        ))),
    }
}

enum Special {
    Cid(Cid),
    Bytes(Vec<u8>),
}

fn special(map: &Map<String, Json>) -> Result<Option<Special>, CborError> {
    let mut entries = map.iter();
    let (Some((key, Json::String(s))), None) = (entries.next(), entries.next()) else {
        return Ok(None);
    };
    Ok(match key.as_str() {
        "$link" => parse_link(s)?.map(Special::Cid),
        "$bytes" => decode_base64(s).map(Special::Bytes),
        _ => None,
    })
}

/// `Ok(None)` if `s` is not a CID string, so the map stays plain.
fn parse_link(s: &str) -> Result<Option<Cid>, CborError> {
    if s.len() > MAX_LINK_LEN {
        return Ok(None);
    }
    let v0 = s.starts_with('Q');
    let bytes = if v0 {
        base_x(s, BASE58BTC)
    } else if let Some(rest) = s.strip_prefix('z') {
        base_x(rest, BASE58BTC)
    } else if let Some(rest) = s.strip_prefix('k') {
        base_x(rest, BASE36)
    } else if let Some(rest) = s.strip_prefix('b') {
        base32_lower(rest)
    } else {
        None
    };
    let Some(parts) = bytes.as_deref().and_then(|b| CidParts::parse(b, v0)) else {
        return Ok(None);
    };
    let CidParts {
        version,
        codec,
        hash,
        digest,
    } = parts;
    if version == 1 && (codec == 0x71 || codec == 0x55) && hash == 0x12 && digest.len() == 32 {
        let mut canonical = [0x01, codec as u8, 0x12, 0x20].to_vec();
        canonical.extend_from_slice(digest);
        return Cid::from_bytes(&canonical).map(Some);
    }
    Err(CborError::InvalidCid(format!(
        "unsupported CID: version {version}, codec {codec:#x}, hash {hash:#x}, {}-byte digest",
        digest.len()
    )))
}

/// A well-formed binary CID, as `multiformats` `CID.decode` accepts it.
struct CidParts<'a> {
    version: u64,
    codec: u64,
    hash: u64,
    digest: &'a [u8],
}

impl<'a> CidParts<'a> {
    /// A bare SHA-256 multihash is a CIDv0, allowed only from a `Q…` string.
    fn parse(bytes: &'a [u8], v0_allowed: bool) -> Option<Self> {
        let varint = |buf: &'a [u8]| {
            let (value, len) = decode_varint(buf).ok()?;
            Some((value, buf.get(len..)?))
        };
        let (first, rest) = varint(bytes)?;
        let (version, codec, multihash) = match first {
            0x12 if v0_allowed => (0, 0x70, bytes),
            1 => {
                let (codec, rest) = varint(rest)?;
                (1, codec, rest)
            }
            _ => return None,
        };
        let (hash, rest) = varint(multihash)?;
        let (len, digest) = varint(rest)?;
        (digest.len() as u64 == len).then_some(Self {
            version,
            codec,
            hash,
            digest,
        })
    }
}

const BASE58BTC: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Decode a base-x string (as the `base-x` package does): each leading zero
/// digit is a zero byte, and the rest is a big-endian number.
fn base_x(s: &str, alphabet: &[u8]) -> Option<Vec<u8>> {
    let base = alphabet.len() as u32;
    let zero = *alphabet.first()?;
    let zeros = s.bytes().take_while(|&c| c == zero).count();
    // Little-endian base 256.
    let mut num: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = alphabet.iter().position(|&a| a == c)? as u32;
        for byte in &mut num {
            carry += u32::from(*byte) * base;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

/// Decode lowercase RFC 4648 base32. Like `multiformats`, trailing `=` are
/// ignored and trailing bits must be zero.
fn base32_lower(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_end_matches('=');
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        return None;
    }
    data_encoding::BASE32_NOPAD
        .decode(s.to_ascii_uppercase().as_bytes())
        .ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cbor::{Codec, decode, encode_value};
    use serde_json::json;

    const CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

    fn safe(json: &Json) -> Result<Vec<u8>, CborError> {
        json_to_drisl(json, Integers::Safe)
    }

    fn link(s: &str) -> Json {
        json!({ "$link": s })
    }

    /// Asserts `json` converts to a plain map, keeping its keys.
    fn assert_plain_map(json: &Json) {
        let bytes = safe(json).unwrap();
        let Value::Map(entries) = decode(&bytes).unwrap() else {
            panic!("{json} did not stay a map");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| *k).collect();
        let want: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), want.len(), "{json}");
        assert!(want.iter().all(|k| keys.contains(k)), "{json}");
    }

    #[test]
    fn matches_the_canonical_encoder() {
        let cid = Cid::compute(Codec::Drisl, b"linked record");
        let json = json!({
            "text": "hello",
            "count": 5,
            "negative": -3,
            "flag": true,
            "nothing": null,
            "nested": {"bb": 2, "a": 1},
            "list": [1, "two", [3]],
            "blob": {"$bytes": "3q2+7w"},
            "ref": {"$link": cid.to_string()},
        });
        let value = Value::Map(vec![
            ("text", Value::Text("hello")),
            ("count", Value::Unsigned(5)),
            ("negative", Value::Signed(-3)),
            ("flag", Value::Bool(true)),
            ("nothing", Value::Null),
            (
                "nested",
                Value::Map(vec![("bb", Value::Unsigned(2)), ("a", Value::Unsigned(1))]),
            ),
            (
                "list",
                Value::Array(vec![
                    Value::Unsigned(1),
                    Value::Text("two"),
                    Value::Array(vec![Value::Unsigned(3)]),
                ]),
            ),
            ("blob", Value::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])),
            ("ref", Value::Cid(cid)),
        ]);
        let bytes = safe(&json).unwrap();
        assert_eq!(bytes, encode_value(&value).unwrap());
        assert_eq!(drisl_to_json(&bytes).unwrap(), json);
    }

    #[test]
    fn links_accept_every_reference_multibase() {
        let want = Value::Cid(CID.parse().unwrap());
        for s in [
            CID,
            "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTDh",
            "k2jvsl7wph2xec9tldt5guqsv8bqse480mslfjw2lyfdlxfws95udh3k",
            // multiformats ignores base32 padding.
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a======",
        ] {
            let bytes = safe(&link(s)).unwrap();
            assert_eq!(decode(&bytes).unwrap(), want, "{s}");
            assert_eq!(parse_cid(s).unwrap().to_string(), CID, "{s}");
            assert_eq!(drisl_to_json(&bytes).unwrap(), link(CID), "{s}");
        }
    }

    #[test]
    fn well_formed_cids_that_cid_cannot_hold_are_errors() {
        for s in [
            // v0
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            // dag-pb, in base32 and base36
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            "k2jmtxw8rjh1z69c6not3wtdxb0u3urbzhyll1t9jg6ox26dhi5sfi1m",
            // sha2-512
            "bafyrgqfevpkejdcjkywyfaiv2e5b7thksj7vfngviwjjp6fuhzbnvcjdrpatmjxehxftrxnqqjeisj7msbh3iicxiq4yh2efqulz2ucvdl7ge",
            // identity hash
            "bafkqaa3bmjrq",
        ] {
            assert!(
                matches!(safe(&link(s)), Err(CborError::InvalidCid(_))),
                "{s}"
            );
            assert!(parse_cid(s).is_err(), "{s}");
        }
    }

    #[test]
    fn malformed_links_stay_plain_maps() {
        let long = format!("b{}", "a".repeat(MAX_LINK_LEN));
        for s in [
            "",
            ".",
            "bafy",
            "BAFYREIDFAYVFUWQA7QLNOPDJIQRXZS6BLMOEU4RUJCJTNCI5BELUDIRZ2A",
            "Bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            // trailing byte, truncated digest, version 2
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2aaa",
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz",
            "bajyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            // non-zero trailing bits
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2b",
            // v0 behind a multibase prefix
            "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "bciqj23bl4uhxa2kti6nltxzm4pw4vefwqbj4aczqas37blgl4huo5xy",
            // unsupported multibase, stray characters
            "mAXESIGUGKlpaAPwW1zxpRCN8y8FbHEpyNEiTNokdCRdBojnQ",
            "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTD0",
            " bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            &long,
        ] {
            assert_plain_map(&link(s));
            assert!(parse_cid(s).is_err(), "{s}");
        }
        for json in [
            json!({"$link": 1234}),
            json!({"$link": null}),
            json!({"$link": {"$link": CID}}),
            json!({"$link": CID, "other": 1}),
            json!({"$link": CID, "$bytes": ""}),
        ] {
            assert_plain_map(&json);
        }
    }

    #[test]
    fn bytes_accept_padded_and_unpadded_base64() {
        for (s, want) in [
            ("", &b""[..]),
            ("TQ", b"M"),
            ("TQ==", b"M"),
            ("TWE=", b"Ma"),
            ("TWFu", b"Man"),
            ("+/+/", &[0xfb, 0xff, 0xbf]),
        ] {
            let bytes = safe(&json!({ "$bytes": s })).unwrap();
            assert_eq!(decode(&bytes).unwrap(), Value::Bytes(want), "{s}");
        }
        let bytes = safe(&json!({"$bytes": "TWE="})).unwrap();
        assert_eq!(drisl_to_json(&bytes).unwrap(), json!({"$bytes": "TWE"}));
    }

    #[test]
    fn malformed_bytes_stay_plain_maps() {
        for json in [
            json!({"$bytes": "🐻"}),
            json!({"$bytes": "TQ="}),
            json!({"$bytes": "-_"}),
            json!({"$bytes": [1, 2, 3]}),
            json!({"$bytes": "TQ", "other": 1}),
        ] {
            assert_plain_map(&json);
        }
    }

    #[test]
    fn integers_are_judged_by_value() {
        let max = MAX_SAFE_INTEGER;
        for (text, want) in [
            ("0", 0),
            ("-0", 0),
            ("-0.0", 0),
            ("123.0", 123),
            ("1e10", 10_000_000_000),
            ("9007199254740991", max),
            ("-9007199254740991", -max),
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            let expected = encode_value(&if want < 0 {
                Value::Signed(want)
            } else {
                Value::Unsigned(want as u64)
            })
            .unwrap();
            assert_eq!(safe(&json).unwrap(), expected, "{text}");
            assert_eq!(
                json_to_drisl(&json, Integers::Any).unwrap(),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn unsafe_integers_need_any() {
        for text in [
            "9007199254740992",
            "-9007199254740992",
            "9223372036854775807",
            "-9223372036854775808",
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            assert!(
                matches!(safe(&json), Err(CborError::DataModel(_))),
                "{text}"
            );
            let bytes = json_to_drisl(&json, Integers::Any).unwrap();
            assert_eq!(drisl_to_json(&bytes).unwrap(), json, "{text}");
        }
    }

    #[test]
    fn floats_and_out_of_range_numbers_are_rejected() {
        for text in [
            "1.5",
            "-0.1",
            "1e20",
            "9007199254740992.0",
            "9223372036854775808",
            "18446744073709551616",
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            for integers in [Integers::Safe, Integers::Any] {
                assert!(
                    matches!(json_to_drisl(&json, integers), Err(CborError::DataModel(_))),
                    "{text}"
                );
            }
        }
        assert!(safe(&json!({"a": [{"b": 0.5}]})).is_err());
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        let json: Json = serde_json::from_str(r#"{"a": 1, "a": {"$bytes": "TQ"}}"#).unwrap();
        assert_eq!(
            safe(&json).unwrap(),
            safe(&json!({"a": {"$bytes": "TQ"}})).unwrap()
        );
    }

    #[test]
    fn drisl_floats_and_oversized_integers_are_rejected() {
        let float = encode_value(&Value::Map(vec![("a", Value::Float(1.5))])).unwrap();
        assert!(matches!(
            drisl_to_json(&float),
            Err(CborError::DataModel(_))
        ));
        assert!(matches!(
            value_to_json(&Value::Unsigned(u64::MAX)),
            Err(CborError::DataModel(_))
        ));
        assert!(matches!(
            drisl_to_json(&[0xff]),
            Err(CborError::InvalidCbor(_))
        ));
    }

    #[test]
    fn base_x_keeps_leading_zeros() {
        assert_eq!(base_x("", BASE58BTC), Some(vec![]));
        assert_eq!(base_x("11", BASE58BTC), Some(vec![0, 0]));
        assert_eq!(base_x("1z", BASE58BTC), Some(vec![0, 57]));
        assert_eq!(base_x("5R", BASE58BTC), Some(vec![1, 0]));
        assert_eq!(base_x("0zz", BASE36), Some(vec![0, 5, 15]));
        assert_eq!(base_x("0", BASE58BTC), None);
    }
}
