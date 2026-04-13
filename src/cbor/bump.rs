//! Bump-allocated DRISL decoding.
//!
//! When the `bumpalo` feature is enabled, this module provides [`BumpValue`]
//! and [`Decoder::decode_bump`] for zero-heap-allocation decoding. All
//! collections (arrays, maps) are allocated as slices in the bump arena,
//! avoiding per-Vec malloc/free and Drop overhead.
//!
//! This is the optimal path for hot loops like firehose decode, where you
//! process one frame at a time and can reset the arena between frames.
//!
//! ```no_run
//! # #[cfg(feature = "bumpalo")]
//! # {
//! use bumpalo::Bump;
//! use crate::cbor::Decoder;
//!
//! let bump = Bump::new();
//! let data: &[u8] = &[0xa1, 0x61, 0x61, 0x01]; // {"a": 1}
//! let mut dec = Decoder::new(data);
//! let val = dec.decode_bump(&bump).unwrap();
//! // val borrows from both `data` (text/bytes) and `bump` (collections)
//! // reset the arena to free everything at once:
//! // bump.reset();
//! # }
//! ```

use bumpalo::Bump;

use crate::cbor::CborError;
use crate::cbor::cid::Cid;
use crate::cbor::decode::Decoder;

/// Maximum nesting depth — mirrors the limit in the standard decoder.
const MAX_DEPTH: usize = 64;

/// Maximum collection length — mirrors the limit in the standard decoder.
const MAX_COLLECTION_LEN: usize = 500_000;

/// Decoded DRISL value with bump-allocated collections.
///
/// Text and bytes borrow from the input buffer (`'data`), while arrays
/// and maps are allocated as slices in the bump arena (`'bump`).
/// This eliminates all heap allocation during decode.
#[derive(Debug, Clone, PartialEq)]
pub enum BumpValue<'bump, 'data> {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Bool(bool),
    Null,
    Text(&'data str),
    Bytes(&'data [u8]),
    Cid(Cid),
    Array(&'bump [BumpValue<'bump, 'data>]),
    Map(&'bump [(&'data str, BumpValue<'bump, 'data>)]),
}

impl<'data> Decoder<'data> {
    /// Decode one DRISL value, allocating collections into the bump arena.
    ///
    /// This is functionally identical to [`Decoder::decode`] but avoids all
    /// heap allocation — arrays and maps are bump-allocated slices instead
    /// of `Vec`s. For hot loops, reset the arena between iterations to
    /// reclaim memory without per-element Drop overhead.
    #[inline]
    pub fn decode_bump<'bump>(
        &mut self,
        bump: &'bump Bump,
    ) -> Result<BumpValue<'bump, 'data>, CborError> {
        self.decode_bump_inner(bump, 0)
    }

    fn decode_bump_inner<'bump>(
        &mut self,
        bump: &'bump Bump,
        depth: usize,
    ) -> Result<BumpValue<'bump, 'data>, CborError> {
        if depth >= MAX_DEPTH {
            return Err(CborError::InvalidCbor(
                "maximum nesting depth exceeded".into(),
            ));
        }
        let initial_byte = self.read_byte()?;
        let major = initial_byte >> 5;
        let additional = initial_byte & 0x1f;

        match major {
            0 => {
                let n = self.read_argument(additional)?;
                Ok(BumpValue::Unsigned(n))
            }
            1 => {
                let n = self.read_argument(additional)?;
                let val = if n <= i64::MAX as u64 {
                    -1 - (n as i64)
                } else {
                    return Err(CborError::InvalidCbor(
                        "negative integer too large for i64".into(),
                    ));
                };
                Ok(BumpValue::Signed(val))
            }
            2 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                let bytes = self.read_slice(len_usize)?;
                Ok(BumpValue::Bytes(bytes))
            }
            3 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                let bytes = self.read_slice(len_usize)?;
                let text = match simdutf8::basic::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(CborError::InvalidCbor(
                            "invalid UTF-8 in text string".into(),
                        ));
                    }
                };
                Ok(BumpValue::Text(text))
            }
            4 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                if len_usize > MAX_COLLECTION_LEN {
                    return Err(CborError::InvalidCbor(
                        "array length exceeds maximum".into(),
                    ));
                }
                let capacity = len_usize.min(self.remaining());
                let items = bump.alloc_slice_fill_with(capacity, |_| BumpValue::Null);
                for item in items.iter_mut() {
                    *item = self.decode_bump_inner(bump, depth + 1)?;
                }
                Ok(BumpValue::Array(items))
            }
            5 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                if len_usize > MAX_COLLECTION_LEN {
                    return Err(CborError::InvalidCbor("map length exceeds maximum".into()));
                }
                let capacity = len_usize.min(self.remaining());
                let entries = bump.alloc_slice_fill_with(capacity, |_| ("", BumpValue::Null));
                let mut prev_key_bytes: &[u8] = &[];
                for entry in entries.iter_mut() {
                    // Decode text key inline (same as standard decoder)
                    let key_start = self.position();
                    let key_byte = self.read_byte()?;
                    let key_major = key_byte >> 5;
                    if key_major != 3 {
                        return Err(CborError::InvalidCbor(
                            "map keys must be text strings".into(),
                        ));
                    }
                    let key_additional = key_byte & 0x1f;
                    let key_len = self.read_argument(key_additional)?;
                    let key_len_usize = usize::try_from(key_len).map_err(|_| {
                        CborError::InvalidCbor("length exceeds platform limits".into())
                    })?;
                    let key_bytes = self.read_slice(key_len_usize)?;
                    let key = match simdutf8::basic::from_utf8(key_bytes) {
                        Ok(s) => s,
                        Err(_) => {
                            return Err(CborError::InvalidCbor(
                                "invalid UTF-8 in text string".into(),
                            ));
                        }
                    };
                    let key_encoded = &self.raw_input()[key_start..self.position()];

                    // Check canonical order
                    if !prev_key_bytes.is_empty() {
                        match prev_key_bytes.cmp(key_encoded) {
                            std::cmp::Ordering::Greater => {
                                return Err(CborError::InvalidCbor(
                                    "map keys not in canonical sort order".into(),
                                ));
                            }
                            std::cmp::Ordering::Equal => {
                                return Err(CborError::InvalidCbor("duplicate map key".into()));
                            }
                            std::cmp::Ordering::Less => {}
                        }
                    }
                    prev_key_bytes = key_encoded;

                    let value = self.decode_bump_inner(bump, depth + 1)?;
                    *entry = (key, value);
                }
                Ok(BumpValue::Map(entries))
            }
            6 => {
                let tag_num = self.read_argument(additional)?;
                if tag_num != 42 {
                    return Err(CborError::InvalidCbor(format!(
                        "unsupported CBOR tag: {tag_num} (only tag 42 is allowed)"
                    )));
                }
                let inner = self.decode_bump_inner(bump, depth)?;
                let bytes = match inner {
                    BumpValue::Bytes(b) => b,
                    _ => {
                        return Err(CborError::InvalidCbor(
                            "tag 42 must wrap a bytestring".into(),
                        ));
                    }
                };
                let cid = Cid::from_tag42_bytes(bytes)?;
                Ok(BumpValue::Cid(cid))
            }
            7 => match additional {
                20 => Ok(BumpValue::Bool(false)),
                21 => Ok(BumpValue::Bool(true)),
                22 => Ok(BumpValue::Null),
                24 => Err(CborError::InvalidCbor("unsupported simple value".into())),
                25 => Err(CborError::InvalidCbor(
                    "half-precision floats not allowed in DRISL".into(),
                )),
                26 => Err(CborError::InvalidCbor(
                    "single-precision floats not allowed in DRISL".into(),
                )),
                27 => {
                    let bytes = self.read_fixed::<8>()?;
                    let val = f64::from_bits(u64::from_be_bytes(bytes));
                    if val.is_nan() {
                        return Err(CborError::InvalidCbor("NaN not allowed in DRISL".into()));
                    }
                    if val.is_infinite() {
                        return Err(CborError::InvalidCbor(
                            "Infinity not allowed in DRISL".into(),
                        ));
                    }
                    Ok(BumpValue::Float(val))
                }
                31 => Err(CborError::InvalidCbor(
                    "indefinite length not allowed in DRISL".into(),
                )),
                _ => Err(CborError::InvalidCbor(format!(
                    "unsupported simple value: {additional}"
                ))),
            },
            _ => Err(CborError::InvalidCbor("invalid major type".into())),
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;
    use crate::cbor::{Codec, encode_value, value::Value};

    fn decode_bump_one<'bump, 'data>(
        data: &'data [u8],
        bump: &'bump Bump,
    ) -> BumpValue<'bump, 'data> {
        let mut dec = Decoder::new(data);
        let val = dec.decode_bump(bump).unwrap();
        assert!(dec.is_empty(), "trailing data");
        val
    }

    #[test]
    fn bump_decode_unsigned() {
        let bump = Bump::new();
        assert_eq!(decode_bump_one(&[0x00], &bump), BumpValue::Unsigned(0));
        assert_eq!(decode_bump_one(&[0x17], &bump), BumpValue::Unsigned(23));
    }

    #[test]
    fn bump_decode_negative() {
        let bump = Bump::new();
        assert_eq!(decode_bump_one(&[0x20], &bump), BumpValue::Signed(-1));
    }

    #[test]
    fn bump_decode_text() {
        let bump = Bump::new();
        match decode_bump_one(b"\x65hello", &bump) {
            BumpValue::Text(s) => assert_eq!(s, "hello"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn bump_decode_bytes() {
        let bump = Bump::new();
        match decode_bump_one(&[0x42, 0xDE, 0xAD], &bump) {
            BumpValue::Bytes(b) => assert_eq!(b, &[0xDE, 0xAD]),
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    #[test]
    fn bump_decode_bool_and_null() {
        let bump = Bump::new();
        assert_eq!(decode_bump_one(&[0xf5], &bump), BumpValue::Bool(true));
        assert_eq!(decode_bump_one(&[0xf4], &bump), BumpValue::Bool(false));
        assert_eq!(decode_bump_one(&[0xf6], &bump), BumpValue::Null);
    }

    #[test]
    fn bump_decode_array() {
        let bump = Bump::new();
        let buf = [0x83, 0x01, 0x02, 0x03];
        match decode_bump_one(&buf, &bump) {
            BumpValue::Array(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], BumpValue::Unsigned(1));
                assert_eq!(items[1], BumpValue::Unsigned(2));
                assert_eq!(items[2], BumpValue::Unsigned(3));
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn bump_decode_map() {
        let bump = Bump::new();
        // {"a": 1}
        let buf = [0xa1, 0x61, 0x61, 0x01];
        match decode_bump_one(&buf, &bump) {
            BumpValue::Map(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "a");
                assert_eq!(entries[0].1, BumpValue::Unsigned(1));
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    #[test]
    fn bump_decode_cid() {
        let bump = Bump::new();
        let cid = Cid::compute(Codec::Drisl, b"test");
        let val = Value::Cid(cid);
        let encoded = encode_value(&val).unwrap();
        match decode_bump_one(&encoded, &bump) {
            BumpValue::Cid(decoded_cid) => assert_eq!(decoded_cid, cid),
            other => panic!("expected CID, got {other:?}"),
        }
    }

    #[test]
    fn bump_reject_unsorted_map_keys() {
        let bump = Bump::new();
        // {"b": 1, "a": 2}
        let buf = [0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02];
        let mut dec = Decoder::new(&buf);
        assert!(dec.decode_bump(&bump).is_err());
    }

    #[test]
    fn bump_reject_indefinite_length() {
        let bump = Bump::new();
        let mut dec = Decoder::new(&[0x9f]); // indefinite array
        assert!(dec.decode_bump(&bump).is_err());
    }

    #[test]
    fn bump_complex_roundtrip_matches_standard() {
        let bump = Bump::new();
        let cid = Cid::compute(Codec::Drisl, b"test");
        let original = Value::Map(vec![
            ("age", Value::Unsigned(30)),
            ("cid", Value::Cid(cid)),
            ("name", Value::Text("alice")),
            (
                "tags",
                Value::Array(vec![Value::Text("rust"), Value::Bool(true), Value::Null]),
            ),
        ]);
        let encoded = encode_value(&original).unwrap();

        // Standard decode
        let std_val = crate::cbor::decode(&encoded).unwrap();

        // Bump decode
        let mut dec = Decoder::new(&encoded);
        let bump_val = dec.decode_bump(&bump).unwrap();
        assert!(dec.is_empty());

        // Verify same structure
        match (&std_val, &bump_val) {
            (Value::Map(std_entries), BumpValue::Map(bump_entries)) => {
                assert_eq!(std_entries.len(), bump_entries.len());
                for (s, b) in std_entries.iter().zip(bump_entries.iter()) {
                    assert_eq!(s.0, b.0, "key mismatch");
                }
            }
            _ => panic!("expected maps"),
        }

        // Re-encode standard and verify bytes match
        let re_encoded = encode_value(&std_val).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn bump_deeply_nested_rejects() {
        let bump = Bump::new();
        let mut buf = vec![0x81; 65]; // 65 x "array of 1"
        buf.push(0x00);
        let mut dec = Decoder::new(&buf);
        assert!(dec.decode_bump(&bump).is_err());
    }
}
