use crate::value::Value;
use crate::{CborError, Cid};

/// Maximum nesting depth for arrays and maps. Protects against stack
/// overflow from maliciously crafted deeply nested CBOR input.
/// AT Protocol records rarely nest beyond 5-6 levels; 64 is generous
/// while staying safe within default thread stack sizes (~8 MB).
const MAX_DEPTH: usize = 64;

/// Maximum number of elements in a single array or map. Protects against
/// OOM from crafted input claiming millions of tiny elements (each
/// `Value` is ~48 bytes in memory, so 1M elements = ~48 MB regardless
/// of input size). AT Protocol collections are bounded well below this.
const MAX_COLLECTION_LEN: usize = 500_000;

/// Strict DRISL decoder. Rejects non-canonical input.
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Decoder<'a> {
    #[inline]
    pub fn new(buf: &'a [u8]) -> Self {
        Decoder {
            buf,
            pos: 0,
            depth: 0,
        }
    }

    /// Decode one DRISL value from the buffer.
    #[inline]
    pub fn decode(&mut self) -> Result<Value<'a>, CborError> {
        if self.depth >= MAX_DEPTH {
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
                Ok(Value::Unsigned(n))
            }
            1 => {
                let n = self.read_argument(additional)?;
                // -(n+1) must fit in i64. i64::MIN = -9223372036854775808, so max n is 9223372036854775807
                let val = if n <= i64::MAX as u64 {
                    -1 - (n as i64)
                } else {
                    return Err(CborError::InvalidCbor(
                        "negative integer too large for i64".into(),
                    ));
                };
                Ok(Value::Signed(val))
            }
            2 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                let bytes = self.read_slice(len_usize)?;
                Ok(Value::Bytes(bytes))
            }
            3 => {
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                let bytes = self.read_slice(len_usize)?;
                // Safety: simdutf8 validates UTF-8 using SIMD instructions
                // (AVX2/SSE4.2) for ~4x throughput on strings > 64 bytes.
                // After validation succeeds, from_utf8_unchecked is safe.
                let text = match simdutf8::basic::from_utf8(bytes) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(CborError::InvalidCbor(
                            "invalid UTF-8 in text string".into(),
                        ));
                    }
                };
                Ok(Value::Text(text))
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
                let mut items = Vec::with_capacity(capacity);
                self.depth += 1;
                for _ in 0..len_usize {
                    items.push(self.decode()?);
                }
                self.depth -= 1;
                Ok(Value::Array(items))
            }
            5 => {
                self.depth += 1;
                let len = self.read_argument(additional)?;
                let len_usize = usize::try_from(len)
                    .map_err(|_| CborError::InvalidCbor("length exceeds platform limits".into()))?;
                if len_usize > MAX_COLLECTION_LEN {
                    return Err(CborError::InvalidCbor("map length exceeds maximum".into()));
                }
                let capacity = len_usize.min(self.remaining());
                let mut entries = Vec::with_capacity(capacity);
                // Track the raw CBOR-encoded key bytes for canonical order
                // checking. Comparing encoded bytes directly is faster than
                // decoding keys and calling cbor_key_cmp (which recomputes
                // header lengths).
                let mut prev_key_bytes: &[u8] = &[];
                for _ in 0..len_usize {
                    // Decode text key inline — avoids the overhead of the full
                    // decode() dispatch (depth check, major type match, Value
                    // construction + destructuring) for every map key. We already
                    // know the key must be a text string.
                    let key_start = self.pos;
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
                    let key_encoded = &self.buf[key_start..self.pos];

                    // Check canonical order by comparing raw CBOR-encoded key
                    // bytes. DRISL canonical ordering is defined as: shorter
                    // encoded form first, then lexicographic — which is exactly
                    // what byte-wise comparison of the encoded keys gives us.
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

                    let value = self.decode()?;
                    entries.push((key, value));
                }
                self.depth -= 1;
                Ok(Value::Map(entries))
            }
            6 => {
                // Tag — only tag 42 is allowed
                let tag_num = self.read_argument(additional)?;
                if tag_num != 42 {
                    return Err(CborError::InvalidCbor(format!(
                        "unsupported CBOR tag: {tag_num} (only tag 42 is allowed)"
                    )));
                }
                // Inner value must be a bytestring
                let inner = self.decode()?;
                let bytes = match inner {
                    Value::Bytes(b) => b,
                    _ => {
                        return Err(CborError::InvalidCbor(
                            "tag 42 must wrap a bytestring".into(),
                        ));
                    }
                };
                let cid = Cid::from_tag42_bytes(bytes)?;
                Ok(Value::Cid(cid))
            }
            7 => {
                // Simple values and floats
                match additional {
                    20 => Ok(Value::Bool(false)),
                    21 => Ok(Value::Bool(true)),
                    22 => Ok(Value::Null),
                    24 => {
                        // Simple value in next byte — not allowed in DRISL
                        // (simple values other than false/true/null are rejected)
                        Err(CborError::InvalidCbor("unsupported simple value".into()))
                    }
                    25 => {
                        // Half-precision float — rejected
                        Err(CborError::InvalidCbor(
                            "half-precision floats not allowed in DRISL".into(),
                        ))
                    }
                    26 => {
                        // Single-precision float — rejected
                        Err(CborError::InvalidCbor(
                            "single-precision floats not allowed in DRISL".into(),
                        ))
                    }
                    27 => {
                        // Double-precision float
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
                        Ok(Value::Float(val))
                    }
                    31 => Err(CborError::InvalidCbor(
                        "indefinite length not allowed in DRISL".into(),
                    )),
                    _ => {
                        // Other simple values (0-19, 23) are not allowed
                        Err(CborError::InvalidCbor(format!(
                            "unsupported simple value: {additional}"
                        )))
                    }
                }
            }
            _ => Err(CborError::InvalidCbor("invalid major type".into())),
        }
    }

    /// How many bytes have been consumed so far.
    pub fn position(&self) -> usize {
        self.pos
    }

    /// Whether all input has been consumed.
    pub fn is_empty(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Return a reference to the full input buffer.
    pub fn raw_input(&self) -> &'a [u8] {
        self.buf
    }

    /// How many bytes remain in the buffer.
    pub(crate) fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    // --- Internal helpers ---

    #[inline(always)]
    pub(crate) fn read_byte(&mut self) -> Result<u8, CborError> {
        if self.pos >= self.buf.len() {
            return Err(CborError::InvalidCbor("unexpected end of input".into()));
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }

    #[inline(always)]
    pub(crate) fn read_fixed<const N: usize>(&mut self) -> Result<[u8; N], CborError> {
        if self.pos + N > self.buf.len() {
            return Err(CborError::InvalidCbor("unexpected end of input".into()));
        }
        let mut arr = [0u8; N];
        arr.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(arr)
    }

    #[inline(always)]
    pub(crate) fn read_slice(&mut self, len: usize) -> Result<&'a [u8], CborError> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| CborError::InvalidCbor("length overflow".into()))?;
        if end > self.buf.len() {
            return Err(CborError::InvalidCbor("unexpected end of input".into()));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Read the argument value from additional info, enforcing minimal encoding.
    #[inline(always)]
    pub(crate) fn read_argument(&mut self, additional: u8) -> Result<u64, CborError> {
        match additional {
            0..=23 => Ok(additional as u64),
            24 => {
                let val = self.read_byte()? as u64;
                if val < 24 {
                    return Err(CborError::InvalidCbor(format!(
                        "non-minimal integer encoding: value {val} should use inline form"
                    )));
                }
                Ok(val)
            }
            25 => {
                let bytes = self.read_fixed::<2>()?;
                let val = u16::from_be_bytes(bytes) as u64;
                if val <= 255 {
                    return Err(CborError::InvalidCbor(format!(
                        "non-minimal integer encoding: value {val} should use 1-byte form"
                    )));
                }
                Ok(val)
            }
            26 => {
                let bytes = self.read_fixed::<4>()?;
                let val = u32::from_be_bytes(bytes) as u64;
                if val <= 65535 {
                    return Err(CborError::InvalidCbor(format!(
                        "non-minimal integer encoding: value {val} should use 2-byte form"
                    )));
                }
                Ok(val)
            }
            27 => {
                let bytes = self.read_fixed::<8>()?;
                let val = u64::from_be_bytes(bytes);
                if val <= 4294967295 {
                    return Err(CborError::InvalidCbor(format!(
                        "non-minimal integer encoding: value {val} should use 4-byte form"
                    )));
                }
                Ok(val)
            }
            28..=30 => Err(CborError::InvalidCbor(format!(
                "reserved additional info value: {additional}"
            ))),
            31 => Err(CborError::InvalidCbor(
                "indefinite length not allowed in DRISL".into(),
            )),
            _ => Err(CborError::InvalidCbor("invalid additional info".into())),
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
    use crate::{Codec, encode_value};

    fn decode_one(data: &[u8]) -> Value<'_> {
        crate::decode(data).unwrap()
    }

    #[test]
    fn decode_unsigned() {
        assert_eq!(decode_one(&[0x00]), Value::Unsigned(0));
        assert_eq!(decode_one(&[0x17]), Value::Unsigned(23));
        assert_eq!(decode_one(&[0x18, 0x18]), Value::Unsigned(24));
        assert_eq!(decode_one(&[0x18, 0xff]), Value::Unsigned(255));
        assert_eq!(decode_one(&[0x19, 0x01, 0x00]), Value::Unsigned(256));
    }

    #[test]
    fn decode_negative() {
        assert_eq!(decode_one(&[0x20]), Value::Signed(-1));
        assert_eq!(decode_one(&[0x37]), Value::Signed(-24));
        assert_eq!(decode_one(&[0x38, 0x18]), Value::Signed(-25));
    }

    #[test]
    fn decode_text() {
        match decode_one(b"\x65hello") {
            Value::Text(s) => assert_eq!(s, "hello"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn decode_bytes() {
        match decode_one(&[0x42, 0xDE, 0xAD]) {
            Value::Bytes(b) => assert_eq!(b, &[0xDE, 0xAD]),
            other => panic!("expected bytes, got {other:?}"),
        }
    }

    #[test]
    fn decode_bool_and_null() {
        assert_eq!(decode_one(&[0xf5]), Value::Bool(true));
        assert_eq!(decode_one(&[0xf4]), Value::Bool(false));
        assert_eq!(decode_one(&[0xf6]), Value::Null);
    }

    #[test]
    fn decode_float64() {
        let buf = [0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(decode_one(&buf), Value::Float(0.0));
    }

    #[test]
    fn decode_array() {
        let buf = [0x83, 0x01, 0x02, 0x03];
        match decode_one(&buf) {
            Value::Array(items) => {
                assert_eq!(items.len(), 3);
                assert_eq!(items[0], Value::Unsigned(1));
            }
            other => panic!("expected array, got {other:?}"),
        }
    }

    #[test]
    fn decode_map() {
        // {"a": 1}
        let buf = [0xa1, 0x61, 0x61, 0x01];
        match decode_one(&buf) {
            Value::Map(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].0, "a");
                assert_eq!(entries[0].1, Value::Unsigned(1));
            }
            other => panic!("expected map, got {other:?}"),
        }
    }

    // --- Rejection tests ---

    #[test]
    fn reject_indefinite_length() {
        assert!(crate::decode(&[0x5f]).is_err()); // indefinite bytes
        assert!(crate::decode(&[0x7f]).is_err()); // indefinite text
        assert!(crate::decode(&[0x9f]).is_err()); // indefinite array
        assert!(crate::decode(&[0xbf]).is_err()); // indefinite map
    }

    #[test]
    fn reject_non_minimal_int() {
        // 23 encoded with additional info 24 (should be inline)
        assert!(crate::decode(&[0x18, 0x17]).is_err());
        // 255 encoded with additional info 25 (should use 1-byte form)
        assert!(crate::decode(&[0x19, 0x00, 0xff]).is_err());
    }

    #[test]
    fn reject_unsorted_map_keys() {
        // {"b": 1, "a": 2}
        let buf = [0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02];
        assert!(crate::decode(&buf).is_err());
    }

    #[test]
    fn reject_duplicate_map_keys() {
        // {"a": 1, "a": 2}
        let buf = [0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02];
        assert!(crate::decode(&buf).is_err());
    }

    #[test]
    fn reject_non_string_map_key() {
        // {1: 2}
        let buf = [0xa1, 0x01, 0x02];
        assert!(crate::decode(&buf).is_err());
    }

    #[test]
    fn reject_half_float() {
        assert!(crate::decode(&[0xf9, 0x00, 0x00]).is_err());
    }

    #[test]
    fn reject_single_float() {
        assert!(crate::decode(&[0xfa, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn reject_nan() {
        assert!(crate::decode(&[0xfb, 0x7f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn reject_infinity() {
        // +Infinity
        assert!(crate::decode(&[0xfb, 0x7f, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
        // -Infinity
        assert!(crate::decode(&[0xfb, 0xff, 0xf0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]).is_err());
    }

    #[test]
    fn reject_tag_not_42() {
        // Tag 1 (datetime)
        assert!(crate::decode(&[0xc1, 0x00]).is_err());
    }

    #[test]
    fn reject_trailing_data() {
        assert!(crate::decode(&[0x01, 0x02]).is_err());
    }

    // --- Roundtrip tests ---

    #[test]
    fn roundtrip_complex() {
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
        let decoded = crate::decode(&encoded).unwrap();
        // Re-encode and compare bytes to verify roundtrip
        let re_encoded = encode_value(&decoded).unwrap();
        assert_eq!(encoded, re_encoded);
    }

    #[test]
    fn roundtrip_deterministic() {
        let val = Value::Map(vec![("b", Value::Unsigned(2)), ("a", Value::Unsigned(1))]);
        let first = encode_value(&val).unwrap();
        for _ in 0..10 {
            assert_eq!(encode_value(&val).unwrap(), first);
        }
    }

    // --- Security: depth and length limits ---

    #[test]
    fn reject_deeply_nested_arrays() {
        // Build [[[[...]]]] nested 65 levels deep — just over MAX_DEPTH (64)
        let mut buf = vec![0x81; 65]; // 65 x "array of 1 element"
        buf.push(0x00); // innermost value: unsigned 0
        let result = crate::decode(&buf);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nesting depth"),
            "expected depth error, got: {err}"
        );
    }

    #[test]
    fn reject_deeply_nested_maps() {
        // Build {"a":{"a":{"a":...}}} nested 65 levels deep
        let map_entry: [u8; 3] = [0xa1, 0x61, 0x61]; // map(1) + text("a")
        let mut buf: Vec<u8> = map_entry.iter().copied().cycle().take(3 * 65).collect();
        buf.push(0x00); // innermost value: unsigned 0
        let result = crate::decode(&buf);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("nesting depth"),
            "expected depth error, got: {err}"
        );
    }

    #[test]
    fn accept_moderate_nesting() {
        // 50 levels of nesting should be fine (well under MAX_DEPTH=64)
        let mut buf = vec![0x81; 50]; // 50 x "array of 1"
        buf.push(0x00); // unsigned 0
        assert!(crate::decode(&buf).is_ok());
    }

    #[test]
    fn reject_huge_array_length() {
        // Array claiming 2^32 elements — exceeds MAX_COLLECTION_LEN
        let buf = [
            0x9a, // array, 4-byte length
            0x00, 0x10, 0x00, 0x00, // 1,048,576 elements
        ];
        let result = crate::decode(&buf);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "expected length error, got: {err}"
        );
    }

    #[test]
    fn reject_huge_map_length() {
        // Map claiming 1M entries
        let buf = [
            0xba, // map, 4-byte length
            0x00, 0x10, 0x00, 0x00, // 1,048,576 entries
        ];
        let result = crate::decode(&buf);
        assert!(result.is_err());
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("exceeds maximum"),
            "expected length error, got: {err}"
        );
    }
}
