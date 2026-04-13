use std::io::Write;

use crate::cbor::{CborError, Cid};

/// Streaming DRISL (deterministic CBOR) encoder.
///
/// All integer values use minimal-length encoding, and floats are always 64-bit.
/// Map keys must be strings, sorted by their CBOR-encoded bytes (shorter first,
/// then lexicographic).
pub struct Encoder<W: Write> {
    writer: W,
}

impl<W: Write> Encoder<W> {
    pub fn new(writer: W) -> Self {
        Encoder { writer }
    }

    /// Consume the encoder and return the underlying writer.
    pub fn into_inner(self) -> W {
        self.writer
    }

    /// Encode a non-negative integer (CBOR major type 0).
    #[inline]
    pub fn encode_u64(&mut self, v: u64) -> Result<(), CborError> {
        self.write_type_value(0, v)
    }

    /// Encode a signed integer (major type 0 for non-negative, major type 1 for negative).
    #[inline]
    pub fn encode_i64(&mut self, v: i64) -> Result<(), CborError> {
        if v >= 0 {
            self.write_type_value(0, v as u64)
        } else {
            self.write_type_value(1, (-1 - v) as u64)
        }
    }

    /// Encode a boolean value.
    #[inline]
    pub fn encode_bool(&mut self, v: bool) -> Result<(), CborError> {
        self.writer.write_all(&[if v { 0xf5 } else { 0xf4 }])?;
        Ok(())
    }

    /// Encode a CBOR null.
    #[inline]
    pub fn encode_null(&mut self) -> Result<(), CborError> {
        self.writer.write_all(&[0xf6])?;
        Ok(())
    }

    /// Encode a 64-bit float. DRISL requires ALWAYS 64-bit. Rejects NaN and Infinity.
    pub fn encode_f64(&mut self, v: f64) -> Result<(), CborError> {
        if v.is_nan() || v.is_infinite() {
            return Err(CborError::InvalidCbor(
                "NaN and Infinity not allowed in DRISL".into(),
            ));
        }
        let be = v.to_bits().to_be_bytes();
        self.writer
            .write_all(&[0xfb, be[0], be[1], be[2], be[3], be[4], be[5], be[6], be[7]])?;
        Ok(())
    }

    /// Encode a text string (CBOR major type 3).
    #[inline]
    pub fn encode_text(&mut self, v: &str) -> Result<(), CborError> {
        self.write_type_value(3, v.len() as u64)?;
        self.writer.write_all(v.as_bytes())?;
        Ok(())
    }

    /// Encode a byte string (CBOR major type 2).
    #[inline]
    pub fn encode_bytes(&mut self, v: &[u8]) -> Result<(), CborError> {
        self.write_type_value(2, v.len() as u64)?;
        self.writer.write_all(v)?;
        Ok(())
    }

    /// Encode an array header (CBOR major type 4). Caller must then encode exactly `len` items.
    pub fn encode_array_header(&mut self, len: u64) -> Result<(), CborError> {
        self.write_type_value(4, len)
    }

    /// Encode a map header (CBOR major type 5). Caller must then encode exactly `len` key-value pairs.
    pub fn encode_map_header(&mut self, len: u64) -> Result<(), CborError> {
        self.write_type_value(5, len)
    }

    /// Encode a CID as CBOR tag 42 + bytestring with 0x00 prefix.
    ///
    /// Writes tag(42) + bytestring(37) + [0x00 + 36-byte CID] in a single call.
    #[inline]
    pub fn encode_cid(&mut self, cid: &Cid) -> Result<(), CborError> {
        // Tag 42 (0xd8 0x2a) + bytestring header for 37 bytes (0x58 0x25)
        // + 0x00 prefix + 36-byte binary CID = 41 bytes total
        let cid_bytes = cid.to_bytes();
        let mut buf = [0u8; 41];
        buf[0] = 0xd8; // tag follows in 1 byte
        buf[1] = 0x2a; // tag 42
        buf[2] = 0x58; // bytestring, 1-byte length follows
        buf[3] = 0x25; // 37 bytes
        buf[4] = 0x00; // tag 42 prefix byte
        buf[5..].copy_from_slice(&cid_bytes);
        self.writer.write_all(&buf)?;
        Ok(())
    }

    /// Write a CBOR type+value header with minimal encoding.
    ///
    /// Merges header byte + payload into a single write to minimize call overhead.
    #[inline(always)]
    fn write_type_value(&mut self, major: u8, value: u64) -> Result<(), CborError> {
        let major_bits = major << 5;
        if value < 24 {
            self.writer.write_all(&[major_bits | value as u8])?;
        } else if value <= u8::MAX as u64 {
            self.writer.write_all(&[major_bits | 24, value as u8])?;
        } else if value <= u16::MAX as u64 {
            let be = (value as u16).to_be_bytes();
            self.writer.write_all(&[major_bits | 25, be[0], be[1]])?;
        } else if value <= u32::MAX as u64 {
            let be = (value as u32).to_be_bytes();
            self.writer
                .write_all(&[major_bits | 26, be[0], be[1], be[2], be[3]])?;
        } else {
            let be = value.to_be_bytes();
            self.writer.write_all(&[
                major_bits | 27,
                be[0],
                be[1],
                be[2],
                be[3],
                be[4],
                be[5],
                be[6],
                be[7],
            ])?;
        }
        Ok(())
    }
}

/// Sort string keys by their CBOR-encoded form and encode as a map.
///
/// CBOR key ordering: shorter encoded keys first, then bytewise comparison.
/// The `encode_value` closure is called for each key in sorted order and must
/// encode exactly one CBOR value for that key.
pub fn encode_text_map<W: Write, F>(
    enc: &mut Encoder<W>,
    keys: &[&str],
    mut encode_value: F,
) -> Result<(), CborError>
where
    F: FnMut(&mut Encoder<W>, &str) -> Result<(), CborError>,
{
    let mut sorted: Vec<&str> = keys.to_vec();
    sorted.sort_by(|a, b| cbor_key_cmp(a, b));

    enc.encode_map_header(sorted.len() as u64)?;
    for key in sorted {
        enc.encode_text(key)?;
        encode_value(enc, key)?;
    }
    Ok(())
}

/// Compare two string keys by CBOR encoding order.
///
/// For DAG-CBOR text string keys: shorter strings sort first (because their
/// CBOR headers encode to fewer bytes), and equal-length strings sort
/// lexicographically by their raw bytes.
///
/// Fast path: all AT Protocol field names are < 24 bytes, so the CBOR header
/// is always 1 byte and total encoded length = 1 + string length. Comparing
/// string lengths directly avoids calling `cbor_header_len` on every comparison.
#[inline]
pub fn cbor_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let a_len = a.len();
    let b_len = b.len();
    if a_len < 24 && b_len < 24 {
        // Header is 1 byte for both, so encoded length order = string length order
        return a_len
            .cmp(&b_len)
            .then_with(|| a.as_bytes().cmp(b.as_bytes()));
    }
    let a_encoded_len = cbor_header_len(a_len as u64) + a_len;
    let b_encoded_len = cbor_header_len(b_len as u64) + b_len;
    a_encoded_len
        .cmp(&b_encoded_len)
        .then_with(|| a.as_bytes().cmp(b.as_bytes()))
}

/// Return the byte length of a CBOR type+value header for the given value.
#[inline]
fn cbor_header_len(value: u64) -> usize {
    if value < 24 {
        1
    } else if value <= u8::MAX as u64 {
        2
    } else if value <= u16::MAX as u64 {
        3
    } else if value <= u32::MAX as u64 {
        5
    } else {
        9
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
    use crate::cbor::Codec;

    fn encode_to_bytes<F>(f: F) -> Vec<u8>
    where
        F: FnOnce(&mut Encoder<&mut Vec<u8>>) -> Result<(), CborError>,
    {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        f(&mut enc).unwrap();
        buf
    }

    #[test]
    fn encode_small_positive_int() {
        assert_eq!(encode_to_bytes(|e| e.encode_u64(0)), [0x00]);
        assert_eq!(encode_to_bytes(|e| e.encode_u64(1)), [0x01]);
        assert_eq!(encode_to_bytes(|e| e.encode_u64(23)), [0x17]);
    }

    #[test]
    fn encode_one_byte_int() {
        assert_eq!(encode_to_bytes(|e| e.encode_u64(24)), [0x18, 0x18]);
        assert_eq!(encode_to_bytes(|e| e.encode_u64(255)), [0x18, 0xff]);
    }

    #[test]
    fn encode_two_byte_int() {
        assert_eq!(encode_to_bytes(|e| e.encode_u64(256)), [0x19, 0x01, 0x00]);
        assert_eq!(encode_to_bytes(|e| e.encode_u64(65535)), [0x19, 0xff, 0xff]);
    }

    #[test]
    fn encode_four_byte_int() {
        assert_eq!(
            encode_to_bytes(|e| e.encode_u64(65536)),
            [0x1a, 0x00, 0x01, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_eight_byte_int() {
        assert_eq!(
            encode_to_bytes(|e| e.encode_u64(u32::MAX as u64 + 1)),
            [0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00]
        );
    }

    #[test]
    fn encode_negative_int() {
        assert_eq!(encode_to_bytes(|e| e.encode_i64(-1)), [0x20]);
        assert_eq!(encode_to_bytes(|e| e.encode_i64(-24)), [0x37]);
        assert_eq!(encode_to_bytes(|e| e.encode_i64(-25)), [0x38, 0x18]);
    }

    #[test]
    fn encode_text() {
        let buf = encode_to_bytes(|e| e.encode_text("hello"));
        assert_eq!(buf[0], 0x65); // major type 3, length 5
        assert_eq!(&buf[1..], b"hello");
    }

    #[test]
    fn encode_bytes() {
        let buf = encode_to_bytes(|e| e.encode_bytes(&[0xDE, 0xAD]));
        assert_eq!(buf[0], 0x42); // major type 2, length 2
        assert_eq!(&buf[1..], &[0xDE, 0xAD]);
    }

    #[test]
    fn encode_bool_and_null() {
        assert_eq!(encode_to_bytes(|e| e.encode_bool(true)), [0xf5]);
        assert_eq!(encode_to_bytes(|e| e.encode_bool(false)), [0xf4]);
        assert_eq!(encode_to_bytes(|e| e.encode_null()), [0xf6]);
    }

    #[test]
    fn encode_float_always_64bit() {
        let buf = encode_to_bytes(|e| e.encode_f64(0.0));
        assert_eq!(buf.len(), 9);
        assert_eq!(buf[0], 0xfb);
    }

    #[test]
    fn encode_float_rejects_nan() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        assert!(enc.encode_f64(f64::NAN).is_err());
    }

    #[test]
    fn encode_float_rejects_infinity() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        assert!(enc.encode_f64(f64::INFINITY).is_err());
        assert!(enc.encode_f64(f64::NEG_INFINITY).is_err());
    }

    #[test]
    fn encode_float_allows_neg_zero() {
        let buf = encode_to_bytes(|e| e.encode_f64(-0.0));
        assert_eq!(buf.len(), 9);
    }

    #[test]
    fn encode_cid_tag42() {
        let cid = Cid::compute(Codec::Drisl, b"test");
        let buf = encode_to_bytes(|e| e.encode_cid(&cid));
        assert_eq!(buf[0], 0xd8); // tag follows in 1 byte
        assert_eq!(buf[1], 0x2a); // tag 42
        // Then bytestring header + 37 bytes (0x00 prefix + 36 CID bytes)
    }

    #[test]
    fn cbor_key_sort_order() {
        // "a" (encoded: 61 61) sorts before "b" (61 62) sorts before "aa" (62 61 61)
        // Because shorter CBOR encoding sorts first
        use std::cmp::Ordering;
        assert_eq!(cbor_key_cmp("a", "b"), Ordering::Less);
        assert_eq!(cbor_key_cmp("b", "aa"), Ordering::Less);
        assert_eq!(cbor_key_cmp("a", "aa"), Ordering::Less);
    }

    #[test]
    fn encode_array() {
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            enc.encode_array_header(3).unwrap();
            enc.encode_u64(1).unwrap();
            enc.encode_u64(2).unwrap();
            enc.encode_u64(3).unwrap();
        }
        assert_eq!(buf[0], 0x83); // array of 3
        assert_eq!(&buf[1..], [0x01, 0x02, 0x03]);
    }

    #[test]
    fn encode_map_manual() {
        // Manually encode a map with sorted keys
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            enc.encode_map_header(2).unwrap();
            // Keys sorted: "a" before "b"
            enc.encode_text("a").unwrap();
            enc.encode_u64(1).unwrap();
            enc.encode_text("b").unwrap();
            enc.encode_u64(2).unwrap();
        }
        assert_eq!(buf[0], 0xa2); // map of 2
    }

    #[test]
    fn encode_text_map_sorts_keys() {
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            // Pass keys in unsorted order
            encode_text_map(&mut enc, &["b", "a"], |enc, key| match key {
                "a" => enc.encode_u64(1),
                "b" => enc.encode_u64(2),
                _ => unreachable!(),
            })
            .unwrap();
        }
        // Should be: map(2), text("a"), uint(1), text("b"), uint(2)
        assert_eq!(buf, [0xa2, 0x61, 0x61, 0x01, 0x61, 0x62, 0x02]);
    }

    #[test]
    fn encode_text_map_shorter_keys_first() {
        let mut buf = Vec::new();
        {
            let mut enc = Encoder::new(&mut buf);
            // "bb" should come after "a" even though 'b' > 'a' and "bb" starts with 'b'
            encode_text_map(&mut enc, &["bb", "a"], |enc, key| match key {
                "a" => enc.encode_u64(1),
                "bb" => enc.encode_u64(2),
                _ => unreachable!(),
            })
            .unwrap();
        }
        // "a" (shorter CBOR) should come first
        assert_eq!(buf, [0xa2, 0x61, 0x61, 0x01, 0x62, 0x62, 0x62, 0x02]);
    }

    #[test]
    fn encode_empty_text() {
        let buf = encode_to_bytes(|e| e.encode_text(""));
        assert_eq!(buf, [0x60]); // major type 3, length 0
    }

    #[test]
    fn encode_empty_bytes() {
        let buf = encode_to_bytes(|e| e.encode_bytes(&[]));
        assert_eq!(buf, [0x40]); // major type 2, length 0
    }

    #[test]
    fn encode_empty_array() {
        let buf = encode_to_bytes(|e| e.encode_array_header(0));
        assert_eq!(buf, [0x80]); // major type 4, length 0
    }

    #[test]
    fn encode_empty_map() {
        let buf = encode_to_bytes(|e| e.encode_map_header(0));
        assert_eq!(buf, [0xa0]); // major type 5, length 0
    }

    #[test]
    fn into_inner_returns_writer() {
        let buf = Vec::new();
        let enc = Encoder::new(buf);
        let recovered = enc.into_inner();
        assert!(recovered.is_empty());
    }
}
