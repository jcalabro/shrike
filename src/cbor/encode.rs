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
    /// Create an encoder that writes to the given writer.
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
        if !v.is_finite() {
            return Err(non_finite());
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
        self.writer.write_all(&tag42(cid))?;
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

/// The error for a NaN or infinite float, which DRISL cannot represent.
pub(crate) fn non_finite() -> CborError {
    CborError::InvalidCbor("NaN and Infinity not allowed in DRISL".into())
}

/// Append a CBOR head (major type and argument) to `buf`, minimally encoded.
#[inline(always)]
pub(crate) fn put_head(buf: &mut Vec<u8>, major: u8, value: u64) {
    let major = major << 5;
    if value < 24 {
        buf.push(major | value as u8);
    } else if value <= u8::MAX as u64 {
        buf.extend_from_slice(&[major | 24, value as u8]);
    } else if value <= u16::MAX as u64 {
        let [a, b] = (value as u16).to_be_bytes();
        buf.extend_from_slice(&[major | 25, a, b]);
    } else if value <= u32::MAX as u64 {
        let [a, b, c, d] = (value as u32).to_be_bytes();
        buf.extend_from_slice(&[major | 26, a, b, c, d]);
    } else {
        let [a, b, c, d, e, f, g, h] = value.to_be_bytes();
        buf.extend_from_slice(&[major | 27, a, b, c, d, e, f, g, h]);
    }
}

/// Append a text string to `buf`.
#[inline(always)]
pub(crate) fn put_text(buf: &mut Vec<u8>, s: &str) {
    put_head(buf, 3, s.len() as u64);
    buf.extend_from_slice(s.as_bytes());
}

/// Append a CID (tag 42, then a byte string of 0x00 and the binary CID).
#[inline(always)]
pub(crate) fn put_cid(buf: &mut Vec<u8>, cid: &Cid) {
    buf.extend_from_slice(&tag42(cid));
}

/// A CID's complete tag 42 encoding.
#[inline(always)]
fn tag42(cid: &Cid) -> [u8; 41] {
    // Tag 42 (0xd8 0x2a) + bytestring header for 37 bytes (0x58 0x25)
    // + 0x00 prefix + 36-byte binary CID = 41 bytes total
    let mut buf = [0u8; 41];
    buf[0] = 0xd8; // tag follows in 1 byte
    buf[1] = 0x2a; // tag 42
    buf[2] = 0x58; // bytestring, 1-byte length follows
    buf[3] = 0x25; // 37 bytes
    buf[4] = 0x00; // tag 42 prefix byte
    buf[5..].copy_from_slice(&cid.to_bytes());
    buf
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
/// CBOR encodings are shorter), and equal-length strings sort
/// lexicographically by their raw bytes.
#[inline]
pub fn cbor_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    // A longer string never has a shorter head, so the encoded lengths order
    // as the string lengths do.
    if a.len() != b.len() {
        return a.len().cmp(&b.len());
    }
    // Keys are short and usually differ early: compare eight bytes at a
    // time, then byte by byte, rather than call `memcmp`.
    let ((a_words, a_rest), (b_words, b_rest)) = (a.as_chunks::<8>(), b.as_chunks::<8>());
    for (x, y) in a_words.iter().zip(b_words) {
        if x != y {
            return u64::from_be_bytes(*x).cmp(&u64::from_be_bytes(*y));
        }
    }
    a_rest
        .iter()
        .zip(b_rest)
        .map(|(x, y)| x.cmp(y))
        .find(|order| order.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
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
        for cid in [
            Cid::compute(Codec::Drisl, b"test"),
            Cid::compute(Codec::Raw, b"test"),
        ] {
            // Tag 42, a 37-byte string header, the 0x00 prefix, the CID.
            let mut want = vec![0xd8, 0x2a, 0x58, 0x25, 0x00];
            want.extend_from_slice(&cid.to_bytes());
            assert_eq!(encode_to_bytes(|e| e.encode_cid(&cid)), want);
            let mut buf = vec![0xaa];
            put_cid(&mut buf, &cid);
            assert_eq!(buf[1..], want);
        }
    }

    #[test]
    fn put_head_matches_encoder() {
        let boundaries = [
            0,
            1,
            23,
            24,
            255,
            256,
            65535,
            65536,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            u64::MAX,
        ];
        for major in 0..8 {
            for value in boundaries {
                let want = encode_to_bytes(|e| e.write_type_value(major, value));
                let mut buf = vec![0xaa];
                put_head(&mut buf, major, value);
                assert_eq!(buf[1..], want, "major {major}, value {value}");
            }
        }
    }

    #[test]
    fn put_text_matches_encoder() {
        for len in [0, 1, 23, 24, 255, 256, 65535, 65536] {
            let s = "é".repeat(len / 2) + &"x".repeat(len % 2);
            let mut buf = Vec::new();
            put_text(&mut buf, &s);
            assert_eq!(buf, encode_to_bytes(|e| e.encode_text(&s)), "length {len}");
        }
    }

    /// The canonical order by definition: shorter encodings first, then
    /// bytewise on the encodings.
    fn encoded_key_cmp(a: &str, b: &str) -> std::cmp::Ordering {
        let (a, b) = (
            encode_to_bytes(|e| e.encode_text(a)),
            encode_to_bytes(|e| e.encode_text(b)),
        );
        a.len().cmp(&b.len()).then_with(|| a.cmp(&b))
    }

    #[test]
    fn cbor_key_cmp_across_head_sizes() {
        // Lengths either side of each head size change, each in a variant
        // that differs from the base key in its first, middle or last byte.
        let mut keys = Vec::new();
        for len in [0, 1, 7, 8, 9, 16, 23, 24, 255, 256, 65535, 65536] {
            let base = "k".repeat(len);
            for at in [0, len / 2, len.saturating_sub(1)] {
                for c in ["j", "l"] {
                    let mut key = base.clone();
                    if len > 0 {
                        key.replace_range(at..=at, c);
                    }
                    keys.push(key);
                }
            }
            keys.push(base);
        }
        for a in &keys {
            for b in &keys {
                assert_eq!(
                    cbor_key_cmp(a, b),
                    encoded_key_cmp(a, b),
                    "lengths {} and {}",
                    a.len(),
                    b.len()
                );
            }
        }
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
