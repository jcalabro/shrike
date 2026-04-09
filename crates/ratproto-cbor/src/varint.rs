use crate::CborError;

/// Encode an unsigned varint into the given Vec.
pub fn encode_varint(mut value: u64, buf: &mut Vec<u8>) {
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if value == 0 {
            break;
        }
    }
}

/// Decode an unsigned varint from the beginning of the slice.
/// Returns (value, bytes_consumed).
pub fn decode_varint(buf: &[u8]) -> Result<(u64, usize), CborError> {
    if buf.is_empty() {
        return Err(CborError::InvalidCbor("empty buffer for varint".into()));
    }

    let mut value: u64 = 0;
    let mut shift = 0u32;

    for (i, &byte) in buf.iter().enumerate() {
        if shift >= 63 && (byte & 0x7F) > 1 {
            return Err(CborError::InvalidCbor("varint overflow".into()));
        }
        value |= ((byte & 0x7F) as u64) << shift;
        if byte & 0x80 == 0 {
            return Ok((value, i + 1));
        }
        shift += 7;
        if shift > 63 {
            return Err(CborError::InvalidCbor("varint overflow".into()));
        }
    }

    Err(CborError::InvalidCbor("truncated varint".into()))
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

    #[test]
    fn varint_roundtrip() {
        let values = [
            0u64,
            1,
            127,
            128,
            255,
            256,
            16383,
            16384,
            u32::MAX as u64,
            u32::MAX as u64 + 1,
            i64::MAX as u64,
        ];
        for v in values {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            let (decoded, len) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn varint_empty_input() {
        assert!(decode_varint(&[]).is_err());
    }

    #[test]
    fn varint_truncated() {
        assert!(decode_varint(&[0x80]).is_err());
    }

    #[test]
    fn varint_single_byte() {
        let (val, len) = decode_varint(&[0x00]).unwrap();
        assert_eq!(val, 0);
        assert_eq!(len, 1);

        let (val, len) = decode_varint(&[0x7F]).unwrap();
        assert_eq!(val, 127);
        assert_eq!(len, 1);
    }

    #[test]
    fn varint_two_bytes() {
        let (val, len) = decode_varint(&[0x80, 0x01]).unwrap();
        assert_eq!(val, 128);
        assert_eq!(len, 2);
    }
}
