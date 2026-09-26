//! Lenient base64 decoding for `$bytes`, matching the reference TypeScript
//! implementation (`@atproto/lex-data` `fromBase64`).

use data_encoding::BASE64_NOPAD;

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Decode standard-alphabet base64, padded or not. Non-zero trailing bits are
/// accepted, as the reference does. Whitespace, the URL-safe alphabet and
/// malformed padding are rejected.
pub(crate) fn decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    let body = bytes
        .strip_suffix(b"==")
        .or_else(|| bytes.strip_suffix(b"="));
    let body = match body {
        Some(body) if bytes.len().is_multiple_of(4) => body,
        Some(_) => return None,
        None => bytes,
    };
    let mut body = body.to_vec();
    // BASE64_NOPAD insists that trailing bits are zero, so clear them.
    let trailing_mask = match body.len() % 4 {
        0 => 0,
        2 => 0b1111,
        3 => 0b11,
        _ => return None,
    };
    if let Some(last) = body.last_mut() {
        let index = ALPHABET.iter().position(|c| c == last)?;
        *last = *ALPHABET.get(index & !trailing_mask)?;
    }
    BASE64_NOPAD.decode(&body).ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn decodes_padded_and_unpadded() {
        assert_eq!(decode(""), Some(vec![]));
        for raw in [
            &b""[..],
            b"\0\0",
            b"\0\0\0",
            b"\0\0\0\0",
            "é".as_bytes(),
            "\0éàç".as_bytes(),
            b"Hello, World!",
            "😀😃😄😁😆😅😂🤣😊😇".as_bytes(),
            &[0xfb, 0xff, 0xbf],
            &[0x4d],
            &[0x4d, 0x61],
            &[0x4d, 0x61, 0x6e],
            &[0x00, 0x4d, 0x61, 0x6e, 0x00],
        ] {
            let padded = data_encoding::BASE64.encode(raw);
            let unpadded = BASE64_NOPAD.encode(raw);
            assert_eq!(decode(&padded).as_deref(), Some(raw), "{padded}");
            assert_eq!(decode(&unpadded).as_deref(), Some(raw), "{unpadded}");
        }
    }

    #[test]
    fn accepts_non_zero_trailing_bits() {
        // "TR" and "TWF" carry set bits after the last whole byte.
        assert_eq!(decode("TR"), decode("TQ"));
        assert_eq!(decode("TR=="), decode("TQ"));
        assert_eq!(decode("TWF"), decode("TWE"));
        assert_eq!(decode("TWF="), Some(b"Ma".to_vec()));
    }

    #[test]
    fn rejects_invalid() {
        for s in [
            "çç",
            "é",
            "YWJjZGU$$$",
            "@@@@",
            "abcd!",
            "ab=cd",
            "YWFhé",
            "YWFhéé",
            "YWFhééé",
            "YWFhéééé",
            "YWFh=",
            "YWFh==",
            "YWFh===",
            "YWFh====",
            "YWFh=====",
            "YWFh======",
            "TWEé",
            "TWE👍",
            "TWE==",
            "TWE===",
            "TQ===",
            "TQ====",
            "T===",
            "=",
            "==",
            "TQ=",
            "T",
            "TWFhT",
            "TW E",
            "TWE\n",
            "-_-_",
        ] {
            assert_eq!(decode(s), None, "{s:?}");
        }
    }
}
