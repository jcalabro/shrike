//! Bounded zstd decode.
//!
//! Native builds decode with libzstd through the `zstd` crate; the browser
//! target (`wasm32-unknown-unknown`) uses the pure-Rust `ruzstd` decoder, since
//! the libzstd C build is unavailable there. Both paths go through
//! [`decompress_bounded`] and must agree byte-for-byte on the shared golden
//! corpus (see `testdata/jetstream/golden`).
//!
//! Every decode is output-bounded: the decoder is drained incrementally and the
//! call fails with [`Error::LimitExceeded`] the moment the running output would
//! exceed `max_out`, so a hostile frame cannot force an unbounded allocation.

use super::error::{Error, Result};
use std::io::Read;

/// Go's `maxDecodedBlockBytes`: the hard cap on a single decompressed block
/// (1 GiB). Callers decoding live frames pass their own, smaller read limit.
pub const MAX_DECODED_BLOCK_BYTES: usize = 1 << 30;

/// Drain chunk size. Independent of the frame; just bounds per-read work.
const READ_CHUNK: usize = 64 * 1024;

/// Decompress a single zstd `frame`, failing if the output would exceed
/// `max_out`. `dict`, when present, is the raw structured dictionary the frame
/// was compressed with; pass `None` for the dictionary-less segment blocks.
pub fn decompress_bounded(frame: &[u8], max_out: usize, dict: Option<&[u8]>) -> Result<Vec<u8>> {
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    {
        decompress_native(frame, max_out, dict)
    }
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    {
        decompress_wasm(frame, max_out, dict)
    }
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn decompress_native(frame: &[u8], max_out: usize, dict: Option<&[u8]>) -> Result<Vec<u8>> {
    let cursor = std::io::Cursor::new(frame);
    let decoder = zstd::stream::read::Decoder::with_dictionary(cursor, dict.unwrap_or(&[]))
        .map_err(|e| Error::Compression(e.to_string()))?;
    // A getBlock frame and each live frame is exactly one zstd frame; stopping
    // after the first guards against trailing-frame smuggling.
    drain(decoder.single_frame(), max_out)
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn decompress_wasm(frame: &[u8], max_out: usize, dict: Option<&[u8]>) -> Result<Vec<u8>> {
    use ruzstd::decoding::{Dictionary, FrameDecoder, StreamingDecoder};

    let mut frame_decoder = FrameDecoder::new();
    if let Some(raw) = dict {
        let dictionary =
            Dictionary::decode_dict(raw).map_err(|e| Error::Compression(format!("{e:?}")))?;
        frame_decoder
            .add_dict(dictionary)
            .map_err(|e| Error::Compression(format!("{e:?}")))?;
    }
    let cursor = std::io::Cursor::new(frame);
    let decoder = StreamingDecoder::new_with_decoder(cursor, frame_decoder)
        .map_err(|e| Error::Compression(format!("{e:?}")))?;
    drain(decoder, max_out)
}

/// The little-endian magic that opens a zstd *structured* dictionary
/// (`ZSTD_MAGIC_DICTIONARY`, RFC 8878 §5). A raw-content dictionary has no such
/// header; the live protocol only ever ships structured dictionaries, so we
/// require it and read the framed dictionary ID that follows.
const DICTIONARY_MAGIC: u32 = 0xEC30_A437;

/// Parse the dictionary ID from a structured zstd dictionary.
///
/// A structured dictionary begins with a 4-byte little-endian magic
/// (`0xEC30A437`) followed by a 4-byte little-endian dictionary ID (RFC 8878
/// §5). The live tail compares this ID against the `zstdDictionary` value the
/// server advertised in each frame envelope: a mismatch means the server
/// rotated its dictionary, and the tail must refetch before it can decode
/// further frames. Mirrors the Go client's `zstddict.ParseID`.
///
/// Returns [`Error::InvalidDictionary`] if the input is shorter than the 8-byte
/// header, does not open with the structured-dictionary magic, or carries the
/// reserved ID `0` (which a real dictionary never uses).
pub fn parse_dictionary_id(dict: &[u8]) -> Result<u32> {
    let header: [u8; 8] =
        dict.get(..8)
            .and_then(|s| s.try_into().ok())
            .ok_or(Error::InvalidDictionary(
                "dictionary shorter than 8-byte header",
            ))?;
    let magic = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    if magic != DICTIONARY_MAGIC {
        return Err(Error::InvalidDictionary(
            "not a structured zstd dictionary (bad magic)",
        ));
    }
    let id = u32::from_le_bytes([header[4], header[5], header[6], header[7]]);
    if id == 0 {
        return Err(Error::InvalidDictionary("dictionary ID is zero"));
    }
    Ok(id)
}

/// Read `reader` to end into a fresh `Vec`, refusing to grow past `max_out`.
fn drain(mut reader: impl Read, max_out: usize) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::Compression(e.to_string()))?;
        if n == 0 {
            break;
        }
        let projected = out.len().saturating_add(n);
        if projected > max_out {
            return Err(Error::LimitExceeded {
                what: "decompressed output",
                value: projected as u64,
                limit: max_out as u64,
            });
        }
        out.extend_from_slice(&buf[..n]);
    }
    Ok(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// Build a minimal structured-dictionary header with the given ID.
    fn dict_header(id: u32) -> Vec<u8> {
        let mut v = DICTIONARY_MAGIC.to_le_bytes().to_vec();
        v.extend_from_slice(&id.to_le_bytes());
        v
    }

    #[test]
    fn parse_dictionary_id_reads_framed_id() {
        assert_eq!(parse_dictionary_id(&dict_header(1)).unwrap(), 1);
        assert_eq!(
            parse_dictionary_id(&dict_header(0xDEAD_BEEF)).unwrap(),
            0xDEAD_BEEF
        );
        // Trailing dictionary body after the header is ignored.
        let mut with_body = dict_header(42);
        with_body.extend_from_slice(&[0u8; 64]);
        assert_eq!(parse_dictionary_id(&with_body).unwrap(), 42);
    }

    #[test]
    fn parse_dictionary_id_rejects_bad_input() {
        // Too short to hold the 8-byte header.
        assert!(matches!(
            parse_dictionary_id(&[]),
            Err(Error::InvalidDictionary(_))
        ));
        assert!(matches!(
            parse_dictionary_id(&dict_header(1)[..7]),
            Err(Error::InvalidDictionary(_))
        ));
        // Right length, wrong magic.
        let mut wrong_magic = dict_header(1);
        wrong_magic[0] ^= 0xFF;
        assert!(matches!(
            parse_dictionary_id(&wrong_magic),
            Err(Error::InvalidDictionary(_))
        ));
        // Reserved ID zero.
        assert!(matches!(
            parse_dictionary_id(&dict_header(0)),
            Err(Error::InvalidDictionary(_))
        ));
    }
}
