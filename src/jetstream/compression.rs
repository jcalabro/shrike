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
