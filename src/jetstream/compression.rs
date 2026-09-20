//! Bounded zstd decode.
//!
//! Native builds decode with libzstd through the `zstd` crate; the browser
//! target (`wasm32-unknown-unknown`) uses the pure-Rust `ruzstd` decoder, since
//! the libzstd C build is unavailable there. Both paths go through
//! [`decompress_bounded`] and must agree byte-for-byte on the shared golden
//! corpus (see `testdata/jetstream/golden`).
//!
//! [`decompress_bounded`] mirrors the reference Go client's klauspost
//! `Decoder.DecodeAll` contract exactly:
//!
//! - the input may hold any number of concatenated zstd frames; their outputs
//!   are concatenated in order;
//! - skippable frames (RFC 8878 §3.1.2) are skipped;
//! - empty input decodes to empty output;
//! - anything after a frame that is not another frame is an error — trailing
//!   garbage is never silently ignored;
//! - each frame's declared window is capped at `min(512 MiB, max_out)`
//!   (klauspost's `MaxWindowSize` clamped by `WithDecoderMaxMemory`), so a
//!   hostile frame cannot force a huge window allocation;
//! - the total decompressed output across all frames is capped at `max_out`:
//!   the decoder is drained incrementally and the call fails with
//!   [`Error::LimitExceeded`] the moment the running output would exceed it.

use super::error::{Error, Result};
use std::io::Read;

/// Go's `maxDecodedBlockBytes`: the hard cap on a single decompressed block
/// (1 GiB). Callers decoding live frames pass their own, smaller read limit.
pub const MAX_DECODED_BLOCK_BYTES: usize = 1 << 30;

/// klauspost's default `MaxWindowSize` (512 MiB): a frame declaring a larger
/// window is rejected before any decode work. `WithDecoderMaxMemory` clamps it
/// further, which [`decompress_bounded`] mirrors with `min(this, max_out)`.
const MAX_WINDOW_BYTES: u64 = 1 << 29;

/// The RFC 8878 minimum window size (1 KiB), used as the floor when a
/// single-segment frame derives its window from the frame content size.
const MIN_WINDOW_BYTES: u64 = 1 << 10;

/// Little-endian magic opening a standard zstd frame (RFC 8878 §3.1.1).
const FRAME_MAGIC: u32 = 0xFD2F_B528;

/// Skippable frames use magics `0x184D2A50..=0x184D2A5F` (RFC 8878 §3.1.2).
const SKIPPABLE_MAGIC_BASE: u32 = 0x184D_2A50;
const SKIPPABLE_MAGIC_MASK: u32 = 0xFFFF_FFF0;

/// Drain chunk size. Independent of the frame; just bounds per-read work.
const READ_CHUNK: usize = 64 * 1024;

/// Decompress every zstd frame in `input`, concatenating their outputs and
/// failing if the total would exceed `max_out`. `dict`, when present, is the
/// raw structured dictionary the frames were compressed with; pass `None` for
/// the dictionary-less segment blocks. Matches the Go client's klauspost
/// `DecodeAll` semantics (see the module docs).
pub fn decompress_bounded(input: &[u8], max_out: usize, dict: Option<&[u8]>) -> Result<Vec<u8>> {
    let max_window = MAX_WINDOW_BYTES.min(max_out as u64);
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < input.len() {
        let rest = &input[off..];
        if let Some(skip) = skippable_frame_len(rest)? {
            // `skippable_frame_len` bounds `skip` by `rest.len()`, so this
            // cannot overshoot the input.
            off += skip;
            continue;
        }
        check_frame_header(rest, max_window, max_out as u64)?;
        let consumed = decompress_one_frame(rest, max_out, dict, &mut out)?;
        if consumed == 0 {
            // Defensive: a validated frame header guarantees progress, but a
            // decoder bug must not spin this loop forever.
            return Err(Error::Compression(
                "zstd frame consumed no input".to_owned(),
            ));
        }
        off += consumed;
    }
    Ok(out)
}

/// If `rest` opens with a skippable-frame magic, return the whole frame's
/// length (magic + 4-byte size + content). A skippable frame truncated by the
/// end of input is an error, as in Go.
fn skippable_frame_len(rest: &[u8]) -> Result<Option<usize>> {
    let Some(magic) = read_le_u32(rest, 0) else {
        return Err(Error::Compression("truncated zstd frame header".to_owned()));
    };
    if magic & SKIPPABLE_MAGIC_MASK != SKIPPABLE_MAGIC_BASE {
        return Ok(None);
    }
    let Some(size) = read_le_u32(rest, 4) else {
        return Err(Error::Compression(
            "truncated zstd skippable frame".to_owned(),
        ));
    };
    let total = 8usize
        .checked_add(size as usize)
        .filter(|&t| t <= rest.len())
        .ok_or_else(|| Error::Compression("truncated zstd skippable frame".to_owned()))?;
    Ok(Some(total))
}

/// Validate the next frame's magic and declared window before handing it to a
/// decoder, mirroring klauspost's pre-decode checks: a non-single-segment
/// frame's window descriptor must not exceed `max_window`
/// (`ErrWindowSizeExceeded`), and a single-segment frame's implied window
/// (`max(frame content size, 1 KiB)`) must not exceed the output cap
/// (`ErrDecoderSizeExceeded`).
fn check_frame_header(rest: &[u8], max_window: u64, max_out: u64) -> Result<()> {
    let magic = read_le_u32(rest, 0)
        .ok_or_else(|| Error::Compression("truncated zstd frame header".to_owned()))?;
    if magic != FRAME_MAGIC {
        return Err(Error::Compression("unknown zstd frame magic".to_owned()));
    }
    let &fhd = rest
        .get(4)
        .ok_or_else(|| Error::Compression("truncated zstd frame header".to_owned()))?;
    let single_segment = fhd & (1 << 5) != 0;
    if !single_segment {
        // Window descriptor byte follows the frame header descriptor
        // (RFC 8878 §3.1.1.1.2).
        let &wd = rest
            .get(5)
            .ok_or_else(|| Error::Compression("truncated zstd frame header".to_owned()))?;
        let window_log = 10 + u64::from(wd >> 3);
        let window_base = 1u64 << window_log;
        let window_add = (window_base / 8) * u64::from(wd & 0x7);
        let window = window_base + window_add;
        if window > max_window {
            return Err(Error::Compression(format!(
                "zstd window size {window} exceeds maximum {max_window}"
            )));
        }
        return Ok(());
    }
    // Single-segment frame: no window descriptor; the window is the frame
    // content size, whose field follows the (optional) dictionary ID.
    let dict_id_len = match fhd & 3 {
        0 => 0usize,
        1 => 1,
        2 => 2,
        _ => 4,
    };
    let fcs_len = match fhd >> 6 {
        0 => 1usize, // single-segment: FCS is always present, 1 byte here
        1 => 2,
        2 => 4,
        _ => 8,
    };
    let fcs_off = 5 + dict_id_len;
    let fcs_bytes = rest
        .get(fcs_off..fcs_off + fcs_len)
        .ok_or_else(|| Error::Compression("truncated zstd frame header".to_owned()))?;
    let fcs = match fcs_bytes.len() {
        1 => u64::from(fcs_bytes[0]),
        // With a 2-byte field the offset 256 is added (RFC 8878 §3.1.1.1.4).
        2 => u64::from(u16::from_le_bytes([fcs_bytes[0], fcs_bytes[1]])) + 256,
        4 => u64::from(u32::from_le_bytes([
            fcs_bytes[0],
            fcs_bytes[1],
            fcs_bytes[2],
            fcs_bytes[3],
        ])),
        _ => u64::from_le_bytes([
            fcs_bytes[0],
            fcs_bytes[1],
            fcs_bytes[2],
            fcs_bytes[3],
            fcs_bytes[4],
            fcs_bytes[5],
            fcs_bytes[6],
            fcs_bytes[7],
        ]),
    };
    let window = fcs.max(MIN_WINDOW_BYTES);
    if window > max_out {
        return Err(Error::LimitExceeded {
            what: "decompressed output",
            value: window,
            limit: max_out,
        });
    }
    Ok(())
}

/// Read a little-endian u32 at `off`, or `None` when out of bounds.
fn read_le_u32(bytes: &[u8], off: usize) -> Option<u32> {
    let s = bytes.get(off..off + 4)?;
    Some(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Decode exactly one frame from the front of `rest`, appending to `out`
/// (bounded so `out` never exceeds `max_out` in total) and returning the
/// number of input bytes the frame consumed.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
fn decompress_one_frame(
    rest: &[u8],
    max_out: usize,
    dict: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<usize> {
    let mut cursor = std::io::Cursor::new(rest);
    let mut decoder =
        zstd::stream::read::Decoder::with_dictionary(&mut cursor, dict.unwrap_or(&[]))
            .map_err(|e| Error::Compression(e.to_string()))?
            .single_frame();
    // The pre-decode byte-exact window check above is the real bound; this only
    // lifts libzstd's default (2^27) above the 512 MiB cap so it never rejects
    // a frame the reference client accepts.
    decoder
        .window_log_max(30)
        .map_err(|e| Error::Compression(e.to_string()))?;
    drain_into(&mut decoder, out, max_out)?;
    // Consume the frame epilogue so the cursor lands exactly after the frame.
    decoder
        .finish_frame()
        .map_err(|e| Error::Compression(e.to_string()))?;
    drop(decoder);
    Ok(cursor.position() as usize)
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
fn decompress_one_frame(
    rest: &[u8],
    max_out: usize,
    dict: Option<&[u8]>,
    out: &mut Vec<u8>,
) -> Result<usize> {
    use ruzstd::decoding::{Dictionary, FrameDecoder, StreamingDecoder};

    let mut frame_decoder = FrameDecoder::new();
    if let Some(raw) = dict {
        let dictionary =
            Dictionary::decode_dict(raw).map_err(|e| Error::Compression(format!("{e:?}")))?;
        frame_decoder
            .add_dict(dictionary)
            .map_err(|e| Error::Compression(format!("{e:?}")))?;
    }
    let mut cursor = std::io::Cursor::new(rest);
    let mut decoder = StreamingDecoder::new_with_decoder(&mut cursor, frame_decoder)
        .map_err(|e| Error::Compression(format!("{e:?}")))?;
    drain_into(&mut decoder, out, max_out)?;
    // Verify the frame content checksum when present, matching libzstd and the
    // Go client's klauspost decoder; ruzstd only records it.
    let frame_decoder = decoder.into_frame_decoder();
    if let (Some(want), Some(got)) = (
        frame_decoder.get_checksum_from_data(),
        frame_decoder.get_calculated_checksum(),
    ) && want != got
    {
        return Err(Error::Compression(
            "zstd content checksum mismatch".to_owned(),
        ));
    }
    Ok(cursor.position() as usize)
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

/// Read `reader` to end, appending to `out` and refusing to grow `out` past
/// `max_out` in total (the cap spans every frame of one decompress call).
fn drain_into(mut reader: impl Read, out: &mut Vec<u8>, max_out: usize) -> Result<()> {
    let mut buf = [0u8; READ_CHUNK];
    loop {
        let n = reader
            .read(&mut buf)
            .map_err(|e| Error::Compression(e.to_string()))?;
        if n == 0 {
            return Ok(());
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

    fn compress(data: &[u8]) -> Vec<u8> {
        zstd::stream::encode_all(std::io::Cursor::new(data), 3).unwrap()
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

    #[test]
    fn empty_input_decodes_to_empty_output() {
        // klauspost DecodeAll on empty input returns empty output, no error.
        assert_eq!(
            decompress_bounded(&[], 4 << 20, None).unwrap(),
            Vec::<u8>::new()
        );
    }

    #[test]
    fn concatenated_frames_decode_in_order() {
        let mut input = compress(b"hello ");
        input.extend_from_slice(&compress(b"world"));
        let out = decompress_bounded(&input, 4 << 20, None).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn trailing_garbage_after_frame_is_rejected() {
        let mut input = compress(b"data");
        input.extend_from_slice(b"garbage!");
        assert!(matches!(
            decompress_bounded(&input, 4 << 20, None),
            Err(Error::Compression(_))
        ));
    }

    #[test]
    fn skippable_frames_are_skipped() {
        // Leading skippable frame, then a data frame, then another skippable.
        let mut input = Vec::new();
        input.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        input.extend_from_slice(&4u32.to_le_bytes());
        input.extend_from_slice(&[0xAA; 4]);
        input.extend_from_slice(&compress(b"payload"));
        input.extend_from_slice(&0x184D_2A5Fu32.to_le_bytes());
        input.extend_from_slice(&0u32.to_le_bytes());
        let out = decompress_bounded(&input, 4 << 20, None).unwrap();
        assert_eq!(out, b"payload");
    }

    #[test]
    fn truncated_skippable_frame_is_rejected() {
        let mut input = Vec::new();
        input.extend_from_slice(&0x184D_2A50u32.to_le_bytes());
        input.extend_from_slice(&16u32.to_le_bytes());
        input.extend_from_slice(&[0xAA; 4]); // declared 16 bytes, only 4 present
        assert!(matches!(
            decompress_bounded(&input, 4 << 20, None),
            Err(Error::Compression(_))
        ));
    }

    #[test]
    fn oversized_window_is_rejected_before_decode() {
        // Hand-built header: magic, descriptor (no single-segment, no dict ID,
        // no FCS), window descriptor exponent 20 → windowLog 30 → 1 GiB.
        let mut input = FRAME_MAGIC.to_le_bytes().to_vec();
        input.push(0x00);
        input.push(20 << 3);
        let err = decompress_bounded(&input, MAX_DECODED_BLOCK_BYTES, None).unwrap_err();
        assert!(matches!(err, Error::Compression(m) if m.contains("window")));
    }

    #[test]
    fn window_within_reference_cap_is_accepted_at_header_check() {
        // Window descriptor exponent 19 → windowLog 29 → exactly 512 MiB, the
        // reference client's cap: the header check must pass (the truncated
        // body then fails later, in the decoder proper).
        let mut input = FRAME_MAGIC.to_le_bytes().to_vec();
        input.push(0x00);
        input.push(19 << 3);
        assert!(check_frame_header(&input, MAX_WINDOW_BYTES, u64::MAX).is_ok());
    }

    #[test]
    fn live_read_limit_caps_declared_window() {
        // With a 64 KiB output cap (a live read limit), a 1 MiB window is
        // rejected even though it is far below the 512 MiB block cap —
        // matching Go's WithDecoderMaxMemory(readLimit) clamp.
        let mut input = FRAME_MAGIC.to_le_bytes().to_vec();
        input.push(0x00);
        input.push(10 << 3); // windowLog 20 → 1 MiB
        let err = decompress_bounded(&input, 64 * 1024, None).unwrap_err();
        assert!(matches!(err, Error::Compression(m) if m.contains("window")));
    }

    #[test]
    fn output_cap_trips_when_window_is_within_bounds() {
        // A high-expansion frame whose declared window fits the cap but whose
        // decompressed output exceeds it: 4 MiB of zeros (declared window
        // ~2 MiB at level 3) against a 3 MiB cap must trip the output limit
        // during the drain — the compression-bomb bound, matching klauspost's
        // ErrDecoderSizeExceeded.
        let bomb = compress(&vec![0u8; 4 << 20]);
        assert!(bomb.len() < 64 * 1024, "bomb should compress small");
        let err = decompress_bounded(&bomb, 3 << 20, None).unwrap_err();
        assert!(matches!(err, Error::LimitExceeded { .. }));
        // The same frame under a roomy cap decodes fully.
        let out = decompress_bounded(&bomb, 5 << 20, None).unwrap();
        assert_eq!(out.len(), 4 << 20);
    }

    #[test]
    fn single_segment_fcs_beyond_output_cap_is_rejected() {
        // Single-segment frame declaring a 1 MiB content size against a
        // 64 KiB cap: rejected from the header, before any decoding.
        let mut input = FRAME_MAGIC.to_le_bytes().to_vec();
        // fhd: fcs field size code 2 (4 bytes) | single-segment flag.
        input.push((2 << 6) | (1 << 5));
        input.extend_from_slice(&(1u32 << 20).to_le_bytes());
        let err = decompress_bounded(&input, 64 * 1024, None).unwrap_err();
        assert!(matches!(err, Error::LimitExceeded { .. }));
    }
}
