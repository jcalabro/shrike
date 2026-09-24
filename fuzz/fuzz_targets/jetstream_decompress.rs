#![no_main]
//! The bounded zstd decompressor is the trust boundary against decompression
//! bombs: it must never panic and must never return more than `max_out` bytes,
//! whatever the frame. The `max_out` cap is itself taken from the input so the
//! guard is exercised at many limits, including zero.

use libfuzzer_sys::fuzz_target;
use shrike::jetstream::decompress_bounded;

fuzz_target!(|data: &[u8]| {
    // Derive a modest, input-controlled output ceiling (<= 64 KiB) so the bound
    // is hit at many sizes without letting a bomb allocate without limit.
    let max_out = if data.len() >= 2 {
        ((usize::from(data[0]) << 8) | usize::from(data[1])) & 0xffff
    } else {
        0
    };
    let frame = if data.len() >= 2 { &data[2..] } else { data };
    if let Ok(out) = decompress_bounded(frame, max_out, None) {
        assert!(
            out.len() <= max_out,
            "decompress_bounded exceeded max_out: {} > {}",
            out.len(),
            max_out
        );
    }
});
