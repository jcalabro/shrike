//! Error types for the Jetstream v2 client.
//!
//! This enum grows one milestone at a time. M0 covers only the portable
//! segment codec, so the variants here describe segment/block/compression
//! decode failures. Transport, planning, and live-stream variants — and the
//! `is_fatal()` recoverable/fatal classification the engine relies on — arrive
//! with the milestones that introduce them.

use thiserror::Error;

/// A Jetstream v2 error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The segment declares a format version this client does not implement.
    #[error("unsupported segment version {found} (expected {expected})")]
    UnsupportedSegmentVersion { found: u16, expected: u16 },

    /// The segment's checksum field is zero, marking a still-active (unsealed)
    /// segment. The archive only serves sealed segments, so this is corruption
    /// or a truncated/partial file.
    #[error("segment is active/unsealed (zero checksum field)")]
    ActiveSegment,

    /// The recomputed xxh3 checksum does not match the sealed header.
    #[error("segment checksum mismatch: computed {computed:#018x}, header {stored:#018x}")]
    ChecksumMismatch { computed: u64, stored: u64 },

    /// A structural invariant was violated (bad magic, invalid kind, offsets
    /// that do not describe a valid layout, and so on).
    #[error("corrupt segment: {0}")]
    CorruptSegment(&'static str),

    /// The input ended before a structure it promised was fully present.
    #[error("truncated segment: {0}")]
    Truncated(&'static str),

    /// A declared or accumulated size exceeded a configured decode limit. This
    /// bounds allocation and guards against decompression bombs.
    #[error("decode limit exceeded: {what} ({value} > {limit})")]
    LimitExceeded {
        what: &'static str,
        value: u64,
        limit: u64,
    },

    /// zstd decompression failed. The message is the underlying decoder's,
    /// which never contains caller data.
    #[error("zstd decode failed: {0}")]
    Compression(String),

    /// The bytes offered as a zstd dictionary are not a valid structured
    /// dictionary.
    #[error("invalid zstd dictionary: {0}")]
    InvalidDictionary(&'static str),
}

/// Convenience alias for results carrying a Jetstream [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
