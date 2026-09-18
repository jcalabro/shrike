//! Sealed `.jss` segment header parsing and whole-segment checksum
//! verification.
//!
//! A segment begins with a fixed 256-byte header: the `jss0` magic, a u64 xxh3
//! checksum, a u16 version, event/block/DID counts, seq and timestamp ranges,
//! and five section offsets, with the trailing header bytes zero. Compressed
//! blocks occupy `[256, footer_offset)`; the footer runs from `footer_offset`
//! to end of file, and its first section is the block index (so
//! `block_index_offset == footer_offset`).
//!
//! The checksum is `xxh3_64(header[12..256] ++ file[footer_offset..])` — the
//! magic and the checksum field itself are excluded, so a reader can verify
//! integrity without first trusting the stored value.
//!
//! M0 parses and integrity-checks the header. Block-index decoding and the
//! streaming block reader arrive in M2.

use super::error::{Error, Result};
use core::hash::Hasher;
use twox_hash::XxHash3_64;

/// Segment magic: the ASCII bytes `jss0`.
pub const MAGIC: [u8; 4] = *b"jss0";

/// Size of the fixed segment header, matching Go's `ReservedHeaderBytes`.
pub const RESERVED_HEADER_BYTES: usize = 256;

/// The only segment format version this client implements.
pub const SEGMENT_VERSION: u16 = 1;

/// The fixed header of a sealed segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SealedHeader {
    /// Stored xxh3 checksum over version-through-end-of-footer.
    pub checksum: u64,
    /// Format version (always [`SEGMENT_VERSION`] for a parsed header).
    pub version: u16,
    /// Number of blocks in `[256, footer_offset)`.
    pub block_count: u32,
    /// Total events across all blocks.
    pub event_count: u32,
    /// Distinct DID count (from the writer's bloom sizing).
    pub unique_did_count: u32,
    /// Minimum Jetstream sequence in the segment.
    pub min_seq: u64,
    /// Maximum Jetstream sequence in the segment.
    pub max_seq: u64,
    /// Minimum witnessed time (unix microseconds).
    pub min_witnessed_at: i64,
    /// Maximum witnessed time (unix microseconds).
    pub max_witnessed_at: i64,
    /// Offset where the footer (and its first section, the block index) begins.
    pub footer_offset: u64,
    /// Offset of the segment-wide DID bloom section.
    pub did_bloom_offset: u64,
    /// Offset of the per-block DID bloom section.
    pub block_did_bloom_offset: u64,
    /// Offset of the collection index section.
    pub collection_index_offset: u64,
    /// Offset of the block index; must equal `footer_offset`.
    pub block_index_offset: u64,
}

impl SealedHeader {
    /// Parse the fixed header from the first [`RESERVED_HEADER_BYTES`] of a
    /// segment. Rejects a bad magic, a zero (active) checksum, and an
    /// unsupported version. Does not validate section-offset ordering; use
    /// [`SealedHeader::validate_layout`] once the file length is known.
    ///
    /// The defined fields end at byte 98; bytes `[98, 256)` are reserved for
    /// future expansion. We deliberately do not require them to be zero, even
    /// though the current writer zero-fills them: the reference `decodeHeader`
    /// does not check them either, and a future writer may populate the region
    /// while keeping `version == 1`, expecting older readers to ignore it. The
    /// reserved bytes are still covered by the xxh3 checksum, so any alteration
    /// that does not recompute the checksum is rejected by
    /// [`SealedHeader::verify_checksum`].
    pub fn parse(bytes: &[u8]) -> Result<Self> {
        let head = bytes
            .get(..RESERVED_HEADER_BYTES)
            .ok_or(Error::Truncated("segment header"))?;
        if head[0..4] != MAGIC {
            return Err(Error::CorruptSegment("bad segment magic"));
        }
        let checksum = read_u64(head, 4);
        if checksum == 0 {
            return Err(Error::ActiveSegment);
        }
        let version = read_u16(head, 12);
        if version != SEGMENT_VERSION {
            return Err(Error::UnsupportedSegmentVersion {
                found: version,
                expected: SEGMENT_VERSION,
            });
        }
        Ok(Self {
            checksum,
            version,
            block_count: read_u32(head, 14),
            event_count: read_u32(head, 18),
            unique_did_count: read_u32(head, 22),
            min_seq: read_u64(head, 26),
            max_seq: read_u64(head, 34),
            min_witnessed_at: read_u64(head, 42) as i64,
            max_witnessed_at: read_u64(head, 50) as i64,
            footer_offset: read_u64(head, 58),
            did_bloom_offset: read_u64(head, 66),
            block_did_bloom_offset: read_u64(head, 74),
            collection_index_offset: read_u64(head, 82),
            block_index_offset: read_u64(head, 90),
        })
    }

    /// Validate that the section offsets describe a consistent layout for a
    /// file of `file_len` bytes:
    /// `256 <= footer_offset == block_index_offset <= did_bloom_offset <=
    /// block_did_bloom_offset <= collection_index_offset <= file_len`.
    pub fn validate_layout(&self, file_len: usize) -> Result<()> {
        let file_len = file_len as u64;
        if self.footer_offset < RESERVED_HEADER_BYTES as u64 {
            return Err(Error::CorruptSegment("footer offset inside header"));
        }
        if self.block_index_offset != self.footer_offset {
            return Err(Error::CorruptSegment(
                "block index offset must equal footer offset",
            ));
        }
        if !(self.footer_offset <= self.did_bloom_offset
            && self.did_bloom_offset <= self.block_did_bloom_offset
            && self.block_did_bloom_offset <= self.collection_index_offset
            && self.collection_index_offset <= file_len)
        {
            return Err(Error::CorruptSegment("footer section offsets out of order"));
        }
        Ok(())
    }

    /// Recompute the segment checksum over `segment` and compare it to the
    /// stored value. `segment` must be the whole sealed file. Validates the
    /// layout first so `footer_offset` is a safe slice bound.
    pub fn verify_checksum(&self, segment: &[u8]) -> Result<()> {
        self.validate_layout(segment.len())?;
        let footer_offset = self.footer_offset as usize;
        let header = segment
            .get(12..RESERVED_HEADER_BYTES)
            .ok_or(Error::Truncated("segment header"))?;
        let footer = segment
            .get(footer_offset..)
            .ok_or(Error::Truncated("segment footer"))?;
        let mut hasher = XxHash3_64::new();
        hasher.write(header);
        hasher.write(footer);
        let computed = hasher.finish();
        if computed != self.checksum {
            return Err(Error::ChecksumMismatch {
                computed,
                stored: self.checksum,
            });
        }
        Ok(())
    }
}

/// Parse a whole sealed segment's header and verify its checksum in one step.
pub fn read_sealed_header(segment: &[u8]) -> Result<SealedHeader> {
    let header = SealedHeader::parse(segment)?;
    header.verify_checksum(segment)?;
    Ok(header)
}

fn read_u16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn read_u32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}

fn read_u64(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        b[off],
        b[off + 1],
        b[off + 2],
        b[off + 3],
        b[off + 4],
        b[off + 5],
        b[off + 6],
        b[off + 7],
    ])
}
