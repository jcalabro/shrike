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
//! integrity without first trusting the stored value. Note that the compressed
//! block region `[256, footer_offset)` is *not* covered by the checksum; the
//! block index inside the footer is, so [`SegmentReader`] cross-checks each
//! block's on-disk length prefix against the checksum-protected index before
//! trusting a frame.
//!
//! [`SealedHeader`] parses and integrity-checks the header;
//! [`SegmentReader`] decodes and validates the block index and hands out
//! individual block frames for the columnar decoder in [`super::block`].

use super::error::{Error, Result};
use core::hash::Hasher;
use twox_hash::XxHash3_64;

/// Size of one block-index entry in the footer, matching Go's
/// `blockIndexEntrySize`.
pub const BLOCK_INDEX_ENTRY_SIZE: usize = 52;

/// Go's `maxBlockCountLimit`: the largest block count a segment may declare.
pub const MAX_BLOCK_COUNT: u32 = 1 << 20;

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

/// One entry of the block index: where a compressed block lives and the range
/// of events it covers. Mirrors Go's `BlockIndexEntry` (a 52-byte little-endian
/// record). `offset` points at the block's 8-byte little-endian compressed-length
/// prefix; the zstd frame itself begins at `offset + 8`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BlockIndexEntry {
    /// Byte offset of the block's length prefix within the segment.
    pub offset: u64,
    /// Compressed frame length in bytes, excluding the 8-byte length prefix.
    pub compressed_size: u32,
    /// Decompressed block length in bytes.
    pub uncompressed_size: u32,
    /// Number of events in the block.
    pub event_count: u32,
    /// Minimum Jetstream sequence in the block.
    pub min_seq: u64,
    /// Maximum Jetstream sequence in the block.
    pub max_seq: u64,
    /// Minimum witnessed time in the block (unix microseconds).
    pub min_witnessed_at: i64,
    /// Maximum witnessed time in the block (unix microseconds).
    pub max_witnessed_at: i64,
}

/// A validated view over a sealed segment: its header, its decoded block index,
/// and the segment bytes, offering per-block frame access for the columnar
/// decoder.
///
/// [`SegmentReader::open`] verifies the header checksum, decodes the block
/// index, and validates every block's placement and sequence ordering, so a
/// reader that opens successfully can hand out frames without re-checking
/// structure. Frame access still cross-checks the block's on-disk length prefix
/// against the checksum-protected index, since the block region itself is
/// outside the checksum.
pub struct SegmentReader<'a> {
    segment: &'a [u8],
    header: SealedHeader,
    blocks: Vec<BlockIndexEntry>,
}

impl<'a> SegmentReader<'a> {
    /// Open and fully validate a sealed segment: parse and checksum the header,
    /// decode the block index, and validate block layout and sequence ordering.
    pub fn open(segment: &'a [u8]) -> Result<Self> {
        let header = read_sealed_header(segment)?;
        let blocks = decode_block_index(&header, segment)?;
        validate_block_offsets(&header, &blocks)?;
        Ok(Self {
            segment,
            header,
            blocks,
        })
    }

    /// The verified segment header.
    pub fn header(&self) -> &SealedHeader {
        &self.header
    }

    /// The decoded, validated block index.
    pub fn blocks(&self) -> &[BlockIndexEntry] {
        &self.blocks
    }

    /// The number of blocks in the segment.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// The raw zstd frame for block `idx`, with its 8-byte length prefix
    /// stripped — byte-for-byte what a `getBlock` response carries. The prefix
    /// is cross-checked against the checksum-protected index before the frame is
    /// trusted, guarding the un-checksummed block region against tampering.
    pub fn block_frame(&self, idx: usize) -> Result<&'a [u8]> {
        let entry = self
            .blocks
            .get(idx)
            .ok_or(Error::CorruptSegment("block index out of range"))?;
        let offset = as_usize(entry.offset)?;
        let prefix = self
            .segment
            .get(offset..offset + 8)
            .ok_or(Error::Truncated("block length prefix"))?;
        // Infallible: the slice is exactly eight bytes.
        let declared = u64::from_le_bytes(prefix.try_into().unwrap_or([0; 8]));
        if declared != u64::from(entry.compressed_size) {
            return Err(Error::CorruptSegment(
                "block length prefix disagrees with block index",
            ));
        }
        let start = offset + 8;
        // `validate_block_offsets` proved `offset + 8 + compressed_size <=
        // footer_offset <= segment.len()`, so this range is in bounds.
        let end = start + entry.compressed_size as usize;
        self.segment
            .get(start..end)
            .ok_or(Error::Truncated("block frame"))
    }
}

/// Decode the block index from the footer of a sealed segment. The index is the
/// footer's first section, `header.block_count` entries of
/// [`BLOCK_INDEX_ENTRY_SIZE`] bytes each, beginning at `block_index_offset`
/// (which equals `footer_offset`).
pub fn decode_block_index(header: &SealedHeader, segment: &[u8]) -> Result<Vec<BlockIndexEntry>> {
    if header.block_count > MAX_BLOCK_COUNT {
        return Err(Error::LimitExceeded {
            what: "block count",
            value: u64::from(header.block_count),
            limit: u64::from(MAX_BLOCK_COUNT),
        });
    }
    let count = header.block_count as usize;
    let bytes_len = count
        .checked_mul(BLOCK_INDEX_ENTRY_SIZE)
        .ok_or(Error::CorruptSegment("block index size overflow"))?;
    let start = as_usize(header.block_index_offset)?;
    let end = start
        .checked_add(bytes_len)
        .ok_or(Error::CorruptSegment("block index end overflow"))?;
    // The index must lie within the footer, before the next section (the
    // segment-wide DID bloom). `validate_layout` (run by `read_sealed_header`)
    // already established the section ordering and bounds.
    if end as u64 > header.did_bloom_offset {
        return Err(Error::CorruptSegment(
            "block index overruns its footer section",
        ));
    }
    let buf = segment
        .get(start..end)
        .ok_or(Error::Truncated("block index"))?;
    let mut blocks = Vec::with_capacity(count);
    for i in 0..count {
        let e = &buf[i * BLOCK_INDEX_ENTRY_SIZE..(i + 1) * BLOCK_INDEX_ENTRY_SIZE];
        blocks.push(BlockIndexEntry {
            offset: read_u64(e, 0),
            compressed_size: read_u32(e, 8),
            uncompressed_size: read_u32(e, 12),
            event_count: read_u32(e, 16),
            min_seq: read_u64(e, 20),
            max_seq: read_u64(e, 28),
            min_witnessed_at: read_u64(e, 36) as i64,
            max_witnessed_at: read_u64(e, 44) as i64,
        });
    }
    Ok(blocks)
}

/// Validate the geometry and ordering of a decoded block index, mirroring Go's
/// `validateBlockOffsets`:
///
/// - each frame `[offset, offset + 8 + compressed_size)` lies within the block
///   region `[256, footer_offset)`;
/// - frames are strictly ascending and non-overlapping;
/// - each entry's `max_seq >= min_seq` and `max_witnessed_at >= min_witnessed_at`;
/// - sequences strictly increase across *non-empty* blocks (empty blocks, whose
///   `event_count == 0`, are skipped in the monotonicity check).
pub fn validate_block_offsets(header: &SealedHeader, blocks: &[BlockIndexEntry]) -> Result<()> {
    let footer = header.footer_offset;
    let mut prev_end: u64 = RESERVED_HEADER_BYTES as u64;
    let mut prev_nonempty_max_seq: Option<u64> = None;
    for b in blocks {
        if b.offset < RESERVED_HEADER_BYTES as u64 {
            return Err(Error::CorruptSegment("block offset inside header"));
        }
        let end = b
            .offset
            .checked_add(8)
            .and_then(|v| v.checked_add(u64::from(b.compressed_size)))
            .ok_or(Error::CorruptSegment("block frame end overflow"))?;
        if end > footer {
            return Err(Error::CorruptSegment("block frame overruns block region"));
        }
        // Strictly ascending, non-overlapping: the next frame must start at or
        // after the previous frame's end.
        if b.offset < prev_end {
            return Err(Error::CorruptSegment(
                "block frames overlap or are out of order",
            ));
        }
        prev_end = end;
        if b.max_seq < b.min_seq {
            return Err(Error::CorruptSegment("block max_seq below min_seq"));
        }
        if b.max_witnessed_at < b.min_witnessed_at {
            return Err(Error::CorruptSegment(
                "block max_witnessed_at below min_witnessed_at",
            ));
        }
        if b.event_count > 0 {
            if let Some(prev_max) = prev_nonempty_max_seq
                && b.min_seq <= prev_max
            {
                return Err(Error::CorruptSegment(
                    "block sequences are not strictly increasing",
                ));
            }
            prev_nonempty_max_seq = Some(b.max_seq);
        }
    }
    Ok(())
}

/// Convert a `u64` offset to `usize`, failing on a platform where it does not
/// fit (32-bit wasm) rather than truncating. A valid in-memory segment is at
/// most `usize::MAX` bytes, so every real offset fits.
fn as_usize(v: u64) -> Result<usize> {
    usize::try_from(v).map_err(|_| Error::CorruptSegment("offset exceeds address space"))
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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    /// A header whose footer holds `block_count` index entries and nothing else,
    /// so `did_bloom_offset` (and the rest) sit at end of file. The checksum is
    /// left zero because these tests exercise index decoding and layout
    /// validation directly, not `read_sealed_header`.
    fn header_for(block_count: u32, footer_offset: u64) -> SealedHeader {
        let index_end = footer_offset + u64::from(block_count) * BLOCK_INDEX_ENTRY_SIZE as u64;
        SealedHeader {
            checksum: 1,
            version: SEGMENT_VERSION,
            block_count,
            event_count: 0,
            unique_did_count: 0,
            min_seq: 0,
            max_seq: 0,
            min_witnessed_at: 0,
            max_witnessed_at: 0,
            footer_offset,
            did_bloom_offset: index_end,
            block_did_bloom_offset: index_end,
            collection_index_offset: index_end,
            block_index_offset: footer_offset,
        }
    }

    fn entry_bytes(e: &BlockIndexEntry) -> [u8; BLOCK_INDEX_ENTRY_SIZE] {
        let mut b = [0u8; BLOCK_INDEX_ENTRY_SIZE];
        b[0..8].copy_from_slice(&e.offset.to_le_bytes());
        b[8..12].copy_from_slice(&e.compressed_size.to_le_bytes());
        b[12..16].copy_from_slice(&e.uncompressed_size.to_le_bytes());
        b[16..20].copy_from_slice(&e.event_count.to_le_bytes());
        b[20..28].copy_from_slice(&e.min_seq.to_le_bytes());
        b[28..36].copy_from_slice(&e.max_seq.to_le_bytes());
        b[36..44].copy_from_slice(&e.min_witnessed_at.to_le_bytes());
        b[44..52].copy_from_slice(&e.max_witnessed_at.to_le_bytes());
        b
    }

    fn entry(
        offset: u64,
        compressed: u32,
        events: u32,
        min_seq: u64,
        max_seq: u64,
    ) -> BlockIndexEntry {
        BlockIndexEntry {
            offset,
            compressed_size: compressed,
            uncompressed_size: compressed,
            event_count: events,
            min_seq,
            max_seq,
            min_witnessed_at: 0,
            max_witnessed_at: 0,
        }
    }

    #[test]
    fn decode_block_index_round_trips_entries() {
        let e0 = entry(256, 10, 2, 1, 2);
        let e1 = entry(256 + 8 + 10, 20, 3, 3, 5);
        // Footer starts after both frames (offset+8+compressed of the last).
        let footer_offset = 256 + 8 + 10 + 8 + 20;
        let header = header_for(2, footer_offset);
        let mut seg = vec![0u8; footer_offset as usize];
        seg.extend_from_slice(&entry_bytes(&e0));
        seg.extend_from_slice(&entry_bytes(&e1));
        let blocks = decode_block_index(&header, &seg).unwrap();
        assert_eq!(blocks, vec![e0, e1]);
        validate_block_offsets(&header, &blocks).unwrap();
    }

    #[test]
    fn decode_block_index_rejects_over_limit_count() {
        let header = header_for(MAX_BLOCK_COUNT + 1, 256);
        // No need for real bytes: the count cap trips before any slice.
        assert!(matches!(
            decode_block_index(&header, &[0u8; 256]),
            Err(Error::LimitExceeded { .. })
        ));
    }

    #[test]
    fn decode_block_index_rejects_overrun_of_footer_section() {
        // block_count implies 52 index bytes, but did_bloom_offset leaves room
        // for only part of them.
        let footer_offset = 256u64;
        let mut header = header_for(1, footer_offset);
        header.did_bloom_offset = footer_offset + 10; // < footer_offset + 52
        header.block_did_bloom_offset = header.did_bloom_offset;
        header.collection_index_offset = header.did_bloom_offset;
        let seg = vec![0u8; (footer_offset + 52) as usize];
        assert!(matches!(
            decode_block_index(&header, &seg),
            Err(Error::CorruptSegment(_))
        ));
    }

    #[test]
    fn decode_block_index_rejects_truncated_index() {
        let footer_offset = 256u64;
        let header = header_for(1, footer_offset);
        // File ends before the single 52-byte entry is complete.
        let seg = vec![0u8; (footer_offset + 40) as usize];
        assert!(matches!(
            decode_block_index(&header, &seg),
            Err(Error::Truncated(_))
        ));
    }

    #[test]
    fn validate_block_offsets_accepts_empty_and_monotonic() {
        // Empty blocks (event_count 0) are skipped in the seq-monotonicity check.
        let header = header_for(3, 1000);
        let blocks = vec![
            entry(256, 10, 2, 1, 2),
            entry(256 + 18, 10, 0, 0, 0), // empty
            entry(256 + 36, 10, 2, 3, 4),
        ];
        validate_block_offsets(&header, &blocks).unwrap();
    }

    #[test]
    fn validate_block_offsets_rejects_overlap() {
        let header = header_for(2, 1000);
        let blocks = vec![
            entry(256, 100, 1, 1, 1),
            entry(300, 10, 1, 2, 2), // starts before prev end (256+8+100=364)
        ];
        assert!(matches!(
            validate_block_offsets(&header, &blocks),
            Err(Error::CorruptSegment(_))
        ));
    }

    #[test]
    fn validate_block_offsets_rejects_frame_past_footer() {
        let header = header_for(1, 300);
        // offset+8+compressed = 256+8+100 = 364 > footer_offset 300.
        let blocks = vec![entry(256, 100, 1, 1, 1)];
        assert!(matches!(
            validate_block_offsets(&header, &blocks),
            Err(Error::CorruptSegment(_))
        ));
    }

    #[test]
    fn validate_block_offsets_rejects_non_monotonic_seq() {
        let header = header_for(2, 1000);
        let blocks = vec![
            entry(256, 10, 2, 1, 5),
            entry(256 + 18, 10, 2, 5, 6), // min_seq 5 <= prev max_seq 5
        ];
        assert!(matches!(
            validate_block_offsets(&header, &blocks),
            Err(Error::CorruptSegment(_))
        ));
    }

    #[test]
    fn validate_block_offsets_rejects_inverted_ranges() {
        let header = header_for(1, 1000);
        let mut e = entry(256, 10, 1, 5, 1); // max_seq < min_seq
        assert!(matches!(
            validate_block_offsets(&header, &[e]),
            Err(Error::CorruptSegment(_))
        ));
        e = entry(256, 10, 1, 1, 2);
        e.min_witnessed_at = 10;
        e.max_witnessed_at = 5; // max < min
        assert!(matches!(
            validate_block_offsets(&header, &[e]),
            Err(Error::CorruptSegment(_))
        ));
    }

    #[test]
    fn validate_block_offsets_rejects_offset_in_header() {
        let header = header_for(1, 1000);
        let blocks = vec![entry(100, 10, 1, 1, 1)]; // offset < 256
        assert!(matches!(
            validate_block_offsets(&header, &blocks),
            Err(Error::CorruptSegment(_))
        ));
    }
}
