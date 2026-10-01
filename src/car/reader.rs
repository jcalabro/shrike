use std::io::{self, Read};

use crate::cbor::{Cid, Decoder, Value};

use crate::car::{Block, CarError};

/// Maximum size of the CAR header (1 MiB). The header contains roots and
/// version — anything larger than this is almost certainly malformed.
const MAX_HEADER_SIZE: u64 = 1 << 20;

/// Maximum size of a single CAR block (128 MiB). Blocks contain a CID + record
/// data. Legitimate AT Protocol records are far smaller than this.
const MAX_BLOCK_SIZE: u64 = 128 << 20;

/// Largest block buffer reserved up front from an untrusted length prefix.
/// Bigger blocks grow as their bytes arrive.
const PREALLOC_LIMIT: usize = 1 << 20;

/// Every block starts with a CIDv1 + sha2-256 multihash.
pub(super) const CID_LEN: usize = 36;

/// Streaming CAR v1 reader. Parses the header on construction, then yields
/// blocks one at a time via `next_block` or `next_block_into`.
pub struct Reader<R: Read> {
    reader: R,
    roots: Vec<Cid>,
}

impl<R: Read> Reader<R> {
    /// Parse the CAR header. Returns the reader positioned at the first block.
    pub fn new(mut reader: R) -> Result<Self, CarError> {
        let header_len = check_header_len(read_varint(&mut reader)?)?;
        let mut header_buf = vec![0u8; header_len];
        reader.read_exact(&mut header_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CarError::InvalidHeader("truncated header".into())
            } else {
                CarError::Io(e)
            }
        })?;
        let roots = decode_header(&header_buf)?;
        Ok(Reader { reader, roots })
    }

    /// Return the root CIDs declared in the CAR header.
    pub fn roots(&self) -> &[Cid] {
        &self.roots
    }

    /// Read the next block. Returns None at EOF.
    pub fn next_block(&mut self) -> Result<Option<Block>, CarError> {
        let mut block = Block::default();
        match self.next_block_into(&mut block)? {
            true => Ok(Some(block)),
            false => Ok(None),
        }
    }

    /// Read the next block into an existing `Block`, reusing its data buffer.
    ///
    /// Returns `Ok(true)` if a block was read, `Ok(false)` at EOF. The
    /// `block.data` Vec is resized to fit the new data but its allocation is
    /// reused across calls — no heap allocation when the next block is the
    /// same size or smaller than the previous one.
    ///
    /// ```no_run
    /// # use shrike::car::{Block, Reader};
    /// # fn example(reader: &mut Reader<&[u8]>) {
    /// let mut block = Block::default();
    /// while reader.next_block_into(&mut block).unwrap() {
    ///     // process block.cid, block.data...
    /// }
    /// # }
    /// ```
    pub fn next_block_into(&mut self, block: &mut Block) -> Result<bool, CarError> {
        // Read block length varint. Return false at EOF.
        let block_len = match read_varint_eof(&mut self.reader)? {
            Some(v) => v,
            None => return Ok(false),
        };

        let block_len_usize = check_block_len(block_len)?;

        // Read CID from first 36 bytes (stack buffer, no alloc)
        let mut cid_buf = [0u8; CID_LEN];
        self.reader.read_exact(&mut cid_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CarError::InvalidBlock("truncated block data".into())
            } else {
                CarError::Io(e)
            }
        })?;
        block.cid = Cid::from_bytes(&cid_buf)?;

        // Read data into the reusable buffer, reusing its allocation. The
        // length prefix is untrusted, so grow only as bytes actually arrive: a
        // tiny input claiming a 128 MiB block must not allocate 128 MiB.
        let data_len = block_len_usize - CID_LEN;
        block.data.clear();
        block.data.reserve(data_len.min(PREALLOC_LIMIT));
        let read = (&mut self.reader)
            .take(data_len as u64)
            .read_to_end(&mut block.data)?;
        if read != data_len {
            return Err(CarError::InvalidBlock("truncated block data".into()));
        }

        Ok(true)
    }
}

/// Validate a header length prefix.
pub(super) fn check_header_len(len: u64) -> Result<usize, CarError> {
    if len > MAX_HEADER_SIZE {
        return Err(CarError::InvalidHeader(format!(
            "header length {len} exceeds maximum of {MAX_HEADER_SIZE}"
        )));
    }
    Ok(len as usize)
}

/// Validate a block length prefix (CID + data).
pub(super) fn check_block_len(len: u64) -> Result<usize, CarError> {
    if len == 0 {
        return Err(CarError::InvalidBlock("zero-length block".into()));
    }
    if len > MAX_BLOCK_SIZE {
        return Err(CarError::InvalidBlock(format!(
            "block length {len} exceeds maximum of {MAX_BLOCK_SIZE}"
        )));
    }
    if len < CID_LEN as u64 {
        return Err(CarError::InvalidBlock(
            "block too short to contain CID".into(),
        ));
    }
    Ok(len as usize)
}

/// Decode the CAR header frame and return its roots.
pub(super) fn decode_header(buf: &[u8]) -> Result<Vec<Cid>, CarError> {
    // Decode header as a DRISL map. The header length varint frames exactly
    // one CBOR map; reject any trailing bytes inside that frame rather than
    // silently ignoring them (matches shrike's strict cbor::decode).
    let mut dec = Decoder::new(buf);
    let val = dec.decode()?;
    if !dec.is_empty() {
        return Err(CarError::InvalidHeader(
            "trailing data after header CBOR map".into(),
        ));
    }

    let entries = match val {
        Value::Map(entries) => entries,
        _ => return Err(CarError::InvalidHeader("header must be a CBOR map".into())),
    };

    let mut version: Option<u64> = None;
    let mut roots: Option<Vec<Cid>> = None;

    for (key, value) in entries {
        match key {
            "version" => {
                let v = match value {
                    Value::Unsigned(n) => n,
                    _ => {
                        return Err(CarError::InvalidHeader("version must be an integer".into()));
                    }
                };
                version = Some(v);
            }
            "roots" => {
                let items = match value {
                    Value::Array(items) => items,
                    _ => return Err(CarError::InvalidHeader("roots must be an array".into())),
                };
                let mut cids = Vec::with_capacity(items.len());
                for item in items {
                    match item {
                        Value::Cid(c) => cids.push(c),
                        _ => {
                            return Err(CarError::InvalidHeader("roots must contain CIDs".into()));
                        }
                    }
                }
                roots = Some(cids);
            }
            _ => {
                // Ignore unknown keys
            }
        }
    }

    let version =
        version.ok_or_else(|| CarError::InvalidHeader("missing 'version' field".into()))?;
    if version != 1 {
        return Err(CarError::InvalidHeader(format!(
            "unsupported version {version}, expected 1"
        )));
    }

    roots.ok_or_else(|| CarError::InvalidHeader("missing 'roots' field".into()))
}

/// Read a varint from a reader; returns Err on malformed varint or I/O error.
fn read_varint<R: Read>(reader: &mut R) -> Result<u64, CarError> {
    match read_varint_eof(reader)? {
        Some(v) => Ok(v),
        None => Err(CarError::InvalidHeader(
            "unexpected EOF reading varint".into(),
        )),
    }
}

/// Read an unsigned LEB128 varint from a reader; returns Ok(None) on clean EOF
/// at the first byte. Reads one byte at a time so it never consumes beyond the
/// varint's final byte (important for the streaming block reader, which reads
/// the CID + data immediately after).
fn read_varint_eof<R: Read>(reader: &mut R) -> Result<Option<u64>, CarError> {
    let mut buf = [0u8; 1];
    let mut value = 0;
    for i in 0.. {
        match reader.read(&mut buf) {
            Ok(0) if i == 0 => return Ok(None),
            Err(e) if i == 0 && e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
            Ok(0) => return Err(CarError::InvalidBlock("truncated varint".into())),
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CarError::InvalidBlock("truncated varint".into()));
            }
            Ok(_) => {}
            Err(e) => return Err(CarError::Io(e)),
        }
        if varint_step(&mut value, i, buf[0])? {
            return Ok(Some(value));
        }
    }
    Err(CarError::InvalidBlock("varint too long".into()))
}

/// Decode a varint from the start of `buf`, returning it and its encoded
/// length. Returns Ok(None) if `buf` ends before the varint does.
pub(super) fn varint_from_slice(buf: &[u8]) -> Result<Option<(u64, usize)>, CarError> {
    let mut value = 0;
    for (i, &byte) in buf.iter().enumerate() {
        if varint_step(&mut value, i, byte)? {
            return Ok(Some((value, i + 1)));
        }
    }
    Ok(None)
}

/// Fold byte `i` of an unsigned LEB128 varint into `value`, returning true
/// once the varint is complete.
///
/// Enforces the multiformats unsigned-varint rules that CAR/DASL framing
/// depends on: at most 9 bytes (63 bits, so no value above 2^63-1), and
/// canonical (minimal) encoding — a multi-byte varint whose final group is
/// zero (i.e. the value would have fit in fewer bytes) is rejected.
fn varint_step(value: &mut u64, i: usize, byte: u8) -> Result<bool, CarError> {
    *value |= u64::from(byte & 0x7F) << (7 * i);
    if byte & 0x80 == 0 {
        if i > 0 && byte == 0 {
            return Err(CarError::InvalidBlock("non-minimal varint encoding".into()));
        }
        return Ok(true);
    }
    if i == 8 {
        return Err(CarError::InvalidBlock("varint too long".into()));
    }
    Ok(false)
}
