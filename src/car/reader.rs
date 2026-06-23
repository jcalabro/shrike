use std::io::{self, Read};

use crate::cbor::{Cid, Decoder, Value};

use crate::car::{Block, CarError};

/// Maximum size of the CAR header (1 MiB). The header contains roots and
/// version — anything larger than this is almost certainly malformed.
const MAX_HEADER_SIZE: u64 = 1 << 20;

/// Maximum size of a single CAR block (128 MiB). Blocks contain a CID + record
/// data. Legitimate AT Protocol records are far smaller than this.
const MAX_BLOCK_SIZE: u64 = 128 << 20;

/// Streaming CAR v1 reader. Parses the header on construction, then yields
/// blocks one at a time via `next_block` or `next_block_into`.
pub struct Reader<R: Read> {
    reader: R,
    roots: Vec<Cid>,
}

impl<R: Read> Reader<R> {
    /// Parse the CAR header. Returns the reader positioned at the first block.
    pub fn new(mut reader: R) -> Result<Self, CarError> {
        // Read header length varint.
        let header_len = read_varint(&mut reader)?;
        if header_len > MAX_HEADER_SIZE {
            return Err(CarError::InvalidHeader(format!(
                "header length {header_len} exceeds maximum of {MAX_HEADER_SIZE}"
            )));
        }

        // Read header bytes.
        let header_len_usize = header_len as usize;

        let mut header_buf = vec![0u8; header_len_usize];
        reader.read_exact(&mut header_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CarError::InvalidHeader("truncated header".into())
            } else {
                CarError::Io(e)
            }
        })?;

        // Decode header as a DRISL map. The header length varint frames exactly
        // one CBOR map; reject any trailing bytes inside that frame rather than
        // silently ignoring them (matches shrike's strict cbor::decode).
        let mut dec = Decoder::new(&header_buf);
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
                            return Err(CarError::InvalidHeader(
                                "version must be an integer".into(),
                            ));
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
                                return Err(CarError::InvalidHeader(
                                    "roots must contain CIDs".into(),
                                ));
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

        let roots = roots.ok_or_else(|| CarError::InvalidHeader("missing 'roots' field".into()))?;

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

        if block_len == 0 {
            return Err(CarError::InvalidBlock("zero-length block".into()));
        }

        if block_len > MAX_BLOCK_SIZE {
            return Err(CarError::InvalidBlock(format!(
                "block length {block_len} exceeds maximum of {MAX_BLOCK_SIZE}"
            )));
        }
        let block_len_usize = block_len as usize;

        if block_len_usize < 36 {
            return Err(CarError::InvalidBlock(
                "block too short to contain CID".into(),
            ));
        }

        // Read CID from first 36 bytes (stack buffer, no alloc)
        let mut cid_buf = [0u8; 36];
        self.reader.read_exact(&mut cid_buf).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CarError::InvalidBlock("truncated block data".into())
            } else {
                CarError::Io(e)
            }
        })?;
        block.cid = Cid::from_bytes(&cid_buf)?;

        // Read data into the reusable buffer — resizes but reuses allocation
        let data_len = block_len_usize - 36;
        block.data.resize(data_len, 0);
        self.reader.read_exact(&mut block.data).map_err(|e| {
            if e.kind() == io::ErrorKind::UnexpectedEof {
                CarError::InvalidBlock("truncated block data".into())
            } else {
                CarError::Io(e)
            }
        })?;

        Ok(true)
    }
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
/// at the first byte.
///
/// Enforces the multiformats unsigned-varint rules that CAR/DASL framing
/// depends on: at most 9 bytes (63 bits), no value above 2^63-1, and canonical
/// (minimal) encoding — a multi-byte varint whose final group is zero (i.e. the
/// value would have fit in fewer bytes) is rejected. Reads one byte at a time
/// so it never consumes beyond the varint's final byte (important for the
/// streaming block reader, which reads the CID + data immediately after).
fn read_varint_eof<R: Read>(reader: &mut R) -> Result<Option<u64>, CarError> {
    // Fast path: try to read the first byte. If EOF, return None.
    let mut buf = [0u8; 1];
    match reader.read(&mut buf) {
        Ok(0) => return Ok(None),
        Ok(_) => {}
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(CarError::Io(e)),
    }

    let first = buf[0];
    if first & 0x80 == 0 {
        // Single-byte varint (most common case for block sizes < 128).
        return Ok(Some(first as u64));
    }

    // Multi-byte varint — continue reading one byte at a time.
    let mut value: u64 = (first & 0x7F) as u64;
    let mut shift = 7u32;

    // The first byte was a continuation byte; allow at most 8 more (9 total =
    // 63 bits per the unsigned-varint spec).
    for _ in 1..9 {
        match reader.read(&mut buf) {
            Ok(0) => return Err(CarError::InvalidBlock("truncated varint".into())),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                return Err(CarError::InvalidBlock("truncated varint".into()));
            }
            Err(e) => return Err(CarError::Io(e)),
        }

        let byte = buf[0];

        // On the 9th byte (shift == 56) only the low 7 bits are valid, and the
        // value must not exceed 2^63-1; reject overflow rather than silently
        // discarding high bits.
        if shift >= 63 && (byte & 0x7F) > 1 {
            return Err(CarError::InvalidBlock("varint overflow".into()));
        }

        value |= ((byte & 0x7F) as u64) << shift;

        if byte & 0x80 == 0 {
            // Terminal byte. Reject a non-minimal encoding: a zero terminal
            // group means the value could have been encoded in fewer bytes.
            if byte == 0 {
                return Err(CarError::InvalidBlock("non-minimal varint encoding".into()));
            }
            return Ok(Some(value));
        }

        shift += 7;
    }

    Err(CarError::InvalidBlock("varint too long".into()))
}
