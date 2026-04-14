use std::io::Write;

use crate::cbor::{Cid, Encoder, encode_text_map};

use crate::car::{Block, CarError};

/// Encode a varint into a stack buffer. Returns the number of bytes written.
#[inline]
fn encode_varint_buf(mut value: u64, buf: &mut [u8; 10]) -> usize {
    let mut i = 0;
    loop {
        let mut byte = (value & 0x7F) as u8;
        value >>= 7;
        if value != 0 {
            byte |= 0x80;
        }
        buf[i] = byte;
        i += 1;
        if value == 0 {
            break;
        }
    }
    i
}

/// Streaming CAR v1 writer. Writes the header on construction, then
/// accepts blocks one at a time via `write_block`.
pub struct Writer<W: Write> {
    writer: W,
}

impl<W: Write> Writer<W> {
    /// Write the CAR header with the given roots.
    pub fn new(mut writer: W, roots: &[Cid]) -> Result<Self, CarError> {
        // Encode the header: {"roots": [...CIDs], "version": 1}
        // Keys in CBOR order: "roots" (5 chars) before "version" (7 chars)
        let mut header_buf = Vec::with_capacity(64 + roots.len() * 41);
        {
            let mut enc = Encoder::new(&mut header_buf);
            let roots_snapshot = roots;
            encode_text_map(&mut enc, &["roots", "version"], |enc, key| match key {
                "roots" => {
                    enc.encode_array_header(roots_snapshot.len() as u64)?;
                    for cid in roots_snapshot {
                        enc.encode_cid(cid)?;
                    }
                    Ok(())
                }
                "version" => enc.encode_u64(1),
                _ => Ok(()),
            })?;
        }

        // Write varint(header_len) + header bytes
        let mut vbuf = [0u8; 10];
        let vlen = encode_varint_buf(header_buf.len() as u64, &mut vbuf);
        writer.write_all(&vbuf[..vlen])?;
        writer.write_all(&header_buf)?;

        Ok(Writer { writer })
    }

    /// Write a single block.
    #[inline]
    pub fn write_block(&mut self, block: &Block) -> Result<(), CarError> {
        let cid_bytes = block.cid.to_bytes();
        let block_len = cid_bytes.len() + block.data.len();

        // Write varint(block_len) from stack buffer — no heap allocation
        let mut vbuf = [0u8; 10];
        let vlen = encode_varint_buf(block_len as u64, &mut vbuf);
        self.writer.write_all(&vbuf[..vlen])?;

        // Write CID + data
        self.writer.write_all(&cid_bytes)?;
        self.writer.write_all(&block.data)?;

        Ok(())
    }

    /// Finish writing and return the underlying writer.
    pub fn finish(self) -> W {
        self.writer
    }
}
