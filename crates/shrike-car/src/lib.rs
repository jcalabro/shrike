use shrike_cbor::Cid;

pub mod reader;
pub mod writer;

pub use reader::Reader;
pub use writer::Writer;

#[derive(Debug, thiserror::Error)]
pub enum CarError {
    #[error("invalid CAR header: {0}")]
    InvalidHeader(String),
    #[error("invalid CAR block: {0}")]
    InvalidBlock(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("CBOR error: {0}")]
    Cbor(#[from] shrike_cbor::CborError),
}

/// A single block in a CAR file.
#[derive(Debug, Clone)]
pub struct Block {
    pub cid: Cid,
    pub data: Vec<u8>,
}

impl Default for Block {
    /// Creates a Block with a zeroed CID and empty data.
    ///
    /// The CID is not valid — this is intended for use with
    /// [`Reader::next_block_into`] which overwrites both fields.
    fn default() -> Self {
        Block {
            cid: Cid::zeroed(),
            data: Vec::new(),
        }
    }
}

/// Read all blocks from a CAR reader into memory.
pub fn read_all(mut reader: impl std::io::Read) -> Result<(Vec<Cid>, Vec<Block>), CarError> {
    let mut car = Reader::new(&mut reader)?;
    let roots = car.roots().to_vec();

    let mut blocks = Vec::new();
    while let Some(block) = car.next_block()? {
        blocks.push(block);
    }

    Ok((roots, blocks))
}

/// Write a complete CAR v1 file to bytes.
pub fn write_all(roots: &[Cid], blocks: &[Block]) -> Result<Vec<u8>, CarError> {
    // Pre-size: header (~100 bytes) + per-block (10 varint + 36 CID + data)
    let estimated = 128 + blocks.iter().map(|b| 10 + 36 + b.data.len()).sum::<usize>();
    let mut buf = Vec::with_capacity(estimated);
    let mut writer = Writer::new(&mut buf, roots)?;
    for block in blocks {
        writer.write_block(block)?;
    }
    Ok(buf)
}

/// Verify all blocks in a CAR file by recomputing each CID.
///
/// Uses the codec from the stored CID to compute a single SHA-256 hash per
/// block. Reuses a single buffer across all blocks to avoid per-block
/// heap allocation.
pub fn verify(mut reader: impl std::io::Read) -> Result<(), CarError> {
    let mut car = Reader::new(&mut reader)?;
    let mut block = Block::default();
    while car.next_block_into(&mut block)? {
        let computed = Cid::compute(block.cid.codec(), &block.data);
        if block.cid != computed {
            return Err(CarError::InvalidBlock(format!(
                "CID mismatch for block: stored {}, computed {}",
                block.cid, computed
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;
    use shrike_cbor::Codec;

    // ---------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------

    /// Build a valid CAR header buffer (varint-prefixed) from a raw CBOR map encoded
    /// by `build_fn`.  This lets individual tests inject malformed headers.
    fn build_car_with_header<F>(build_fn: F) -> Vec<u8>
    where
        F: FnOnce(&mut shrike_cbor::Encoder<&mut Vec<u8>>),
    {
        let mut header_buf = Vec::new();
        {
            let mut enc = shrike_cbor::Encoder::new(&mut header_buf);
            build_fn(&mut enc);
        }
        let mut car_buf = Vec::new();
        shrike_cbor::varint::encode_varint(header_buf.len() as u64, &mut car_buf);
        car_buf.extend_from_slice(&header_buf);
        car_buf
    }

    // ---------------------------------------------------------------------------
    // Original tests (preserved)
    // ---------------------------------------------------------------------------

    #[test]
    fn write_and_read_roundtrip() {
        let blocks: Vec<Block> = (0..3)
            .map(|i| {
                let data = format!("block {i}").into_bytes();
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        let written = write_all(&[blocks[0].cid], &blocks).unwrap();
        let (roots, read_blocks) = read_all(&written[..]).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0], blocks[0].cid);
        assert_eq!(read_blocks.len(), 3);
        for (orig, read) in blocks.iter().zip(read_blocks.iter()) {
            assert_eq!(orig.cid, read.cid);
            assert_eq!(orig.data, read.data);
        }
    }

    #[test]
    fn empty_car() {
        let root = Cid::compute(Codec::Drisl, b"root");
        let written = write_all(&[root], &[]).unwrap();
        let (roots, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(roots, vec![root]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn verify_valid_car() {
        let blocks: Vec<Block> = (0..3)
            .map(|i| {
                let data = format!("block {i}").into_bytes();
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        let written = write_all(&[blocks[0].cid], &blocks).unwrap();
        verify(&written[..]).unwrap();
    }

    #[test]
    fn verify_corrupt_data_fails() {
        let data = b"test data".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let mut written = write_all(&[cid], &[Block { cid, data }]).unwrap();
        // Corrupt the last byte of block data
        let len = written.len();
        written[len - 1] ^= 0xff;
        assert!(verify(&written[..]).is_err());
    }

    #[test]
    fn reader_rejects_wrong_version() {
        // Manually construct a header with version 2
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(2).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(0).unwrap();
            enc.encode_text("version").unwrap();
            enc.encode_u64(2).unwrap();
        });

        assert!(Reader::new(&car_buf[..]).is_err());
    }

    #[test]
    fn large_block_roundtrip() {
        let data = vec![0xABu8; 100_000];
        let cid = Cid::compute(Codec::Raw, &data);
        let block = Block { cid, data };
        let written = write_all(&[cid], std::slice::from_ref(&block)).unwrap();
        let (_, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data.len(), 100_000);
    }

    #[test]
    fn multiple_roots() {
        let root1 = Cid::compute(Codec::Drisl, b"root1");
        let root2 = Cid::compute(Codec::Drisl, b"root2");
        let written = write_all(&[root1, root2], &[]).unwrap();
        let (roots, _) = read_all(&written[..]).unwrap();
        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], root1);
        assert_eq!(roots[1], root2);
    }

    // ---------------------------------------------------------------------------
    // Reader edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn reader_empty_input_errors() {
        assert!(Reader::new(&[][..]).is_err());
    }

    #[test]
    fn reader_header_with_no_roots() {
        // A valid CAR v1 header whose roots array is empty is legal.
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(2).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(0).unwrap();
            enc.encode_text("version").unwrap();
            enc.encode_u64(1).unwrap();
        });
        let car = Reader::new(&car_buf[..]).unwrap();
        assert!(car.roots().is_empty());
    }

    #[test]
    fn reader_header_with_many_roots() {
        // Five roots should be accepted without error.
        let roots: Vec<Cid> = (0..5)
            .map(|i| Cid::compute(Codec::Drisl, format!("root{i}").as_bytes()))
            .collect();

        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(2).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(roots.len() as u64).unwrap();
            for r in &roots {
                enc.encode_cid(r).unwrap();
            }
            enc.encode_text("version").unwrap();
            enc.encode_u64(1).unwrap();
        });

        let car = Reader::new(&car_buf[..]).unwrap();
        assert_eq!(car.roots().len(), 5);
        for (i, r) in roots.iter().enumerate() {
            assert_eq!(car.roots()[i], *r);
        }
    }

    #[test]
    fn reader_truncated_block_errors() {
        // Write a valid header, then write a block-length varint that promises more
        // bytes than are actually present.
        let root = Cid::compute(Codec::Raw, b"root");
        let mut car = write_all(&[root], &[]).unwrap();

        // Claim a block of 200 bytes but write only 10.
        shrike_cbor::varint::encode_varint(200, &mut car);
        car.extend_from_slice(&[0u8; 10]);

        assert!(read_all(&car[..]).is_err());
    }

    #[test]
    fn reader_block_with_wrong_cid_length_errors() {
        // Build a header, then a block whose announced length < 36 (too short for a CID).
        let root = Cid::compute(Codec::Raw, b"root");
        let mut car = write_all(&[root], &[]).unwrap();

        // 10-byte "block": not enough to hold a 36-byte CID.
        let fake_data = vec![0u8; 10];
        shrike_cbor::varint::encode_varint(fake_data.len() as u64, &mut car);
        car.extend_from_slice(&fake_data);

        assert!(read_all(&car[..]).is_err());
    }

    #[test]
    fn reader_very_large_block() {
        // 1 MiB + 1 byte of data; verifies no length-overflow panics, etc.
        let data = vec![0x5Au8; 1_048_577];
        let cid = Cid::compute(Codec::Raw, &data);
        let block = Block {
            cid,
            data: data.clone(),
        };
        let written = write_all(&[cid], std::slice::from_ref(&block)).unwrap();
        let (_, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, data);
    }

    // ---------------------------------------------------------------------------
    // Writer edge cases
    // ---------------------------------------------------------------------------

    #[test]
    fn writer_zero_blocks_just_header() {
        let root = Cid::compute(Codec::Drisl, b"only-root");
        let written = write_all(&[root], &[]).unwrap();
        // Must be parseable; roots preserved; no blocks.
        let (roots, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(roots, vec![root]);
        assert!(blocks.is_empty());
    }

    #[test]
    fn writer_single_block() {
        let data = b"singleton".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let block = Block {
            cid,
            data: data.clone(),
        };
        let written = write_all(&[cid], std::slice::from_ref(&block)).unwrap();
        let (roots, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(roots, vec![cid]);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].data, data);
    }

    #[test]
    fn writer_many_blocks() {
        let blocks: Vec<Block> = (0..100)
            .map(|i| {
                let data = format!("block-{i:04}").into_bytes();
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        let written = write_all(&[blocks[0].cid], &blocks).unwrap();
        let (_, read_blocks) = read_all(&written[..]).unwrap();
        assert_eq!(read_blocks.len(), 100);
        for (orig, read) in blocks.iter().zip(read_blocks.iter()) {
            assert_eq!(orig.cid, read.cid);
            assert_eq!(orig.data, read.data);
        }
    }

    // ---------------------------------------------------------------------------
    // Roundtrip tests
    // ---------------------------------------------------------------------------

    #[test]
    fn roundtrip_mixed_codecs() {
        // Mix Drisl and Raw blocks in the same CAR.
        let drisl_data = b"drisl content".to_vec();
        let raw_data = b"raw content".to_vec();
        let drisl_block = Block {
            cid: Cid::compute(Codec::Drisl, &drisl_data),
            data: drisl_data.clone(),
        };
        let raw_block = Block {
            cid: Cid::compute(Codec::Raw, &raw_data),
            data: raw_data.clone(),
        };
        let blocks = vec![drisl_block.clone(), raw_block.clone()];
        let written = write_all(&[drisl_block.cid, raw_block.cid], &blocks).unwrap();
        let (roots, read_blocks) = read_all(&written[..]).unwrap();

        assert_eq!(roots.len(), 2);
        assert_eq!(roots[0], drisl_block.cid);
        assert_eq!(roots[1], raw_block.cid);
        assert_eq!(read_blocks.len(), 2);
        assert_eq!(read_blocks[0].cid, drisl_block.cid);
        assert_eq!(read_blocks[0].data, drisl_data);
        assert_eq!(read_blocks[1].cid, raw_block.cid);
        assert_eq!(read_blocks[1].data, raw_data);
    }

    #[test]
    fn roundtrip_preserves_exact_bytes() {
        // Ensure the raw bytes coming back from read are bit-for-bit identical.
        let data: Vec<u8> = (0u8..=255).cycle().take(512).collect();
        let cid = Cid::compute(Codec::Raw, &data);
        let block = Block {
            cid,
            data: data.clone(),
        };
        let written = write_all(&[cid], std::slice::from_ref(&block)).unwrap();
        let (_, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(blocks[0].data, data);
    }

    #[test]
    fn roundtrip_multiple_roots() {
        // Five roots, five blocks – each root maps 1-to-1 with its block.
        let pairs: Vec<(Cid, Block)> = (0..5)
            .map(|i| {
                let data = format!("content-{i}").into_bytes();
                let cid = Cid::compute(Codec::Drisl, &data);
                (cid, Block { cid, data })
            })
            .collect();
        let roots: Vec<Cid> = pairs.iter().map(|(c, _)| *c).collect();
        let blocks: Vec<Block> = pairs.into_iter().map(|(_, b)| b).collect();

        let written = write_all(&roots, &blocks).unwrap();
        let (read_roots, read_blocks) = read_all(&written[..]).unwrap();

        assert_eq!(read_roots, roots);
        assert_eq!(read_blocks.len(), blocks.len());
        for (orig, read) in blocks.iter().zip(read_blocks.iter()) {
            assert_eq!(orig.cid, read.cid);
            assert_eq!(orig.data, read.data);
        }
    }

    #[test]
    fn roundtrip_empty_data_blocks() {
        // Blocks with zero-length data payloads.
        let data: Vec<u8> = vec![];
        let cid = Cid::compute(Codec::Raw, &data);
        let block = Block {
            cid,
            data: data.clone(),
        };
        let written = write_all(&[cid], std::slice::from_ref(&block)).unwrap();
        let (_, blocks) = read_all(&written[..]).unwrap();
        assert_eq!(blocks.len(), 1);
        assert!(blocks[0].data.is_empty());
        assert_eq!(blocks[0].cid, cid);
    }

    // ---------------------------------------------------------------------------
    // Verify tests
    // ---------------------------------------------------------------------------

    #[test]
    fn verify_passes_on_valid_data() {
        let blocks: Vec<Block> = (0..5)
            .map(|i| {
                let data = format!("valid-{i}").into_bytes();
                Block {
                    cid: Cid::compute(if i % 2 == 0 { Codec::Drisl } else { Codec::Raw }, &data),
                    data,
                }
            })
            .collect();
        let roots = vec![blocks[0].cid];
        let written = write_all(&roots, &blocks).unwrap();
        verify(&written[..]).unwrap();
    }

    #[test]
    fn verify_fails_on_corrupted_cid() {
        // Write a valid block, then manually corrupt the CID bytes in the output
        // (the CID lives right after the block-length varint).
        let data = b"cid-corruption-test".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let mut written = write_all(&[cid], &[Block { cid, data }]).unwrap();

        // The CID bytes begin right after the header section.  Find the varint
        // that encodes the block length: it follows immediately after the header.
        // Rather than re-parsing, flip a byte in the hash portion of the first
        // CID (bytes 4..36 within the block payload, which starts after the
        // block-length varint).  We scan from the end of the header by writing
        // a second CAR with zero blocks to find the split point.
        let header_only = {
            let mut h = Vec::new();
            let w = Writer::new(&mut h, &[cid]).unwrap();
            // write nothing – just get header length
            let _ = w.finish();
            h
        };
        // block-length varint starts right after header_only
        let varint_start = header_only.len();
        // skip the varint (single byte if block_len < 128, else multi-byte)
        // block_len = 36 (cid) + data.len() < 128, so the varint is 1 byte.
        let cid_start = varint_start + 1;
        // flip a byte in the middle of the SHA-256 hash (offset 20 within CID)
        written[cid_start + 20] ^= 0xff;

        assert!(verify(&written[..]).is_err());
    }

    #[test]
    fn verify_fails_on_corrupted_block_data() {
        let data = b"block-data-corruption".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let mut written = write_all(&[cid], &[Block { cid, data }]).unwrap();
        // The block data lives at the very end – flip the last byte.
        let n = written.len();
        written[n - 1] ^= 0xAA;
        assert!(verify(&written[..]).is_err());
    }

    #[test]
    fn verify_fails_when_block_data_swapped() {
        // Two blocks whose CIDs are computed from their own data.
        // Swap the data payloads so each block's CID no longer matches its data.
        let data_a = b"payload-alpha".to_vec();
        let data_b = b"payload-beta".to_vec();
        let cid_a = Cid::compute(Codec::Raw, &data_a);
        let cid_b = Cid::compute(Codec::Raw, &data_b);

        // Write block_a with data_b and block_b with data_a (swapped).
        let blocks = vec![
            Block {
                cid: cid_a,
                data: data_b,
            },
            Block {
                cid: cid_b,
                data: data_a,
            },
        ];
        let written = write_all(&[cid_a, cid_b], &blocks).unwrap();
        assert!(verify(&written[..]).is_err());
    }

    // ---------------------------------------------------------------------------
    // Streaming reader test
    // ---------------------------------------------------------------------------

    #[test]
    fn streaming_reader_matches_read_all() {
        // Build a CAR with several blocks, then compare next_block() iteration
        // results with those from read_all().
        let blocks: Vec<Block> = (0..7)
            .map(|i| {
                let data = format!("stream-block-{i}").into_bytes();
                let codec = if i % 2 == 0 { Codec::Drisl } else { Codec::Raw };
                Block {
                    cid: Cid::compute(codec, &data),
                    data,
                }
            })
            .collect();
        let roots = vec![blocks[0].cid, blocks[1].cid];
        let written = write_all(&roots, &blocks).unwrap();

        // read_all path
        let (ra_roots, ra_blocks) = read_all(&written[..]).unwrap();

        // streaming path
        let mut car = Reader::new(&written[..]).unwrap();
        assert_eq!(car.roots(), ra_roots.as_slice());

        let mut stream_blocks = Vec::new();
        while let Some(block) = car.next_block().unwrap() {
            stream_blocks.push(block);
        }
        // Subsequent calls after EOF should return None, not an error.
        assert!(car.next_block().unwrap().is_none());

        assert_eq!(stream_blocks.len(), ra_blocks.len());
        for (s, r) in stream_blocks.iter().zip(ra_blocks.iter()) {
            assert_eq!(s.cid, r.cid);
            assert_eq!(s.data, r.data);
        }
    }

    // --- Security: header and block validation ---

    #[test]
    fn reader_rejects_version_zero() {
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(2).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(0).unwrap();
            enc.encode_text("version").unwrap();
            enc.encode_u64(0).unwrap();
        });
        assert!(Reader::new(&car_buf[..]).is_err());
    }

    #[test]
    fn reader_rejects_version_three() {
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(2).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(0).unwrap();
            enc.encode_text("version").unwrap();
            enc.encode_u64(3).unwrap();
        });
        assert!(Reader::new(&car_buf[..]).is_err());
    }

    #[test]
    fn reader_rejects_missing_roots() {
        // Header with version but no roots field
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(1).unwrap();
            enc.encode_text("version").unwrap();
            enc.encode_u64(1).unwrap();
        });
        assert!(Reader::new(&car_buf[..]).is_err());
    }

    #[test]
    fn reader_rejects_missing_version() {
        // Header with roots but no version field
        let car_buf = build_car_with_header(|enc| {
            enc.encode_map_header(1).unwrap();
            enc.encode_text("roots").unwrap();
            enc.encode_array_header(0).unwrap();
        });
        assert!(Reader::new(&car_buf[..]).is_err());
    }

    #[test]
    fn reader_rejects_incomplete_varint() {
        // Single byte 0x80 — continuation bit set but no follow-up byte
        let buf = [0x80];
        assert!(Reader::new(&buf[..]).is_err());
    }

    #[test]
    fn deterministic_write() {
        let blocks: Vec<Block> = (0..10)
            .map(|i| {
                let data = format!("block-{i}").into_bytes();
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        let first = write_all(&[blocks[0].cid], &blocks).unwrap();
        for _ in 0..10 {
            let again = write_all(&[blocks[0].cid], &blocks).unwrap();
            assert_eq!(first, again, "write_all must be deterministic");
        }
    }

    #[test]
    fn next_block_into_reuses_buffer() {
        // Verify that next_block_into doesn't allocate new buffers
        // by checking that the Vec capacity grows to the largest block
        // and stays there.
        let blocks: Vec<Block> = (0..5)
            .map(|i| {
                let data = vec![i as u8; 100 * (i + 1)];
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        let written = write_all(&[blocks[0].cid], &blocks).unwrap();

        let mut reader = Reader::new(&written[..]).unwrap();
        let mut block = Block::default();
        let mut max_cap = 0;
        while reader.next_block_into(&mut block).unwrap() {
            if block.data.capacity() > max_cap {
                max_cap = block.data.capacity();
            }
        }
        // After reading all blocks, capacity should be >= largest block data
        assert!(max_cap >= 500); // largest block is 500 bytes
    }
}
