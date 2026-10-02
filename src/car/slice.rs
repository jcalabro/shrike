use crate::car::CarError;
use crate::car::reader::{
    CID_LEN, check_block_len, check_header_len, decode_header, varint_from_slice,
};
use crate::cbor::Cid;

/// A block borrowed from a CAR held in memory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlockRef<'a> {
    pub cid: Cid,
    pub data: &'a [u8],
}

/// CAR v1 reader over bytes already in memory, such as a sync response or a
/// firehose event's `blocks`.
///
/// Blocks borrow from the input instead of being copied out, and it applies
/// the same validation, with the same errors, as [`Reader`](crate::car::Reader).
/// As an iterator it stops after the first error.
///
/// ```
/// # use shrike::car::{self, Block, SliceReader};
/// # use shrike::cbor::{Cid, Codec};
/// # let data = b"hello".to_vec();
/// # let cid = Cid::compute(Codec::Raw, &data);
/// # let car_bytes = car::write_all(&[cid], &[Block { cid, data }]).unwrap();
/// let mut reader = SliceReader::new(&car_bytes)?;
/// assert_eq!(reader.roots(), &[cid]);
/// for block in reader {
///     assert_eq!(block?.data, b"hello");
/// }
/// # Ok::<(), car::CarError>(())
/// ```
#[derive(Debug, Clone)]
pub struct SliceReader<'a> {
    rest: &'a [u8],
    pub(super) roots: Vec<Cid>,
}

impl<'a> SliceReader<'a> {
    /// Parse the CAR header, leaving the reader at the first block.
    pub fn new(car: &'a [u8]) -> Result<Self, CarError> {
        let (len, prefix) = match varint_from_slice(car)? {
            Some(varint) => varint,
            None if car.is_empty() => {
                return Err(CarError::InvalidHeader(
                    "unexpected EOF reading varint".into(),
                ));
            }
            None => return Err(CarError::InvalidBlock("truncated varint".into())),
        };
        let len = check_header_len(len)?;
        let Some((header, rest)) = car[prefix..].split_at_checked(len) else {
            return Err(CarError::InvalidHeader("truncated header".into()));
        };
        Ok(SliceReader {
            rest,
            roots: decode_header(header)?,
        })
    }

    /// The root CIDs declared in the CAR header.
    pub fn roots(&self) -> &[Cid] {
        &self.roots
    }

    /// The next block, or `None` at the end of the input.
    pub fn next_block(&mut self) -> Result<Option<BlockRef<'a>>, CarError> {
        self.next().transpose()
    }

    #[inline]
    fn split_block(&mut self) -> Result<BlockRef<'a>, CarError> {
        let buf = self.rest;
        // Nearly every block is 128 bytes to 16 KiB long: a two-byte length.
        let (len, prefix) = match *buf {
            [b0, ..] if b0 < 0x80 => (u64::from(b0), 1),
            [b0, b1, ..] if b1 < 0x80 && b1 != 0 => (u64::from(b0 & 0x7f) | u64::from(b1) << 7, 2),
            _ => varint_from_slice(buf)?
                .ok_or_else(|| CarError::InvalidBlock("truncated varint".into()))?,
        };
        let len = check_block_len(len)?;
        let truncated = || CarError::InvalidBlock("truncated block data".into());
        let frame = buf.get(prefix..).ok_or_else(truncated)?;
        let cid = Cid::from_bytes(frame.get(..CID_LEN).ok_or_else(truncated)?)?;
        let (block, rest) = frame.split_at_checked(len).ok_or_else(truncated)?;
        self.rest = rest;
        Ok(BlockRef {
            cid,
            data: &block[CID_LEN..],
        })
    }
}

impl<'a> Iterator for SliceReader<'a> {
    type Item = Result<BlockRef<'a>, CarError>;

    #[inline]
    fn next(&mut self) -> Option<Self::Item> {
        if self.rest.is_empty() {
            return None;
        }
        let block = self.split_block();
        if block.is_err() {
            // Nothing after a malformed block can be read.
            self.rest = &[];
        }
        Some(block)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::car::{Block, Reader, write_all};
    use crate::cbor::Codec;
    use proptest::prelude::*;

    fn sample_car(sizes: &[usize]) -> Vec<u8> {
        let blocks: Vec<Block> = sizes
            .iter()
            .enumerate()
            .map(|(i, &n)| {
                let data: Vec<u8> = (0..n).map(|j| (i * 31 + j) as u8).collect();
                Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();
        write_all(&[blocks[0].cid], &blocks).unwrap()
    }

    /// Roots, blocks and the error that stopped the read, with the error
    /// rendered so that messages must match too.
    type Outcome = (Option<Vec<Cid>>, Vec<(Cid, Vec<u8>)>, Option<String>);

    fn read_sync(car: &[u8]) -> Outcome {
        let mut reader = match Reader::new(car) {
            Ok(r) => r,
            Err(e) => return (None, Vec::new(), Some(format!("{e:?}"))),
        };
        let roots = Some(reader.roots().to_vec());
        let mut blocks = Vec::new();
        loop {
            match reader.next_block() {
                Ok(Some(b)) => blocks.push((b.cid, b.data)),
                Ok(None) => return (roots, blocks, None),
                Err(e) => return (roots, blocks, Some(format!("{e:?}"))),
            }
        }
    }

    fn read_slice(car: &[u8]) -> Outcome {
        let mut reader = match SliceReader::new(car) {
            Ok(r) => r,
            Err(e) => return (None, Vec::new(), Some(format!("{e:?}"))),
        };
        let roots = Some(reader.roots().to_vec());
        let mut blocks = Vec::new();
        for block in reader.by_ref() {
            match block {
                Ok(b) => blocks.push((b.cid, b.data.to_vec())),
                Err(e) => {
                    assert!(reader.next().is_none(), "the iterator stops after an error");
                    return (roots, blocks, Some(format!("{e:?}")));
                }
            }
        }
        (roots, blocks, None)
    }

    #[test]
    fn reads_blocks_in_place() {
        let car = sample_car(&[0, 1, 100, 4096]);
        let outcome = read_slice(&car);
        assert_eq!(outcome, read_sync(&car));
        assert_eq!(outcome.1.len(), 4);
        assert!(outcome.2.is_none());

        // Each block's data is a view of the input.
        let range = car.as_ptr_range();
        for block in SliceReader::new(&car).unwrap() {
            let data = block.unwrap().data.as_ptr_range();
            assert!(range.start <= data.start && data.end <= range.end);
        }
    }

    #[test]
    fn header_only_car() {
        let car = write_all(&[], &[]).unwrap();
        assert_eq!(read_slice(&car), (Some(vec![]), vec![], None));
    }

    #[test]
    fn matches_reader_on_every_truncation_and_mutation() {
        let car = sample_car(&[3, 40, 200]);
        for len in 0..=car.len() {
            assert_eq!(read_slice(&car[..len]), read_sync(&car[..len]), "{len}");
        }
        for i in 0..car.len() {
            for mutate in [|b: u8| b ^ 0x01, |b: u8| b ^ 0x80, |_| 0x00, |_| 0xff] {
                let mut bad = car.clone();
                bad[i] = mutate(bad[i]);
                assert_eq!(read_slice(&bad), read_sync(&bad), "byte {i}");
            }
        }
    }

    #[test]
    fn matches_reader_on_malformed_lengths() {
        let car = sample_car(&[10]);
        let (header_len, n) = varint_from_slice(&car).unwrap().unwrap();
        let blocks_at = n + header_len as usize;
        let mut huge_header = Vec::new();
        crate::cbor::varint::encode_varint((1 << 20) + 1, &mut huge_header);
        let mut huge_block = Vec::new();
        crate::cbor::varint::encode_varint((128 << 20) + 1, &mut huge_block);
        for prefix in [
            &[0x80, 0x00][..],             // non-minimal
            &[0xff; 9][..],                // too long
            &[0xff, 0xff, 0xff, 0xff][..], // truncated
            &[0x00][..],                   // empty
            &[CID_LEN as u8 - 1][..],      // shorter than a CID
            &huge_header[..],
            &huge_block[..],
        ] {
            // In place of the header length...
            assert_eq!(read_slice(prefix), read_sync(prefix), "{prefix:02x?}");
            // ...and of the first block length.
            let mut bad = car[..blocks_at].to_vec();
            bad.extend_from_slice(prefix);
            assert_eq!(read_slice(&bad), read_sync(&bad), "{prefix:02x?}");
        }
    }

    proptest! {
        #[test]
        fn prop_matches_reader(
            sizes in prop::collection::vec(0usize..600, 1..8),
            cut in any::<prop::sample::Index>(),
            flip in prop::option::of((any::<prop::sample::Index>(), 1u8..=255)),
        ) {
            let mut car = sample_car(&sizes);
            if let Some((at, mask)) = flip {
                let i = at.index(car.len());
                car[i] ^= mask;
            }
            let car = &car[..cut.index(car.len() + 1)];
            prop_assert_eq!(read_slice(car), read_sync(car));
        }
    }
}
