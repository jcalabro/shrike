use std::ops::Range;

use crate::car::reader::{
    CID_LEN, check_block_len, check_header_len, decode_header, varint_from_slice,
};
use crate::car::{Block, CarError};
use crate::cbor::Cid;

/// Incremental CAR v1 reader for bytes that arrive in chunks, such as a
/// streamed HTTP response body.
///
/// Unlike [`Reader`](crate::car::Reader) it performs no I/O, so it works with
/// any async runtime (or none): [`push`](Self::push) appends a chunk, and
/// [`next_block`](Self::next_block) yields each block once all of its bytes
/// have arrived. It applies the same validation as `Reader`. Draining every
/// available block after each push keeps the buffer to at most one partial
/// block plus the latest chunk.
///
/// ```
/// # use shrike::car::{self, Block, IncrementalReader};
/// # use shrike::cbor::{Cid, Codec};
/// # let data = b"hello".to_vec();
/// # let cid = Cid::compute(Codec::Raw, &data);
/// # let car_bytes = car::write_all(&[cid], &[Block { cid, data }]).unwrap();
/// let mut reader = IncrementalReader::new();
/// let mut blocks = Vec::new();
/// for chunk in car_bytes.chunks(7) {
///     reader.push(chunk);
///     while let Some(block) = reader.next_block()? {
///         blocks.push(block);
///     }
/// }
/// reader.finish()?;
/// assert_eq!(reader.roots(), Some(&[cid][..]));
/// assert_eq!(blocks.len(), 1);
/// # Ok::<(), car::CarError>(())
/// ```
#[derive(Debug, Default)]
pub struct IncrementalReader {
    buf: Vec<u8>,
    /// Start of the unconsumed bytes in `buf`.
    pos: usize,
    roots: Option<Vec<Cid>>,
}

impl IncrementalReader {
    pub fn new() -> Self {
        Self::default()
    }

    /// Append the next chunk of the CAR stream.
    pub fn push(&mut self, chunk: &[u8]) {
        if self.pos > 0 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        self.buf.extend_from_slice(chunk);
    }

    /// The root CIDs declared in the CAR header, once it has arrived.
    pub fn roots(&self) -> Option<&[Cid]> {
        self.roots.as_deref()
    }

    /// Decode the next block from the bytes pushed so far.
    ///
    /// Returns `Ok(None)` when the next block (or the header) has not fully
    /// arrived; push more bytes, or call [`finish`](Self::finish) at the end
    /// of the stream. After an error the stream is invalid and the reader
    /// should be discarded.
    pub fn next_block(&mut self) -> Result<Option<Block>, CarError> {
        if !self.read_header()? {
            return Ok(None);
        }
        let Some(frame) = self.next_frame(check_block_len)? else {
            return Ok(None);
        };
        let frame = &self.buf[frame];
        Ok(Some(Block {
            cid: Cid::from_bytes(&frame[..CID_LEN])?,
            data: frame[CID_LEN..].to_vec(),
        }))
    }

    /// The data length (excluding the CID) of the next block, as soon as its
    /// length prefix has arrived and before its body has.
    ///
    /// Lets a caller enforce its own limits before buffering a block that
    /// would exceed them. Returns `Ok(None)` while the prefix (or the header)
    /// is incomplete; consumes nothing but the header.
    pub fn next_block_data_len(&mut self) -> Result<Option<usize>, CarError> {
        if !self.read_header()? {
            return Ok(None);
        }
        let Some((len, _)) = varint_from_slice(&self.buf[self.pos..])? else {
            return Ok(None);
        };
        Ok(Some(check_block_len(len)? - CID_LEN))
    }

    /// Check that the stream ended cleanly: the header arrived and no partial
    /// block is left over.
    pub fn finish(&self) -> Result<(), CarError> {
        let rest = &self.buf[self.pos..];
        if self.roots.is_none() {
            return Err(CarError::InvalidHeader(if rest.is_empty() {
                "unexpected EOF reading varint".into()
            } else {
                "truncated header".into()
            }));
        }
        if rest.is_empty() {
            return Ok(());
        }
        Err(CarError::InvalidBlock(match varint_from_slice(rest)? {
            Some(_) => "truncated block data".into(),
            None => "truncated varint".into(),
        }))
    }

    /// Decode the header if it has not been yet, returning whether it has
    /// arrived.
    fn read_header(&mut self) -> Result<bool, CarError> {
        if self.roots.is_none() {
            let Some(header) = self.next_frame(check_header_len)? else {
                return Ok(false);
            };
            self.roots = Some(decode_header(&self.buf[header])?);
        }
        Ok(true)
    }

    /// Consume the next length-prefixed frame if all of it has arrived,
    /// returning its body's range in `buf`. The length is validated as soon
    /// as its varint is complete, before any of the body is buffered.
    fn next_frame(
        &mut self,
        check_len: fn(u64) -> Result<usize, CarError>,
    ) -> Result<Option<Range<usize>>, CarError> {
        let rest = &self.buf[self.pos..];
        let Some((len, prefix)) = varint_from_slice(rest)? else {
            return Ok(None);
        };
        let len = check_len(len)?;
        if rest.len() - prefix < len {
            return Ok(None);
        }
        let start = self.pos + prefix;
        self.pos = start + len;
        Ok(Some(start..self.pos))
    }
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
    use crate::car::{Reader, write_all};
    use crate::cbor::Codec;
    use proptest::prelude::*;

    fn sample_car(sizes: &[usize]) -> (Vec<Cid>, Vec<Block>, Vec<u8>) {
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
        let roots = vec![blocks[0].cid];
        let car = write_all(&roots, &blocks).unwrap();
        (roots, blocks, car)
    }

    /// Everything a reader produced: roots, blocks, and whether it failed.
    type Outcome = (Option<Vec<Cid>>, Vec<(Cid, Vec<u8>)>, bool);

    fn read_sync(car: &[u8]) -> Outcome {
        let mut reader = match Reader::new(car) {
            Ok(r) => r,
            Err(_) => return (None, Vec::new(), true),
        };
        let roots = Some(reader.roots().to_vec());
        let mut blocks = Vec::new();
        loop {
            match reader.next_block() {
                Ok(Some(b)) => blocks.push((b.cid, b.data)),
                Ok(None) => return (roots, blocks, false),
                Err(_) => return (roots, blocks, true),
            }
        }
    }

    /// Feed `car` in chunks of the given sizes (cycled), draining after each.
    fn read_incremental(car: &[u8], chunk_sizes: &[usize]) -> Outcome {
        let mut reader = IncrementalReader::new();
        let mut blocks = Vec::new();
        let mut rest = car;
        let mut sizes = chunk_sizes.iter().cycle();
        let roots = |r: &IncrementalReader| r.roots().map(<[Cid]>::to_vec);
        while !rest.is_empty() {
            let n = (*sizes.next().unwrap()).clamp(1, rest.len());
            let (chunk, tail) = rest.split_at(n);
            rest = tail;
            reader.push(chunk);
            loop {
                // The lookahead predicts the length of the block next_block
                // yields, and must fail only where next_block would (else the
                // outcome differs from Reader's).
                let Ok(len) = reader.next_block_data_len() else {
                    return (roots(&reader), blocks, true);
                };
                match reader.next_block() {
                    Ok(Some(b)) => {
                        assert_eq!(len, Some(b.data.len()));
                        blocks.push((b.cid, b.data));
                    }
                    Ok(None) => break,
                    Err(_) => return (roots(&reader), blocks, true),
                }
            }
        }
        let failed = reader.finish().is_err();
        (roots(&reader), blocks, failed)
    }

    const CHUNKINGS: &[&[usize]] = &[&[1], &[2, 3, 5], &[37], &[usize::MAX]];

    fn assert_matches_sync(car: &[u8]) {
        let expected = read_sync(car);
        for sizes in CHUNKINGS {
            assert_eq!(
                read_incremental(car, sizes),
                expected,
                "chunks {sizes:?}, car {car:02x?}"
            );
        }
    }

    #[test]
    fn reads_every_chunking() {
        let (roots, blocks, car) = sample_car(&[0, 1, 100, 4096]);
        let want: Vec<_> = blocks.iter().map(|b| (b.cid, b.data.clone())).collect();
        for sizes in CHUNKINGS {
            assert_eq!(
                read_incremental(&car, sizes),
                (Some(roots.clone()), want.clone(), false)
            );
        }
    }

    #[test]
    fn header_only_car() {
        let car = write_all(&[], &[]).unwrap();
        assert_eq!(read_incremental(&car, &[1]), (Some(vec![]), vec![], false));
    }

    #[test]
    fn matches_reader_on_every_truncation_and_mutation() {
        let (_, _, car) = sample_car(&[3, 40, 200]);
        for len in 0..=car.len() {
            assert_matches_sync(&car[..len]);
        }
        for i in 0..car.len() {
            for mutate in [|b: u8| b ^ 0x01, |b: u8| b ^ 0x80, |_| 0x00, |_| 0xff] {
                let mut bad = car.clone();
                bad[i] = mutate(bad[i]);
                assert_matches_sync(&bad);
            }
        }
    }

    #[test]
    fn matches_reader_on_malformed_varints() {
        let (_, _, car) = sample_car(&[10]);
        let (header_len, n) = varint_from_slice(&car).unwrap().unwrap();
        let blocks_at = n + header_len as usize;
        for prefix in [
            &[0x80, 0x00][..],             // non-minimal
            &[0xff; 9][..],                // too long
            &[0xff, 0xff, 0xff, 0xff][..], // truncated
        ] {
            // In place of the header length...
            assert_matches_sync(prefix);
            // ...and of the first block length.
            let mut bad = car[..blocks_at].to_vec();
            bad.extend_from_slice(prefix);
            assert_matches_sync(&bad);
        }
    }

    #[test]
    fn rejects_oversized_lengths_before_buffering_the_body() {
        // An absurd header length fails on the prefix alone.
        let mut reader = IncrementalReader::new();
        let mut prefix = Vec::new();
        crate::cbor::varint::encode_varint((1 << 20) + 1, &mut prefix);
        reader.push(&prefix);
        assert!(matches!(
            reader.next_block(),
            Err(CarError::InvalidHeader(_))
        ));

        // So does an absurd block length, without waiting for 128 MiB.
        let (_, _, car) = sample_car(&[1]);
        let (header_len, n) = varint_from_slice(&car).unwrap().unwrap();
        let mut reader = IncrementalReader::new();
        reader.push(&car[..n + header_len as usize]);
        assert!(reader.next_block().unwrap().is_none());
        prefix.clear();
        crate::cbor::varint::encode_varint((128 << 20) + 1, &mut prefix);
        reader.push(&prefix);
        assert!(matches!(
            reader.next_block(),
            Err(CarError::InvalidBlock(_))
        ));
    }

    #[test]
    fn next_block_data_len_arrives_with_the_length_prefix() {
        let (_, blocks, car) = sample_car(&[300]);
        let (header_len, n) = varint_from_slice(&car).unwrap().unwrap();
        let blocks_at = n + header_len as usize;
        let mut reader = IncrementalReader::new();
        reader.push(&car[..blocks_at]);
        assert_eq!(reader.next_block_data_len().unwrap(), None);
        // The 2-byte prefix of a 336-byte frame, but none of its body.
        reader.push(&car[blocks_at..blocks_at + 1]);
        assert_eq!(reader.next_block_data_len().unwrap(), None);
        reader.push(&car[blocks_at + 1..blocks_at + 2]);
        assert_eq!(reader.next_block_data_len().unwrap(), Some(300));
        assert!(reader.next_block().unwrap().is_none());
        // Peeking consumes nothing.
        reader.push(&car[blocks_at + 2..]);
        assert_eq!(reader.next_block_data_len().unwrap(), Some(300));
        assert_eq!(reader.next_block().unwrap().unwrap().data, blocks[0].data);
        assert_eq!(reader.next_block_data_len().unwrap(), None);
        reader.finish().unwrap();

        // An invalid length fails as soon as it arrives.
        let mut reader = IncrementalReader::new();
        reader.push(&car[..blocks_at]);
        reader.push(&[CID_LEN as u8 - 1]);
        assert!(matches!(
            reader.next_block_data_len(),
            Err(CarError::InvalidBlock(_))
        ));
    }

    #[test]
    fn finish_reports_where_the_stream_stopped() {
        let (_, _, car) = sample_car(&[50]);
        let (header_len, n) = varint_from_slice(&car).unwrap().unwrap();
        let blocks_at = n + header_len as usize;
        let cases: &[(&[u8], &str)] = &[
            (&[], "unexpected EOF reading varint"),
            (&car[..2], "truncated header"),
            (
                &[&car[..blocks_at], &[0x80][..]].concat(),
                "truncated varint",
            ),
            (&car[..car.len() - 1], "truncated block data"),
        ];
        for (input, want) in cases {
            let mut reader = IncrementalReader::new();
            reader.push(input);
            while reader.next_block().unwrap().is_some() {}
            let err = reader.finish().unwrap_err().to_string();
            assert!(err.contains(want), "{err:?} should contain {want:?}");
        }
    }

    #[test]
    fn buffers_at_most_a_partial_block_plus_one_chunk() {
        let sizes = vec![1000; 64];
        let (_, _, car) = sample_car(&sizes);
        let mut reader = IncrementalReader::new();
        let mut count = 0;
        for chunk in car.chunks(300) {
            reader.push(chunk);
            while reader.next_block().unwrap().is_some() {
                count += 1;
            }
            assert!(
                reader.buf.len() <= 1000 + 36 + 2 + 300,
                "{}",
                reader.buf.len()
            );
        }
        reader.finish().unwrap();
        assert_eq!(count, 64);
    }

    proptest! {
        #[test]
        fn prop_matches_reader(
            sizes in prop::collection::vec(0usize..600, 1..8),
            chunks in prop::collection::vec(1usize..256, 1..8),
            cut in any::<prop::sample::Index>(),
            flip in prop::option::of((any::<prop::sample::Index>(), 1u8..=255)),
        ) {
            let (_, _, mut car) = sample_car(&sizes);
            if let Some((at, mask)) = flip {
                let i = at.index(car.len());
                car[i] ^= mask;
            }
            let len = cut.index(car.len() + 1);
            let car = &car[..len];
            prop_assert_eq!(read_incremental(car, &chunks), read_sync(car));
        }
    }
}
