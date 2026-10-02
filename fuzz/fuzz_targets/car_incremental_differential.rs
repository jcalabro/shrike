#![no_main]
//! Differential oracle: the chunk-fed `IncrementalReader` (used to stream
//! getRepo bodies) MUST agree with the blocking `Reader` on every input and
//! every chunking: the same roots, the same blocks, and failure at the same
//! point. The first input byte picks the chunk size. `next_block_data_len`
//! must agree with the blocks `next_block` then yields. The borrowing
//! `SliceReader` must agree too, down to the error it stops with.

use libfuzzer_sys::fuzz_target;
use shrike::car::{IncrementalReader, Reader, SliceReader};
use shrike::cbor::Cid;

/// Roots, blocks, and the error that stopped the read.
type Outcome = (Option<Vec<Cid>>, Vec<(Cid, Vec<u8>)>, Option<String>);

fn read_sync(car: &[u8]) -> Outcome {
    let mut reader = match Reader::new(car) {
        Ok(reader) => reader,
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
    let reader = match SliceReader::new(car) {
        Ok(reader) => reader,
        Err(e) => return (None, Vec::new(), Some(format!("{e:?}"))),
    };
    let roots = Some(reader.roots().to_vec());
    let mut blocks = Vec::new();
    for block in reader {
        match block {
            Ok(b) => blocks.push((b.cid, b.data.to_vec())),
            Err(e) => return (roots, blocks, Some(format!("{e:?}"))),
        }
    }
    (roots, blocks, None)
}

fn read_incremental(car: &[u8], chunk: usize) -> (Option<Vec<Cid>>, Vec<(Cid, Vec<u8>)>, bool) {
    let mut reader = IncrementalReader::new();
    let mut blocks = Vec::new();
    for piece in car.chunks(chunk) {
        reader.push(piece);
        loop {
            // The lookahead predicts the length of the block next_block yields,
            // and must fail only where next_block would (else the outcome
            // differs from Reader's).
            let Ok(len) = reader.next_block_data_len() else {
                return (reader.roots().map(<[Cid]>::to_vec), blocks, true);
            };
            match reader.next_block() {
                Ok(Some(b)) => {
                    assert_eq!(len, Some(b.data.len()));
                    blocks.push((b.cid, b.data));
                }
                Ok(None) => break,
                Err(_) => return (reader.roots().map(<[Cid]>::to_vec), blocks, true),
            }
        }
    }
    let failed = reader.finish().is_err();
    (reader.roots().map(<[Cid]>::to_vec), blocks, failed)
}

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, car)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk).max(1);
    let (roots, blocks, error) = read_sync(car);
    assert_eq!(
        read_incremental(car, chunk),
        (roots.clone(), blocks.clone(), error.is_some())
    );
    assert_eq!(read_slice(car), (roots, blocks, error));
});
