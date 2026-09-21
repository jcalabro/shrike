//! Offline stage measurements on captured getBlock frames.
//!
//! Usage: cargo run --release --example jetstream_bench --features jetstream --
//! <decompress|raw|filtered|typed|verify> <corpus-directory> <iterations> [collection]
//! Omit collection for all events. `verify` hashes event contents and errors;
//! keep it separate from timing runs. Corpus files must end in `.zst`.

use std::{error::Error, hint::black_box, path::PathBuf, time::Instant};

use sha2::{Digest, Sha256};
use shrike::api::app::bsky::FeedLike;
use shrike::jetstream::{
    Event, EventPayload, Filter, Operation, decode_block, decode_block_frame_filtered,
    decompress_bounded,
};

fn field(hash: &mut Sha256, value: &[u8]) {
    hash.update((value.len() as u64).to_le_bytes());
    hash.update(value);
}

fn fingerprint(hash: &mut Sha256, event: &Event) -> Result<(), Box<dyn Error>> {
    field(hash, &event.seq.to_le_bytes());
    field(hash, event.did.as_str().as_bytes());
    field(hash, &event.time_us.to_le_bytes());
    field(hash, event.kind().as_wire().as_bytes());
    match &event.payload {
        EventPayload::Commit(c) => {
            field(
                hash,
                &[match c.operation {
                    Operation::Create => 1,
                    Operation::Update => 2,
                    Operation::Delete => 3,
                }],
            );
            field(hash, c.collection.as_str().as_bytes());
            field(hash, c.rkey.as_str().as_bytes());
            field(hash, c.rev.to_string().as_bytes());
            field(hash, &[u8::from(c.record.is_some())]);
            if let Some(record) = &c.record {
                field(hash, record.as_cbor());
            }
        }
        EventPayload::Identity(v) => field(hash, &v.to_cbor()?),
        EventPayload::Account(v) => field(hash, &v.to_cbor()?),
        EventPayload::Sync(v) => field(hash, &v.to_cbor()?),
    }
    Ok(())
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("missing mode")?;
    if !["decompress", "raw", "filtered", "typed", "verify"].contains(&mode.as_str()) {
        return Err("unknown mode".into());
    }
    let dir = PathBuf::from(args.next().ok_or("missing corpus directory")?);
    let iterations: usize = args.next().ok_or("missing iterations")?.parse()?;
    if iterations == 0 {
        return Err("iterations must be positive".into());
    }
    let collection = args.next();
    if args.next().is_some() {
        return Err("too many arguments".into());
    }
    let filter = match &collection {
        Some(c) => Filter::new().collection(c)?,
        None => Filter::new(),
    };
    let mut paths: Vec<_> = std::fs::read_dir(dir)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<Result<_, _>>()?;
    paths.retain(|p| p.extension().is_some_and(|e| e == "zst"));
    paths.sort();
    if paths.is_empty() {
        return Err("corpus has no .zst files".into());
    }
    let frames: Vec<_> = paths.iter().map(std::fs::read).collect::<Result<_, _>>()?;
    let compressed_bytes: usize = frames.iter().map(Vec::len).sum();
    // Setup and I/O are outside the measured interval. `raw` excludes zstd.
    let bodies = if mode == "raw" {
        frames
            .iter()
            .map(|f| decompress_bounded(f, 1 << 30, None))
            .collect::<Result<Vec<_>, _>>()?
    } else {
        Vec::new()
    };
    let mut hash = Sha256::new();
    let (mut events, mut dropped, mut typed, mut typed_errors) = (0u64, 0u64, 0u64, 0u64);
    let start = Instant::now();
    for _ in 0..iterations {
        for (index, frame) in frames.iter().enumerate() {
            match mode.as_str() {
                "decompress" => {
                    black_box(decompress_bounded(black_box(frame), 1 << 30, None)?);
                }
                "raw" => {
                    let rows = decode_block(black_box(&bodies[index]))?;
                    events += rows.len() as u64;
                    black_box(rows);
                }
                _ => {
                    let decoded = decode_block_frame_filtered(black_box(frame), &filter)?;
                    events += decoded.events.len() as u64;
                    dropped += decoded.dropped.len() as u64;
                    if mode == "typed" {
                        for event in &decoded.events {
                            if let EventPayload::Commit(c) = &event.payload
                                && c.collection.as_str() == "app.bsky.feed.like"
                                && let Some(record) = &c.record
                            {
                                match FeedLike::from_cbor(record.as_cbor()) {
                                    Ok(like) => {
                                        black_box(like);
                                        typed += 1;
                                    }
                                    Err(_) => typed_errors += 1,
                                }
                            }
                        }
                    } else if mode == "verify" {
                        field(&mut hash, &(index as u64).to_le_bytes());
                        for event in &decoded.events {
                            fingerprint(&mut hash, event)?;
                        }
                        for error in &decoded.dropped {
                            field(&mut hash, error.to_string().as_bytes());
                        }
                    }
                    black_box(decoded);
                }
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    println!(
        "{}",
        serde_json::json!({
            "mode": mode, "collection": collection, "iterations": iterations,
            "blocks": frames.len(), "compressed_bytes": compressed_bytes,
            "elapsed_s": elapsed, "events": events, "dropped": dropped,
            "typed": typed, "typed_errors": typed_errors,
            "fingerprint": if mode == "verify" { Some(format!("{:x}", hash.finalize())) } else { None },
        })
    );
    Ok(())
}
