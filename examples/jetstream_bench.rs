//! Offline stage measurements on captured getBlock frames.
//!
//! Usage: cargo run --release --example jetstream_bench --features jetstream --
//! <decompress|raw|filtered|typed|verify> <corpus-directory> <iterations> [collection]
//! Omit collection for all events. `verify` hashes event contents and errors;
//! keep it separate from timing runs. Corpus files must end in `.zst`.
//! `typed`, `view`, and `mapped` decode likes, posts and profiles with the owned,
//! borrowed-record, and scoped borrowed-event APIs respectively. Other records
//! remain opaque. `verify-mapped` hashes the scoped API's retained owned outputs.

use std::{error::Error, hint::black_box, path::PathBuf, time::Instant};

use sha2::{Digest, Sha256};
use shrike::api::app::bsky::{
    ActorProfile, ActorProfileCborView, FeedLike, FeedLikeCborView, FeedPost, FeedPostCborView,
};
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

// Three different schema shapes: a small nested record, arrays/unions, and
// optional profile/blob fields. Unknown collections are left opaque.
fn typed_check(collection: &str, record: &[u8], borrowed: bool) -> Option<bool> {
    macro_rules! check {
        ($owned:ty, $view:ty) => {
            if borrowed {
                <$view>::from_cbor(record).map(black_box).is_ok()
            } else {
                <$owned>::from_cbor(record).map(black_box).is_ok()
            }
        };
    }
    Some(match collection {
        "app.bsky.feed.like" => check!(FeedLike, FeedLikeCborView),
        "app.bsky.feed.post" => check!(FeedPost, FeedPostCborView),
        "app.bsky.actor.profile" => check!(ActorProfile, ActorProfileCborView),
        _ => return None,
    })
}

fn main() -> Result<(), Box<dyn Error>> {
    let mut args = std::env::args().skip(1);
    let mode = args.next().ok_or("missing mode")?;
    if ![
        "decompress",
        "raw",
        "filtered",
        "typed",
        "view",
        "mapped",
        "verify",
        "verify-mapped",
    ]
    .contains(&mode.as_str())
    {
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
                "verify-mapped" => {
                    let decoded =
                        shrike::jetstream::decode_block_frame_mapped(frame, &filter, &|e| {
                            e.to_owned()
                        })?;
                    events += decoded.events.len() as u64;
                    dropped += decoded.dropped.len() as u64;
                    field(&mut hash, &(index as u64).to_le_bytes());
                    for event in &decoded.events {
                        fingerprint(
                            &mut hash,
                            event.value.as_ref().map_err(ToString::to_string)?,
                        )?;
                    }
                    for error in &decoded.dropped {
                        field(&mut hash, error.to_string().as_bytes());
                    }
                }
                "mapped" => {
                    let decoded = shrike::jetstream::decode_block_frame_mapped(
                        black_box(frame),
                        &filter,
                        &|event| {
                            if let shrike::jetstream::EventPayloadView::Commit(c) = &event.payload
                                && let Some(record) = c.record
                            {
                                match typed_check(&c.collection, record, true) {
                                    Some(true) => (1u64, 0u64),
                                    Some(false) => (0, 1),
                                    None => (0, 0),
                                }
                            } else {
                                (0, 0)
                            }
                        },
                    )?;
                    events += decoded.events.len() as u64;
                    dropped += decoded.dropped.len() as u64;
                    for event in &decoded.events {
                        typed += event.value.0;
                        typed_errors += event.value.1;
                    }
                    black_box(decoded);
                }
                _ => {
                    let decoded = decode_block_frame_filtered(black_box(frame), &filter)?;
                    events += decoded.events.len() as u64;
                    dropped += decoded.dropped.len() as u64;
                    if mode == "typed" || mode == "view" {
                        for event in &decoded.events {
                            if let EventPayload::Commit(c) = &event.payload
                                && let Some(record) = &c.record
                                && let Some(valid) = typed_check(
                                    c.collection.as_str(),
                                    record.as_cbor(),
                                    mode == "view",
                                )
                            {
                                typed += u64::from(valid);
                                typed_errors += u64::from(!valid);
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
            "fingerprint": if mode.starts_with("verify") { Some(format!("{:x}", hash.finalize())) } else { None },
        })
    );
    Ok(())
}
