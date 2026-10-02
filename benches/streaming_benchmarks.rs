#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Firehose `#commit` frame parsing.

mod common;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use shrike::cbor::json::{Integers, json_to_drisl};
use shrike::cbor::{Value, encode_value};
use shrike::crypto::K256SigningKey;
use shrike::repo::CommitData;
use shrike::streaming::parse_firehose_frame;

/// The `{op: 1, t: "#commit"}` frame header.
fn commit_header() -> Vec<u8> {
    encode_value(&Value::Map(vec![
        ("t", Value::Text("#commit")),
        ("op", Value::Unsigned(1)),
    ]))
    .unwrap()
}

/// Real firehose commits (indigo's test vectors), as wire frames.
fn indigo_frames() -> Vec<(String, Vec<u8>)> {
    [4621317030u64, 4621317332, 4621332152, 4623075231]
        .iter()
        .map(|seq| {
            let path = format!(
                "{}/testdata/repo_proofs/firehose_commits/firehose_commit_{seq}.json",
                env!("CARGO_MANIFEST_DIR")
            );
            let mut body: serde_json::Value =
                serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
            let body = body.as_object_mut().unwrap();
            body.retain(|_, v| !v.is_null());
            body.insert("blobs".into(), serde_json::json!([]));
            let mut frame = commit_header();
            frame.extend(json_to_drisl(&body.clone().into(), Integers::Any).unwrap());
            (format!("indigo_{seq}"), frame)
        })
        .collect()
}

/// A one-record commit to a large repository, with the covering proof a
/// Sync 1.1 producer ships.
fn sync11_frame() -> Vec<u8> {
    let key = K256SigningKey::from_bytes(&[7; 32]).unwrap();
    let mut repo = common::synthetic_repo(43_649, &key);
    let (collection, rkey, record) = common::record(1_000_000);
    repo.create(&collection, &rkey, &record).unwrap();
    let c: CommitData = repo.commit(&key).unwrap();
    let car = c.relevant_car().unwrap();
    let repo_did = c.commit.did.to_string();
    let rev = c.rev().to_string();
    let since = c.since.unwrap().to_string();
    let paths: Vec<String> = c.ops.iter().map(|o| o.path()).collect();
    let ops = c
        .ops
        .iter()
        .zip(&paths)
        .map(|(op, path)| {
            let link = |cid: Option<shrike::cbor::Cid>| cid.map_or(Value::Null, Value::Cid);
            Value::Map(vec![
                ("cid", link(op.cid)),
                ("path", Value::Text(path)),
                ("prev", link(op.prev)),
                ("action", Value::Text(op.action.as_str())),
            ])
        })
        .collect();
    let body = Value::Map(vec![
        ("ops", Value::Array(ops)),
        ("rev", Value::Text(&rev)),
        ("seq", Value::Unsigned(123_456_789)),
        ("repo", Value::Text(&repo_did)),
        ("time", Value::Text("2024-01-01T00:00:00.000Z")),
        ("blobs", Value::Array(vec![])),
        ("since", Value::Text(&since)),
        ("blocks", Value::Bytes(&car)),
        ("commit", Value::Cid(c.cid)),
        ("rebase", Value::Bool(false)),
        ("tooBig", Value::Bool(false)),
        ("prevData", Value::Cid(c.prev_data.unwrap())),
    ]);
    let mut frame = commit_header();
    frame.extend(encode_value(&body).unwrap());
    frame
}

fn bench_parse_firehose_frame(c: &mut Criterion) {
    let mut group = c.benchmark_group("parse_firehose_frame");
    let mut frames = indigo_frames();
    frames.push(("sync11_create".into(), sync11_frame()));
    for (name, frame) in &frames {
        parse_firehose_frame(frame).unwrap();
        group.throughput(Throughput::Bytes(frame.len() as u64));
        group.bench_with_input(BenchmarkId::new("commit", name), frame, |b, frame| {
            b.iter(|| black_box(parse_firehose_frame(black_box(frame)).unwrap()));
        });
    }
    group.finish();
}

criterion_group!(benches, bench_parse_firehose_frame);
criterion_main!(benches);
