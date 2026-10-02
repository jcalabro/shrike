#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Per-record work over a real repository's records: lexicon validation and
//! conversion between DRISL and JSON.

mod common;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use shrike::cbor::json::{Integers, drisl_to_json, drisl_to_json_into, json_slice_to_drisl};
use shrike::lexicon::{Catalog, validate_record};

/// Each collection's records, as DRISL and as JSON text.
struct Corpus {
    collection: &'static str,
    short: &'static str,
    drisl: Vec<Vec<u8>>,
    json: Vec<Vec<u8>>,
}

fn corpora() -> Vec<Corpus> {
    common::COLLECTIONS
        .iter()
        .map(|&collection| {
            let drisl = common::calabro_records(collection);
            let json = drisl
                .iter()
                .map(|r| serde_json::to_vec(&drisl_to_json(r).unwrap()).unwrap())
                .collect();
            Corpus {
                collection,
                short: collection.rsplit('.').next().unwrap(),
                drisl,
                json,
            }
        })
        .collect()
}

fn catalog() -> Catalog {
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/benches/fixtures/lexicons");
    let mut catalog = Catalog::new();
    for entry in std::fs::read_dir(dir).unwrap() {
        catalog
            .add_schema(&std::fs::read(entry.unwrap().path()).unwrap())
            .unwrap();
    }
    catalog
}

fn bench_validate(c: &mut Criterion) {
    let catalog = catalog();
    let mut group = c.benchmark_group("validate_record");
    for corpus in corpora() {
        // The issue's corpus is all valid records; drop the few old records
        // that today's lexicons reject.
        let values: Vec<serde_json::Value> = corpus
            .json
            .iter()
            .map(|j| serde_json::from_slice(j).unwrap())
            .filter(|v| validate_record(&catalog, corpus.collection, v).is_ok())
            .collect();
        assert!(
            values.len() * 10 >= corpus.json.len() * 9,
            "{}",
            corpus.short
        );
        group.throughput(Throughput::Elements(values.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(corpus.short, values.len()),
            &values,
            |b, values| {
                b.iter(|| {
                    for v in values {
                        validate_record(&catalog, corpus.collection, black_box(v)).unwrap();
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_drisl_to_json(c: &mut Criterion) {
    let corpora = corpora();
    let mut group = c.benchmark_group("drisl_to_json_bytes");
    for corpus in &corpora {
        group.throughput(Throughput::Elements(corpus.drisl.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(corpus.short, corpus.drisl.len()),
            &corpus.drisl,
            |b, records| {
                b.iter(|| {
                    for r in records {
                        let mut json = Vec::new();
                        drisl_to_json_into(black_box(r), &mut json).unwrap();
                        black_box(json);
                    }
                });
            },
        );
    }
    group.finish();

    // The same JSON text by way of a `serde_json::Value`.
    let mut group = c.benchmark_group("drisl_to_json_tree_bytes");
    for corpus in &corpora {
        group.throughput(Throughput::Elements(corpus.drisl.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(corpus.short, corpus.drisl.len()),
            &corpus.drisl,
            |b, records| {
                b.iter(|| {
                    for r in records {
                        let json = drisl_to_json(black_box(r)).unwrap();
                        black_box(serde_json::to_vec(&json).unwrap());
                    }
                });
            },
        );
    }
    group.finish();
}

fn bench_json_to_drisl(c: &mut Criterion) {
    let mut group = c.benchmark_group("json_bytes_to_drisl");
    for corpus in corpora() {
        group.throughput(Throughput::Elements(corpus.json.len() as u64));
        group.bench_with_input(
            BenchmarkId::new(corpus.short, corpus.json.len()),
            &corpus.json,
            |b, records| {
                b.iter(|| {
                    for j in records {
                        black_box(json_slice_to_drisl(black_box(j), Integers::Safe).unwrap());
                    }
                });
            },
        );
    }
    group.finish();
}

criterion_group!(
    benches,
    bench_validate,
    bench_drisl_to_json,
    bench_json_to_drisl,
);
criterion_main!(benches);
