#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use shrike_car::{Block, Reader, read_all, verify, write_all};
use shrike_cbor::{Cid, Codec};

// ---------------------------------------------------------------------------
// Real-world fixture: calabro.io AT Protocol repo (~1.5 MB, ~5k blocks)
// ---------------------------------------------------------------------------

const CALABRO_CAR: &[u8] = include_bytes!("fixtures/calabro.car");

// ---------------------------------------------------------------------------
// Synthetic fixture builders
// ---------------------------------------------------------------------------

/// Build a synthetic CAR file with `n` blocks of `data_size` bytes each.
fn build_synthetic_car(n: usize, data_size: usize) -> Vec<u8> {
    let blocks: Vec<Block> = (0..n)
        .map(|i| {
            // Deterministic data seeded by index
            let data: Vec<u8> = (0..data_size)
                .map(|j| ((i * 31 + j * 7) % 256) as u8)
                .collect();
            Block {
                cid: Cid::compute(Codec::Drisl, &data),
                data,
            }
        })
        .collect();
    let root = blocks[0].cid;
    write_all(&[root], &blocks).expect("write_all failed")
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_read_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("read_all");

    // Real-world CAR
    group.bench_function("calabro_1.5mb", |b| {
        b.iter(|| {
            let (roots, blocks) = read_all(black_box(CALABRO_CAR)).expect("read_all");
            black_box((roots, blocks));
        });
    });

    // Synthetic at various scales
    for &(n, data_size, label) in &[
        (10, 100, "10x100b"),
        (100, 200, "100x200b"),
        (1000, 200, "1000x200b"),
    ] {
        let car = build_synthetic_car(n, data_size);
        group.bench_with_input(BenchmarkId::new("synthetic", label), &car, |b, car| {
            b.iter(|| {
                let (roots, blocks) = read_all(black_box(car.as_slice())).expect("read_all");
                black_box((roots, blocks));
            });
        });
    }

    group.finish();
}

fn bench_streaming_read(c: &mut Criterion) {
    let mut group = c.benchmark_group("streaming_read");

    // next_block: allocates a new Vec per block
    group.bench_function("calabro_alloc_per_block", |b| {
        b.iter(|| {
            let mut reader = Reader::new(black_box(CALABRO_CAR)).expect("reader");
            let mut count = 0u64;
            while let Some(block) = reader.next_block().expect("next_block") {
                black_box(&block);
                count += 1;
            }
            black_box(count);
        });
    });

    // next_block_into: reuses a single buffer across all blocks
    group.bench_function("calabro_reuse_buffer", |b| {
        b.iter(|| {
            let mut reader = Reader::new(black_box(CALABRO_CAR)).expect("reader");
            let mut block = Block::default();
            let mut count = 0u64;
            while reader.next_block_into(&mut block).expect("next_block_into") {
                black_box(&block);
                count += 1;
            }
            black_box(count);
        });
    });

    group.finish();
}

fn bench_write_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("write_all");

    // Read the real CAR first, then benchmark writing it back
    let (roots, blocks) = read_all(CALABRO_CAR).expect("read_all");
    group.bench_function("calabro_1.5mb", |b| {
        b.iter(|| {
            let written = write_all(black_box(&roots), black_box(&blocks)).expect("write_all");
            black_box(written);
        });
    });

    // Synthetic
    for &(n, data_size, label) in &[
        (10, 100, "10x100b"),
        (100, 200, "100x200b"),
        (1000, 200, "1000x200b"),
    ] {
        let car = build_synthetic_car(n, data_size);
        let (roots, blocks) = read_all(car.as_slice()).expect("read_all");
        group.bench_with_input(
            BenchmarkId::new("synthetic", label),
            &(roots, blocks),
            |b, (roots, blocks)| {
                b.iter(|| {
                    let written =
                        write_all(black_box(roots), black_box(blocks)).expect("write_all");
                    black_box(written);
                });
            },
        );
    }

    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("verify");

    // SHA-256 dominated — measures CID recomputation throughput
    group.bench_function("calabro_1.5mb", |b| {
        b.iter(|| {
            verify(black_box(CALABRO_CAR)).expect("verify");
        });
    });

    for &(n, data_size, label) in &[(100, 200, "100x200b"), (1000, 200, "1000x200b")] {
        let car = build_synthetic_car(n, data_size);
        group.bench_with_input(BenchmarkId::new("synthetic", label), &car, |b, car| {
            b.iter(|| {
                verify(black_box(car.as_slice())).expect("verify");
            });
        });
    }

    group.finish();
}

fn bench_header_parse(c: &mut Criterion) {
    let mut group = c.benchmark_group("header_parse");

    // Just the Reader::new overhead (header parsing, no block reading)
    group.bench_function("calabro", |b| {
        b.iter(|| {
            let reader = Reader::new(black_box(CALABRO_CAR)).expect("reader");
            black_box(reader.roots());
        });
    });

    group.finish();
}

fn bench_block_write(c: &mut Criterion) {
    let mut group = c.benchmark_group("block_write");

    // Per-block write overhead at different data sizes
    for &data_size in &[64, 256, 1024, 4096] {
        let data: Vec<u8> = (0..data_size).map(|i| (i % 256) as u8).collect();
        let block = Block {
            cid: Cid::compute(Codec::Drisl, &data),
            data,
        };
        let root = block.cid;

        group.bench_with_input(
            BenchmarkId::new("single_block", data_size),
            &block,
            |b, block| {
                b.iter(|| {
                    let mut buf = Vec::with_capacity(data_size + 128);
                    let mut writer = shrike_car::Writer::new(&mut buf, &[root]).expect("writer");
                    writer.write_block(black_box(block)).expect("write_block");
                    black_box(buf);
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_read_all,
    bench_streaming_read,
    bench_write_all,
    bench_verify,
    bench_header_parse,
    bench_block_write,
);
criterion_main!(benches);
