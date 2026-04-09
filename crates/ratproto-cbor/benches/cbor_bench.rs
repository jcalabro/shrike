#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use ratproto_cbor::{
    Cid, Codec, Decoder, Encoder, cbor_key_cmp, decode, encode_value, encode_value_into,
};

// ---------------------------------------------------------------------------
// Fixture data: real CBOR blocks extracted from pfrazee.com's AT Protocol repo
// ---------------------------------------------------------------------------

const COMMIT: &[u8] = include_bytes!("fixtures/commit.cbor");
const MST_NODE_SMALL: &[u8] = include_bytes!("fixtures/mst_node_small.cbor");
const MST_NODE_LARGE: &[u8] = include_bytes!("fixtures/mst_node_large.cbor");
const RECORD_POST: &[u8] = include_bytes!("fixtures/record_post.cbor");
const RECORD_PROFILE: &[u8] = include_bytes!("fixtures/record_profile.cbor");
const RECORD_LIKE: &[u8] = include_bytes!("fixtures/record_like.cbor");

struct Fixture {
    name: &'static str,
    data: &'static [u8],
}

const FIXTURES: &[Fixture] = &[
    Fixture {
        name: "commit",
        data: COMMIT,
    },
    Fixture {
        name: "mst_small",
        data: MST_NODE_SMALL,
    },
    Fixture {
        name: "mst_large",
        data: MST_NODE_LARGE,
    },
    Fixture {
        name: "record_post",
        data: RECORD_POST,
    },
    Fixture {
        name: "record_profile",
        data: RECORD_PROFILE,
    },
    Fixture {
        name: "record_like",
        data: RECORD_LIKE,
    },
];

// ---------------------------------------------------------------------------
// Synthetic data builders for controlled benchmarks
// ---------------------------------------------------------------------------

/// Encode a simple CBOR map with N string keys and integer values.
fn build_map(num_keys: usize) -> Vec<u8> {
    // Build keys of varying lengths to exercise key sorting
    let keys: Vec<String> = (0..num_keys).map(|i| format!("field_{i:04}")).collect();
    let key_refs: Vec<&str> = keys.iter().map(|s| s.as_str()).collect();

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    ratproto_cbor::encode_text_map(&mut enc, &key_refs, |enc, _key| enc.encode_u64(42))
        .expect("encode failed");
    buf
}

/// Encode a CBOR array of N integers.
fn build_array(len: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    enc.encode_array_header(len as u64).expect("header");
    for i in 0..len {
        enc.encode_u64(i as u64).expect("item");
    }
    buf
}

// ---------------------------------------------------------------------------
// Benchmark groups
// ---------------------------------------------------------------------------

fn bench_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("decode");

    for fixture in FIXTURES {
        group.throughput(Throughput::Bytes(fixture.data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("real", fixture.name),
            &fixture.data,
            |b, data| {
                b.iter(|| {
                    let val = decode(black_box(data)).expect("decode failed");
                    black_box(val);
                });
            },
        );
    }

    // Synthetic: maps of increasing size to show scaling behavior
    for &n in &[5, 20, 100] {
        let data = build_map(n);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("synthetic_map", n), &data, |b, data| {
            b.iter(|| {
                let val = decode(black_box(data)).expect("decode failed");
                black_box(val);
            });
        });
    }

    // Synthetic: arrays of increasing size
    for &n in &[10, 100, 1000] {
        let data = build_array(n);
        group.throughput(Throughput::Bytes(data.len() as u64));
        group.bench_with_input(BenchmarkId::new("synthetic_array", n), &data, |b, data| {
            b.iter(|| {
                let val = decode(black_box(data)).expect("decode failed");
                black_box(val);
            });
        });
    }

    // Primitives: measure baseline overhead per type
    let int_data = {
        let mut buf = Vec::new();
        Encoder::new(&mut buf).encode_u64(1_000_000).expect("enc");
        buf
    };
    group.throughput(Throughput::Bytes(int_data.len() as u64));
    group.bench_function("primitive/u64", |b| {
        b.iter(|| {
            let val = decode(black_box(&int_data)).expect("decode");
            black_box(val);
        });
    });

    let text_data = {
        let mut buf = Vec::new();
        Encoder::new(&mut buf)
            .encode_text("hello world, this is a typical short string field value")
            .expect("enc");
        buf
    };
    group.throughput(Throughput::Bytes(text_data.len() as u64));
    group.bench_function("primitive/text_56b", |b| {
        b.iter(|| {
            let val = decode(black_box(&text_data)).expect("decode");
            black_box(val);
        });
    });

    group.finish();
}

fn bench_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode");

    // Decode fixtures once (they're 'static), then benchmark ONLY the encode.
    for fixture in FIXTURES {
        let value = decode(fixture.data).expect("decode fixture");
        group.throughput(Throughput::Bytes(fixture.data.len() as u64));
        group.bench_with_input(BenchmarkId::new("real", fixture.name), &value, |b, val| {
            b.iter(|| {
                let encoded = encode_value(black_box(val)).expect("encode failed");
                black_box(encoded);
            });
        });
    }

    // Pure encode of synthetic maps
    for &n in &[5, 20, 100] {
        let map_bytes = build_map(n);
        let value = decode(&map_bytes).expect("decode");
        group.throughput(Throughput::Bytes(map_bytes.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("synthetic_map", n),
            &map_bytes,
            |b, data| {
                // Must decode per-iter since Value borrows from non-static data
                b.iter(|| {
                    let val = decode(black_box(data)).expect("decode");
                    let encoded = encode_value(&val).expect("encode");
                    black_box(encoded);
                });
            },
        );
        drop(value);
    }

    // Low-level: encode primitives individually
    group.bench_function("primitive/u64", |b| {
        b.iter(|| {
            let mut buf = Vec::with_capacity(16);
            Encoder::new(&mut buf)
                .encode_u64(black_box(1_000_000))
                .expect("enc");
            black_box(buf);
        });
    });

    group.bench_function("primitive/text_56b", |b| {
        let text = "hello world, this is a typical short string field value";
        b.iter(|| {
            let mut buf = Vec::with_capacity(64);
            Encoder::new(&mut buf)
                .encode_text(black_box(text))
                .expect("enc");
            black_box(buf);
        });
    });

    group.bench_function("primitive/cid", |b| {
        let cid = Cid::compute(Codec::Drisl, b"benchmark test data");
        b.iter(|| {
            let mut buf = Vec::with_capacity(48);
            Encoder::new(&mut buf)
                .encode_cid(black_box(&cid))
                .expect("enc");
            black_box(buf);
        });
    });

    group.finish();
}

fn bench_encode_buffer_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("encode_buffer_reuse");

    for fixture in FIXTURES {
        let value = decode(fixture.data).expect("decode fixture");
        group.throughput(Throughput::Bytes(fixture.data.len() as u64));

        // encode_value: allocates a new Vec each time
        group.bench_with_input(
            BenchmarkId::new("new_alloc", fixture.name),
            &value,
            |b, val| {
                b.iter(|| {
                    let encoded = encode_value(black_box(val)).expect("encode");
                    black_box(encoded);
                });
            },
        );

        // encode_value_into: reuses a pre-allocated buffer
        group.bench_with_input(
            BenchmarkId::new("reuse_buf", fixture.name),
            &value,
            |b, val| {
                let mut buf = Vec::with_capacity(4096);
                b.iter(|| {
                    buf.clear();
                    encode_value_into(black_box(val), &mut buf).expect("encode");
                    black_box(&buf);
                });
            },
        );
    }

    group.finish();
}

fn bench_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("roundtrip");

    for fixture in FIXTURES {
        group.throughput(Throughput::Bytes(fixture.data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("decode_encode", fixture.name),
            &fixture.data,
            |b, data| {
                b.iter(|| {
                    let val = decode(black_box(data)).expect("decode");
                    let encoded = encode_value(&val).expect("encode");
                    // Verify determinism: re-encoded bytes must match original
                    debug_assert_eq!(encoded.as_slice(), *data);
                    black_box(encoded);
                });
            },
        );
    }

    group.finish();
}

fn bench_cid(c: &mut Criterion) {
    let mut group = c.benchmark_group("cid");

    // CID computation (SHA-256 hashing) at various data sizes
    for &size in &[64, 256, 1024, 4096] {
        let data: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
        group.throughput(Throughput::Bytes(size as u64));
        group.bench_with_input(BenchmarkId::new("compute", size), &data, |b, data| {
            b.iter(|| {
                let cid = Cid::compute(Codec::Drisl, black_box(data));
                black_box(cid);
            });
        });
    }

    // Binary roundtrip: to_bytes + from_bytes
    let cid = Cid::compute(Codec::Drisl, b"benchmark data");
    group.bench_function("binary_roundtrip", |b| {
        b.iter(|| {
            let bytes = black_box(cid).to_bytes();
            let parsed = Cid::from_bytes(&bytes).expect("from_bytes");
            black_box(parsed);
        });
    });

    // String roundtrip: to_string + parse (includes base32 encode/decode)
    group.bench_function("string_roundtrip", |b| {
        b.iter(|| {
            let s = black_box(cid).to_string();
            let parsed: Cid = s.parse().expect("parse");
            black_box(parsed);
        });
    });

    // Just to_string (base32 encode)
    group.bench_function("to_string", |b| {
        b.iter(|| {
            let s = black_box(cid).to_string();
            black_box(s);
        });
    });

    // Just parse (base32 decode)
    let cid_str = cid.to_string();
    group.bench_function("parse", |b| {
        b.iter(|| {
            let parsed: Cid = black_box(&cid_str).parse().expect("parse");
            black_box(parsed);
        });
    });

    // Batch CID computation: amortize overhead across many items
    let payloads: Vec<Vec<u8>> = (0..100)
        .map(|i| (0..64).map(|j| ((i * 64 + j) % 256) as u8).collect())
        .collect();
    group.throughput(Throughput::Bytes(100 * 64));
    group.bench_function("compute_batch_100x64b", |b| {
        b.iter(|| {
            for payload in &payloads {
                let cid = Cid::compute(Codec::Drisl, black_box(payload));
                black_box(cid);
            }
        });
    });

    group.finish();
}

fn bench_key_cmp(c: &mut Criterion) {
    let mut group = c.benchmark_group("key_cmp");

    // Compare keys of same length (exercises bytewise comparison)
    group.bench_function("same_len_short", |b| {
        b.iter(|| {
            black_box(cbor_key_cmp(black_box("did"), black_box("rev")));
        });
    });

    group.bench_function("same_len_long", |b| {
        b.iter(|| {
            black_box(cbor_key_cmp(
                black_box("app.bsky.feed.post"),
                black_box("app.bsky.feed.like"),
            ));
        });
    });

    // Compare keys of different lengths (exercises length-first ordering)
    group.bench_function("diff_len", |b| {
        b.iter(|| {
            black_box(cbor_key_cmp(black_box("e"), black_box("version")));
        });
    });

    // Sort a realistic set of AT Protocol field names
    group.bench_function("sort_commit_keys", |b| {
        let keys = ["did", "rev", "sig", "data", "prev", "version"];
        b.iter(|| {
            let mut sorted = black_box(keys);
            sorted.sort_by(|a, b| cbor_key_cmp(a, b));
            black_box(sorted);
        });
    });

    group.bench_function("sort_post_keys", |b| {
        let keys = [
            "$type",
            "text",
            "createdAt",
            "langs",
            "facets",
            "reply",
            "embed",
        ];
        b.iter(|| {
            let mut sorted = black_box(keys);
            sorted.sort_by(|a, b| cbor_key_cmp(a, b));
            black_box(sorted);
        });
    });

    group.finish();
}

fn bench_decoder_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("decoder_streaming");

    // Measure Decoder directly (no trailing-data check overhead)
    for fixture in FIXTURES {
        group.throughput(Throughput::Bytes(fixture.data.len() as u64));
        group.bench_with_input(
            BenchmarkId::new("decoder_new_decode", fixture.name),
            &fixture.data,
            |b, data| {
                b.iter(|| {
                    let mut dec = Decoder::new(black_box(data));
                    let val = dec.decode().expect("decode");
                    black_box(val);
                });
            },
        );
    }

    group.finish();
}

/// Benchmark batch processing patterns common in AT Protocol: decode many
/// records sequentially, simulating firehose or backfill ingestion.
fn bench_batch_decode(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_decode");

    // Decode all fixtures sequentially (simulates processing a commit of records)
    let total_bytes: u64 = FIXTURES.iter().map(|f| f.data.len() as u64).sum();
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("all_fixtures", |b| {
        b.iter(|| {
            for fixture in FIXTURES {
                let val = decode(black_box(fixture.data)).expect("decode");
                black_box(val);
            }
        });
    });

    // Decode the same fixture 100 times (simulates bulk record processing)
    group.throughput(Throughput::Bytes(RECORD_POST.len() as u64 * 100));
    group.bench_function("100x_record_post", |b| {
        b.iter(|| {
            for _ in 0..100 {
                let val = decode(black_box(RECORD_POST)).expect("decode");
                black_box(val);
            }
        });
    });

    group.finish();
}

/// Benchmark full roundtrip with buffer reuse: decode + re-encode many records
/// into the same buffer (typical pattern in repo sync).
fn bench_batch_roundtrip(c: &mut Criterion) {
    let mut group = c.benchmark_group("batch_roundtrip");

    let total_bytes: u64 = FIXTURES.iter().map(|f| f.data.len() as u64).sum();
    group.throughput(Throughput::Bytes(total_bytes));
    group.bench_function("all_fixtures_reuse_buf", |b| {
        let mut buf = Vec::with_capacity(4096);
        b.iter(|| {
            for fixture in FIXTURES {
                let val = decode(black_box(fixture.data)).expect("decode");
                buf.clear();
                encode_value_into(&val, &mut buf).expect("encode");
                black_box(&buf);
            }
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_decode,
    bench_encode,
    bench_encode_buffer_reuse,
    bench_roundtrip,
    bench_cid,
    bench_key_cmp,
    bench_decoder_streaming,
    bench_batch_decode,
    bench_batch_roundtrip,
);
criterion_main!(benches);
