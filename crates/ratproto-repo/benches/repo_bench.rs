#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use criterion::{BenchmarkId, Criterion, black_box, criterion_group, criterion_main};
use ratproto_cbor::{Cid, Codec};
use ratproto_crypto::{P256SigningKey, SigningKey};
use ratproto_repo::commit::Commit;
use ratproto_repo::repo::Repo;
use ratproto_syntax::{Did, Nsid, RecordKey, Tid, TidClock};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn test_did() -> Did {
    Did::try_from("did:plc:test123456789abcdefghij").unwrap()
}

fn test_commit(sk: &P256SigningKey) -> Commit {
    let data_cid = Cid::compute(Codec::Drisl, b"test data");
    let rev = Tid::try_from("2222222222222").unwrap();
    let mut commit = Commit {
        did: test_did(),
        version: 3,
        rev,
        prev: None,
        data: data_cid,
        sig: None,
    };
    commit.sign(sk).unwrap();
    commit
}

fn col(s: &str) -> Nsid {
    Nsid::try_from(s).unwrap()
}

fn rk(s: &str) -> RecordKey {
    RecordKey::try_from(s).unwrap()
}

/// Generate a fake record of the given size.
fn fake_record(i: usize, size: usize) -> Vec<u8> {
    (0..size).map(|j| ((i * 31 + j * 7) % 256) as u8).collect()
}

// ---------------------------------------------------------------------------
// Commit benchmarks
// ---------------------------------------------------------------------------

fn bench_commit_encode(c: &mut Criterion) {
    let mut group = c.benchmark_group("commit");
    let sk = P256SigningKey::generate();
    let commit = test_commit(&sk);

    group.bench_function("to_cbor", |b| {
        b.iter(|| {
            let encoded = black_box(&commit).to_cbor().expect("encode");
            black_box(encoded);
        });
    });

    let encoded = commit.to_cbor().unwrap();
    group.bench_function("from_cbor", |b| {
        b.iter(|| {
            let decoded = Commit::from_cbor(black_box(&encoded)).expect("decode");
            black_box(decoded);
        });
    });

    group.bench_function("roundtrip", |b| {
        b.iter(|| {
            let encoded = black_box(&commit).to_cbor().expect("encode");
            let decoded = Commit::from_cbor(&encoded).expect("decode");
            black_box(decoded);
        });
    });

    group.bench_function("unsigned_bytes", |b| {
        b.iter(|| {
            let bytes = black_box(&commit).unsigned_bytes().expect("unsigned");
            black_box(bytes);
        });
    });

    group.finish();
}

fn bench_commit_sign_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("sign_verify");
    let sk = P256SigningKey::generate();

    group.bench_function("sign_p256", |b| {
        let data_cid = Cid::compute(Codec::Drisl, b"sign bench");
        let rev = Tid::try_from("2222222222222").unwrap();
        b.iter(|| {
            let mut commit = Commit {
                did: test_did(),
                version: 3,
                rev,
                prev: None,
                data: data_cid,
                sig: None,
            };
            commit.sign(black_box(&sk)).expect("sign");
            black_box(&commit);
        });
    });

    let commit = test_commit(&sk);
    group.bench_function("verify_p256", |b| {
        b.iter(|| {
            black_box(&commit)
                .verify(black_box(sk.public_key()))
                .expect("verify");
        });
    });

    // Full cycle: sign + encode + decode + verify
    group.bench_function("sign_encode_decode_verify", |b| {
        let data_cid = Cid::compute(Codec::Drisl, b"full cycle");
        let rev = Tid::try_from("2222222222222").unwrap();
        b.iter(|| {
            let mut commit = Commit {
                did: test_did(),
                version: 3,
                rev,
                prev: None,
                data: data_cid,
                sig: None,
            };
            commit.sign(&sk).expect("sign");
            let encoded = commit.to_cbor().expect("encode");
            let decoded = Commit::from_cbor(&encoded).expect("decode");
            decoded.verify(sk.public_key()).expect("verify");
            black_box(decoded);
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Repo CRUD benchmarks
// ---------------------------------------------------------------------------

fn bench_repo_create(c: &mut Criterion) {
    let mut group = c.benchmark_group("repo_create");
    let collection = col("app.bsky.feed.post");

    for &n in &[100, 1000] {
        let records: Vec<Vec<u8>> = (0..n).map(|i| fake_record(i, 200)).collect();
        let rkeys: Vec<RecordKey> = (0..n).map(|i| rk(&format!("3k{i:010}"))).collect();

        group.bench_with_input(BenchmarkId::new("sequential", n), &n, |b, _| {
            b.iter(|| {
                let clock = TidClock::new(0).unwrap();
                let mut repo = Repo::new(test_did(), clock);
                for (rkey, record) in rkeys.iter().zip(records.iter()) {
                    repo.create(&collection, rkey, record).expect("create");
                }
                black_box(&repo);
            });
        });
    }

    group.finish();
}

fn bench_repo_get(c: &mut Criterion) {
    let mut group = c.benchmark_group("repo_get");
    let collection = col("app.bsky.feed.post");

    for &n in &[100, 1000] {
        let clock = TidClock::new(0).unwrap();
        let mut repo = Repo::new(test_did(), clock);
        let rkeys: Vec<RecordKey> = (0..n).map(|i| rk(&format!("3k{i:010}"))).collect();
        for (i, rkey) in rkeys.iter().enumerate() {
            repo.create(&collection, rkey, &fake_record(i, 200))
                .expect("create");
        }

        // Benchmark: look up records spread across the tree
        let probe_indices: Vec<usize> = (0..10).map(|i| i * n / 10).collect();
        group.bench_with_input(
            BenchmarkId::new("10_lookups", n),
            &probe_indices,
            |b, probes| {
                b.iter(|| {
                    for &i in probes {
                        let result = repo.get(&collection, black_box(&rkeys[i])).expect("get");
                        black_box(result);
                    }
                });
            },
        );
    }

    group.finish();
}

fn bench_repo_commit(c: &mut Criterion) {
    let mut group = c.benchmark_group("repo_commit");
    let sk = P256SigningKey::generate();
    let collection = col("app.bsky.feed.post");

    for &n in &[100, 1000] {
        let records: Vec<Vec<u8>> = (0..n).map(|i| fake_record(i, 200)).collect();
        let rkeys: Vec<RecordKey> = (0..n).map(|i| rk(&format!("3k{i:010}"))).collect();

        group.bench_with_input(BenchmarkId::new("create_then_commit", n), &n, |b, _| {
            b.iter(|| {
                let clock = TidClock::new(0).unwrap();
                let mut repo = Repo::new(test_did(), clock);
                for (rkey, record) in rkeys.iter().zip(records.iter()) {
                    repo.create(&collection, rkey, record).expect("create");
                }
                let commit = repo.commit(black_box(&sk)).expect("commit");
                black_box(commit);
            });
        });
    }

    group.finish();
}

fn bench_repo_list(c: &mut Criterion) {
    let mut group = c.benchmark_group("repo_list");
    let collection = col("app.bsky.feed.post");

    for &n in &[100, 1000] {
        let clock = TidClock::new(0).unwrap();
        let mut repo = Repo::new(test_did(), clock);
        let rkeys: Vec<RecordKey> = (0..n).map(|i| rk(&format!("3k{i:010}"))).collect();
        for (i, rkey) in rkeys.iter().enumerate() {
            repo.create(&collection, rkey, &fake_record(i, 200))
                .expect("create");
        }

        group.bench_with_input(BenchmarkId::new("all", n), &n, |b, _| {
            b.iter(|| {
                let entries = repo.list(&collection).expect("list");
                black_box(entries.len());
            });
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_commit_encode,
    bench_commit_sign_verify,
    bench_repo_create,
    bench_repo_get,
    bench_repo_commit,
    bench_repo_list,
);
criterion_main!(benches);
