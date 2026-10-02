#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use shrike::cbor::{Cid, Codec};
use shrike::crypto::{K256SigningKey, P256SigningKey, SigningKey};
use shrike::repo::commit::Commit;
use shrike::repo::repo::Repo;
use shrike::repo::verify_record_proof;
use shrike::syntax::{Did, Nsid, RecordKey, Tid, TidClock};

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

/// Records in the large synthetic repository: the size of the real repo
/// the issue's numbers came from.
const LARGE: u64 = 43_649;

/// Commits, record proofs, and CAR handling on a large, long-lived repo.
fn bench_large_repo(c: &mut Criterion) {
    let key = K256SigningKey::from_bytes(&[7; 32]).unwrap();
    let mut repo = common::synthetic_repo(LARGE, &key);
    let paths: Vec<(Nsid, RecordKey)> = (0..LARGE)
        .map(|i| {
            let (collection, rkey, _) = common::record(i);
            (collection, rkey)
        })
        .collect();
    let mut rng = common::SplitMix(1);
    let probes: Vec<usize> = (0..1000).map(|_| rng.below(paths.len())).collect();

    let mut group = c.benchmark_group("large_repo");
    group.sample_size(30);

    // A one-record write signed into a commit, as a PDS does per request.
    let mut i = 0u64;
    group.bench_function(BenchmarkId::new("update_commit", LARGE), |b| {
        b.iter(|| {
            i += 1;
            let (collection, rkey) = &paths[probes[i as usize % probes.len()]];
            repo.update(collection, rkey, &common::record(LARGE + i).2)
                .unwrap();
            black_box(repo.commit(&key).unwrap());
        });
    });

    let mut j = 0;
    group.bench_function(BenchmarkId::new("record_proof", LARGE), |b| {
        b.iter(|| {
            j = (j + 1) % probes.len();
            let (collection, rkey) = &paths[probes[j]];
            black_box(repo.record_proof(collection, rkey).unwrap());
        });
    });

    let proofs: Vec<(usize, Vec<u8>)> = probes
        .iter()
        .take(100)
        .map(|&p| (p, repo.record_proof(&paths[p].0, &paths[p].1).unwrap()))
        .collect();
    let did = common::did();
    let mut j = 0;
    group.bench_function(BenchmarkId::new("verify_record_proof", LARGE), |b| {
        b.iter(|| {
            j = (j + 1) % proofs.len();
            let (p, car) = &proofs[j];
            let (collection, rkey) = &paths[*p];
            black_box(verify_record_proof(car, &did, key.public_key(), collection, rkey).unwrap());
        });
    });
    group.finish();

    let car = repo.export_car().unwrap();
    let mut group = c.benchmark_group("large_repo_car");
    group.sample_size(20);
    group.measurement_time(Duration::from_secs(8));
    group.throughput(Throughput::Bytes(car.len() as u64));
    group.bench_function(BenchmarkId::new("read_all", LARGE), |b| {
        b.iter(|| black_box(shrike::car::read_all(black_box(&car[..])).unwrap()));
    });
    group.bench_function(BenchmarkId::new("verify", LARGE), |b| {
        b.iter(|| shrike::car::verify(black_box(&car[..])).unwrap());
    });
    group.bench_function(BenchmarkId::new("load_car", LARGE), |b| {
        b.iter(|| black_box(Repo::load_car(black_box(&car)).unwrap()));
    });
    group.bench_function(BenchmarkId::new("export_car", LARGE), |b| {
        b.iter(|| black_box(repo.export_car().unwrap()));
    });
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
    bench_large_repo,
);
criterion_main!(benches);
