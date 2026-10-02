#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

//! Commit-sized signing and verification on both atproto curves.

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use shrike::crypto::{
    K256SigningKey, K256VerifyingKey, P256SigningKey, P256VerifyingKey, SigningKey, VerifyingKey,
};

/// About the size of a commit's unsigned bytes.
const MESSAGE: &[u8] = &[0x5a; 160];

fn bench_curve(c: &mut Criterion, name: &str, key: &dyn SigningKey, parsed: &dyn VerifyingKey) {
    let mut group = c.benchmark_group(name);
    group.bench_function("sign", |b| {
        b.iter(|| black_box(key.sign(black_box(MESSAGE)).unwrap()));
    });
    let sig = key.sign(MESSAGE).unwrap();
    group.bench_function("verify", |b| {
        b.iter(|| parsed.verify(black_box(MESSAGE), black_box(&sig)).unwrap());
    });
    group.finish();
}

fn bench_crypto(c: &mut Criterion) {
    let k256 = K256SigningKey::from_bytes(&[7; 32]).unwrap();
    let k256_public = K256VerifyingKey::from_bytes(&k256.public_key().to_bytes()).unwrap();
    bench_curve(c, "k256", &k256, &k256_public);

    let p256 = P256SigningKey::from_bytes(&[7; 32]).unwrap();
    let p256_public = P256VerifyingKey::from_bytes(&p256.public_key().to_bytes()).unwrap();
    bench_curve(c, "p256", &p256, &p256_public);

    let mut group = c.benchmark_group("k256");
    let compressed = k256.public_key().to_bytes();
    group.bench_function("parse_public_key", |b| {
        b.iter(|| black_box(K256VerifyingKey::from_bytes(black_box(&compressed)).unwrap()));
    });
    group.finish();
}

criterion_group!(benches, bench_crypto);
criterion_main!(benches);
