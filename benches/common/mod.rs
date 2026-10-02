//! Fixtures shared by the benchmarks: realistic records, a large synthetic
//! repository, and the records of a real one (calabro.io).
#![allow(dead_code)]

use shrike::cbor::{Cid, Codec, Value, encode_value};
use shrike::crypto::SigningKey;
use shrike::repo::{Repo, WriteOp};
use shrike::syntax::{Did, Nsid, RecordKey, Tid, TidClock};

/// The calabro.io repository (~1.5 MB, ~4,300 records).
pub const CALABRO_CAR: &[u8] = include_bytes!("../fixtures/calabro.car");

/// The record collections that make up most of a real repository.
pub const COLLECTIONS: [&str; 4] = [
    "app.bsky.feed.like",
    "app.bsky.feed.post",
    "app.bsky.feed.repost",
    "app.bsky.graph.follow",
];

pub fn did() -> Did {
    Did::try_from("did:plc:4uz2445cjiw7w4nobfgnu35f").unwrap()
}

/// A deterministic, strictly increasing TID.
pub fn tid(i: u64) -> Tid {
    Tid::new(1_700_000_000_000_000 + i * 1_000_003, (i % 1024) as u16).unwrap()
}

fn other_did(i: u64) -> String {
    format!("did:plc:{:024x}", i.wrapping_mul(0x9e37_79b9_7f4a_7c15))
}

fn created_at(i: u64) -> String {
    format!(
        "2024-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        1 + i % 12,
        1 + i % 28,
        i % 24,
        i % 60,
        (i / 7) % 60,
        i % 1000
    )
}

/// The `i`th record of a synthetic repository, shaped like the real thing:
/// mostly likes, then follows, posts and reposts.
pub fn record(i: u64) -> (Nsid, RecordKey, Vec<u8>) {
    let collection = match i % 8 {
        0..=3 => COLLECTIONS[0],
        4 | 5 => COLLECTIONS[3],
        6 => COLLECTIONS[1],
        _ => COLLECTIONS[2],
    };
    let created = created_at(i);
    let subject_uri = format!("at://{}/app.bsky.feed.post/{}", other_did(i), tid(i * 31));
    let subject_cid = Cid::compute(Codec::Drisl, &i.to_be_bytes()).to_string();
    let subject_did = other_did(i);
    let text = format!(
        "post number {i}: the quick brown fox jumps over the lazy dog, and then \
         keeps going for a while so the text is a realistic length"
    );
    let strong_ref = Value::Map(vec![
        ("cid", Value::Text(&subject_cid)),
        ("uri", Value::Text(&subject_uri)),
    ]);
    let value = match collection {
        "app.bsky.feed.post" => Value::Map(vec![
            ("$type", Value::Text(collection)),
            ("createdAt", Value::Text(&created)),
            ("langs", Value::Array(vec![Value::Text("en")])),
            ("text", Value::Text(&text)),
        ]),
        "app.bsky.graph.follow" => Value::Map(vec![
            ("$type", Value::Text(collection)),
            ("createdAt", Value::Text(&created)),
            ("subject", Value::Text(&subject_did)),
        ]),
        _ => Value::Map(vec![
            ("$type", Value::Text(collection)),
            ("createdAt", Value::Text(&created)),
            ("subject", strong_ref),
        ]),
    };
    (
        Nsid::try_from(collection).unwrap(),
        RecordKey::try_from(tid(i).to_string().as_str()).unwrap(),
        encode_value(&value).unwrap(),
    )
}

/// A committed repository of `n` synthetic records.
pub fn synthetic_repo(n: u64, key: &dyn SigningKey) -> Repo {
    let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
    let writes: Vec<WriteOp> = (0..n)
        .map(|i| {
            let (collection, rkey, record) = record(i);
            WriteOp::Create {
                collection,
                rkey,
                record,
            }
        })
        .collect();
    repo.apply_writes(&writes, key).unwrap();
    repo
}

/// The calabro.io repository's records in `collection`, as DRISL bytes.
pub fn calabro_records(collection: &str) -> Vec<Vec<u8>> {
    let mut repo = Repo::load_car(CALABRO_CAR).unwrap();
    let collection = Nsid::try_from(collection).unwrap();
    let keys = repo.list(&collection).unwrap();
    keys.into_iter()
        .map(|(rkey, _)| repo.get(&collection, &rkey).unwrap().unwrap().1)
        .collect()
}

/// A small, fast, deterministic PRNG for picking benchmark inputs.
pub struct SplitMix(pub u64);

impl SplitMix {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}
