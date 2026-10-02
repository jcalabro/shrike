//! `drisl_to_json_into` writes exactly what `serde_json::to_vec` writes of
//! `drisl_to_json`, and fails the same way, over real repositories and the
//! vendored DRISL and JSON fixtures.
#![allow(clippy::unwrap_used, clippy::panic)]
#![cfg(all(feature = "cbor", feature = "car"))]

use serde_json::Value as Json;
use shrike::cbor::json::{Integers, drisl_to_json, drisl_to_json_into, json_to_drisl};

/// Asserts both conversions agree on `bytes`, and returns whether it converts.
fn check(bytes: &[u8]) -> bool {
    let mut out = b"kept".to_vec();
    let actual = drisl_to_json_into(bytes, &mut out);
    match drisl_to_json(bytes) {
        Ok(json) => {
            actual.unwrap_or_else(|e| panic!("{e} for {bytes:02x?}"));
            assert_eq!(out[..4], *b"kept");
            assert_eq!(out[4..], serde_json::to_vec(&json).unwrap(), "{bytes:02x?}");
            true
        }
        Err(want) => {
            let got = actual
                .err()
                .unwrap_or_else(|| panic!("accepted {bytes:02x?}"));
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{bytes:02x?}");
            assert_eq!(out, b"kept");
            false
        }
    }
}

#[test]
fn repository_blocks() {
    for path in [
        "benches/fixtures/calabro.car",
        "testdata/greenground.repo.car",
        "testdata/repo_slice.car",
    ] {
        let car = std::fs::read(path).unwrap();
        let (_, blocks) = shrike::car::read_slice(&car).unwrap();
        let converted = blocks.iter().filter(|b| check(b.data)).count();
        assert_eq!(converted, blocks.len(), "{path}");
        // Every truncation of a sample of records, MST nodes and commits.
        for block in blocks.iter().step_by(97) {
            for end in 0..block.data.len() {
                assert!(!check(&block.data[..end]), "{path}");
            }
        }
    }
}

#[test]
fn data_model_fixtures() {
    #[derive(serde::Deserialize)]
    struct Fixture {
        cbor_base64: String,
    }
    let raw = std::fs::read_to_string("testdata/cbor_data_model_fixtures.json").unwrap();
    let fixtures: Vec<Fixture> = serde_json::from_str(&raw).unwrap();
    for f in &fixtures {
        let bytes = data_encoding::BASE64_NOPAD
            .decode(f.cbor_base64.as_bytes())
            .unwrap();
        assert!(check(&bytes));
    }
}

/// Mostly inputs DRISL rejects, so this compares errors.
#[test]
fn rfc8949_vectors() {
    #[derive(serde::Deserialize)]
    struct Vector {
        hex: String,
    }
    let raw = std::fs::read_to_string("testdata/cbor_rfc8949_vectors.json").unwrap();
    let vectors: Vec<Vector> = serde_json::from_str(&raw).unwrap();
    let converted = vectors
        .iter()
        .filter(|v| {
            check(
                &data_encoding::HEXLOWER_PERMISSIVE
                    .decode(v.hex.as_bytes())
                    .unwrap(),
            )
        })
        .count();
    assert!(converted > 0 && converted < vectors.len());
}

/// JSON documents with many keys whose DRISL and bytewise orders differ:
/// the lex-json vectors and every lexicon fixture.
#[test]
fn json_fixtures() {
    let mut documents = Vec::new();
    let raw = std::fs::read_to_string("testdata/lex_json_vectors.json").unwrap();
    let vectors: Json = serde_json::from_str(&raw).unwrap();
    for group in ["special", "plain"] {
        for v in vectors[group].as_array().unwrap() {
            documents.push(v["json"].clone());
        }
    }
    let mut dirs = vec![
        std::path::PathBuf::from("testdata/lexicon"),
        std::path::PathBuf::from("benches/fixtures/lexicons"),
    ];
    while let Some(dir) = dirs.pop() {
        for entry in std::fs::read_dir(dir).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                dirs.push(path);
            } else if path.extension().is_some_and(|e| e == "json") {
                documents.push(serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap());
            }
        }
    }
    let mut converted = 0;
    for json in &documents {
        // Some documents hold floats, which DRISL cannot.
        if let Ok(bytes) = json_to_drisl(json, Integers::Any) {
            assert!(check(&bytes));
            converted += 1;
        }
    }
    assert!(converted > 50, "{converted}");
}
