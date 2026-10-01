//! Record-data interop fixtures shared with indigo
//! (`atproto/lexicon/testdata`), validated against `example.lexicon.record`.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use shrike::lexicon::{Catalog, validate_record};

const DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/testdata/lexicon/interop");

fn catalog() -> Catalog {
    let mut catalog = Catalog::new();
    for entry in std::fs::read_dir(format!("{DIR}/catalog")).unwrap() {
        let path = entry.unwrap().path();
        catalog
            .add_schema(&std::fs::read(&path).unwrap())
            .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    }
    catalog
}

fn fixtures(name: &str) -> Vec<(String, serde_json::Value)> {
    let raw = std::fs::read(format!("{DIR}/{name}")).unwrap();
    let all: Vec<serde_json::Value> = serde_json::from_slice(&raw).unwrap();
    assert!(!all.is_empty());
    all.into_iter()
        .map(|f| (f["name"].as_str().unwrap().to_owned(), f["data"].clone()))
        .collect()
}

#[test]
fn valid_records() {
    let catalog = catalog();
    for (name, data) in fixtures("record-data-valid.json") {
        if let Err(e) = validate_record(&catalog, "example.lexicon.record", &data) {
            panic!("{name}: {e}");
        }
    }
}

#[test]
fn invalid_records() {
    let catalog = catalog();
    for (name, data) in fixtures("record-data-invalid.json") {
        assert!(
            validate_record(&catalog, "example.lexicon.record", &data).is_err(),
            "{name}: accepted"
        );
    }
}
