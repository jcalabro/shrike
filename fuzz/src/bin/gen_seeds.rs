//! Generate seed corpora for the byte-oriented fuzz targets.
//!
//! Writes valid, real-world-shaped encoded artifacts (DRISL values, MST node
//! blocks, CAR files, CIDs, commits, labels) into `corpus/<target>/` so the
//! fuzzer starts from meaningful inputs and mutates outward, reaching deep code
//! paths far faster than from empty/random seeds.
//!
//! Run from the repo root: `just fuzz-seed` (or `cargo run --bin gen_seeds`
//! inside `fuzz/`). Idempotent; safe to re-run.

use std::fs;
use std::io::Write;
use std::path::Path;

use shrike::cbor::{Cid, Codec, Value, encode_value};
use shrike::mst::node::{EntryData, NodeData, encode_node_data};

fn write_seed(target: &str, name: &str, bytes: &[u8]) {
    let dir = Path::new("corpus").join(target);
    if let Err(e) = fs::create_dir_all(&dir) {
        eprintln!("warn: mkdir {dir:?}: {e}");
        return;
    }
    let path = dir.join(name);
    match fs::File::create(&path).and_then(|mut f| f.write_all(bytes)) {
        Ok(()) => println!("  {target}/{name} ({} bytes)", bytes.len()),
        Err(e) => eprintln!("warn: write {path:?}: {e}"),
    }
}

fn cid() -> Cid {
    Cid::compute(Codec::Drisl, b"seed")
}

fn main() {
    println!("generating fuzz seeds...");

    // --- DRISL values (cbor_decode, cbor_decode_differential) ---
    let values: &[(&str, Value)] = &[
        ("u0", Value::Unsigned(0)),
        ("imax", Value::Unsigned(i64::MAX as u64)),
        ("neg", Value::Signed(-42)),
        ("float", Value::Float(1.5)),
        ("true", Value::Bool(true)),
        ("null", Value::Null),
        ("text", Value::Text("hello world")),
        ("bytes", Value::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])),
        ("cid", Value::Cid(cid())),
        (
            "array",
            Value::Array(vec![Value::Unsigned(1), Value::Text("x"), Value::Null]),
        ),
        (
            "map",
            Value::Map(vec![
                ("a", Value::Unsigned(1)),
                ("b", Value::Cid(cid())),
                ("text", Value::Text("v")),
            ]),
        ),
    ];
    for (name, v) in values {
        if let Ok(bytes) = encode_value(v) {
            for t in ["cbor_decode", "cbor_decode_differential"] {
                write_seed(t, name, &bytes);
            }
        }
    }

    // --- MST node blocks (mst_decode_node_data*, mst_load_and_walk) ---
    let nodes: &[(&str, NodeData)] = &[
        (
            "empty",
            NodeData {
                left: None,
                entries: vec![],
            },
        ),
        (
            "single",
            NodeData {
                left: None,
                entries: vec![EntryData {
                    prefix_len: 0,
                    key_suffix: b"app.bsky.feed.post/aaa".to_vec(),
                    value: cid(),
                    right: None,
                }],
            },
        ),
        (
            "prefix_compressed",
            NodeData {
                left: Some(cid()),
                entries: vec![
                    EntryData {
                        prefix_len: 0,
                        key_suffix: b"app.bsky.feed.post/aaa".to_vec(),
                        value: cid(),
                        right: None,
                    },
                    EntryData {
                        prefix_len: 19,
                        key_suffix: b"bbb".to_vec(),
                        value: cid(),
                        right: Some(cid()),
                    },
                ],
            },
        ),
    ];
    for (name, nd) in nodes {
        if let Ok(bytes) = encode_node_data(nd) {
            for t in [
                "mst_decode_node_data",
                "mst_decode_node_data_roundtrip",
                "mst_load_and_walk",
            ] {
                write_seed(t, name, &bytes);
            }
        }
    }

    // --- CID bytes (cid_parse) ---
    write_seed("cid_parse", "drisl_cid", &cid().to_bytes());
    write_seed(
        "cid_parse",
        "raw_cid",
        &Cid::compute(Codec::Raw, b"blob").to_bytes(),
    );
    write_seed("cid_parse", "cid_string", cid().to_string().as_bytes());

    // --- CAR files (car_read_all) ---
    {
        use shrike::car::{Block, write_all};
        let block = Block {
            cid: Cid::compute(Codec::Raw, b"hello"),
            data: b"hello".to_vec(),
        };
        if let Ok(car) = write_all(&[block.cid], std::slice::from_ref(&block)) {
            write_seed("car_read_all", "one_block", &car);
        }
        if let Ok(empty) = write_all(&[cid()], &[]) {
            write_seed("car_read_all", "empty", &empty);
        }
    }

    // --- Syntax identifiers (syntax_parsers) ---
    for (name, s) in [
        ("did_plc", "did:plc:z72i7hdynmk6r22z27h6tvur"),
        ("did_web", "did:web:example.com"),
        ("handle", "alice.bsky.social"),
        ("nsid", "app.bsky.feed.post"),
        (
            "aturi",
            "at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jui7kd2z3b2a",
        ),
        ("tid", "3jui7kd2z3b2a"),
        ("datetime", "2024-01-01T00:00:00.000Z"),
        ("recordkey", "self"),
        ("language", "en-US"),
    ] {
        write_seed("syntax_parsers", name, s.as_bytes());
    }

    println!("done.");
}
