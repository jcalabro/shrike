#![no_main]
//! `json_slice_to_drisl` must give exactly what `serde_json::from_slice` and
//! then `json_to_drisl` give, output and error alike. Each input is tried as
//! JSON text, and as a structured document that reaches duplicate keys,
//! `$link` and `$bytes` maps, escapes and number edge cases far more often.

use arbitrary::{Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use shrike::cbor::json::{Integers, JsonError, json_slice_to_drisl, json_to_drisl};
use std::fmt::Write;

const CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

const LINKS: &[&str] = &[
    CID,
    "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTDh",
    "k2jvsl7wph2xec9tldt5guqsv8bqse480mslfjw2lyfdlxfws95udh3k",
    "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a==",
    "bafkreig77vqcdozl2wyk6z3cscaj5q5fggi53aoh64fewkdiri3cdauyn4",
    "bafy",
    "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
    "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
];

const BASE64: &[&str] = &[
    "", "TQ", "TQ=", "TQ==", "TQ===", "TWFu", "+/+/", "aGk", "-_",
];

const KEYS: &[&str] = &["a", "b", "aa", "ab", "$link", "$bytes", "$type", "\\u0061"];

#[derive(Arbitrary, Debug)]
enum Doc {
    Null,
    Bool(bool),
    Int(i64),
    Uint(u64),
    Float(f64),
    /// `{mantissa}e{exponent}`, or with a `.0` fraction.
    Exp(i64, i16, bool),
    Str(String, bool),
    Link(u8),
    Bytes(u8),
    Arr(Vec<Doc>),
    Obj(Vec<(Key, Doc)>),
    /// `serde_json`'s private raw value token as the first key.
    Raw(Box<Doc>),
}

#[derive(Arbitrary, Debug)]
enum Key {
    Known(u8),
    /// 20 to 275 bytes, across the one-, two- and three-byte CBOR heads.
    Long(u8),
    Any(String, bool),
}

/// A JSON string, its non-ASCII characters escaped if `escape`.
fn string(out: &mut String, s: &str, escape: bool) {
    if !escape {
        out.push_str(&serde_json::to_string(s).unwrap());
        return;
    }
    out.push('"');
    for c in s.chars() {
        match c {
            '"' | '\\' => {
                out.push('\\');
                out.push(c);
            }
            ' '..='~' => out.push(c),
            _ => {
                for unit in c.encode_utf16(&mut [0; 2]) {
                    write!(out, "\\u{unit:04x}").unwrap();
                }
            }
        }
    }
    out.push('"');
}

fn render(out: &mut String, doc: &Doc, depth: usize) {
    if depth > 16 {
        out.push_str("null");
        return;
    }
    match doc {
        Doc::Null => out.push_str("null"),
        Doc::Bool(b) => write!(out, "{b}").unwrap(),
        Doc::Int(n) => write!(out, "{n}").unwrap(),
        Doc::Uint(n) => write!(out, "{n}").unwrap(),
        Doc::Float(f) => write!(out, "{f:?}").unwrap(),
        Doc::Exp(m, e, true) => write!(out, "{m}e{e}").unwrap(),
        Doc::Exp(m, _, false) => write!(out, "{m}.0").unwrap(),
        Doc::Str(s, escape) => string(out, s, *escape),
        Doc::Link(i) => write!(
            out,
            "{{\"$link\":\"{}\"}}",
            LINKS[*i as usize % LINKS.len()]
        )
        .unwrap(),
        Doc::Bytes(i) => write!(
            out,
            "{{\"$bytes\":\"{}\"}}",
            BASE64[*i as usize % BASE64.len()]
        )
        .unwrap(),
        Doc::Arr(items) => {
            out.push('[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                render(out, item, depth + 1);
            }
            out.push(']');
        }
        Doc::Obj(members) => {
            out.push('{');
            for (i, (key, value)) in members.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                let known = match key {
                    Key::Known(k) => KEYS[*k as usize % KEYS.len()],
                    _ => "",
                };
                match key {
                    Key::Known(_) => write!(out, "\"{known}\"").unwrap(),
                    Key::Long(n) => write!(out, "\"{}\"", "k".repeat(20 + *n as usize)).unwrap(),
                    Key::Any(s, escape) => string(out, s, *escape),
                }
                out.push(':');
                // A value that `$link` or `$bytes` may take.
                match (known, value) {
                    ("$link", Doc::Link(i)) => {
                        write!(out, "\"{}\"", LINKS[*i as usize % LINKS.len()]).unwrap()
                    }
                    ("$bytes", Doc::Bytes(i)) => {
                        write!(out, "\"{}\"", BASE64[*i as usize % BASE64.len()]).unwrap()
                    }
                    _ => render(out, value, depth + 1),
                }
            }
            out.push('}');
        }
        // Each level escapes the last again, doubling its backslashes.
        Doc::Raw(inner) if depth > 2 => render(out, inner, depth + 1),
        Doc::Raw(inner) => {
            let mut text = String::new();
            render(&mut text, inner, depth + 1);
            out.push_str("{\"$serde_json::private::RawValue\":");
            string(out, &text, false);
            out.push('}');
        }
    }
}

fn check(json: &[u8]) {
    for integers in [Integers::Safe, Integers::Any] {
        let want: Result<Vec<u8>, JsonError> = serde_json::from_slice(json)
            .map_err(JsonError::from)
            .and_then(|v| Ok(json_to_drisl(&v, integers)?));
        let got = json_slice_to_drisl(json, integers);
        assert_eq!(format!("{got:?}"), format!("{want:?}"));
    }
}

fuzz_target!(|data: &[u8]| {
    check(data);
    if let Ok(doc) = Doc::arbitrary(&mut Unstructured::new(data)) {
        let mut json = String::new();
        render(&mut json, &doc, 0);
        check(json.as_bytes());
    }
});
