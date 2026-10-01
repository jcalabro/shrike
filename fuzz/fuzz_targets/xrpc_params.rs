#![no_main]
//! Query-string parsing and typed parameter decoding must never panic on
//! arbitrary input.

use libfuzzer_sys::fuzz_target;
use shrike::xrpc_server::Params;

#[allow(dead_code)]
#[derive(serde::Deserialize)]
struct Typed {
    s: Option<String>,
    n: Option<i64>,
    u: Option<u32>,
    f: Option<f64>,
    b: Option<bool>,
    list: Option<Vec<String>>,
    nums: Option<Vec<i64>>,
    #[serde(rename = "type")]
    kind: Option<Kind>,
}

#[derive(serde::Deserialize)]
#[serde(rename_all = "lowercase")]
enum Kind {
    A,
    B,
}

fuzz_target!(|data: &[u8]| {
    let Ok(query) = std::str::from_utf8(data) else {
        return;
    };
    let params = Params::from_query(query);
    let _ = params.get("s");
    let _ = params.get_all("list");
    let _ = params.deserialize::<Typed>();
    let _ = params.deserialize::<serde_json::Value>();
    let _ = params.deserialize::<std::collections::HashMap<String, Vec<String>>>();
});
