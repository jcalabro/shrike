#![no_main]
//! The subscription frame decoder must never panic on arbitrary bytes, and a
//! decoded frame must survive an encode/decode round trip unchanged.

use libfuzzer_sys::fuzz_target;
use shrike::xrpc_server::Frame;

fuzz_target!(|data: &[u8]| {
    let Ok(frame) = Frame::decode(data) else {
        return;
    };
    let _ = frame.to_json("io.example.stream");
    let encoded = frame.encode().expect("a decoded frame encodes");
    assert_eq!(Frame::decode(&encoded).expect("re-decode"), frame);
});
