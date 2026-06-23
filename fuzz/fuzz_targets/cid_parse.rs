#![no_main]
//! CID parsing must never panic, and parsing is a fixed point: any CID accepted
//! from bytes must re-encode to the identical 36 bytes (and likewise for the
//! base32 string form). Catches non-canonical aliases and round-trip drift.

use libfuzzer_sys::fuzz_target;
use shrike::cbor::Cid;

#[derive(arbitrary::Arbitrary, Debug)]
struct Input<'a> {
    bytes: &'a [u8],
    text: &'a str,
}

fuzz_target!(|input: Input| {
    // Binary form: accepted bytes must round-trip exactly.
    if let Ok(cid) = Cid::from_bytes(input.bytes) {
        let out = cid.to_bytes();
        assert_eq!(input.bytes, out, "Cid::from_bytes is not a fixed point");
    }

    // String form: accepted strings must round-trip exactly (canonical
    // lowercase base32), and the parsed CID's Display must re-parse equal.
    if let Ok(cid) = input.text.parse::<Cid>() {
        assert_eq!(
            input.text,
            cid.to_string(),
            "Cid::from_str is not a fixed point — non-canonical alias accepted"
        );
        let reparsed: Cid = cid.to_string().parse().expect("Display must re-parse");
        assert_eq!(cid, reparsed, "Cid Display/FromStr round-trip mismatch");
    }
});
