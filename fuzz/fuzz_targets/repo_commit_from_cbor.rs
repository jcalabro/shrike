#![no_main]
//! `Commit::from_cbor` must never panic on arbitrary bytes. Any commit it
//! accepts that carries a signature must re-encode and re-decode to an equal
//! commit (decode→encode→decode fixed point over the signed wire form).

use libfuzzer_sys::fuzz_target;
use shrike::repo::Commit;

fuzz_target!(|data: &[u8]| {
    let Ok(commit) = Commit::from_cbor(data) else {
        return;
    };
    // to_cbor errors on an unsigned commit (it must not fabricate a zero sig),
    // so only round-trip signed commits.
    if commit.sig.is_none() {
        return;
    }
    let encoded = Commit::to_cbor(&commit).expect("signed commit must encode");
    let decoded = Commit::from_cbor(&encoded).expect("re-decode must succeed");
    assert_eq!(decoded.did, commit.did, "did mismatch after round-trip");
    assert_eq!(decoded.version, commit.version, "version mismatch");
    assert_eq!(decoded.rev, commit.rev, "rev mismatch");
    assert_eq!(decoded.prev, commit.prev, "prev mismatch");
    assert_eq!(decoded.data, commit.data, "data CID mismatch");
    assert_eq!(
        decoded.sig.as_ref().map(|s| *s.as_bytes()),
        commit.sig.as_ref().map(|s| *s.as_bytes()),
        "sig mismatch after round-trip"
    );
});
