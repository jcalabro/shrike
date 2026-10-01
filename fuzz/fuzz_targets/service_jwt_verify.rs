#![no_main]
//! Service JWT verification must never panic on arbitrary tokens, and must
//! never accept one: the fuzzer cannot forge a signature from this key.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};
use std::time::{Duration, UNIX_EPOCH};

use libfuzzer_sys::fuzz_target;
use shrike::service_auth::ServiceJwtVerifier;

// A fixed P-256 key from the indigo service-auth vectors.
const DID_KEY: &str = "did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART";

fuzz_target!(|data: &[u8]| {
    let Ok(jwt) = std::str::from_utf8(data) else {
        return;
    };
    let resolver = |_iss: String, _refresh: bool| async { Ok(DID_KEY.to_owned()) };
    let verifier = ServiceJwtVerifier::new(Some("did:example:aud"), resolver);
    let now = UNIX_EPOCH + Duration::from_secs(1_700_000_000);
    for lxm in [None, Some("com.example.method")] {
        // Every future here is immediately ready.
        let fut = pin!(verifier.verify_at(jwt, lxm, now));
        if let Poll::Ready(result) = fut.poll(&mut Context::from_waker(Waker::noop())) {
            assert!(result.is_err(), "accepted a forged token: {jwt}");
        }
    }
});
