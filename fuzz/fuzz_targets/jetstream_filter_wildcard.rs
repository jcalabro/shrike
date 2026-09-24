#![no_main]
//! Collection-predicate parsing (including the `*.*.*` NSID-wildcard grammar)
//! and `matches_segment` must never panic on arbitrary strings. Any collection
//! the parser accepts must survive being matched against arbitrary kind/DID/
//! collection triples without panicking — the wildcard matcher walks two dotted
//! strings and must stay total on ragged input.

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;
use shrike::jetstream::{Filter, Kind};

#[derive(Arbitrary, Debug)]
struct Input<'a> {
    collection_pat: &'a str,
    did_pat: &'a str,
    kind: u8,
    probe_did: &'a str,
    probe_collection: &'a str,
}

fn kind_of(v: u8) -> Kind {
    match v % 4 {
        0 => Kind::Commit,
        1 => Kind::Identity,
        2 => Kind::Account,
        _ => Kind::Sync,
    }
}

fuzz_target!(|input: Input| {
    // Build a filter from the arbitrary predicates. Parsing may reject them —
    // that is fine; we only require it never panics.
    let mut filter = Filter::new();
    if let Ok(f) = filter.clone().collection(input.collection_pat) {
        filter = f;
    }
    if let Ok(f) = filter.clone().did(input.did_pat) {
        filter = f;
    }
    // matches_segment must be total on any kind/DID/collection triple.
    let _ = filter.matches_segment(kind_of(input.kind), input.probe_did, input.probe_collection);
});
