#![no_main]
//! Feed arbitrary bytes through the MST load + traverse path
//! (`Tree::load` → `entries`/`get`), which reconstructs entry keys from
//! prefix-compressed data. Unlike decoding alone, this exercises the
//! prefix-length reslice and key-order checks that a malformed block could
//! otherwise panic on (the H2/H3/H4 hardening). It must never panic — only
//! error or return data.

use libfuzzer_sys::fuzz_target;
use shrike::Cid;
use shrike::cbor::Codec;
use shrike::mst::{MemBlockStore, Tree, block_store::BlockStore};

fuzz_target!(|data: &[u8]| {
    // Store the arbitrary bytes under their own (content-addressed) CID and
    // load a tree rooted there.
    let store = MemBlockStore::new();
    let root = Cid::compute(Codec::Drisl, data);
    if store.put_block(root, data.to_vec()).is_err() {
        return;
    }
    let mut tree = Tree::load(Box::new(store), root);

    // Both traversal entry points must be panic-free regardless of contents.
    let _ = tree.entries();
    let _ = tree.get("app.bsky.feed.post/aaaaaaaaaaaaa");
});
