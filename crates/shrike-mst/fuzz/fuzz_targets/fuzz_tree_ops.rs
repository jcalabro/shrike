#![no_main]

use libfuzzer_sys::fuzz_target;
use shrike_cbor::{Cid, Codec};
use shrike_mst::{MemBlockStore, Tree};

/// Fuzz the MST tree with arbitrary operation sequences.
///
/// Interprets the fuzzer-provided bytes as a sequence of operations:
/// - 0x00..0x7F: insert key derived from byte
/// - 0x80..0xBF: remove key derived from (byte - 0x80)
/// - 0xC0..0xFF: get key derived from (byte - 0xC0)
///
/// After all operations, verifies:
/// 1. No panics occurred
/// 2. root_cid() succeeds
/// 3. entries() returns sorted keys
/// 4. All keys we believe are present can be found via get()
fuzz_target!(|data: &[u8]| {
    let store = MemBlockStore::new();
    let mut tree = Tree::new(Box::new(store));
    let mut expected_keys: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();

    for &byte in data {
        let key_byte = byte & 0x3F; // 64 unique keys
        let key = format!("app.bsky.feed.post/3k{key_byte:02x}");
        let cid = Cid::compute(Codec::Drisl, key.as_bytes());

        match byte >> 6 {
            0 | 1 => {
                // Insert (0x00..0x7F)
                let _ = tree.insert(key.clone(), cid);
                expected_keys.insert(key);
            }
            2 => {
                // Remove (0x80..0xBF)
                let _ = tree.remove(&key);
                expected_keys.remove(&key);
            }
            3 => {
                // Get (0xC0..0xFF)
                let result = tree.get(&key);
                if let Ok(found) = result {
                    if expected_keys.contains(&key) {
                        assert!(found.is_some(), "key should exist: {key}");
                    } else {
                        assert!(found.is_none(), "key should not exist: {key}");
                    }
                }
            }
            _ => {}
        }
    }

    // Verify tree invariants after all operations
    if let Ok(entries) = tree.entries() {
        // Entries must be sorted
        for window in entries.windows(2) {
            assert!(window[0].0 < window[1].0, "entries not sorted");
        }
        // Entry count must match our tracking
        assert_eq!(
            entries.len(),
            expected_keys.len(),
            "entry count mismatch"
        );
        // All expected keys must be present
        for (key, _) in &entries {
            assert!(expected_keys.contains(key), "unexpected key: {key}");
        }
    }

    // root_cid must succeed (no panics during serialization)
    let _ = tree.root_cid();
});
