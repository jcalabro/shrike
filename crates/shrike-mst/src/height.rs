use sha2::{Digest, Sha256};

/// Compute the MST height for a given key.
///
/// SHA-256 hashes the key, then counts leading zero 2-bit pairs.
#[inline]
pub fn height_for_key(key: &str) -> u8 {
    let hash: [u8; 32] = Sha256::digest(key.as_bytes()).into();
    height_from_hash(&hash)
}

/// Count leading zero 2-bit pairs in a 32-byte hash.
///
/// Processes 8 bytes at a time as a big-endian u64, using leading_zeros()
/// to efficiently count. Each byte has 4 two-bit pairs, so after i zero
/// bytes the base count is i*4.
#[inline]
fn height_from_hash(h: &[u8; 32]) -> u8 {
    for i in (0..32).step_by(8) {
        let word = u64::from_be_bytes([
            h[i],
            h[i + 1],
            h[i + 2],
            h[i + 3],
            h[i + 4],
            h[i + 5],
            h[i + 6],
            h[i + 7],
        ]);
        if word == 0 {
            continue;
        }
        return (i as u8) * 4 + (word.leading_zeros() as u8) / 2;
    }
    128 // all zeros
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    #[test]
    fn height_for_key_interop() {
        // All 9 vectors from atproto-interop-tests/mst/key_heights.json.
        let tests: &[(&str, u8)] = &[
            ("", 0),
            ("asdf", 0),
            ("blue", 1),
            ("2653ae71", 0),
            ("88bfafc7", 2),
            ("2a92d355", 4),
            ("884976f5", 6),
            ("app.bsky.feed.post/454397e440ec", 4),
            ("app.bsky.feed.post/9adeb165882c", 8),
        ];
        for &(key, expected) in tests {
            assert_eq!(height_for_key(key), expected, "height_for_key({key:?})");
        }
    }

    #[test]
    fn height_for_key_additional() {
        // Additional vectors
        assert_eq!(height_for_key("2653ae71"), 0);
        assert_eq!(height_for_key("blue"), 1);
    }

    #[test]
    fn height_from_hash_multi_word_zeros() {
        // Reference: count leading zero 2-bit pairs byte-by-byte.
        fn ref_height(h: &[u8; 32]) -> u8 {
            let mut count: u8 = 0;
            for &b in h {
                if b < 64 {
                    count += 1;
                }
                if b < 16 {
                    count += 1;
                }
                if b < 4 {
                    count += 1;
                }
                if b == 0 {
                    count += 1;
                } else {
                    break;
                }
            }
            count
        }

        let tests: &[(&str, [u8; 32], u8)] = &[
            (
                "no leading zeros",
                {
                    let mut h = [0u8; 32];
                    h[0] = 0xFF;
                    h
                },
                0,
            ),
            (
                "one zero byte then 0x01",
                {
                    let mut h = [0u8; 32];
                    h[1] = 0x01;
                    h
                },
                7,
            ), // 4 pairs from zero byte + 3 pairs from 0x01
            (
                "8 zero bytes then 0x01",
                {
                    let mut h = [0u8; 32];
                    h[8] = 0x01;
                    h
                },
                35,
            ), // 32 pairs from 8 zero bytes + 3 from 0x01
            (
                "8 zero bytes then 0x30",
                {
                    let mut h = [0u8; 32];
                    h[8] = 0x30;
                    h
                },
                33,
            ), // 32 + 1
            (
                "16 zero bytes then 0x01",
                {
                    let mut h = [0u8; 32];
                    h[16] = 0x01;
                    h
                },
                67,
            ), // 64 + 3
            (
                "24 zero bytes then 0xFF",
                {
                    let mut h = [0u8; 32];
                    h[24] = 0xFF;
                    h
                },
                96,
            ), // 24*4 + 0
            ("all zeros", [0u8; 32], 128),
        ];

        for (name, hash, expected) in tests {
            let got = height_from_hash(hash);
            let reference = ref_height(hash);
            assert_eq!(got, *expected, "{name}: height_from_hash mismatch");
            assert_eq!(
                reference, got,
                "{name}: height_from_hash disagrees with reference"
            );
        }
    }

    #[test]
    fn height_deterministic() {
        for key in ["", "blue", "com.example.record/3jqfcqzm3fo2j"] {
            let h1 = height_for_key(key);
            let h2 = height_for_key(key);
            assert_eq!(h1, h2, "non-deterministic height for {key:?}");
        }
    }

    #[test]
    fn commit_proof_fixture_keys() {
        let keys = [
            ("A0/374913", 0u8),
            ("B1/986427", 1),
            ("C0/451630", 0),
            ("D2/269196", 2),
            ("E0/670489", 0),
            ("F1/085263", 1),
            ("G0/765327", 0),
            ("C2/014073", 2),
            ("B2/827649", 2),
            ("E2/819540", 2),
            ("H0/131238", 0),
            ("A2/827942", 2),
            ("G2/611528", 2),
            ("R2/742766", 2),
        ];
        for (key, expected) in keys {
            assert_eq!(height_for_key(key), expected, "height_for_key({key:?})");
        }
    }
}
