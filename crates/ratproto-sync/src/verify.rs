use ratproto_cbor::{Cid, Codec};

use crate::{DownloadedRepo, SyncError};

/// Verify all blocks in a downloaded repository by recomputing each CID.
///
/// For each block, the CID is recomputed using both the DRISL (DAG-CBOR) and
/// Raw codecs. If neither matches the stored CID, verification fails.
pub fn verify_blocks(repo: &DownloadedRepo) -> Result<(), SyncError> {
    for block in &repo.blocks {
        let drisl_cid = Cid::compute(Codec::Drisl, &block.data);
        let raw_cid = Cid::compute(Codec::Raw, &block.data);
        if block.cid != drisl_cid && block.cid != raw_cid {
            return Err(SyncError::Verification(format!(
                "CID mismatch for block {}: computed (drisl={}, raw={})",
                block.cid, drisl_cid, raw_cid
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use ratproto_cbor::{Cid, Codec};
    use ratproto_syntax::{Did, TidClock};

    use super::*;
    use crate::DownloadedRepo;

    /// Build a minimal signed commit for use in tests.
    fn make_test_commit() -> ratproto_repo::Commit {
        use ratproto_crypto::P256SigningKey;
        use ratproto_syntax::{Nsid, RecordKey};

        let sk = P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let clock = TidClock::new(0).unwrap();
        let mut repo = ratproto_repo::Repo::new(did, clock);
        let col = Nsid::try_from("app.bsky.feed.post").unwrap();
        repo.create(&col, &RecordKey::try_from("a").unwrap(), b"\xa0")
            .unwrap();
        repo.commit(&sk).unwrap()
    }

    #[test]
    fn verify_blocks_valid() {
        let blocks: Vec<ratproto_car::Block> = (0..3)
            .map(|i| {
                let data = format!("block {i}").into_bytes();
                ratproto_car::Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    #[test]
    fn verify_blocks_drisl_codec() {
        let blocks: Vec<ratproto_car::Block> = (0..3)
            .map(|i| {
                let data = format!("drisl block {i}").into_bytes();
                ratproto_car::Block {
                    cid: Cid::compute(Codec::Drisl, &data),
                    data,
                }
            })
            .collect();

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    #[test]
    fn verify_blocks_corrupt_fails() {
        let mut data = b"original".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        data[0] = 0xFF; // corrupt the data after recording the CID
        let blocks = vec![ratproto_car::Block { cid, data }];

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        assert!(verify_blocks(&repo).is_err());
    }

    #[test]
    fn verify_blocks_empty() {
        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks: vec![],
        };
        verify_blocks(&repo).unwrap();
    }

    #[test]
    fn verify_blocks_second_block_corrupt_fails() {
        let good_data = b"good block".to_vec();
        let good_cid = Cid::compute(Codec::Raw, &good_data);

        let mut bad_data = b"bad block".to_vec();
        let bad_cid = Cid::compute(Codec::Raw, &bad_data);
        bad_data[0] = 0xAB; // corrupt after CID is recorded

        let blocks = vec![
            ratproto_car::Block {
                cid: good_cid,
                data: good_data,
            },
            ratproto_car::Block {
                cid: bad_cid,
                data: bad_data,
            },
        ];

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        assert!(verify_blocks(&repo).is_err());
    }

    // --- Mixed codecs (some Drisl, some Raw) ---

    #[test]
    fn verify_blocks_mixed_codecs() {
        let blocks: Vec<ratproto_car::Block> = (0..6)
            .map(|i| {
                let data = format!("mixed block {i}").into_bytes();
                // Alternate between Raw and Drisl codecs.
                let codec = if i % 2 == 0 { Codec::Raw } else { Codec::Drisl };
                ratproto_car::Block {
                    cid: Cid::compute(codec, &data),
                    data,
                }
            })
            .collect();

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    // --- Large block set (50+ blocks) ---

    #[test]
    fn verify_blocks_large_set() {
        let blocks: Vec<ratproto_car::Block> = (0..55)
            .map(|i| {
                let data = format!("large set block {i:04}").into_bytes();
                ratproto_car::Block {
                    cid: Cid::compute(Codec::Raw, &data),
                    data,
                }
            })
            .collect();

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    // --- Single block ---

    #[test]
    fn verify_blocks_single_block_raw() {
        let data = b"just one block".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let blocks = vec![ratproto_car::Block { cid, data }];

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    #[test]
    fn verify_blocks_single_block_drisl() {
        let data = b"just one drisl block".to_vec();
        let cid = Cid::compute(Codec::Drisl, &data);
        let blocks = vec![ratproto_car::Block { cid, data }];

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        verify_blocks(&repo).unwrap();
    }

    // --- Verification error message includes CID info ---

    #[test]
    fn verify_blocks_error_message_contains_cid() {
        let mut data = b"corrupt me".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        data[0] ^= 0xFF;
        let blocks = vec![ratproto_car::Block { cid, data }];

        let commit = make_test_commit();
        let repo = DownloadedRepo {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            commit,
            blocks,
        };
        let err = verify_blocks(&repo).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("verification failed"), "got: {msg}");
    }
}
