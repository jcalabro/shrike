pub mod commit;
pub mod repo;

pub use commit::Commit;
pub use repo::Repo;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum RepoError {
    #[error("record already exists: {0}")]
    RecordExists(String),
    #[error("record not found: {0}")]
    RecordNotFound(String),
    #[error("commit error: {0}")]
    Commit(String),
    #[error("MST error: {0}")]
    Mst(#[from] shrike_mst::MstError),
    #[error("CBOR error: {0}")]
    Cbor(#[from] shrike_cbor::CborError),
    #[error("crypto error: {0}")]
    Crypto(#[from] shrike_crypto::CryptoError),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use shrike_cbor::{Cid, Codec, Encoder, Value};
    use shrike_crypto::SigningKey;
    use shrike_syntax::{Did, Nsid, RecordKey, Tid, TidClock};

    use crate::commit::Commit;
    use crate::repo::Repo;

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    fn make_repo(did_str: &str) -> Repo {
        let did = Did::try_from(did_str).unwrap();
        let clock = TidClock::new(0).unwrap();
        Repo::new(did, clock)
    }

    fn col(s: &str) -> Nsid {
        Nsid::try_from(s).unwrap()
    }

    fn rk(s: &str) -> RecordKey {
        RecordKey::try_from(s).unwrap()
    }

    // A valid DRISL-encoded empty map: 0xa0
    const EMPTY_MAP: &[u8] = b"\xa0";

    // -----------------------------------------------------------------------
    // Original tests (preserved)
    // -----------------------------------------------------------------------

    #[test]
    fn repo_create_and_get() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let collection = col("app.bsky.feed.post");
        let rkey = rk("abc123");
        let record = b"\xa1\x64text\x65hello"; // DRISL: {"text": "hello"}
        let cid = repo.create(&collection, &rkey, record).unwrap();
        let (got_cid, got_data) = repo.get(&collection, &rkey).unwrap().unwrap();
        assert_eq!(cid, got_cid);
        assert_eq!(got_data, record);
    }

    #[test]
    fn repo_create_duplicate_fails() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        let k = rk("abc");
        repo.create(&c, &k, EMPTY_MAP).unwrap();
        assert!(repo.create(&c, &k, EMPTY_MAP).is_err());
    }

    #[test]
    fn repo_update_existing() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        let k = rk("abc");
        repo.create(&c, &k, EMPTY_MAP).unwrap();
        let new_cid = repo.update(&c, &k, b"\xa1\x61v\x01").unwrap();
        let (got_cid, _) = repo.get(&c, &k).unwrap().unwrap();
        assert_eq!(new_cid, got_cid);
    }

    #[test]
    fn repo_update_nonexistent_fails() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        let k = rk("nope");
        assert!(repo.update(&c, &k, EMPTY_MAP).is_err());
    }

    #[test]
    fn repo_delete() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        let k = rk("abc");
        repo.create(&c, &k, EMPTY_MAP).unwrap();
        repo.delete(&c, &k).unwrap();
        assert!(repo.get(&c, &k).unwrap().is_none());
    }

    #[test]
    fn repo_list_collection() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        for key in ["a", "b", "c"] {
            repo.create(&c, &rk(key), EMPTY_MAP).unwrap();
        }
        let entries = repo.list(&c).unwrap();
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].0.as_str(), "a");
    }

    #[test]
    fn commit_sign_and_verify_p256() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let commit = repo.commit(&sk).unwrap();
        commit.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn commit_verify_wrong_key() {
        let sk1 = shrike_crypto::P256SigningKey::generate();
        let sk2 = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let commit = repo.commit(&sk1).unwrap();
        assert!(commit.verify(sk2.public_key()).is_err());
    }

    #[test]
    fn commit_cbor_roundtrip() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let commit = repo.commit(&sk).unwrap();
        let encoded = commit.to_cbor().unwrap();
        let decoded = Commit::from_cbor(&encoded).unwrap();
        assert_eq!(commit.did, decoded.did);
        assert_eq!(commit.version, decoded.version);
        assert_eq!(commit.rev, decoded.rev);
        assert_eq!(commit.data, decoded.data);
        assert_eq!(
            commit.sig.map(|s| *s.as_bytes()),
            decoded.sig.map(|s| *s.as_bytes()),
        );
    }

    // -----------------------------------------------------------------------
    // Commit encoding/decoding edge cases
    // -----------------------------------------------------------------------

    #[test]
    fn commit_cbor_roundtrip_with_prev_cid() {
        // Build a commit whose `prev` field is Some.
        let sk = shrike_crypto::P256SigningKey::generate();
        let prev_cid = Cid::compute(Codec::Drisl, b"previous commit data");
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let rev = Tid::new(1_700_000_000_000_000, 0);
        let data_cid = Cid::compute(Codec::Drisl, b"mst root");

        let mut commit = Commit {
            did,
            version: 3,
            rev,
            prev: Some(prev_cid),
            data: data_cid,
            sig: None,
        };
        commit.sign(&sk).unwrap();

        let encoded = commit.to_cbor().unwrap();
        let decoded = Commit::from_cbor(&encoded).unwrap();

        assert!(decoded.prev.is_some(), "prev should survive round-trip");
        assert_eq!(decoded.prev.unwrap(), prev_cid);
        decoded.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn commit_cbor_roundtrip_with_prev_none() {
        // Build a commit whose `prev` field is None.
        let sk = shrike_crypto::P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let rev = Tid::new(1_700_000_000_000_000, 0);
        let data_cid = Cid::compute(Codec::Drisl, b"mst root");

        let mut commit = Commit {
            did,
            version: 3,
            rev,
            prev: None,
            data: data_cid,
            sig: None,
        };
        commit.sign(&sk).unwrap();

        let encoded = commit.to_cbor().unwrap();
        let decoded = Commit::from_cbor(&encoded).unwrap();

        assert!(
            decoded.prev.is_none(),
            "prev should be None after round-trip"
        );
        decoded.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn commit_from_cbor_with_corrupted_data_errors() {
        // Garbage bytes should fail to decode.
        let result = Commit::from_cbor(b"this is not valid cbor at all!!!!");
        assert!(result.is_err(), "expected error decoding corrupted CBOR");

        // Truncated CBOR should also fail.
        let result2 = Commit::from_cbor(&[0x00]);
        assert!(result2.is_err(), "expected error decoding truncated CBOR");

        // Empty slice should fail.
        let result3 = Commit::from_cbor(b"");
        assert!(result3.is_err(), "expected error decoding empty bytes");
    }

    #[test]
    fn commit_from_cbor_wrong_version_errors() {
        // Manually craft a commit CBOR with version=1 (below the minimum of 2).
        let did_str = "did:plc:test123456789abcdefghij";
        let data_cid = Cid::compute(Codec::Drisl, b"root");
        let rev_str = "2222222222222"; // valid TID string (all '2's = zero)

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // Map with 4 fields: did, version, rev, data (no sig — will be v3 validation, but version=1)
        enc.encode_map_header(5).unwrap();
        enc.encode_text("did").unwrap();
        enc.encode_text(did_str).unwrap();
        enc.encode_text("rev").unwrap();
        enc.encode_text(rev_str).unwrap();
        enc.encode_text("sig").unwrap();
        enc.encode_bytes(&[0u8; 64]).unwrap();
        enc.encode_text("data").unwrap();
        enc.encode_cid(&data_cid).unwrap();
        enc.encode_text("version").unwrap();
        enc.encode_u64(1).unwrap(); // version 1 — unsupported

        let result = Commit::from_cbor(&buf);
        assert!(result.is_err(), "version 1 should be rejected");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("unsupported commit version"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn commit_from_cbor_wrong_high_version_errors() {
        let did_str = "did:plc:test123456789abcdefghij";
        let data_cid = Cid::compute(Codec::Drisl, b"root");

        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_map_header(3).unwrap();
        enc.encode_text("did").unwrap();
        enc.encode_text(did_str).unwrap();
        enc.encode_text("data").unwrap();
        enc.encode_cid(&data_cid).unwrap();
        enc.encode_text("version").unwrap();
        enc.encode_u64(999).unwrap(); // far-future version — unsupported

        let result = Commit::from_cbor(&buf);
        assert!(result.is_err(), "version 999 should be rejected");
        let err_msg = format!("{}", result.err().unwrap());
        assert!(
            err_msg.contains("unsupported commit version"),
            "unexpected error message: {err_msg}"
        );
    }

    #[test]
    fn commit_cbor_is_deterministic() {
        // Encoding the same commit twice must produce identical bytes.
        let sk = shrike_crypto::P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let rev = Tid::new(1_700_000_000_000_000, 0);
        let data_cid = Cid::compute(Codec::Drisl, b"mst root");

        let mut commit = Commit {
            did,
            version: 3,
            rev,
            prev: None,
            data: data_cid,
            sig: None,
        };
        commit.sign(&sk).unwrap();

        let enc1 = commit.to_cbor().unwrap();
        let enc2 = commit.to_cbor().unwrap();
        assert_eq!(enc1, enc2, "commit CBOR encoding must be deterministic");
    }

    #[test]
    fn commit_tamper_did_breaks_signature() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let mut commit = repo.commit(&sk).unwrap();

        // Tamper the DID.
        commit.did = Did::try_from("did:plc:tampered9876543210aaaaa").unwrap();
        assert!(
            commit.verify(sk.public_key()).is_err(),
            "tampered DID should fail verification"
        );
    }

    #[test]
    fn commit_tamper_version_breaks_signature() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let mut commit = repo.commit(&sk).unwrap();

        // Tamper the version.
        commit.version = 2;
        assert!(
            commit.verify(sk.public_key()).is_err(),
            "tampered version should fail verification"
        );
    }

    #[test]
    fn commit_tamper_rev_breaks_signature() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let mut commit = repo.commit(&sk).unwrap();

        // Tamper the rev.
        let orig_ts = commit.rev.timestamp_micros();
        commit.rev = Tid::new(orig_ts + 1_000_000, commit.rev.clock_id());
        assert!(
            commit.verify(sk.public_key()).is_err(),
            "tampered rev should fail verification"
        );
    }

    #[test]
    fn commit_tamper_data_breaks_signature() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let mut commit = repo.commit(&sk).unwrap();

        // Tamper the data CID.
        commit.data = Cid::compute(Codec::Drisl, b"different mst root");
        assert!(
            commit.verify(sk.public_key()).is_err(),
            "tampered data CID should fail verification"
        );
    }

    #[test]
    fn commit_tamper_prev_breaks_signature() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let mut commit = repo.commit(&sk).unwrap();

        // Tamper the prev field (was None, now set to some CID).
        commit.prev = Some(Cid::compute(Codec::Drisl, b"injected prev"));
        assert!(
            commit.verify(sk.public_key()).is_err(),
            "tampered prev should fail verification"
        );
    }

    // -----------------------------------------------------------------------
    // Repo CRUD operations — comprehensive
    // -----------------------------------------------------------------------

    #[test]
    fn repo_create_multiple_collections_isolated() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let posts = col("app.bsky.feed.post");
        let likes = col("app.bsky.feed.like");
        let follows = col("app.bsky.graph.follow");

        let post_data = b"\xa1\x64text\x64post";
        let like_data = b"\xa1\x67subject\x61x";
        let follow_data = b"\xa1\x67subject\x61y";

        let rkey = rk("samekey");

        repo.create(&posts, &rkey, post_data).unwrap();
        repo.create(&likes, &rkey, like_data).unwrap();
        repo.create(&follows, &rkey, follow_data).unwrap();

        // Each collection stores its own data independently.
        let (_, got_post) = repo.get(&posts, &rkey).unwrap().unwrap();
        let (_, got_like) = repo.get(&likes, &rkey).unwrap().unwrap();
        let (_, got_follow) = repo.get(&follows, &rkey).unwrap().unwrap();

        assert_eq!(got_post, post_data);
        assert_eq!(got_like, like_data);
        assert_eq!(got_follow, follow_data);
    }

    #[test]
    fn repo_update_changes_cid() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        let k = rk("mykey");

        let cid_before = repo.create(&c, &k, EMPTY_MAP).unwrap();

        // Record with different content → different CID.
        let new_data = b"\xa1\x61v\x01";
        let cid_after = repo.update(&c, &k, new_data).unwrap();

        assert_ne!(cid_before, cid_after, "update must produce a new CID");

        let (stored_cid, stored_data) = repo.get(&c, &k).unwrap().unwrap();
        assert_eq!(stored_cid, cid_after);
        assert_eq!(stored_data, new_data);
    }

    #[test]
    fn repo_delete_nonexistent_is_idempotent() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");

        // MST's remove() returns Ok(None) for missing keys, so delete
        // on a nonexistent record succeeds silently (idempotent).
        repo.delete(&c, &rk("nonexistent")).unwrap();
    }

    #[test]
    fn repo_get_from_empty_repo_returns_none() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");

        let result = repo.get(&c, &rk("anything")).unwrap();
        assert!(result.is_none(), "get on empty repo should return None");
    }

    #[test]
    fn repo_list_on_empty_collection_returns_empty_vec() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        // Add a record in a different collection so the repo is not completely empty.
        let other = col("com.example.other");
        repo.create(&other, &rk("x"), EMPTY_MAP).unwrap();

        let target = col("app.bsky.feed.post");
        let entries = repo.list(&target).unwrap();
        assert!(
            entries.is_empty(),
            "list on collection with no records should return empty vec"
        );
    }

    #[test]
    fn repo_list_across_collections_only_returns_requested_collection() {
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let posts = col("app.bsky.feed.post");
        let likes = col("app.bsky.feed.like");

        repo.create(&posts, &rk("p1"), EMPTY_MAP).unwrap();
        repo.create(&posts, &rk("p2"), EMPTY_MAP).unwrap();
        repo.create(&likes, &rk("l1"), EMPTY_MAP).unwrap();
        repo.create(&likes, &rk("l2"), EMPTY_MAP).unwrap();
        repo.create(&likes, &rk("l3"), EMPTY_MAP).unwrap();

        let post_list = repo.list(&posts).unwrap();
        assert_eq!(post_list.len(), 2, "should only list posts");
        for (k, _) in &post_list {
            assert!(
                k.as_str().starts_with('p'),
                "unexpected key in post list: {}",
                k.as_str()
            );
        }

        let like_list = repo.list(&likes).unwrap();
        assert_eq!(like_list.len(), 3, "should only list likes");
        for (k, _) in &like_list {
            assert!(
                k.as_str().starts_with('l'),
                "unexpected key in like list: {}",
                k.as_str()
            );
        }
    }

    #[test]
    fn commit_produces_different_rev_each_time() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("r1"), EMPTY_MAP).unwrap();
        let commit1 = repo.commit(&sk).unwrap();

        repo.create(&c, &rk("r2"), EMPTY_MAP).unwrap();
        let commit2 = repo.commit(&sk).unwrap();

        assert_ne!(
            commit1.rev, commit2.rev,
            "each commit must have a strictly increasing TID rev"
        );
        assert!(
            commit2.rev > commit1.rev,
            "rev must be monotonically increasing"
        );
    }

    // -----------------------------------------------------------------------
    // MST key format
    // -----------------------------------------------------------------------

    #[test]
    fn mst_key_format_is_collection_slash_rkey() {
        // Verify that listing returns rkeys (not the full MST key) but the list
        // operation strips the collection prefix correctly — and that a record
        // stored under "app.bsky.feed.post/mykey" is not found under another
        // collection's list.
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let posts = col("app.bsky.feed.post");
        let k = rk("mykey");

        repo.create(&posts, &k, EMPTY_MAP).unwrap();

        let entries = repo.list(&posts).unwrap();
        assert_eq!(entries.len(), 1);
        // The returned key should be just the rkey, not "app.bsky.feed.post/mykey".
        assert_eq!(entries[0].0.as_str(), "mykey");
    }

    #[test]
    fn same_rkey_in_different_collections_are_independent() {
        // Records with the same rkey in different collections must be completely
        // independent — different CIDs and independent lifecycle.
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let posts = col("app.bsky.feed.post");
        let likes = col("app.bsky.feed.like");
        let shared_key = rk("tidabc123");

        let post_data = b"\xa1\x64type\x64post";
        let like_data = b"\xa1\x64type\x64like";

        let cid_post = repo.create(&posts, &shared_key, post_data).unwrap();
        let cid_like = repo.create(&likes, &shared_key, like_data).unwrap();

        // CIDs must differ because content differs.
        assert_ne!(cid_post, cid_like);

        // Both must be independently retrievable.
        let (_, got_post) = repo.get(&posts, &shared_key).unwrap().unwrap();
        let (_, got_like) = repo.get(&likes, &shared_key).unwrap().unwrap();
        assert_eq!(got_post, post_data);
        assert_eq!(got_like, like_data);

        // Deleting from one collection must not affect the other.
        repo.delete(&posts, &shared_key).unwrap();
        assert!(repo.get(&posts, &shared_key).unwrap().is_none());
        assert!(repo.get(&likes, &shared_key).unwrap().is_some());
    }

    // -----------------------------------------------------------------------
    // Roundtrip integrity
    // -----------------------------------------------------------------------

    #[test]
    fn roundtrip_create_commit_encode_decode_verify() {
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let posts = col("app.bsky.feed.post");
        let likes = col("app.bsky.feed.like");

        repo.create(&posts, &rk("p1"), b"\xa1\x64text\x62hi")
            .unwrap();
        repo.create(&posts, &rk("p2"), b"\xa1\x64text\x62yo")
            .unwrap();
        repo.create(&likes, &rk("l1"), b"\xa1\x67subject\x62ok")
            .unwrap();

        // Produce a signed commit.
        let commit = repo.commit(&sk).unwrap();

        // Commit should verify immediately.
        commit.verify(sk.public_key()).unwrap();

        // Encode to CBOR.
        let cbor_bytes = commit.to_cbor().unwrap();

        // Decode back from CBOR.
        let decoded = Commit::from_cbor(&cbor_bytes).unwrap();

        // All fields must match.
        assert_eq!(commit.did, decoded.did);
        assert_eq!(commit.version, decoded.version);
        assert_eq!(commit.rev, decoded.rev);
        assert_eq!(commit.data, decoded.data);
        assert_eq!(
            commit.sig.map(|s| *s.as_bytes()),
            decoded.sig.map(|s| *s.as_bytes()),
        );
        assert_eq!(commit.prev, decoded.prev);

        // The decoded commit must also pass signature verification.
        decoded.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn roundtrip_with_k256_key() {
        let sk = shrike_crypto::K256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();

        let commit = repo.commit(&sk).unwrap();
        commit.verify(sk.public_key()).unwrap();

        let cbor_bytes = commit.to_cbor().unwrap();
        let decoded = Commit::from_cbor(&cbor_bytes).unwrap();
        decoded.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn roundtrip_commit_prev_cid_chain() {
        // Simulate two commits where the second references the first as prev.
        let sk = shrike_crypto::P256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");

        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("first"), EMPTY_MAP).unwrap();
        let commit1 = repo.commit(&sk).unwrap();

        // After commit1, the repo's prev_commit is set internally.
        repo.create(&c, &rk("second"), EMPTY_MAP).unwrap();
        let commit2 = repo.commit(&sk).unwrap();

        // commit2 should reference commit1 as its prev.
        assert!(commit2.prev.is_some(), "second commit must have a prev CID");

        // Both commits must verify individually.
        commit1.verify(sk.public_key()).unwrap();
        commit2.verify(sk.public_key()).unwrap();

        // Roundtrip commit2 through CBOR and verify again.
        let cbor = commit2.to_cbor().unwrap();
        let decoded2 = Commit::from_cbor(&cbor).unwrap();
        assert!(decoded2.prev.is_some());
        decoded2.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn commit_sign_and_verify_k256() {
        let sk = shrike_crypto::K256SigningKey::generate();
        let mut repo = make_repo("did:plc:test123456789abcdefghij");
        let c = col("app.bsky.feed.post");
        repo.create(&c, &rk("a"), EMPTY_MAP).unwrap();
        let commit = repo.commit(&sk).unwrap();
        commit.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn unsigned_bytes_exclude_sig_field() {
        // unsigned_bytes() must not contain the signature so that sign/verify works
        // correctly even after the sig is populated.
        let sk = shrike_crypto::P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let rev = Tid::new(1_700_000_000_000_000, 7);
        let data_cid = Cid::compute(Codec::Drisl, b"mst root bytes");

        let mut commit = Commit {
            did,
            version: 3,
            rev,
            prev: None,
            data: data_cid,
            sig: None,
        };

        let unsigned_before = commit.unsigned_bytes().unwrap();
        commit.sign(&sk).unwrap();
        let unsigned_after = commit.unsigned_bytes().unwrap();

        assert_eq!(
            unsigned_before, unsigned_after,
            "unsigned_bytes must be identical before and after signing"
        );
    }

    // --- V2 commit tests ---

    #[test]
    fn v2_commit_decodes_without_rev_and_sig() {
        // Build a v2 commit CBOR with no rev and no sig fields.
        let data_cid = Cid::compute(Codec::Drisl, b"data");
        let val = Value::Map(vec![
            ("did", Value::Text("did:plc:test123456789abcdefghij")),
            ("data", Value::Cid(data_cid)),
            ("prev", Value::Null),
            ("version", Value::Unsigned(2)),
        ]);
        let encoded = shrike_cbor::encode_value(&val).unwrap();
        let commit = Commit::from_cbor(&encoded).unwrap();

        assert_eq!(commit.version, 2);
        assert_eq!(commit.did.as_str(), "did:plc:test123456789abcdefghij");
        assert_eq!(commit.data, data_cid);
        assert!(commit.sig.is_none(), "v2 commit without sig should be None");
        // rev defaults to epoch
        assert_eq!(commit.rev.as_u64(), 0);
    }

    #[test]
    fn v2_commit_verify_returns_error() {
        // V2 commits with no signature cannot be verified.
        let data_cid = Cid::compute(Codec::Drisl, b"data");
        let val = Value::Map(vec![
            ("did", Value::Text("did:plc:test123456789abcdefghij")),
            ("data", Value::Cid(data_cid)),
            ("prev", Value::Null),
            ("version", Value::Unsigned(2)),
        ]);
        let encoded = shrike_cbor::encode_value(&val).unwrap();
        let commit = Commit::from_cbor(&encoded).unwrap();

        let sk = shrike_crypto::P256SigningKey::generate();
        let result = commit.verify(sk.public_key());
        assert!(result.is_err(), "verify on unsigned v2 commit should fail");
    }

    #[test]
    fn v2_commit_with_sig_can_be_verified() {
        // V2 commit that does have a signature should verify.
        let sk = shrike_crypto::P256SigningKey::generate();
        let data_cid = Cid::compute(Codec::Drisl, b"data");
        let rev = Tid::try_from("2222222222222").unwrap();

        let mut commit = Commit {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            version: 2,
            rev,
            prev: None,
            data: data_cid,
            sig: None,
        };
        commit.sign(&sk).unwrap();
        assert!(commit.sig.is_some());

        commit.verify(sk.public_key()).unwrap();
    }

    #[test]
    fn v3_commit_missing_sig_rejected() {
        let data_cid = Cid::compute(Codec::Drisl, b"data");
        let val = Value::Map(vec![
            ("did", Value::Text("did:plc:test123456789abcdefghij")),
            ("rev", Value::Text("2222222222222")),
            ("data", Value::Cid(data_cid)),
            ("prev", Value::Null),
            ("version", Value::Unsigned(3)),
        ]);
        let encoded = shrike_cbor::encode_value(&val).unwrap();
        let result = Commit::from_cbor(&encoded);
        assert!(result.is_err(), "v3 commit without sig should be rejected");
    }

    #[test]
    fn v3_commit_missing_rev_rejected() {
        let data_cid = Cid::compute(Codec::Drisl, b"data");
        let val = Value::Map(vec![
            ("did", Value::Text("did:plc:test123456789abcdefghij")),
            ("sig", Value::Bytes(&[0xAB; 64])),
            ("data", Value::Cid(data_cid)),
            ("prev", Value::Null),
            ("version", Value::Unsigned(3)),
        ]);
        let encoded = shrike_cbor::encode_value(&val).unwrap();
        let result = Commit::from_cbor(&encoded);
        assert!(result.is_err(), "v3 commit without rev should be rejected");
    }

    #[test]
    fn commit_cbor_roundtrip_v2_with_sig() {
        // V2 commit with signature should roundtrip through CBOR.
        let sk = shrike_crypto::P256SigningKey::generate();
        let data_cid = Cid::compute(Codec::Drisl, b"v2 data");
        let rev = Tid::try_from("2222222222222").unwrap();

        let mut commit = Commit {
            did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
            version: 2,
            rev,
            prev: None,
            data: data_cid,
            sig: None,
        };
        commit.sign(&sk).unwrap();

        let encoded = commit.to_cbor().unwrap();
        let decoded = Commit::from_cbor(&encoded).unwrap();
        assert_eq!(decoded.version, 2);
        assert_eq!(decoded.did, commit.did);
        assert_eq!(decoded.data, commit.data);
        assert!(decoded.sig.is_some());

        // Verify the decoded commit
        decoded.verify(sk.public_key()).unwrap();
    }
}
