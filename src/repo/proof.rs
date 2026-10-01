//! Record proofs, as served by `com.atproto.sync.getRecord`.
//!
//! A record proof is a CAR file whose single root is a signed commit. It
//! carries the MST nodes on the search path for one record key, and the
//! record block itself when the record exists. Verifying it proves that the
//! repository's signing key committed to that record (or to its absence)
//! without trusting the server that sent it.

use std::borrow::Cow;
use std::cell::RefCell;
use std::collections::HashMap;

use crate::car::{Block, CarError, Reader};
use crate::cbor::{Cid, Codec};
use crate::crypto::VerifyingKey;
use crate::mst::{BlockSource, DetachedTree, MstError};
use crate::repo::RepoError;
use crate::repo::commit::Commit;
use crate::repo::repo::mst_key;
use crate::syntax::{Did, Nsid, RecordKey};

/// Errors from building or verifying a record proof.
#[derive(Debug, thiserror::Error)]
pub enum ProofError {
    #[error("malformed proof CAR: {0}")]
    Car(#[from] CarError),
    #[error("proof CAR must have exactly one root, found {0}")]
    RootCount(usize),
    #[error("block {0} does not match its CID")]
    CidMismatch(Cid),
    #[error("block {0} missing from proof")]
    MissingBlock(Cid),
    #[error("invalid commit: {0}")]
    InvalidCommit(#[source] RepoError),
    #[error("proof commit is for {found}, expected {expected}")]
    DidMismatch { expected: Did, found: Did },
    #[error("invalid commit signature: {0}")]
    InvalidSignature(#[source] RepoError),
    #[error("invalid MST in proof: {0}")]
    Mst(#[from] MstError),
    #[error("block {0} is not DRISL")]
    NotDrisl(Cid),
    #[error("repository has no commit")]
    NoCommit,
}

/// A verified record proof.
#[derive(Debug, Clone)]
pub struct RecordProof {
    /// The signed commit at the proof's root.
    pub commit: Commit,
    /// CID of the commit block.
    pub commit_cid: Cid,
    /// The record's CID and DRISL bytes, or `None` if the proof shows the
    /// record does not exist at that commit.
    pub record: Option<(Cid, Vec<u8>)>,
}

/// Verify a record proof CAR for `collection/rkey` in `did`'s repository.
///
/// Every block is hashed against its CID, the root commit must belong to
/// `did` and carry a valid signature from `key`, and the record is looked up
/// through the MST nodes in the proof. A node missing from the search path is
/// an error, never a "not found". Blocks the lookup does not need are ignored.
pub fn verify_record_proof(
    car: &[u8],
    did: &Did,
    key: &dyn VerifyingKey,
    collection: &Nsid,
    rkey: &RecordKey,
) -> Result<RecordProof, ProofError> {
    let mut reader = Reader::new(car)?;
    let commit_cid = match reader.roots() {
        [root] => *root,
        roots => return Err(ProofError::RootCount(roots.len())),
    };

    let mut blocks: HashMap<Cid, Vec<u8>> = HashMap::new();
    let mut block = Block::default();
    while reader.next_block_into(&mut block)? {
        if Cid::compute(block.cid.codec(), &block.data) != block.cid {
            return Err(ProofError::CidMismatch(block.cid));
        }
        blocks
            .entry(block.cid)
            .or_insert_with(|| std::mem::take(&mut block.data));
    }

    let commit_bytes = drisl_block(&blocks, &commit_cid)?;
    let commit = Commit::from_cbor(commit_bytes).map_err(ProofError::InvalidCommit)?;
    if commit.did != *did {
        return Err(ProofError::DidMismatch {
            expected: did.clone(),
            found: commit.did,
        });
    }
    commit.verify(key).map_err(ProofError::InvalidSignature)?;

    let mut tree = DetachedTree::load(commit.data);
    let record = match tree.get(&blocks, &mst_key(collection, rkey))? {
        None => None,
        Some(cid) => Some((cid, drisl_block(&blocks, &cid)?.to_vec())),
    };

    Ok(RecordProof {
        commit,
        commit_cid,
        record,
    })
}

/// Build the record proof CAR for `collection/rkey` at the commit
/// `commit_cid`, reading blocks from `src`.
///
/// The CAR holds the commit, the MST nodes on the key's search path, and the
/// record block if the record exists, which is what the reference PDS serves
/// from `com.atproto.sync.getRecord`. A proof for an absent key shows its
/// absence.
pub fn record_proof_car(
    src: &dyn BlockSource,
    commit_cid: &Cid,
    collection: &Nsid,
    rkey: &RecordKey,
) -> Result<Vec<u8>, ProofError> {
    let read = |cid: &Cid| -> Result<Vec<u8>, ProofError> {
        src.read_block(cid)?
            .map(Cow::into_owned)
            .ok_or(ProofError::MissingBlock(*cid))
    };

    let commit_bytes = read(commit_cid)?;
    let commit = Commit::from_cbor(&commit_bytes).map_err(ProofError::InvalidCommit)?;

    let recorder = Recorder {
        src,
        seen: RefCell::new(Vec::new()),
    };
    let mut tree = DetachedTree::load(commit.data);
    let found = tree.get(&recorder, &mst_key(collection, rkey))?;

    let mut blocks = vec![Block {
        cid: *commit_cid,
        data: commit_bytes,
    }];
    blocks.extend(
        recorder
            .seen
            .into_inner()
            .into_iter()
            .map(|(cid, data)| Block { cid, data }),
    );
    if let Some(cid) = found {
        blocks.push(Block {
            data: read(&cid)?,
            cid,
        });
    }
    Ok(crate::car::write_all(&[*commit_cid], &blocks)?)
}

/// Look up a block that must be present and DRISL-encoded.
fn drisl_block<'a>(blocks: &'a HashMap<Cid, Vec<u8>>, cid: &Cid) -> Result<&'a [u8], ProofError> {
    if cid.codec() != Codec::Drisl {
        return Err(ProofError::NotDrisl(*cid));
    }
    blocks
        .get(cid)
        .map(Vec::as_slice)
        .ok_or(ProofError::MissingBlock(*cid))
}

/// A [`BlockSource`] that remembers every block it hands out, in order.
struct Recorder<'a> {
    src: &'a dyn BlockSource,
    seen: RefCell<Vec<(Cid, Vec<u8>)>>,
}

impl BlockSource for Recorder<'_> {
    fn read_block(&self, cid: &Cid) -> Result<Option<Cow<'_, [u8]>>, MstError> {
        let Some(data) = self.src.read_block(cid)? else {
            return Ok(None);
        };
        let data = data.into_owned();
        self.seen.borrow_mut().push((*cid, data.clone()));
        Ok(Some(Cow::Owned(data)))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::car::{read_all, write_all};
    use crate::cbor::Codec;
    use crate::crypto::{K256SigningKey, P256SigningKey, SigningKey};
    use crate::repo::Repo;
    use crate::syntax::TidClock;

    const DID: &str = "did:plc:proofproofproofproofproo";

    fn did() -> Did {
        Did::try_from(DID).unwrap()
    }

    fn col(s: &str) -> Nsid {
        Nsid::try_from(s).unwrap()
    }

    fn rk(s: &str) -> RecordKey {
        RecordKey::try_from(s).unwrap()
    }

    /// DRISL `{"n": i}`.
    fn record(i: u8) -> Vec<u8> {
        let mut v = b"\xa1\x61n".to_vec();
        if i < 24 {
            v.push(i);
        } else {
            v.extend_from_slice(&[0x18, i]);
        }
        v
    }

    /// A repo with `n` records spread over two collections, committed.
    fn filled_repo(n: u8, key: &dyn SigningKey) -> Repo {
        let mut repo = Repo::new(did(), TidClock::new(0).unwrap());
        for i in 0..n {
            let c = if i % 2 == 0 {
                "com.example.even"
            } else {
                "com.example.odd"
            };
            repo.create(&col(c), &rk(&format!("rec{i:03}")), &record(i))
                .unwrap();
        }
        repo.commit(key).unwrap();
        repo
    }

    fn proof(repo: &Repo, c: &str, k: &str) -> Vec<u8> {
        repo.record_proof(&col(c), &rk(k)).unwrap()
    }

    fn verify(
        car: &[u8],
        key: &dyn SigningKey,
        c: &str,
        k: &str,
    ) -> Result<RecordProof, ProofError> {
        verify_record_proof(car, &did(), key.public_key(), &col(c), &rk(k))
    }

    /// Rewrite a proof CAR with `edit` applied to its (roots, blocks).
    fn rewrite(car: &[u8], edit: impl FnOnce(&mut Vec<Cid>, &mut Vec<Block>)) -> Vec<u8> {
        let (mut roots, mut blocks) = read_all(car).unwrap();
        edit(&mut roots, &mut blocks);
        write_all(&roots, &blocks).unwrap()
    }

    #[test]
    fn every_record_verifies_with_both_key_types() {
        let keys: [Box<dyn SigningKey>; 2] = [
            Box::new(P256SigningKey::generate()),
            Box::new(K256SigningKey::generate()),
        ];
        for key in &keys {
            let mut repo = filled_repo(60, key.as_ref());
            for i in 0..60u8 {
                let c = if i % 2 == 0 {
                    "com.example.even"
                } else {
                    "com.example.odd"
                };
                let k = format!("rec{i:03}");
                let got = verify(&proof(&repo, c, &k), key.as_ref(), c, &k).unwrap();
                let (cid, bytes) = got.record.unwrap();
                assert_eq!(bytes, record(i));
                assert_eq!(Some((cid, bytes)), repo.get(&col(c), &rk(&k)).unwrap());
                assert_eq!(got.commit.did, did());
            }
        }
    }

    #[test]
    fn proof_is_minimal() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(200, &key);
        let (roots, blocks) = read_all(&proof(&repo, "com.example.even", "rec100")[..]).unwrap();
        assert_eq!(roots.len(), 1);
        assert_eq!(blocks[0].cid, roots[0], "commit block comes first");
        // Commit + a short MST path + the record: nowhere near the whole repo.
        assert!(blocks.len() < 10, "proof has {} blocks", blocks.len());
    }

    #[test]
    fn absent_record_proves_nonexistence() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(40, &key);
        for k in ["rec000a", "aaaa", "zzzz", "rec017"] {
            let got = verify(
                &proof(&repo, "com.example.even", k),
                &key,
                "com.example.even",
                k,
            )
            .unwrap();
            assert!(got.record.is_none(), "{k} should be absent");
        }
        // An empty repository proves every key absent.
        let mut empty = Repo::new(did(), TidClock::new(0).unwrap());
        empty.commit(&key).unwrap();
        let got = verify(
            &proof(&empty, "com.example.even", "x"),
            &key,
            "com.example.even",
            "x",
        )
        .unwrap();
        assert!(got.record.is_none());
    }

    #[test]
    fn proof_for_one_key_does_not_prove_another() {
        // A proof only carries one search path: using it for a key in another
        // part of the tree must fail on a missing node, not report "absent".
        let key = P256SigningKey::generate();
        let repo = filled_repo(200, &key);
        let car = proof(&repo, "com.example.even", "rec000");
        let err = verify(&car, &key, "com.example.odd", "rec199").unwrap_err();
        assert!(
            matches!(err, ProofError::Mst(MstError::BlockNotFound(_))),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_signing_key() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(10, &key);
        let car = proof(&repo, "com.example.even", "rec000");
        let other = P256SigningKey::generate();
        let err = verify(&car, &other, "com.example.even", "rec000").unwrap_err();
        assert!(
            matches!(err, ProofError::InvalidSignature(_)),
            "got {err:?}"
        );
        let other = K256SigningKey::generate();
        let err = verify(&car, &other, "com.example.even", "rec000").unwrap_err();
        assert!(
            matches!(err, ProofError::InvalidSignature(_)),
            "got {err:?}"
        );
    }

    #[test]
    fn rejects_wrong_did() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(10, &key);
        let car = proof(&repo, "com.example.even", "rec000");
        let other = Did::try_from("did:plc:someoneelseentirely000").unwrap();
        let err = verify_record_proof(
            &car,
            &other,
            key.public_key(),
            &col("com.example.even"),
            &rk("rec000"),
        )
        .unwrap_err();
        assert!(matches!(err, ProofError::DidMismatch { .. }), "got {err:?}");
    }

    #[test]
    fn rejects_tampered_block_data() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(30, &key);
        let car = proof(&repo, "com.example.even", "rec004");
        let n = read_all(&car[..]).unwrap().1.len();
        // Tamper with every block in turn: commit, each MST node, the record.
        for i in 0..n {
            let bad = rewrite(&car, |_, blocks| {
                let last = blocks[i].data.len() - 1;
                blocks[i].data[last] ^= 0x01;
            });
            let err = verify(&bad, &key, "com.example.even", "rec004").unwrap_err();
            assert!(
                matches!(err, ProofError::CidMismatch(_)),
                "block {i}: {err:?}"
            );
        }
    }

    #[test]
    fn rejects_missing_blocks() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(30, &key);
        let car = proof(&repo, "com.example.even", "rec004");
        let n = read_all(&car[..]).unwrap().1.len();
        for i in 0..n {
            let bad = rewrite(&car, |_, blocks| {
                blocks.remove(i);
            });
            let err = verify(&bad, &key, "com.example.even", "rec004").unwrap_err();
            let expected = if i == 0 || i == n - 1 {
                matches!(err, ProofError::MissingBlock(_))
            } else {
                matches!(err, ProofError::Mst(MstError::BlockNotFound(_)))
            };
            assert!(expected, "removing block {i} of {n}: {err:?}");
        }
    }

    #[test]
    fn rejects_bad_roots() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(5, &key);
        let car = proof(&repo, "com.example.even", "rec000");

        let none = rewrite(&car, |roots, _| roots.clear());
        assert!(matches!(
            verify(&none, &key, "com.example.even", "rec000"),
            Err(ProofError::RootCount(0))
        ));

        let two = rewrite(&car, |roots, _| roots.push(roots[0]));
        assert!(matches!(
            verify(&two, &key, "com.example.even", "rec000"),
            Err(ProofError::RootCount(2))
        ));

        let elsewhere = rewrite(&car, |roots, _| roots[0] = Cid::compute(Codec::Drisl, b"x"));
        assert!(matches!(
            verify(&elsewhere, &key, "com.example.even", "rec000"),
            Err(ProofError::MissingBlock(_))
        ));

        // A root that points at the record rather than a commit.
        let at_record = rewrite(&car, |roots, blocks| roots[0] = blocks.last().unwrap().cid);
        assert!(matches!(
            verify(&at_record, &key, "com.example.even", "rec000"),
            Err(ProofError::InvalidCommit(_))
        ));
    }

    #[test]
    fn rejects_raw_codec_commit_and_record() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(5, &key);
        let car = proof(&repo, "com.example.even", "rec000");
        // Re-address the commit as a raw block: the hash still matches.
        let raw_commit = rewrite(&car, |roots, blocks| {
            let cid = Cid::compute(Codec::Raw, &blocks[0].data);
            blocks[0].cid = cid;
            roots[0] = cid;
        });
        assert!(matches!(
            verify(&raw_commit, &key, "com.example.even", "rec000"),
            Err(ProofError::NotDrisl(_))
        ));

        // A validly signed commit whose MST points at a raw-codec record.
        use crate::mst::{BlockStore, MemBlockStore, Tree};
        use std::rc::Rc;
        struct Shared(Rc<MemBlockStore>);
        impl BlockStore for Shared {
            fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
                self.0.get_block(cid)
            }
            fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
                self.0.put_block(cid, data)
            }
            fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
                self.0.has_block(cid)
            }
        }
        let store = Rc::new(MemBlockStore::new());
        let data = record(1);
        let raw = Cid::compute(Codec::Raw, &data);
        store.put_block(raw, data).unwrap();
        let mut tree = Tree::new(Box::new(Shared(Rc::clone(&store))));
        tree.insert("com.example.even/rec001".into(), raw).unwrap();
        let root = tree.root_cid().unwrap();
        let signed =
            Commit::create_signed(did(), TidClock::new(0).unwrap().next(), root, &key).unwrap();
        store.put_block(signed.cid, signed.bytes).unwrap();
        let car = record_proof_car(
            &*store,
            &signed.cid,
            &col("com.example.even"),
            &rk("rec001"),
        )
        .unwrap();
        assert!(matches!(
            verify(&car, &key, "com.example.even", "rec001"),
            Err(ProofError::NotDrisl(cid)) if cid == raw
        ));
    }

    #[test]
    fn rejects_garbage_and_truncation() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(5, &key);
        let car = proof(&repo, "com.example.even", "rec000");
        for len in [0, 1, 10, car.len() / 2, car.len() - 1] {
            assert!(
                verify(&car[..len], &key, "com.example.even", "rec000").is_err(),
                "truncated to {len} bytes"
            );
        }
        assert!(verify(b"not a car at all", &key, "com.example.even", "rec000").is_err());
    }

    #[test]
    fn extra_and_duplicate_blocks_are_ignored() {
        let key = P256SigningKey::generate();
        let repo = filled_repo(10, &key);
        let car = proof(&repo, "com.example.even", "rec002");
        let padded = rewrite(&car, |_, blocks| {
            let junk = b"unrelated".to_vec();
            blocks.push(Block {
                cid: Cid::compute(Codec::Raw, &junk),
                data: junk,
            });
            blocks.push(blocks[0].clone());
        });
        let got = verify(&padded, &key, "com.example.even", "rec002").unwrap();
        assert_eq!(got.record.unwrap().1, record(2));
    }

    #[test]
    fn proof_reflects_last_commit_not_pending_writes() {
        let key = P256SigningKey::generate();
        let mut repo = filled_repo(4, &key);
        repo.update(&col("com.example.even"), &rk("rec000"), &record(99))
            .unwrap();
        let got = verify(
            &proof(&repo, "com.example.even", "rec000"),
            &key,
            "com.example.even",
            "rec000",
        )
        .unwrap();
        assert_eq!(got.record.unwrap().1, record(0));
        repo.commit(&key).unwrap();
        let got = verify(
            &proof(&repo, "com.example.even", "rec000"),
            &key,
            "com.example.even",
            "rec000",
        )
        .unwrap();
        assert_eq!(got.record.unwrap().1, record(99));
    }

    #[test]
    fn uncommitted_repo_has_no_proof() {
        let repo = Repo::new(did(), TidClock::new(0).unwrap());
        assert!(matches!(
            repo.record_proof(&col("com.example.even"), &rk("a")),
            Err(ProofError::NoCommit)
        ));
    }
}
