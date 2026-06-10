#![allow(clippy::result_large_err)]
// VerifierError intentionally keeps full typed context for untrusted sync data
// so callers can distinguish recovery actions without parsing strings.

use std::cell::RefCell;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use crate::cbor::Cid;
use crate::mst::{BlockStore, MstError, Tree};
use crate::repo::Commit;
use crate::sync::{RawCommit, RawRepoOp, VerifierError};
use crate::syntax::Did;

/// Block store backed by the blocks carried in a commit CAR.
///
/// MST inversion starts from existing CAR blocks but also needs to persist the
/// newly materialized inverse tree. Original CAR blocks stay in `blocks`;
/// locally generated blocks are kept separately and are only visible through
/// the `BlockStore` implementation.
#[derive(Debug)]
pub struct CarBlockStore {
    blocks: Arc<HashMap<Cid, Vec<u8>>>,
    generated: RefCell<HashMap<Cid, Vec<u8>>>,
}

impl Clone for CarBlockStore {
    fn clone(&self) -> Self {
        Self {
            blocks: Arc::clone(&self.blocks),
            generated: RefCell::new(self.generated.borrow().clone()),
        }
    }
}

impl CarBlockStore {
    pub(crate) fn new(blocks: HashMap<Cid, Vec<u8>>) -> Self {
        Self {
            blocks: Arc::new(blocks),
            generated: RefCell::new(HashMap::new()),
        }
    }

    /// Return a validated block from the original CAR payload.
    ///
    /// Generated MST blocks produced while computing inverse roots are exposed
    /// through the `BlockStore` implementation, not this accessor.
    pub fn get(&self, cid: &Cid) -> Option<&[u8]> {
        self.blocks.get(cid).map(Vec::as_slice)
    }

    fn generated_block(&self, cid: &Cid) -> Option<Vec<u8>> {
        self.generated.borrow().get(cid).cloned()
    }
}

impl BlockStore for CarBlockStore {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
        self.blocks
            .get(cid)
            .cloned()
            .or_else(|| self.generated_block(cid))
            .ok_or_else(|| MstError::BlockNotFound(cid.to_string()))
    }

    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
        if let Some(existing) = self.blocks.get(&cid) {
            if existing != &data {
                return Err(MstError::Internal(format!(
                    "attempted to overwrite CAR block {cid}"
                )));
            }
            return Ok(());
        }
        if let Some(existing) = self.generated.borrow().get(&cid) {
            if existing != &data {
                return Err(MstError::Internal(format!(
                    "attempted to overwrite generated block {cid}"
                )));
            }
            return Ok(());
        }
        self.generated.borrow_mut().insert(cid, data);
        Ok(())
    }

    fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
        Ok(self.blocks.contains_key(cid) || self.generated.borrow().contains_key(cid))
    }
}

#[derive(Debug)]
pub struct DecodedCommitCar {
    pub inner: Commit,
    pub store: CarBlockStore,
    pub car_root: Cid,
}

pub fn decode_commit_car(raw: &RawCommit) -> Result<DecodedCommitCar, VerifierError> {
    let (roots, blocks) =
        crate::car::read_all(&raw.blocks[..]).map_err(|source| VerifierError::Car {
            did: Some(raw.repo.clone()),
            rev: Some(raw.rev.to_string()),
            source,
        })?;

    let car_root = roots
        .first()
        .copied()
        .ok_or_else(|| inversion_error(raw, "CAR has no roots"))?;

    if car_root != raw.commit {
        return Err(VerifierError::FieldMismatch {
            did: raw.repo.clone(),
            rev: Some(raw.rev.to_string()),
            field: "commit",
            expected: raw.commit.to_string(),
            actual: car_root.to_string(),
        });
    }

    let mut block_map = HashMap::with_capacity(blocks.len());
    for block in blocks {
        let computed = Cid::compute(block.cid.codec(), &block.data);
        if computed != block.cid {
            return Err(VerifierError::Car {
                did: Some(raw.repo.clone()),
                rev: Some(raw.rev.to_string()),
                source: crate::car::CarError::InvalidBlock(format!(
                    "CID mismatch for block: stored {}, computed {}",
                    block.cid, computed
                )),
            });
        }

        if let Some(existing) = block_map.get(&block.cid) {
            if existing != &block.data {
                return Err(VerifierError::Car {
                    did: Some(raw.repo.clone()),
                    rev: Some(raw.rev.to_string()),
                    source: crate::car::CarError::InvalidBlock(format!(
                        "duplicate block with different bytes: {}",
                        block.cid
                    )),
                });
            }
            continue;
        }
        block_map.insert(block.cid, block.data);
    }

    let store = CarBlockStore::new(block_map);
    let commit_block = store.get(&raw.commit).ok_or_else(|| {
        inversion_error(raw, format!("commit block {} missing from CAR", raw.commit))
    })?;
    let inner = Commit::from_cbor(commit_block).map_err(|source| VerifierError::Repo {
        did: Some(raw.repo.clone()),
        rev: Some(raw.rev.to_string()),
        source,
    })?;

    Ok(DecodedCommitCar {
        inner,
        store,
        car_root,
    })
}

/// Decode the commit block embedded in a `#sync` event CAR.
///
/// Per `com.atproto.sync.subscribeRepos#sync`, the CAR carries only the
/// signed commit block (no MST nodes, no records) and its first root is the
/// commit CID. This is deliberately cheaper than [`decode_commit_car`]: it
/// neither walks the MST nor materializes a block store, so it works on the
/// commit-only CAR a real `#sync` frame ships.
pub fn decode_sync_commit(did: &Did, rev: &str, blocks: &[u8]) -> Result<Commit, VerifierError> {
    let (roots, car_blocks) =
        crate::car::read_all(blocks).map_err(|source| VerifierError::Car {
            did: Some(did.clone()),
            rev: Some(rev.to_owned()),
            source,
        })?;

    let commit_cid = roots
        .first()
        .copied()
        .ok_or_else(|| VerifierError::Inversion {
            did: did.clone(),
            rev: rev.to_owned(),
            message: "sync CAR has no roots".to_owned(),
        })?;

    let block = car_blocks
        .iter()
        .find(|block| block.cid == commit_cid)
        .ok_or_else(|| VerifierError::Inversion {
            did: did.clone(),
            rev: rev.to_owned(),
            message: format!("commit block {commit_cid} missing from sync CAR"),
        })?;

    let computed = Cid::compute(block.cid.codec(), &block.data);
    if computed != block.cid {
        return Err(VerifierError::Car {
            did: Some(did.clone()),
            rev: Some(rev.to_owned()),
            source: crate::car::CarError::InvalidBlock(format!(
                "CID mismatch for sync commit block: stored {}, computed {computed}",
                block.cid
            )),
        });
    }

    Commit::from_cbor(&block.data).map_err(|source| VerifierError::Repo {
        did: Some(did.clone()),
        rev: Some(rev.to_owned()),
        source,
    })
}

pub fn find_duplicate_path(ops: &[RawRepoOp]) -> Option<&str> {
    let mut seen = HashSet::with_capacity(ops.len());
    for op in ops {
        if !seen.insert(op.path.as_str()) {
            return Some(op.path.as_str());
        }
    }
    None
}

pub fn invert_commit(raw: &RawCommit) -> Result<Cid, VerifierError> {
    if let Some(path) = find_duplicate_path(&raw.ops) {
        return Err(VerifierError::DuplicatePath {
            did: raw.repo.clone(),
            rev: raw.rev.to_string(),
            path: path.to_owned(),
        });
    }

    let decoded = decode_commit_car(raw)?;
    invert_decoded_commit(raw, &decoded.inner, &decoded.store)
}

pub fn invert_decoded_commit(
    raw: &RawCommit,
    inner: &Commit,
    store: &CarBlockStore,
) -> Result<Cid, VerifierError> {
    if let Some(path) = find_duplicate_path(&raw.ops) {
        return Err(VerifierError::DuplicatePath {
            did: raw.repo.clone(),
            rev: raw.rev.to_string(),
            path: path.to_owned(),
        });
    }

    let mut tree = Tree::load(Box::new(store.clone()), inner.data);

    for op in raw.ops.iter().rev() {
        match op.action.as_str() {
            "create" => {
                tree.remove(&op.path)
                    .map_err(|source| mst_inversion_error(raw, source))?;
            }
            "update" | "delete" => {
                let prev = op.prev.ok_or_else(|| {
                    inversion_error(
                        raw,
                        format!("missing prev for {} op at {}", op.action, op.path),
                    )
                })?;
                tree.insert(op.path.clone(), prev)
                    .map_err(|source| mst_inversion_error(raw, source))?;
            }
            _ => {
                return Err(inversion_error(
                    raw,
                    format!("unknown repo op action {:?} at {}", op.action, op.path),
                ));
            }
        }
    }

    tree.root_cid()
        .map_err(|source| mst_inversion_error(raw, source))
}

pub fn check_op_cids(
    raw: &RawCommit,
    data_cid: Cid,
    store: &CarBlockStore,
) -> Result<(), VerifierError> {
    let mut tree = Tree::load(Box::new(store.clone()), data_cid);

    for op in &raw.ops {
        match op.action.as_str() {
            "create" | "update" => {
                let Some(expected) = op.cid else {
                    return Err(VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: None,
                        actual: None,
                    });
                };
                let actual = tree
                    .get(&op.path)
                    .map_err(|_| VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: Some(expected),
                        actual: None,
                    })?;
                if actual != Some(expected) {
                    return Err(VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: Some(expected),
                        actual,
                    });
                }
            }
            "delete" => {
                if let Some(claimed) = op.cid {
                    return Err(VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: None,
                        actual: Some(claimed),
                    });
                }
                let actual = tree
                    .get(&op.path)
                    .map_err(|_| VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: None,
                        actual: None,
                    })?;
                if actual.is_some() {
                    return Err(VerifierError::OpCidMismatch {
                        did: raw.repo.clone(),
                        rev: raw.rev.to_string(),
                        path: op.path.clone(),
                        expected: None,
                        actual,
                    });
                }
            }
            _ => {
                return Err(inversion_error(
                    raw,
                    format!("unknown repo op action {:?} at {}", op.action, op.path),
                ));
            }
        }
    }

    Ok(())
}

fn mst_inversion_error(raw: &RawCommit, source: MstError) -> VerifierError {
    inversion_error(raw, format!("MST error: {source}"))
}

fn inversion_error(raw: &RawCommit, message: impl Into<String>) -> VerifierError {
    VerifierError::Inversion {
        did: raw.repo.clone(),
        rev: raw.rev.to_string(),
        message: message.into(),
    }
}
