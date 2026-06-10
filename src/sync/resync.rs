#![allow(clippy::result_large_err)]
// Full-repo verification returns VerifierError directly to preserve precise
// policy/recovery context for callers and tests.

use std::collections::HashMap;

use crate::car;
use crate::cbor::Cid;
use crate::mst::Tree;
use crate::repo::Commit;
use crate::sync::{CarBlockStore, VerifierError, VerifierOp};
use crate::syntax::{Did, Tid};

pub const DEFAULT_MAX_REPO_CAR_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_MAX_REPO_BLOCKS: usize = 1_000_000;
pub const DEFAULT_MAX_REPO_BLOCK_BYTES: usize = 512 * 1024 * 1024;
pub const DEFAULT_MAX_REPO_RECORDS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RepoLoadLimits {
    pub max_car_bytes: usize,
    pub max_blocks: usize,
    pub max_block_bytes: usize,
    pub max_records: usize,
}

impl Default for RepoLoadLimits {
    fn default() -> Self {
        Self {
            max_car_bytes: DEFAULT_MAX_REPO_CAR_BYTES,
            max_blocks: DEFAULT_MAX_REPO_BLOCKS,
            max_block_bytes: DEFAULT_MAX_REPO_BLOCK_BYTES,
            max_records: DEFAULT_MAX_REPO_RECORDS,
        }
    }
}

pub(crate) struct LoadedRepo {
    pub commit: Commit,
    pub ops: Vec<VerifierOp>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResyncEvent {
    pub did: Did,
    pub old_rev: Option<String>,
    pub new_rev: String,
    pub reason: String,
    pub ops: Vec<VerifierOp>,
}

pub(crate) fn load_repo_from_car(
    did: &Did,
    car_bytes: &[u8],
    limits: RepoLoadLimits,
) -> Result<LoadedRepo, VerifierError> {
    if car_bytes.len() > limits.max_car_bytes {
        return Err(VerifierError::OversizedCommit {
            did: did.clone(),
            rev: None,
            field: "repo_car_bytes",
            bytes: car_bytes.len(),
            limit: limits.max_car_bytes,
        });
    }

    let (roots, blocks) = car::read_all(car_bytes).map_err(|source| VerifierError::Car {
        did: Some(did.clone()),
        rev: None,
        source,
    })?;
    if blocks.len() > limits.max_blocks {
        return Err(VerifierError::OversizedCommit {
            did: did.clone(),
            rev: None,
            field: "repo_blocks",
            bytes: blocks.len(),
            limit: limits.max_blocks,
        });
    }

    let block_bytes = blocks
        .iter()
        .try_fold(0usize, |sum, block| sum.checked_add(block.data.len()))
        .ok_or_else(|| VerifierError::OversizedCommit {
            did: did.clone(),
            rev: None,
            field: "repo_block_bytes",
            bytes: usize::MAX,
            limit: limits.max_block_bytes,
        })?;
    if block_bytes > limits.max_block_bytes {
        return Err(VerifierError::OversizedCommit {
            did: did.clone(),
            rev: None,
            field: "repo_block_bytes",
            bytes: block_bytes,
            limit: limits.max_block_bytes,
        });
    }

    let commit_cid = roots
        .first()
        .copied()
        .ok_or_else(|| VerifierError::Inversion {
            did: did.clone(),
            rev: "<unknown>".to_owned(),
            message: "CAR has no roots".to_owned(),
        })?;

    let mut block_map = HashMap::with_capacity(blocks.len());
    for block in blocks {
        let computed = Cid::compute(block.cid.codec(), &block.data);
        if computed != block.cid {
            return Err(VerifierError::Car {
                did: Some(did.clone()),
                rev: None,
                source: car::CarError::InvalidBlock(format!(
                    "CID mismatch for block: stored {}, computed {}",
                    block.cid, computed
                )),
            });
        }
        if let Some(existing) = block_map.get(&block.cid) {
            if existing != &block.data {
                return Err(VerifierError::Car {
                    did: Some(did.clone()),
                    rev: None,
                    source: car::CarError::InvalidBlock(format!(
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
    let commit_block = store
        .get(&commit_cid)
        .ok_or_else(|| VerifierError::Inversion {
            did: did.clone(),
            rev: "<unknown>".to_owned(),
            message: format!("commit block {commit_cid} missing from CAR"),
        })?;
    let commit = Commit::from_cbor(commit_block).map_err(|source| VerifierError::Repo {
        did: Some(did.clone()),
        rev: None,
        source,
    })?;
    if commit.did != *did {
        return Err(VerifierError::FieldMismatch {
            did: did.clone(),
            rev: Some(commit.rev.to_string()),
            field: "did",
            expected: did.as_str().to_owned(),
            actual: commit.did.as_str().to_owned(),
        });
    }
    if commit.version != 3 {
        return Err(VerifierError::FieldMismatch {
            did: did.clone(),
            rev: Some(commit.rev.to_string()),
            field: "version",
            expected: "3".to_owned(),
            actual: commit.version.to_string(),
        });
    }

    let ops = repo_ops(did, commit.rev, commit.data, &store, limits)?;
    Ok(LoadedRepo { commit, ops })
}

fn repo_ops(
    did: &Did,
    rev: Tid,
    data: Cid,
    store: &CarBlockStore,
    limits: RepoLoadLimits,
) -> Result<Vec<VerifierOp>, VerifierError> {
    let mut tree = Tree::load(Box::new(store.clone()), data);
    let entries = tree.entries().map_err(|source| VerifierError::Inversion {
        did: did.clone(),
        rev: rev.to_string(),
        message: format!("MST error: {source}"),
    })?;
    if entries.len() > limits.max_records {
        return Err(VerifierError::OversizedCommit {
            did: did.clone(),
            rev: Some(rev.to_string()),
            field: "repo_records",
            bytes: entries.len(),
            limit: limits.max_records,
        });
    }

    let mut ops = Vec::with_capacity(entries.len());
    for (path, cid) in entries {
        let Some(record) = store.get(&cid) else {
            return Err(VerifierError::OpCidMismatch {
                did: did.clone(),
                rev: rev.to_string(),
                path,
                expected: Some(cid),
                actual: None,
            });
        };
        ops.push(VerifierOp {
            repo: did.clone(),
            rev,
            action: "resync".to_owned(),
            path,
            cid: Some(cid),
            prev: None,
            record: record.to_vec(),
        });
    }
    Ok(ops)
}
