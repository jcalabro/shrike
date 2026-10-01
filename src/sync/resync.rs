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

/// Builds a repo from its CAR as the bytes arrive, enforcing `limits` and
/// verifying each block's CID along the way, so a hostile or broken source is
/// cut off as soon as it crosses a limit rather than after the whole body has
/// been buffered.
pub(crate) struct RepoCarLoader<'a> {
    did: &'a Did,
    limits: RepoLoadLimits,
    reader: car::IncrementalReader,
    car_bytes: usize,
    block_count: usize,
    block_bytes: usize,
    blocks: HashMap<Cid, Vec<u8>>,
}

impl<'a> RepoCarLoader<'a> {
    pub(crate) fn new(did: &'a Did, limits: RepoLoadLimits) -> Self {
        Self {
            did,
            limits,
            reader: car::IncrementalReader::new(),
            car_bytes: 0,
            block_count: 0,
            block_bytes: 0,
            blocks: HashMap::new(),
        }
    }

    /// Consume the next chunk of the CAR.
    pub(crate) fn push(&mut self, chunk: &[u8]) -> Result<(), VerifierError> {
        self.car_bytes = self.car_bytes.saturating_add(chunk.len());
        if self.car_bytes > self.limits.max_car_bytes {
            return Err(self.oversized(
                "repo_car_bytes",
                self.car_bytes,
                self.limits.max_car_bytes,
            ));
        }
        self.reader.push(chunk);
        while let Some(block) = self.reader.next_block().map_err(|e| self.car_err(e))? {
            self.add_block(block)?;
        }
        Ok(())
    }

    fn add_block(&mut self, block: car::Block) -> Result<(), VerifierError> {
        // Duplicates count towards the limits: they cost the same to receive.
        self.block_count += 1;
        if self.block_count > self.limits.max_blocks {
            return Err(self.oversized("repo_blocks", self.block_count, self.limits.max_blocks));
        }
        self.block_bytes = self.block_bytes.saturating_add(block.data.len());
        if self.block_bytes > self.limits.max_block_bytes {
            return Err(self.oversized(
                "repo_block_bytes",
                self.block_bytes,
                self.limits.max_block_bytes,
            ));
        }

        let computed = Cid::compute(block.cid.codec(), &block.data);
        if computed != block.cid {
            return Err(self.car_err(car::CarError::InvalidBlock(format!(
                "CID mismatch for block: stored {}, computed {}",
                block.cid, computed
            ))));
        }
        if let Some(existing) = self.blocks.get(&block.cid) {
            if existing != &block.data {
                return Err(self.car_err(car::CarError::InvalidBlock(format!(
                    "duplicate block with different bytes: {}",
                    block.cid
                ))));
            }
            return Ok(());
        }
        self.blocks.insert(block.cid, block.data);
        Ok(())
    }

    /// Finish the CAR and decode the repo it holds.
    pub(crate) fn finish(self) -> Result<LoadedRepo, VerifierError> {
        let did = self.did;
        self.reader.finish().map_err(|e| self.car_err(e))?;
        let commit_cid = self
            .reader
            .roots()
            .and_then(|roots| roots.first().copied())
            .ok_or_else(|| VerifierError::Inversion {
                did: did.clone(),
                rev: "<unknown>".to_owned(),
                message: "CAR has no roots".to_owned(),
            })?;
        load_repo(did, commit_cid, self.blocks, self.limits)
    }

    fn oversized(&self, field: &'static str, bytes: usize, limit: usize) -> VerifierError {
        VerifierError::OversizedCommit {
            did: self.did.clone(),
            rev: None,
            field,
            bytes,
            limit,
        }
    }

    fn car_err(&self, source: car::CarError) -> VerifierError {
        VerifierError::Car {
            did: Some(self.did.clone()),
            rev: None,
            source,
        }
    }
}

fn load_repo(
    did: &Did,
    commit_cid: Cid,
    block_map: HashMap<Cid, Vec<u8>>,
    limits: RepoLoadLimits,
) -> Result<LoadedRepo, VerifierError> {
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
