//! AT Protocol concurrent repo backfill engine.
//!
//! # Status
//!
//! **Work in progress.** The supporting pieces — configuration, the
//! [`Checkpoint`] trait for crash-recovery, Fisher-Yates batch
//! [shuffling](shuffle_batch), and cancellation — are implemented and tested,
//! but [`BackfillEngine::run`] is currently a skeleton: it loads the checkpoint,
//! waits for cancellation, and returns zero stats. Repo iteration
//! (`list_repos` pagination + worker dispatch) is not yet wired up, so a `run`
//! does not actually download repositories. The scaffolding is in place so the
//! download loop can be dropped in without changing the public API.
//!
//! # Planned design
//!
//! [`BackfillEngine`] will download all repositories from a relay or PDS
//! concurrently, with:
//! - Cursor-based pagination with crash-recovery via the [`Checkpoint`] trait.
//! - Fisher-Yates batch shuffling to distribute load across PDS hosts.
//! - Configurable worker concurrency and batch size.
//! - Graceful shutdown via [`tokio_util::sync::CancellationToken`].

pub mod checkpoint;
pub mod engine;

pub use checkpoint::{Checkpoint, NoopCheckpoint};
pub use engine::{BackfillConfig, BackfillEngine, BackfillStats, shuffle_batch};

use thiserror::Error;

/// Errors produced by the backfill engine.
#[derive(Debug, Error)]
pub enum BackfillError {
    #[error("checkpoint error: {0}")]
    Checkpoint(String),
    #[error("sync error: {0}")]
    Sync(String),
    #[error("XRPC error: {0}")]
    Xrpc(#[from] crate::xrpc::Error),
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use crate::backfill::*;

    #[test]
    fn noop_checkpoint() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        let cp = NoopCheckpoint;
        rt.block_on(async {
            assert!(cp.load().await.unwrap().is_none());
            cp.save("cursor-123").await.unwrap();
            assert!(cp.load().await.unwrap().is_none()); // noop doesn't persist
        });
    }
}
