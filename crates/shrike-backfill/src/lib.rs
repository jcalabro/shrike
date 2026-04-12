//! AT Protocol concurrent repo backfill engine.
//!
//! # Overview
//!
//! This crate provides a [`BackfillEngine`] that downloads all repositories
//! from a relay or PDS concurrently.
//!
//! Key features:
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
    Xrpc(#[from] shrike_xrpc::Error),
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
