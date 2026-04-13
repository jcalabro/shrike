use std::time::Duration;

use rand::seq::SliceRandom;
use tokio_util::sync::CancellationToken;

use crate::backfill::{
    BackfillError,
    checkpoint::{Checkpoint, NoopCheckpoint},
};

/// Configuration for the backfill engine.
///
/// Only [`sync_host`](BackfillConfig::sync_host) is required. All other
/// fields default to `None`, meaning "use the built-in default" (see each
/// field's doc comment).
#[derive(Default)]
pub struct BackfillConfig {
    /// Host URL to sync repos from.
    pub sync_host: String,
    /// Number of concurrent download workers. None means 50.
    pub workers: Option<usize>,
    /// Number of DIDs per shuffle batch. None means 100,000.
    pub batch_size: Option<usize>,
    /// Checkpoint implementation for resume support. None uses a no-op.
    pub checkpoint: Option<Box<dyn Checkpoint>>,
}

/// Statistics collected during a backfill run.
pub struct BackfillStats {
    pub repos_downloaded: u64,
    pub repos_failed: u64,
    pub elapsed: Duration,
}

/// The concurrent backfill engine.
pub struct BackfillEngine {
    // TODO: used once list_repos pagination is implemented.
    #[allow(dead_code)]
    sync_host: String,
    #[allow(dead_code)]
    workers: usize,
    #[allow(dead_code)]
    batch_size: usize,
    checkpoint: Box<dyn Checkpoint>,
}

impl BackfillEngine {
    pub fn new(config: BackfillConfig) -> Self {
        BackfillEngine {
            sync_host: config.sync_host,
            workers: config.workers.unwrap_or(50),
            batch_size: config.batch_size.unwrap_or(100_000),
            checkpoint: config
                .checkpoint
                .unwrap_or_else(|| Box::new(NoopCheckpoint)),
        }
    }

    /// Run the backfill engine until cancellation.
    ///
    /// The algorithm:
    /// 1. Load cursor from checkpoint.
    /// 2. List repos via sync client with pagination.
    /// 3. Accumulate DIDs in batches of `batch_size`.
    /// 4. Shuffle each batch (Fisher-Yates) for PDS load distribution.
    /// 5. Dispatch to worker pool.
    /// 6. Track stats, checkpoint periodically.
    /// 7. On cancel, save checkpoint and return stats.
    ///
    /// The actual repo iteration requires the full sync client with generated
    /// API types (`list_repos` is currently `todo!()`). This method implements
    /// the surrounding structure — cancellation, stats tracking, and
    /// checkpointing — and is intentionally skeletal until list_repos is
    /// available.
    pub async fn run(&self, cancel: CancellationToken) -> Result<BackfillStats, BackfillError> {
        let start = tokio::time::Instant::now();

        // Load cursor from checkpoint so a restarted run continues where it left off.
        let _cursor = self.checkpoint.load().await?;

        // Placeholder: wait for cancellation. The full implementation would
        // paginate through repos, shuffle each batch, and dispatch to workers.
        cancel.cancelled().await;

        // On cancel, persist the cursor so the next run can resume.
        // (cursor is empty here since no pages were fetched in the skeleton)
        self.checkpoint.save("").await?;

        Ok(BackfillStats {
            repos_downloaded: 0,
            repos_failed: 0,
            elapsed: start.elapsed(),
        })
    }
}

/// Shuffle a batch in-place using Fisher-Yates via the `rand` crate.
///
/// Randomising the order distributes load across different PDS hosts rather
/// than hammering a single host with all its repos consecutively.
pub fn shuffle_batch<T>(batch: &mut [T]) {
    let mut rng = rand::rng();
    batch.shuffle(&mut rng);
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

    #[tokio::test]
    async fn engine_respects_cancellation() {
        let engine = BackfillEngine::new(BackfillConfig {
            sync_host: "https://bsky.network".into(),
            ..Default::default()
        });
        let cancel = CancellationToken::new();
        let cancel_clone = cancel.clone();

        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_millis(50)).await;
            cancel_clone.cancel();
        });

        let stats = engine.run(cancel).await.unwrap();
        assert!(stats.elapsed < Duration::from_secs(5));
    }

    #[test]
    fn shuffle_batch_preserves_elements() {
        let mut batch: Vec<u32> = (0..100).collect();
        let original = batch.clone();
        shuffle_batch(&mut batch);
        batch.sort();
        assert_eq!(batch, original);
    }

    #[test]
    fn engine_resolves_defaults() {
        let engine = BackfillEngine::new(BackfillConfig {
            sync_host: "https://bsky.network".into(),
            ..Default::default()
        });
        assert_eq!(engine.workers, 50);
        assert_eq!(engine.batch_size, 100_000);
    }

    #[test]
    fn engine_overrides() {
        let engine = BackfillEngine::new(BackfillConfig {
            sync_host: "https://bsky.network".into(),
            workers: Some(10),
            batch_size: Some(500),
            ..Default::default()
        });
        assert_eq!(engine.workers, 10);
        assert_eq!(engine.batch_size, 500);
    }
}
