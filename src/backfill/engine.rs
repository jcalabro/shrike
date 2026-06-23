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
    /// Number of repositories successfully downloaded.
    pub repos_downloaded: u64,
    /// Number of repositories that failed to download.
    pub repos_failed: u64,
    /// Wall-clock time elapsed during the run.
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
    /// Create a new backfill engine from the given configuration.
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
        let cursor = self.checkpoint.load().await?;

        // Placeholder: wait for cancellation. The full implementation would
        // paginate through repos, shuffle each batch, and dispatch to workers,
        // advancing `cursor` as pages complete.
        cancel.cancelled().await;

        // Persist only a non-empty cursor. The skeleton fetches no pages, so
        // `cursor` is whatever we loaded; never overwrite a previously
        // persisted resume point with an empty string.
        if let Some(cursor) = cursor.as_deref().map(str::trim).filter(|c| !c.is_empty()) {
            self.checkpoint.save(cursor).await?;
        }

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

    /// A checkpoint that returns a preloaded cursor and records every save.
    struct RecordingCheckpoint {
        preload: Option<String>,
        saves: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    }

    impl crate::backfill::Checkpoint for RecordingCheckpoint {
        fn save(
            &self,
            cursor: &str,
        ) -> crate::backfill::checkpoint::BoxFuture<'_, Result<(), BackfillError>> {
            let saves = std::sync::Arc::clone(&self.saves);
            let cursor = cursor.to_string();
            Box::pin(async move {
                saves.lock().unwrap().push(cursor);
                Ok(())
            })
        }
        fn load(
            &self,
        ) -> crate::backfill::checkpoint::BoxFuture<'_, Result<Option<String>, BackfillError>>
        {
            let preload = self.preload.clone();
            Box::pin(async move { Ok(preload) })
        }
    }

    #[tokio::test]
    async fn run_does_not_clobber_existing_checkpoint() {
        // L29: the skeleton run() must not overwrite a previously-persisted
        // resume cursor with an empty string on cancel.
        let saves = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let engine = BackfillEngine::new(BackfillConfig {
            sync_host: "https://bsky.network".into(),
            checkpoint: Some(Box::new(RecordingCheckpoint {
                preload: Some("page-42".into()),
                saves: std::sync::Arc::clone(&saves),
            })),
            ..Default::default()
        });
        let cancel = CancellationToken::new();
        cancel.cancel();
        engine.run(cancel).await.unwrap();
        // No empty cursor was persisted (the only acceptable save is the
        // preloaded non-empty cursor, never "").
        let recorded = saves.lock().unwrap();
        assert!(
            !recorded.iter().any(|c| c.is_empty()),
            "run() must not save an empty cursor, got {recorded:?}"
        );
    }

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
