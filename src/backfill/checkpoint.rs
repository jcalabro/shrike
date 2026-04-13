use std::future::Future;
use std::pin::Pin;

use crate::backfill::BackfillError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Persist cursor position for crash recovery
pub trait Checkpoint: Send + Sync {
    fn save(&self, cursor: &str) -> BoxFuture<'_, Result<(), BackfillError>>;
    fn load(&self) -> BoxFuture<'_, Result<Option<String>, BackfillError>>;
}

/// No-op checkpoint for testing
pub struct NoopCheckpoint;

impl Checkpoint for NoopCheckpoint {
    fn save(&self, _cursor: &str) -> BoxFuture<'_, Result<(), BackfillError>> {
        Box::pin(async { Ok(()) })
    }
    fn load(&self) -> BoxFuture<'_, Result<Option<String>, BackfillError>> {
        Box::pin(async { Ok(None) })
    }
}
