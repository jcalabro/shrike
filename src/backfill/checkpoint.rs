use std::future::Future;
use std::pin::Pin;

use crate::backfill::BackfillError;

pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Persist cursor position for crash recovery.
///
/// Implement this trait to store the backfill cursor in a database or file
/// so that a restarted run can continue where it left off.
pub trait Checkpoint: Send + Sync {
    /// Save the current cursor position.
    fn save(&self, cursor: &str) -> BoxFuture<'_, Result<(), BackfillError>>;
    /// Load the last saved cursor, or None if no checkpoint exists.
    fn load(&self) -> BoxFuture<'_, Result<Option<String>, BackfillError>>;
}

/// No-op checkpoint that discards cursor state. Suitable for testing or
/// when crash recovery is not needed.
pub struct NoopCheckpoint;

impl Checkpoint for NoopCheckpoint {
    fn save(&self, _cursor: &str) -> BoxFuture<'_, Result<(), BackfillError>> {
        Box::pin(async { Ok(()) })
    }
    fn load(&self) -> BoxFuture<'_, Result<Option<String>, BackfillError>> {
        Box::pin(async { Ok(None) })
    }
}
