//! A minimal cooperative cancellation token shared between a client and its
//! archive workers.
//!
//! Archive planning and downloads are long-running loops; a caller must be able
//! to ask them to stop and have them wind down cleanly rather than run to
//! completion. [`CancelToken`] is a cloneable flag every clone observes: the
//! caller (or a dropping client) calls [`CancelToken::cancel`], and the worker
//! loops check [`CancelToken::is_cancelled`] between steps — before each request
//! attempt, before each backoff sleep, and between body chunks — returning
//! [`crate::jetstream::Error::Canceled`] promptly.
//!
//! It is deliberately tiny and dependency-free (an `Arc<AtomicBool>`), so it
//! works identically on native and on `wasm32-unknown-unknown`. It provides
//! *cooperative* cancellation at operation boundaries, which is the granularity
//! that matters for a clean shutdown; it does not forcibly interrupt an
//! in-flight syscall.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// A cloneable cancellation flag. All clones share one underlying state, so
/// cancelling any clone cancels them all.
#[derive(Clone, Default)]
pub struct CancelToken {
    flag: Arc<AtomicBool>,
}

impl CancelToken {
    /// Create a fresh, un-cancelled token.
    pub fn new() -> Self {
        CancelToken::default()
    }

    /// Request cancellation. Idempotent; observable by every clone.
    pub fn cancel(&self) {
        self.flag.store(true, Ordering::SeqCst);
    }

    /// Whether cancellation has been requested.
    pub fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::SeqCst)
    }

    /// Resolve once cancellation has been requested.
    ///
    /// The live tail blocks on the next WebSocket frame, which may never arrive
    /// on a silent connection; racing that read against this future lets a
    /// cancelled stream shut down promptly instead of waiting out a stalled
    /// socket. It polls the flag rather than depending on a runtime-specific
    /// notification primitive, so it behaves identically on native and
    /// `wasm32-unknown-unknown`. Under a paused test clock the poll sleeps are
    /// auto-advanced, so a cancellation test does not wait real time.
    pub(crate) async fn cancelled(&self) {
        while !self.is_cancelled() {
            crate::platform::sleep(core::time::Duration::from_millis(CANCEL_POLL_MILLIS)).await;
        }
    }

    /// Sleep for `delay`, racing cancellation. Returns `false` when cancelled
    /// (before or during the sleep), so a backoff wait never outlives a
    /// shutdown request — matching the Go client, whose retry sleeps select on
    /// `ctx.Done()`.
    pub(crate) async fn sleep_cancelable(&self, delay: core::time::Duration) -> bool {
        use futures::future::{Either, select};
        if self.is_cancelled() {
            return false;
        }
        let sleep = crate::platform::sleep(delay);
        let cancelled = self.cancelled();
        futures::pin_mut!(sleep, cancelled);
        matches!(select(sleep, cancelled).await, Either::Left(_))
    }
}

/// How often [`CancelToken::cancelled`] re-checks the flag. Cancellation is a
/// rare, latency-tolerant event, so a coarse interval keeps the idle cost
/// negligible while still winding a stalled read down within a fraction of a
/// second.
const CANCEL_POLL_MILLIS: u64 = 100;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn clones_share_state() {
        let a = CancelToken::new();
        let b = a.clone();
        assert!(!a.is_cancelled());
        assert!(!b.is_cancelled());
        b.cancel();
        assert!(a.is_cancelled());
        assert!(b.is_cancelled());
    }

    #[test]
    fn cancel_is_idempotent() {
        let t = CancelToken::new();
        t.cancel();
        t.cancel();
        assert!(t.is_cancelled());
    }
}
