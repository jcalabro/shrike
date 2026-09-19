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
}

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
