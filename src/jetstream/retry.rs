//! A bounded, deterministic retry combinator for archive requests.
//!
//! Archive control requests (`planSnapshot`) and bulk downloads (`getSegment`,
//! `getBlock`) share one policy shape: retry a transient failure — a `429`, a
//! `5xx`, or a retryable transport fault — a bounded number of times with
//! exponential backoff, and stop immediately on anything fatal. The backoff is
//! *deterministic* (no jitter): the M3 acceptance requires reproducible results
//! across the fault-injection suite, and jitter would defeat that. A
//! server-supplied `Retry-After` / `RateLimit-Reset` hint acts as a floor on the
//! wait so the client never retries ahead of when the server said it may.
//!
//! This is a small, purpose-built policy rather than a reuse of
//! [`crate::xrpc::retry`]: the XRPC policy adds randomized jitter and is tied to
//! that stack's error types. The plan accepts this minor duplication to keep the
//! Jetstream client's timing deterministic and its dependencies self-contained.
//!
//! [`with_retry`] drives the loop over an operation that classifies each attempt
//! as [`Attempt::Ok`], [`Attempt::Retry`], or [`Attempt::Fatal`]. Between
//! attempts it honors the shared [`CancelToken`], returning
//! [`Error::Canceled`] rather than sleeping when cancellation is requested.

use core::future::Future;
use core::time::Duration;

use super::cancel::CancelToken;
use super::error::{Error, Result};

/// A bounded exponential-backoff policy.
#[derive(Debug, Clone, Copy)]
pub struct RetryConfig {
    /// The total number of attempts, including the first. `1` disables retry.
    pub max_attempts: u32,
    /// The base backoff applied before the first retry; doubles each retry.
    pub base_delay: Duration,
    /// The ceiling on the *computed* backoff (a server hint may exceed it).
    pub max_delay: Duration,
}

impl RetryConfig {
    /// The default policy for short archive control requests: three attempts,
    /// 500 ms base backoff, capped at 30 s.
    pub const fn control() -> Self {
        RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }

    /// The default policy for bulk downloads. The same shape as [`control`];
    /// separated so the two can diverge without touching call sites.
    ///
    /// [`control`]: RetryConfig::control
    pub const fn download() -> Self {
        RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }

    /// The deterministic delay before the retry with 0-based index `retry_index`.
    ///
    /// The computed backoff is `base_delay * 2^retry_index`, saturating and
    /// capped at `max_delay`. A server `hint` (from `Retry-After` /
    /// `RateLimit-Reset`) acts as a floor: the effective delay is the larger of
    /// the two, so the client never retries before the server said it may, even
    /// if that exceeds `max_delay`.
    pub fn delay_for(&self, retry_index: u32, hint: Option<Duration>) -> Duration {
        let shift = retry_index.min(16);
        let factor = 1u32.checked_shl(shift).unwrap_or(u32::MAX);
        let backoff = self.base_delay.saturating_mul(factor).min(self.max_delay);
        match hint {
            Some(h) => backoff.max(h),
            None => backoff,
        }
    }
}

/// The classification of a single attempt inside [`with_retry`].
pub enum Attempt<T> {
    /// The operation succeeded; stop and return the value.
    Ok(T),
    /// The operation failed transiently; retry after the (optional) hinted floor
    /// unless the attempt budget is exhausted, in which case `err` is returned.
    Retry {
        /// A server-supplied minimum wait (`Retry-After` / `RateLimit-Reset`).
        delay_hint: Option<Duration>,
        /// The error to surface if this was the last attempt.
        err: Error,
    },
    /// The operation failed unrecoverably; stop and return `err` immediately.
    Fatal(Error),
}

/// Drive `op` under the retry policy `cfg`, honoring `cancel` between attempts.
///
/// `op` is invoked with the 0-based attempt number and classifies its outcome.
/// On [`Attempt::Retry`], the loop sleeps for [`RetryConfig::delay_for`] (with
/// the hint as a floor) and tries again until the attempt budget is spent, then
/// returns the last error. Cancellation is checked before each attempt and again
/// before each sleep, returning [`Error::Canceled`] without waiting.
pub(crate) async fn with_retry<T, F, Fut>(
    cfg: &RetryConfig,
    cancel: &CancelToken,
    mut op: F,
) -> Result<T>
where
    F: FnMut(u32) -> Fut,
    Fut: Future<Output = Attempt<T>>,
{
    let mut attempt: u32 = 0;
    loop {
        if cancel.is_cancelled() {
            return Err(Error::Canceled);
        }
        match op(attempt).await {
            Attempt::Ok(value) => return Ok(value),
            Attempt::Fatal(err) => return Err(err),
            Attempt::Retry { delay_hint, err } => {
                let next = attempt.saturating_add(1);
                if next >= cfg.max_attempts {
                    return Err(err);
                }
                let delay = cfg.delay_for(attempt, delay_hint);
                if cancel.is_cancelled() {
                    return Err(Error::Canceled);
                }
                crate::platform::sleep(delay).await;
                attempt = next;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::cell::Cell;

    #[test]
    fn backoff_doubles_and_caps() {
        let cfg = RetryConfig {
            max_attempts: 10,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        };
        assert_eq!(cfg.delay_for(0, None), Duration::from_millis(500));
        assert_eq!(cfg.delay_for(1, None), Duration::from_secs(1));
        assert_eq!(cfg.delay_for(2, None), Duration::from_secs(2));
        // Caps at max_delay rather than growing without bound.
        assert_eq!(cfg.delay_for(20, None), Duration::from_secs(30));
    }

    #[test]
    fn hint_is_a_floor_even_above_cap() {
        let cfg = RetryConfig::control();
        // Hint below the backoff: backoff wins.
        assert_eq!(
            cfg.delay_for(0, Some(Duration::from_millis(100))),
            Duration::from_millis(500)
        );
        // Hint above the cap: the hint is honored.
        assert_eq!(
            cfg.delay_for(0, Some(Duration::from_secs(60))),
            Duration::from_secs(60)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn retries_until_success() {
        let cfg = RetryConfig {
            max_attempts: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        };
        let cancel = CancelToken::new();
        let seen = Cell::new(0u32);
        let out: Result<u32> = with_retry(&cfg, &cancel, |attempt| {
            seen.set(seen.get() + 1);
            async move {
                if attempt < 2 {
                    Attempt::Retry {
                        delay_hint: None,
                        err: Error::Transport {
                            message: "boom".to_owned(),
                            retryable: true,
                        },
                    }
                } else {
                    Attempt::Ok(attempt)
                }
            }
        })
        .await;
        assert_eq!(out.unwrap(), 2);
        assert_eq!(seen.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn exhausts_budget_and_returns_last_error() {
        let cfg = RetryConfig {
            max_attempts: 3,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        };
        let cancel = CancelToken::new();
        let seen = Cell::new(0u32);
        let out: Result<u32> = with_retry(&cfg, &cancel, |_| {
            seen.set(seen.get() + 1);
            async move {
                Attempt::Retry {
                    delay_hint: None,
                    err: Error::Transport {
                        message: "always".to_owned(),
                        retryable: true,
                    },
                }
            }
        })
        .await;
        assert!(matches!(out, Err(Error::Transport { .. })));
        assert_eq!(seen.get(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn fatal_stops_immediately() {
        let cfg = RetryConfig::control();
        let cancel = CancelToken::new();
        let seen = Cell::new(0u32);
        let out: Result<u32> = with_retry(&cfg, &cancel, |_| {
            seen.set(seen.get() + 1);
            async move { Attempt::Fatal(Error::PlanInvalid("nope")) }
        })
        .await;
        assert!(matches!(out, Err(Error::PlanInvalid(_))));
        assert_eq!(seen.get(), 1);
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_before_first_attempt() {
        let cfg = RetryConfig::control();
        let cancel = CancelToken::new();
        cancel.cancel();
        let out: Result<u32> = with_retry(&cfg, &cancel, |_| async move { Attempt::Ok(1) }).await;
        assert!(matches!(out, Err(Error::Canceled)));
    }

    #[tokio::test(start_paused = true)]
    async fn cancellation_between_attempts() {
        let cfg = RetryConfig {
            max_attempts: 5,
            base_delay: Duration::from_millis(1),
            max_delay: Duration::from_millis(4),
        };
        let cancel = CancelToken::new();
        let seen = Cell::new(0u32);
        let out: Result<u32> = with_retry(&cfg, &cancel, |attempt| {
            seen.set(seen.get() + 1);
            // Cancel after the first failing attempt; the loop must not sleep
            // through into a second attempt.
            if attempt == 0 {
                cancel.cancel();
            }
            async move {
                Attempt::Retry {
                    delay_hint: None,
                    err: Error::Transport {
                        message: "boom".to_owned(),
                        retryable: true,
                    },
                }
            }
        })
        .await;
        assert!(matches!(out, Err(Error::Canceled)));
        assert_eq!(seen.get(), 1);
    }
}
