use std::time::Duration;

use rand::Rng;

/// Configures exponential backoff with full jitter for reconnection attempts.
///
/// Defaults to 1s initial delay, 30s max, 2x multiplier.
pub struct BackoffPolicy {
    /// Delay before the first reconnection attempt (default 1s).
    pub initial_delay: Duration,
    /// Upper bound on backoff delay (default 30s).
    pub max_delay: Duration,
    /// Factor by which the delay grows each attempt (default 2.0).
    pub multiplier: f64,
}

impl Default for BackoffPolicy {
    fn default() -> Self {
        BackoffPolicy {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(30),
            multiplier: 2.0,
        }
    }
}

impl BackoffPolicy {
    /// Compute delay for a given attempt with full jitter.
    ///
    /// The base delay grows exponentially: `initial_delay * multiplier^attempt`,
    /// capped at `max_delay`. The returned value is a uniform random duration
    /// in `[0, capped_delay)`.
    pub fn delay(&self, attempt: u32) -> Duration {
        let base = self.initial_delay.as_secs_f64() * self.multiplier.powi(attempt as i32);
        let capped = base.min(self.max_delay.as_secs_f64());
        // Full jitter: uniform random in [0, capped)
        let jittered = rand::rng().random::<f64>() * capped;
        Duration::from_secs_f64(jittered)
    }
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
    fn backoff_increases() {
        let policy = BackoffPolicy::default();
        // Delays should generally increase (modulo jitter).
        // Test the underlying math without jitter.
        let d0 = policy.initial_delay.as_secs_f64();
        let d1 = d0 * policy.multiplier;
        let d2 = d1 * policy.multiplier;
        assert!(d1 > d0);
        assert!(d2 > d1);
    }

    #[test]
    fn backoff_caps_at_max() {
        let policy = BackoffPolicy {
            initial_delay: Duration::from_secs(1),
            max_delay: Duration::from_secs(5),
            multiplier: 10.0,
        };
        // After a few attempts, delay should be capped.
        for _ in 0..100 {
            let delay = policy.delay(10);
            assert!(delay <= Duration::from_secs(5));
        }
    }

    #[test]
    fn backoff_jitter_produces_variety() {
        let policy = BackoffPolicy::default();
        let delays: Vec<Duration> = (0..20).map(|_| policy.delay(3)).collect();
        // With jitter, not all delays should be identical.
        let first = delays[0];
        assert!(
            delays.iter().any(|d| *d != first),
            "jitter should produce varied delays"
        );
    }
}
