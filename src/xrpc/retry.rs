use std::time::Duration;

/// Exponential backoff retry policy for XRPC requests.
///
/// Defaults to 3 retries with 500ms base delay and 30s cap.
#[derive(Debug, Clone)]
pub struct RetryPolicy {
    /// Maximum number of retry attempts (default 3).
    pub max_retries: u32,
    /// Initial delay before the first retry (default 500ms).
    pub base_delay: Duration,
    /// Upper bound on delay between retries (default 30s).
    pub max_delay: Duration,
}

impl Default for RetryPolicy {
    fn default() -> Self {
        RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        }
    }
}

impl RetryPolicy {
    /// Compute the delay for a given attempt number (0-indexed).
    /// Doubles each time: base_delay * 2^attempt, capped at max_delay.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.base_delay.saturating_mul(2u32.saturating_pow(attempt));
        delay.min(self.max_delay)
    }
}
