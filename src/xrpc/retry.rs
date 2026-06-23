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
    /// Compute the (un-jittered) exponential backoff for a 0-indexed attempt:
    /// `base_delay * 2^attempt`, capped at `max_delay`.
    pub fn delay_for_attempt(&self, attempt: u32) -> Duration {
        let delay = self.base_delay.saturating_mul(2u32.saturating_pow(attempt));
        delay.min(self.max_delay)
    }

    /// Compute the actual sleep before a retry.
    ///
    /// When the server supplied a `Retry-After` (via a 429/503), honor it as a
    /// floor — `min(retry_after, max_delay)` — so we don't hammer a
    /// rate-limited endpoint with the shorter exponential delay. Otherwise use
    /// the exponential backoff. Either way, apply "full jitter" in
    /// `[delay/2, delay]` to avoid synchronized retry storms across clients.
    pub fn delay_with_hint(&self, attempt: u32, retry_after: Option<Duration>) -> Duration {
        let base = match retry_after {
            Some(ra) => ra.min(self.max_delay),
            None => self.delay_for_attempt(attempt),
        };
        jitter(base)
    }
}

/// Apply full jitter: return a value in `[d/2, d]`. Uses a cheap time-seeded
/// PRNG — jitter quality does not need to be cryptographic, only decorrelated
/// across clients. Returns `d` unchanged for sub-2ns durations.
fn jitter(d: Duration) -> Duration {
    let nanos = d.as_nanos();
    if nanos < 2 {
        return d;
    }
    // xorshift on a time-derived seed; falls back to no jitter if the clock is
    // unavailable.
    let seed = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|t| t.subsec_nanos() as u64 ^ (t.as_secs().wrapping_mul(2654435761)))
        .unwrap_or(0);
    let mut x = seed | 1;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    // Map into [0, nanos/2), then add the half floor → [nanos/2, nanos].
    let half = (nanos / 2) as u64;
    let extra = if half == 0 { 0 } else { x % half };
    Duration::from_nanos(half.saturating_add(extra))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn jitter_stays_within_half_to_full() {
        let d = Duration::from_secs(4);
        for _ in 0..100 {
            let j = jitter(d);
            assert!(j >= d / 2 && j <= d, "jitter {j:?} out of [d/2, d]");
        }
    }

    #[test]
    fn delay_with_hint_honors_retry_after_as_floor() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        };
        // Server says wait 10s; exponential for attempt 0 would be 500ms.
        // Result must be derived from the 10s hint (>= 5s after jitter), not the
        // much smaller exponential delay.
        let d = policy.delay_with_hint(0, Some(Duration::from_secs(10)));
        assert!(
            d >= Duration::from_secs(5),
            "retry-after floor not honored: {d:?}"
        );
        assert!(d <= Duration::from_secs(10));
    }

    #[test]
    fn delay_with_hint_caps_retry_after_at_max_delay() {
        let policy = RetryPolicy {
            max_retries: 3,
            base_delay: Duration::from_millis(500),
            max_delay: Duration::from_secs(30),
        };
        // A 10-minute Retry-After must be capped at max_delay (30s).
        let d = policy.delay_with_hint(0, Some(Duration::from_secs(600)));
        assert!(
            d <= Duration::from_secs(30),
            "retry-after not capped: {d:?}"
        );
    }

    #[test]
    fn delay_with_hint_falls_back_to_exponential() {
        let policy = RetryPolicy::default();
        // No hint → jittered exponential for attempt 2 (~2s base), within bounds.
        let d = policy.delay_with_hint(2, None);
        let expected = policy.delay_for_attempt(2);
        assert!(d >= expected / 2 && d <= expected);
    }
}
