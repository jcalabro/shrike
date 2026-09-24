//! Small runtime primitives whose native implementations are unavailable in a
//! browser's `wasm32-unknown-unknown` environment.

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn unix_time_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
        })
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn unix_time_millis() -> u64 {
    let millis = js_sys::Date::now();
    if millis.is_finite() && millis > 0.0 {
        millis as u64
    } else {
        0
    }
}

#[cfg(feature = "oauth")]
pub(crate) fn unix_time_secs() -> u64 {
    unix_time_millis() / 1_000
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
pub(crate) fn unix_time_micros() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |duration| {
            u64::try_from(duration.as_micros()).unwrap_or(u64::MAX)
        })
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
pub(crate) fn unix_time_micros() -> u64 {
    unix_time_millis().saturating_mul(1_000)
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[cfg(any(
    feature = "xrpc",
    feature = "identity",
    feature = "streaming",
    feature = "oauth",
    feature = "sync",
    feature = "backfill",
    feature = "jetstream"
))]
pub(crate) async fn sleep(duration: std::time::Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[cfg(any(
    feature = "xrpc",
    feature = "identity",
    feature = "streaming",
    feature = "oauth",
    feature = "sync",
    feature = "backfill",
    feature = "jetstream"
))]
pub(crate) async fn sleep(duration: std::time::Duration) {
    let millis = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
    gloo_timers::future::TimeoutFuture::new(millis).await;
}

/// An opaque flush/timeout deadline. On native it is Tokio's clock (so a paused
/// test clock advances it deterministically); on the browser target it is a
/// `Date.now()` millisecond stamp.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[cfg(feature = "jetstream")]
pub(crate) type Deadline = tokio::time::Instant;

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[cfg(feature = "jetstream")]
pub(crate) type Deadline = u64;

/// The deadline `delay` from now.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[cfg(feature = "jetstream")]
pub(crate) fn deadline_after(delay: std::time::Duration) -> Deadline {
    tokio::time::Instant::now() + delay
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[cfg(feature = "jetstream")]
pub(crate) fn deadline_after(delay: std::time::Duration) -> Deadline {
    unix_time_millis().saturating_add(u64::try_from(delay.as_millis()).unwrap_or(u64::MAX))
}

/// The time remaining until `deadline`, zero once it has passed.
#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
#[cfg(feature = "jetstream")]
pub(crate) fn time_until(deadline: Deadline) -> std::time::Duration {
    // Tokio's `duration_since` saturates to zero when the deadline has passed.
    deadline.duration_since(tokio::time::Instant::now())
}

#[cfg(all(target_family = "wasm", target_os = "unknown"))]
#[cfg(feature = "jetstream")]
pub(crate) fn time_until(deadline: Deadline) -> std::time::Duration {
    std::time::Duration::from_millis(deadline.saturating_sub(unix_time_millis()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn current_time_is_nonzero() {
        assert!(super::unix_time_millis() > 0);
        #[cfg(feature = "oauth")]
        assert!(super::unix_time_secs() > 0);
    }
}
