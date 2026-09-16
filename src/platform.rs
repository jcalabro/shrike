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
    feature = "backfill"
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
    feature = "backfill"
))]
pub(crate) async fn sleep(duration: std::time::Duration) {
    let millis = u32::try_from(duration.as_millis()).unwrap_or(u32::MAX);
    gloo_timers::future::TimeoutFuture::new(millis).await;
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
