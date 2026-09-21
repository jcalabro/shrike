//! Keep CPU-heavy archive decoding off the native async executor. The caller's
//! ordered download stream bounds the number of jobs; transports stay !Send.

use super::cancel::CancelToken;
use super::error::Result;

pub(crate) async fn run<T, F>(work: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce(CancelToken) -> Result<T> + Send + 'static,
{
    #[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
    if let Ok(runtime) = tokio::runtime::Handle::try_current() {
        let stop = CancelToken::new();
        let worker_stop = stop.clone();
        let task = runtime.spawn_blocking(move || work(worker_stop));
        let _guard = StopOnDrop {
            stop,
            abort: task.abort_handle(),
        };
        return task.await.map_err(|err| {
            if err.is_cancelled() {
                super::error::Error::Canceled
            } else {
                super::error::Error::DownloadFailed("archive decoder task failed")
            }
        })?;
    }
    // Browser clients and callers using a different executor keep the portable
    // synchronous path, with the same validation and ordered results.
    work(CancelToken::new())
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
struct StopOnDrop {
    stop: CancelToken,
    abort: tokio::task::AbortHandle,
}

#[cfg(not(all(target_family = "wasm", target_os = "unknown")))]
impl Drop for StopOnDrop {
    fn drop(&mut self) {
        // Abort prevents a queued job from starting. Already-running work
        // cooperatively stops at block boundaries, including on future drop.
        self.stop.cancel();
        self.abort.abort();
    }
}

#[cfg(all(test, not(all(target_family = "wasm", target_os = "unknown"))))]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    #[test]
    fn works_without_a_tokio_runtime() {
        assert_eq!(futures::executor::block_on(run(|_| Ok(42))).unwrap(), 42);
    }

    #[tokio::test]
    async fn preserves_worker_results_and_errors() {
        assert_eq!(run(|_| Ok(42)).await.unwrap(), 42);
        assert!(matches!(
            run::<(), _>(|_| Err(super::super::error::Error::CorruptSegment("test"))).await,
            Err(super::super::error::Error::CorruptSegment("test"))
        ));
    }

    #[tokio::test]
    async fn dropping_the_future_stops_running_work() {
        let (started, start) = tokio::sync::oneshot::channel();
        let (done, finished) = std::sync::mpsc::channel();
        let mut task = Box::pin(run(move |stop| {
            started.send(()).unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            while !stop.is_cancelled() && Instant::now() < deadline {
                std::thread::sleep(Duration::from_millis(1));
            }
            done.send(stop.is_cancelled()).unwrap();
            Ok(())
        }));
        tokio::select! {
            result = start => result.unwrap(),
            _ = &mut task => panic!("work finished before cancellation"),
        }
        drop(task);
        assert!(finished.recv_timeout(Duration::from_secs(3)).unwrap());
    }
}
