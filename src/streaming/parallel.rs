//! Keyed FIFO scheduler for parallel firehose verification.
//!
//! [`Scheduler`] dispatches per-key work units to a fixed pool of worker tasks
//! while guaranteeing that units sharing a key run sequentially in arrival
//! order. Different keys run concurrently across the pool. This is the
//! concurrency primitive behind verifier-aware streaming: keying on the repo
//! DID gives same-DID FIFO (so chain-state advances never race) while letting
//! independent DIDs verify in parallel.
//!
//! The design mirrors indigo's parallel scheduler with three additions tuned
//! for untrusted upstreams: a per-key queue cap with drop-oldest semantics, a
//! shutdown that drains in-flight work, and a result channel the caller drains.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Arc;

use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

/// A small sorted set of in-flight firehose seqs, used to compute the
/// watermark cursor under parallel verification: `min() - 1` is the highest
/// seq that can be safely persisted, because every seq below the minimum
/// in-flight has already been collected. Linear inserts/removes are cheap at
/// the sizes involved (bounded by workers + total queued depth).
#[derive(Debug, Default)]
pub struct InflightSeqs {
    xs: Vec<i64>,
}

impl InflightSeqs {
    pub fn new() -> Self {
        Self { xs: Vec::new() }
    }

    /// Insert `seq`, keeping the set sorted ascending. Ignores non-positive
    /// seqs (control/resync frames carry none).
    pub fn add(&mut self, seq: i64) {
        if seq <= 0 {
            return;
        }
        let idx = self.xs.partition_point(|&x| x < seq);
        self.xs.insert(idx, seq);
    }

    /// Remove the first occurrence of `seq`. No-op if absent or non-positive.
    pub fn remove(&mut self, seq: i64) {
        if seq <= 0 {
            return;
        }
        if let Ok(idx) = self.xs.binary_search(&seq) {
            self.xs.remove(idx);
        }
    }

    /// The smallest in-flight seq, or 0 if empty.
    pub fn min(&self) -> i64 {
        self.xs.first().copied().unwrap_or(0)
    }

    pub fn len(&self) -> usize {
        self.xs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.xs.is_empty()
    }
}

/// A keyed FIFO work scheduler.
///
/// Work units are submitted via [`Scheduler::add_work`] with a key. Units with
/// the same key never run concurrently and run in submission order; units with
/// different keys may run concurrently up to the worker-pool size.
pub struct Scheduler<K, W>
where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
{
    inner: Arc<SchedulerInner<K, W>>,
    /// The sole sender for the worker feeder. Held only here (never by workers)
    /// so dropping the scheduler — or calling `shutdown` — closes the channel
    /// and lets idle workers observe end-of-stream and exit.
    feeder_tx: mpsc::UnboundedSender<(K, W)>,
    handles: Vec<JoinHandle<()>>,
}

struct SchedulerInner<K, W>
where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
{
    /// Per-key queue cap; 0 disables drops (unbounded per-key growth).
    key_queue_cap: usize,
    /// Active keys → queued tail units. A key present in the map (even with an
    /// empty queue) means a worker owns its chain; new arrivals append instead
    /// of dispatching, preserving the single-owner-per-key invariant.
    active: Mutex<HashMap<K, Vec<W>>>,
}

/// Outcome of [`Scheduler::add_work`].
#[derive(Debug, PartialEq, Eq)]
pub enum AddOutcome<W> {
    /// The unit was accepted (dispatched or queued).
    Queued,
    /// The per-key queue was full; `dropped` is the evicted oldest unit.
    Dropped(W),
    /// The scheduler is shutting down; the unit was not accepted.
    ShuttingDown(W),
}

impl<K, W> Scheduler<K, W>
where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
{
    /// Create a scheduler with `workers` worker tasks (at least 1) and a
    /// per-key queue cap of `key_queue_cap` (0 = unbounded). Each accepted unit
    /// is run through `run`, whose output is sent on the result channel
    /// returned alongside the scheduler. `run` is invoked concurrently across
    /// keys but serially within a key.
    pub fn new<F, Fut, R>(
        workers: usize,
        key_queue_cap: usize,
        result_capacity: usize,
        run: F,
    ) -> (Self, mpsc::Receiver<R>)
    where
        F: Fn(W) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = R> + Send + 'static,
        R: Send + 'static,
    {
        let workers = workers.max(1);
        let (feeder_tx, feeder_rx) = mpsc::unbounded_channel::<(K, W)>();
        let (result_tx, result_rx) = mpsc::channel(result_capacity.max(1));
        let inner = Arc::new(SchedulerInner {
            key_queue_cap,
            active: Mutex::new(HashMap::new()),
        });
        let run = Arc::new(run);

        // A single shared receiver behind a Mutex lets any idle worker grab the
        // next freshly-active key (tokio's mpsc receiver is single-consumer and
        // not Clone). The lock is held only to dequeue; work runs outside it,
        // so up to `workers` chains run concurrently.
        let shared_rx = Arc::new(Mutex::new(feeder_rx));

        let mut handles = Vec::with_capacity(workers);
        for _ in 0..workers {
            let inner = Arc::clone(&inner);
            let run = Arc::clone(&run);
            let result_tx = result_tx.clone();
            let shared_rx = Arc::clone(&shared_rx);
            handles.push(tokio::spawn(async move {
                worker_loop(inner, run, result_tx, shared_rx).await;
            }));
        }

        (
            Scheduler {
                inner,
                feeder_tx,
                handles,
            },
            result_rx,
        )
    }

    /// Submit a unit of work for `key`.
    pub async fn add_work(&self, key: K, work: W) -> AddOutcome<W> {
        if self.feeder_tx.is_closed() {
            return AddOutcome::ShuttingDown(work);
        }

        let mut active = self.inner.active.lock().await;
        if let Some(queue) = active.get_mut(&key) {
            // A worker owns this key's chain. Append to the tail, dropping the
            // oldest queued unit on overflow.
            if self.inner.key_queue_cap > 0 && queue.len() >= self.inner.key_queue_cap {
                let dropped = queue.remove(0);
                queue.push(work);
                return AddOutcome::Dropped(dropped);
            }
            queue.push(work);
            return AddOutcome::Queued;
        }

        // Claim the key and dispatch its head unit to a free worker. Hold the
        // `active` lock across the send so a concurrent worker draining the
        // same key cannot remove the entry between our insert and dispatch.
        active.insert(key.clone(), Vec::new());
        match self.feeder_tx.send((key.clone(), work)) {
            Ok(()) => {
                drop(active);
                AddOutcome::Queued
            }
            Err(mpsc::error::SendError((_, work))) => {
                active.remove(&key);
                AddOutcome::ShuttingDown(work)
            }
        }
    }

    /// Shut down the worker pool, waiting for in-flight units to complete.
    /// Queued (not-yet-started) units are abandoned. Consumes the scheduler.
    pub async fn shutdown(mut self) {
        // Replace the feeder with a closed channel: dropping the sole live
        // sender closes it, so idle workers' `recv()` returns `None` and they
        // exit once their current chain drains.
        let (dead_tx, _) = mpsc::unbounded_channel();
        self.feeder_tx = dead_tx;
        for handle in std::mem::take(&mut self.handles) {
            let _ = handle.await;
        }
    }

    /// Abort the worker pool immediately without waiting for in-flight units.
    pub fn abort(mut self) {
        for handle in std::mem::take(&mut self.handles) {
            handle.abort();
        }
    }
}

impl<K, W> Drop for Scheduler<K, W>
where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
{
    fn drop(&mut self) {
        // Ensure worker tasks don't outlive the scheduler (e.g. when the
        // owning stream is dropped without an explicit shutdown).
        for handle in &self.handles {
            handle.abort();
        }
    }
}

async fn worker_loop<K, W, F, Fut, R>(
    inner: Arc<SchedulerInner<K, W>>,
    run: Arc<F>,
    result_tx: mpsc::Sender<R>,
    shared_rx: Arc<Mutex<mpsc::UnboundedReceiver<(K, W)>>>,
) where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
    F: Fn(W) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    loop {
        let next = {
            let mut rx = shared_rx.lock().await;
            rx.recv().await
        };
        let Some((key, work)) = next else {
            return;
        };
        run_chain(&inner, &run, &result_tx, key, work).await;
    }
}

/// Run `work`, then drain the key's queue serially until empty, then release
/// the key. A single worker owns the key for the whole chain, so same-key units
/// never run concurrently.
async fn run_chain<K, W, F, Fut, R>(
    inner: &Arc<SchedulerInner<K, W>>,
    run: &Arc<F>,
    result_tx: &mpsc::Sender<R>,
    key: K,
    mut work: W,
) where
    K: Eq + Hash + Clone + Send + 'static,
    W: Send + 'static,
    F: Fn(W) -> Fut + Send + Sync + 'static,
    Fut: std::future::Future<Output = R> + Send + 'static,
    R: Send + 'static,
{
    loop {
        let result = run(work).await;
        if result_tx.send(result).await.is_err() {
            // Result consumer is gone; release the key and stop.
            inner.active.lock().await.remove(&key);
            return;
        }

        let mut active = inner.active.lock().await;
        match active.get_mut(&key) {
            Some(queue) if !queue.is_empty() => {
                work = queue.remove(0);
            }
            _ => {
                active.remove(&key);
                return;
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    #[tokio::test]
    async fn preserves_same_key_order() {
        let (sched, mut results) = Scheduler::<u8, usize>::new(4, 0, 256, |w| async move {
            // Jitter so out-of-order completion would surface if ordering broke.
            tokio::time::sleep(Duration::from_millis((w % 3) as u64)).await;
            w
        });
        for i in 0..100usize {
            assert!(matches!(sched.add_work(7, i).await, AddOutcome::Queued));
        }
        let mut got = Vec::new();
        for _ in 0..100 {
            got.push(results.recv().await.unwrap());
        }
        let expected: Vec<usize> = (0..100).collect();
        assert_eq!(
            got, expected,
            "same-key work must complete in arrival order"
        );
        sched.abort();
    }

    #[tokio::test]
    async fn runs_different_keys_concurrently() {
        let barrier = Arc::new(tokio::sync::Barrier::new(8));
        let entered = Arc::new(AtomicUsize::new(0));
        let entered2 = Arc::clone(&entered);
        let barrier2 = Arc::clone(&barrier);
        let (sched, mut results) = Scheduler::<u8, u8>::new(8, 0, 64, move |w| {
            let barrier = Arc::clone(&barrier2);
            let entered = Arc::clone(&entered2);
            async move {
                entered.fetch_add(1, Ordering::SeqCst);
                // All eight must arrive before any proceeds; if keys were
                // serialized this would deadlock and the test would time out.
                barrier.wait().await;
                w
            }
        });
        for key in 0..8u8 {
            assert!(matches!(sched.add_work(key, key).await, AddOutcome::Queued));
        }
        for _ in 0..8 {
            tokio::time::timeout(Duration::from_secs(2), results.recv())
                .await
                .expect("all keys should run concurrently")
                .unwrap();
        }
        assert_eq!(entered.load(Ordering::SeqCst), 8);
        sched.abort();
    }

    #[tokio::test]
    async fn drops_oldest_when_per_key_queue_full() {
        // One worker, queue cap 1. Hold the active unit so the queue fills.
        let release = Arc::new(tokio::sync::Notify::new());
        let release2 = Arc::clone(&release);
        let started = Arc::new(tokio::sync::Notify::new());
        let started2 = Arc::clone(&started);
        let (sched, mut results) = Scheduler::<u8, usize>::new(1, 1, 64, move |w| {
            let release = Arc::clone(&release2);
            let started = Arc::clone(&started2);
            async move {
                if w == 0 {
                    started.notify_one();
                    release.notified().await;
                }
                w
            }
        });

        // Unit 0 starts and blocks, occupying the worker.
        assert!(matches!(sched.add_work(1, 0).await, AddOutcome::Queued));
        started.notified().await;
        // Unit 1 queues (cap 1, queue now full).
        assert!(matches!(sched.add_work(1, 1).await, AddOutcome::Queued));
        // Unit 2 overflows: the oldest queued unit (1) is dropped.
        assert_eq!(sched.add_work(1, 2).await, AddOutcome::Dropped(1));

        release.notify_one();
        let mut got = Vec::new();
        for _ in 0..2 {
            got.push(results.recv().await.unwrap());
        }
        assert_eq!(got, vec![0, 2], "dropped unit 1 must not run; 0 then 2 do");
        sched.abort();
    }

    #[test]
    fn inflight_tracks_min_and_ignores_nonpositive() {
        let mut inflight = InflightSeqs::new();
        inflight.add(30);
        inflight.add(10);
        inflight.add(20);
        inflight.add(0); // ignored
        inflight.add(-5); // ignored
        assert_eq!(inflight.len(), 3);
        assert_eq!(inflight.min(), 10);
        inflight.remove(10);
        assert_eq!(inflight.min(), 20);
        inflight.remove(20);
        inflight.remove(30);
        assert!(inflight.is_empty());
        assert_eq!(inflight.min(), 0);
    }

    #[tokio::test]
    async fn shutdown_does_not_hang() {
        let (sched, results) = Scheduler::<u8, u8>::new(2, 0, 8, |w| async move { w });
        sched.add_work(1, 1).await;
        sched.add_work(2, 2).await;
        // Drain so workers aren't blocked on a full result channel.
        drop(results);
        tokio::time::timeout(Duration::from_secs(2), sched.shutdown())
            .await
            .expect("shutdown must not hang");
    }
}
