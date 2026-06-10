#![allow(clippy::result_large_err)]
// The verifier exposes typed, context-rich errors so consumers can make
// resync/policy decisions without string matching.

use std::collections::{HashMap, VecDeque, hash_map::DefaultHasher};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::sync::Mutex as StdMutex;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use tokio::sync::{Mutex, mpsc};
use tokio::task::JoinHandle;

use crate::cbor::Cid;
use crate::identity::{Directory, Identity, IdentityError};
use crate::sync::resync::{LoadedRepo, RepoLoadLimits, ResyncEvent, load_repo_from_car};
use crate::sync::{
    ChainState, HostingState, RawAccount, RawCommit, RawSync, StateStore, SyncClient, SyncError,
    VerifierError, check_op_cids, decode_commit_car, decode_sync_commit, find_duplicate_path,
    invert_decoded_commit,
};
use crate::syntax::{Did, Tid};

pub const DEFAULT_FUTURE_REV_TOLERANCE: Duration = Duration::from_secs(5 * 60);
pub const MAX_COMMIT_BLOCKS_BYTES: usize = 2_000_000;
pub const MAX_COMMIT_OPS: usize = 200;
pub const VERIFIER_LOCK_STRIPES: usize = 256;
const DEFAULT_PENDING_QUEUE_CAPACITY: usize = 64;
const DEFAULT_ASYNC_CHANNEL_CAPACITY: usize = 128;

/// Default per-DID resync refill rate: 5 resyncs per minute.
pub const DEFAULT_RESYNC_LIMIT_PER_SECOND: f64 = 5.0 / 60.0;
/// Default per-DID resync burst: 5 resyncs may fire back-to-back.
pub const DEFAULT_RESYNC_BURST: f64 = 5.0;
/// Default bound on the per-DID resync-limiter map. Evicting a DID's bucket
/// just gives its next resync a fresh full bucket, equivalent to a long-quiet
/// account returning to activity.
pub const DEFAULT_RESYNC_LIMITER_CAPACITY: usize = 16_384;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VerifierPolicy {
    Resync,
    Error,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostingPolicy {
    Track,
    Gate,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LegacyCommitPolicy {
    Accept,
    Reject,
}

/// Per-DID resync rate limit. A token bucket refills at `per_second` tokens per
/// second up to `burst` tokens; each resync consumes one token. Disabled
/// (unbounded) when `per_second <= 0` or `burst <= 0`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct ResyncRateLimit {
    pub per_second: f64,
    pub burst: f64,
}

impl Default for ResyncRateLimit {
    fn default() -> Self {
        Self {
            per_second: DEFAULT_RESYNC_LIMIT_PER_SECOND,
            burst: DEFAULT_RESYNC_BURST,
        }
    }
}

impl ResyncRateLimit {
    /// A limit that never throttles. Useful for tests and conservative callers
    /// that gate resyncs elsewhere.
    pub fn unlimited() -> Self {
        Self {
            per_second: 0.0,
            burst: 0.0,
        }
    }

    fn is_enabled(&self) -> bool {
        self.per_second > 0.0 && self.burst > 0.0
    }
}

/// A single per-DID token bucket. Tokens refill lazily on each check using the
/// verifier's injectable clock, so no background timer is needed.
struct TokenBucket {
    tokens: f64,
    last_refill: SystemTime,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct VerifierStats {
    pub events_verified: u64,
    pub chain_breaks: u64,
    pub inversion_failures: u64,
    pub inversion_incomplete: u64,
    pub signature_failures: u64,
    pub rev_replays_dropped: u64,
    pub chain_state_save_failures: u64,
    pub future_revs_rejected: u64,
    pub field_mismatches: u64,
    pub op_cid_mismatches: u64,
    pub legacy_commits: u64,
    pub missing_record_blocks_ops: u64,
    pub duplicate_paths: u64,
    pub oversized_commits: u64,
    pub accounts_inactive: u64,
    pub account_event_replays_dropped: u64,
    pub sync_no_ops: u64,
    pub resyncs: u64,
    pub resync_failures: u64,
    pub resync_rate_limited: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifierOp {
    pub repo: Did,
    pub rev: Tid,
    pub action: String,
    pub path: String,
    pub cid: Option<Cid>,
    pub prev: Option<Cid>,
    /// Raw record bytes for create/update/resync ops, pulled from the commit
    /// CAR. Empty for deletes, and for create/update ops whose record block was
    /// absent from the CAR (counted via `missing_record_blocks_ops`).
    pub record: Vec<u8>,
}

#[async_trait]
pub trait IdentityResolver: Send + Sync {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError>;
    async fn purge(&self, did: &Did) -> Result<(), IdentityError>;
}

#[async_trait]
pub trait SyncRepoSource: Send + Sync {
    async fn get_repo_car(&self, did: &Did) -> Result<Vec<u8>, SyncError>;
}

#[async_trait]
impl IdentityResolver for Directory {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        Directory::lookup_did(self, did).await
    }

    async fn purge(&self, did: &Did) -> Result<(), IdentityError> {
        Directory::purge(self, did).await;
        Ok(())
    }
}

#[async_trait]
impl SyncRepoSource for SyncClient {
    async fn get_repo_car(&self, did: &Did) -> Result<Vec<u8>, SyncError> {
        SyncClient::get_repo_car(self, did).await
    }
}

#[derive(Clone)]
pub struct VerifierOptions {
    state_store: Arc<dyn StateStore>,
    identity_resolver: Arc<dyn IdentityResolver>,
    repo_source: Option<Arc<dyn SyncRepoSource>>,
    verifier_policy: VerifierPolicy,
    hosting_policy: HostingPolicy,
    legacy_commit_policy: LegacyCommitPolicy,
    repo_load_limits: RepoLoadLimits,
    async_resync_workers: usize,
    pending_queue_capacity: usize,
    async_channel_capacity: usize,
    lenient_inversion: bool,
    future_rev_tolerance: Duration,
    resync_rate_limit: ResyncRateLimit,
    resync_limiter_capacity: usize,
    now: Arc<dyn Fn() -> SystemTime + Send + Sync>,
}

impl VerifierOptions {
    pub fn new(
        state_store: Arc<dyn StateStore>,
        identity_resolver: Arc<dyn IdentityResolver>,
    ) -> Self {
        Self {
            state_store,
            identity_resolver,
            repo_source: None,
            verifier_policy: VerifierPolicy::Resync,
            hosting_policy: HostingPolicy::Track,
            legacy_commit_policy: LegacyCommitPolicy::Accept,
            repo_load_limits: RepoLoadLimits::default(),
            async_resync_workers: 0,
            pending_queue_capacity: DEFAULT_PENDING_QUEUE_CAPACITY,
            async_channel_capacity: DEFAULT_ASYNC_CHANNEL_CAPACITY,
            // Default true to match the production relay (and atmos): when an
            // upstream's prevData matches our state but a block-incomplete CAR
            // prevents a full local inversion, accept the commit and surface an
            // `InversionIncomplete` signal rather than forcing a resync.
            lenient_inversion: true,
            future_rev_tolerance: DEFAULT_FUTURE_REV_TOLERANCE,
            resync_rate_limit: ResyncRateLimit::default(),
            resync_limiter_capacity: DEFAULT_RESYNC_LIMITER_CAPACITY,
            now: Arc::new(SystemTime::now),
        }
    }

    pub fn with_verifier_policy(mut self, policy: VerifierPolicy) -> Self {
        self.verifier_policy = policy;
        self
    }

    pub fn with_hosting_policy(mut self, policy: HostingPolicy) -> Self {
        self.hosting_policy = policy;
        self
    }

    pub fn with_legacy_commit_policy(mut self, policy: LegacyCommitPolicy) -> Self {
        self.legacy_commit_policy = policy;
        self
    }

    pub fn with_repo_source(mut self, repo_source: Arc<dyn SyncRepoSource>) -> Self {
        self.repo_source = Some(repo_source);
        self
    }

    pub fn with_repo_load_limits(mut self, limits: RepoLoadLimits) -> Self {
        self.repo_load_limits = limits;
        self
    }

    pub fn with_async_resync_workers(mut self, workers: usize) -> Self {
        self.async_resync_workers = workers;
        self
    }

    pub fn with_pending_queue_capacity(mut self, capacity: usize) -> Self {
        self.pending_queue_capacity = capacity;
        self
    }

    pub fn with_async_channel_capacity(mut self, capacity: usize) -> Self {
        self.async_channel_capacity = capacity;
        self
    }

    pub fn with_lenient_inversion(mut self, lenient: bool) -> Self {
        self.lenient_inversion = lenient;
        self
    }

    pub fn with_future_rev_tolerance(mut self, tolerance: Duration) -> Self {
        self.future_rev_tolerance = tolerance;
        self
    }

    pub fn with_resync_rate_limit(mut self, limit: ResyncRateLimit) -> Self {
        self.resync_rate_limit = limit;
        self
    }

    pub fn with_resync_limiter_capacity(mut self, capacity: usize) -> Self {
        self.resync_limiter_capacity = capacity.max(1);
        self
    }

    pub fn with_now<F>(mut self, now: F) -> Self
    where
        F: Fn() -> SystemTime + Send + Sync + 'static,
    {
        self.now = Arc::new(now);
        self
    }
}

#[derive(Default)]
struct VerifierCounters {
    events_verified: AtomicU64,
    chain_breaks: AtomicU64,
    inversion_failures: AtomicU64,
    inversion_incomplete: AtomicU64,
    signature_failures: AtomicU64,
    rev_replays_dropped: AtomicU64,
    chain_state_save_failures: AtomicU64,
    future_revs_rejected: AtomicU64,
    field_mismatches: AtomicU64,
    op_cid_mismatches: AtomicU64,
    legacy_commits: AtomicU64,
    missing_record_blocks_ops: AtomicU64,
    duplicate_paths: AtomicU64,
    oversized_commits: AtomicU64,
    accounts_inactive: AtomicU64,
    account_event_replays_dropped: AtomicU64,
    sync_no_ops: AtomicU64,
    resyncs: AtomicU64,
    resync_failures: AtomicU64,
    resync_rate_limited: AtomicU64,
}

impl VerifierCounters {
    fn snapshot(&self) -> VerifierStats {
        VerifierStats {
            events_verified: self.events_verified.load(Ordering::Relaxed),
            chain_breaks: self.chain_breaks.load(Ordering::Relaxed),
            inversion_failures: self.inversion_failures.load(Ordering::Relaxed),
            inversion_incomplete: self.inversion_incomplete.load(Ordering::Relaxed),
            signature_failures: self.signature_failures.load(Ordering::Relaxed),
            rev_replays_dropped: self.rev_replays_dropped.load(Ordering::Relaxed),
            chain_state_save_failures: self.chain_state_save_failures.load(Ordering::Relaxed),
            future_revs_rejected: self.future_revs_rejected.load(Ordering::Relaxed),
            field_mismatches: self.field_mismatches.load(Ordering::Relaxed),
            op_cid_mismatches: self.op_cid_mismatches.load(Ordering::Relaxed),
            legacy_commits: self.legacy_commits.load(Ordering::Relaxed),
            missing_record_blocks_ops: self.missing_record_blocks_ops.load(Ordering::Relaxed),
            duplicate_paths: self.duplicate_paths.load(Ordering::Relaxed),
            oversized_commits: self.oversized_commits.load(Ordering::Relaxed),
            accounts_inactive: self.accounts_inactive.load(Ordering::Relaxed),
            account_event_replays_dropped: self
                .account_event_replays_dropped
                .load(Ordering::Relaxed),
            sync_no_ops: self.sync_no_ops.load(Ordering::Relaxed),
            resyncs: self.resyncs.load(Ordering::Relaxed),
            resync_failures: self.resync_failures.load(Ordering::Relaxed),
            resync_rate_limited: self.resync_rate_limited.load(Ordering::Relaxed),
        }
    }
}

struct PendingResync {
    old_rev: Option<String>,
    reason: String,
    commits: VecDeque<RawCommit>,
}

struct AsyncResyncState {
    pending: Mutex<HashMap<Did, PendingResync>>,
    event_tx: StdMutex<Option<mpsc::Sender<ResyncEvent>>>,
    event_rx: StdMutex<Option<mpsc::Receiver<ResyncEvent>>>,
    error_tx: StdMutex<Option<mpsc::Sender<VerifierError>>>,
    error_rx: StdMutex<Option<mpsc::Receiver<VerifierError>>>,
    handles: StdMutex<Vec<JoinHandle<()>>>,
    closed: AtomicBool,
}

impl AsyncResyncState {
    fn new(channel_capacity: usize) -> Self {
        let (event_tx, event_rx) = mpsc::channel(channel_capacity);
        let (error_tx, error_rx) = mpsc::channel(channel_capacity);
        Self {
            pending: Mutex::new(HashMap::new()),
            event_tx: StdMutex::new(Some(event_tx)),
            event_rx: StdMutex::new(Some(event_rx)),
            error_tx: StdMutex::new(Some(error_tx)),
            error_rx: StdMutex::new(Some(error_rx)),
            handles: StdMutex::new(Vec::new()),
            closed: AtomicBool::new(false),
        }
    }
}

#[derive(Clone)]
pub struct Verifier {
    options: VerifierOptions,
    stats: Arc<VerifierCounters>,
    locks: Arc<[Mutex<()>]>,
    async_resync: Arc<AsyncResyncState>,
    resync_limiters: Arc<Mutex<HashMap<Did, TokenBucket>>>,
}

impl Verifier {
    pub fn new(options: VerifierOptions) -> Self {
        let async_channel_capacity = options.async_channel_capacity.max(1);
        Self {
            async_resync: Arc::new(AsyncResyncState::new(async_channel_capacity)),
            resync_limiters: Arc::new(Mutex::new(HashMap::new())),
            options,
            stats: Arc::new(VerifierCounters::default()),
            locks: Arc::from(
                (0..VERIFIER_LOCK_STRIPES)
                    .map(|_| Mutex::new(()))
                    .collect::<Vec<_>>()
                    .into_boxed_slice(),
            ),
        }
    }

    pub fn stats(&self) -> VerifierStats {
        self.stats.snapshot()
    }

    pub fn state_store(&self) -> Arc<dyn StateStore> {
        Arc::clone(&self.options.state_store)
    }

    pub fn lock_stripes(&self) -> usize {
        self.locks.len()
    }

    pub fn resync_events(&self) -> mpsc::Receiver<ResyncEvent> {
        take_receiver(&self.async_resync.event_rx).unwrap_or_else(closed_receiver)
    }

    pub fn async_errors(&self) -> mpsc::Receiver<VerifierError> {
        take_receiver(&self.async_resync.error_rx).unwrap_or_else(closed_receiver)
    }

    pub async fn close(&self) {
        self.async_resync.closed.store(true, Ordering::SeqCst);
        self.async_resync.pending.lock().await.clear();
        if let Ok(mut handles) = self.async_resync.handles.lock() {
            for handle in handles.drain(..) {
                handle.abort();
            }
        }
        take_sender(&self.async_resync.event_tx);
        take_sender(&self.async_resync.error_tx);
    }

    pub async fn verify_commit(
        &self,
        raw: &RawCommit,
    ) -> Result<Option<Vec<VerifierOp>>, VerifierError> {
        self.verify_commit_internal(raw, true).await
    }

    async fn verify_commit_internal(
        &self,
        raw: &RawCommit,
        allow_async_resync: bool,
    ) -> Result<Option<Vec<VerifierOp>>, VerifierError> {
        self.reject_future_rev(raw)?;
        self.reject_oversized(raw)?;

        if allow_async_resync && self.buffer_commit_if_resyncing(raw).await {
            return Ok(None);
        }

        let _guard = self.lock_for(&raw.repo).lock().await;

        self.check_hosting_gate(raw).await?;

        let chain = self.options.state_store.load_chain(&raw.repo).await?;
        if is_rev_replay(&raw.repo, raw.rev, chain.as_ref())? {
            self.stats
                .rev_replays_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        if let Some(path) = find_duplicate_path(&raw.ops) {
            self.stats.duplicate_paths.fetch_add(1, Ordering::Relaxed);
            let err = VerifierError::DuplicatePath {
                did: raw.repo.clone(),
                rev: raw.rev.to_string(),
                path: path.to_owned(),
            };
            return self
                .handle_recoverable_resync(raw, chain.as_ref(), err, allow_async_resync)
                .await;
        }

        let decoded = decode_commit_car(raw).inspect_err(|err| self.count_decode_error(err))?;

        let previous_root =
            match self.previous_root(raw, &decoded.inner, &decoded.store, chain.as_ref()) {
                Ok(root) => root,
                Err(err) => {
                    self.count_inversion_error(&err);
                    return self
                        .handle_recoverable_resync(raw, chain.as_ref(), err, allow_async_resync)
                        .await;
                }
            };

        let chain_error = match self.check_chain(raw, chain.as_ref(), previous_root) {
            Ok(chain_error) => chain_error,
            Err(err) => {
                return self
                    .handle_recoverable_resync(raw, chain.as_ref(), err, allow_async_resync)
                    .await;
            }
        };
        self.check_fields(raw, &decoded.inner)?;
        self.verify_signature(&raw.repo, raw.rev, &decoded.inner)
            .await?;
        if let Err(err) = check_op_cids(raw, decoded.inner.data, &decoded.store) {
            if matches!(&err, VerifierError::OpCidMismatch { .. }) {
                self.stats.op_cid_mismatches.fetch_add(1, Ordering::Relaxed);
            }
            return self
                .handle_recoverable_resync(raw, chain.as_ref(), err, allow_async_resync)
                .await;
        }

        self.save_chain(raw, decoded.inner.data, chain_error.as_ref())
            .await?;

        if let Some(err) = chain_error {
            return Err(err);
        }

        self.stats.events_verified.fetch_add(1, Ordering::Relaxed);
        Ok(Some(self.verifier_ops(raw, &decoded.store)))
    }

    /// Build verified ops from the parsed envelope ops, attaching record bytes
    /// from the commit CAR. A create/update op whose record block is absent
    /// from the CAR still flows through (with empty bytes) but increments
    /// `missing_record_blocks_ops` so operators can spot incomplete upstreams.
    fn verifier_ops(&self, raw: &RawCommit, store: &crate::sync::CarBlockStore) -> Vec<VerifierOp> {
        raw.ops
            .iter()
            .map(|op| {
                let record = match op.cid {
                    Some(cid) => match store.get(&cid) {
                        Some(bytes) => bytes.to_vec(),
                        None => {
                            self.stats
                                .missing_record_blocks_ops
                                .fetch_add(1, Ordering::Relaxed);
                            Vec::new()
                        }
                    },
                    None => Vec::new(),
                };
                VerifierOp {
                    repo: raw.repo.clone(),
                    rev: raw.rev,
                    action: op.action.clone(),
                    path: op.path.clone(),
                    cid: op.cid,
                    prev: op.prev,
                    record,
                }
            })
            .collect()
    }

    /// Surface a non-fatal error on the async-error channel.
    ///
    /// Used by streaming integration so an `#account` persistence failure is
    /// observable without suppressing delivery of the event itself: the
    /// consumer still sees the hosting-status change even though the verifier's
    /// own bookkeeping failed.
    pub async fn report_async_error(&self, err: VerifierError) {
        self.send_async_error(err).await;
    }

    pub async fn on_account_event(&self, raw: &RawAccount) -> Result<(), VerifierError> {
        let lock = self.lock_for(&raw.did).lock().await;
        let current = self.options.state_store.load_hosting(&raw.did).await?;
        if current
            .as_ref()
            .map(|state| raw.seq <= state.seq)
            .unwrap_or(false)
        {
            self.stats
                .account_event_replays_dropped
                .fetch_add(1, Ordering::Relaxed);
            drop(lock);
            return Ok(());
        }

        self.options
            .state_store
            .save_hosting(
                &raw.did,
                HostingState {
                    active: raw.active,
                    status: raw.status.clone(),
                    seq: raw.seq,
                    time: raw.time.clone(),
                },
            )
            .await?;
        Ok(())
    }

    pub async fn verify_sync(
        &self,
        raw: &RawSync,
    ) -> Result<Option<Vec<VerifierOp>>, VerifierError> {
        let rev = parse_sync_rev(raw)?;
        self.reject_future_sync_rev(raw, rev)?;

        let _guard = self.lock_for(&raw.did).lock().await;
        self.check_hosting_gate_for_did(&raw.did).await?;

        let chain = self.options.state_store.load_chain(&raw.did).await?;
        if is_rev_replay(&raw.did, rev, chain.as_ref())? {
            self.stats
                .rev_replays_dropped
                .fetch_add(1, Ordering::Relaxed);
            return Ok(None);
        }

        // No-op fast path: a `#sync` CAR carries only the signed commit block.
        // When its data CID matches persisted state the upstream is merely
        // confirming current state, so we validate envelope/inner fields and
        // signature, then advance the rev without fetching the full repo.
        //
        // A CAR *decode* failure is a transport-level glitch (truncated CAR,
        // etc.) and falls through to resync — getRepo is the right recovery.
        // Field or signature failures, by contrast, are intentional
        // malformation and surface as typed errors that bypass policy: a
        // forged commit reusing our data CID with a future rev would otherwise
        // poison the rev tracker and silently drop every legitimate follow-on
        // event below the forged rev.
        if let Some(chain) = chain.as_ref()
            && !raw.blocks.is_empty()
            && raw.blocks.len() <= MAX_COMMIT_BLOCKS_BYTES
        {
            match decode_sync_commit(&raw.did, &raw.rev, &raw.blocks) {
                Ok(inner) if inner.data == chain.data => {
                    self.check_sync_fields(raw, rev, &inner)?;
                    self.verify_signature(&raw.did, inner.rev, &inner).await?;
                    self.options
                        .state_store
                        .save_chain(
                            &raw.did,
                            ChainState {
                                rev: rev.to_string(),
                                data: inner.data,
                            },
                        )
                        .await?;
                    self.stats.sync_no_ops.fetch_add(1, Ordering::Relaxed);
                    return Ok(None);
                }
                // Data CID mismatch (our state and the upstream disagree) or a
                // decode failure (transport noise): getRepo is authoritative.
                Ok(_) | Err(_) => {}
            }
        }

        drop(_guard);
        self.resync(&raw.did).await.map(Some)
    }

    pub async fn resync(&self, did: &Did) -> Result<Vec<VerifierOp>, VerifierError> {
        match self.resync_inner(did).await {
            Ok(ops) => Ok(ops),
            // Rate limiting is a deliberate throttle, not a fetch/validation
            // failure: surface it verbatim and count it separately so it does
            // not inflate resync_failures.
            Err(err @ VerifierError::ResyncRateLimited { .. }) => {
                self.stats
                    .resync_rate_limited
                    .fetch_add(1, Ordering::Relaxed);
                Err(err)
            }
            Err(err) => {
                let err = wrap_resync_error(did, err);
                self.stats.resync_failures.fetch_add(1, Ordering::Relaxed);
                self.count_resync_error(&err);
                Err(err)
            }
        }
    }

    /// Consume one token from the per-DID resync bucket. Returns false when the
    /// DID has exhausted its budget. Buckets refill lazily using the injectable
    /// clock; the map is bounded by `resync_limiter_capacity` with eviction of
    /// the most-replenished bucket (the least likely to be throttling).
    async fn allow_resync(&self, did: &Did) -> bool {
        let limit = self.options.resync_rate_limit;
        if !limit.is_enabled() {
            return true;
        }
        let now = (self.options.now)();
        let mut limiters = self.resync_limiters.lock().await;

        if !limiters.contains_key(did) && limiters.len() >= self.options.resync_limiter_capacity {
            evict_fullest_bucket(&mut limiters);
        }

        let bucket = limiters.entry(did.clone()).or_insert_with(|| TokenBucket {
            tokens: limit.burst,
            last_refill: now,
        });

        let elapsed = now
            .duration_since(bucket.last_refill)
            .unwrap_or_default()
            .as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * limit.per_second).min(limit.burst);
        bucket.last_refill = now;

        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            true
        } else {
            false
        }
    }

    async fn handle_recoverable_resync(
        &self,
        raw: &RawCommit,
        chain: Option<&ChainState>,
        err: VerifierError,
        allow_async_resync: bool,
    ) -> Result<Option<Vec<VerifierOp>>, VerifierError> {
        if self.options.verifier_policy == VerifierPolicy::Resync
            && allow_async_resync
            && self.options.async_resync_workers > 0
            && !self.async_resync.closed.load(Ordering::SeqCst)
        {
            self.enqueue_resync(raw, chain.map(|state| state.rev.clone()), err)
                .await;
            return Ok(None);
        }
        Err(err)
    }

    async fn enqueue_resync(&self, raw: &RawCommit, old_rev: Option<String>, err: VerifierError) {
        let did = raw.repo.clone();
        let reason = err.to_string();
        let mut pending = self.async_resync.pending.lock().await;
        if let Some(state) = pending.get_mut(&did) {
            if state.commits.len() >= self.options.pending_queue_capacity {
                let overflow = VerifierError::BufferOverflow {
                    did,
                    len: state.commits.len(),
                    limit: self.options.pending_queue_capacity,
                };
                drop(pending);
                self.send_async_error(overflow).await;
                return;
            }
            state.commits.push_back(raw.clone());
            return;
        }

        pending.insert(
            did.clone(),
            PendingResync {
                old_rev,
                reason,
                commits: VecDeque::new(),
            },
        );
        drop(pending);
        self.spawn_resync_job(did);
    }

    async fn buffer_commit_if_resyncing(&self, raw: &RawCommit) -> bool {
        if self.options.async_resync_workers == 0 || self.async_resync.closed.load(Ordering::SeqCst)
        {
            return false;
        }
        let mut overflow = None;
        let buffered = {
            let mut pending = self.async_resync.pending.lock().await;
            let Some(state) = pending.get_mut(&raw.repo) else {
                return false;
            };
            if state.commits.len() >= self.options.pending_queue_capacity {
                overflow = Some(VerifierError::BufferOverflow {
                    did: raw.repo.clone(),
                    len: state.commits.len(),
                    limit: self.options.pending_queue_capacity,
                });
            } else {
                state.commits.push_back(raw.clone());
            }
            true
        };
        if let Some(err) = overflow {
            self.send_async_error(err).await;
        }
        buffered
    }

    fn spawn_resync_job(&self, did: Did) {
        let verifier = self.clone();
        let handle = tokio::spawn(async move {
            verifier.run_resync_job(did).await;
        });
        if let Ok(mut handles) = self.async_resync.handles.lock() {
            handles.retain(|handle| !handle.is_finished());
            handles.push(handle);
        }
    }

    async fn run_resync_job(&self, did: Did) {
        let (old_rev, reason) = {
            let pending = self.async_resync.pending.lock().await;
            let Some(state) = pending.get(&did) else {
                return;
            };
            (state.old_rev.clone(), state.reason.clone())
        };

        let mut ops = match self.resync(&did).await {
            Ok(ops) => ops,
            Err(err) => {
                self.finish_resync_job(&did).await;
                self.send_async_error(err).await;
                return;
            }
        };

        loop {
            let pending_commits = {
                let mut pending = self.async_resync.pending.lock().await;
                match pending.get_mut(&did) {
                    Some(state) => state.commits.drain(..).collect::<Vec<_>>(),
                    None => Vec::new(),
                }
            };

            if pending_commits.is_empty() {
                let mut pending = self.async_resync.pending.lock().await;
                if let Some(state) = pending.get(&did)
                    && state.commits.is_empty()
                {
                    pending.remove(&did);
                    break;
                }
                continue;
            }

            for commit in pending_commits {
                match self.verify_commit_internal(&commit, false).await {
                    Ok(Some(mut commit_ops)) => ops.append(&mut commit_ops),
                    Ok(None) => {}
                    Err(err) => self.send_async_error(err).await,
                }
            }
        }

        let new_rev = match self.options.state_store.load_chain(&did).await {
            Ok(Some(state)) => state.rev,
            Ok(None) => String::new(),
            Err(err) => {
                self.send_async_error(VerifierError::StateStore(err)).await;
                String::new()
            }
        };
        self.send_resync_event(ResyncEvent {
            did,
            old_rev,
            new_rev,
            reason,
            ops,
        })
        .await;
    }

    async fn finish_resync_job(&self, did: &Did) {
        self.async_resync.pending.lock().await.remove(did);
    }

    async fn send_resync_event(&self, event: ResyncEvent) {
        let tx = clone_sender(&self.async_resync.event_tx);
        if let Some(tx) = tx {
            let _ = tx.send(event).await;
        }
    }

    async fn send_async_error(&self, err: VerifierError) {
        let tx = clone_sender(&self.async_resync.error_tx);
        if let Some(tx) = tx {
            let _ = tx.send(err).await;
        }
    }

    fn lock_for(&self, did: &Did) -> &Mutex<()> {
        &self.locks[lock_stripe(did)]
    }

    fn reject_future_rev(&self, raw: &RawCommit) -> Result<(), VerifierError> {
        let now_micros = (self.options.now)()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let tolerance_micros = self.options.future_rev_tolerance.as_micros() as u64;
        if raw.rev.timestamp_micros() > now_micros.saturating_add(tolerance_micros) {
            self.stats
                .future_revs_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::FutureRev {
                did: raw.repo.clone(),
                rev: raw.rev.to_string(),
            });
        }
        Ok(())
    }

    fn reject_future_sync_rev(&self, raw: &RawSync, rev: Tid) -> Result<(), VerifierError> {
        let now_micros = (self.options.now)()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_micros() as u64;
        let tolerance_micros = self.options.future_rev_tolerance.as_micros() as u64;
        if rev.timestamp_micros() > now_micros.saturating_add(tolerance_micros) {
            self.stats
                .future_revs_rejected
                .fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::FutureRev {
                did: raw.did.clone(),
                rev: raw.rev.clone(),
            });
        }
        Ok(())
    }

    fn reject_oversized(&self, raw: &RawCommit) -> Result<(), VerifierError> {
        // `tooBig` is deprecated in Sync 1.1: producers must set it to false and
        // consumers must ignore it (the spec replaces it with the size limits
        // enforced below). We parse it for completeness but never gate on it.
        if raw.blocks.len() > MAX_COMMIT_BLOCKS_BYTES {
            self.stats.oversized_commits.fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::OversizedCommit {
                did: raw.repo.clone(),
                rev: Some(raw.rev.to_string()),
                field: "blocks",
                bytes: raw.blocks.len(),
                limit: MAX_COMMIT_BLOCKS_BYTES,
            });
        }
        if raw.ops.len() > MAX_COMMIT_OPS {
            self.stats.oversized_commits.fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::OversizedCommit {
                did: raw.repo.clone(),
                rev: Some(raw.rev.to_string()),
                field: "ops",
                bytes: raw.ops.len(),
                limit: MAX_COMMIT_OPS,
            });
        }
        Ok(())
    }

    async fn check_hosting_gate(&self, raw: &RawCommit) -> Result<(), VerifierError> {
        self.check_hosting_gate_for_did(&raw.repo).await
    }

    async fn check_hosting_gate_for_did(&self, did: &Did) -> Result<(), VerifierError> {
        if self.options.hosting_policy != HostingPolicy::Gate {
            return Ok(());
        }
        let hosting = self.options.state_store.load_hosting(did).await?;
        if HostingState::is_active(hosting.as_ref()) {
            return Ok(());
        }

        self.stats.accounts_inactive.fetch_add(1, Ordering::Relaxed);
        Err(VerifierError::RepoInactive {
            did: did.clone(),
            status: hosting.as_ref().and_then(|state| state.status.clone()),
            seq: hosting.as_ref().map(|state| state.seq),
            time: hosting.as_ref().map(|state| state.time.clone()),
        })
    }

    fn previous_root(
        &self,
        raw: &RawCommit,
        inner: &crate::repo::Commit,
        store: &crate::sync::CarBlockStore,
        chain: Option<&ChainState>,
    ) -> Result<Option<Cid>, VerifierError> {
        if chain.is_none() {
            return Ok(None);
        }
        if self.is_legacy_shape(raw, chain) {
            self.stats.legacy_commits.fetch_add(1, Ordering::Relaxed);
            if self.options.legacy_commit_policy == LegacyCommitPolicy::Reject {
                return Err(VerifierError::LegacyCommit {
                    did: raw.repo.clone(),
                    rev: raw.rev.to_string(),
                    seen_rev: chain.map(|state| state.rev.clone()),
                    seen_data: chain.map(|state| state.data),
                });
            }
            return Ok(None);
        }
        invert_decoded_commit(raw, inner, store).map(Some)
    }

    fn is_legacy_shape(&self, raw: &RawCommit, chain: Option<&ChainState>) -> bool {
        chain.is_some()
            && raw.prev_data.is_none()
            && !raw.ops.is_empty()
            && raw.ops.iter().all(|op| op.prev.is_none())
    }

    fn check_chain(
        &self,
        raw: &RawCommit,
        chain: Option<&ChainState>,
        previous_root: Option<Cid>,
    ) -> Result<Option<VerifierError>, VerifierError> {
        let Some(chain) = chain else {
            return Ok(None);
        };

        if previous_root.is_none() {
            return Ok(None);
        }

        let expected = Some(chain.data);
        if raw.prev_data == expected && previous_root != expected {
            if self.options.lenient_inversion {
                self.stats
                    .inversion_incomplete
                    .fetch_add(1, Ordering::Relaxed);
                return Ok(None);
            }
            self.stats.chain_breaks.fetch_add(1, Ordering::Relaxed);
            let err = VerifierError::ChainBreak {
                did: raw.repo.clone(),
                rev: raw.rev.to_string(),
                expected,
                actual: previous_root,
            };
            return match self.options.verifier_policy {
                VerifierPolicy::Error => Ok(Some(err)),
                VerifierPolicy::Resync => Err(VerifierError::ResyncRequired {
                    did: raw.repo.clone(),
                    reason: err.to_string(),
                }),
            };
        }
        if raw.prev_data == expected && previous_root == expected {
            return Ok(None);
        }

        let err = VerifierError::ChainBreak {
            did: raw.repo.clone(),
            rev: raw.rev.to_string(),
            expected,
            actual: raw.prev_data.or(previous_root),
        };
        self.stats.chain_breaks.fetch_add(1, Ordering::Relaxed);

        match self.options.verifier_policy {
            VerifierPolicy::Error => Ok(Some(err)),
            VerifierPolicy::Resync => Err(VerifierError::ResyncRequired {
                did: raw.repo.clone(),
                reason: err.to_string(),
            }),
        }
    }

    fn check_fields(
        &self,
        raw: &RawCommit,
        inner: &crate::repo::Commit,
    ) -> Result<(), VerifierError> {
        if inner.did != raw.repo {
            return self.field_mismatch(
                raw,
                "did",
                raw.repo.as_str().to_owned(),
                inner.did.as_str().to_owned(),
            );
        }
        if inner.rev != raw.rev {
            return self.field_mismatch(raw, "rev", raw.rev.to_string(), inner.rev.to_string());
        }
        if inner.version != 3 {
            return self.field_mismatch(raw, "version", "3".to_owned(), inner.version.to_string());
        }
        Ok(())
    }

    fn check_sync_fields(
        &self,
        raw: &RawSync,
        rev: Tid,
        inner: &crate::repo::Commit,
    ) -> Result<(), VerifierError> {
        if inner.did != raw.did {
            self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::FieldMismatch {
                did: raw.did.clone(),
                rev: Some(raw.rev.clone()),
                field: "did",
                expected: raw.did.as_str().to_owned(),
                actual: inner.did.as_str().to_owned(),
            });
        }
        if inner.rev != rev {
            self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::FieldMismatch {
                did: raw.did.clone(),
                rev: Some(raw.rev.clone()),
                field: "rev",
                expected: raw.rev.clone(),
                actual: inner.rev.to_string(),
            });
        }
        if inner.version != 3 {
            self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
            return Err(VerifierError::FieldMismatch {
                did: raw.did.clone(),
                rev: Some(raw.rev.clone()),
                field: "version",
                expected: "3".to_owned(),
                actual: inner.version.to_string(),
            });
        }
        Ok(())
    }

    fn field_mismatch<T>(
        &self,
        raw: &RawCommit,
        field: &'static str,
        expected: String,
        actual: String,
    ) -> Result<T, VerifierError> {
        self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
        Err(VerifierError::FieldMismatch {
            did: raw.repo.clone(),
            rev: Some(raw.rev.to_string()),
            field,
            expected,
            actual,
        })
    }

    async fn verify_signature(
        &self,
        did: &Did,
        rev: Tid,
        inner: &crate::repo::Commit,
    ) -> Result<(), VerifierError> {
        match self.verify_signature_once(did, inner).await {
            Ok(()) => Ok(()),
            Err(SignatureAttemptError::Identity(err)) => Err(err),
            Err(SignatureAttemptError::Invalid(first_reason)) => {
                self.options
                    .identity_resolver
                    .purge(did)
                    .await
                    .map_err(|source| VerifierError::Identity {
                        did: did.clone(),
                        source,
                    })?;
                match self.verify_signature_once(did, inner).await {
                    Ok(()) => Ok(()),
                    Err(SignatureAttemptError::Identity(err)) => Err(err),
                    Err(SignatureAttemptError::Invalid(second_reason)) => {
                        self.stats
                            .signature_failures
                            .fetch_add(1, Ordering::Relaxed);
                        Err(VerifierError::SignatureInvalid {
                            did: did.clone(),
                            rev: rev.to_string(),
                            reason: format!("{first_reason}; after refresh: {second_reason}"),
                        })
                    }
                }
            }
        }
    }

    async fn verify_signature_once(
        &self,
        did: &Did,
        inner: &crate::repo::Commit,
    ) -> Result<(), SignatureAttemptError> {
        let identity = self
            .options
            .identity_resolver
            .lookup_did(did)
            .await
            .map_err(|source| {
                SignatureAttemptError::Identity(VerifierError::Identity {
                    did: did.clone(),
                    source,
                })
            })?;
        let key = identity.signing_key().ok_or_else(|| {
            SignatureAttemptError::Invalid("identity has no #atproto signing key".to_owned())
        })?;
        inner
            .verify(key)
            .map_err(|err| SignatureAttemptError::Invalid(err.to_string()))
    }

    async fn resync_inner(&self, did: &Did) -> Result<Vec<VerifierOp>, VerifierError> {
        {
            let _guard = self.lock_for(did).lock().await;
            self.check_hosting_gate_for_did(did).await?;
        }

        if !self.allow_resync(did).await {
            return Err(VerifierError::ResyncRateLimited { did: did.clone() });
        }

        let source =
            self.options
                .repo_source
                .as_ref()
                .ok_or_else(|| VerifierError::ResyncRequired {
                    did: did.clone(),
                    reason: "no sync repo source configured".to_owned(),
                })?;
        let car = source
            .get_repo_car(did)
            .await
            .map_err(|err| VerifierError::ResyncRequired {
                did: did.clone(),
                reason: err.to_string(),
            })?;
        let loaded = load_repo_from_car(did, &car, self.options.repo_load_limits)?;
        self.verify_loaded_repo(did, &loaded).await?;

        let _guard = self.lock_for(did).lock().await;
        self.check_hosting_gate_for_did(did).await?;
        let chain = self.options.state_store.load_chain(did).await?;
        if let Some(chain) = chain.as_ref() {
            let current_rev =
                Tid::try_from(chain.rev.as_str()).map_err(|_| VerifierError::FieldMismatch {
                    did: did.clone(),
                    rev: Some(loaded.commit.rev.to_string()),
                    field: "chain.rev",
                    expected: "valid TID".to_owned(),
                    actual: chain.rev.clone(),
                })?;
            if loaded.commit.rev < current_rev
                || (loaded.commit.rev == current_rev && loaded.commit.data != chain.data)
            {
                return Err(VerifierError::RevRegression {
                    did: did.clone(),
                    current: chain.rev.clone(),
                    fetched: loaded.commit.rev.to_string(),
                });
            }
        }

        self.options
            .state_store
            .save_chain(
                did,
                ChainState {
                    rev: loaded.commit.rev.to_string(),
                    data: loaded.commit.data,
                },
            )
            .await?;
        self.stats.resyncs.fetch_add(1, Ordering::Relaxed);
        Ok(loaded.ops)
    }

    async fn verify_loaded_repo(
        &self,
        did: &Did,
        loaded: &LoadedRepo,
    ) -> Result<(), VerifierError> {
        if loaded.commit.did != *did {
            return Err(VerifierError::FieldMismatch {
                did: did.clone(),
                rev: Some(loaded.commit.rev.to_string()),
                field: "did",
                expected: did.as_str().to_owned(),
                actual: loaded.commit.did.as_str().to_owned(),
            });
        }
        self.verify_signature(did, loaded.commit.rev, &loaded.commit)
            .await
    }

    async fn save_chain(
        &self,
        raw: &RawCommit,
        data: Cid,
        original_error: Option<&VerifierError>,
    ) -> Result<(), VerifierError> {
        match self
            .options
            .state_store
            .save_chain(
                &raw.repo,
                ChainState {
                    rev: raw.rev.to_string(),
                    data,
                },
            )
            .await
        {
            Ok(()) => Ok(()),
            Err(err) => {
                if original_error.is_some() {
                    self.stats
                        .chain_state_save_failures
                        .fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
                Err(VerifierError::StateStore(err))
            }
        }
    }

    fn count_decode_error(&self, err: &VerifierError) {
        match err {
            VerifierError::FieldMismatch { .. } => {
                self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
            }
            VerifierError::DuplicatePath { .. } => {
                self.stats.duplicate_paths.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn count_resync_error(&self, err: &VerifierError) {
        let inner = match err {
            VerifierError::ResyncFailed { source, .. } => source.as_ref(),
            err => err,
        };
        match inner {
            VerifierError::OversizedCommit { .. } => {
                self.stats.oversized_commits.fetch_add(1, Ordering::Relaxed);
            }
            VerifierError::FieldMismatch { .. } => {
                self.stats.field_mismatches.fetch_add(1, Ordering::Relaxed);
            }
            VerifierError::OpCidMismatch { .. } => {
                self.stats.op_cid_mismatches.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    fn count_inversion_error(&self, err: &VerifierError) {
        match err {
            VerifierError::DuplicatePath { .. } => {
                self.stats.duplicate_paths.fetch_add(1, Ordering::Relaxed);
            }
            _ => {
                self.stats
                    .inversion_failures
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

enum SignatureAttemptError {
    Identity(VerifierError),
    Invalid(String),
}

fn is_rev_replay(did: &Did, rev: Tid, chain: Option<&ChainState>) -> Result<bool, VerifierError> {
    let Some(chain) = chain else {
        return Ok(false);
    };
    let chain_rev =
        Tid::try_from(chain.rev.as_str()).map_err(|_| VerifierError::FieldMismatch {
            did: did.clone(),
            rev: Some(rev.to_string()),
            field: "chain.rev",
            expected: "valid TID".to_owned(),
            actual: chain.rev.clone(),
        })?;
    Ok(rev <= chain_rev)
}

fn parse_sync_rev(raw: &RawSync) -> Result<Tid, VerifierError> {
    Tid::try_from(raw.rev.as_str()).map_err(|_| VerifierError::FieldMismatch {
        did: raw.did.clone(),
        rev: Some(raw.rev.clone()),
        field: "rev",
        expected: "valid TID".to_owned(),
        actual: raw.rev.clone(),
    })
}

fn wrap_resync_error(did: &Did, err: VerifierError) -> VerifierError {
    match err {
        VerifierError::ResyncFailed { .. } => err,
        err => VerifierError::ResyncFailed {
            did: did.clone(),
            source: Box::new(err),
        },
    }
}

fn closed_receiver<T>() -> mpsc::Receiver<T> {
    let (tx, rx) = mpsc::channel(1);
    drop(tx);
    rx
}

fn take_receiver<T>(mutex: &StdMutex<Option<mpsc::Receiver<T>>>) -> Option<mpsc::Receiver<T>> {
    mutex.lock().ok().and_then(|mut guard| guard.take())
}

fn take_sender<T>(mutex: &StdMutex<Option<mpsc::Sender<T>>>) -> Option<mpsc::Sender<T>> {
    mutex.lock().ok().and_then(|mut guard| guard.take())
}

fn clone_sender<T>(mutex: &StdMutex<Option<mpsc::Sender<T>>>) -> Option<mpsc::Sender<T>> {
    mutex.lock().ok().and_then(|guard| guard.clone())
}

/// Evict the bucket with the most tokens — the DID least likely to be actively
/// throttled, so dropping it loses the least useful throttling state.
fn evict_fullest_bucket(limiters: &mut HashMap<Did, TokenBucket>) {
    if let Some(key) = limiters
        .iter()
        .max_by(|a, b| a.1.tokens.total_cmp(&b.1.tokens))
        .map(|(did, _)| did.clone())
    {
        limiters.remove(&key);
    }
}

fn lock_stripe(did: &Did) -> usize {
    let mut hasher = DefaultHasher::new();
    did.hash(&mut hasher);
    (hasher.finish() as usize) % VERIFIER_LOCK_STRIPES
}
