use std::collections::HashMap;
use std::hash::Hash;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use async_trait::async_trait;

use crate::lexicon::resolver::{FetchedRecord, LexiconResolveError, ResolvedLexicon};
use crate::syntax::{Did, Nsid};

/// Where a resolution step's result came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolutionSource {
    /// A hook supplied it ([`LexiconResolverHooks::on_resolve_authority`] or
    /// [`LexiconResolverHooks::on_fetch`]), e.g. from a cache.
    Hook,
    /// It was resolved from the network.
    Network,
}

/// Callbacks that observe and short-circuit Lexicon resolution, typically to
/// cache it. Every method has a no-op default.
///
/// Each step runs `on_<step>` first; if it returns a value, the network is
/// skipped. Then exactly one of `on_<step>_result` or `on_<step>_error` runs,
/// whether the value came from the hook or the network.
///
/// A record from [`on_fetch`](Self::on_fetch) is still checked against its
/// CID and validated as a Lexicon document, but it is not re-verified against
/// the repository's signing key: return only records that were verified when
/// they were first resolved, such as those passed to
/// [`on_fetch_result`](Self::on_fetch_result). Implementations backed by
/// remote storage should treat their own failures as a miss (`None`).
///
/// [`MemoryLexiconCache`] is the default implementation.
#[async_trait]
pub trait LexiconResolverHooks: Send + Sync {
    /// Supply the authority DID for `nsid` instead of resolving it via DNS.
    async fn on_resolve_authority(&self, _nsid: &Nsid) -> Option<Did> {
        None
    }

    /// Called after the authority DID for `nsid` is known.
    async fn on_resolve_authority_result(
        &self,
        _nsid: &Nsid,
        _did: &Did,
        _source: ResolutionSource,
    ) {
    }

    /// Called when resolving the authority for `nsid` fails.
    async fn on_resolve_authority_error(&self, _nsid: &Nsid, _err: &LexiconResolveError) {}

    /// Supply the Lexicon record `did` publishes for `nsid` instead of
    /// fetching it from the network.
    async fn on_fetch(&self, _did: &Did, _nsid: &Nsid) -> Option<FetchedRecord> {
        None
    }

    /// Called after a Lexicon record is fetched and validated.
    async fn on_fetch_result(
        &self,
        _did: &Did,
        _nsid: &Nsid,
        _lexicon: &ResolvedLexicon,
        _source: ResolutionSource,
    ) {
    }

    /// Called when fetching or validating a Lexicon record fails.
    async fn on_fetch_error(&self, _did: &Did, _nsid: &Nsid, _err: &LexiconResolveError) {}
}

/// Hooks that do nothing: every resolution goes to the network.
#[derive(Debug, Clone, Copy, Default)]
pub struct NoHooks;

impl LexiconResolverHooks for NoHooks {}

const DEFAULT_AUTHORITY_TTL: Duration = Duration::from_secs(5 * 60);
const DEFAULT_RECORD_TTL: Duration = Duration::from_secs(60 * 60);
const DEFAULT_CAPACITY: usize = 1024;

/// The default [`LexiconResolverHooks`]: a bounded, in-memory TTL cache of
/// authority DIDs (keyed by NSID authority, so one lookup serves a whole NSID
/// group) and of verified Lexicon records (keyed by DID and NSID).
///
/// Authorities are cached briefly by default (5 minutes): the Lexicon spec
/// asks resolvers not to cache DNS results for long, since authority changes
/// are not announced anywhere. Records are cached for an hour. Failures are
/// not cached.
pub struct MemoryLexiconCache {
    authorities: Mutex<TtlMap<String, Did>>,
    records: Mutex<TtlMap<(Did, Nsid), FetchedRecord>>,
}

impl MemoryLexiconCache {
    /// Create a cache with the default TTLs and a capacity of 1024 entries
    /// per map.
    pub fn new() -> Self {
        MemoryLexiconCache {
            authorities: Mutex::new(TtlMap::new(DEFAULT_AUTHORITY_TTL, DEFAULT_CAPACITY)),
            records: Mutex::new(TtlMap::new(DEFAULT_RECORD_TTL, DEFAULT_CAPACITY)),
        }
    }

    /// Set how long a resolved authority DID is reused.
    pub fn with_authority_ttl(self, ttl: Duration) -> Self {
        lock(&self.authorities).ttl = ttl;
        self
    }

    /// Set how long a verified Lexicon record is reused.
    pub fn with_record_ttl(self, ttl: Duration) -> Self {
        lock(&self.records).ttl = ttl;
        self
    }

    /// Set the maximum number of entries in each map. When full, expired
    /// entries are dropped first, then the entry closest to expiry.
    pub fn with_capacity(self, capacity: usize) -> Self {
        lock(&self.authorities).capacity = capacity;
        lock(&self.records).capacity = capacity;
        self
    }

    /// Drop everything cached for `nsid`: its group's authority and every
    /// record for it.
    pub fn purge(&self, nsid: &Nsid) {
        lock(&self.authorities).map.remove(&nsid.authority());
        lock(&self.records).map.retain(|(_, n), _| n != nsid);
    }

    /// Drop everything.
    pub fn clear(&self) {
        lock(&self.authorities).map.clear();
        lock(&self.records).map.clear();
    }
}

impl Default for MemoryLexiconCache {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl LexiconResolverHooks for MemoryLexiconCache {
    async fn on_resolve_authority(&self, nsid: &Nsid) -> Option<Did> {
        lock(&self.authorities).get(&nsid.authority())
    }

    async fn on_resolve_authority_result(&self, nsid: &Nsid, did: &Did, source: ResolutionSource) {
        // Re-inserting a hit would extend its lifetime indefinitely.
        if source == ResolutionSource::Network {
            lock(&self.authorities).insert(nsid.authority(), did.clone());
        }
    }

    async fn on_fetch(&self, did: &Did, nsid: &Nsid) -> Option<FetchedRecord> {
        lock(&self.records).get(&(did.clone(), nsid.clone()))
    }

    async fn on_fetch_result(
        &self,
        did: &Did,
        nsid: &Nsid,
        lexicon: &ResolvedLexicon,
        source: ResolutionSource,
    ) {
        if source == ResolutionSource::Network {
            lock(&self.records).insert(
                (did.clone(), nsid.clone()),
                FetchedRecord {
                    cid: lexicon.cid,
                    record: lexicon.record.clone(),
                },
            );
        }
    }
}

/// Lock a mutex, recovering from poisoning: the maps hold no invariants a
/// panicking holder could break.
fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|e| e.into_inner())
}

struct TtlMap<K, V> {
    map: HashMap<K, (V, Instant)>,
    ttl: Duration,
    capacity: usize,
}

impl<K: Hash + Eq + Clone, V: Clone> TtlMap<K, V> {
    fn new(ttl: Duration, capacity: usize) -> Self {
        TtlMap {
            map: HashMap::new(),
            ttl,
            capacity,
        }
    }

    fn get(&mut self, key: &K) -> Option<V> {
        let (value, expires) = self.map.get(key)?;
        if *expires > Instant::now() {
            return Some(value.clone());
        }
        self.map.remove(key);
        None
    }

    fn insert(&mut self, key: K, value: V) {
        if self.capacity == 0 || self.ttl.is_zero() {
            return;
        }
        let now = Instant::now();
        if self.map.len() >= self.capacity && !self.map.contains_key(&key) {
            self.map.retain(|_, (_, expires)| *expires > now);
            if self.map.len() >= self.capacity
                && let Some(oldest) = self
                    .map
                    .iter()
                    .min_by_key(|(_, (_, expires))| *expires)
                    .map(|(k, _)| k.clone())
            {
                self.map.remove(&oldest);
            }
        }
        let expires = now
            .checked_add(self.ttl)
            .or_else(|| now.checked_add(DEFAULT_RECORD_TTL))
            .unwrap_or(now);
        self.map.insert(key, (value, expires));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn ttl_map_expires_entries() {
        let mut m = TtlMap::new(Duration::from_millis(30), 10);
        m.insert("a", 1);
        assert_eq!(m.get(&"a"), Some(1));
        std::thread::sleep(Duration::from_millis(40));
        assert_eq!(m.get(&"a"), None);
        assert!(m.map.is_empty(), "expired entry is dropped on read");
    }

    #[test]
    fn ttl_map_is_bounded_and_evicts_soonest_expiry() {
        let mut m = TtlMap::new(Duration::from_secs(60), 3);
        for i in 0..3 {
            m.insert(i, i);
            std::thread::sleep(Duration::from_millis(2));
        }
        m.insert(3, 3);
        assert_eq!(m.map.len(), 3);
        assert_eq!(m.get(&0), None, "oldest entry evicted");
        for i in 1..4 {
            assert_eq!(m.get(&i), Some(i));
        }
        // Overwriting an existing key never evicts.
        m.insert(2, 20);
        assert_eq!(m.map.len(), 3);
        assert_eq!(m.get(&2), Some(20));
    }

    #[test]
    fn ttl_map_prefers_evicting_expired_entries() {
        let mut m = TtlMap::new(Duration::from_millis(20), 2);
        m.insert("old", 0);
        std::thread::sleep(Duration::from_millis(30));
        m.ttl = Duration::from_secs(60);
        m.insert("fresh", 1);
        m.insert("new", 2);
        assert_eq!(m.get(&"fresh"), Some(1));
        assert_eq!(m.get(&"new"), Some(2));
        assert_eq!(m.get(&"old"), None);
    }

    #[test]
    fn ttl_map_zero_capacity_or_ttl_stores_nothing() {
        let mut m = TtlMap::new(Duration::from_secs(60), 0);
        m.insert(1, 1);
        assert_eq!(m.get(&1), None);
        let mut m = TtlMap::new(Duration::ZERO, 10);
        m.insert(1, 1);
        assert_eq!(m.get(&1), None);
    }

    #[test]
    fn ttl_map_huge_ttl_does_not_overflow() {
        let mut m = TtlMap::new(Duration::MAX, 10);
        m.insert(1, 1);
        assert_eq!(m.get(&1), Some(1));
    }

    #[tokio::test]
    async fn memory_cache_keys_authorities_by_group() {
        let cache = MemoryLexiconCache::new();
        let post = Nsid::try_from("app.bsky.feed.post").unwrap();
        let like = Nsid::try_from("app.bsky.feed.like").unwrap();
        let other = Nsid::try_from("app.bsky.graph.follow").unwrap();
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();

        cache
            .on_resolve_authority_result(&post, &did, ResolutionSource::Network)
            .await;
        assert_eq!(cache.on_resolve_authority(&like).await, Some(did.clone()));
        assert_eq!(cache.on_resolve_authority(&other).await, None);

        cache.purge(&like);
        assert_eq!(cache.on_resolve_authority(&post).await, None);
    }

    #[tokio::test]
    async fn memory_cache_does_not_refresh_hits() {
        let cache = MemoryLexiconCache::new().with_authority_ttl(Duration::from_millis(30));
        let nsid = Nsid::try_from("com.example.thing").unwrap();
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        cache
            .on_resolve_authority_result(&nsid, &did, ResolutionSource::Network)
            .await;
        std::thread::sleep(Duration::from_millis(20));
        // A hook-sourced result (the cache's own hit) must not extend the TTL.
        cache
            .on_resolve_authority_result(&nsid, &did, ResolutionSource::Hook)
            .await;
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.on_resolve_authority(&nsid).await, None);
    }
}
