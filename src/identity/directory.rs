use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::syntax::Did;
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::identity::Identity;
use crate::identity::IdentityError;
use crate::identity::did_web::resolve_did_web;
use crate::identity::plc::PlcClient;

const DEFAULT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CAPACITY: usize = 1024;

struct CacheEntry {
    identity: Arc<Identity>,
    expires_at: Instant,
    generation: u64,
}

/// A caching identity resolver that supports `did:plc` and `did:web`.
pub struct Directory {
    plc: PlcClient,
    http: reqwest::Client,
    cache: Mutex<HashMap<Did, CacheEntry>>,
    generation: AtomicU64,
    ttl: Duration,
    capacity: usize,
}

impl Directory {
    /// Create a Directory using the production PLC endpoint (`https://plc.directory`).
    pub fn new() -> Self {
        Self::with_plc_url("https://plc.directory")
    }

    /// Create a Directory with a custom PLC directory URL.
    pub fn with_plc_url(plc_url: &str) -> Self {
        Directory {
            plc: PlcClient::new(plc_url),
            http: reqwest::Client::new(),
            cache: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            ttl: DEFAULT_TTL,
            capacity: DEFAULT_CAPACITY,
        }
    }

    /// Resolve a DID to an `Arc<Identity>`, using the cache when possible.
    pub async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        let generation = self.generation.load(Ordering::Acquire);

        // Check cache first.
        {
            let cache = self.cache.lock().await;
            if let Some(entry) = cache.get(did)
                && entry.expires_at > Instant::now()
                && entry.generation == generation
            {
                return Ok(Arc::clone(&entry.identity));
            }
        }

        // Resolve via the appropriate method.
        let doc = match did.method() {
            "plc" => self.plc.resolve(did).await?,
            "web" => resolve_did_web(did, &self.http).await?,
            method => {
                return Err(IdentityError::NotFound(format!(
                    "unsupported DID method: {method}"
                )));
            }
        };

        let identity = Arc::new(Identity::from_document(doc)?);

        // Store in cache, evicting one stale entry if at capacity.
        let mut cache = self.cache.lock().await;
        if self.generation.load(Ordering::Acquire) != generation {
            return Ok(identity);
        }
        if cache.len() >= self.capacity && !cache.contains_key(did) {
            // Simple eviction: remove the first expired entry found, or any entry.
            let expired_key = cache
                .iter()
                .find(|(_, e)| e.expires_at <= Instant::now())
                .map(|(k, _)| k.clone());
            if let Some(k) = expired_key {
                cache.remove(&k);
            } else if let Some(k) = cache.keys().next().cloned() {
                cache.remove(&k);
            }
        }
        cache.insert(
            did.clone(),
            CacheEntry {
                identity: Arc::clone(&identity),
                expires_at: Instant::now() + self.ttl,
                generation,
            },
        );

        Ok(identity)
    }

    /// Remove a cached DID entry, forcing the next lookup to resolve it again.
    pub async fn purge(&self, did: &Did) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        self.cache.lock().await.remove(did);
    }
}

impl Default for Directory {
    fn default() -> Self {
        Self::new()
    }
}
