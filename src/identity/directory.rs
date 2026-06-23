use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use crate::syntax::{Did, Handle};
use tokio::sync::Mutex;
use tokio::time::Instant;

use crate::identity::Identity;
use crate::identity::IdentityError;
use crate::identity::did_web::resolve_did_web;
use crate::identity::handle::resolve_handle;
use crate::identity::plc::PlcClient;

const DEFAULT_TTL: Duration = Duration::from_secs(300);
const DEFAULT_CAPACITY: usize = 1024;

struct CacheEntry {
    identity: Arc<Identity>,
    expires_at: Instant,
    generation: u64,
}

/// A caching identity resolver that supports `did:plc` and `did:web`, plus
/// handle resolution (DNS `_atproto` TXT and HTTPS `.well-known/atproto-did`)
/// with bidirectional handle/DID verification.
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
            http: crate::outbound::hardened_client(),
            cache: Mutex::new(HashMap::new()),
            generation: AtomicU64::new(0),
            ttl: DEFAULT_TTL,
            capacity: DEFAULT_CAPACITY,
        }
    }

    /// Resolve a handle to a DID (forward direction only — **no** bidirectional
    /// verification). DNS `_atproto.<handle>` TXT is tried first, then the
    /// HTTPS `https://<handle>/.well-known/atproto-did` fallback.
    ///
    /// The returned DID is *claimed* by the handle's operator; it is only
    /// trustworthy once cross-checked against the DID document (use
    /// [`Directory::lookup_handle`], which does this).
    pub async fn resolve_handle(&self, handle: &Handle) -> Result<Did, IdentityError> {
        resolve_handle(handle, &self.http).await
    }

    /// Resolve a handle to a fully-verified [`Identity`].
    ///
    /// Resolves the handle to a DID, fetches that DID's document, and then
    /// requires the document to declare the same handle (bidirectional
    /// verification). Returns [`IdentityError::HandleMismatch`] if the DID
    /// document does not claim the handle back. The returned identity's
    /// `handle` field is the verified handle.
    pub async fn lookup_handle(&self, handle: &Handle) -> Result<Arc<Identity>, IdentityError> {
        let did = self.resolve_handle(handle).await?;
        let identity = self.lookup_did(&did).await?;
        match &identity.handle {
            Some(h) if h == handle => Ok(identity),
            _ => Err(IdentityError::HandleMismatch(format!(
                "handle {handle} resolved to {did}, but that DID document does not declare {handle}"
            ))),
        }
    }

    /// Resolve a DID to an `Arc<Identity>`, using the cache when possible.
    ///
    /// The identity's `handle` is bidirectionally verified: the DID document's
    /// declared handle is resolved back to a DID, and `handle` is set only if
    /// it round-trips to this same DID; otherwise it is `None` (the declared
    /// handle is untrusted).
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

        let mut identity = Identity::from_document(doc)?;

        // Bidirectionally verify the declared handle: resolve it back to a DID
        // and keep it only if it matches this DID. A declared handle that does
        // not resolve (or resolves elsewhere) is untrusted → clear to None.
        identity.handle = match identity.declared_handle() {
            Some(declared) => {
                let resolved = self.resolve_handle(&declared).await;
                verify_declared_handle(declared, resolved.as_ref().ok(), did)
            }
            None => None,
        };

        let identity = Arc::new(identity);

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

/// Decide whether a DID document's declared handle is bidirectionally verified.
///
/// Returns `Some(declared)` only if resolving the declared handle yielded
/// exactly the DID whose document declared it; otherwise `None` (the handle is
/// untrusted — it didn't resolve, or resolved to a different DID, i.e. an
/// impersonation attempt). Factored out so this security decision is unit-tested
/// independently of live DNS/HTTPS resolution.
fn verify_declared_handle(declared: Handle, resolved: Option<&Did>, did: &Did) -> Option<Handle> {
    match resolved {
        Some(resolved) if resolved == did => Some(declared),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did(s: &str) -> Did {
        Did::try_from(s).unwrap()
    }

    #[test]
    fn verify_handle_matches() {
        let d = did("did:plc:z72i7hdynmk6r22z27h6tvur");
        let h = Handle::try_from("alice.bsky.social").unwrap();
        // Declared handle resolves back to the same DID → verified.
        assert_eq!(verify_declared_handle(h.clone(), Some(&d), &d), Some(h));
    }

    #[test]
    fn verify_handle_resolves_to_different_did() {
        // Declared handle resolves to a DIFFERENT DID → impersonation → None.
        let doc_did = did("did:plc:z72i7hdynmk6r22z27h6tvur");
        let other = did("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa");
        let h = Handle::try_from("attacker.bsky.social").unwrap();
        assert_eq!(verify_declared_handle(h, Some(&other), &doc_did), None);
    }

    #[test]
    fn verify_handle_unresolvable() {
        // Declared handle does not resolve at all → untrusted → None.
        let d = did("did:plc:z72i7hdynmk6r22z27h6tvur");
        let h = Handle::try_from("ghost.bsky.social").unwrap();
        assert_eq!(verify_declared_handle(h, None, &d), None);
    }
}
