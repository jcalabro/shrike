//! Pluggable DNS TXT lookups.
//!
//! [`TxtResolver`] abstracts TXT queries so callers can inject their own DNS
//! (DNS-over-HTTPS, a test double, a caching layer). [`SystemTxtResolver`] is
//! the default, backed by hickory and the system resolver configuration.

use async_trait::async_trait;
use hickory_resolver::TokioResolver;

/// One TXT record: its character-strings, in wire order. Most records hold a
/// single string; values over 255 bytes are split across several.
pub type TxtRecord = Vec<Vec<u8>>;

/// Errors from a TXT lookup.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TxtError {
    /// The name does not exist (NXDOMAIN) or has no TXT records. This is an
    /// authoritative answer, safe to cache as a negative result.
    #[error("no TXT records for {0}")]
    NotFound(String),
    /// The lookup did not produce an answer: timeout, SERVFAIL, an unusable
    /// resolver configuration. Retrying later may succeed.
    #[error("TXT lookup for {name} failed: {message}")]
    Failed { name: String, message: String },
}

/// Resolves DNS TXT records.
#[async_trait]
pub trait TxtResolver: Send + Sync {
    /// Look up the TXT records at `name`, a fully qualified domain name
    /// without the trailing dot (e.g. `_lexicon.feed.bsky.app`).
    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, TxtError>;
}

/// [`TxtResolver`] using hickory with the system resolver configuration.
///
/// The underlying resolver is built on first use and shared across lookups,
/// so its record cache (which honors DNS TTLs) is shared too. Names are
/// queried as fully qualified, so the system search domains are never
/// appended.
#[derive(Default)]
pub struct SystemTxtResolver {
    resolver: tokio::sync::OnceCell<TokioResolver>,
}

impl SystemTxtResolver {
    /// Create a resolver. The system configuration is read on first lookup.
    pub fn new() -> Self {
        Self::default()
    }
}

#[async_trait]
impl TxtResolver for SystemTxtResolver {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, TxtError> {
        let failed = |message: String| TxtError::Failed {
            name: name.to_owned(),
            message,
        };
        let resolver = self
            .resolver
            .get_or_try_init(|| async {
                TokioResolver::builder_tokio()
                    .map(|b| b.build())
                    .map_err(|e| failed(format!("DNS resolver init: {e}")))
            })
            .await?;

        let fqdn = format!("{}.", name.trim_end_matches('.'));
        match resolver.txt_lookup(fqdn).await {
            Ok(lookup) => Ok(lookup
                .iter()
                .map(|txt| txt.txt_data().iter().map(|s| s.to_vec()).collect())
                .collect()),
            Err(e) if e.is_nx_domain() || e.is_no_records_found() => {
                Err(TxtError::NotFound(name.to_owned()))
            }
            Err(e) => Err(failed(e.to_string())),
        }
    }
}
