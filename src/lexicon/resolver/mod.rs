//! Network Lexicon resolution: fetch the authoritative, signed schema for an
//! NSID.
//!
//! [`LexiconResolver::get`] follows the Lexicon spec's publication chain:
//!
//! 1. **Authority**: the `_lexicon.<authority>` DNS TXT record names the DID
//!    that publishes the NSID group's schemas (see
//!    [`resolve_lexicon_authority`]).
//! 2. **Identity**: that DID resolves to a DID document with a PDS endpoint
//!    and a signing key.
//! 3. **Fetch**: `com.atproto.sync.getRecord` on the PDS returns a record
//!    proof for `com.atproto.lexicon.schema/<nsid>`.
//! 4. **Verify**: the proof's commit must be signed by the DID's key and
//!    include the record (see [`verify_record_proof`]).
//! 5. **Validate**: the record must be a valid Lexicon document whose `id` is
//!    the requested NSID.
//!
//! [`LexiconResolverHooks`] observe each step and can short-circuit it, which
//! is how caching works. [`MemoryLexiconCache`] is the default; bring your own
//! implementation to share a cache across processes.
//!
//! # Hardening
//!
//! The PDS endpoint comes from a DID document, so it is untrusted. Requests
//! use the same SSRF-hardened client as identity resolution: no redirects,
//! bounded timeouts, and (under the default [`AddressPolicy::DenyLocal`])
//! refusal of loopback, private, and link-local destinations, including
//! literal IP endpoints. Endpoints must be `http` or `https` without
//! credentials. Responses are capped at [`DEFAULT_MAX_PROOF_BYTES`], just over
//! the 1 MiB maximum record size, as in the reference implementation.
//!
//! Only native targets are supported: browsers cannot query DNS TXT records.

mod hooks;

use std::sync::Arc;
use std::time::Duration;

use crate::cbor::{Cid, Codec};
use crate::identity::{
    AddressPolicy, Directory, IdentityError, LexiconAuthorityError, SystemTxtResolver, TxtResolver,
    resolve_lexicon_authority,
};
use crate::lexicon::catalog::check_schema;
use crate::lexicon::{LexiconError, Schema};
use crate::repo::{ProofError, verify_record_proof};
use crate::syntax::{AtUri, Did, Nsid, RecordKey, SyntaxError};

pub use hooks::{LexiconResolverHooks, MemoryLexiconCache, NoHooks, ResolutionSource};

/// The collection Lexicon schema records are published in.
pub const LEXICON_SCHEMA_NSID: &str = "com.atproto.lexicon.schema";

/// Default cap on a record proof response: 1 MiB (the maximum record size)
/// plus 10 KiB for the commit and MST nodes, matching the reference.
pub const DEFAULT_MAX_PROOF_BYTES: usize = (1024 + 10) * 1024;

/// Default total timeout for the record fetch.
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Cap on an error response body, which is read only for its XRPC error name.
const MAX_ERROR_BODY_BYTES: usize = 16 * 1024;

/// A resolved and verified Lexicon.
#[derive(Debug, Clone)]
pub struct ResolvedLexicon {
    /// Where the schema record lives:
    /// `at://<did>/com.atproto.lexicon.schema/<nsid>`.
    pub uri: AtUri,
    /// CID of the schema record.
    pub cid: Cid,
    /// The parsed Lexicon document.
    pub schema: Schema,
    /// The record as atproto JSON, including `$type`. Pass its serialization
    /// to [`Catalog::add_schema`](crate::lexicon::Catalog::add_schema).
    pub json: serde_json::Value,
    /// The record's DRISL bytes.
    pub record: Vec<u8>,
}

/// A Lexicon schema record as stored in a repository: what
/// [`LexiconResolverHooks::on_fetch`] returns to skip the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchedRecord {
    /// CID of the record.
    pub cid: Cid,
    /// The record's DRISL bytes.
    pub record: Vec<u8>,
}

/// Errors from Lexicon resolution.
#[derive(Debug, thiserror::Error)]
pub enum LexiconResolveError {
    #[error("resolving Lexicon authority for {nsid}: {source}")]
    Authority {
        nsid: Nsid,
        #[source]
        source: LexiconAuthorityError,
    },
    #[error("resolving {did}: {source}")]
    Identity {
        did: Did,
        #[source]
        source: IdentityError,
    },
    #[error("DID document for {did} has no atproto PDS endpoint")]
    MissingPds { did: Did },
    #[error("DID document for {did} has no atproto signing key")]
    MissingSigningKey { did: Did },
    #[error("unusable PDS endpoint {endpoint:?} for {did}: {reason}")]
    InvalidPdsEndpoint {
        did: Did,
        endpoint: String,
        reason: String,
    },
    #[error("fetching {uri}: {message}")]
    Http { uri: AtUri, message: String },
    #[error("fetching {uri}: HTTP {status} {detail}")]
    HttpStatus {
        uri: AtUri,
        status: u16,
        /// The XRPC error name and message, if the body carried them.
        detail: String,
    },
    #[error("{uri} not found")]
    RecordNotFound { uri: AtUri },
    #[error("record proof for {uri} exceeds {limit} bytes")]
    TooLarge { uri: AtUri, limit: usize },
    #[error("verifying record proof for {uri}: {source}")]
    Proof {
        uri: AtUri,
        #[source]
        source: ProofError,
    },
    #[error("invalid Lexicon record at {uri}: {reason}")]
    InvalidRecord { uri: AtUri, reason: String },
    #[error("invalid Lexicon document at {uri}: {source}")]
    InvalidDocument {
        uri: AtUri,
        #[source]
        source: LexiconError,
    },
    #[error("Lexicon document id {id:?} at {uri} does not match its NSID")]
    IdMismatch { uri: AtUri, id: String },
    #[error(transparent)]
    Syntax(#[from] SyntaxError),
}

impl LexiconResolveError {
    /// Whether the failure may be temporary (DNS or network trouble, a
    /// server error, rate limiting), so retrying later could succeed. Other
    /// errors are definitive answers about the published data.
    pub fn is_transient(&self) -> bool {
        match self {
            Self::Authority { source, .. } => matches!(source, LexiconAuthorityError::Lookup(_)),
            Self::Identity { source, .. } => matches!(source, IdentityError::Network(_)),
            Self::Http { .. } => true,
            Self::HttpStatus { status, .. } => *status >= 500 || *status == 429,
            _ => false,
        }
    }
}

/// Resolves Lexicon documents from the network by NSID. See the
/// [module docs](self).
///
/// ```no_run
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// use shrike::lexicon::resolver::LexiconResolver;
/// use shrike::syntax::Nsid;
///
/// let resolver = LexiconResolver::new();
/// let lexicon = resolver.get(&Nsid::try_from("app.bsky.feed.post")?).await?;
/// println!("{} ({})", lexicon.uri, lexicon.cid);
/// # Ok(())
/// # }
/// ```
pub struct LexiconResolver {
    directory: Arc<Directory>,
    txt: Arc<dyn TxtResolver>,
    hooks: Arc<dyn LexiconResolverHooks>,
    http: reqwest::Client,
    address_policy: AddressPolicy,
    timeout: Duration,
    max_proof_bytes: usize,
}

impl LexiconResolver {
    /// Create a resolver using the production PLC directory, the system DNS
    /// resolver, a [`MemoryLexiconCache`], and [`AddressPolicy::DenyLocal`].
    pub fn new() -> Self {
        let address_policy = AddressPolicy::default();
        LexiconResolver {
            directory: Arc::new(Directory::new()),
            txt: Arc::new(SystemTxtResolver::new()),
            hooks: Arc::new(MemoryLexiconCache::new()),
            http: crate::outbound::hardened_client_with_timeout(address_policy, DEFAULT_TIMEOUT),
            address_policy,
            timeout: DEFAULT_TIMEOUT,
            max_proof_bytes: DEFAULT_MAX_PROOF_BYTES,
        }
    }

    /// Resolve DIDs through `directory` (and share its DID document cache).
    pub fn with_directory(mut self, directory: Arc<Directory>) -> Self {
        self.directory = directory;
        self
    }

    /// Query `_lexicon` TXT records through `txt`.
    pub fn with_txt_resolver(mut self, txt: Arc<dyn TxtResolver>) -> Self {
        self.txt = txt;
        self
    }

    /// Replace the default [`MemoryLexiconCache`] hooks. Pass [`NoHooks`] to
    /// disable caching.
    pub fn with_hooks(mut self, hooks: Arc<dyn LexiconResolverHooks>) -> Self {
        self.hooks = hooks;
        self
    }

    /// Set which addresses the record fetch may connect to. Pass
    /// [`AddressPolicy::AllowLocal`] only for PDSes on localhost or a private
    /// network you trust. The [`Directory`] has its own policy.
    pub fn with_address_policy(mut self, policy: AddressPolicy) -> Self {
        self.address_policy = policy;
        self.http = crate::outbound::hardened_client_with_timeout(policy, self.timeout);
        self
    }

    /// Set the total timeout for the record fetch (default 30 seconds).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self.http = crate::outbound::hardened_client_with_timeout(self.address_policy, timeout);
        self
    }

    /// Set the largest record proof response accepted (default
    /// [`DEFAULT_MAX_PROOF_BYTES`]).
    pub fn with_max_proof_bytes(mut self, max: usize) -> Self {
        self.max_proof_bytes = max;
        self
    }

    /// Resolve and fetch the Lexicon for `nsid`: [`resolve_authority`] then
    /// [`fetch`].
    ///
    /// [`resolve_authority`]: Self::resolve_authority
    /// [`fetch`]: Self::fetch
    pub async fn get(&self, nsid: &Nsid) -> Result<ResolvedLexicon, LexiconResolveError> {
        let did = self.resolve_authority(nsid).await?;
        self.fetch(&did, nsid).await
    }

    /// Resolve the DID that publishes the Lexicon for `nsid`, from the hooks
    /// or the `_lexicon` DNS TXT record.
    pub async fn resolve_authority(&self, nsid: &Nsid) -> Result<Did, LexiconResolveError> {
        let result = match self.hooks.on_resolve_authority(nsid).await {
            Some(did) => Ok((did, ResolutionSource::Hook)),
            None => resolve_lexicon_authority(&*self.txt, nsid)
                .await
                .map(|did| (did, ResolutionSource::Network))
                .map_err(|source| LexiconResolveError::Authority {
                    nsid: nsid.clone(),
                    source,
                }),
        };
        match result {
            Ok((did, source)) => {
                self.hooks
                    .on_resolve_authority_result(nsid, &did, source)
                    .await;
                Ok(did)
            }
            Err(err) => {
                self.hooks.on_resolve_authority_error(nsid, &err).await;
                Err(err)
            }
        }
    }

    /// Fetch, verify, and validate the Lexicon for `nsid` published by
    /// `did`, from the hooks or the network. Use this directly to resolve
    /// against a known authority without consulting DNS.
    pub async fn fetch(
        &self,
        did: &Did,
        nsid: &Nsid,
    ) -> Result<ResolvedLexicon, LexiconResolveError> {
        let result = self.fetch_and_validate(did, nsid).await;
        match &result {
            Ok((lexicon, source)) => {
                self.hooks
                    .on_fetch_result(did, nsid, lexicon, *source)
                    .await
            }
            Err(err) => self.hooks.on_fetch_error(did, nsid, err).await,
        }
        result.map(|(lexicon, _)| lexicon)
    }

    async fn fetch_and_validate(
        &self,
        did: &Did,
        nsid: &Nsid,
    ) -> Result<(ResolvedLexicon, ResolutionSource), LexiconResolveError> {
        let uri = AtUri::try_from(format!("at://{did}/{LEXICON_SCHEMA_NSID}/{nsid}").as_str())?;
        let (fetched, source) = match self.hooks.on_fetch(did, nsid).await {
            Some(fetched) => (fetched, ResolutionSource::Hook),
            None => (
                self.fetch_network(&uri, did, nsid).await?,
                ResolutionSource::Network,
            ),
        };
        Ok((validate(uri, nsid, fetched)?, source))
    }

    async fn fetch_network(
        &self,
        uri: &AtUri,
        did: &Did,
        nsid: &Nsid,
    ) -> Result<FetchedRecord, LexiconResolveError> {
        let identity = self.directory.lookup_did(did).await.map_err(|source| {
            LexiconResolveError::Identity {
                did: did.clone(),
                source,
            }
        })?;
        let endpoint = identity
            .pds_endpoint()
            .ok_or_else(|| LexiconResolveError::MissingPds { did: did.clone() })?;
        let key = identity
            .signing_key()
            .ok_or_else(|| LexiconResolveError::MissingSigningKey { did: did.clone() })?;
        let url = self.get_record_url(did, endpoint, nsid)?;

        let http_err = |e: reqwest::Error| LexiconResolveError::Http {
            uri: uri.clone(),
            message: e.to_string(),
        };
        let resp = crate::outbound::apply_user_agent(self.http.get(url))
            .header(reqwest::header::ACCEPT, "application/vnd.ipld.car")
            .send()
            .await
            .map_err(http_err)?;

        let status = resp.status();
        if !status.is_success() {
            let (error, message) =
                match crate::outbound::read_capped(resp, MAX_ERROR_BODY_BYTES).await {
                    Ok(Some(body)) => xrpc_error(&body),
                    _ => (None, None),
                };
            if error.as_deref() == Some("RecordNotFound") {
                return Err(LexiconResolveError::RecordNotFound { uri: uri.clone() });
            }
            let detail = [error, message].into_iter().flatten().collect::<Vec<_>>();
            return Err(LexiconResolveError::HttpStatus {
                uri: uri.clone(),
                status: status.as_u16(),
                detail: detail.join(": "),
            });
        }

        let car = crate::outbound::read_capped(resp, self.max_proof_bytes)
            .await
            .map_err(http_err)?
            .ok_or_else(|| LexiconResolveError::TooLarge {
                uri: uri.clone(),
                limit: self.max_proof_bytes,
            })?;
        let collection = Nsid::try_from(LEXICON_SCHEMA_NSID)?;
        let rkey = RecordKey::try_from(nsid.as_str())?;
        let proof = verify_record_proof(&car, did, key, &collection, &rkey).map_err(|source| {
            LexiconResolveError::Proof {
                uri: uri.clone(),
                source,
            }
        })?;
        let (cid, record) = proof
            .record
            .ok_or_else(|| LexiconResolveError::RecordNotFound { uri: uri.clone() })?;
        Ok(FetchedRecord { cid, record })
    }

    /// Build the `getRecord` URL on an untrusted PDS endpoint, refusing
    /// endpoints that could be used to reach something other than a PDS.
    fn get_record_url(
        &self,
        did: &Did,
        endpoint: &str,
        nsid: &Nsid,
    ) -> Result<url::Url, LexiconResolveError> {
        let invalid = |reason: &str| LexiconResolveError::InvalidPdsEndpoint {
            did: did.clone(),
            endpoint: endpoint.to_owned(),
            reason: reason.to_owned(),
        };
        let mut url = url::Url::parse(endpoint).map_err(|e| invalid(&e.to_string()))?;
        if !matches!(url.scheme(), "https" | "http") {
            return Err(invalid("scheme must be http or https"));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid("credentials are not allowed"));
        }
        let host = url.host_str().ok_or_else(|| invalid("missing host"))?;
        if crate::outbound::host_is_blocked_literal_ip(host, self.address_policy) {
            return Err(invalid("local address refused by the address policy"));
        }
        url.set_path("/xrpc/com.atproto.sync.getRecord");
        url.set_fragment(None);
        url.query_pairs_mut()
            .clear()
            .append_pair("did", did.as_str())
            .append_pair("collection", LEXICON_SCHEMA_NSID)
            .append_pair("rkey", nsid.as_str());
        Ok(url)
    }
}

impl Default for LexiconResolver {
    fn default() -> Self {
        Self::new()
    }
}

/// Check a fetched record and parse it as the Lexicon document for `nsid`.
fn validate(
    uri: AtUri,
    nsid: &Nsid,
    fetched: FetchedRecord,
) -> Result<ResolvedLexicon, LexiconResolveError> {
    let invalid = |reason: String| LexiconResolveError::InvalidRecord {
        uri: uri.clone(),
        reason,
    };
    let FetchedRecord { cid, record } = fetched;
    if cid.codec() != Codec::Drisl {
        return Err(invalid(format!("record CID {cid} is not DRISL")));
    }
    if Cid::compute(Codec::Drisl, &record) != cid {
        return Err(invalid(format!("record does not match its CID {cid}")));
    }
    let json = crate::cbor::json::drisl_to_json(&record).map_err(|e| invalid(e.to_string()))?;
    match json.get("$type").and_then(serde_json::Value::as_str) {
        Some(LEXICON_SCHEMA_NSID) => {}
        other => {
            return Err(invalid(format!(
                "$type is {other:?}, expected {LEXICON_SCHEMA_NSID:?}"
            )));
        }
    }
    let schema = serde_json::from_value::<Schema>(json.clone())
        .map_err(LexiconError::from)
        .and_then(check_schema)
        .map_err(|source| LexiconResolveError::InvalidDocument {
            uri: uri.clone(),
            source,
        })?;
    if schema.id != nsid.as_str() {
        return Err(LexiconResolveError::IdMismatch { uri, id: schema.id });
    }
    Ok(ResolvedLexicon {
        uri,
        cid,
        schema,
        json,
        record,
    })
}

/// The `error` and `message` of an XRPC error body, if it is one.
fn xrpc_error(body: &[u8]) -> (Option<String>, Option<String>) {
    #[derive(serde::Deserialize)]
    struct Body {
        error: Option<String>,
        message: Option<String>,
    }
    match serde_json::from_slice::<Body>(body) {
        Ok(b) => (b.error, b.message),
        Err(_) => (None, None),
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    fn did() -> Did {
        Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap()
    }

    fn nsid() -> Nsid {
        Nsid::try_from("com.example.thing").unwrap()
    }

    fn uri() -> AtUri {
        AtUri::try_from(
            "at://did:plc:z72i7hdynmk6r22z27h6tvur/com.atproto.lexicon.schema/com.example.thing",
        )
        .unwrap()
    }

    fn fetched(json: serde_json::Value) -> FetchedRecord {
        let record =
            crate::cbor::json::json_to_drisl(&json, crate::cbor::json::Integers::Safe).unwrap();
        FetchedRecord {
            cid: Cid::compute(Codec::Drisl, &record),
            record,
        }
    }

    fn doc() -> serde_json::Value {
        serde_json::json!({
            "$type": "com.atproto.lexicon.schema",
            "lexicon": 1,
            "id": "com.example.thing",
            "defs": { "main": { "type": "token" } }
        })
    }

    #[test]
    fn validate_accepts_a_good_document() {
        let got = validate(uri(), &nsid(), fetched(doc())).unwrap();
        assert_eq!(got.schema.id, "com.example.thing");
        assert_eq!(got.json, doc());
        assert_eq!(got.uri, uri());
    }

    #[test]
    fn validate_rejects_cid_problems() {
        let mut f = fetched(doc());
        f.record.push(0);
        assert!(matches!(
            validate(uri(), &nsid(), f),
            Err(LexiconResolveError::InvalidRecord { .. })
        ));
        let mut f = fetched(doc());
        f.cid = Cid::compute(Codec::Raw, &f.record);
        assert!(matches!(
            validate(uri(), &nsid(), f),
            Err(LexiconResolveError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn validate_rejects_non_drisl_bytes() {
        let record = vec![0xff, 0x00];
        let f = FetchedRecord {
            cid: Cid::compute(Codec::Drisl, &record),
            record,
        };
        assert!(matches!(
            validate(uri(), &nsid(), f),
            Err(LexiconResolveError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn validate_requires_lexicon_schema_type() {
        for t in [
            serde_json::json!("app.bsky.feed.post"),
            serde_json::json!(1),
            serde_json::Value::Null,
        ] {
            let mut d = doc();
            d["$type"] = t;
            assert!(matches!(
                validate(uri(), &nsid(), fetched(d)),
                Err(LexiconResolveError::InvalidRecord { .. })
            ));
        }
        let mut d = doc();
        d.as_object_mut().unwrap().remove("$type");
        assert!(matches!(
            validate(uri(), &nsid(), fetched(d)),
            Err(LexiconResolveError::InvalidRecord { .. })
        ));
    }

    #[test]
    fn validate_rejects_invalid_documents() {
        let mut bad_version = doc();
        bad_version["lexicon"] = 999.into();
        let mut no_defs = doc();
        no_defs.as_object_mut().unwrap().remove("defs");
        let mut bad_required = doc();
        bad_required["defs"] = serde_json::json!({
            "main": { "type": "object", "required": ["x"], "properties": {} }
        });
        for d in [bad_version, no_defs, bad_required] {
            assert!(
                matches!(
                    validate(uri(), &nsid(), fetched(d.clone())),
                    Err(LexiconResolveError::InvalidDocument { .. })
                ),
                "{d}"
            );
        }
    }

    #[test]
    fn validate_requires_id_to_match() {
        for id in [
            "com.example.other",
            "com.example.Thing",
            "",
            "com.example.thing ",
        ] {
            let mut d = doc();
            d["id"] = id.into();
            let err = validate(uri(), &nsid(), fetched(d)).unwrap_err();
            assert!(
                matches!(
                    err,
                    LexiconResolveError::IdMismatch { .. }
                        | LexiconResolveError::InvalidDocument { .. }
                ),
                "{id:?}: {err:?}"
            );
        }
    }

    #[test]
    fn pds_endpoint_validation() {
        let deny = LexiconResolver::new();
        let allow = LexiconResolver::new().with_address_policy(AddressPolicy::AllowLocal);
        let ok = |r: &LexiconResolver, e: &str| r.get_record_url(&did(), e, &nsid());

        let url = ok(&deny, "https://pds.example.com/some/path?q=1#frag").unwrap();
        assert_eq!(
            url.as_str(),
            "https://pds.example.com/xrpc/com.atproto.sync.getRecord?did=did%3Aplc%3Az72i7hdynmk6r22z27h6tvur&collection=com.atproto.lexicon.schema&rkey=com.example.thing"
        );
        assert!(ok(&deny, "http://pds.example.com:8080").is_ok());

        for bad in [
            "",
            "not a url",
            "ftp://pds.example.com",
            "file:///etc/passwd",
            "data:text/plain,hi",
            "https://user:pass@pds.example.com",
            "https://user@pds.example.com",
            "http://127.0.0.1:2583",
            "http://[::1]:2583",
            "http://169.254.169.254",
            "http://10.0.0.1",
            "http://0x7f.1",
        ] {
            assert!(
                matches!(
                    ok(&deny, bad),
                    Err(LexiconResolveError::InvalidPdsEndpoint { .. })
                ),
                "{bad:?} must be refused"
            );
        }
        assert!(ok(&allow, "http://127.0.0.1:2583").is_ok());
        assert!(ok(&allow, "ftp://127.0.0.1").is_err());
    }

    #[test]
    fn xrpc_error_parsing() {
        assert_eq!(
            xrpc_error(br#"{"error":"RecordNotFound","message":"nope"}"#),
            (Some("RecordNotFound".into()), Some("nope".into()))
        );
        assert_eq!(xrpc_error(b"<html>"), (None, None));
        assert_eq!(xrpc_error(br#"{"error":5}"#), (None, None));
    }

    #[test]
    fn transient_classification() {
        let http_status = |status| LexiconResolveError::HttpStatus {
            uri: uri(),
            status,
            detail: String::new(),
        };
        assert!(http_status(500).is_transient());
        assert!(http_status(503).is_transient());
        assert!(http_status(429).is_transient());
        assert!(!http_status(400).is_transient());
        assert!(!http_status(404).is_transient());
        assert!(!LexiconResolveError::RecordNotFound { uri: uri() }.is_transient());
        assert!(
            LexiconResolveError::Authority {
                nsid: nsid(),
                source: LexiconAuthorityError::Lookup(crate::identity::TxtError::Failed {
                    name: "x".into(),
                    message: "y".into()
                })
            }
            .is_transient()
        );
        assert!(
            !LexiconResolveError::Authority {
                nsid: nsid(),
                source: LexiconAuthorityError::NotFound { name: "x".into() }
            }
            .is_transient()
        );
    }
}
