use crate::cbor::Cid;
use crate::sync::state::StateStoreError;
use crate::syntax::Did;

/// Errors produced by Sync 1.1 verification.
#[derive(Debug, thiserror::Error)]
pub enum VerifierError {
    #[error("future rev for {did}: {rev}")]
    FutureRev { did: Did, rev: String },

    #[error("chain break for {did} rev {rev}: expected {expected:?}, actual {actual:?}")]
    ChainBreak {
        did: Did,
        rev: String,
        expected: Option<Cid>,
        actual: Option<Cid>,
    },

    #[error(
        "field mismatch for {did} {rev:?} field {field}: expected {expected:?}, actual {actual:?}"
    )]
    FieldMismatch {
        did: Did,
        rev: Option<String>,
        field: &'static str,
        expected: String,
        actual: String,
    },

    #[error("invalid signature for {did} rev {rev}: {reason}")]
    SignatureInvalid {
        did: Did,
        rev: String,
        reason: String,
    },

    #[error(
        "op CID mismatch for {did} rev {rev} path {path}: expected {expected:?}, actual {actual:?}"
    )]
    OpCidMismatch {
        did: Did,
        rev: String,
        path: String,
        expected: Option<Cid>,
        actual: Option<Cid>,
    },

    #[error("duplicate repo op path for {did} rev {rev}: {path}")]
    DuplicatePath { did: Did, rev: String, path: String },

    #[error("legacy sync commit for {did} rev {rev}: seen rev {seen_rev:?}")]
    LegacyCommit {
        did: Did,
        rev: String,
        seen_rev: Option<String>,
        seen_data: Option<Cid>,
    },

    #[error("oversized commit for {did} {rev:?}: {field}={bytes} exceeds limit {limit}")]
    OversizedCommit {
        did: Did,
        rev: Option<String>,
        field: &'static str,
        bytes: usize,
        limit: usize,
    },

    #[error("repo inactive for {did}: status {status:?}, seq {seq:?}, time {time:?}")]
    RepoInactive {
        did: Did,
        status: Option<String>,
        seq: Option<i64>,
        time: Option<String>,
    },

    #[error("resync required for {did}: {reason}")]
    ResyncRequired { did: Did, reason: String },

    #[error("resync rate limited for {did}")]
    ResyncRateLimited { did: Did },

    #[error("pending verifier queue overflow for {did}: len {len}, limit {limit}")]
    BufferOverflow { did: Did, len: usize, limit: usize },

    #[error("rev regression for {did}: current {current}, fetched {fetched}")]
    RevRegression {
        did: Did,
        current: String,
        fetched: String,
    },

    #[error("resync failed for {did}: {source}")]
    ResyncFailed {
        did: Did,
        #[source]
        source: Box<VerifierError>,
    },

    #[error("inversion failed for {did} rev {rev}: {message}")]
    Inversion {
        did: Did,
        rev: String,
        message: String,
    },

    #[error("state store error: {0}")]
    StateStore(#[from] StateStoreError),

    #[error("CAR error for {did:?} {rev:?}: {source}")]
    Car {
        did: Option<Did>,
        rev: Option<String>,
        #[source]
        source: crate::car::CarError,
    },

    #[error("CBOR error for {did:?} {rev:?}: {source}")]
    Cbor {
        did: Option<Did>,
        rev: Option<String>,
        #[source]
        source: crate::cbor::CborError,
    },

    #[error("repo error for {did:?} {rev:?}: {source}")]
    Repo {
        did: Option<Did>,
        rev: Option<String>,
        #[source]
        source: crate::repo::RepoError,
    },

    #[error("identity error for {did}: {source}")]
    Identity {
        did: Did,
        #[source]
        source: crate::identity::IdentityError,
    },
}
