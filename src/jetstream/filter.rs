//! Subscription filters: the three independent, AND-composed predicates a
//! caller uses to narrow a Jetstream subscription.
//!
//! - `kinds`: which event kinds to receive; empty means all.
//! - `dids`: which repos to receive; empty means all; applies to every kind.
//! - `collections`: exact NSIDs or terminal `.*` namespace wildcards; empty
//!   means all; **applies only to commits**. DID-level events (identity,
//!   account, sync) bypass the collection predicate entirely.
//!
//! The same filter is applied twice at runtime: the planner may return archive
//! false positives, and the live tail sees everything the server's coarser
//! query matched, so each decoded event is re-checked here. The matching logic
//! mirrors the Go client's `wants()` exactly.
//!
//! Validation runs before any I/O and is total: a [`Filter`] can only hold
//! syntactically valid DIDs and collection patterns, and [`Filter::validate`]
//! enforces the count limits and the cross-field rule (a collection filter is
//! meaningless — and rejected — when a non-empty kind filter excludes commits).

use std::collections::HashSet;

use super::error::{Error, Result};
use super::event::{Event, EventPayload};
use crate::syntax::{Did, Nsid};

/// Maximum number of distinct event kinds in a filter.
pub const MAX_KINDS: usize = 4;
/// Maximum number of DIDs in a filter.
pub const MAX_DIDS: usize = 10_000;
/// Maximum number of collection patterns in a filter.
pub const MAX_COLLECTIONS: usize = 100;

/// A Jetstream event kind, used both to classify events and to filter them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    /// A record mutation (create, update, or delete).
    Commit,
    /// An identity change (handle/DID document).
    Identity,
    /// An account status change.
    Account,
    /// A repo sync (`#sync`) marker.
    Sync,
}

impl Kind {
    /// The wire token used in the `wantedCollections`-free v2 `kinds` query
    /// parameter (`"commit"`, `"identity"`, `"account"`, `"sync"`).
    pub const fn as_wire(self) -> &'static str {
        match self {
            Kind::Commit => "commit",
            Kind::Identity => "identity",
            Kind::Account => "account",
            Kind::Sync => "sync",
        }
    }

    /// Parse a wire token into a [`Kind`].
    pub fn from_wire(s: &str) -> Option<Kind> {
        match s {
            "commit" => Some(Kind::Commit),
            "identity" => Some(Kind::Identity),
            "account" => Some(Kind::Account),
            "sync" => Some(Kind::Sync),
            _ => None,
        }
    }
}

/// One collection predicate: an exact NSID or a terminal `.*` namespace prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
enum CollectionFilter {
    /// Matches a commit whose collection equals this NSID exactly.
    Exact(Nsid),
    /// Matches a commit whose collection begins with this prefix. The prefix
    /// keeps its trailing dot (e.g. `"app.bsky.feed."` for `app.bsky.feed.*`),
    /// so `app.bsky.feed` alone does not match — mirroring the Go client.
    Prefix(String),
}

impl CollectionFilter {
    fn matches(&self, collection: &Nsid) -> bool {
        match self {
            CollectionFilter::Exact(nsid) => nsid == collection,
            CollectionFilter::Prefix(prefix) => collection.as_str().starts_with(prefix.as_str()),
        }
    }

    /// The original wire form (`nsid` or `prefix.*`), for building query params.
    fn to_wire(&self) -> String {
        match self {
            CollectionFilter::Exact(nsid) => nsid.as_str().to_owned(),
            CollectionFilter::Prefix(prefix) => format!("{prefix}*"),
        }
    }
}

/// The three-dimensional subscription filter. An empty dimension means "all".
///
/// Build with [`Filter::new`] and the fluent setters, then hand it to the
/// client builder, which calls [`Filter::validate`]. Syntax errors surface at
/// the setter that introduced them; count and cross-field errors surface at
/// validation.
#[derive(Debug, Clone, Default)]
pub struct Filter {
    kinds: Vec<Kind>,
    dids: HashSet<Did>,
    collections: Vec<CollectionFilter>,
}

impl Filter {
    /// An empty filter that matches every event.
    pub fn new() -> Filter {
        Filter::default()
    }

    /// Set the event kinds, replacing any previously set. Duplicates are folded.
    pub fn kinds(mut self, kinds: impl IntoIterator<Item = Kind>) -> Filter {
        self.kinds.clear();
        for k in kinds {
            if !self.kinds.contains(&k) {
                self.kinds.push(k);
            }
        }
        self
    }

    /// Add one DID, validating its syntax.
    pub fn did(mut self, did: impl AsRef<str>) -> Result<Filter> {
        let did = Did::try_from(did.as_ref())
            .map_err(|_| Error::InvalidConfig("filter DID is not a valid DID"))?;
        self.dids.insert(did);
        Ok(self)
    }

    /// Add several DIDs, validating each.
    pub fn dids<I, S>(mut self, dids: I) -> Result<Filter>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for d in dids {
            let did = Did::try_from(d.as_ref())
                .map_err(|_| Error::InvalidConfig("filter DID is not a valid DID"))?;
            self.dids.insert(did);
        }
        Ok(self)
    }

    /// Add one collection predicate: an exact NSID (`app.bsky.feed.post`) or a
    /// terminal namespace wildcard (`app.bsky.feed.*`). The wildcard namespace
    /// must be a valid dotted NSID prefix of at least two labels.
    pub fn collection(mut self, collection: impl AsRef<str>) -> Result<Filter> {
        self.collections
            .push(parse_collection(collection.as_ref())?);
        Ok(self)
    }

    /// Add several collection predicates.
    pub fn collections<I, S>(mut self, collections: I) -> Result<Filter>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for c in collections {
            self.collections.push(parse_collection(c.as_ref())?);
        }
        Ok(self)
    }

    /// Whether the kind filter admits commits (empty means all kinds).
    fn wants_commits(&self) -> bool {
        self.kinds.is_empty() || self.kinds.contains(&Kind::Commit)
    }

    /// Validate counts and the cross-field rule. Called before any I/O.
    pub fn validate(&self) -> Result<()> {
        if self.kinds.len() > MAX_KINDS {
            return Err(Error::InvalidConfig("too many kinds (max 4)"));
        }
        if self.dids.len() > MAX_DIDS {
            return Err(Error::InvalidConfig("too many DIDs (max 10000)"));
        }
        if self.collections.len() > MAX_COLLECTIONS {
            return Err(Error::InvalidConfig("too many collections (max 100)"));
        }
        // A collection filter only constrains commits; if the kind filter
        // already excludes commits, the collection filter can never match and
        // is a caller mistake.
        if !self.collections.is_empty() && !self.wants_commits() {
            return Err(Error::InvalidConfig(
                "collection filter set but kind filter excludes commits",
            ));
        }
        Ok(())
    }

    /// Whether `event` passes the filter. Mirrors the Go client's `wants()`:
    /// kind and DID predicates apply to every event; the collection predicate
    /// applies only to commits, and DID-level events bypass it.
    pub fn matches(&self, event: &Event) -> bool {
        // Kind predicate (empty means all).
        if !self.kinds.is_empty() && !self.kinds.contains(&event.kind()) {
            return false;
        }
        // DID predicate (empty means all), applied to every kind.
        if !self.dids.is_empty() && !self.dids.contains(&event.did) {
            return false;
        }
        // Collection predicate (empty means all), applied to commits only.
        if self.collections.is_empty() {
            return true;
        }
        match &event.payload {
            EventPayload::Commit(commit) => self
                .collections
                .iter()
                .any(|c| c.matches(&commit.collection)),
            // DID-level events are not constrained by a collection filter.
            _ => true,
        }
    }

    /// Whether a raw segment row passes the kind/DID/collection predicates,
    /// working directly from the decoded column values so a filtered-out row need
    /// never be converted into an [`Event`]. Mirrors the Go client's `rowSelector`
    /// (the seq-range check is the planner's and engine's concern, not the
    /// filter's): the kind and DID predicates apply to every row; the collection
    /// predicate applies only to commits, and a DID-level row — or a commit whose
    /// collection is empty (v1 parity) — bypasses it.
    ///
    /// `did` and `collection` are the raw column bytes reinterpreted as `&str`;
    /// callers pass `""` for a column that is not valid UTF-8, which correctly
    /// fails a constrained DID/collection predicate while still admitting the row
    /// when that dimension is unfiltered (the row is then dropped, not silently
    /// kept, when its typed conversion fails).
    pub fn matches_segment(&self, kind: Kind, did: &str, collection: &str) -> bool {
        // Kind predicate (empty means all).
        if !self.kinds.is_empty() && !self.kinds.contains(&kind) {
            return false;
        }
        // DID predicate (empty means all), applied to every kind. The filter's
        // DID set only ever holds syntactically valid DIDs, so a row DID that
        // fails to parse can never be a member and correctly fails the predicate.
        if !self.dids.is_empty() {
            match Did::try_from(did) {
                Ok(d) if self.dids.contains(&d) => {}
                _ => return false,
            }
        }
        // Collection predicate (empty means all), applied to commits only.
        if self.collections.is_empty() {
            return true;
        }
        if kind != Kind::Commit || collection.is_empty() {
            return true;
        }
        match Nsid::try_from(collection) {
            Ok(nsid) => self.collections.iter().any(|c| c.matches(&nsid)),
            // A commit whose collection is not a valid NSID cannot satisfy any
            // exact or wildcard predicate, so a constrained subscription drops it.
            Err(_) => false,
        }
    }

    /// The kinds as wire tokens, for building the `kinds` query parameter.
    pub fn kind_wire_tokens(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.kinds.iter().map(|k| k.as_wire())
    }

    /// The DIDs, for building the `dids` query parameter.
    pub fn did_wire_tokens(&self) -> impl Iterator<Item = &str> + '_ {
        self.dids.iter().map(Did::as_str)
    }

    /// The collections in wire form (`nsid` or `prefix.*`), for the query.
    pub fn collection_wire_tokens(&self) -> impl Iterator<Item = String> + '_ {
        self.collections.iter().map(CollectionFilter::to_wire)
    }
}

/// Parse one collection filter entry.
fn parse_collection(raw: &str) -> Result<CollectionFilter> {
    if let Some(namespace) = raw.strip_suffix(".*") {
        validate_wildcard_namespace(namespace)?;
        // Match the Go client: keep the dot, drop the star.
        Ok(CollectionFilter::Prefix(format!(
            "{}.",
            namespace.to_ascii_lowercase()
        )))
    } else {
        let nsid = Nsid::try_from(raw)
            .map_err(|_| Error::InvalidConfig("collection is not a valid NSID or wildcard"))?;
        Ok(CollectionFilter::Exact(nsid))
    }
}

/// Validate the namespace part of a `namespace.*` wildcard: dot-separated NSID
/// domain labels, at least two, the first starting with a letter. This is the
/// NSID authority grammar without the trailing name segment.
fn validate_wildcard_namespace(namespace: &str) -> Result<()> {
    let err = || Error::InvalidConfig("collection wildcard namespace is not a valid NSID prefix");
    if namespace.is_empty() || namespace.len() > 253 {
        return Err(err());
    }
    let mut label_count = 0usize;
    for (i, label) in namespace.split('.').enumerate() {
        label_count += 1;
        validate_domain_label(label).map_err(|_| err())?;
        // The leftmost label (TLD position in the reversed NSID) starts alpha.
        if i == 0
            && !label
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
        {
            return Err(err());
        }
    }
    if label_count < 2 {
        return Err(err());
    }
    Ok(())
}

/// Validate a single NSID domain label: 1..=63 bytes, alphanumeric ends,
/// interior alphanumeric-or-hyphen.
fn validate_domain_label(label: &str) -> Result<()> {
    let bytes = label.as_bytes();
    if bytes.is_empty() || bytes.len() > 63 {
        return Err(Error::InvalidConfig("invalid label"));
    }
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return Err(Error::InvalidConfig("invalid label"));
    }
    for &b in &bytes[1..bytes.len().saturating_sub(1)] {
        if !(b.is_ascii_alphanumeric() || b == b'-') {
            return Err(Error::InvalidConfig("invalid label"));
        }
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn kind_wire_round_trip() {
        for k in [Kind::Commit, Kind::Identity, Kind::Account, Kind::Sync] {
            assert_eq!(Kind::from_wire(k.as_wire()), Some(k));
        }
        assert_eq!(Kind::from_wire("nope"), None);
    }

    #[test]
    fn kinds_fold_duplicates() {
        let f = Filter::new().kinds([Kind::Commit, Kind::Commit, Kind::Sync]);
        assert_eq!(f.kinds, vec![Kind::Commit, Kind::Sync]);
        f.validate().unwrap();
    }

    #[test]
    fn exact_collection_parses_and_normalizes() {
        let c = parse_collection("App.Bsky.Feed.post").unwrap();
        match c {
            CollectionFilter::Exact(nsid) => assert_eq!(nsid.as_str(), "app.bsky.feed.post"),
            other => panic!("expected exact, got {other:?}"),
        }
    }

    #[test]
    fn wildcard_keeps_dot_drops_star() {
        let c = parse_collection("app.bsky.feed.*").unwrap();
        assert_eq!(c, CollectionFilter::Prefix("app.bsky.feed.".to_owned()));
        assert_eq!(c.to_wire(), "app.bsky.feed.*");
    }

    #[test]
    fn wildcard_prefix_matching_semantics() {
        let c = parse_collection("app.bsky.feed.*").unwrap();
        assert!(c.matches(&Nsid::try_from("app.bsky.feed.post").unwrap()));
        assert!(c.matches(&Nsid::try_from("app.bsky.feed.like").unwrap()));
        // A different namespace does not match.
        assert!(!c.matches(&Nsid::try_from("app.bsky.graph.follow").unwrap()));
    }

    #[test]
    fn two_label_wildcard_is_valid() {
        assert!(parse_collection("app.bsky.*").is_ok());
    }

    #[test]
    fn invalid_wildcards_rejected() {
        // Single label is not a namespace prefix.
        assert!(parse_collection("app.*").is_err());
        // Empty namespace.
        assert!(parse_collection(".*").is_err());
        // Leading digit in the TLD position.
        assert!(parse_collection("9foo.bar.*").is_err());
        // Bad label characters.
        assert!(parse_collection("app.b_sky.*").is_err());
    }

    #[test]
    fn count_limits_enforced() {
        // DIDs: build MAX_DIDS + 1 distinct valid DIDs.
        let mut f = Filter::new();
        for i in 0..(MAX_DIDS + 1) {
            f = f.did(format!("did:plc:{i:0>24}")).unwrap();
        }
        assert!(matches!(f.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn collection_limit_enforced() {
        let mut f = Filter::new();
        for i in 0..(MAX_COLLECTIONS + 1) {
            f = f.collection(format!("app.bsky.feed.c{i}")).unwrap();
        }
        assert!(matches!(f.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn collection_without_commit_kind_is_rejected() {
        let f = Filter::new()
            .kinds([Kind::Identity])
            .collection("app.bsky.feed.post")
            .unwrap();
        assert!(matches!(f.validate(), Err(Error::InvalidConfig(_))));
    }

    #[test]
    fn collection_with_commit_kind_is_ok() {
        let f = Filter::new()
            .kinds([Kind::Commit, Kind::Identity])
            .collection("app.bsky.feed.post")
            .unwrap();
        f.validate().unwrap();
    }

    const D: &str = "did:plc:abcdefghijklmnopqrstuvwx";

    /// The collection predicate constrains commits only; DID-level markers
    /// (identity/account/sync) bypass it. This is the consumer's only signal to
    /// purge a dead account, so it must survive a narrow collection filter —
    /// mirrors the Go client's `wants()` contract exercised end-to-end by the
    /// engine's `collection_filter_passes_did_markers_across_archive_and_live`.
    #[test]
    fn collection_filter_constrains_commits_but_bypasses_markers() {
        let f = Filter::new().collection("app.bsky.feed.post").unwrap();
        // Commit: only the matching collection passes.
        assert!(f.matches_segment(Kind::Commit, D, "app.bsky.feed.post"));
        assert!(!f.matches_segment(Kind::Commit, D, "app.bsky.feed.like"));
        // Every DID-level marker bypasses the collection predicate.
        for kind in [Kind::Identity, Kind::Account, Kind::Sync] {
            assert!(f.matches_segment(kind, D, ""));
        }
    }

    /// A `kinds=[commit]` filter excludes the DID-level markers entirely, even
    /// though those markers otherwise bypass the collection predicate.
    #[test]
    fn commit_only_kind_filter_excludes_markers() {
        let f = Filter::new().kinds([Kind::Commit]);
        assert!(f.matches_segment(Kind::Commit, D, "app.bsky.feed.post"));
        for kind in [Kind::Identity, Kind::Account, Kind::Sync] {
            assert!(!f.matches_segment(kind, D, ""));
        }
    }

    /// The DID predicate applies to every kind, including markers, and a row DID
    /// that is absent (or unparseable) fails a constrained subscription.
    #[test]
    fn did_predicate_applies_to_every_kind() {
        let other = "did:plc:zzzzzzzzzzzzzzzzzzzzzzzz";
        let f = Filter::new().did(D).unwrap();
        assert!(f.matches_segment(Kind::Commit, D, "app.bsky.feed.post"));
        assert!(f.matches_segment(Kind::Account, D, ""));
        assert!(!f.matches_segment(Kind::Account, other, ""));
        // A row DID that is not even a valid DID cannot be a member.
        assert!(!f.matches_segment(Kind::Sync, "not-a-did", ""));
    }

    /// An empty filter (the default) admits every kind, DID, and collection.
    #[test]
    fn empty_filter_admits_everything() {
        let f = Filter::new();
        assert!(f.matches_segment(Kind::Commit, D, "app.bsky.feed.post"));
        assert!(f.matches_segment(Kind::Commit, D, ""));
        for kind in [Kind::Identity, Kind::Account, Kind::Sync] {
            assert!(f.matches_segment(kind, D, ""));
        }
    }
}
