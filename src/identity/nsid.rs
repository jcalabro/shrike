//! NSID → DID resolution for Lexicon publication.
//!
//! Per the Lexicon spec, the DID that publishes the schemas for an NSID group
//! is declared by a DNS TXT record `did=<did>` at `_lexicon.<authority>`,
//! where the authority is the NSID minus its name segment, reversed:
//! `app.bsky.feed.post` → `_lexicon.feed.bsky.app`. Resolution is not
//! hierarchical: only that exact name is queried, never a parent or child.

use crate::identity::txt::{TxtError, TxtRecord, TxtResolver};
use crate::syntax::{Did, Nsid};

/// Longest DNS name, in presentation form without the trailing dot.
const MAX_DNS_NAME_LEN: usize = 253;

/// Errors from resolving an NSID's Lexicon authority.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LexiconAuthorityError {
    /// No `did=` TXT record exists at the name.
    #[error("no did= TXT record at {name}")]
    NotFound { name: String },
    /// More than one `did=` TXT record exists at the name.
    #[error("{count} did= TXT records at {name}; expected exactly one")]
    Ambiguous { name: String, count: usize },
    /// The `did=` value is not a valid DID.
    #[error("invalid DID {value:?} in TXT record at {name}")]
    InvalidDid { name: String, value: String },
    /// The DNS lookup itself failed; retrying later may succeed.
    #[error(transparent)]
    Lookup(TxtError),
}

/// The DNS name holding `nsid`'s Lexicon authority record:
/// `_lexicon.<authority>`.
pub fn lexicon_authority_name(nsid: &Nsid) -> String {
    format!("_lexicon.{}", nsid.authority())
}

/// Resolve the DID that publishes the Lexicon for `nsid`.
///
/// Exactly one TXT record at [`lexicon_authority_name`] must start with
/// `did=` (records are matched after joining their character-strings; others
/// are ignored), and its value must be a valid DID. The DID is not resolved
/// or otherwise verified here.
pub async fn resolve_lexicon_authority(
    txt: &dyn TxtResolver,
    nsid: &Nsid,
) -> Result<Did, LexiconAuthorityError> {
    let name = lexicon_authority_name(nsid);
    // An NSID authority may be up to 253 characters, which leaves no room for
    // the `_lexicon.` label. Such a name cannot exist in DNS.
    if name.len() > MAX_DNS_NAME_LEN {
        return Err(LexiconAuthorityError::NotFound { name });
    }
    match txt.lookup_txt(&name).await {
        Ok(records) => parse_lexicon_txt(&name, &records),
        Err(TxtError::NotFound(_)) => Err(LexiconAuthorityError::NotFound { name }),
        Err(e) => Err(LexiconAuthorityError::Lookup(e)),
    }
}

/// Pick the DID out of the TXT records at `name`, matching the reference
/// implementation: join each record's strings, keep those starting with
/// `did=`, require exactly one, and parse its value strictly (no trimming).
fn parse_lexicon_txt(name: &str, records: &[TxtRecord]) -> Result<Did, LexiconAuthorityError> {
    let values: Vec<Vec<u8>> = records
        .iter()
        .map(|chunks| chunks.concat())
        .filter_map(|joined| joined.strip_prefix(b"did=").map(<[u8]>::to_vec))
        .collect();
    let value = match values.as_slice() {
        [value] => value,
        [] => {
            return Err(LexiconAuthorityError::NotFound {
                name: name.to_owned(),
            });
        }
        many => {
            return Err(LexiconAuthorityError::Ambiguous {
                name: name.to_owned(),
                count: many.len(),
            });
        }
    };
    let invalid = || LexiconAuthorityError::InvalidDid {
        name: name.to_owned(),
        value: String::from_utf8_lossy(value).into_owned(),
    };
    let text = std::str::from_utf8(value).map_err(|_| invalid())?;
    Did::try_from(text).map_err(|_| invalid())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::identity::txt::SystemTxtResolver;
    use async_trait::async_trait;
    use std::sync::Mutex;

    /// Serves canned TXT answers and records which names were queried.
    struct FakeTxt {
        answer: Result<Vec<TxtRecord>, TxtError>,
        queried: Mutex<Vec<String>>,
    }

    impl FakeTxt {
        fn records(records: &[&[&str]]) -> Self {
            Self::answer(Ok(records
                .iter()
                .map(|chunks| chunks.iter().map(|s| s.as_bytes().to_vec()).collect())
                .collect()))
        }

        fn answer(answer: Result<Vec<TxtRecord>, TxtError>) -> Self {
            FakeTxt {
                answer,
                queried: Mutex::new(Vec::new()),
            }
        }
    }

    #[async_trait]
    impl TxtResolver for FakeTxt {
        async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, TxtError> {
            self.queried.lock().unwrap().push(name.to_owned());
            self.answer.clone()
        }
    }

    fn nsid(s: &str) -> Nsid {
        Nsid::try_from(s).unwrap()
    }

    async fn resolve(txt: &FakeTxt, n: &str) -> Result<Did, LexiconAuthorityError> {
        resolve_lexicon_authority(txt, &nsid(n)).await
    }

    const LONG_CHUNK: &str = "chunk long domain aspdfoiuwerpoaisdfupasodfiuaspdfoiuasdpfoiausdfpaosidfuaspodifuaspdfoiuasdpfoiasudfpasodifuaspdofiuaspdfoiuasd";

    #[test]
    fn authority_name_reverses_domain_and_drops_name() {
        assert_eq!(
            lexicon_authority_name(&nsid("app.bsky.feed.post")),
            "_lexicon.feed.bsky.app"
        );
        assert_eq!(
            lexicon_authority_name(&nsid("com.example.fooBar")),
            "_lexicon.example.com"
        );
        assert_eq!(
            lexicon_authority_name(&nsid("edu.university.dept.lab.blogging.getBlogPost")),
            "_lexicon.blogging.lab.dept.university.edu"
        );
        // Authority is case-insensitive and normalized; the name keeps case.
        assert_eq!(
            lexicon_authority_name(&nsid("COM.Example.fooBar")),
            "_lexicon.example.com"
        );
    }

    // The following cases are ported from the reference
    // packages/lexicon-resolver/tests/lexicon.test.ts "DID authority" suite.

    #[tokio::test]
    async fn simple_resolution() {
        let txt = FakeTxt::records(&[&["did=did:example:simpleDid"]]);
        let did = resolve(&txt, "test.simple.name").await.unwrap();
        assert_eq!(did.as_str(), "did:example:simpleDid");
        assert_eq!(*txt.queried.lock().unwrap(), ["_lexicon.simple.test"]);
    }

    #[tokio::test]
    async fn noisy_resolution() {
        let txt = FakeTxt::records(&[
            &["blah blah blah"],
            &["did:example:fakeDid"],
            &["atproto=did:example:fakeDid"],
            &["did=did:example:noisyDid"],
            &[LONG_CHUNK, "apsodfiuweproiasudfpoasidfu"],
        ]);
        let did = resolve(&txt, "test.noisy.name").await.unwrap();
        assert_eq!(did.as_str(), "did:example:noisyDid");
    }

    #[tokio::test]
    async fn bad_resolution() {
        let txt = FakeTxt::records(&[
            &["blah blah blah"],
            &["did:example:fakeDid"],
            &["atproto=did:example:fakeDid"],
            &[LONG_CHUNK, "apsodfiuweproiasudfpoasidfu"],
        ]);
        assert!(matches!(
            resolve(&txt, "test.bad.name").await,
            Err(LexiconAuthorityError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn multiple_dids_rejected() {
        let txt = FakeTxt::records(&[
            &["did=did:example:firstDid"],
            &["did=did:example:secondDid"],
        ]);
        assert_eq!(
            resolve(&txt, "test.multi.name").await,
            Err(LexiconAuthorityError::Ambiguous {
                name: "_lexicon.multi.test".into(),
                count: 2
            })
        );
        // Even when one of them is not a valid DID.
        let txt = FakeTxt::records(&[&["did=did:example:firstDid"], &["did=garbage"]]);
        assert!(matches!(
            resolve(&txt, "test.multi.name").await,
            Err(LexiconAuthorityError::Ambiguous { count: 2, .. })
        ));
    }

    #[tokio::test]
    async fn invalid_did_rejected() {
        for value in [
            "did=not:a:did",
            "did=",
            "did= did:plc:z72i7hdynmk6r22z27h6tvur",
            "did=did:plc:z72i7hdynmk6r22z27h6tvur ",
        ] {
            let txt = FakeTxt::records(&[&[value]]);
            assert!(
                matches!(
                    resolve(&txt, "test.invalid.name").await,
                    Err(LexiconAuthorityError::InvalidDid { .. })
                ),
                "{value:?}"
            );
        }
        let txt = FakeTxt::answer(Ok(vec![vec![b"did=did:plc:\xff\xfe".to_vec()]]));
        assert!(matches!(
            resolve(&txt, "test.invalid.name").await,
            Err(LexiconAuthorityError::InvalidDid { .. })
        ));
    }

    // Additional cases beyond the reference suite.

    #[tokio::test]
    async fn chunked_did_record_is_joined() {
        let txt = FakeTxt::records(&[&["did=did:plc:", "z72i7hdynmk6r22z27h6tvur"]]);
        let did = resolve(&txt, "test.chunked.name").await.unwrap();
        assert_eq!(did.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[tokio::test]
    async fn prefix_is_case_sensitive() {
        let txt = FakeTxt::records(&[&["DID=did:plc:z72i7hdynmk6r22z27h6tvur"]]);
        assert!(matches!(
            resolve(&txt, "test.case.name").await,
            Err(LexiconAuthorityError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn empty_and_nonutf8_records_are_ignored() {
        let txt = FakeTxt::answer(Ok(vec![
            vec![],
            vec![b"\xff\xfe".to_vec()],
            vec![b"did=did:web:example.com".to_vec()],
        ]));
        let did = resolve(&txt, "test.junk.name").await.unwrap();
        assert_eq!(did.as_str(), "did:web:example.com");
        assert!(matches!(
            resolve(&FakeTxt::answer(Ok(vec![])), "test.junk.name").await,
            Err(LexiconAuthorityError::NotFound { .. })
        ));
    }

    #[tokio::test]
    async fn dns_errors_are_classified() {
        let txt = FakeTxt::answer(Err(TxtError::NotFound("_lexicon.nx.test".into())));
        assert!(matches!(
            resolve(&txt, "test.nx.name").await,
            Err(LexiconAuthorityError::NotFound { .. })
        ));
        let failed = TxtError::Failed {
            name: "_lexicon.servfail.test".into(),
            message: "timed out".into(),
        };
        let txt = FakeTxt::answer(Err(failed.clone()));
        assert_eq!(
            resolve(&txt, "test.servfail.name").await,
            Err(LexiconAuthorityError::Lookup(failed))
        );
    }

    #[tokio::test]
    async fn overlong_name_is_not_queried() {
        // A 253-character authority is a valid NSID domain, but `_lexicon.`
        // pushes the DNS name past the 253-character limit.
        let label = "a".repeat(63);
        let n = format!("com.{label}.{label}.{label}.{}.name", "b".repeat(57));
        let txt = FakeTxt::records(&[&["did=did:example:x"]]);
        assert!(matches!(
            resolve(&txt, &n).await,
            Err(LexiconAuthorityError::NotFound { .. })
        ));
        assert!(txt.queried.lock().unwrap().is_empty());
    }

    #[tokio::test]
    async fn system_resolver_reports_reserved_tld_as_not_found_or_failed() {
        // `.invalid` never resolves (RFC 6761). Depending on the environment
        // the lookup is an NXDOMAIN or a failure; either way it must not
        // panic or produce records.
        let txt = SystemTxtResolver::new();
        let result = txt.lookup_txt("_lexicon.nonexistent.invalid").await;
        assert!(result.is_err(), "{result:?}");
    }
}
