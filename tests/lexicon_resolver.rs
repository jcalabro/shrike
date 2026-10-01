//! End-to-end Lexicon resolution against a mock network: a fake DNS TXT
//! resolver, and a local HTTP server acting as both PLC directory and PDS.
//! Repositories, commits, and record proofs are real, built with
//! `shrike::repo`.
//!
//! The happy- and sad-path cases from the reference
//! packages/lexicon-resolver/tests/{lexicon,record}.test.ts are ported here,
//! along with transport hardening and hook behavior.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use axum::body::Body;
use axum::extract::{Path, Query, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use serde_json::{Value, json};
use shrike::cbor::Cid;
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::identity::{
    AddressPolicy, Directory, LexiconAuthorityError, TxtError, TxtRecord, TxtResolver,
};
use shrike::lexicon::resolver::{
    FetchedRecord, LexiconResolveError, LexiconResolver, LexiconResolverHooks, MemoryLexiconCache,
    NoHooks, ResolutionSource, ResolvedLexicon,
};
use shrike::repo::{ProofError, Repo};
use shrike::syntax::{Did, Nsid, RecordKey, TidClock};

// ---------------------------------------------------------------------------
// Mock network
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum Canned {
    Car(Vec<u8>),
    /// A body with no Content-Length (chunked transfer encoding).
    Chunked(Vec<u8>),
    Status(u16, String),
    Redirect(String),
    Slow(Duration),
}

#[derive(Default)]
struct Shared {
    docs: Mutex<HashMap<String, Value>>,
    pds: Mutex<HashMap<(String, String), Canned>>,
    plc_hits: AtomicUsize,
    pds_hits: AtomicUsize,
}

#[derive(Default)]
struct FakeTxt {
    records: Mutex<HashMap<String, Result<Vec<TxtRecord>, TxtError>>>,
    queries: AtomicUsize,
}

#[async_trait]
impl TxtResolver for FakeTxt {
    async fn lookup_txt(&self, name: &str) -> Result<Vec<TxtRecord>, TxtError> {
        self.queries.fetch_add(1, Ordering::SeqCst);
        self.records
            .lock()
            .unwrap()
            .get(name)
            .cloned()
            .unwrap_or_else(|| Err(TxtError::NotFound(name.to_owned())))
    }
}

struct Net {
    base: String,
    shared: Arc<Shared>,
    txt: Arc<FakeTxt>,
}

async fn plc(State(s): State<Arc<Shared>>, Path(did): Path<String>) -> Response {
    s.plc_hits.fetch_add(1, Ordering::SeqCst);
    match s.docs.lock().unwrap().get(&did) {
        Some(doc) => axum::Json(doc.clone()).into_response(),
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

async fn get_record(
    State(s): State<Arc<Shared>>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    s.pds_hits.fetch_add(1, Ordering::SeqCst);
    assert_eq!(
        q.get("collection").map(String::as_str),
        Some("com.atproto.lexicon.schema")
    );
    let key = (q["did"].clone(), q["rkey"].clone());
    let canned = s.pds.lock().unwrap().get(&key).cloned();
    match canned {
        Some(Canned::Car(car)) => {
            ([(header::CONTENT_TYPE, "application/vnd.ipld.car")], car).into_response()
        }
        Some(Canned::Chunked(body)) => {
            let stream = futures::stream::iter(
                body.chunks(1024)
                    .map(|c| Ok::<_, std::io::Error>(c.to_vec()))
                    .collect::<Vec<_>>(),
            );
            Body::from_stream(stream).into_response()
        }
        Some(Canned::Status(code, body)) => {
            (StatusCode::from_u16(code).unwrap(), body).into_response()
        }
        Some(Canned::Redirect(to)) => (StatusCode::FOUND, [(header::LOCATION, to)]).into_response(),
        Some(Canned::Slow(delay)) => {
            tokio::time::sleep(delay).await;
            StatusCode::OK.into_response()
        }
        None => (
            StatusCode::BAD_REQUEST,
            r#"{"error":"InvalidRequest","message":"Could not find repo"}"#,
        )
            .into_response(),
    }
}

impl Net {
    async fn start() -> Net {
        let shared = Arc::new(Shared::default());
        let app = axum::Router::new()
            .route("/plc/{did}", get(plc))
            .route("/xrpc/com.atproto.sync.getRecord", get(get_record))
            .with_state(Arc::clone(&shared));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, app).await });
        Net {
            base,
            shared,
            txt: Arc::new(FakeTxt::default()),
        }
    }

    /// A resolver wired to this network, with no caching and a fresh DID
    /// document cache, so every call observes the current network state.
    fn resolver(&self) -> LexiconResolver {
        let dir = Directory::with_plc_url_and_policy(
            &format!("{}/plc", self.base),
            AddressPolicy::AllowLocal,
        );
        LexiconResolver::new()
            .with_directory(Arc::new(dir))
            .with_txt_resolver(self.txt.clone())
            .with_address_policy(AddressPolicy::AllowLocal)
            .with_hooks(Arc::new(NoHooks))
    }

    fn set_txt(&self, name: &str, records: &[&str]) {
        self.set_txt_answer(
            name,
            Ok(records
                .iter()
                .map(|r| vec![r.as_bytes().to_vec()])
                .collect()),
        );
    }

    fn set_txt_answer(&self, name: &str, answer: Result<Vec<TxtRecord>, TxtError>) {
        self.txt
            .records
            .lock()
            .unwrap()
            .insert(name.to_owned(), answer);
    }

    fn set_doc(&self, did: &Did, doc: Value) {
        self.shared
            .docs
            .lock()
            .unwrap()
            .insert(did.to_string(), doc);
    }

    /// Publish `account`'s DID document, naming this server as its PDS.
    fn register(&self, account: &Account) {
        self.set_doc(&account.did, account.doc(&self.base));
    }

    fn can(&self, did: &Did, rkey: &str, canned: Canned) {
        self.shared
            .pds
            .lock()
            .unwrap()
            .insert((did.to_string(), rkey.to_owned()), canned);
    }

    /// Serve the current record proof for `account`'s `rkey`.
    fn serve(&self, account: &Account, rkey: &str) {
        self.can(&account.did, rkey, Canned::Car(account.proof(rkey)));
    }

    fn pds_hits(&self) -> usize {
        self.shared.pds_hits.load(Ordering::SeqCst)
    }
}

struct Account {
    did: Did,
    key: P256SigningKey,
    repo: Repo,
}

impl Account {
    fn new(name: &str) -> Account {
        let did = Did::try_from(format!("did:plc:{name:a<24}").as_str()).unwrap();
        let mut repo = Repo::new(did.clone(), TidClock::new(0).unwrap());
        let key = P256SigningKey::generate();
        repo.commit(&key).unwrap();
        Account { did, key, repo }
    }

    fn doc(&self, pds: &str) -> Value {
        json!({
            "id": self.did.as_str(),
            "alsoKnownAs": [],
            "verificationMethod": [{
                "id": format!("{}#atproto", self.did),
                "type": "Multikey",
                "controller": self.did.as_str(),
                "publicKeyMultibase": self.key.public_key().multibase(),
            }],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": pds,
            }],
        })
    }

    /// Write `record` to the lexicon schema collection at `rkey` and commit.
    fn put(&mut self, rkey: &str, record: Value) -> Cid {
        let bytes =
            shrike::cbor::json::json_to_drisl(&record, shrike::cbor::json::Integers::Safe).unwrap();
        let col = Nsid::try_from("com.atproto.lexicon.schema").unwrap();
        let rk = RecordKey::try_from(rkey).unwrap();
        let cid = match self.repo.get(&col, &rk).unwrap() {
            Some(_) => self.repo.update(&col, &rk, &bytes).unwrap(),
            None => self.repo.create(&col, &rk, &bytes).unwrap(),
        };
        self.repo.commit(&self.key).unwrap();
        cid
    }

    fn proof(&self, rkey: &str) -> Vec<u8> {
        self.repo
            .record_proof(
                &Nsid::try_from("com.atproto.lexicon.schema").unwrap(),
                &RecordKey::try_from(rkey).unwrap(),
            )
            .unwrap()
    }
}

fn lexicon_doc(id: &str) -> Value {
    json!({
        "$type": "com.atproto.lexicon.schema",
        "lexicon": 1,
        "id": id,
        "defs": {},
    })
}

fn nsid(s: &str) -> Nsid {
    Nsid::try_from(s).unwrap()
}

/// A network where alice publishes the `example.alice.*` group, with one
/// lexicon already published and served.
async fn alice_net(rkey: &str) -> (Net, Account) {
    let net = Net::start().await;
    let mut alice = Account::new("alice");
    net.register(&alice);
    net.set_txt("_lexicon.alice.example", &[&format!("did={}", alice.did)]);
    alice.put(rkey, lexicon_doc(rkey));
    net.serve(&alice, rkey);
    (net, alice)
}

// ---------------------------------------------------------------------------
// Happy paths
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolves_lexicon() {
    let net = Net::start().await;
    let mut alice = Account::new("alice");
    net.register(&alice);
    net.set_txt("_lexicon.alice.example", &[&format!("did={}", alice.did)]);
    let doc = json!({
        "$type": "com.atproto.lexicon.schema",
        "lexicon": 1,
        "id": "example.alice.name1",
        "description": "a test lexicon",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["text"],
                    "properties": { "text": { "type": "string", "maxLength": 10 } }
                }
            }
        },
    });
    let cid = alice.put("example.alice.name1", doc.clone());
    net.serve(&alice, "example.alice.name1");

    let got = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap();
    assert_eq!(got.cid, cid);
    assert_eq!(
        got.uri.as_str(),
        format!(
            "at://{}/com.atproto.lexicon.schema/example.alice.name1",
            alice.did
        )
    );
    assert_eq!(got.schema.id, "example.alice.name1");
    assert_eq!(got.json, doc);

    // The resolved JSON loads straight into a catalog and validates records.
    let mut catalog = shrike::lexicon::Catalog::new();
    catalog
        .add_schema(&serde_json::to_vec(&got.json).unwrap())
        .unwrap();
    shrike::lexicon::validate_record(&catalog, "example.alice.name1", &json!({"text": "hi"}))
        .unwrap();
    assert!(
        shrike::lexicon::validate_record(
            &catalog,
            "example.alice.name1",
            &json!({"text": "far too long"})
        )
        .is_err()
    );
}

#[tokio::test]
async fn resolves_lexicon_based_on_override_authority() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    let mut carol = Account::new("carol");
    net.register(&carol);
    let mut alice_doc = lexicon_doc("example.alice.override");
    alice_doc["defs"] = json!({ "alice": { "type": "string" } });
    alice.put("example.alice.override", alice_doc);
    net.serve(&alice, "example.alice.override");
    let mut carol_doc = lexicon_doc("example.alice.override");
    carol_doc["defs"] = json!({ "carol": { "type": "string" } });
    let carol_cid = carol.put("example.alice.override", carol_doc.clone());
    net.serve(&carol, "example.alice.override");

    let resolver = net.resolver();
    let got = resolver
        .fetch(&carol.did, &nsid("example.alice.override"))
        .await
        .unwrap();
    assert_eq!(got.cid, carol_cid);
    assert_eq!(got.json, carol_doc);
    assert!(got.uri.as_str().contains(carol.did.as_str()));
    // Going through DNS still finds alice's.
    let got = resolver.get(&nsid("example.alice.override")).await.unwrap();
    assert!(got.json["defs"].get("alice").is_some());
}

#[tokio::test]
async fn resolves_despite_missing_at_handle() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let mut doc = alice.doc(&net.base);
    doc["alsoKnownAs"] = json!(["notat://alice.example"]);
    net.set_doc(&alice.did, doc);
    net.resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn resolves_large_repo_and_tolerates_chunked_responses() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    for i in 0..300 {
        alice.put(
            &format!("example.alice.n{i:03}"),
            lexicon_doc(&format!("example.alice.n{i:03}")),
        );
    }
    for rkey in [
        "example.alice.n000",
        "example.alice.n150",
        "example.alice.n299",
    ] {
        net.can(&alice.did, rkey, Canned::Chunked(alice.proof(rkey)));
        let got = net.resolver().get(&nsid(rkey)).await.unwrap();
        assert_eq!(got.schema.id, rkey);
    }
}

#[tokio::test]
async fn concurrent_resolutions() {
    let (net, _alice) = alice_net("example.alice.name1").await;
    let resolver = Arc::new(net.resolver());
    let tasks: Vec<_> = (0..16)
        .map(|_| {
            let r = Arc::clone(&resolver);
            tokio::spawn(async move { r.get(&nsid("example.alice.name1")).await })
        })
        .collect();
    for t in tasks {
        t.await.unwrap().unwrap();
    }
}

// ---------------------------------------------------------------------------
// Sad paths: authority
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fails_on_missing_dns_entry() {
    let (net, _alice) = alice_net("example.alice.name1").await;
    let mut bob = Account::new("bob");
    net.register(&bob);
    bob.put("example.bob.name", lexicon_doc("example.bob.name"));
    net.serve(&bob, "example.bob.name");
    let err = net
        .resolver()
        .get(&nsid("example.bob.name"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Authority {
                source: LexiconAuthorityError::NotFound { .. },
                ..
            }
        ),
        "{err:?}"
    );
    assert!(!err.is_transient());
    assert_eq!(net.pds_hits(), 0);
}

#[tokio::test]
async fn authority_is_not_hierarchical() {
    // Only `_lexicon.alice.example` exists; `example.alice.sub.thing` lives
    // under `_lexicon.sub.alice.example`, which must not fall back to it.
    let (net, _alice) = alice_net("example.alice.name1").await;
    let err = net
        .resolver()
        .get(&nsid("example.alice.sub.thing"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::Authority { .. }),
        "{err:?}"
    );
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn fails_on_ambiguous_or_invalid_dns_entry() {
    let (net, alice) = alice_net("example.alice.name1").await;
    net.set_txt(
        "_lexicon.alice.example",
        &[
            &format!("did={}", alice.did),
            "did=did:plc:otherotherotherotherothe",
        ],
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Authority {
                source: LexiconAuthorityError::Ambiguous { count: 2, .. },
                ..
            }
        ),
        "{err:?}"
    );
    net.set_txt("_lexicon.alice.example", &["did=not:a:did"]);
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Authority {
                source: LexiconAuthorityError::InvalidDid { .. },
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn dns_failure_is_transient() {
    let (net, _alice) = alice_net("example.alice.name1").await;
    net.set_txt_answer(
        "_lexicon.alice.example",
        Err(TxtError::Failed {
            name: "_lexicon.alice.example".into(),
            message: "SERVFAIL".into(),
        }),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(err.is_transient(), "{err:?}");
}

// ---------------------------------------------------------------------------
// Sad paths: identity
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fails_on_unresolvable_did() {
    let (net, _alice) = alice_net("example.alice.name1").await;
    // A did:plc the directory does not know, and a DID method it cannot
    // resolve (the reference suite's `did:example`).
    for did in ["did:plc:unknownunknownunknownunk", "did:example:simpleDid"] {
        net.set_txt("_lexicon.alice.example", &[&format!("did={did}")]);
        let err = net
            .resolver()
            .get(&nsid("example.alice.name1"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, LexiconResolveError::Identity { .. }),
            "{did}: {err:?}"
        );
    }
    assert_eq!(net.pds_hits(), 0);
}

#[tokio::test]
async fn fails_on_missing_signing_key() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let mut doc = alice.doc(&net.base);
    doc["verificationMethod"][0]["id"] = json!(format!("{}#not_atproto", alice.did));
    net.set_doc(&alice.did, doc);
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::MissingSigningKey { .. }),
        "{err:?}"
    );
    assert_eq!(net.pds_hits(), 0);
}

#[tokio::test]
async fn fails_on_missing_pds() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let mut doc = alice.doc(&net.base);
    doc["service"][0]["id"] = json!("#not_atproto_pds");
    net.set_doc(&alice.did, doc);
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::MissingPds { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sad paths: record and proof
// ---------------------------------------------------------------------------

#[tokio::test]
async fn fails_on_missing_record() {
    let (net, alice) = alice_net("example.alice.name1").await;
    // The reference PDS answers with a proof of absence.
    net.serve(&alice, "example.alice.missing");
    let err = net
        .resolver()
        .get(&nsid("example.alice.missing"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::RecordNotFound { .. }),
        "{err:?}"
    );
    // Or with an XRPC RecordNotFound error.
    net.can(
        &alice.did,
        "example.alice.missing",
        Canned::Status(400, r#"{"error":"RecordNotFound"}"#.into()),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.missing"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::RecordNotFound { .. }),
        "{err:?}"
    );
    assert!(!err.is_transient());
}

#[tokio::test]
async fn fails_on_mismatched_id() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    alice.put(
        "example.alice.mismatch",
        lexicon_doc("example.test1.mismatch.bad"),
    );
    net.serve(&alice, "example.alice.mismatch");
    let err = net
        .resolver()
        .get(&nsid("example.alice.mismatch"))
        .await
        .unwrap_err();
    match err {
        LexiconResolveError::IdMismatch { id, .. } => assert_eq!(id, "example.test1.mismatch.bad"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn fails_on_bad_verification() {
    let (net, alice) = alice_net("example.alice.name1").await;
    // Switch alice's DID document to a key that did not sign her commits.
    let mut doc = alice.doc(&net.base);
    doc["verificationMethod"][0]["publicKeyMultibase"] =
        json!(P256SigningKey::generate().public_key().multibase());
    net.set_doc(&alice.did, doc);
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Proof {
                source: ProofError::InvalidSignature(_),
                ..
            }
        ),
        "{err:?}"
    );
    // Restoring the key restores resolution.
    net.register(&alice);
    net.resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap();
}

#[tokio::test]
async fn fails_on_proof_from_another_repo() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let mut mallory = Account::new("mallory");
    mallory.put("example.alice.name1", lexicon_doc("example.alice.name1"));
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Car(mallory.proof("example.alice.name1")),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Proof {
                source: ProofError::DidMismatch { .. },
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn fails_on_corrupted_car_block() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let car = alice.proof("example.alice.name1");
    let (roots, mut blocks) = shrike::car::read_all(&car[..]).unwrap();
    let record = blocks.last_mut().unwrap();
    record.data = vec![0xa0]; // `{}`, no longer matching its CID
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Car(shrike::car::write_all(&roots, &blocks).unwrap()),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            LexiconResolveError::Proof {
                source: ProofError::CidMismatch(_),
                ..
            }
        ),
        "{err:?}"
    );
}

#[tokio::test]
async fn fails_on_garbage_proof() {
    let (net, alice) = alice_net("example.alice.name1").await;
    for body in [vec![], b"<html>hello</html>".to_vec(), vec![0xff; 64]] {
        net.can(&alice.did, "example.alice.name1", Canned::Car(body));
        let err = net
            .resolver()
            .get(&nsid("example.alice.name1"))
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                LexiconResolveError::Proof {
                    source: ProofError::Car(_),
                    ..
                }
            ),
            "{err:?}"
        );
    }
}

#[tokio::test]
async fn fails_on_invalid_lexicon_document() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    let mut doc = lexicon_doc("example.alice.baddoc");
    doc["lexicon"] = json!(999);
    alice.put("example.alice.baddoc", doc);
    net.serve(&alice, "example.alice.baddoc");
    let err = net
        .resolver()
        .get(&nsid("example.alice.baddoc"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::InvalidDocument { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn fails_on_wrong_record_type() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    let mut doc = lexicon_doc("example.alice.wrongtype");
    doc["$type"] = json!("app.bsky.feed.post");
    alice.put("example.alice.wrongtype", doc);
    net.serve(&alice, "example.alice.wrongtype");
    let err = net
        .resolver()
        .get(&nsid("example.alice.wrongtype"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::InvalidRecord { .. }),
        "{err:?}"
    );
}

// ---------------------------------------------------------------------------
// Sad paths: transport hardening
// ---------------------------------------------------------------------------

#[tokio::test]
async fn deny_local_refuses_local_pds_before_connecting() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let resolver = || net.resolver().with_address_policy(AddressPolicy::DenyLocal);

    // A literal loopback endpoint is refused up front.
    let err = resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::InvalidPdsEndpoint { .. }),
        "{err:?}"
    );

    // A hostname resolving to loopback is refused at connect time.
    let port = net.base.rsplit(':').next().unwrap();
    net.set_doc(&alice.did, alice.doc(&format!("http://localhost:{port}")));
    let err = resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(matches!(err, LexiconResolveError::Http { .. }), "{err:?}");

    assert_eq!(net.pds_hits(), 0);
}

#[tokio::test]
async fn refuses_unusable_pds_endpoints() {
    let (net, alice) = alice_net("example.alice.name1").await;
    for endpoint in [
        "ftp://pds.example.com",
        "not a url",
        "https://u:p@pds.example.com",
    ] {
        net.set_doc(&alice.did, alice.doc(endpoint));
        let err = net
            .resolver()
            .get(&nsid("example.alice.name1"))
            .await
            .unwrap_err();
        assert!(
            matches!(err, LexiconResolveError::InvalidPdsEndpoint { .. }),
            "{endpoint}: {err:?}"
        );
    }
}

#[tokio::test]
async fn does_not_follow_redirects() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let mut other = Account::new("other");
    other.put("example.alice.name1", lexicon_doc("example.alice.name1"));
    net.serve(&other, "example.alice.name1");
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Redirect(format!(
            "{}/xrpc/com.atproto.sync.getRecord?did={}&collection=com.atproto.lexicon.schema&rkey=example.alice.name1",
            net.base, other.did
        )),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::HttpStatus { status: 302, .. }),
        "{err:?}"
    );
    assert_eq!(net.pds_hits(), 1, "redirect target must not be fetched");
}

#[tokio::test]
async fn caps_response_size() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let proof = alice.proof("example.alice.name1");
    let limit = proof.len() - 1;

    // Rejected from Content-Length.
    let err = net
        .resolver()
        .with_max_proof_bytes(limit)
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::TooLarge { .. }),
        "{err:?}"
    );

    // Rejected while streaming, with no Content-Length to go on.
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Chunked(proof.clone()),
    );
    let err = net
        .resolver()
        .with_max_proof_bytes(limit)
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::TooLarge { .. }),
        "{err:?}"
    );

    // Exactly at the limit is fine.
    net.resolver()
        .with_max_proof_bytes(proof.len())
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap();

    // The default cap rejects a hostile multi-megabyte body.
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Chunked(vec![0; 3 << 20]),
    );
    let err = net
        .resolver()
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(
        matches!(err, LexiconResolveError::TooLarge { .. }),
        "{err:?}"
    );
}

#[tokio::test]
async fn reports_http_errors() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let cases = [
        (500, "oops".to_string(), true),
        (503, String::new(), true),
        (429, String::new(), true),
        (
            400,
            r#"{"error":"RepoTakendown","message":"gone"}"#.to_string(),
            false,
        ),
        (404, "x".repeat(100_000), false),
    ];
    for (status, body, transient) in cases {
        net.can(
            &alice.did,
            "example.alice.name1",
            Canned::Status(status, body.clone()),
        );
        let err = net
            .resolver()
            .get(&nsid("example.alice.name1"))
            .await
            .unwrap_err();
        match &err {
            LexiconResolveError::HttpStatus {
                status: got,
                detail,
                ..
            } => {
                assert_eq!(*got, status);
                if body.contains("RepoTakendown") {
                    assert_eq!(detail, "RepoTakendown: gone");
                } else {
                    assert!(detail.is_empty(), "{detail}");
                }
            }
            other => panic!("{status}: {other:?}"),
        }
        assert_eq!(err.is_transient(), transient, "{status}");
    }
}

#[tokio::test]
async fn times_out_slow_pds() {
    let (net, alice) = alice_net("example.alice.name1").await;
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Slow(Duration::from_secs(10)),
    );
    let start = std::time::Instant::now();
    let err = net
        .resolver()
        .with_timeout(Duration::from_millis(200))
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    assert!(matches!(err, LexiconResolveError::Http { .. }), "{err:?}");
    assert!(err.is_transient());
    assert!(start.elapsed() < Duration::from_secs(5));
}

// ---------------------------------------------------------------------------
// Hooks and caching
// ---------------------------------------------------------------------------

#[tokio::test]
async fn memory_cache_skips_the_network() {
    let (net, mut alice) = alice_net("example.alice.name1").await;
    alice.put("example.alice.name2", lexicon_doc("example.alice.name2"));
    net.serve(&alice, "example.alice.name2");
    let cache = Arc::new(MemoryLexiconCache::new());
    let resolver = net.resolver().with_hooks(cache.clone());

    let first = resolver.get(&nsid("example.alice.name1")).await.unwrap();
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 1);
    assert_eq!(net.pds_hits(), 1);

    let again = resolver.get(&nsid("example.alice.name1")).await.unwrap();
    assert_eq!(again.cid, first.cid);
    assert_eq!(again.json, first.json);
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 1);
    assert_eq!(net.pds_hits(), 1);

    // Another NSID in the same group reuses the authority but fetches.
    resolver.get(&nsid("example.alice.name2")).await.unwrap();
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 1);
    assert_eq!(net.pds_hits(), 2);

    // Purging forces a full resolution again.
    cache.purge(&nsid("example.alice.name1"));
    resolver.get(&nsid("example.alice.name1")).await.unwrap();
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 2);
    assert_eq!(net.pds_hits(), 3);
}

#[tokio::test]
async fn memory_cache_does_not_cache_failures() {
    let (net, alice) = alice_net("example.alice.name1").await;
    net.can(
        &alice.did,
        "example.alice.name1",
        Canned::Status(500, String::new()),
    );
    let resolver = net
        .resolver()
        .with_hooks(Arc::new(MemoryLexiconCache::new()));
    resolver
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap_err();
    net.serve(&alice, "example.alice.name1");
    resolver.get(&nsid("example.alice.name1")).await.unwrap();
    assert_eq!(net.pds_hits(), 2);
}

#[derive(Default)]
struct Recorder {
    events: Mutex<Vec<String>>,
    authority: Option<Did>,
    record: Option<FetchedRecord>,
}

#[async_trait]
impl LexiconResolverHooks for Recorder {
    async fn on_resolve_authority(&self, _nsid: &Nsid) -> Option<Did> {
        self.events.lock().unwrap().push("authority".into());
        self.authority.clone()
    }
    async fn on_resolve_authority_result(&self, _: &Nsid, did: &Did, source: ResolutionSource) {
        self.events
            .lock()
            .unwrap()
            .push(format!("authority_result {did} {source:?}"));
    }
    async fn on_resolve_authority_error(&self, _: &Nsid, _: &LexiconResolveError) {
        self.events.lock().unwrap().push("authority_error".into());
    }
    async fn on_fetch(&self, _: &Did, _: &Nsid) -> Option<FetchedRecord> {
        self.events.lock().unwrap().push("fetch".into());
        self.record.clone()
    }
    async fn on_fetch_result(
        &self,
        _: &Did,
        _: &Nsid,
        lexicon: &ResolvedLexicon,
        source: ResolutionSource,
    ) {
        self.events
            .lock()
            .unwrap()
            .push(format!("fetch_result {} {source:?}", lexicon.schema.id));
    }
    async fn on_fetch_error(&self, _: &Did, _: &Nsid, _: &LexiconResolveError) {
        self.events.lock().unwrap().push("fetch_error".into());
    }
}

#[tokio::test]
async fn hooks_observe_every_step() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let hooks = Arc::new(Recorder::default());
    net.resolver()
        .with_hooks(hooks.clone())
        .get(&nsid("example.alice.name1"))
        .await
        .unwrap();
    assert_eq!(
        *hooks.events.lock().unwrap(),
        [
            "authority".to_string(),
            format!("authority_result {} Network", alice.did),
            "fetch".into(),
            "fetch_result example.alice.name1 Network".into(),
        ]
    );

    // The authority resolves but the record does not.
    let hooks = Arc::new(Recorder::default());
    net.resolver()
        .with_hooks(hooks.clone())
        .get(&nsid("example.alice.nope"))
        .await
        .unwrap_err();
    assert_eq!(
        *hooks.events.lock().unwrap(),
        [
            "authority".to_string(),
            format!("authority_result {} Network", alice.did),
            "fetch".into(),
            "fetch_error".into(),
        ]
    );

    // The authority does not resolve, so nothing is fetched.
    let hooks = Arc::new(Recorder::default());
    net.resolver()
        .with_hooks(hooks.clone())
        .get(&nsid("example.nobody.thing"))
        .await
        .unwrap_err();
    assert_eq!(
        *hooks.events.lock().unwrap(),
        ["authority", "authority_error"]
    );
}

#[tokio::test]
async fn hooks_can_supply_authority_and_record() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let record = {
        let bytes = shrike::cbor::json::json_to_drisl(
            &lexicon_doc("example.alice.cached"),
            shrike::cbor::json::Integers::Safe,
        )
        .unwrap();
        FetchedRecord {
            cid: Cid::compute(shrike::cbor::Codec::Drisl, &bytes),
            record: bytes,
        }
    };
    let hooks = Arc::new(Recorder {
        authority: Some(alice.did.clone()),
        record: Some(record.clone()),
        ..Default::default()
    });
    let got = net
        .resolver()
        .with_hooks(hooks.clone())
        .get(&nsid("example.alice.cached"))
        .await
        .unwrap();
    assert_eq!(got.cid, record.cid);
    assert_eq!(net.txt.queries.load(Ordering::SeqCst), 0);
    assert_eq!(net.pds_hits(), 0);
    assert_eq!(
        *hooks.events.lock().unwrap(),
        [
            "authority".to_string(),
            format!("authority_result {} Hook", alice.did),
            "fetch".into(),
            "fetch_result example.alice.cached Hook".into(),
        ]
    );
}

#[tokio::test]
async fn hook_records_are_still_validated() {
    let (net, alice) = alice_net("example.alice.name1").await;
    let bytes = shrike::cbor::json::json_to_drisl(
        &lexicon_doc("example.alice.name1"),
        shrike::cbor::json::Integers::Safe,
    )
    .unwrap();
    let cid = Cid::compute(shrike::cbor::Codec::Drisl, &bytes);

    // A record that does not match its CID (a corrupted cache entry).
    let mut tampered = bytes.clone();
    *tampered.last_mut().unwrap() ^= 1;
    // A record for a different NSID.
    let other = shrike::cbor::json::json_to_drisl(
        &lexicon_doc("example.alice.other"),
        shrike::cbor::json::Integers::Safe,
    )
    .unwrap();
    let other_cid = Cid::compute(shrike::cbor::Codec::Drisl, &other);

    for record in [
        FetchedRecord {
            cid,
            record: tampered,
        },
        FetchedRecord {
            cid: other_cid,
            record: other,
        },
    ] {
        let hooks = Arc::new(Recorder {
            authority: Some(alice.did.clone()),
            record: Some(record),
            ..Default::default()
        });
        net.resolver()
            .with_hooks(hooks.clone())
            .get(&nsid("example.alice.name1"))
            .await
            .unwrap_err();
        assert_eq!(hooks.events.lock().unwrap().last().unwrap(), "fetch_error");
    }
    assert_eq!(net.pds_hits(), 0);
}

// ---------------------------------------------------------------------------
// Live network
// ---------------------------------------------------------------------------

/// Resolves a real, published lexicon. Run with `--ignored`.
#[tokio::test]
#[ignore = "requires network access"]
async fn live_resolves_app_bsky_feed_post() {
    let got = LexiconResolver::new()
        .get(&nsid("app.bsky.feed.post"))
        .await
        .unwrap();
    assert_eq!(got.schema.id, "app.bsky.feed.post");
    assert!(got.schema.defs.contains_key("main"));
}
