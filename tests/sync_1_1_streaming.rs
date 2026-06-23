#![cfg(all(feature = "sync", feature = "streaming"))]
#![allow(clippy::unwrap_used, clippy::expect_used)]

#[allow(dead_code)]
mod support;

use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use async_trait::async_trait;
use futures::{SinkExt, StreamExt};
use shrike::crypto::{P256VerifyingKey, SigningKey, VerifyingKey};
use shrike::identity::{Identity, IdentityError};
use shrike::streaming::{Client, Config, Event, Operation};
use shrike::sync::{
    ChainState, HostingPolicy, IdentityResolver, MemStateStore, StateStore, SyncError,
    SyncRepoSource, Verifier, VerifierOptions,
};
use shrike::syntax::Did;
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

use support::sync1::{
    CommitFixture, account_frame, commit_chain_for_did, commit_fixture_create,
    commit_fixture_create_for_did, commit_fixture_update, commit_frame_with_since_and_flags,
    mutate_signed_commit, raw_op, sync_commit_car, sync_frame,
};

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[tokio::test]
async fn subscribe_without_verifier_keeps_existing_commit_behavior() {
    let fixture = commit_fixture_create();
    let url = serve_frames(vec![commit_frame_from_fixture(&fixture)]).await;
    let client = Client::new(Config {
        url,
        batch_size: Some(1),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let batch = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert_eq!(batch.len(), 1);
    assert!(matches!(batch[0], Event::Commit { .. }));
    let Event::Commit {
        did, operations, ..
    } = &batch[0]
    else {
        return;
    };
    assert_eq!(did, &fixture.raw_commit.repo);
    assert_eq!(operations.len(), 1);
    assert!(matches!(operations[0], Operation::Create { .. }));
}

#[tokio::test]
async fn subscribe_with_verifier_yields_verified_ops() {
    let fixture = commit_fixture_create();
    let verifier = verifier_for_fixture(&fixture, HostingPolicy::Track, None);
    let store = verifier.state_store();
    let url = serve_frames(vec![commit_frame_from_fixture(&fixture)]).await;
    let client = Client::new(Config {
        url,
        batch_size: Some(1),
        verifier: Some(Arc::new(verifier)),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let batch = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(matches!(batch[0], Event::Commit { .. }));
    let Event::Commit {
        operations, rev, ..
    } = &batch[0]
    else {
        return;
    };
    assert_eq!(*rev, fixture.raw_commit.rev);
    assert!(matches!(operations[0], Operation::Create { .. }));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verifier_error_flushes_partial_batch_before_error() {
    let fixture = commit_fixture_create();
    let mut bad = commit_fixture_update();
    let bad_rev =
        shrike::syntax::Tid::new(fixture.raw_commit.rev.timestamp_micros() + 1, 0).unwrap();
    mutate_signed_commit(&mut bad, |commit| commit.rev = bad_rev);
    bad.raw_commit.rev = bad_rev;
    bad.raw_commit.seq = fixture.raw_commit.seq + 1;
    let wrong_key = shrike::crypto::P256SigningKey::generate()
        .public_key()
        .to_bytes();
    let verifier = verifier_for_did(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes, wrong_key, wrong_key],
        HostingPolicy::Track,
        None,
    );
    let url = serve_frames(vec![
        commit_frame_from_fixture(&fixture),
        commit_frame_from_fixture(&bad),
    ])
    .await;
    let client = Client::new(Config {
        url,
        batch_size: Some(10),
        verifier: Some(Arc::new(verifier)),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let batch = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let err = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();

    assert_eq!(batch.len(), 1);
    assert!(err.to_string().contains("invalid signature"));
}

#[tokio::test]
async fn account_event_gates_following_commit() {
    let fixture = commit_fixture_create();
    let verifier = verifier_for_fixture(&fixture, HostingPolicy::Gate, None);
    let store = verifier.state_store();
    let url = serve_frames(vec![
        account_frame(
            &fixture.raw_commit.repo,
            10,
            false,
            Some("takendown"),
            "2026-06-09T15:00:00.000Z",
        ),
        commit_frame_from_fixture(&fixture),
    ])
    .await;
    let client = Client::new(Config {
        url,
        batch_size: Some(10),
        verifier: Some(Arc::new(verifier)),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let batch = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let err = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();

    assert!(matches!(batch[0], Event::Account { active: false, .. }));
    assert!(err.to_string().contains("repo inactive"));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn sync_resync_ops_are_emitted_as_stream_events() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let verifier = verifier_for_fixture(&fixture, HostingPolicy::Track, Some(repo_source));
    verifier
        .state_store()
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();
    let url = serve_frames(vec![sync_frame(
        &fixture.raw_commit.repo,
        &fixture.raw_commit.rev.to_string(),
        fixture.raw_commit.seq + 1,
        &sync_commit_car(&fixture),
    )])
    .await;
    let client = Client::new(Config {
        url,
        batch_size: Some(1),
        verifier: Some(Arc::new(verifier)),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let batch = tokio::time::timeout(TEST_TIMEOUT, stream.next())
        .await
        .unwrap()
        .unwrap()
        .unwrap();

    assert!(matches!(batch[0], Event::Commit { .. }));
    let Event::Commit { operations, .. } = &batch[0] else {
        return;
    };
    assert!(
        matches!(
            &operations[0],
            Operation::Resync { record, .. } if !record.is_empty()
        ),
        "resync op should carry record bytes from the fetched repo, got {:?}",
        operations[0]
    );
}

#[tokio::test]
async fn cursor_advances_past_silently_dropped_frames() {
    // A rev-replay commit is silently dropped by the verifier, but its seq must
    // still advance the cursor watermark so a restart doesn't reprocess it.
    let fixture = commit_fixture_create();
    let verifier = verifier_for_fixture(&fixture, HostingPolicy::Track, None);
    // Seed chain state at the commit's own rev so the incoming commit is a
    // replay (rev <= persisted rev) and gets dropped.
    verifier
        .state_store()
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: fixture.raw_commit.rev.to_string(),
                data: fixture.post_data,
            },
        )
        .await
        .unwrap();
    let dropped_seq = fixture.raw_commit.seq;
    let url = serve_frames(vec![commit_frame_from_fixture(&fixture)]).await;
    let client = Client::new(Config {
        url,
        batch_size: Some(10),
        batch_timeout: Some(std::time::Duration::from_millis(50)),
        verifier: Some(Arc::new(verifier)),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    // The replay is dropped, so no batch is yielded; poll until the cursor
    // catches up via the timeout-driven watermark flush, or the stream ends.
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    loop {
        if client.cursor() == Some(dropped_seq) {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "cursor never advanced past dropped seq"
        );
        tokio::select! {
            _ = stream.next() => {}
            _ = tokio::time::sleep(std::time::Duration::from_millis(20)) => {}
        }
    }
    assert_eq!(client.cursor(), Some(dropped_seq));
}

// --- Parallel verification integration tests ---

const DID_A: &str = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
const DID_B: &str = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb";

/// Resolver that maps each DID to its own key, with an optional barrier that
/// blocks every lookup until released — used to prove cross-DID concurrency.
struct MultiDidResolver {
    keys: HashMap<String, [u8; 33]>,
    gate: Option<Arc<tokio::sync::Barrier>>,
}

impl MultiDidResolver {
    fn new(entries: Vec<(&str, [u8; 33])>, gate: Option<Arc<tokio::sync::Barrier>>) -> Self {
        Self {
            keys: entries
                .into_iter()
                .map(|(did, key)| (did.to_owned(), key))
                .collect(),
            gate,
        }
    }
}

#[async_trait]
impl IdentityResolver for MultiDidResolver {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        if let Some(gate) = &self.gate {
            gate.wait().await;
        }
        let key = *self
            .keys
            .get(did.as_str())
            .ok_or_else(|| IdentityError::NotFound(did.to_string()))?;
        let mut keys = HashMap::new();
        keys.insert(
            "#atproto".to_owned(),
            Box::new(P256VerifyingKey::from_bytes(&key).unwrap()) as Box<dyn VerifyingKey>,
        );
        Ok(Arc::new(Identity {
            did: did.clone(),
            handle: None,
            keys,
            services: HashMap::new(),
        }))
    }

    async fn purge(&self, _did: &Did) -> Result<(), IdentityError> {
        Ok(())
    }
}

fn parallel_verifier(resolver: Arc<dyn IdentityResolver>) -> Verifier {
    let store = Arc::new(MemStateStore::new());
    Verifier::new(VerifierOptions::new(store as Arc<dyn StateStore>, resolver))
}

#[tokio::test]
async fn parallel_verifies_different_dids_concurrently() {
    let a = commit_fixture_create_for_did(DID_A, 1);
    let b = commit_fixture_create_for_did(DID_B, 2);
    // The barrier requires BOTH DIDs' lookups to be in flight at once; under a
    // serial verifier this would deadlock (timeout).
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let resolver = Arc::new(MultiDidResolver::new(
        vec![(DID_A, a.public_key_bytes), (DID_B, b.public_key_bytes)],
        Some(gate),
    ));
    let verifier = parallel_verifier(resolver);
    let url = serve_frames(vec![
        commit_frame_from_fixture(&a),
        commit_frame_from_fixture(&b),
    ])
    .await;
    let client = Client::new(Config {
        url,
        batch_size: Some(2),
        batch_timeout: Some(std::time::Duration::from_millis(50)),
        verifier: Some(Arc::new(verifier)),
        parallelism: Some(4),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let mut seen = 0;
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    while seen < 2 {
        let batch = tokio::time::timeout(deadline - tokio::time::Instant::now(), stream.next())
            .await
            .expect("parallel verification deadlocked — DIDs were not concurrent")
            .unwrap()
            .unwrap();
        seen += batch
            .iter()
            .filter(|e| matches!(e, Event::Commit { .. }))
            .count();
    }
    assert_eq!(seen, 2);
}

#[tokio::test]
async fn parallel_preserves_per_did_order() {
    // A valid 5-commit chain for one DID. Even with parallelism, same-DID FIFO
    // must hold: every commit chains off the previous, so any reordering would
    // surface as a chain break and drop later commits. All five delivering in
    // rev order proves the per-key serialization.
    let chain = commit_chain_for_did(DID_A, 5);
    let resolver = Arc::new(MultiDidResolver::new(
        vec![(DID_A, chain[0].public_key_bytes)],
        None,
    ));
    let verifier = parallel_verifier(resolver);
    let frames: Vec<Vec<u8>> = chain
        .iter()
        .map(support::sync1::commit_frame_for_fixture)
        .collect();
    let expected_revs: Vec<_> = chain.iter().map(|c| c.raw_commit.rev).collect();
    let url = serve_frames(frames).await;
    let client = Client::new(Config {
        url,
        batch_size: Some(10),
        batch_timeout: Some(std::time::Duration::from_millis(20)),
        verifier: Some(Arc::new(verifier)),
        parallelism: Some(4),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let mut revs = Vec::new();
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    while revs.len() < 5 && tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(batch))) =
            tokio::time::timeout(std::time::Duration::from_millis(100), stream.next()).await
        {
            for e in &batch {
                if let Event::Commit { rev, .. } = e {
                    revs.push(*rev);
                }
            }
        }
    }
    assert_eq!(
        revs, expected_revs,
        "same-DID commits must be delivered in chain order"
    );
}

#[tokio::test]
async fn parallel_cursor_is_monotonic() {
    let a = commit_fixture_create_for_did(DID_A, 10);
    let b = commit_fixture_create_for_did(DID_B, 20);
    let resolver = Arc::new(MultiDidResolver::new(
        vec![(DID_A, a.public_key_bytes), (DID_B, b.public_key_bytes)],
        None,
    ));
    let verifier = parallel_verifier(resolver);
    let url = serve_frames(vec![
        commit_frame_from_fixture(&a),
        commit_frame_from_fixture(&b),
    ])
    .await;
    let client = Client::new(Config {
        url,
        batch_size: Some(1),
        batch_timeout: Some(std::time::Duration::from_millis(20)),
        verifier: Some(Arc::new(verifier)),
        parallelism: Some(4),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let mut last = -1;
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    let mut delivered = 0;
    while delivered < 2 && tokio::time::Instant::now() < deadline {
        if let Ok(Some(Ok(batch))) =
            tokio::time::timeout(std::time::Duration::from_millis(100), stream.next()).await
        {
            delivered += batch.len();
        }
        let cur = client.cursor().unwrap_or(-1);
        assert!(cur >= last, "cursor regressed: {cur} < {last}");
        last = cur;
    }
}

#[tokio::test]
async fn parallel_queue_overflow_surfaces_error() {
    // per_did_queue = 1, and the verifier blocks on a barrier so the first
    // unit for DID_A stays in flight while a burst of same-DID commits arrive,
    // overflowing the per-key queue.
    let a = commit_fixture_create_for_did(DID_A, 1);
    let mut frames = vec![commit_frame_from_fixture(&a)];
    for seq in 2..=6 {
        let extra = commit_fixture_create_for_did(DID_A, seq);
        frames.push(commit_frame_from_fixture(&extra));
    }
    // Barrier of 2 holds every lookup until a second waiter arrives; with one
    // in-flight unit and no second verification permitted, the active unit
    // blocks, forcing the rest into the (cap-1) per-DID queue → overflow.
    let gate = Arc::new(tokio::sync::Barrier::new(2));
    let resolver = Arc::new(MultiDidResolver::new(
        vec![(DID_A, a.public_key_bytes)],
        Some(gate),
    ));
    let verifier = parallel_verifier(resolver);
    let url = serve_frames(frames).await;
    let client = Client::new(Config {
        url,
        batch_size: Some(10),
        batch_timeout: Some(std::time::Duration::from_millis(50)),
        verifier: Some(Arc::new(verifier)),
        parallelism: Some(4),
        per_did_queue: Some(1),
        ..Config::default()
    });

    let mut stream = Box::pin(client.subscribe());
    let mut saw_overflow = false;
    let deadline = tokio::time::Instant::now() + TEST_TIMEOUT;
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(std::time::Duration::from_millis(100), stream.next()).await {
            Ok(Some(Err(err))) => {
                if matches!(err, shrike::streaming::StreamError::QueueOverflow { .. }) {
                    saw_overflow = true;
                    break;
                }
            }
            Ok(Some(Ok(_))) => {}
            _ => {}
        }
    }
    assert!(
        saw_overflow,
        "expected a QueueOverflow error under per_did_queue=1"
    );
}

async fn serve_frames(frames: Vec<Vec<u8>>) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut ws = tokio_tungstenite::accept_async(stream).await.unwrap();
        for frame in frames {
            ws.send(Message::Binary(frame.into())).await.unwrap();
        }
        let _ = ws.close(None).await;
    });
    format!("ws://{addr}")
}

fn commit_frame_from_fixture(fixture: &CommitFixture) -> Vec<u8> {
    let ops = fixture
        .raw_commit
        .ops
        .iter()
        .map(|op| {
            raw_op(
                match op.action.as_str() {
                    "create" => "create",
                    "update" => "update",
                    "delete" => "delete",
                    _ => "unknown",
                },
                "app.bsky.feed.post/abc",
                op.cid,
                op.prev,
            )
        })
        .collect();
    commit_frame_with_since_and_flags(
        &fixture.raw_commit.repo,
        &fixture.raw_commit.rev.to_string(),
        "3aaaaaaaaaaaa",
        fixture.raw_commit.seq,
        fixture.raw_commit.commit,
        fixture.raw_commit.prev_data.unwrap(),
        &fixture.raw_commit.blocks,
        fixture.raw_commit.too_big,
        fixture.raw_commit.rebase,
        ops,
    )
}

fn verifier_for_fixture(
    fixture: &CommitFixture,
    hosting_policy: HostingPolicy,
    repo_source: Option<Arc<dyn SyncRepoSource>>,
) -> Verifier {
    verifier_for_did(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        hosting_policy,
        repo_source,
    )
}

fn verifier_for_did(
    did: Did,
    keys: Vec<[u8; 33]>,
    hosting_policy: HostingPolicy,
    repo_source: Option<Arc<dyn SyncRepoSource>>,
) -> Verifier {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let mut options = VerifierOptions::new(
        store as Arc<dyn StateStore>,
        resolver as Arc<dyn IdentityResolver>,
    )
    .with_hosting_policy(hosting_policy);
    if let Some(repo_source) = repo_source {
        options = options.with_repo_source(repo_source);
    }
    Verifier::new(options)
}

struct FakeIdentityResolver {
    did: Did,
    keys: std::sync::Mutex<VecDeque<[u8; 33]>>,
}

impl FakeIdentityResolver {
    fn new(did: Did, keys: Vec<[u8; 33]>) -> Self {
        Self {
            did,
            keys: std::sync::Mutex::new(VecDeque::from(keys)),
        }
    }
}

#[async_trait]
impl IdentityResolver for FakeIdentityResolver {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        assert_eq!(did, &self.did);
        let mut keys = self.keys.lock().unwrap();
        let key = if keys.len() > 1 {
            keys.pop_front().unwrap()
        } else {
            *keys.front().unwrap()
        };
        let mut keys = HashMap::new();
        keys.insert(
            "#atproto".to_owned(),
            Box::new(P256VerifyingKey::from_bytes(&key).unwrap()) as Box<dyn VerifyingKey>,
        );
        Ok(Arc::new(Identity {
            did: did.clone(),
            handle: None,
            keys,
            services: HashMap::new(),
        }))
    }

    async fn purge(&self, _did: &Did) -> Result<(), IdentityError> {
        Ok(())
    }
}

struct FakeRepoSource {
    cars: tokio::sync::Mutex<VecDeque<Vec<u8>>>,
    calls: AtomicUsize,
}

impl FakeRepoSource {
    fn with_car(car: Vec<u8>) -> Self {
        Self {
            cars: tokio::sync::Mutex::new(VecDeque::from([car])),
            calls: AtomicUsize::new(0),
        }
    }
}

#[async_trait]
impl SyncRepoSource for FakeRepoSource {
    async fn get_repo_car(&self, _did: &Did) -> Result<Vec<u8>, SyncError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.cars
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| SyncError::Sync("no fake getRepo CAR queued".to_owned()))
    }
}
