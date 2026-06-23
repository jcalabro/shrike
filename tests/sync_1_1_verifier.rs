#![cfg(feature = "sync")]
#![allow(clippy::unwrap_used)]

#[allow(dead_code)]
mod support;

use std::collections::{HashMap, VecDeque};
use std::error::Error;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use shrike::car;
use shrike::cbor::{Cid, Codec};
use shrike::crypto::{P256VerifyingKey, SigningKey, VerifyingKey};
use shrike::identity::{Identity, IdentityError};
use shrike::sync::{
    ChainState, HostingPolicy, HostingState, IdentityResolver, LegacyCommitPolicy,
    MAX_COMMIT_BLOCKS_BYTES, MAX_COMMIT_OPS, MemStateStore, RepoLoadLimits, StateStore,
    StateStoreError, StateStoreOperation, SyncError, SyncRepoSource, Verifier, VerifierError,
    VerifierOptions, VerifierPolicy, VerifierStats, check_op_cids, decode_commit_car,
    invert_commit,
};
use shrike::syntax::{Did, Tid};

use support::sync1::{
    commit_fixture_cid_data_mismatch, commit_fixture_create, commit_fixture_delete,
    commit_fixture_duplicate_paths, commit_fixture_missing_commit_block,
    commit_fixture_multi_op_disjoint, commit_fixture_root_mismatch, commit_fixture_update,
    mutate_signed_commit,
};

const TEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(2);

#[test]
fn invert_create_returns_previous_root() {
    let fixture = commit_fixture_create();

    let previous_root = invert_commit(&fixture.raw_commit).unwrap();

    assert_eq!(previous_root, fixture.prev_data);
}

#[test]
fn invert_update_uses_op_prev_cid() {
    let fixture = commit_fixture_update();

    let previous_root = invert_commit(&fixture.raw_commit).unwrap();

    assert_eq!(previous_root, fixture.prev_data);
}

#[test]
fn invert_delete_uses_op_prev_cid() {
    let fixture = commit_fixture_delete();

    let previous_root = invert_commit(&fixture.raw_commit).unwrap();

    assert_eq!(previous_root, fixture.prev_data);
}

#[test]
fn invert_multi_op_disjoint_returns_previous_root() {
    let fixture = commit_fixture_multi_op_disjoint();

    let previous_root = invert_commit(&fixture.raw_commit).unwrap();

    assert_eq!(previous_root, fixture.prev_data);
}

#[test]
fn invert_rejects_update_without_prev() {
    let mut fixture = commit_fixture_update();
    fixture.raw_commit.ops[0].prev = None;

    let err = invert_commit(&fixture.raw_commit).unwrap_err();

    assert!(
        err.to_string().contains("missing prev"),
        "unexpected error: {err}"
    );
}

#[test]
fn invert_rejects_missing_commit_block() {
    let fixture = commit_fixture_missing_commit_block();

    let err = invert_commit(&fixture.raw_commit).unwrap_err();

    assert!(
        err.to_string().contains("commit block"),
        "unexpected error: {err}"
    );
}

#[test]
fn decode_commit_car_rejects_root_mismatch() {
    let fixture = commit_fixture_root_mismatch();

    let err = decode_commit_car(&fixture.raw_commit).unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch {
            field: "commit",
            ..
        }
    ));
}

#[test]
fn decode_commit_car_rejects_block_cid_mismatch() {
    let fixture = commit_fixture_cid_data_mismatch();

    let err = decode_commit_car(&fixture.raw_commit).unwrap_err();

    assert!(matches!(err, VerifierError::Car { .. }));
}

#[test]
fn invert_rejects_duplicate_paths_before_mutating_tree() {
    let fixture = commit_fixture_duplicate_paths();

    let err = invert_commit(&fixture.raw_commit).unwrap_err();

    assert!(matches!(
        err,
        VerifierError::DuplicatePath { path, .. } if path == fixture.raw_commit.ops[0].path
    ));
}

#[test]
fn check_op_cids_accepts_matching_create_update_and_delete() {
    for fixture in [
        commit_fixture_create(),
        commit_fixture_update(),
        commit_fixture_delete(),
    ] {
        let decoded = decode_commit_car(&fixture.raw_commit).unwrap();
        check_op_cids(&fixture.raw_commit, fixture.post_data, &decoded.store).unwrap();
    }
}

#[test]
fn check_op_cids_rejects_missing_create_cid_even_when_path_absent() {
    let mut fixture = commit_fixture_delete();
    fixture.raw_commit.ops[0].action = "create".to_owned();
    fixture.raw_commit.ops[0].cid = None;

    let decoded = decode_commit_car(&fixture.raw_commit).unwrap();
    let err = check_op_cids(&fixture.raw_commit, fixture.post_data, &decoded.store).unwrap_err();

    assert!(matches!(
        err,
        VerifierError::OpCidMismatch {
            expected: None,
            actual: None,
            ..
        }
    ));
}

#[test]
fn check_op_cids_rejects_missing_update_cid_even_when_path_absent() {
    let mut fixture = commit_fixture_delete();
    fixture.raw_commit.ops[0].action = "update".to_owned();
    fixture.raw_commit.ops[0].cid = None;

    let decoded = decode_commit_car(&fixture.raw_commit).unwrap();
    let err = check_op_cids(&fixture.raw_commit, fixture.post_data, &decoded.store).unwrap_err();

    assert!(matches!(
        err,
        VerifierError::OpCidMismatch {
            expected: None,
            actual: None,
            ..
        }
    ));
}

#[test]
fn check_op_cids_rejects_delete_with_cid() {
    let mut fixture = commit_fixture_delete();
    fixture.raw_commit.ops[0].cid = fixture.prev_record;

    let decoded = decode_commit_car(&fixture.raw_commit).unwrap();
    let err = check_op_cids(&fixture.raw_commit, fixture.post_data, &decoded.store).unwrap_err();

    assert!(matches!(
        err,
        VerifierError::OpCidMismatch {
            expected: None,
            actual: Some(_),
            ..
        }
    ));
}

#[test]
fn check_op_cids_rejects_unknown_action() {
    let mut fixture = commit_fixture_create();
    fixture.raw_commit.ops[0].action = "wat".to_owned();

    let decoded = decode_commit_car(&fixture.raw_commit).unwrap();
    let err = check_op_cids(&fixture.raw_commit, fixture.post_data, &decoded.store).unwrap_err();

    assert!(matches!(err, VerifierError::Inversion { .. }));
}

#[tokio::test]
async fn mem_state_store_round_trips_chain_and_hosting() {
    let store = MemStateStore::new();
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let chain = ChainState {
        rev: "3zzzzzzzzzzzz".to_owned(),
        data: Cid::compute(Codec::Drisl, b"chain-state"),
    };
    let hosting = HostingState {
        active: false,
        status: Some("takendown".to_owned()),
        seq: 88,
        time: "2026-06-09T15:00:00.000Z".to_owned(),
    };

    assert_eq!(store.load_chain(&did).await.unwrap(), None);
    assert_eq!(store.load_hosting(&did).await.unwrap(), None);

    store.save_chain(&did, chain.clone()).await.unwrap();
    store.save_hosting(&did, hosting.clone()).await.unwrap();

    assert_eq!(store.load_chain(&did).await.unwrap(), Some(chain));
    assert_eq!(store.load_hosting(&did).await.unwrap(), Some(hosting));

    store.delete(&did).await.unwrap();

    assert_eq!(store.load_chain(&did).await.unwrap(), None);
    assert_eq!(store.load_hosting(&did).await.unwrap(), None);
}

#[tokio::test]
async fn mem_state_store_is_safe_under_concurrent_access() {
    let store: Arc<dyn StateStore> = Arc::new(MemStateStore::new());
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let mut handles = Vec::new();

    for i in 0..32 {
        let store = Arc::clone(&store);
        let did = did.clone();
        handles.push(tokio::spawn(async move {
            let chain = ChainState {
                rev: format!("3zzzzzzzzzz{i:02}"),
                data: Cid::compute(Codec::Drisl, format!("chain-state-{i}").as_bytes()),
            };
            store.save_chain(&did, chain).await.unwrap();
        }));
    }

    for handle in handles {
        handle.await.unwrap();
    }

    assert!(store.load_chain(&did).await.unwrap().is_some());
}

#[test]
fn chain_and_hosting_state_round_trip_through_json() {
    let chain = ChainState {
        rev: "3zzzzzzzzzzzz".to_owned(),
        data: Cid::compute(Codec::Drisl, b"chain-state"),
    };
    let chain_json = serde_json::to_string(&chain).unwrap();
    assert_eq!(
        serde_json::from_str::<ChainState>(&chain_json).unwrap(),
        chain
    );

    let hosting = HostingState {
        active: false,
        status: Some("takendown".to_owned()),
        seq: 88,
        time: "2026-06-09T15:00:00.000Z".to_owned(),
    };
    let hosting_json = serde_json::to_string(&hosting).unwrap();
    assert_eq!(
        serde_json::from_str::<HostingState>(&hosting_json).unwrap(),
        hosting
    );

    let active_hosting = HostingState {
        active: true,
        status: None,
        seq: 89,
        time: "2026-06-09T15:00:01.000Z".to_owned(),
    };
    let active_hosting_json = serde_json::to_string(&active_hosting).unwrap();
    assert_eq!(
        serde_json::from_str::<HostingState>(&active_hosting_json).unwrap(),
        active_hosting
    );
}

#[test]
fn hosting_state_defaults_missing_state_to_active() {
    assert!(HostingState::is_active(None));
    assert!(HostingState::is_active(Some(&HostingState {
        active: true,
        status: None,
        seq: 1,
        time: "2026-06-09T15:00:00.000Z".to_owned(),
    })));
    assert!(!HostingState::is_active(Some(&HostingState {
        active: false,
        status: Some("takendown".to_owned()),
        seq: 2,
        time: "2026-06-09T15:00:01.000Z".to_owned(),
    })));
}

#[test]
fn verifier_stats_default_is_zero() {
    assert_eq!(
        VerifierStats::default(),
        VerifierStats {
            events_verified: 0,
            chain_breaks: 0,
            inversion_failures: 0,
            inversion_incomplete: 0,
            signature_failures: 0,
            rev_replays_dropped: 0,
            chain_state_save_failures: 0,
            future_revs_rejected: 0,
            field_mismatches: 0,
            op_cid_mismatches: 0,
            legacy_commits: 0,
            missing_record_blocks_ops: 0,
            duplicate_paths: 0,
            oversized_commits: 0,
            accounts_inactive: 0,
            account_event_replays_dropped: 0,
            sync_no_ops: 0,
            resyncs: 0,
            resync_failures: 0,
            resync_rate_limited: 0,
        }
    );
}

#[test]
fn verifier_error_converts_to_sync_error() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let err: SyncError = VerifierError::FutureRev {
        did: did.clone(),
        rev: "3zzzzzzzzzzzz".to_owned(),
    }
    .into();

    assert!(matches!(err, SyncError::Verifier(_)));
    let SyncError::Verifier(source) = err else {
        return;
    };
    assert!(matches!(*source, VerifierError::FutureRev { did: got, .. } if got == did));
}

#[test]
fn state_store_error_preserves_operation_context_and_source() {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let err = StateStoreError::operation(
        &did,
        StateStoreOperation::SaveChain,
        std::io::Error::new(std::io::ErrorKind::TimedOut, "database timeout"),
    );

    assert!(err.to_string().contains("save_chain"));
    assert!(err.to_string().contains(did.as_str()));
    assert!(err.source().is_some());
}

#[tokio::test]
async fn verify_commit_accepts_first_sighting_and_saves_chain() {
    let fixture = commit_fixture_create();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].action, "create");
    assert_eq!(ops[0].path, fixture.raw_commit.ops[0].path);
    assert_eq!(ops[0].cid, fixture.raw_commit.ops[0].cid);
    assert!(
        !ops[0].record.is_empty(),
        "verified create op should carry the record bytes from the CAR"
    );
    assert_eq!(
        Cid::compute(Codec::Drisl, &ops[0].record),
        ops[0].cid.unwrap(),
        "record bytes should hash to the op CID"
    );
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
    assert_eq!(verifier.stats().events_verified, 1);
    assert_eq!(verifier.stats().missing_record_blocks_ops, 0);
}

#[tokio::test]
async fn verify_commit_counts_missing_record_block_and_yields_empty_bytes() {
    // A create op whose record block is absent from the CAR still flows
    // through (empty bytes) but is counted so operators can spot incomplete
    // upstreams. Strip only the record block, leaving the MST nodes so the
    // op-CID check (which reads the tree, not the record) still passes.
    let mut fixture = commit_fixture_create();
    let record_cid = fixture.raw_commit.ops[0].cid.unwrap();
    let (roots, blocks) = car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let blocks: Vec<car::Block> = blocks
        .into_iter()
        .filter(|block| block.cid != record_cid)
        .collect();
    fixture.raw_commit.blocks = car::write_all(&roots, &blocks).unwrap();

    let (verifier, _store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert!(ops[0].record.is_empty());
    assert_eq!(verifier.stats().missing_record_blocks_ops, 1);
    assert_eq!(verifier.stats().events_verified, 1);
}

#[tokio::test]
async fn verify_commit_silently_drops_rev_replay() {
    let fixture = commit_fixture_create();
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: fixture.raw_commit.rev.to_string(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let result = verifier.verify_commit(&fixture.raw_commit).await.unwrap();

    assert!(result.is_none());
    assert_eq!(verifier.stats().rev_replays_dropped, 1);
    assert_eq!(resolver.lookups(), 0);
    assert_eq!(
        store
            .load_chain(&fixture.raw_commit.repo)
            .await
            .unwrap()
            .unwrap()
            .data,
        fixture.prev_data
    );
}

#[tokio::test]
async fn verify_commit_rejects_future_rev_without_advancing_state() {
    let fixture = commit_fixture_create();
    let (verifier, store, _resolver) = verifier_for_keys_with_now(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
        || UNIX_EPOCH,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::FutureRev { .. }));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().future_revs_rejected, 1);
}

#[tokio::test]
async fn verify_commit_rejects_oversized_blocks_before_car_decode() {
    let mut fixture = commit_fixture_create();
    fixture.raw_commit.blocks = vec![0; MAX_COMMIT_BLOCKS_BYTES + 1];
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::OversizedCommit {
            field: "blocks",
            limit: MAX_COMMIT_BLOCKS_BYTES,
            ..
        }
    ));
    assert_eq!(resolver.lookups(), 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn verify_commit_rejects_too_many_ops_before_car_decode() {
    let mut fixture = commit_fixture_create();
    let op = fixture.raw_commit.ops[0].clone();
    fixture.raw_commit.ops = vec![op; MAX_COMMIT_OPS + 1];
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::OversizedCommit {
            field: "ops",
            limit: MAX_COMMIT_OPS,
            ..
        }
    ));
    assert_eq!(resolver.lookups(), 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn verify_commit_ignores_deprecated_too_big_flag() {
    // Sync 1.1 deprecates `tooBig`: consumers must ignore it. A commit that
    // sets the flag but is otherwise well-formed verifies normally.
    let mut fixture = commit_fixture_create();
    fixture.raw_commit.too_big = true;
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(verifier.stats().missing_record_blocks_ops, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_commit_rejects_inactive_repo_when_gated() {
    let fixture = commit_fixture_create();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Gate,
    );
    store
        .save_hosting(
            &fixture.raw_commit.repo,
            HostingState {
                active: false,
                status: Some("takendown".to_owned()),
                seq: 9,
                time: "2026-06-09T15:00:00.000Z".to_owned(),
            },
        )
        .await
        .unwrap();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::RepoInactive {
            status: Some(status),
            seq: Some(9),
            ..
        } if status == "takendown"
    ));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().accounts_inactive, 1);
}

#[tokio::test]
async fn account_event_saves_hosting_state_and_drops_replay() {
    let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let (verifier, store, _resolver) = verifier_for_keys(
        did.clone(),
        vec![
            shrike::crypto::P256SigningKey::generate()
                .public_key()
                .to_bytes(),
        ],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );
    let account = shrike::sync::RawAccount {
        did: did.clone(),
        seq: 10,
        time: "2026-06-09T15:00:00.000Z".to_owned(),
        active: false,
        status: Some("takendown".to_owned()),
    };

    verifier.on_account_event(&account).await.unwrap();
    verifier.on_account_event(&account).await.unwrap();

    let state = store.load_hosting(&did).await.unwrap().unwrap();
    assert!(!state.active);
    assert_eq!(state.status.as_deref(), Some("takendown"));
    assert_eq!(state.seq, 10);
    assert_eq!(verifier.stats().account_event_replays_dropped, 1);
}

#[tokio::test]
async fn hosting_gate_rejects_commit_for_inactive_account_from_event() {
    let fixture = commit_fixture_create();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Gate,
    );
    verifier
        .on_account_event(&shrike::sync::RawAccount {
            did: fixture.raw_commit.repo.clone(),
            seq: 10,
            time: "2026-06-09T15:00:00.000Z".to_owned(),
            active: false,
            status: Some("takendown".to_owned()),
        })
        .await
        .unwrap();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::RepoInactive { .. }));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().accounts_inactive, 1);
}

#[tokio::test]
async fn verify_commit_rejects_outer_inner_did_mismatch() {
    let mut fixture = commit_fixture_create();
    fixture.raw_commit.repo = Did::try_from("did:plc:other123456789abcdefghij").unwrap();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch { field: "did", .. }
    ));
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().field_mismatches, 1);
}

#[tokio::test]
async fn verify_commit_rejects_outer_inner_rev_mismatch() {
    let mut fixture = commit_fixture_create();
    mutate_signed_commit(&mut fixture, |commit| {
        commit.rev = shrike::syntax::Tid::new(commit.rev.timestamp_micros() + 1, 0).unwrap();
    });
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch { field: "rev", .. }
    ));
    assert_eq!(verifier.stats().field_mismatches, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn verify_commit_rejects_inner_commit_version_mismatch() {
    let mut fixture = commit_fixture_create();
    mutate_signed_commit(&mut fixture, |commit| {
        commit.version = 2;
    });
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch {
            field: "version",
            ..
        }
    ));
    assert_eq!(verifier.stats().field_mismatches, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn verify_commit_rejects_car_root_mismatch_without_identity_lookup() {
    let fixture = commit_fixture_root_mismatch();
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch {
            field: "commit",
            ..
        }
    ));
    assert_eq!(resolver.lookups(), 0);
    assert_eq!(verifier.stats().field_mismatches, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn verify_commit_rejects_bad_signature_after_identity_refresh() {
    let fixture = commit_fixture_create();
    let wrong_key = shrike::crypto::P256SigningKey::generate()
        .public_key()
        .to_bytes();
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![wrong_key, wrong_key],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::SignatureInvalid { .. }));
    assert_eq!(resolver.lookups(), 2);
    assert_eq!(resolver.purges(), 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    assert_eq!(verifier.stats().signature_failures, 1);
}

#[tokio::test]
async fn verify_commit_refreshes_identity_once_on_signature_rotation() {
    let fixture = commit_fixture_create();
    let wrong_key = shrike::crypto::P256SigningKey::generate()
        .public_key()
        .to_bytes();
    let (verifier, store, resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![wrong_key, fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let result = verifier.verify_commit(&fixture.raw_commit).await.unwrap();

    assert!(result.is_some());
    assert_eq!(resolver.lookups(), 2);
    assert_eq!(resolver.purges(), 1);
    assert_eq!(verifier.stats().signature_failures, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_commit_accepts_first_sighting_update_without_inversion() {
    let fixture = commit_fixture_update();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].action, "update");
    assert_eq!(verifier.stats().inversion_failures, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_commit_reports_chain_break_under_policy_error() {
    let fixture = commit_fixture_update();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );
    let wrong_root = Cid::compute(Codec::Drisl, b"wrong-root");
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: wrong_root,
            },
        )
        .await
        .unwrap();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::ChainBreak { .. }));
    assert_eq!(verifier.stats().chain_breaks, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_sync_noop_advances_rev_when_data_matches() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::new());
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        Arc::clone(&repo_source),
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.post_data,
            },
        )
        .await
        .unwrap();

    let result = verifier
        .verify_sync(&raw_sync_from_fixture(&fixture))
        .await
        .unwrap();

    assert!(result.is_none());
    assert_eq!(repo_source.calls(), 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
    assert_eq!(verifier.stats().sync_no_ops, 1);
}

#[tokio::test]
async fn verify_sync_rejects_matching_data_with_bad_signature() {
    let fixture = commit_fixture_create();
    let wrong_key = shrike::crypto::P256SigningKey::generate()
        .public_key()
        .to_bytes();
    let repo_source = Arc::new(FakeRepoSource::new());
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![wrong_key, wrong_key],
        repo_source,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.post_data,
            },
        )
        .await
        .unwrap();

    let err = verifier
        .verify_sync(&raw_sync_from_fixture(&fixture))
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::SignatureInvalid { .. }));
    assert_eq!(verifier.stats().signature_failures, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: "3aaaaaaaaaaaa".to_owned(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_sync_fetches_repo_when_data_differs() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes, fixture.public_key_bytes],
        Arc::clone(&repo_source),
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let ops = verifier
        .verify_sync(&raw_sync_from_fixture(&fixture))
        .await
        .unwrap()
        .unwrap();

    assert_eq!(repo_source.calls(), 1);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].action, "resync");
    assert_eq!(ops[0].path, fixture.raw_commit.ops[0].path);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
    assert_eq!(verifier.stats().resyncs, 1);
}

#[tokio::test]
async fn verify_sync_fetches_repo_when_embedded_car_is_malformed_and_data_differs() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        Arc::clone(&repo_source),
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();
    let mut raw_sync = raw_sync_from_fixture(&fixture);
    raw_sync.blocks = b"not a car".to_vec();

    let ops = verifier.verify_sync(&raw_sync).await.unwrap().unwrap();

    assert_eq!(repo_source.calls(), 1);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].action, "resync");
}

#[tokio::test]
async fn verify_sync_fetches_repo_when_embedded_car_exceeds_commit_limit_even_if_data_matches() {
    let fixture = commit_fixture_create();
    let (roots, mut blocks) = car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let extra = vec![0u8; MAX_COMMIT_BLOCKS_BYTES + 1];
    blocks.push(car::Block {
        cid: Cid::compute(Codec::Raw, &extra),
        data: extra,
    });
    let mut raw_sync = raw_sync_from_fixture(&fixture);
    raw_sync.blocks = car::write_all(&roots, &blocks).unwrap();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        Arc::clone(&repo_source),
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.post_data,
            },
        )
        .await
        .unwrap();

    let ops = verifier.verify_sync(&raw_sync).await.unwrap().unwrap();

    assert_eq!(repo_source.calls(), 1);
    assert_eq!(ops.len(), 1);
    assert_eq!(ops[0].action, "resync");
}

#[tokio::test]
async fn resync_throttles_after_burst_and_refills_over_time() {
    use std::sync::atomic::AtomicU64;
    let fixture = commit_fixture_create();
    // Burst 2, refill 1 token/sec. The injected clock starts at a fixed epoch
    // and only advances when the test moves it.
    let clock = Arc::new(AtomicU64::new(1_000_000));
    let clock_for_now = Arc::clone(&clock);
    let now =
        move || UNIX_EPOCH + std::time::Duration::from_millis(clock_for_now.load(Ordering::SeqCst));
    let repo_source = Arc::new(FakeRepoSource::with_repeated_car(
        fixture.raw_commit.blocks.clone(),
        8,
    ));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_rate_limit_and_clock(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes; 8],
        repo_source,
        shrike::sync::ResyncRateLimit {
            per_second: 1.0,
            burst: 2.0,
        },
        now,
    );

    // Two resyncs allowed by the initial burst.
    verifier.resync(&fixture.raw_commit.repo).await.unwrap();
    verifier.resync(&fixture.raw_commit.repo).await.unwrap();

    // Third is throttled — bucket is empty and no time has passed.
    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();
    assert!(matches!(err, VerifierError::ResyncRateLimited { .. }));
    assert_eq!(verifier.stats().resync_rate_limited, 1);
    assert_eq!(verifier.stats().resyncs, 2);
    assert_eq!(verifier.stats().resync_failures, 0);

    // Advance the clock one second: exactly one token refills.
    clock.fetch_add(1_000, Ordering::SeqCst);
    verifier.resync(&fixture.raw_commit.repo).await.unwrap();
    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();
    assert!(matches!(err, VerifierError::ResyncRateLimited { .. }));
    assert_eq!(verifier.stats().resyncs, 3);
    assert_eq!(verifier.stats().resync_rate_limited, 2);
}

#[tokio::test]
async fn resync_unlimited_rate_never_throttles() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_repeated_car(
        fixture.raw_commit.blocks.clone(),
        10,
    ));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_rate_limit_and_clock(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes; 10],
        repo_source,
        shrike::sync::ResyncRateLimit::unlimited(),
        SystemTime::now,
    );

    for _ in 0..10 {
        verifier.resync(&fixture.raw_commit.repo).await.unwrap();
    }
    assert_eq!(verifier.stats().resyncs, 10);
    assert_eq!(verifier.stats().resync_rate_limited, 0);
}

#[tokio::test]
async fn resync_rejects_rev_regression() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
    );
    let higher_rev = Tid::new(fixture.raw_commit.rev.timestamp_micros() + 1, 0).unwrap();
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: higher_rev.to_string(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::RevRegression { .. })
    ));
    assert_eq!(verifier.stats().resync_failures, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: higher_rev.to_string(),
            data: fixture.prev_data,
        })
    );
}

#[tokio::test]
async fn resync_allows_equal_rev_when_data_matches() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: fixture.raw_commit.rev.to_string(),
                data: fixture.post_data,
            },
        )
        .await
        .unwrap();

    let ops = verifier.resync(&fixture.raw_commit.repo).await.unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(verifier.stats().resyncs, 1);
}

#[tokio::test]
async fn resync_wraps_bad_signature_as_resync_failed() {
    let fixture = commit_fixture_create();
    let wrong_key = shrike::crypto::P256SigningKey::generate()
        .public_key()
        .to_bytes();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, _store, _resolver) = verifier_for_keys_and_repo_source(
        fixture.raw_commit.repo.clone(),
        vec![wrong_key, wrong_key],
        repo_source,
    );

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::SignatureInvalid { .. })
    ));
    assert_eq!(verifier.stats().signature_failures, 1);
    assert_eq!(verifier.stats().resync_failures, 1);
}

#[tokio::test]
async fn resync_rejects_oversized_get_repo_car_before_decode() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_and_limits(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        RepoLoadLimits {
            max_car_bytes: fixture.raw_commit.blocks.len() - 1,
            ..RepoLoadLimits::default()
        },
    );

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::OversizedCommit { field: "repo_car_bytes", .. })
    ));
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn resync_rejects_too_many_repo_blocks() {
    let fixture = commit_fixture_create();
    let (roots, mut blocks) = car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let extra = b"extra repo block";
    blocks.push(car::Block {
        cid: Cid::compute(Codec::Drisl, extra),
        data: extra.to_vec(),
    });
    let repo_source = Arc::new(FakeRepoSource::with_car(
        car::write_all(&roots, &blocks).unwrap(),
    ));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_and_limits(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        RepoLoadLimits {
            max_blocks: blocks.len() - 1,
            ..RepoLoadLimits::default()
        },
    );

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::OversizedCommit { field: "repo_blocks", .. })
    ));
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn resync_rejects_excess_aggregate_repo_block_bytes() {
    let fixture = commit_fixture_create();
    let (roots, blocks) = car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let total_block_bytes = blocks.iter().map(|block| block.data.len()).sum::<usize>();
    let repo_source = Arc::new(FakeRepoSource::with_car(
        car::write_all(&roots, &blocks).unwrap(),
    ));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_and_limits(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        RepoLoadLimits {
            max_block_bytes: total_block_bytes - 1,
            ..RepoLoadLimits::default()
        },
    );

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::OversizedCommit { field: "repo_block_bytes", .. })
    ));
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn resync_rejects_too_many_repo_records() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, _store, _resolver) = verifier_for_keys_repo_source_and_limits(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        RepoLoadLimits {
            max_records: 0,
            ..RepoLoadLimits::default()
        },
    );

    let err = verifier.resync(&fixture.raw_commit.repo).await.unwrap_err();

    assert!(matches!(
        err,
        VerifierError::ResyncFailed {
            source,
            ..
        } if matches!(*source, VerifierError::OversizedCommit { field: "repo_records", .. })
    ));
    assert_eq!(verifier.stats().oversized_commits, 1);
}

#[tokio::test]
async fn policy_resync_queues_chain_break_and_emits_resync_event() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        1,
        8,
    );
    let mut events = verifier.resync_events();
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.record.unwrap(),
            },
        )
        .await
        .unwrap();

    let result = verifier.verify_commit(&fixture.raw_commit).await.unwrap();
    let event = tokio::time::timeout(TEST_TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(result.is_none());
    assert_eq!(event.did, fixture.raw_commit.repo);
    assert_eq!(event.old_rev.as_deref(), Some("3aaaaaaaaaaaa"));
    assert_eq!(event.new_rev, fixture.raw_commit.rev.to_string());
    assert_eq!(event.ops.len(), 1);
    assert_eq!(event.ops[0].action, "resync");
    assert_eq!(verifier.stats().resyncs, 1);
}

#[tokio::test]
async fn policy_resync_routes_malformed_car_through_resync() {
    // M14: a truncated/corrupt commit CAR is a recoverable decode failure —
    // re-fetching the repo resolves it — so under the Resync policy it must be
    // queued for async resync rather than returned as a hard error.
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        1,
        8,
    );
    let mut events = verifier.resync_events();
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.record.unwrap(),
            },
        )
        .await
        .unwrap();

    let mut raw = fixture.raw_commit.clone();
    raw.blocks = b"not a valid car file".to_vec();

    let result = verifier.verify_commit(&raw).await.unwrap();
    let event = tokio::time::timeout(TEST_TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(result.is_none());
    assert_eq!(event.did, fixture.raw_commit.repo);
    assert_eq!(event.ops.len(), 1);
    assert_eq!(event.ops[0].action, "resync");
    assert_eq!(verifier.stats().resyncs, 1);
}

#[tokio::test]
async fn policy_resync_routes_missing_commit_block_through_resync() {
    // M14: a CAR whose announced commit block is absent is recoverable — route
    // it through resync under the Resync policy. The repo source must serve a
    // CAR signed by the *same* key the resolver knows, so derive the stripped
    // input from the same fixture whose full CAR feeds the repo source.
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));

    // Build a copy of the frame with the commit block stripped from its CAR.
    let (roots, blocks) = car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let without_commit: Vec<car::Block> = blocks
        .into_iter()
        .filter(|b| b.cid != fixture.raw_commit.commit)
        .collect();
    let mut raw = fixture.raw_commit.clone();
    raw.blocks = car::write_all(&roots, &without_commit).unwrap();

    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        1,
        8,
    );
    let mut events = verifier.resync_events();
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.record.unwrap(),
            },
        )
        .await
        .unwrap();

    let result = verifier.verify_commit(&raw).await.unwrap();
    let event = tokio::time::timeout(TEST_TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();

    assert!(result.is_none());
    assert_eq!(event.ops[0].action, "resync");
    assert_eq!(verifier.stats().resyncs, 1);
}

#[tokio::test]
async fn policy_resync_still_hard_errors_on_car_root_mismatch() {
    // M14: a CAR-root/announced-commit mismatch is an internally inconsistent
    // frame, NOT repo divergence — re-fetching the same repo would not resolve
    // it, so it must stay a hard error even under the Resync policy and must not
    // enqueue a resync.
    let fixture = commit_fixture_root_mismatch();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        1,
        8,
    );
    let mut events = verifier.resync_events();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(
        err,
        VerifierError::FieldMismatch {
            field: "commit",
            ..
        }
    ));
    assert_eq!(verifier.stats().resyncs, 0);
    assert_eq!(verifier.stats().field_mismatches, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
    // No resync should have been queued.
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(100), events.recv())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn commits_for_resyncing_did_are_buffered_and_replayed() {
    let create = commit_fixture_create();
    let mut update = commit_fixture_update();
    let update_rev = Tid::new(create.raw_commit.rev.timestamp_micros() + 1, 0).unwrap();
    mutate_signed_commit(&mut update, |commit| commit.rev = update_rev);
    update.raw_commit.rev = update_rev;
    update.raw_commit.seq = create.raw_commit.seq + 1;
    let repo_source = Arc::new(BlockingRepoSource::new(create.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        create.raw_commit.repo.clone(),
        vec![create.public_key_bytes, update.public_key_bytes],
        Arc::clone(&repo_source),
        1,
        8,
    );
    let mut events = verifier.resync_events();
    store
        .save_chain(
            &create.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: create.record.unwrap(),
            },
        )
        .await
        .unwrap();

    assert!(
        verifier
            .verify_commit(&create.raw_commit)
            .await
            .unwrap()
            .is_none()
    );
    repo_source.wait_until_called().await;
    assert!(
        verifier
            .verify_commit(&update.raw_commit)
            .await
            .unwrap()
            .is_none()
    );
    repo_source.release();
    let event = tokio::time::timeout(TEST_TIMEOUT, events.recv())
        .await
        .unwrap()
        .unwrap();

    assert_eq!(event.ops.len(), 2);
    assert_eq!(event.ops[0].action, "resync");
    assert_eq!(event.ops[1].action, "update");
    assert_eq!(event.ops[1].rev, update_rev);
}

#[tokio::test]
async fn pending_queue_overflow_surfaces_buffer_overflow() {
    let create = commit_fixture_create();
    let mut update = commit_fixture_update();
    let update_rev = Tid::new(create.raw_commit.rev.timestamp_micros() + 1, 0).unwrap();
    mutate_signed_commit(&mut update, |commit| commit.rev = update_rev);
    update.raw_commit.rev = update_rev;
    let repo_source = Arc::new(BlockingRepoSource::new(create.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        create.raw_commit.repo.clone(),
        vec![create.public_key_bytes, update.public_key_bytes],
        Arc::clone(&repo_source),
        1,
        1,
    );
    let mut errors = verifier.async_errors();
    store
        .save_chain(
            &create.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: create.record.unwrap(),
            },
        )
        .await
        .unwrap();

    assert!(
        verifier
            .verify_commit(&create.raw_commit)
            .await
            .unwrap()
            .is_none()
    );
    repo_source.wait_until_called().await;
    assert!(
        verifier
            .verify_commit(&update.raw_commit)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        verifier
            .verify_commit(&update.raw_commit)
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        verifier
            .verify_commit(&update.raw_commit)
            .await
            .unwrap()
            .is_none()
    );

    let err = tokio::time::timeout(TEST_TIMEOUT, errors.recv())
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(err, VerifierError::BufferOverflow { .. }));
    repo_source.release();
    verifier.close().await;
}

#[tokio::test]
async fn close_stops_workers_and_closes_channels() {
    let fixture = commit_fixture_create();
    let repo_source = Arc::new(FakeRepoSource::with_car(fixture.raw_commit.blocks.clone()));
    let (verifier, store, _resolver) = verifier_for_keys_repo_source_and_workers(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        repo_source,
        2,
        8,
    );
    let mut events = verifier.resync_events();
    let mut errors = verifier.async_errors();

    verifier.close().await;

    assert!(events.recv().await.is_none());
    assert!(errors.recv().await.is_none());
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.record.unwrap(),
            },
        )
        .await
        .unwrap();
    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();
    assert!(matches!(err, VerifierError::ResyncRequired { .. }));
}

#[tokio::test]
async fn verify_commit_reports_op_cid_mismatch_without_advancing_state() {
    let mut fixture = commit_fixture_create();
    fixture.raw_commit.ops[0].cid = Some(Cid::compute(Codec::Drisl, b"wrong-record"));
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::OpCidMismatch { .. }));
    assert_eq!(verifier.stats().op_cid_mismatches, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn verify_commit_accepts_inversion_incomplete_by_default() {
    // Lenient inversion is the default (matches the production relay and
    // atmos): a block-incomplete CAR whose prevData still matches our state is
    // accepted and surfaces an InversionIncomplete signal rather than breaking
    // the chain.
    let mut fixture = commit_fixture_multi_op_disjoint();
    fixture.raw_commit.ops.pop();
    let (verifier, store, _resolver) = verifier_for_keys(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        VerifierPolicy::Error,
        HostingPolicy::Track,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(verifier.stats().inversion_incomplete, 1);
    assert_eq!(verifier.stats().chain_breaks, 0);
}

#[tokio::test]
async fn verify_commit_can_opt_into_strict_inversion() {
    let mut fixture = commit_fixture_multi_op_disjoint();
    fixture.raw_commit.ops.pop();
    let (verifier, store, _resolver) = verifier_for_keys_with_lenient_inversion(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        false,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::ChainBreak { .. }));
    assert_eq!(verifier.stats().chain_breaks, 1);
    assert_eq!(verifier.stats().inversion_incomplete, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_commit_returns_identity_error_without_signature_counter_when_resolver_fails() {
    let fixture = commit_fixture_create();
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FailingIdentityResolver);
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        resolver as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error);
    let verifier = Verifier::new(options);

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::Identity { .. }));
    assert_eq!(verifier.stats().signature_failures, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        None
    );
}

#[tokio::test]
async fn verify_commit_preserves_chain_break_when_policy_error_save_fails() {
    let fixture = commit_fixture_update();
    let store = Arc::new(SaveFailingStateStore::new(ChainState {
        rev: "3aaaaaaaaaaaa".to_owned(),
        data: Cid::compute(Codec::Drisl, b"wrong-root"),
    }));
    let resolver = Arc::new(FakeIdentityResolver::new(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
    ));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        resolver as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error);
    let verifier = Verifier::new(options);

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::ChainBreak { .. }));
    assert_eq!(verifier.stats().chain_breaks, 1);
    assert_eq!(verifier.stats().chain_state_save_failures, 1);
}

#[tokio::test]
async fn verify_commit_accepts_legacy_non_first_sighting_under_accept_policy() {
    let mut fixture = commit_fixture_update();
    fixture.raw_commit.prev_data = None;
    fixture.raw_commit.ops[0].prev = None;
    let (verifier, store, _resolver) = verifier_for_keys_with_legacy(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        LegacyCommitPolicy::Accept,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let ops = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(ops.len(), 1);
    assert_eq!(verifier.stats().legacy_commits, 1);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[tokio::test]
async fn verify_commit_rejects_legacy_when_policy_rejects() {
    let mut fixture = commit_fixture_update();
    fixture.raw_commit.prev_data = None;
    fixture.raw_commit.ops[0].prev = None;
    let (verifier, store, _resolver) = verifier_for_keys_with_legacy(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        LegacyCommitPolicy::Reject,
    );
    store
        .save_chain(
            &fixture.raw_commit.repo,
            ChainState {
                rev: "3aaaaaaaaaaaa".to_owned(),
                data: fixture.prev_data,
            },
        )
        .await
        .unwrap();

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap_err();

    assert!(matches!(err, VerifierError::LegacyCommit { .. }));
    assert_eq!(verifier.stats().legacy_commits, 1);
}

#[tokio::test]
async fn verify_commit_accepts_legacy_shape_on_first_sighting_without_inversion() {
    let mut fixture = commit_fixture_update();
    fixture.raw_commit.prev_data = None;
    fixture.raw_commit.ops[0].prev = None;
    let (verifier, store, _resolver) = verifier_for_keys_with_legacy(
        fixture.raw_commit.repo.clone(),
        vec![fixture.public_key_bytes],
        LegacyCommitPolicy::Accept,
    );

    let err = verifier
        .verify_commit(&fixture.raw_commit)
        .await
        .unwrap()
        .unwrap();

    assert_eq!(err.len(), 1);
    assert_eq!(verifier.stats().legacy_commits, 0);
    assert_eq!(
        store.load_chain(&fixture.raw_commit.repo).await.unwrap(),
        Some(ChainState {
            rev: fixture.raw_commit.rev.to_string(),
            data: fixture.post_data,
        })
    );
}

#[test]
fn verifier_lock_stripes_are_bounded() {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FailingIdentityResolver);
    let verifier = Verifier::new(VerifierOptions::new(
        store as Arc<dyn StateStore>,
        resolver as Arc<dyn IdentityResolver>,
    ));

    assert_eq!(verifier.lock_stripes(), 256);
}

struct FakeIdentityResolver {
    did: Did,
    keys: tokio::sync::Mutex<VecDeque<[u8; 33]>>,
    lookups: AtomicUsize,
    purges: AtomicUsize,
}

impl FakeIdentityResolver {
    fn new(did: Did, keys: Vec<[u8; 33]>) -> Self {
        Self {
            did,
            keys: tokio::sync::Mutex::new(keys.into()),
            lookups: AtomicUsize::new(0),
            purges: AtomicUsize::new(0),
        }
    }

    fn lookups(&self) -> usize {
        self.lookups.load(Ordering::SeqCst)
    }

    fn purges(&self) -> usize {
        self.purges.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl IdentityResolver for FakeIdentityResolver {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        if did != &self.did {
            return Err(IdentityError::NotFound(did.to_string()));
        }
        self.lookups.fetch_add(1, Ordering::SeqCst);
        let mut keys = self.keys.lock().await;
        let key_bytes = match keys.pop_front() {
            Some(key) => key,
            None => return Err(IdentityError::NotFound("no fake key queued".to_owned())),
        };
        let mut signing_keys: HashMap<String, Box<dyn VerifyingKey>> = HashMap::new();
        signing_keys.insert(
            "#atproto".to_owned(),
            Box::new(P256VerifyingKey::from_bytes(&key_bytes).unwrap()),
        );
        Ok(Arc::new(Identity {
            did: did.clone(),
            handle: None,
            keys: signing_keys,
            services: HashMap::new(),
        }))
    }

    async fn purge(&self, did: &Did) -> Result<(), IdentityError> {
        if did != &self.did {
            return Err(IdentityError::NotFound(did.to_string()));
        }
        self.purges.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

struct FailingIdentityResolver;

#[async_trait]
impl IdentityResolver for FailingIdentityResolver {
    async fn lookup_did(&self, did: &Did) -> Result<Arc<Identity>, IdentityError> {
        Err(IdentityError::NotFound(did.to_string()))
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
    fn new() -> Self {
        Self {
            cars: tokio::sync::Mutex::new(VecDeque::new()),
            calls: AtomicUsize::new(0),
        }
    }

    fn with_car(car: Vec<u8>) -> Self {
        Self {
            cars: tokio::sync::Mutex::new(VecDeque::from([car])),
            calls: AtomicUsize::new(0),
        }
    }

    fn with_repeated_car(car: Vec<u8>, count: usize) -> Self {
        Self {
            cars: tokio::sync::Mutex::new(std::iter::repeat_n(car, count).collect()),
            calls: AtomicUsize::new(0),
        }
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
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

struct BlockingRepoSource {
    car: Vec<u8>,
    release_rx: std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    release_tx: std::sync::Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
    called: tokio::sync::Notify,
    calls: AtomicUsize,
}

impl BlockingRepoSource {
    fn new(car: Vec<u8>) -> Self {
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        Self {
            car,
            release_rx: std::sync::Mutex::new(Some(release_rx)),
            release_tx: std::sync::Mutex::new(Some(release_tx)),
            called: tokio::sync::Notify::new(),
            calls: AtomicUsize::new(0),
        }
    }

    async fn wait_until_called(&self) {
        if self.calls.load(Ordering::SeqCst) > 0 {
            return;
        }
        self.called.notified().await;
    }

    fn release(&self) {
        if let Some(tx) = self.release_tx.lock().unwrap().take() {
            let _ = tx.send(());
        }
    }
}

#[async_trait]
impl SyncRepoSource for BlockingRepoSource {
    async fn get_repo_car(&self, _did: &Did) -> Result<Vec<u8>, SyncError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.called.notify_waiters();
        let release_rx = self.release_rx.lock().unwrap().take();
        if let Some(release_rx) = release_rx {
            let _ = release_rx.await;
        }
        Ok(self.car.clone())
    }
}

struct SaveFailingStateStore {
    chain: ChainState,
}

impl SaveFailingStateStore {
    fn new(chain: ChainState) -> Self {
        Self { chain }
    }
}

#[async_trait]
impl StateStore for SaveFailingStateStore {
    async fn load_chain(&self, _did: &Did) -> Result<Option<ChainState>, StateStoreError> {
        Ok(Some(self.chain.clone()))
    }

    async fn save_chain(&self, did: &Did, _state: ChainState) -> Result<(), StateStoreError> {
        Err(StateStoreError::operation(
            did,
            StateStoreOperation::SaveChain,
            std::io::Error::new(std::io::ErrorKind::TimedOut, "save failed"),
        ))
    }

    async fn load_hosting(&self, _did: &Did) -> Result<Option<HostingState>, StateStoreError> {
        Ok(None)
    }

    async fn save_hosting(&self, _did: &Did, _state: HostingState) -> Result<(), StateStoreError> {
        Ok(())
    }

    async fn delete(&self, _did: &Did) -> Result<(), StateStoreError> {
        Ok(())
    }
}

fn verifier_for_keys(
    did: Did,
    keys: Vec<[u8; 33]>,
    verifier_policy: VerifierPolicy,
    hosting_policy: HostingPolicy,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    verifier_for_keys_with_now(did, keys, verifier_policy, hosting_policy, SystemTime::now)
}

fn verifier_for_keys_and_repo_source(
    did: Did,
    keys: Vec<[u8; 33]>,
    repo_source: Arc<FakeRepoSource>,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error)
    .with_repo_source(repo_source as Arc<dyn SyncRepoSource>);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_repo_source_and_limits(
    did: Did,
    keys: Vec<[u8; 33]>,
    repo_source: Arc<FakeRepoSource>,
    limits: RepoLoadLimits,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error)
    .with_repo_source(repo_source as Arc<dyn SyncRepoSource>)
    .with_repo_load_limits(limits);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_repo_source_rate_limit_and_clock(
    did: Did,
    keys: Vec<[u8; 33]>,
    repo_source: Arc<FakeRepoSource>,
    rate_limit: shrike::sync::ResyncRateLimit,
    now: impl Fn() -> SystemTime + Send + Sync + 'static,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error)
    .with_repo_source(repo_source as Arc<dyn SyncRepoSource>)
    .with_resync_rate_limit(rate_limit)
    .with_now(now);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_repo_source_and_workers<T>(
    did: Did,
    keys: Vec<[u8; 33]>,
    repo_source: Arc<T>,
    workers: usize,
    pending_capacity: usize,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>)
where
    T: SyncRepoSource + 'static,
{
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let repo_source: Arc<dyn SyncRepoSource> = repo_source;
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Resync)
    .with_repo_source(repo_source)
    .with_async_resync_workers(workers)
    .with_pending_queue_capacity(pending_capacity);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_with_now(
    did: Did,
    keys: Vec<[u8; 33]>,
    verifier_policy: VerifierPolicy,
    hosting_policy: HostingPolicy,
    now: impl Fn() -> SystemTime + Send + Sync + 'static,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(verifier_policy)
    .with_hosting_policy(hosting_policy)
    .with_now(now);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_with_legacy(
    did: Did,
    keys: Vec<[u8; 33]>,
    legacy_policy: LegacyCommitPolicy,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error)
    .with_legacy_commit_policy(legacy_policy);
    (Verifier::new(options), store, resolver)
}

fn verifier_for_keys_with_lenient_inversion(
    did: Did,
    keys: Vec<[u8; 33]>,
    lenient: bool,
) -> (Verifier, Arc<MemStateStore>, Arc<FakeIdentityResolver>) {
    let store = Arc::new(MemStateStore::new());
    let resolver = Arc::new(FakeIdentityResolver::new(did, keys));
    let options = VerifierOptions::new(
        Arc::clone(&store) as Arc<dyn StateStore>,
        Arc::clone(&resolver) as Arc<dyn IdentityResolver>,
    )
    .with_verifier_policy(VerifierPolicy::Error)
    .with_lenient_inversion(lenient);
    (Verifier::new(options), store, resolver)
}

fn raw_sync_from_fixture(fixture: &support::sync1::CommitFixture) -> shrike::sync::RawSync {
    shrike::sync::RawSync {
        did: fixture.raw_commit.repo.clone(),
        rev: fixture.raw_commit.rev.to_string(),
        seq: fixture.raw_commit.seq + 1,
        time: fixture.raw_commit.time.clone(),
        blocks: support::sync1::sync_commit_car(fixture),
    }
}
