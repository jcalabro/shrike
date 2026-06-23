//! Integration tests for identity resolution through a mock PLC directory.
//!
//! These exercise the full `Directory::lookup_did` path — HTTP fetch, body
//! cap, document-id verification, and key extraction — that the firehose
//! verifier depends on (`signing_key()`). Real did:plc documents use the
//! fully-qualified verificationMethod id form (`did:plc:xxx#atproto`), so the
//! happy-path test pins that form end-to-end (regression for C3 / M17).
#![cfg(feature = "identity")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;

use shrike::crypto::{K256SigningKey, SigningKey};
use shrike::identity::{Directory, IdentityError};
use shrike::syntax::Did;

const DID: &str = "did:plc:z72i7hdynmk6r22z27h6tvur";

#[derive(Clone)]
struct MockPlc {
    doc: Arc<String>,
}

async fn serve_did(State(state): State<MockPlc>, Path(did): Path<String>) -> impl IntoResponse {
    if did == DID {
        (StatusCode::OK, (*state.doc).clone()).into_response()
    } else {
        (StatusCode::NOT_FOUND, "not found").into_response()
    }
}

/// Spawn the mock PLC server, returning its base URL (`http://127.0.0.1:PORT`).
async fn spawn_plc(doc: String) -> String {
    let state = MockPlc { doc: Arc::new(doc) };
    let app = Router::new()
        .route("/{did}", get(serve_did))
        .with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("http://{addr}")
}

fn did_doc_with_fully_qualified_vm(multibase: &str) -> String {
    format!(
        r#"{{
            "id": "{DID}",
            "verificationMethod": [{{
                "id": "{DID}#atproto",
                "type": "Multikey",
                "publicKeyMultibase": "{multibase}"
            }}],
            "service": [{{
                "id": "{DID}#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://pds.example.com"
            }}]
        }}"#
    )
}

#[tokio::test]
async fn lookup_did_resolves_signing_key_from_fully_qualified_vm_id() {
    // The end-to-end path the verifier uses: a real did:plc document with the
    // fully-qualified vm id must yield a usable signing key and PDS endpoint.
    let sk = K256SigningKey::generate();
    let expected_bytes = sk.public_key().to_bytes();
    let multibase = sk.public_key().multibase();

    let base = spawn_plc(did_doc_with_fully_qualified_vm(&multibase)).await;
    let dir = Directory::with_plc_url(&base);

    let identity = dir.lookup_did(&Did::try_from(DID).unwrap()).await.unwrap();

    let key = identity
        .signing_key()
        .expect("signing key must resolve from the fully-qualified vm id");
    assert_eq!(key.to_bytes(), expected_bytes);
    assert_eq!(identity.pds_endpoint(), Some("https://pds.example.com"));
    // No alsoKnownAs → handle stays None (no spurious verification).
    assert!(identity.handle.is_none());
}

#[tokio::test]
async fn lookup_did_caches_second_lookup() {
    // The second lookup must be served from cache (same Arc), not re-fetched.
    let sk = K256SigningKey::generate();
    let multibase = sk.public_key().multibase();
    let base = spawn_plc(did_doc_with_fully_qualified_vm(&multibase)).await;
    let dir = Directory::with_plc_url(&base);
    let did = Did::try_from(DID).unwrap();

    let first = dir.lookup_did(&did).await.unwrap();
    let second = dir.lookup_did(&did).await.unwrap();
    assert!(
        Arc::ptr_eq(&first, &second),
        "second lookup must hit the cache"
    );

    // After purge, a fresh Arc is returned.
    dir.purge(&did).await;
    let third = dir.lookup_did(&did).await.unwrap();
    assert!(
        !Arc::ptr_eq(&first, &third),
        "purge must force a re-resolve"
    );
}

#[tokio::test]
async fn lookup_did_rejects_document_id_mismatch() {
    // A directory that returns a document whose id != the requested DID must be
    // rejected (impersonation guard in fetch_did_document).
    let doc =
        r#"{"id": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "verificationMethod": [], "service": []}"#
            .to_string();
    let base = spawn_plc(doc).await;
    let dir = Directory::with_plc_url(&base);

    match dir.lookup_did(&Did::try_from(DID).unwrap()).await {
        Err(IdentityError::InvalidDocument(_)) => {}
        other => panic!(
            "id mismatch must be InvalidDocument, got {:?}",
            other.map(|_| "ok")
        ),
    }
}

#[tokio::test]
async fn lookup_did_not_found_maps_to_error() {
    // A 404 from the directory maps to NotFound.
    let dir = Directory::with_plc_url(&spawn_plc("{}".to_string()).await);
    match dir
        .lookup_did(&Did::try_from("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa").unwrap())
        .await
    {
        Err(IdentityError::NotFound(_)) => {}
        other => panic!("expected NotFound, got {:?}", other.map(|_| "ok")),
    }
}

#[tokio::test]
async fn lookup_did_rejects_unsupported_method() {
    let dir = Directory::new();
    match dir
        .lookup_did(&Did::try_from("did:example:whatever").unwrap())
        .await
    {
        Err(IdentityError::NotFound(msg)) => assert!(msg.contains("unsupported")),
        other => panic!(
            "unsupported method must be rejected, got {:?}",
            other.map(|_| "ok")
        ),
    }
}
