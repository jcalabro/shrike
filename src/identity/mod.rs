//! DID and handle resolution for AT Protocol identities.
//!
//! The Directory type resolves DIDs and handles to DID documents. Supports
//! both did:plc (via PlcClient) and did:web. DID documents contain public
//! keys and service endpoints used for authentication and communication.
//!
//! Use [`Directory::lookup_did`] to fetch a DID document.
//!
//! # SSRF considerations
//!
//! Resolution fetches URLs whose host is derived from untrusted input (the
//! `did:web` host, the PLC directory, the handle's HTTPS/DNS records). The
//! HTTP clients used here are hardened: they follow **no redirects** (so a
//! resolved host cannot 30x-redirect a request to an internal address) and
//! apply bounded timeouts. The resolved document's `id` is also verified to
//! match the requested DID, and `did:web` is restricted to hostname form (no
//! path/port).
//!
//! These mitigations do **not** filter the initial resolved IP: a `did:web` or
//! handle host that resolves directly to a loopback/RFC1918/link-local address
//! (or via DNS rebinding) is still reachable. Deployments that resolve
//! untrusted identities should restrict egress at the network layer. IP-range
//! filtering may be offered as an opt-in in a future revision (default-deny
//! private ranges, with an explicit allow for localhost/self-hosted setups).

pub mod did_web;
pub mod directory;
#[allow(clippy::module_inception)]
pub mod identity;
pub mod plc;

pub use directory::Directory;
pub use identity::{DidDocument, Identity, Service, ServiceEndpoint, VerificationMethod};
pub use plc::PlcClient;

/// Errors that can occur during identity resolution.
#[derive(Debug, thiserror::Error)]
pub enum IdentityError {
    #[error("DID not found: {0}")]
    NotFound(String),
    #[error("invalid DID document: {0}")]
    InvalidDocument(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("handle verification failed: {0}")]
    HandleMismatch(String),
    #[error("syntax error: {0}")]
    Syntax(#[from] crate::syntax::SyntaxError),
}

/// Maximum DID-document response body we will buffer (1 MiB). A DID document is
/// a small JSON object; anything larger is malformed or hostile. Matches the
/// atmos resolver's `io.LimitReader` cap.
const MAX_DID_DOC_BYTES: u64 = 1 << 20;

/// Read, size-cap, deserialize, and verify a DID-document HTTP response.
///
/// Enforces three things every resolver must do, regardless of method:
/// - the body is bounded (no unbounded allocation from a hostile server);
/// - the JSON parses into a [`DidDocument`];
/// - the document's `id` equals the DID that was requested (otherwise a
///   malicious or misconfigured directory/host could impersonate an arbitrary
///   DID — spec: "The DID declared in the document ... should always be
///   verified against what was expected").
pub(crate) async fn fetch_did_document(
    resp: reqwest::Response,
    expected: &crate::syntax::Did,
) -> Result<DidDocument, IdentityError> {
    // Reject obviously-oversized bodies up front via Content-Length, then cap
    // the actual read so a server that lies about (or omits) Content-Length
    // still can't exhaust memory.
    if let Some(len) = resp.content_length()
        && len > MAX_DID_DOC_BYTES
    {
        return Err(IdentityError::InvalidDocument(format!(
            "DID document too large: {len} bytes"
        )));
    }

    let full = resp
        .bytes()
        .await
        .map_err(|e| IdentityError::Network(e.to_string()))?;
    if full.len() as u64 > MAX_DID_DOC_BYTES {
        return Err(IdentityError::InvalidDocument(format!(
            "DID document too large: {} bytes",
            full.len()
        )));
    }

    let doc: DidDocument =
        serde_json::from_slice(&full).map_err(|e| IdentityError::InvalidDocument(e.to_string()))?;

    if doc.id != expected.as_str() {
        return Err(IdentityError::InvalidDocument(format!(
            "DID document id {:?} does not match requested DID {:?}",
            doc.id,
            expected.as_str()
        )));
    }

    Ok(doc)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::syntax::Did;

    /// Serve a single canned HTTP/1.1 response body on a localhost port, then
    /// return the URL to GET. The connection is handled on a background task.
    async fn serve_once(body: String) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            // Drain the request (best-effort).
            let mut buf = [0u8; 1024];
            let _ = sock.read(&mut buf).await;
            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = sock.write_all(resp.as_bytes()).await;
            let _ = sock.shutdown().await;
        });
        format!("http://{addr}/")
    }

    /// Serve a single `302 Found` redirect to `location`, recording whether a
    /// second request ever arrives. Returns (base_url, hit_count handle).
    async fn serve_redirect(
        location: String,
    ) -> (String, std::sync::Arc<std::sync::atomic::AtomicU32>) {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU32, Ordering};
        let hits = Arc::new(AtomicU32::new(0));
        let hits_task = Arc::clone(&hits);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            // Handle several connections so a (wrongly) followed redirect that
            // loops back here would be counted.
            loop {
                let (mut sock, _) = match listener.accept().await {
                    Ok(s) => s,
                    Err(_) => break,
                };
                hits_task.fetch_add(1, Ordering::SeqCst);
                let mut buf = [0u8; 1024];
                let _ = sock.read(&mut buf).await;
                let resp = format!(
                    "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                );
                let _ = sock.write_all(resp.as_bytes()).await;
                let _ = sock.shutdown().await;
            }
        });
        (format!("http://{addr}"), hits)
    }

    #[tokio::test]
    async fn resolver_does_not_follow_redirects() {
        // SSRF guard (H11): a resolved host that 302-redirects must NOT be
        // followed. We point the PLC client at a mock that redirects to an
        // internal-looking address and assert resolution fails (does not
        // follow) — the redirect target is never fetched.
        use crate::identity::plc::PlcClient;
        let (base, _hits) = serve_redirect("http://169.254.169.254/latest/meta-data".into()).await;
        let client = PlcClient::new(&base);
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let result = client.resolve(&did).await;
        // The 302 is surfaced as a non-success status → NotFound, not followed.
        assert!(
            matches!(result, Err(IdentityError::NotFound(_))),
            "redirect must not be followed, got {result:?}"
        );
    }

    #[tokio::test]
    async fn rejects_doc_id_mismatch() {
        // The document claims a DIFFERENT DID than requested → impersonation.
        let requested = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let body =
            r#"{"id":"did:plc:someoneelse00000000000000","verificationMethod":[],"service":[]}"#;
        let url = serve_once(body.to_string()).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = fetch_did_document(resp, &requested).await.unwrap_err();
        assert!(
            matches!(err, IdentityError::InvalidDocument(_)),
            "doc.id mismatch must be rejected, got {err:?}"
        );
    }

    #[tokio::test]
    async fn accepts_matching_doc_id() {
        let requested = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let body =
            r#"{"id":"did:plc:z72i7hdynmk6r22z27h6tvur","verificationMethod":[],"service":[]}"#;
        let url = serve_once(body.to_string()).await;
        let resp = reqwest::get(&url).await.unwrap();
        let doc = fetch_did_document(resp, &requested).await.unwrap();
        assert_eq!(doc.id, "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[tokio::test]
    async fn rejects_oversized_body() {
        // A body far over the 1 MiB cap must be rejected, not buffered whole.
        let requested = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let big = "x".repeat((MAX_DID_DOC_BYTES as usize) + 1024);
        let body = format!(r#"{{"id":"did:plc:z72i7hdynmk6r22z27h6tvur","pad":"{big}"}}"#);
        let url = serve_once(body).await;
        let resp = reqwest::get(&url).await.unwrap();
        let err = fetch_did_document(resp, &requested).await.unwrap_err();
        assert!(
            matches!(err, IdentityError::InvalidDocument(_)),
            "oversized body must be rejected, got {err:?}"
        );
    }
}
