//! DID and handle resolution for AT Protocol identities.
//!
//! The Directory type resolves DIDs and handles to DID documents. Supports
//! both did:plc (via PlcClient) and did:web. DID documents contain public
//! keys and service endpoints used for authentication and communication.
//!
//! Use Directory::resolve_did to fetch a DID document or
//! Directory::resolve_handle to look up a DID from a handle.

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
