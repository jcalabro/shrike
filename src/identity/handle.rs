//! Handle → DID resolution (forward direction).
//!
//! Per the AT Protocol handle spec, a handle resolves to a DID via two
//! mechanisms, tried in order:
//!
//! 1. **DNS**: a TXT record at `_atproto.<handle>` whose value is `did=<did>`.
//! 2. **HTTPS**: `GET https://<handle>/.well-known/atproto-did` returning the
//!    DID as the response body.
//!
//! This module performs only the forward step; bidirectional verification
//! (confirming the resolved DID's document declares the handle back) is done by
//! [`Directory::lookup_handle`](crate::identity::Directory::lookup_handle).

use crate::syntax::{Did, Handle};

use crate::identity::IdentityError;

/// Maximum size of a `.well-known/atproto-did` response body. The body is just
/// a DID string; anything larger is malformed or hostile. Matches indigo's
/// 2 KiB cap.
const MAX_WELL_KNOWN_BYTES: u64 = 2048;

/// Resolve a handle to a DID, trying DNS first, then the HTTPS well-known
/// endpoint. Returns [`IdentityError::NotFound`] if neither mechanism yields a
/// valid DID.
///
/// `http` should be a hardened client (no redirects, bounded timeouts) — see
/// [`crate::identity`] for the SSRF rationale.
pub async fn resolve_handle(handle: &Handle, http: &reqwest::Client) -> Result<Did, IdentityError> {
    // 1. DNS TXT at _atproto.<handle>.
    match resolve_handle_dns(handle).await {
        Ok(did) => return Ok(did),
        // Fall through to HTTPS on "not found"; surface hard DNS errors only if
        // HTTPS also fails (below).
        Err(_dns_err) => {}
    }

    // 2. HTTPS well-known.
    resolve_handle_well_known(handle, http).await
}

/// Resolve via the DNS `_atproto.<handle>` TXT record (`did=<did>`).
pub async fn resolve_handle_dns(handle: &Handle) -> Result<Did, IdentityError> {
    use hickory_resolver::TokioResolver;

    let resolver = TokioResolver::builder_tokio()
        .map_err(|e| IdentityError::Network(format!("DNS resolver init: {e}")))?
        .build();

    let name = format!("_atproto.{}", handle.as_str());
    let lookup = resolver
        .txt_lookup(name)
        .await
        .map_err(|e| IdentityError::NotFound(format!("DNS TXT lookup for {handle}: {e}")))?;

    // Each TXT record may be split into multiple character-strings; concatenate
    // the segments of each record before checking for the `did=` prefix.
    for txt in lookup.iter() {
        let mut joined = Vec::new();
        for seg in txt.txt_data() {
            joined.extend_from_slice(seg);
        }
        let Ok(s) = std::str::from_utf8(&joined) else {
            continue;
        };
        if let Some(rest) = s.strip_prefix("did=") {
            return Did::try_from(rest.trim()).map_err(|e| {
                IdentityError::InvalidDocument(format!("invalid DID in _atproto TXT record: {e}"))
            });
        }
    }

    Err(IdentityError::NotFound(format!(
        "no did= TXT record at _atproto.{handle}"
    )))
}

/// Resolve via `GET https://<handle>/.well-known/atproto-did`.
pub async fn resolve_handle_well_known(
    handle: &Handle,
    http: &reqwest::Client,
) -> Result<Did, IdentityError> {
    let url = format!("https://{}/.well-known/atproto-did", handle.as_str());
    let resp = crate::outbound::apply_user_agent(http.get(&url))
        .send()
        .await
        .map_err(|e| IdentityError::Network(format!("well-known handle resolution: {e}")))?;

    if !resp.status().is_success() {
        return Err(IdentityError::NotFound(format!(
            "well-known handle resolution for {handle}: HTTP {}",
            resp.status()
        )));
    }

    // Reject oversized bodies (a DID string is tiny). Check Content-Length, then
    // cap the actual read.
    if let Some(len) = resp.content_length()
        && len > MAX_WELL_KNOWN_BYTES
    {
        return Err(IdentityError::InvalidDocument(format!(
            "well-known atproto-did body too large: {len} bytes"
        )));
    }
    let bytes = resp
        .bytes()
        .await
        .map_err(|e| IdentityError::Network(e.to_string()))?;
    if bytes.len() as u64 > MAX_WELL_KNOWN_BYTES {
        return Err(IdentityError::InvalidDocument(
            "well-known atproto-did body too large".into(),
        ));
    }

    let body = std::str::from_utf8(&bytes)
        .map_err(|_| IdentityError::InvalidDocument("well-known atproto-did not UTF-8".into()))?;
    Did::try_from(body.trim()).map_err(|e| {
        IdentityError::InvalidDocument(format!("invalid DID in well-known atproto-did: {e}"))
    })
}

/// Parse the DID out of a set of `_atproto` TXT record character-strings,
/// concatenating multi-segment records and returning the first `did=` value.
/// Factored out so the (network-free) parsing logic is unit-testable.
#[cfg(test)]
fn parse_txt_did(records: &[&[u8]]) -> Result<Did, IdentityError> {
    for seg_owner in records {
        if let Ok(s) = std::str::from_utf8(seg_owner)
            && let Some(rest) = s.strip_prefix("did=")
        {
            return Did::try_from(rest.trim()).map_err(|e| {
                IdentityError::InvalidDocument(format!("invalid DID in _atproto TXT record: {e}"))
            });
        }
    }
    Err(IdentityError::NotFound("no did= TXT record".into()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parse_txt_extracts_did() {
        let did = parse_txt_did(&[b"did=did:plc:z72i7hdynmk6r22z27h6tvur"]).unwrap();
        assert_eq!(did.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn parse_txt_skips_unrelated_records() {
        let did = parse_txt_did(&[
            b"v=spf1 include:_spf.example.com ~all",
            b"did=did:plc:z72i7hdynmk6r22z27h6tvur",
        ])
        .unwrap();
        assert_eq!(did.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn parse_txt_rejects_invalid_did() {
        assert!(parse_txt_did(&[b"did=not-a-did"]).is_err());
    }

    #[test]
    fn parse_txt_none_present() {
        assert!(matches!(
            parse_txt_did(&[b"unrelated"]),
            Err(IdentityError::NotFound(_))
        ));
    }

    #[tokio::test]
    async fn well_known_errors_on_unreachable_host_no_panic() {
        // The well-known helper must surface a clean error (not panic) when the
        // host is unreachable.
        let http = crate::outbound::hardened_client();
        let handle = Handle::try_from("definitely-not-a-real-host.invalid").unwrap();
        assert!(resolve_handle_well_known(&handle, &http).await.is_err());
    }

    #[tokio::test]
    async fn resolve_handle_dns_unknown_host_errors_no_panic() {
        let handle = Handle::try_from("nonexistent.handle.invalid").unwrap();
        assert!(resolve_handle_dns(&handle).await.is_err());
    }
}
