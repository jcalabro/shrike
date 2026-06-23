use crate::syntax::Did;

use crate::identity::DidDocument;
use crate::identity::IdentityError;

/// PLC Directory client.
pub struct PlcClient {
    url: String,
    http: reqwest::Client,
}

impl PlcClient {
    /// Create a PLC client pointing at the given directory URL.
    ///
    /// The PLC endpoint is operator-configured (the DID travels in the URL
    /// path, not the host), so it is treated as trusted: connect-time address
    /// filtering is **not** applied here. The redirect/timeout hardening still
    /// applies. This is also what lets a local PLC mirror
    /// (`http://127.0.0.1:...`) be used in tests and self-hosting.
    pub fn new(url: &str) -> Self {
        PlcClient {
            url: url.to_string(),
            http: crate::outbound::hardened_client(crate::outbound::AddressPolicy::AllowLocal),
        }
    }

    /// Create a PLC client using the production `https://plc.directory` endpoint.
    pub fn production() -> Self {
        Self::new("https://plc.directory")
    }

    /// Resolve a `did:plc` DID to its DID document.
    pub async fn resolve(&self, did: &Did) -> Result<DidDocument, IdentityError> {
        let url = format!("{}/{}", self.url, did.as_str());
        let resp = crate::outbound::apply_user_agent(self.http.get(&url))
            .send()
            .await
            .map_err(|e| IdentityError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(IdentityError::NotFound(did.to_string()));
        }
        crate::identity::fetch_did_document(resp, did).await
    }
}
