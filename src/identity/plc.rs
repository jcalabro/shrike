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
    pub fn new(url: &str) -> Self {
        PlcClient {
            url: url.to_string(),
            http: reqwest::Client::new(),
        }
    }

    /// Create a PLC client using the production `https://plc.directory` endpoint.
    pub fn production() -> Self {
        Self::new("https://plc.directory")
    }

    /// Resolve a `did:plc` DID to its DID document.
    pub async fn resolve(&self, did: &Did) -> Result<DidDocument, IdentityError> {
        let url = format!("{}/{}", self.url, did.as_str());
        let resp = self
            .http
            .get(&url)
            .send()
            .await
            .map_err(|e| IdentityError::Network(e.to_string()))?;
        if !resp.status().is_success() {
            return Err(IdentityError::NotFound(did.to_string()));
        }
        resp.json()
            .await
            .map_err(|e| IdentityError::InvalidDocument(e.to_string()))
    }
}
