use crate::syntax::{Did, Handle};
use serde::{Deserialize, Serialize};

/// Credentials returned by `com.atproto.server.createSession`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    /// Short-lived access token for authenticated XRPC requests.
    pub access_jwt: String,
    /// Long-lived token used to obtain new access tokens.
    pub refresh_jwt: String,
    /// The account's handle (e.g., "alice.bsky.social").
    pub handle: Handle,
    /// The account's DID (e.g., "did:plc:...").
    pub did: Did,
}
