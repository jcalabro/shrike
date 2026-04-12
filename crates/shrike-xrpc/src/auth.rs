use serde::{Deserialize, Serialize};
use shrike_syntax::{Did, Handle};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: Handle,
    pub did: Did,
}
