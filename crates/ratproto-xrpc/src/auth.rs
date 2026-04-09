use ratproto_syntax::{Did, Handle};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthInfo {
    pub access_jwt: String,
    pub refresh_jwt: String,
    pub handle: Handle,
    pub did: Did,
}
