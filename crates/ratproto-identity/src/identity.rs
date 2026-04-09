use std::collections::HashMap;

use ratproto_crypto::VerifyingKey;
use ratproto_syntax::{Did, Handle};
use serde::Deserialize;

use crate::IdentityError;

/// Resolved identity — the result of looking up a DID.
pub struct Identity {
    pub did: Did,
    pub handle: Option<Handle>,
    pub keys: HashMap<String, Box<dyn VerifyingKey>>,
    pub services: HashMap<String, ServiceEndpoint>,
}

/// A service endpoint extracted from a DID document.
#[derive(Debug, Clone)]
pub struct ServiceEndpoint {
    pub id: String,
    pub r#type: String,
    pub endpoint: String,
}

impl Identity {
    /// Get the PDS endpoint URL.
    pub fn pds_endpoint(&self) -> Option<&str> {
        self.services
            .get("#atproto_pds")
            .map(|s| s.endpoint.as_str())
    }

    /// Get the atproto signing key.
    pub fn signing_key(&self) -> Option<&dyn VerifyingKey> {
        self.keys.get("#atproto").map(|k| k.as_ref())
    }

    /// Build an Identity from a parsed DID document.
    pub fn from_document(doc: DidDocument) -> Result<Self, IdentityError> {
        let did = Did::try_from(doc.id.as_str())
            .map_err(|e| IdentityError::InvalidDocument(format!("invalid DID: {e}")))?;

        // Extract handle from alsoKnownAs (at:// URIs).
        let handle = doc
            .also_known_as
            .iter()
            .filter_map(|uri| uri.strip_prefix("at://"))
            .filter_map(|h| Handle::try_from(h).ok())
            .next();

        // Extract verification keys.
        let mut keys: HashMap<String, Box<dyn VerifyingKey>> = HashMap::new();
        for vm in &doc.verification_method {
            if let Some(ref multibase) = vm.public_key_multibase
                && let Ok(key) = ratproto_crypto::parse_did_key(&format!("did:key:{multibase}"))
            {
                keys.insert(vm.id.clone(), key);
            }
        }

        // Extract services.
        let mut services = HashMap::new();
        for svc in &doc.service {
            services.insert(
                svc.id.clone(),
                ServiceEndpoint {
                    id: svc.id.clone(),
                    r#type: svc.r#type.clone(),
                    endpoint: svc.service_endpoint.clone(),
                },
            );
        }

        Ok(Identity {
            did,
            handle,
            keys,
            services,
        })
    }
}

/// DID Document JSON structure.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DidDocument {
    pub id: String,
    #[serde(default)]
    pub also_known_as: Vec<String>,
    #[serde(default)]
    pub verification_method: Vec<VerificationMethod>,
    #[serde(default)]
    pub service: Vec<Service>,
}

/// A verification method entry in a DID document.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethod {
    pub id: String,
    pub r#type: String,
    #[serde(default)]
    pub public_key_multibase: Option<String>,
}

/// A service entry in a DID document.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    pub r#type: String,
    pub service_endpoint: String,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_document() {
        let json = r##"{
            "id": "did:plc:z72i7hdynmk6r22z27h6tvur",
            "alsoKnownAs": ["at://bsky.app"],
            "verificationMethod": [],
            "service": [{
                "id": "#atproto_pds",
                "type": "AtprotoPersonalDataServer",
                "serviceEndpoint": "https://bsky.social"
            }]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.did.as_str(), "did:plc:z72i7hdynmk6r22z27h6tvur");
        assert_eq!(identity.pds_endpoint(), Some("https://bsky.social"));
    }

    #[test]
    fn extract_handle_from_also_known_as() {
        let doc: DidDocument = serde_json::from_str(
            r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": ["at://alice.bsky.social"],
            "verificationMethod": [],
            "service": []
        }"#,
        )
        .unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(
            identity.handle.as_ref().unwrap().as_str(),
            "alice.bsky.social"
        );
    }

    #[test]
    fn pds_endpoint_missing() {
        let doc: DidDocument = serde_json::from_str(
            r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": [],
            "verificationMethod": [],
            "service": []
        }"#,
        )
        .unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.pds_endpoint(), None);
    }

    #[test]
    fn signing_key_none_when_no_verification_methods() {
        let doc: DidDocument = serde_json::from_str(
            r#"{
            "id": "did:plc:test123456789abcdefghij",
            "verificationMethod": [],
            "service": []
        }"#,
        )
        .unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert!(identity.signing_key().is_none());
    }

    // --- DID document parsing edge cases ---

    #[test]
    fn did_document_missing_optional_fields_uses_defaults() {
        // alsoKnownAs, verificationMethod, and service all have #[serde(default)]
        let json = r#"{"id": "did:plc:test123456789abcdefghij"}"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        assert!(doc.also_known_as.is_empty());
        assert!(doc.verification_method.is_empty());
        assert!(doc.service.is_empty());
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.did.as_str(), "did:plc:test123456789abcdefghij");
        assert!(identity.handle.is_none());
    }

    #[test]
    fn did_document_extra_fields_are_ignored() {
        let json = r#"{
            "id": "did:plc:test123456789abcdefghij",
            "unknownField": "should be ignored",
            "anotherExtra": 42,
            "verificationMethod": [],
            "service": []
        }"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.did.as_str(), "did:plc:test123456789abcdefghij");
    }

    #[test]
    fn did_document_multiple_verification_methods() {
        let json = r##"{
            "id": "did:plc:test123456789abcdefghij",
            "verificationMethod": [
                {
                    "id": "#atproto",
                    "type": "Multikey",
                    "publicKeyMultibase": null
                },
                {
                    "id": "#atproto2",
                    "type": "Multikey",
                    "publicKeyMultibase": null
                }
            ],
            "service": []
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        assert_eq!(doc.verification_method.len(), 2);
        assert_eq!(doc.verification_method[0].id, "#atproto");
        assert_eq!(doc.verification_method[1].id, "#atproto2");
    }

    #[test]
    fn did_document_multiple_services() {
        let json = r##"{
            "id": "did:plc:test123456789abcdefghij",
            "verificationMethod": [],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://bsky.social"
                },
                {
                    "id": "#atproto_notif",
                    "type": "BskyNotificationService",
                    "serviceEndpoint": "https://notif.bsky.app"
                }
            ]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.services.len(), 2);
        assert_eq!(identity.pds_endpoint(), Some("https://bsky.social"));
        let notif = identity.services.get("#atproto_notif").unwrap();
        assert_eq!(notif.endpoint, "https://notif.bsky.app");
    }

    // --- Handle extraction edge cases ---

    #[test]
    fn handle_extraction_uses_first_at_uri() {
        let json = r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": [
                "at://alice.bsky.social",
                "at://alice-backup.bsky.social"
            ],
            "verificationMethod": [],
            "service": []
        }"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        // Only the first at:// URI should be used.
        assert_eq!(
            identity.handle.as_ref().unwrap().as_str(),
            "alice.bsky.social"
        );
    }

    #[test]
    fn handle_extraction_ignores_non_at_uris() {
        let json = r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": [
                "https://alice.example.com",
                "ftp://other.example.com"
            ],
            "verificationMethod": [],
            "service": []
        }"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert!(
            identity.handle.is_none(),
            "non-at:// URIs should be ignored"
        );
    }

    #[test]
    fn handle_extraction_skips_invalid_handles() {
        let json = r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": [
                "at://not_a_valid_handle!!!"
            ],
            "verificationMethod": [],
            "service": []
        }"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        // Invalid handle syntax — should be silently skipped, not error.
        assert!(identity.handle.is_none());
    }

    #[test]
    fn handle_extraction_non_at_before_at_still_finds_at() {
        let json = r#"{
            "id": "did:plc:test123456789abcdefghij",
            "alsoKnownAs": [
                "https://skip.me",
                "at://bob.bsky.social"
            ],
            "verificationMethod": [],
            "service": []
        }"#;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(
            identity.handle.as_ref().unwrap().as_str(),
            "bob.bsky.social"
        );
    }

    // --- Service endpoint extraction ---

    #[test]
    fn service_endpoint_find_pds() {
        let json = r##"{
            "id": "did:plc:test123456789abcdefghij",
            "verificationMethod": [],
            "service": [
                {
                    "id": "#other_service",
                    "type": "SomeType",
                    "serviceEndpoint": "https://other.example.com"
                },
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://my-pds.example.com"
                }
            ]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        assert_eq!(identity.pds_endpoint(), Some("https://my-pds.example.com"));
    }

    #[test]
    fn service_endpoint_type_and_id_accessible() {
        let json = r##"{
            "id": "did:plc:test123456789abcdefghij",
            "verificationMethod": [],
            "service": [
                {
                    "id": "#atproto_pds",
                    "type": "AtprotoPersonalDataServer",
                    "serviceEndpoint": "https://pds.example.com"
                }
            ]
        }"##;
        let doc: DidDocument = serde_json::from_str(json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        let svc = identity.services.get("#atproto_pds").unwrap();
        assert_eq!(svc.id, "#atproto_pds");
        assert_eq!(svc.r#type, "AtprotoPersonalDataServer");
        assert_eq!(svc.endpoint, "https://pds.example.com");
    }

    // --- Verification method with valid multibase key ---

    #[test]
    fn verification_method_with_valid_multibase_key() {
        use ratproto_crypto::{P256SigningKey, SigningKey};

        // Generate a real P-256 key and get its multibase representation.
        let sk = P256SigningKey::generate();
        let multibase = sk.public_key().multibase();

        let json = format!(
            r##"{{
                "id": "did:plc:test123456789abcdefghij",
                "verificationMethod": [
                    {{
                        "id": "#atproto",
                        "type": "Multikey",
                        "publicKeyMultibase": "{multibase}"
                    }}
                ],
                "service": []
            }}"##
        );

        let doc: DidDocument = serde_json::from_str(&json).unwrap();
        let identity = Identity::from_document(doc).unwrap();
        // The key should be parsed and stored.
        assert!(identity.signing_key().is_some());
        // The stored key bytes should match the original.
        let stored_bytes = identity.signing_key().unwrap().to_bytes();
        assert_eq!(stored_bytes, sk.public_key().to_bytes());
    }

    // --- Directory construction ---

    #[test]
    fn directory_default_construction() {
        let dir = crate::Directory::new();
        let _ = dir;
    }

    #[test]
    fn directory_with_custom_plc_url() {
        let dir = crate::Directory::with_plc_url("https://custom-plc.example.com");
        let _ = dir;
    }

    #[test]
    fn directory_default_trait() {
        let dir = crate::Directory::default();
        let _ = dir;
    }
}
