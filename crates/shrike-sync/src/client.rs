use std::sync::Arc;

use shrike_syntax::Did;

use crate::{DownloadedRepo, RepoEntry, SyncError};

/// A client for the `com.atproto.sync.*` XRPC namespace.
pub struct SyncClient {
    xrpc: shrike_xrpc::Client,
    // Retained for future identity-verified sync operations.
    #[allow(dead_code)]
    identity: Option<Arc<shrike_identity::Directory>>,
}

impl SyncClient {
    /// Create a new `SyncClient` backed by an XRPC client without identity resolution.
    pub fn new(xrpc: shrike_xrpc::Client) -> Self {
        SyncClient {
            xrpc,
            identity: None,
        }
    }

    /// Create a new `SyncClient` with an identity directory for DID verification.
    pub fn with_identity(xrpc: shrike_xrpc::Client, dir: Arc<shrike_identity::Directory>) -> Self {
        SyncClient {
            xrpc,
            identity: Some(dir),
        }
    }

    /// Download an entire repository as a CAR file and parse the commit and blocks.
    ///
    /// Calls `com.atproto.sync.getRepo` with the given DID, then parses the
    /// binary CAR response.
    pub async fn get_repo(&self, did: &Did) -> Result<DownloadedRepo, SyncError> {
        let params = serde_json::json!({ "did": did.as_str() });
        let car_bytes = self
            .xrpc
            .query_raw("com.atproto.sync.getRepo", &params)
            .await?;

        let (roots, blocks) = shrike_car::read_all(&car_bytes[..])?;

        let root_cid = roots
            .first()
            .ok_or_else(|| SyncError::Sync("CAR has no roots".into()))?;

        let root_block = blocks
            .iter()
            .find(|b| b.cid == *root_cid)
            .ok_or_else(|| SyncError::Sync("root block not found in CAR".into()))?;

        let commit = shrike_repo::Commit::from_cbor(&root_block.data)?;

        Ok(DownloadedRepo {
            did: commit.did.clone(),
            commit,
            blocks,
        })
    }

    /// List repositories available on a PDS or relay, with cursor-based pagination.
    ///
    /// Returns a list of [`RepoEntry`] values and an optional cursor for the next page.
    ///
    /// Note: this method requires generated API types and is not yet implemented.
    #[allow(unused_variables)]
    pub async fn list_repos(
        &self,
        cursor: Option<&str>,
    ) -> Result<(Vec<RepoEntry>, Option<String>), SyncError> {
        Err(SyncError::Sync("list_repos not yet implemented".into()))
    }
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
    use shrike_cbor::{Cid, Codec};
    use shrike_crypto::P256SigningKey;
    use shrike_syntax::{Did, Nsid, RecordKey, TidClock};

    fn make_test_commit() -> shrike_repo::Commit {
        let sk = P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let clock = TidClock::new(0).unwrap();
        let mut repo = shrike_repo::Repo::new(did, clock);
        let col = Nsid::try_from("app.bsky.feed.post").unwrap();
        repo.create(&col, &RecordKey::try_from("a").unwrap(), b"\xa0")
            .unwrap();
        repo.commit(&sk).unwrap()
    }

    #[test]
    fn sync_client_construction() {
        let client = SyncClient::new(shrike_xrpc::Client::new("https://bsky.social"));
        // Just verify it compiles and constructs without error.
        let _ = client;
    }

    #[test]
    fn sync_client_with_identity_construction() {
        let dir = Arc::new(shrike_identity::Directory::new());
        let client =
            SyncClient::with_identity(shrike_xrpc::Client::new("https://bsky.social"), dir);
        let _ = client;
    }

    // --- SyncClient configuration: with_identity accepts any Directory ---

    #[test]
    fn sync_client_with_custom_plc_url() {
        let dir = Arc::new(shrike_identity::Directory::with_plc_url(
            "https://custom-plc.example.com",
        ));
        let client =
            SyncClient::with_identity(shrike_xrpc::Client::new("https://pds.example.com"), dir);
        let _ = client;
    }

    #[test]
    fn sync_client_with_default_directory() {
        let dir = Arc::new(shrike_identity::Directory::default());
        let client =
            SyncClient::with_identity(shrike_xrpc::Client::new("https://bsky.social"), dir);
        let _ = client;
    }

    // --- DownloadedRepo construction: verify fields accessible ---

    #[test]
    fn downloaded_repo_fields_accessible() {
        let commit = make_test_commit();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();

        let data = b"test block data".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let blocks = vec![shrike_car::Block { cid, data }];

        let repo = DownloadedRepo {
            did: did.clone(),
            commit,
            blocks,
        };

        assert_eq!(repo.did.as_str(), "did:plc:test123456789abcdefghij");
        assert_eq!(repo.blocks.len(), 1);
        assert_eq!(repo.blocks[0].cid, cid);
        assert_eq!(repo.blocks[0].data, b"test block data");
        // commit.did should match the constructed DID
        assert_eq!(repo.commit.did.as_str(), "did:plc:test123456789abcdefghij");
    }

    #[test]
    fn downloaded_repo_empty_blocks() {
        let commit = make_test_commit();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();

        let repo = DownloadedRepo {
            did,
            commit,
            blocks: vec![],
        };

        assert!(repo.blocks.is_empty());
    }

    // --- Record type: field access ---

    #[test]
    fn record_field_access() {
        let collection = Nsid::try_from("app.bsky.feed.post").unwrap();
        let rkey = RecordKey::try_from("3jwdwj2ctlk26").unwrap();
        let data = b"record payload".to_vec();
        let cid = Cid::compute(Codec::Drisl, &data);

        let record = crate::Record {
            collection: collection.clone(),
            rkey: rkey.clone(),
            cid,
            data: data.clone(),
        };

        assert_eq!(record.collection.as_str(), "app.bsky.feed.post");
        assert_eq!(record.rkey.as_str(), "3jwdwj2ctlk26");
        assert_eq!(record.cid, cid);
        assert_eq!(record.data, data);
    }

    #[test]
    fn repo_entry_field_access() {
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let head = Cid::compute(Codec::Drisl, b"head block");

        let entry = crate::RepoEntry {
            did: did.clone(),
            head,
        };

        assert_eq!(entry.did.as_str(), "did:plc:test123456789abcdefghij");
        assert_eq!(entry.head, head);
    }
}
