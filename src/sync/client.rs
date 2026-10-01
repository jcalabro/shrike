use std::sync::Arc;

use futures::StreamExt;

use crate::syntax::Did;

use crate::sync::{
    DEFAULT_MAX_REPO_CAR_BYTES, DownloadedRepo, RepoCarStream, RepoEntry, SyncError,
};

/// A client for the `com.atproto.sync.*` XRPC namespace.
pub struct SyncClient {
    xrpc: crate::xrpc::Client,
    // Retained for future identity-verified sync operations.
    #[allow(dead_code)]
    identity: Option<Arc<crate::identity::Directory>>,
}

impl SyncClient {
    /// Create a new `SyncClient` backed by an XRPC client without identity resolution.
    pub fn new(xrpc: crate::xrpc::Client) -> Self {
        SyncClient {
            xrpc,
            identity: None,
        }
    }

    /// Create a new `SyncClient` with an identity directory for DID verification.
    pub fn with_identity(xrpc: crate::xrpc::Client, dir: Arc<crate::identity::Directory>) -> Self {
        SyncClient {
            xrpc,
            identity: Some(dir),
        }
    }

    /// Download an entire repository as a CAR file and parse the commit and blocks.
    ///
    /// Calls `com.atproto.sync.getRepo` with the given DID and decodes the CAR
    /// as it streams in. Bodies over [`DEFAULT_MAX_REPO_CAR_BYTES`] are
    /// rejected.
    pub async fn get_repo(&self, did: &Did) -> Result<DownloadedRepo, SyncError> {
        let mut car = self.get_repo_car_stream(did).await?;
        let mut reader = crate::car::IncrementalReader::new();
        let mut blocks = Vec::new();
        let mut size = 0;
        while let Some(chunk) = car.next().await {
            let chunk = chunk?;
            size += chunk.len();
            if size > DEFAULT_MAX_REPO_CAR_BYTES {
                return Err(crate::xrpc::Error::ResponseTooLarge {
                    size: size as u64,
                    limit: DEFAULT_MAX_REPO_CAR_BYTES as u64,
                }
                .into());
            }
            reader.push(&chunk);
            while let Some(block) = reader.next_block()? {
                blocks.push(block);
            }
        }
        reader.finish()?;

        let root_cid = reader
            .roots()
            .and_then(|roots| roots.first())
            .ok_or_else(|| SyncError::Sync("CAR has no roots".into()))?;

        let root_block = blocks
            .iter()
            .find(|b| b.cid == *root_cid)
            .ok_or_else(|| SyncError::Sync("root block not found in CAR".into()))?;

        let commit = crate::repo::Commit::from_cbor(&root_block.data)?;

        Ok(DownloadedRepo {
            did: commit.did.clone(),
            commit,
            blocks,
        })
    }

    /// Download an entire repository as raw CAR bytes, up to 512 MB.
    pub async fn get_repo_car(&self, did: &Did) -> Result<Vec<u8>, SyncError> {
        let params = serde_json::json!({ "did": did.as_str() });
        Ok(self
            .xrpc
            .query_raw("com.atproto.sync.getRepo", &params)
            .await?)
    }

    /// Stream an entire repository's raw CAR bytes as they arrive.
    ///
    /// No size limit applies; the caller must bound how much it reads. Feed the
    /// chunks to a [`car::IncrementalReader`](crate::car::IncrementalReader) to
    /// decode blocks without buffering the whole repo.
    pub async fn get_repo_car_stream(&self, did: &Did) -> Result<RepoCarStream, SyncError> {
        let params = serde_json::json!({ "did": did.as_str() });
        let resp = self
            .xrpc
            .query_response("com.atproto.sync.getRepo", &params)
            .await?;
        Ok(resp
            .bytes_stream()
            .map(|chunk| chunk.map_err(|e| crate::xrpc::Error::Network(e).into()))
            .boxed())
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
    use crate::cbor::{Cid, Codec};
    use crate::crypto::P256SigningKey;
    use crate::syntax::{Did, Nsid, RecordKey, TidClock};

    fn make_test_commit() -> crate::repo::Commit {
        let sk = P256SigningKey::generate();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
        let clock = TidClock::new(0).unwrap();
        let mut repo = crate::repo::Repo::new(did, clock);
        let col = Nsid::try_from("app.bsky.feed.post").unwrap();
        repo.create(&col, &RecordKey::try_from("a").unwrap(), b"\xa0")
            .unwrap();
        repo.commit(&sk).unwrap()
    }

    #[test]
    fn sync_client_construction() {
        let client = SyncClient::new(crate::xrpc::Client::new("https://bsky.social"));
        // Just verify it compiles and constructs without error.
        let _ = client;
    }

    #[test]
    fn sync_client_with_identity_construction() {
        let dir = Arc::new(crate::identity::Directory::new());
        let client =
            SyncClient::with_identity(crate::xrpc::Client::new("https://bsky.social"), dir);
        let _ = client;
    }

    // --- SyncClient configuration: with_identity accepts any Directory ---

    #[test]
    fn sync_client_with_custom_plc_url() {
        let dir = Arc::new(crate::identity::Directory::with_plc_url(
            "https://custom-plc.example.com",
        ));
        let client =
            SyncClient::with_identity(crate::xrpc::Client::new("https://pds.example.com"), dir);
        let _ = client;
    }

    #[test]
    fn sync_client_with_default_directory() {
        let dir = Arc::new(crate::identity::Directory::default());
        let client =
            SyncClient::with_identity(crate::xrpc::Client::new("https://bsky.social"), dir);
        let _ = client;
    }

    // --- DownloadedRepo construction: verify fields accessible ---

    #[test]
    fn downloaded_repo_fields_accessible() {
        let commit = make_test_commit();
        let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();

        let data = b"test block data".to_vec();
        let cid = Cid::compute(Codec::Raw, &data);
        let blocks = vec![crate::car::Block { cid, data }];

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

        let record = crate::sync::Record {
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

        let entry = crate::sync::RepoEntry {
            did: did.clone(),
            head,
        };

        assert_eq!(entry.did.as_str(), "did:plc:test123456789abcdefghij");
        assert_eq!(entry.head, head);
    }

    // --- getRepo over HTTP ---

    /// A CAR holding a signed commit (the root) and one record block.
    fn repo_car() -> (crate::repo::Commit, Vec<u8>) {
        let commit = make_test_commit();
        let commit_bytes = commit.to_cbor().unwrap();
        let root = Cid::compute(Codec::Drisl, &commit_bytes);
        let record = b"\xa1\x61a\x01".to_vec();
        let blocks = [
            crate::car::Block {
                cid: root,
                data: commit_bytes,
            },
            crate::car::Block {
                cid: Cid::compute(Codec::Drisl, &record),
                data: record,
            },
        ];
        (commit, crate::car::write_all(&[root], &blocks).unwrap())
    }

    /// Serve `car` from getRepo as a chunked body of `chunk`-byte pieces.
    async fn serve_repo(car: Vec<u8>, chunk: usize) -> String {
        use axum::{Router, body::Body, routing::get};
        let app = Router::new().route(
            "/xrpc/com.atproto.sync.getRepo",
            get(move || {
                let chunks: Vec<Result<bytes::Bytes, std::io::Error>> = car
                    .chunks(chunk)
                    .map(|c| Ok(bytes::Bytes::copy_from_slice(c)))
                    .collect();
                async move { Body::from_stream(futures::stream::iter(chunks)) }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
        format!("http://{addr}")
    }

    fn did() -> Did {
        Did::try_from("did:plc:test123456789abcdefghij").unwrap()
    }

    #[tokio::test]
    async fn get_repo_decodes_chunked_car() {
        let (commit, car) = repo_car();
        let client = SyncClient::new(crate::xrpc::Client::new(&serve_repo(car, 5).await));
        let repo = client.get_repo(&did()).await.unwrap();
        assert_eq!(repo.did, did());
        assert_eq!(repo.commit.rev, commit.rev);
        assert_eq!(repo.commit.data, commit.data);
        assert_eq!(repo.blocks.len(), 2);
    }

    #[tokio::test]
    async fn get_repo_car_stream_yields_the_body() {
        let (_, car) = repo_car();
        let client = SyncClient::new(crate::xrpc::Client::new(&serve_repo(car.clone(), 3).await));
        let mut stream = client.get_repo_car_stream(&did()).await.unwrap();
        let mut body = Vec::new();
        while let Some(chunk) = stream.next().await {
            body.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(body, car);
        assert_eq!(client.get_repo_car(&did()).await.unwrap(), car);
    }

    #[tokio::test]
    async fn get_repo_rejects_truncated_car() {
        let (_, mut car) = repo_car();
        car.pop();
        let client = SyncClient::new(crate::xrpc::Client::new(&serve_repo(car, 64).await));
        let err = client.get_repo(&did()).await.err().unwrap();
        assert!(
            matches!(err, SyncError::Car(crate::car::CarError::InvalidBlock(ref m)) if m == "truncated block data"),
            "{err:?}"
        );
    }

    #[tokio::test]
    async fn get_repo_rejects_car_missing_root_block() {
        let (_, car) = repo_car();
        let (roots, blocks) = crate::car::read_all(&car[..]).unwrap();
        let car = crate::car::write_all(&roots, &blocks[1..]).unwrap();
        let client = SyncClient::new(crate::xrpc::Client::new(&serve_repo(car, 64).await));
        let err = client.get_repo(&did()).await.err().unwrap();
        assert!(matches!(err, SyncError::Sync(ref m) if m == "root block not found in CAR"));
    }
}
