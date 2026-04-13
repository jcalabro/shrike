use anyhow::{Context, Result};

use shrike::api::com::atproto::{
    RepoDescribeRepoParams, RepoGetRecordParams, RepoListRecordsParams, repo_describe_repo,
    repo_get_record, repo_list_records,
};
use shrike::syntax::{AtUri, Did, Handle};
use shrike::xrpc::{AuthInfo, Client};

use crate::resolve;
use crate::session;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Fetch a record by AT-URI
    Get(GetArgs),
    /// List records for a repo
    List(ListArgs),
}

#[derive(clap::Args)]
pub struct GetArgs {
    /// AT-URI of the record
    pub at_uri: String,
}

#[derive(clap::Args)]
pub struct ListArgs {
    /// DID or handle
    pub did_or_handle: String,
    /// Collection NSID (omit to list collections)
    pub collection: Option<String>,
    /// Maximum number of records
    #[arg(long, default_value = "50")]
    pub limit: i64,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Get(args) => get(args).await,
        Command::List(args) => list(args).await,
    }
}

fn make_authed_client_from_session() -> Result<Client> {
    match session::require()? {
        session::ActiveSession::AppPassword(sess) => {
            let handle = Handle::try_from(sess.handle.as_str());
            let did = Did::try_from(sess.did.as_str());
            match (handle, did) {
                (Ok(h), Ok(d)) => {
                    let auth = AuthInfo {
                        access_jwt: sess.access_jwt.clone(),
                        refresh_jwt: sess.refresh_jwt.clone(),
                        handle: h,
                        did: d,
                    };
                    Ok(Client::with_auth(&sess.host, auth))
                }
                _ => {
                    anyhow::bail!("stored session has invalid handle or DID — try logging in again")
                }
            }
        }
        session::ActiveSession::OAuth(sess) => {
            // For OAuth sessions, create a client with the access token as Bearer.
            // Note: This doesn't include DPoP proofs — full DPoP support requires
            // using AuthenticatedClient from shrike-oauth. For now, some endpoints
            // accept Bearer tokens from OAuth sessions.
            let auth = AuthInfo {
                access_jwt: sess.token_set.access_token.clone(),
                refresh_jwt: sess.token_set.refresh_token.clone().unwrap_or_default(),
                handle: Handle::try_from("handle.invalid")
                    .unwrap_or_else(|_| Handle::try_from("x.invalid").unwrap_or_default()),
                did: Did::try_from(sess.token_set.sub.as_str())
                    .map_err(|e| anyhow::anyhow!("invalid DID in OAuth session: {e}"))?,
            };
            Ok(Client::with_auth(&sess.token_set.aud, auth))
        }
    }
}

async fn get(args: GetArgs) -> Result<()> {
    let client = make_authed_client_from_session()?;

    let uri = AtUri::try_from(args.at_uri.as_str()).context("invalid AT-URI")?;

    let authority = uri.authority();
    let collection = uri
        .collection()
        .context("AT-URI must include a collection")?;
    let rkey = uri.rkey().context("AT-URI must include a record key")?;

    // Resolve handle to DID if needed.
    let repo = if authority.starts_with("did:") {
        authority.to_string()
    } else {
        resolve::resolve_to_did(authority)
            .await
            .context("failed to resolve authority")?
            .to_string()
    };

    let params = RepoGetRecordParams {
        repo,
        collection: collection.to_string(),
        rkey: rkey.to_string(),
        cid: None,
    };

    let output = repo_get_record(&client, &params)
        .await
        .context("failed to fetch record")?;

    println!(
        "{}",
        serde_json::to_string_pretty(&output.value).context("failed to serialize record")?
    );

    Ok(())
}

async fn list(args: ListArgs) -> Result<()> {
    let client = make_authed_client_from_session()?;

    let did = resolve::resolve_to_did(&args.did_or_handle)
        .await
        .context("failed to resolve identity")?;

    match args.collection {
        Some(collection) => list_records(&client, &did, &collection, args.limit, args.json).await,
        None => list_collections(&client, &did, args.json).await,
    }
}

async fn list_records(
    client: &Client,
    did: &Did,
    collection: &str,
    limit: i64,
    json: bool,
) -> Result<()> {
    let params = RepoListRecordsParams {
        repo: did.to_string(),
        collection: collection.to_string(),
        limit: Some(limit),
        cursor: None,
        reverse: None,
    };

    let output = repo_list_records(client, &params)
        .await
        .context("failed to list records")?;

    if json {
        #[derive(serde::Serialize)]
        struct RecordEntry {
            uri: String,
            cid: String,
        }
        let entries: Vec<RecordEntry> = output
            .records
            .iter()
            .map(|r| RecordEntry {
                uri: r.uri.to_string(),
                cid: r.cid.clone(),
            })
            .collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&entries).context("failed to serialize records")?
        );
    } else {
        for record in &output.records {
            println!("{}  {}", record.uri, record.cid);
        }
    }

    Ok(())
}

async fn list_collections(client: &Client, did: &Did, json: bool) -> Result<()> {
    let params = RepoDescribeRepoParams {
        repo: did.to_string(),
    };

    let output = repo_describe_repo(client, &params)
        .await
        .context("failed to describe repo")?;

    if json {
        let collections: Vec<String> = output.collections.iter().map(|c| c.to_string()).collect();
        println!(
            "{}",
            serde_json::to_string_pretty(&collections)
                .context("failed to serialize collections")?
        );
    } else {
        for collection in &output.collections {
            println!("{collection}");
        }
    }

    Ok(())
}
