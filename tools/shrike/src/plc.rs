use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use shrike::identity::Directory;
use shrike::syntax::Did;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Resolve a DID via the PLC directory
    Resolve(ResolveArgs),
    /// Show PLC operation audit log for a DID
    History(HistoryArgs),
}

#[derive(clap::Args)]
pub struct ResolveArgs {
    /// DID to resolve
    pub did: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct HistoryArgs {
    /// DID to look up
    pub did: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Resolve(args) => resolve(args).await,
        Command::History(args) => history(args).await,
    }
}

async fn resolve(args: ResolveArgs) -> Result<()> {
    let did = Did::try_from(args.did.as_str()).context("invalid DID")?;
    let dir = Directory::new();
    let identity = dir
        .lookup_did(&did)
        .await
        .context("failed to resolve DID")?;

    if args.json {
        #[derive(Serialize)]
        struct Output {
            did: String,
            handle: Option<String>,
            pds: Option<String>,
            signing_key: Option<String>,
        }
        let output = Output {
            did: identity.did.to_string(),
            handle: identity.handle.as_ref().map(|h| h.to_string()),
            pds: identity.pds_endpoint().map(|s| s.to_string()),
            signing_key: identity.signing_key().map(|k| k.did_key()),
        };
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("did:     {}", identity.did);
        if let Some(ref h) = identity.handle {
            println!("handle:  {h}");
        }
        if let Some(pds) = identity.pds_endpoint() {
            println!("pds:     {pds}");
        }
        if let Some(k) = identity.signing_key() {
            println!("signing: {}", k.did_key());
        }
    }

    Ok(())
}

#[derive(Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
struct PlcLogEntry {
    did: String,
    cid: String,
    nullified: bool,
    created_at: String,
}

async fn history(args: HistoryArgs) -> Result<()> {
    let did = Did::try_from(args.did.as_str()).context("invalid DID")?;
    let url = format!("https://plc.directory/{}/log/audit", did);
    let entries: Vec<PlcLogEntry> = reqwest::get(&url)
        .await
        .context("failed to fetch PLC audit log")?
        .json()
        .await
        .context("failed to parse PLC audit log")?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&entries)?);
    } else {
        for (i, entry) in entries.iter().enumerate() {
            let status = if entry.nullified {
                "(nullified)"
            } else {
                "(active)"
            };
            println!("{}  {}  {}  {status}", i + 1, entry.created_at, entry.cid);
        }
    }

    Ok(())
}
