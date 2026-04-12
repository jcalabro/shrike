use anyhow::{Context, Result};
use serde::Serialize;
use shrike_identity::Directory;
use shrike_syntax::{Did, Handle};

#[derive(clap::Args)]
pub struct Args {
    /// Handle or DID to resolve
    pub handle_or_did: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
    /// Print only the DID
    #[arg(long)]
    pub did_only: bool,
}

#[derive(Serialize)]
struct Output {
    did: String,
    handle: Option<String>,
    pds: Option<String>,
    signing_key: Option<String>,
}

/// Resolve a handle to a DID.
///
/// Tries HTTP `.well-known/atproto-did` first, then falls back to DNS TXT
/// lookup on `_atproto.{handle}`.
pub async fn resolve_handle(handle: &Handle) -> Result<Did> {
    // Try HTTP .well-known first
    let url = format!("https://{}/.well-known/atproto-did", handle);
    if let Ok(resp) = reqwest::get(&url).await
        && resp.status().is_success()
        && let Ok(did_str) = resp.text().await
        && let Ok(did) = Did::try_from(did_str.trim())
    {
        return Ok(did);
    }

    // Fall back to DNS TXT _atproto.{handle}
    resolve_handle_dns(handle)
        .await
        .with_context(|| format!("failed to resolve handle '{handle}'"))
}

/// Resolve a handle via DNS TXT record at `_atproto.{handle}`.
async fn resolve_handle_dns(handle: &Handle) -> Result<Did> {
    let resolver = hickory_resolver::Resolver::builder_tokio()
        .context("failed to create DNS resolver")?
        .build();

    let name = format!("_atproto.{}.", handle);
    let lookup = resolver
        .txt_lookup(&name)
        .await
        .context("DNS TXT lookup failed")?;

    for record in lookup {
        let txt = record.to_string();
        if let Some(did_str) = txt.strip_prefix("did=") {
            return Did::try_from(did_str).context("DNS TXT record contains invalid DID");
        }
    }

    anyhow::bail!("no _atproto DNS TXT record found")
}

/// Parse input as a DID or handle. If it's a handle, resolve to DID.
pub async fn resolve_to_did(input: &str) -> Result<Did> {
    if input.starts_with("did:") {
        return Did::try_from(input).context("invalid DID");
    }
    let handle = Handle::try_from(input).context("invalid handle")?;
    resolve_handle(&handle).await
}

pub async fn run(args: Args) -> Result<()> {
    let did = resolve_to_did(&args.handle_or_did).await?;

    if args.did_only {
        println!("{did}");
        return Ok(());
    }

    let dir = Directory::new();
    let identity = dir
        .lookup_did(&did)
        .await
        .context("failed to resolve DID")?;

    let handle_str = identity.handle.as_ref().map(|h| h.to_string());
    let pds_str = identity.pds_endpoint().map(|s| s.to_string());
    let signing_str = identity.signing_key().map(|k| k.did_key());

    let output = Output {
        did: identity.did.to_string(),
        handle: handle_str,
        pds: pds_str,
        signing_key: signing_str,
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("did:     {}", output.did);
        if let Some(ref h) = output.handle {
            println!("handle:  {h}");
        }
        if let Some(ref p) = output.pds {
            println!("pds:     {p}");
        }
        if let Some(ref k) = output.signing_key {
            println!("signing: {k}");
        }
    }

    Ok(())
}
