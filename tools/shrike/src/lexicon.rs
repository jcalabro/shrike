use anyhow::{Context, Result};
use shrike::lexicon::resolver::LexiconResolver;
use shrike::syntax::{Did, Nsid};

#[derive(clap::Subcommand)]
pub enum Command {
    /// Resolve and verify a published Lexicon by NSID
    Resolve(ResolveArgs),
}

#[derive(clap::Args)]
pub struct ResolveArgs {
    /// NSID to resolve (e.g. app.bsky.feed.post)
    pub nsid: String,
    /// Fetch from this DID instead of resolving the `_lexicon` DNS authority
    #[arg(long)]
    pub did: Option<String>,
    /// Print only the Lexicon document JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Resolve(args) => resolve(args).await,
    }
}

async fn resolve(args: ResolveArgs) -> Result<()> {
    let nsid = Nsid::try_from(args.nsid.as_str()).context("invalid NSID")?;
    let resolver = LexiconResolver::new();
    let lexicon = match args.did {
        Some(did) => {
            let did = Did::try_from(did.as_str()).context("invalid DID")?;
            resolver.fetch(&did, &nsid).await
        }
        None => resolver.get(&nsid).await,
    }
    .with_context(|| format!("failed to resolve Lexicon for {nsid}"))?;

    if !args.json {
        println!("uri: {}", lexicon.uri);
        println!("cid: {}", lexicon.cid);
    }
    println!("{}", serde_json::to_string_pretty(&lexicon.json)?);
    Ok(())
}
