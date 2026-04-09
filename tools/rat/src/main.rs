use anyhow::Result;
use clap::{Parser, Subcommand};

mod account;
mod key;
mod plc;
mod record;
mod repo;
mod resolve;
mod session;
mod subscribe;
mod syntax;
mod validate;

#[derive(Parser)]
#[command(name = "rat", about = "AT Protocol CLI tool", version)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Validate AT Protocol syntax types
    Syntax(syntax::Args),

    /// Generate or inspect cryptographic keys
    #[command(subcommand)]
    Key(key::Command),

    /// Resolve a handle or DID to its identity
    Resolve(resolve::Args),

    /// PLC directory operations
    #[command(subcommand)]
    Plc(plc::Command),

    /// Repository operations
    #[command(subcommand)]
    Repo(repo::Command),

    /// Validate a JSON record against a Lexicon schema
    Validate(validate::Args),

    /// Fetch or list records
    #[command(subcommand)]
    Record(record::Command),

    /// Account login, logout, and status
    #[command(subcommand)]
    Account(account::Command),

    /// Stream live events from the network
    Subscribe(subscribe::Args),
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Syntax(args) => syntax::run(args),
        Command::Key(cmd) => key::run(cmd),
        Command::Resolve(args) => resolve::run(args).await,
        Command::Plc(cmd) => plc::run(cmd).await,
        Command::Repo(cmd) => repo::run(cmd).await,
        Command::Validate(args) => validate::run(args),
        Command::Record(cmd) => record::run(cmd).await,
        Command::Account(cmd) => account::run(cmd).await,
        Command::Subscribe(args) => subscribe::run(args).await,
    }
}
