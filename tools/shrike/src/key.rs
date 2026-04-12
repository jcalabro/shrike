use anyhow::{Context, Result, bail};
use shrike_crypto::{K256SigningKey, P256SigningKey, SigningKey, VerifyingKey, parse_did_key};
use serde::Serialize;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Generate a new signing key pair
    Generate(GenerateArgs),
    /// Inspect a did:key or multibase public key
    Inspect(InspectArgs),
}

#[derive(clap::Args)]
pub struct GenerateArgs {
    /// Key type: p256 or k256
    #[arg(long, default_value = "p256")]
    pub r#type: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// did:key or multibase-encoded public key
    pub key: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct KeyOutput {
    r#type: String,
    did_key: String,
    multibase: String,
    public_hex: String,
}

pub fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Generate(args) => generate(args),
        Command::Inspect(args) => inspect(args),
    }
}

fn generate(args: GenerateArgs) -> Result<()> {
    let output = match args.r#type.as_str() {
        "p256" => {
            let sk = P256SigningKey::generate();
            key_output("P-256", sk.public_key())
        }
        "k256" => {
            let sk = K256SigningKey::generate();
            key_output("K-256", sk.public_key())
        }
        other => bail!("unknown key type '{other}': expected p256 or k256"),
    };
    print_key_output(&output, args.json)
}

fn inspect(args: InspectArgs) -> Result<()> {
    let did_key_str = if args.key.starts_with("did:key:") {
        args.key.clone()
    } else if args.key.starts_with('z') {
        format!("did:key:{}", args.key)
    } else {
        bail!("expected a did:key (did:key:z...) or multibase (z...) encoded public key");
    };
    let pk = parse_did_key(&did_key_str).context("failed to parse key")?;
    let type_name = if did_key_str.starts_with("did:key:zDn") {
        "P-256"
    } else {
        "K-256"
    };
    let output = key_output(type_name, pk.as_ref());
    print_key_output(&output, args.json)
}

fn key_output(type_name: &str, pk: &dyn VerifyingKey) -> KeyOutput {
    let bytes = pk.to_bytes();
    KeyOutput {
        r#type: type_name.to_string(),
        did_key: pk.did_key(),
        multibase: pk.multibase(),
        public_hex: bytes.iter().map(|b| format!("{b:02x}")).collect(),
    }
}

fn print_key_output(output: &KeyOutput, json: bool) -> Result<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(output)?);
    } else {
        println!("type:      {}", output.r#type);
        println!("did:key:   {}", output.did_key);
        println!("multibase: {}", output.multibase);
        println!("public:    {}", output.public_hex);
    }
    Ok(())
}
