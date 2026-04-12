use anyhow::Result;
use serde::Serialize;

use shrike_syntax::{AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid};

#[derive(clap::Args)]
pub struct Args {
    /// Type to validate: did, handle, nsid, at-uri, tid, record-key, rkey, datetime, language
    pub r#type: String,
    /// Value to validate
    pub value: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Serialize)]
struct Output {
    r#type: String,
    input: String,
    valid: bool,
    normalized: Option<String>,
    error: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let result = validate(&args.r#type, &args.value);

    let output = match result {
        Ok(normalized) => Output {
            r#type: args.r#type.clone(),
            input: args.value.clone(),
            valid: true,
            normalized: if normalized != args.value {
                Some(normalized)
            } else {
                None
            },
            error: None,
        },
        Err(e) => Output {
            r#type: args.r#type.clone(),
            input: args.value.clone(),
            valid: false,
            normalized: None,
            error: Some(e.to_string()),
        },
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if output.valid {
        println!("valid");
        if let Some(ref norm) = output.normalized {
            println!("  normalized: {norm}");
        }
    } else {
        println!("invalid");
        if let Some(ref err) = output.error {
            println!("  error: {err}");
        }
    }

    if !output.valid {
        std::process::exit(1);
    }

    Ok(())
}

fn validate(typ: &str, value: &str) -> Result<String, Box<dyn std::error::Error>> {
    match typ {
        "did" => Ok(Did::try_from(value)?.to_string()),
        "handle" => Ok(Handle::try_from(value)?.to_string()),
        "nsid" => Ok(Nsid::try_from(value)?.to_string()),
        "at-uri" => Ok(AtUri::try_from(value)?.to_string()),
        "tid" => Ok(Tid::try_from(value)?.to_string()),
        "record-key" | "rkey" => Ok(RecordKey::try_from(value)?.to_string()),
        "datetime" => Ok(Datetime::try_from(value)?.to_string()),
        "language" => Ok(Language::try_from(value)?.to_string()),
        _ => Err(format!(
            "unknown type '{typ}': expected one of did, handle, nsid, at-uri, tid, record-key, rkey, datetime, language"
        )
        .into()),
    }
}
