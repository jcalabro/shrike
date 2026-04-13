use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::Serialize;
use shrike::lexicon::{Catalog, validate_record};

#[derive(clap::Args)]
pub struct Args {
    /// Collection NSID (e.g. app.bsky.feed.post)
    pub collection: String,
    /// Path to JSON record file
    pub json_file: String,
    /// Path to lexicon directory
    #[arg(long)]
    pub lexdir: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub fn run(args: Args) -> Result<()> {
    let lexdir = find_lexdir(args.lexdir.as_deref())?;
    let catalog = load_catalog(&lexdir)?;

    let record_data = fs::read_to_string(&args.json_file)
        .with_context(|| format!("could not read {}", args.json_file))?;
    let record: serde_json::Value =
        serde_json::from_str(&record_data).context("invalid JSON in record file")?;

    let result = validate_record(&catalog, &args.collection, &record);

    #[derive(Serialize)]
    struct Output {
        collection: String,
        valid: bool,
        error: Option<String>,
    }

    let output = match result {
        Ok(()) => Output {
            collection: args.collection,
            valid: true,
            error: None,
        },
        Err(e) => Output {
            collection: args.collection,
            valid: false,
            error: Some(e.to_string()),
        },
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&output)?);
    } else if output.valid {
        println!("valid");
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

fn find_lexdir(explicit: Option<&str>) -> Result<String> {
    if let Some(dir) = explicit {
        return Ok(dir.to_string());
    }
    let candidates = ["./lexicons", "../atmos/lexicons"];
    for candidate in &candidates {
        if Path::new(candidate).is_dir() {
            return Ok(candidate.to_string());
        }
    }
    anyhow::bail!(
        "could not find lexicon directory; tried ./lexicons and ../atmos/lexicons. \
         Use --lexdir to specify the path"
    )
}

fn load_catalog(lexdir: &str) -> Result<Catalog> {
    let mut catalog = Catalog::new();
    load_dir_recursive(&mut catalog, Path::new(lexdir))?;
    Ok(catalog)
}

fn load_dir_recursive(catalog: &mut Catalog, dir: &Path) -> Result<()> {
    let entries =
        fs::read_dir(dir).with_context(|| format!("could not read directory {}", dir.display()))?;
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        if path.is_dir() {
            load_dir_recursive(catalog, &path)?;
        } else if path.extension().is_some_and(|e| e == "json") {
            let data =
                fs::read(&path).with_context(|| format!("could not read {}", path.display()))?;
            if let Err(e) = catalog.add_schema(&data) {
                eprintln!("warning: skipping {}: {e}", path.display());
            }
        }
    }
    Ok(())
}
