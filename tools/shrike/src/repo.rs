use std::collections::HashMap;
use std::fs::File;
use std::io::BufReader;

use anyhow::{Context, Result};
use serde::Serialize;
use shrike::api::com::atproto::{SyncGetRepoParams, sync_get_repo};
use shrike::cbor::{Cid, Value};
use shrike::repo::Commit;
use shrike::xrpc::Client;

#[derive(clap::Subcommand)]
pub enum Command {
    /// Download a repository as a CAR file
    Export(ExportArgs),
    /// Inspect a local CAR file
    Inspect(InspectArgs),
    /// List records in a local CAR file
    Ls(LsArgs),
}

#[derive(clap::Args)]
pub struct ExportArgs {
    /// DID or handle of the repo to export
    pub did_or_handle: String,
    /// Output file path (default: <did>.car)
    #[arg(short, long)]
    pub output: Option<String>,
}

#[derive(clap::Args)]
pub struct InspectArgs {
    /// Path to CAR file
    pub car_file: String,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct LsArgs {
    /// Path to CAR file
    pub car_file: String,
    /// Filter by collection NSID
    pub collection: Option<String>,
    /// Output as JSON
    #[arg(long)]
    pub json: bool,
}

pub async fn run(cmd: Command) -> Result<()> {
    match cmd {
        Command::Export(args) => export(args).await,
        Command::Inspect(args) => inspect(args),
        Command::Ls(args) => ls(args),
    }
}

// ---------------------------------------------------------------------------
// Internal types
// ---------------------------------------------------------------------------

struct CarData {
    root_cid: Cid,
    commit: Commit,
    block_map: HashMap<String, Vec<u8>>,
}

struct MstEntry {
    key: String,
    value_cid: Cid,
}

// ---------------------------------------------------------------------------
// CAR reading
// ---------------------------------------------------------------------------

fn read_car(path: &str) -> Result<CarData> {
    let file = File::open(path).with_context(|| format!("failed to open CAR file: {path}"))?;
    let reader = BufReader::new(file);

    let (roots, blocks) =
        shrike::car::read_all(reader).with_context(|| "failed to read CAR file")?;

    let root_cid = roots.first().copied().context("CAR file has no root CID")?;

    // Build block lookup map keyed by CID string.
    let mut block_map = HashMap::with_capacity(blocks.len());
    for block in &blocks {
        block_map.insert(block.cid.to_string(), block.data.clone());
    }

    // Decode the root block as a commit.
    let root_data = block_map
        .get(&root_cid.to_string())
        .context("root CID block not found in CAR")?;

    let commit =
        Commit::from_cbor(root_data).with_context(|| "failed to decode commit from root block")?;

    Ok(CarData {
        root_cid,
        commit,
        block_map,
    })
}

// ---------------------------------------------------------------------------
// MST walking
// ---------------------------------------------------------------------------

fn collect_mst_entries(
    block_map: &HashMap<String, Vec<u8>>,
    root_cid: Cid,
) -> Result<Vec<MstEntry>> {
    let mut entries = Vec::new();
    walk_mst_node(block_map, root_cid, &mut entries, 0)?;
    Ok(entries)
}

/// Maximum MST recursion depth to prevent stack overflow on malformed data.
const MAX_MST_DEPTH: u32 = 128;

fn walk_mst_node(
    block_map: &HashMap<String, Vec<u8>>,
    cid: Cid,
    out: &mut Vec<MstEntry>,
    depth: u32,
) -> Result<()> {
    if depth > MAX_MST_DEPTH {
        anyhow::bail!("MST exceeds maximum depth of {MAX_MST_DEPTH}");
    }

    let data = block_map
        .get(&cid.to_string())
        .with_context(|| format!("MST node block not found: {cid}"))?;

    let value =
        shrike::cbor::decode(data).with_context(|| format!("failed to decode MST node: {cid}"))?;

    let map_entries = match value {
        Value::Map(entries) => entries,
        _ => anyhow::bail!("MST node is not a CBOR map: {cid}"),
    };

    // Extract "l" (left subtree) and "e" (entries array) from the map.
    let mut left_cid: Option<Cid> = None;
    let mut node_entries: Vec<MstNodeEntry> = Vec::new();

    for (key, val) in map_entries {
        match key {
            "l" => match val {
                Value::Cid(c) => left_cid = Some(c),
                Value::Null => {}
                _ => anyhow::bail!("MST node 'l' field is not a CID or null"),
            },
            "e" => {
                let items = match val {
                    Value::Array(items) => items,
                    _ => anyhow::bail!("MST node 'e' field is not an array"),
                };
                for item in items {
                    node_entries.push(parse_mst_entry(item)?);
                }
            }
            _ => {} // ignore unknown fields
        }
    }

    // Walk in-order: left subtree first.
    if let Some(l) = left_cid {
        walk_mst_node(block_map, l, out, depth + 1)?;
    }

    // Process entries, reconstructing full keys from prefix compression.
    let mut prev_key = String::new();
    for entry in node_entries {
        let prefix_len = entry.prefix_len as usize;
        if prefix_len > prev_key.len() {
            anyhow::bail!(
                "MST entry prefix length ({prefix_len}) exceeds previous key length ({})",
                prev_key.len()
            );
        }

        let mut full_key = String::with_capacity(prefix_len + entry.key_suffix.len());
        full_key.push_str(&prev_key[..prefix_len]);
        full_key.push_str(&entry.key_suffix);

        prev_key.clone_from(&full_key);

        out.push(MstEntry {
            key: full_key,
            value_cid: entry.value_cid,
        });

        // Walk right subtree if present.
        if let Some(t) = entry.tree_cid {
            walk_mst_node(block_map, t, out, depth + 1)?;
        }
    }

    Ok(())
}

struct MstNodeEntry {
    key_suffix: String,
    prefix_len: u64,
    value_cid: Cid,
    tree_cid: Option<Cid>,
}

fn parse_mst_entry(value: Value<'_>) -> Result<MstNodeEntry> {
    let fields = match value {
        Value::Map(entries) => entries,
        _ => anyhow::bail!("MST entry is not a CBOR map"),
    };

    let mut key_suffix: Option<String> = None;
    let mut prefix_len: Option<u64> = None;
    let mut value_cid: Option<Cid> = None;
    let mut tree_cid: Option<Cid> = None;

    for (key, val) in fields {
        match key {
            "k" => {
                let bytes = match val {
                    Value::Bytes(b) => b,
                    _ => anyhow::bail!("MST entry 'k' field is not bytes"),
                };
                key_suffix = Some(
                    String::from_utf8(bytes.to_vec())
                        .context("MST entry 'k' is not valid UTF-8")?,
                );
            }
            "p" => {
                prefix_len = Some(match val {
                    Value::Unsigned(n) => n,
                    _ => anyhow::bail!("MST entry 'p' field is not an unsigned integer"),
                });
            }
            "v" => {
                value_cid = Some(match val {
                    Value::Cid(c) => c,
                    _ => anyhow::bail!("MST entry 'v' field is not a CID"),
                });
            }
            "t" => match val {
                Value::Cid(c) => tree_cid = Some(c),
                Value::Null => {}
                _ => anyhow::bail!("MST entry 't' field is not a CID or null"),
            },
            _ => {} // ignore unknown fields
        }
    }

    Ok(MstNodeEntry {
        key_suffix: key_suffix.context("MST entry missing 'k' field")?,
        prefix_len: prefix_len.context("MST entry missing 'p' field")?,
        value_cid: value_cid.context("MST entry missing 'v' field")?,
        tree_cid,
    })
}

// ---------------------------------------------------------------------------
// Subcommands
// ---------------------------------------------------------------------------

fn inspect(args: InspectArgs) -> Result<()> {
    let car = read_car(&args.car_file)?;
    let entries = collect_mst_entries(&car.block_map, car.commit.data)?;

    // Group by collection (the part before the '/' in each key).
    let mut collections: HashMap<String, u64> = HashMap::new();
    for entry in &entries {
        if let Some(slash_pos) = entry.key.find('/') {
            let collection = &entry.key[..slash_pos];
            *collections.entry(collection.to_string()).or_insert(0) += 1;
        }
    }

    if args.json {
        let output = InspectJson {
            did: car.commit.did.to_string(),
            revision: car.root_cid.to_string(),
            version: car.commit.version,
            records: entries.len() as u64,
            collections: &collections,
        };
        let json =
            serde_json::to_string_pretty(&output).context("failed to serialize inspect output")?;
        println!("{json}");
    } else {
        println!("did:         {}", car.commit.did);
        println!("revision:    {}", car.root_cid);
        println!("version:     {}", car.commit.version);
        println!("records:     {}", entries.len());
        println!("collections:");

        // Sort collections alphabetically for stable output.
        let mut sorted: Vec<_> = collections.iter().collect();
        sorted.sort_by_key(|(name, _)| (*name).clone());
        for (name, count) in sorted {
            println!("  {name}: {count}");
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct InspectJson<'a> {
    did: String,
    revision: String,
    version: u32,
    records: u64,
    collections: &'a HashMap<String, u64>,
}

fn ls(args: LsArgs) -> Result<()> {
    let car = read_car(&args.car_file)?;
    let entries = collect_mst_entries(&car.block_map, car.commit.data)?;

    // Optionally filter by collection.
    let filtered: Vec<&MstEntry> = if let Some(ref col) = args.collection {
        let prefix = format!("{col}/");
        entries
            .iter()
            .filter(|e| e.key.starts_with(&prefix))
            .collect()
    } else {
        entries.iter().collect()
    };

    if args.json {
        let records: Vec<LsJsonRecord> = filtered
            .iter()
            .map(|e| LsJsonRecord {
                key: &e.key,
                cid: e.value_cid.to_string(),
            })
            .collect();
        let json =
            serde_json::to_string_pretty(&records).context("failed to serialize ls output")?;
        println!("{json}");
    } else {
        for entry in &filtered {
            println!("{}  {}", entry.key, entry.value_cid);
        }
    }

    Ok(())
}

#[derive(Serialize)]
struct LsJsonRecord<'a> {
    key: &'a str,
    cid: String,
}

async fn export(args: ExportArgs) -> Result<()> {
    let did = crate::resolve::resolve_to_did(&args.did_or_handle).await?;

    // Resolve the target DID to find their PDS endpoint.
    // sync.getRepo must be sent to the user's actual PDS, not
    // our session host (which may be a different server).
    let dir = shrike::identity::Directory::new();
    let identity = dir
        .lookup_did(&did)
        .await
        .context("failed to resolve DID")?;
    let pds = identity
        .pds_endpoint()
        .context("DID document has no PDS endpoint")?;

    // sync.getRepo doesn't require authentication — use an
    // unauthenticated client pointed at the target's PDS.
    let client = Client::new(pds);

    let params = SyncGetRepoParams {
        did: did.to_string(),
        since: None,
    };
    let car_bytes = sync_get_repo(&client, &params)
        .await
        .context("failed to download repository")?;

    let output_path = args.output.unwrap_or_else(|| format!("{did}.car"));
    std::fs::write(&output_path, &car_bytes)
        .with_context(|| format!("failed to write {output_path}"))?;

    let size_mb = car_bytes.len() as f64 / (1024.0 * 1024.0);
    println!("exported {did} to {output_path} ({size_mb:.1} MB)");
    Ok(())
}
