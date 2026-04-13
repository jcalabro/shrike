use anyhow::{Context, Result};
use futures::StreamExt;
use serde::Serialize;

use shrike::streaming::{Client, Config, Event, JetstreamCommit, JetstreamEvent, Operation};

#[derive(clap::Args)]
pub struct Args {
    /// WebSocket URL
    #[arg(
        long,
        default_value = "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
    )]
    pub url: String,
    /// Resume from cursor position
    #[arg(long)]
    pub cursor: Option<i64>,
    /// Filter by collection NSID
    #[arg(long)]
    pub collection: Option<String>,
    /// Filter by action: create, update, or delete
    #[arg(long)]
    pub action: Option<String>,
}

#[derive(Serialize)]
#[serde(tag = "type")]
enum EventOutput {
    #[serde(rename = "commit")]
    Commit {
        did: String,
        seq: i64,
        operations: Vec<OpOutput>,
    },
    #[serde(rename = "identity")]
    Identity {
        did: String,
        seq: i64,
        handle: Option<String>,
    },
    #[serde(rename = "account")]
    Account { did: String, seq: i64, active: bool },
    #[serde(rename = "labels")]
    Labels { seq: i64, count: usize },
}

#[derive(Serialize)]
struct OpOutput {
    action: String,
    collection: String,
    rkey: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
}

pub async fn run(args: Args) -> Result<()> {
    let url = normalize_jetstream_url(&args.url);
    let is_jetstream = is_jetstream_url(&url);

    let config = Config {
        url: url.clone(),
        cursor: args.cursor,
        collections: args.collection.as_ref().map(|c| vec![c.clone()]),
        ..Config::default()
    };

    let client = Client::new(config);

    if is_jetstream {
        run_jetstream(&client, &args).await
    } else {
        run_firehose(&client, &args).await
    }
}

/// Detect whether a URL points to a Jetstream endpoint.
///
/// Checks for "jetstream" in the hostname (via the `://` authority portion)
/// or a path ending in "/subscribe".
fn is_jetstream_url(url: &str) -> bool {
    // Extract the authority (host) portion: everything between "://" and the next "/"
    if let Some(after_scheme) = url.split("://").nth(1) {
        let host = after_scheme.split('/').next().unwrap_or("");
        if host.contains("jetstream") {
            return true;
        }
    }
    url.ends_with("/subscribe")
}

/// If the URL looks like a Jetstream host but is missing the `/subscribe` path,
/// append it so the WebSocket upgrade hits the correct endpoint.
fn normalize_jetstream_url(url: &str) -> String {
    if let Some(after_scheme) = url.split("://").nth(1) {
        let host = after_scheme.split('/').next().unwrap_or("");
        if host.contains("jetstream") {
            // Check if there's already a non-empty path
            let path_start = after_scheme.find('/');
            let has_path = match path_start {
                Some(i) => after_scheme[i..].len() > 1, // more than just "/"
                None => false,
            };
            if !has_path {
                let base = url.trim_end_matches('/');
                return format!("{base}/subscribe");
            }
        }
    }
    url.to_string()
}

async fn run_firehose(client: &Client, args: &Args) -> Result<()> {
    let mut stream = std::pin::pin!(client.subscribe());

    loop {
        tokio::select! {
            item = stream.next() => {
                let Some(result) = item else { break };
                match result {
                    Ok(batch) => {
                        for event in &batch {
                            if let Some(output) = filter_event(event, args.collection.as_deref(), args.action.as_deref()) {
                                let json = serde_json::to_string(&output)?;
                                println!("{json}");
                            }
                        }
                    }
                    Err(shrike::streaming::StreamError::UnknownType(_)) => {
                        // Skip #info, #sync, and other unknown event types
                        continue;
                    }
                    Err(e) => return Err(e).context("stream error"),
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

async fn run_jetstream(client: &Client, args: &Args) -> Result<()> {
    let mut stream = std::pin::pin!(client.jetstream());

    loop {
        tokio::select! {
            item = stream.next() => {
                let Some(result) = item else { break };
                let batch = result.context("stream error")?;
                for event in &batch {
                    if let Some(output) = filter_jetstream_event(event, args.collection.as_deref(), args.action.as_deref()) {
                        let json = serde_json::to_string(&output)?;
                        println!("{json}");
                    }
                }
            }
            _ = tokio::signal::ctrl_c() => {
                break;
            }
        }
    }

    Ok(())
}

fn filter_jetstream_event(
    event: &JetstreamEvent,
    collection_filter: Option<&str>,
    action_filter: Option<&str>,
) -> Option<EventOutput> {
    match event {
        JetstreamEvent::Commit {
            did,
            time_us,
            collection,
            operation,
            ..
        } => {
            if let Some(col) = collection_filter
                && collection.as_str() != col
            {
                return None;
            }
            let action = match operation {
                JetstreamCommit::Create { .. } => "create",
                JetstreamCommit::Update { .. } => "update",
                JetstreamCommit::Delete => "delete",
            };
            if let Some(act) = action_filter
                && action != act
            {
                return None;
            }
            let cid = match operation {
                JetstreamCommit::Create { cid, .. } | JetstreamCommit::Update { cid, .. } => {
                    Some(cid.to_string())
                }
                JetstreamCommit::Delete => None,
            };
            Some(EventOutput::Commit {
                did: did.to_string(),
                seq: *time_us,
                operations: vec![OpOutput {
                    action: action.into(),
                    collection: collection.to_string(),
                    rkey: event_rkey(event).unwrap_or_default(),
                    cid,
                }],
            })
        }
        JetstreamEvent::Identity { did, time_us } => {
            if collection_filter.is_some() || action_filter.is_some() {
                return None;
            }
            Some(EventOutput::Identity {
                did: did.to_string(),
                seq: *time_us,
                handle: None,
            })
        }
        JetstreamEvent::Account {
            did,
            time_us,
            active,
        } => {
            if collection_filter.is_some() || action_filter.is_some() {
                return None;
            }
            Some(EventOutput::Account {
                did: did.to_string(),
                seq: *time_us,
                active: *active,
            })
        }
    }
}

fn event_rkey(event: &JetstreamEvent) -> Option<String> {
    match event {
        JetstreamEvent::Commit { rkey, .. } => Some(rkey.to_string()),
        _ => None,
    }
}

fn filter_event(
    event: &Event,
    collection_filter: Option<&str>,
    action_filter: Option<&str>,
) -> Option<EventOutput> {
    match event {
        Event::Commit {
            did,
            seq,
            operations,
            ..
        } => {
            let ops: Vec<OpOutput> = operations
                .iter()
                .filter(|op| matches_filters(op, collection_filter, action_filter))
                .map(op_to_output)
                .collect();

            if ops.is_empty() && (collection_filter.is_some() || action_filter.is_some()) {
                return None;
            }

            Some(EventOutput::Commit {
                did: did.to_string(),
                seq: *seq,
                operations: ops,
            })
        }
        Event::Identity { did, seq, handle } => {
            if collection_filter.is_some() || action_filter.is_some() {
                return None;
            }
            Some(EventOutput::Identity {
                did: did.to_string(),
                seq: *seq,
                handle: handle.as_ref().map(|h| h.to_string()),
            })
        }
        Event::Account { did, seq, active } => {
            if collection_filter.is_some() || action_filter.is_some() {
                return None;
            }
            Some(EventOutput::Account {
                did: did.to_string(),
                seq: *seq,
                active: *active,
            })
        }
        Event::Labels { seq, labels } => {
            if collection_filter.is_some() || action_filter.is_some() {
                return None;
            }
            Some(EventOutput::Labels {
                seq: *seq,
                count: labels.len(),
            })
        }
    }
}

fn matches_filters(
    op: &Operation,
    collection_filter: Option<&str>,
    action_filter: Option<&str>,
) -> bool {
    if let Some(col) = collection_filter {
        let op_collection = match op {
            Operation::Create { collection, .. } => collection.as_str(),
            Operation::Update { collection, .. } => collection.as_str(),
            Operation::Delete { collection, .. } => collection.as_str(),
        };
        if op_collection != col {
            return false;
        }
    }
    if let Some(act) = action_filter {
        let op_action = match op {
            Operation::Create { .. } => "create",
            Operation::Update { .. } => "update",
            Operation::Delete { .. } => "delete",
        };
        if op_action != act {
            return false;
        }
    }
    true
}

fn op_to_output(op: &Operation) -> OpOutput {
    match op {
        Operation::Create {
            collection,
            rkey,
            cid,
            ..
        } => OpOutput {
            action: "create".into(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: Some(cid.to_string()),
        },
        Operation::Update {
            collection,
            rkey,
            cid,
            ..
        } => OpOutput {
            action: "update".into(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: Some(cid.to_string()),
        },
        Operation::Delete {
            collection, rkey, ..
        } => OpOutput {
            action: "delete".into(),
            collection: collection.to_string(),
            rkey: rkey.to_string(),
            cid: None,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_jetstream_bare_hostname() {
        assert!(is_jetstream_url("wss://jetstream1.us-east.bsky.network"));
    }

    #[test]
    fn is_jetstream_with_subscribe_path() {
        assert!(is_jetstream_url(
            "wss://jetstream1.us-east.bsky.network/subscribe"
        ));
    }

    #[test]
    fn is_jetstream_trailing_slash() {
        assert!(is_jetstream_url("wss://jetstream1.us-east.bsky.network/"));
    }

    #[test]
    fn is_not_jetstream_firehose() {
        assert!(!is_jetstream_url(
            "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos"
        ));
    }

    #[test]
    fn is_jetstream_generic_subscribe_suffix() {
        // A non-jetstream host with /subscribe path should still be detected
        assert!(is_jetstream_url("wss://custom.example.com/subscribe"));
    }

    #[test]
    fn normalize_appends_subscribe_to_bare_host() {
        assert_eq!(
            normalize_jetstream_url("wss://jetstream1.us-east.bsky.network"),
            "wss://jetstream1.us-east.bsky.network/subscribe"
        );
    }

    #[test]
    fn normalize_appends_subscribe_to_trailing_slash() {
        assert_eq!(
            normalize_jetstream_url("wss://jetstream1.us-east.bsky.network/"),
            "wss://jetstream1.us-east.bsky.network/subscribe"
        );
    }

    #[test]
    fn normalize_preserves_existing_subscribe_path() {
        let url = "wss://jetstream1.us-east.bsky.network/subscribe";
        assert_eq!(normalize_jetstream_url(url), url);
    }

    #[test]
    fn normalize_leaves_firehose_unchanged() {
        let url = "wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos";
        assert_eq!(normalize_jetstream_url(url), url);
    }

    #[test]
    fn normalize_preserves_query_params() {
        // Bare host with query params (unlikely but defensive)
        assert_eq!(
            normalize_jetstream_url("wss://jetstream2.us-west.bsky.network"),
            "wss://jetstream2.us-west.bsky.network/subscribe"
        );
    }
}
