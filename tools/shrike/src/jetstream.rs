//! `shrike jetstream` — stream events through the Jetstream v2 client.
//!
//! This drives [`shrike::jetstream::Engine`], the sealed-archive-plus-live client,
//! rather than the legacy line-delimited `streaming` module. Three modes fall out
//! of the flags:
//!
//! - **Live tail** (default): pure live from the current tip, no archive.
//! - **Replay + cutover** (`--after-seq N`): replay the sealed archive from the
//!   exclusive sequence `N`, then cut over to the live tail.
//! - **Snapshot** (`--snapshot-only`): replay the sealed archive and stop; pair
//!   with `--before-seq` to bound the upper end of the window.
//!
//! The archive is authenticated with a bearer key read only from the
//! `JETSTREAM_API_KEY` environment variable — never a flag, so it stays out of
//! shell history and process listings. The live tail needs no key.

use anyhow::{Context, Result, bail};

use shrike::jetstream::{
    ApiKey, ArchiveClient, ArchiveConfig, Batch, CancelToken, ClientArchive, Delivery, Engine,
    EngineConfig, EngineSink, Event, EventPayload, Filter, HttpDictionarySource, Info, Kind,
    LiveConfig, NativeHttpTransport, NativeWsTransport, Operation, StatsHandle,
};

#[derive(clap::Args)]
pub struct Args {
    /// Jetstream host, without a scheme (e.g. jetstream.us-east.bsky.network).
    #[arg(long, default_value = "jetstream.us-east.bsky.network")]
    pub host: String,

    /// Use ws:// and http:// instead of wss:// and https:// (loopback testing).
    #[arg(long)]
    pub insecure: bool,

    /// Host for sealed-archive replay, if different from --host.
    #[arg(long)]
    pub archive_host: Option<String>,

    /// Filter by collection NSID or `namespace.*` prefix (repeatable).
    #[arg(long = "collection")]
    pub collections: Vec<String>,

    /// Filter by repo DID (repeatable).
    #[arg(long = "did")]
    pub dids: Vec<String>,

    /// Filter by event kind: commit, identity, account, or sync (repeatable).
    #[arg(long = "kind")]
    pub kinds: Vec<String>,

    /// Replay the sealed archive from this exclusive sequence, then cut over to
    /// the live tail. Requires JETSTREAM_API_KEY.
    #[arg(long)]
    pub after_seq: Option<u64>,

    /// Upper (inclusive) archive bound. Only valid with --snapshot-only.
    #[arg(long)]
    pub before_seq: Option<u64>,

    /// Replay the sealed archive and stop; never tail live. Requires
    /// JETSTREAM_API_KEY.
    #[arg(long)]
    pub snapshot_only: bool,

    /// Disable zstd decompression of live frames.
    #[arg(long)]
    pub no_compression: bool,

    /// Emit newline-delimited JSON instead of human-readable lines.
    #[arg(long)]
    pub json: bool,

    /// Print periodic progress stats instead of individual events.
    #[arg(long)]
    pub stats: bool,
}

pub async fn run(args: Args) -> Result<()> {
    let secure = !args.insecure;
    let filter = build_filter(&args)?;

    let mut live = LiveConfig::new(&args.host, secure);
    live.filter = filter;
    live.compression = !args.no_compression;
    let read_limit = live.read_limit;

    let mut config = EngineConfig::new(live);
    config.after_seq = args.after_seq.unwrap_or(0);
    config.before_seq = args.before_seq;
    config.snapshot_only = args.snapshot_only;

    let needs_archive = args.after_seq.is_some() || args.snapshot_only || args.before_seq.is_some();

    let cancel = CancelToken::new();
    let archive = if needs_archive {
        Some(build_archive(&args, secure)?)
    } else {
        None
    };

    let dict_transport = NativeHttpTransport::new().context("failed to build HTTP transport")?;
    let dict = HttpDictionarySource::new(dict_transport, args.host.clone(), secure, cancel.clone());
    let ws = NativeWsTransport::new(read_limit);

    let engine = Engine::new(archive, ws, dict, config, cancel.clone());
    let stats = engine.stats();

    // Ctrl-C requests a clean stop: the engine finishes the batch in flight and
    // returns Ok(()), so a persisted cursor stays consistent.
    let cancel_on_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_on_signal.cancel();
        }
    });

    let output = if args.stats {
        Output::Stats { json: args.json }
    } else {
        Output::Events { json: args.json }
    };
    let mut sink = CliSink {
        output,
        stats: stats.clone(),
    };

    engine
        .run(&mut sink)
        .await
        .context("jetstream engine failed")?;

    // A final snapshot so a stats run always ends with the totals, even if the
    // last batch did not trigger a periodic print.
    if args.stats {
        emit_stats(&stats, args.json);
    }
    Ok(())
}

/// Build the archive source, reading the bearer key from the environment.
fn build_archive(args: &Args, secure: bool) -> Result<ClientArchive<NativeHttpTransport>> {
    let key = ApiKey::new(std::env::var("JETSTREAM_API_KEY").unwrap_or_default());
    if key.is_empty() {
        bail!("archive replay requires the JETSTREAM_API_KEY environment variable");
    }
    let host = args
        .archive_host
        .clone()
        .unwrap_or_else(|| args.host.clone());
    let mut archive_config = ArchiveConfig::new(host, key);
    archive_config.secure = secure;
    let transport = NativeHttpTransport::new().context("failed to build HTTP transport")?;
    let client =
        ArchiveClient::new(transport, archive_config).context("invalid archive configuration")?;
    Ok(ClientArchive::new(client))
}

/// Assemble the event filter from the repeatable `--kind`/`--did`/`--collection`
/// flags. An empty filter matches everything.
fn build_filter(args: &Args) -> Result<Filter> {
    let mut filter = Filter::new();
    if !args.kinds.is_empty() {
        let mut kinds = Vec::with_capacity(args.kinds.len());
        for k in &args.kinds {
            let kind = Kind::from_wire(k).with_context(|| {
                format!("unknown event kind: {k} (expected commit, identity, account, or sync)")
            })?;
            kinds.push(kind);
        }
        filter = filter.kinds(kinds);
    }
    if !args.dids.is_empty() {
        filter = filter.dids(&args.dids).context("invalid --did filter")?;
    }
    if !args.collections.is_empty() {
        filter = filter
            .collections(&args.collections)
            .context("invalid --collection filter")?;
    }
    Ok(filter)
}

/// What the sink writes to stdout.
enum Output {
    /// One line per event (human or JSON).
    Events { json: bool },
    /// A progress snapshot after each batch (human or JSON).
    Stats { json: bool },
}

struct CliSink {
    output: Output,
    stats: StatsHandle,
}

impl EngineSink for CliSink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        match delivery {
            Delivery::Batch(batch) => match self.output {
                Output::Events { json } => emit_batch(&batch, json),
                Output::Stats { json } => emit_stats(&self.stats, json),
            },
            // Advisories go to stderr so stdout stays a clean event/stats stream.
            Delivery::Info(info) => emit_info(&info),
        }
        true
    }

    async fn recoverable(&mut self, error: shrike::jetstream::Error) -> bool {
        eprintln!("recoverable error: {error}");
        // Keep streaming: a recoverable error is delivered in order and the
        // engine continues after it.
        true
    }
}

fn emit_batch(batch: &Batch, json: bool) {
    for event in batch.events() {
        emit_event(event, json);
    }
}

fn emit_event(event: &Event, json: bool) {
    if json {
        match event_to_json(event) {
            Ok(value) => match serde_json::to_string(&value) {
                Ok(line) => println!("{line}"),
                Err(e) => eprintln!("failed to serialize event seq={}: {e}", event.seq),
            },
            Err(e) => eprintln!("failed to convert event seq={}: {e}", event.seq),
        }
    } else {
        println!("{}", event_human(event));
    }
}

fn event_to_json(event: &Event) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert("seq".into(), event.seq.into());
    obj.insert("did".into(), event.did.as_str().into());
    obj.insert("time_us".into(), event.time_us.into());
    obj.insert("kind".into(), event.kind().as_wire().into());
    match &event.payload {
        EventPayload::Commit(commit) => {
            obj.insert("operation".into(), operation_str(commit.operation).into());
            obj.insert("collection".into(), commit.collection.as_str().into());
            obj.insert("rkey".into(), commit.rkey.as_str().into());
            obj.insert("rev".into(), commit.rev.to_string().into());
            if let Some(record) = &commit.record {
                obj.insert("record".into(), record.to_json().context("record to_json")?);
            }
        }
        EventPayload::Identity(v) => {
            obj.insert(
                "identity".into(),
                serde_json::to_value(v).context("identity to_json")?,
            );
        }
        EventPayload::Account(v) => {
            obj.insert(
                "account".into(),
                serde_json::to_value(v).context("account to_json")?,
            );
        }
        EventPayload::Sync(v) => {
            obj.insert(
                "sync".into(),
                serde_json::to_value(v).context("sync to_json")?,
            );
        }
    }
    Ok(serde_json::Value::Object(obj))
}

fn event_human(event: &Event) -> String {
    let did = event.did.as_str();
    match &event.payload {
        EventPayload::Commit(c) => format!(
            "seq={} commit {} {}/{} did={}",
            event.seq,
            operation_str(c.operation),
            c.collection.as_str(),
            c.rkey.as_str(),
            did,
        ),
        EventPayload::Identity(_) => format!("seq={} identity did={did}", event.seq),
        EventPayload::Account(_) => format!("seq={} account did={did}", event.seq),
        EventPayload::Sync(_) => format!("seq={} sync did={did}", event.seq),
    }
}

fn operation_str(op: Operation) -> &'static str {
    match op {
        Operation::Create => "create",
        Operation::Update => "update",
        Operation::Delete => "delete",
    }
}

fn emit_stats(stats: &StatsHandle, json: bool) {
    let s = stats.snapshot();
    let downloads = stats.active_downloads();
    if json {
        let value = serde_json::json!({
            "pages": s.pages,
            "sealed_tip_seq": s.sealed_tip_seq,
            "planned_through_seq": s.planned_through_seq,
            "residual_gap": s.residual_gap,
            "delivered_events": s.delivered_events,
            "last_processed_seq": s.last_processed_seq,
            "active_downloads": downloads,
        });
        match serde_json::to_string(&value) {
            Ok(line) => println!("{line}"),
            Err(e) => eprintln!("failed to serialize stats: {e}"),
        }
    } else {
        println!(
            "pages={} tip={} planned={} gap={} delivered={} processed={} downloads={}",
            s.pages,
            s.sealed_tip_seq,
            s.planned_through_seq,
            s.residual_gap,
            s.delivered_events,
            s.last_processed_seq,
            downloads,
        );
    }
}

fn emit_info(info: &Info) {
    match &info.message {
        Some(m) => eprintln!("#info {} — {m}", info.name),
        None => eprintln!("#info {}", info.name),
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            host: "jetstream.us-east.bsky.network".into(),
            insecure: false,
            archive_host: None,
            collections: Vec::new(),
            dids: Vec::new(),
            kinds: Vec::new(),
            after_seq: None,
            before_seq: None,
            snapshot_only: false,
            no_compression: false,
            json: false,
            stats: false,
        }
    }

    #[test]
    fn empty_filter_is_accepted() {
        assert!(build_filter(&args()).is_ok());
    }

    #[test]
    fn valid_kinds_parse() {
        let a = Args {
            kinds: vec!["commit".into(), "identity".into()],
            ..args()
        };
        assert!(build_filter(&a).is_ok());
    }

    #[test]
    fn unknown_kind_is_rejected() {
        let a = Args {
            kinds: vec!["bogus".into()],
            ..args()
        };
        let err = build_filter(&a).expect_err("bogus kind must be rejected");
        assert!(err.to_string().contains("bogus"));
    }

    #[test]
    fn invalid_collection_is_rejected() {
        let a = Args {
            collections: vec!["not a valid nsid".into()],
            ..args()
        };
        assert!(build_filter(&a).is_err());
    }

    #[test]
    fn operation_str_covers_all_variants() {
        assert_eq!(operation_str(Operation::Create), "create");
        assert_eq!(operation_str(Operation::Update), "update");
        assert_eq!(operation_str(Operation::Delete), "delete");
    }
}
