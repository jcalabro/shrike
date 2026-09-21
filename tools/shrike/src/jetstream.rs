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

use std::io::{self, Write};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use shrike::jetstream::{
    ApiKey, ArchiveClient, ArchiveConfig, Batch, CancelToken, ClientArchive, Delivery, Engine,
    EngineConfig, EngineSink, Event, EventPayload, Filter, HttpDictionarySource, Info, Kind,
    LiveConfig, NativeHttpTransport, NativeWsTransport, Operation, StatsHandle,
};

#[derive(clap::Args)]
pub struct Args {
    /// Jetstream host, without a scheme (e.g. jetstream.us-east.bsky.network).
    /// Required: with no default, an accidental invocation cannot silently start
    /// a production full replay.
    #[arg(long)]
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

    /// Decode like records into FeedLike and report successes/errors in stats.
    #[arg(long, requires = "stats")]
    pub typed_likes: bool,

    /// Experimental scoped archive transform; decode before owning records.
    #[arg(long, requires_all = ["snapshot_only", "stats"])]
    pub scoped: bool,

    /// Native CPU workers per whole segment in scoped mode (1..=32).
    #[arg(long, requires = "scoped")]
    pub decode_workers: Option<std::num::NonZeroUsize>,

    /// Concurrent archive segments and block/stripe requests per segment.
    #[arg(long)]
    pub download_concurrency: Option<std::num::NonZeroUsize>,

    /// Fetch each whole archive segment in one stream instead of parallel ranges.
    #[arg(long)]
    pub single_stream: bool,

    /// Maximum events per delivery. Larger batches can amortize CPU work.
    #[arg(long)]
    pub batch_size: Option<std::num::NonZeroUsize>,
}

pub async fn run(args: Args) -> Result<()> {
    let secure = !args.insecure;
    let filter = build_filter(&args)?;

    let mut live = LiveConfig::new(&args.host, secure);
    live.filter = filter;
    live.compression = !args.no_compression;
    if let Some(size) = args.batch_size {
        live.max_batch = size.get();
    }
    let read_limit = live.read_limit;

    let mut config = EngineConfig::new(live);
    config.after_seq = args.after_seq.unwrap_or(0);
    config.before_seq = args.before_seq;
    config.snapshot_only = args.snapshot_only;

    let needs_archive = args.after_seq.is_some() || args.snapshot_only || args.before_seq.is_some();

    let cancel = CancelToken::new();
    let http = NativeHttpTransport::new().context("failed to build HTTP transport")?;
    let archive = if needs_archive {
        Some(build_archive(&args, secure, http.clone())?)
    } else {
        None
    };

    let dict = HttpDictionarySource::new(http, args.host.clone(), secure, cancel.clone());
    let ws = NativeWsTransport::new(read_limit);

    // The first Ctrl-C requests a clean stop: the engine finishes the batch in
    // flight and returns Ok(()), so a persisted cursor stays consistent. A second
    // Ctrl-C forces an immediate exit for a run that is wedged mid-batch.
    let cancel_on_signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            cancel_on_signal.cancel();
        }
        if tokio::signal::ctrl_c().await.is_ok() {
            // 130 = 128 + SIGINT, the conventional shell exit status for Ctrl-C.
            std::process::exit(130);
        }
    });

    if args.scoped {
        let typed = args.typed_likes;
        let archive = archive
            .map(|a| {
                let mapped = a.map(move |event| map_scoped(event, typed));
                mapped.with_decode_workers(args.decode_workers.map(|n| n.get()).unwrap_or(1))
            })
            .transpose()?;
        let engine = Engine::new(archive, ws, dict, config, cancel);
        let mut sink = CliSink {
            output: Output::Stats { json: args.json },
            stats: engine.stats(),
            typed_likes: typed,
            decoded: 0,
            decode_errors: 0,
            started: Instant::now(),
            last_report: Instant::now(),
        };
        engine
            .run_snapshot(&mut sink)
            .await
            .context("scoped snapshot failed")?;
        let _ = emit_stats(&sink, args.json);
        return Ok(());
    }

    let engine = Engine::new(archive, ws, dict, config, cancel.clone());
    let stats = engine.stats();

    let output = if args.stats {
        Output::Stats { json: args.json }
    } else {
        Output::Events { json: args.json }
    };
    let mut sink = CliSink {
        output,
        stats: stats.clone(),
        typed_likes: args.typed_likes,
        decoded: 0,
        decode_errors: 0,
        started: Instant::now(),
        last_report: Instant::now(),
    };

    engine
        .run(&mut sink)
        .await
        .context("jetstream engine failed")?;

    // A final snapshot so a stats run always ends with the totals, even if the
    // last batch did not trigger a periodic print. A broken pipe here is a clean
    // exit, not an error, so the write result is intentionally discarded.
    if args.stats {
        let _ = emit_stats(&sink, args.json);
    }
    Ok(())
}

/// Build the archive source, reading the bearer key from the environment.
fn build_archive(
    args: &Args,
    secure: bool,
    transport: NativeHttpTransport,
) -> Result<ClientArchive<NativeHttpTransport>> {
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
    if let Some(concurrency) = args.download_concurrency {
        archive_config.limits.concurrency = concurrency.get();
    }
    if args.single_stream {
        archive_config.limits.stripe_bytes = u64::MAX;
    }
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
    /// A progress snapshot at most once per second (human or JSON).
    Stats { json: bool },
}

struct CliSink {
    output: Output,
    stats: StatsHandle,
    typed_likes: bool,
    decoded: u64,
    decode_errors: u64,
    started: Instant,
    last_report: Instant,
}

impl EngineSink for CliSink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        let result = match delivery {
            Delivery::Batch(batch) => match self.output {
                Output::Events { json } => emit_batch(&batch, json),
                Output::Stats { json } => {
                    if self.typed_likes {
                        let (decoded, errors) = decode_likes(&batch);
                        self.decoded += decoded;
                        self.decode_errors += errors;
                    }
                    if self.last_report.elapsed() >= Duration::from_secs(1) {
                        self.last_report = Instant::now();
                        emit_stats(self, json)
                    } else {
                        Ok(())
                    }
                }
            },
            // Advisories go to stderr so stdout stays a clean event/stats stream.
            Delivery::Info(info) => {
                emit_info(&info);
                Ok(())
            }
        };
        // A broken stdout pipe (e.g. `shrike jetstream … | head`) is a clean stop,
        // not a failure — the same as Go's client exiting when `enc.Encode`
        // returns an error. Returning `false` ends the run with Ok(()).
        !is_broken_pipe(&result)
    }

    async fn recoverable(&mut self, error: shrike::jetstream::Error) -> bool {
        eprintln!("recoverable error: {error}");
        // Keep streaming: a recoverable error is delivered in order and the
        // engine continues after it.
        true
    }
}

fn map_scoped(event: shrike::jetstream::EventView<'_>, typed: bool) -> u8 {
    if typed
        && let shrike::jetstream::EventPayloadView::Commit(c) = &event.payload
        && c.collection == "app.bsky.feed.like"
        && let Some(record) = c.record
    {
        match shrike::api::app::bsky::FeedLikeCborView::from_cbor(record) {
            Ok(like) => {
                std::hint::black_box(like);
                1
            }
            Err(_) => 2,
        }
    } else {
        std::hint::black_box(event);
        0
    }
}

impl EngineSink<shrike::jetstream::MappedEvent<u8>> for CliSink {
    async fn deliver(&mut self, delivery: Delivery<shrike::jetstream::MappedEvent<u8>>) -> bool {
        if let Delivery::Batch(batch) = delivery {
            for event in batch.events() {
                match event.value {
                    1 => self.decoded += 1,
                    2 => self.decode_errors += 1,
                    _ => {}
                }
            }
            if self.last_report.elapsed() >= Duration::from_secs(1) {
                self.last_report = Instant::now();
                if let Output::Stats { json } = self.output {
                    return !is_broken_pipe(&emit_stats(self, json));
                }
            }
        }
        true
    }
    async fn recoverable(&mut self, error: shrike::jetstream::Error) -> bool {
        eprintln!("recoverable error: {error}");
        true
    }
}

fn decode_like(
    event: &Event,
) -> Option<
    std::result::Result<shrike::api::app::bsky::FeedLikeCborView<'_>, shrike::cbor::CborError>,
> {
    if let EventPayload::Commit(commit) = &event.payload
        && commit.collection.as_str() == "app.bsky.feed.like"
        && let Some(record) = &commit.record
    {
        Some(shrike::api::app::bsky::FeedLikeCborView::from_cbor(
            record.as_cbor(),
        ))
    } else {
        None
    }
}

fn count_likes<'a>(
    values: impl IntoIterator<
        Item = Option<
            std::result::Result<
                shrike::api::app::bsky::FeedLikeCborView<'a>,
                shrike::cbor::CborError,
            >,
        >,
    >,
) -> (u64, u64) {
    let (mut decoded, mut errors) = (0, 0);
    for value in values.into_iter().flatten() {
        match value {
            Ok(like) => {
                std::hint::black_box(like);
                decoded += 1;
            }
            Err(_) => errors += 1,
        }
    }
    (decoded, errors)
}

fn decode_likes(batch: &Batch) -> (u64, u64) {
    count_likes(batch.events().iter().map(decode_like))
}

/// Whether an emit result is a broken-pipe error (downstream reader closed).
fn is_broken_pipe(result: &io::Result<()>) -> bool {
    matches!(result, Err(e) if e.kind() == io::ErrorKind::BrokenPipe)
}

fn emit_batch(batch: &Batch, json: bool) -> io::Result<()> {
    // Lock stdout once for the whole batch so lines are not interleaved and the
    // per-line lock overhead is paid once.
    let mut out = io::stdout().lock();
    for event in batch.events() {
        emit_event(&mut out, event, json)?;
    }
    out.flush()
}

fn emit_event(out: &mut impl Write, event: &Event, json: bool) -> io::Result<()> {
    if json {
        match event_to_json(event) {
            Ok(value) => match serde_json::to_string(&value) {
                Ok(line) => writeln!(out, "{line}")?,
                Err(e) => eprintln!("failed to serialize event seq={}: {e}", event.seq),
            },
            Err(e) => eprintln!("failed to convert event seq={}: {e}", event.seq),
        }
    } else {
        writeln!(out, "{}", event_human(event))?;
    }
    Ok(())
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

fn emit_stats(sink: &CliSink, json: bool) -> io::Result<()> {
    let s = sink.stats.snapshot();
    let downloads = sink.stats.active_downloads();
    let elapsed = sink.started.elapsed().as_secs_f64();
    let rate = s.delivered_events as f64 / elapsed.max(f64::MIN_POSITIVE);
    let mut out = io::stdout().lock();
    if json {
        let value = serde_json::json!({
            "pages": s.pages,
            "sealed_tip_seq": s.sealed_tip_seq,
            "planned_through_seq": s.planned_through_seq,
            "residual_gap": s.residual_gap,
            "delivered_events": s.delivered_events,
            "last_processed_seq": s.last_processed_seq,
            "active_downloads": downloads,
            "elapsed_seconds": elapsed,
            "events_per_second": rate,
            "typed_likes": sink.typed_likes,
            "decoded": sink.decoded,
            "decode_errors": sink.decode_errors,
        });
        match serde_json::to_string(&value) {
            Ok(line) => writeln!(out, "{line}")?,
            Err(e) => eprintln!("failed to serialize stats: {e}"),
        }
    } else {
        writeln!(
            out,
            "pages={} tip={} planned={} gap={} delivered={} processed={} downloads={} elapsed={elapsed:.3}s events_per_second={rate:.0} typed_likes={} decoded={} decode_errors={}",
            s.pages,
            s.sealed_tip_seq,
            s.planned_through_seq,
            s.residual_gap,
            s.delivered_events,
            s.last_processed_seq,
            downloads,
            sink.typed_likes,
            sink.decoded,
            sink.decode_errors,
        )?;
    }
    out.flush()
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
            typed_likes: false,
            scoped: false,
            decode_workers: None,
            download_concurrency: None,
            single_stream: false,
            batch_size: None,
        }
    }

    #[test]
    fn typed_stats_count_valid_and_invalid_likes_but_skip_other_records_and_deletes() {
        use shrike::jetstream::{RawEvent, SegmentKind, raw_event_to_event};
        let make = |seq, collection: &str, kind, payload: &[u8]| {
            raw_event_to_event(RawEvent {
                seq,
                witnessed_at: 0,
                indexed_at: 0,
                kind,
                collection: collection.as_bytes().to_vec(),
                did: b"did:plc:abcdefghijklmnopqrstuvwx".to_vec(),
                rkey: b"3l3qo2vuowo2b".to_vec(),
                rev: b"3l3qo2vutsw2b".to_vec(),
                payload: payload.to_vec(),
            })
            .expect("valid event envelope")
        };
        let good = include_bytes!("../../../benches/fixtures/record_like.cbor");
        let batch = Batch::new(vec![
            make(1, "app.bsky.feed.like", SegmentKind::Create, good),
            make(2, "app.bsky.feed.like", SegmentKind::Update, &[0xff]),
            make(3, "app.bsky.feed.post", SegmentKind::Create, &[0xff]),
            make(4, "app.bsky.feed.like", SegmentKind::Delete, &[]),
        ]);
        assert_eq!(decode_likes(&batch), (1, 1));
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
