//! Bounded replay with ordinary borrowed, owned, or JSON-consuming sinks.
//! Build with `cargo build --release --features full --example jetstream_replay`.
//! Uses the same window/host/concurrency flags as the stats CLI, plus
//! `--consume=borrowed|owned|json`. Results are JSON; timings and RSS can be
//! collected with scripts/bench-jetstream.py using the example as a Rust binary.

use shrike::jetstream::{
    ApiKey, ArchiveClient, ArchiveConfig, Batch, CancelToken, ClientArchive, Delivery, Engine,
    EngineConfig, EngineSink, EventPayload, Filter, HttpDictionarySource, LiveConfig,
    NativeHttpTransport, NativeWsTransport,
};
use std::{error::Error, hint::black_box, time::Instant};

struct Sink {
    mode: String,
    decoded: u64,
    errors: u64,
}
impl EngineSink for Sink {
    async fn deliver(&mut self, delivery: Delivery) -> bool {
        if let Delivery::Batch(batch) = delivery {
            match self.mode.as_str() {
                "owned" => {
                    black_box(batch.into_events());
                }
                "borrowed" => {
                    black_box(batch.events());
                }
                "json" => consume_json(&batch, &mut self.decoded, &mut self.errors),
                _ => return false,
            }
        }
        true
    }
    async fn recoverable(&mut self, error: shrike::jetstream::Error) -> bool {
        eprintln!("recoverable error: {error}");
        true
    }
}

fn consume_json(batch: &Batch, decoded: &mut u64, errors: &mut u64) {
    for event in batch.events() {
        if let EventPayload::Commit(c) = &event.payload
            && let Some(r) = &c.record
        {
            match r.to_json() {
                Ok(value)
                    if r.as_cbor().first().is_some_and(|byte| byte >> 5 == 5)
                        && value.is_object() =>
                {
                    black_box(value);
                    black_box(r.cid().to_string());
                    *decoded += 1;
                }
                _ => *errors += 1,
            }
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let value = |key: &str| args.iter().find_map(|a| a.strip_prefix(key));
    let host = value("--host=").ok_or("--host is required")?;
    let after: u64 = value("--after-seq=").unwrap_or("0").parse()?;
    let before: u64 = value("--before-seq=")
        .ok_or("a bounded --before-seq is required")?
        .parse()?;
    let concurrency: usize = value("--download-concurrency=").unwrap_or("8").parse()?;
    if concurrency == 0 {
        return Err("concurrency must be positive".into());
    }
    let mode = value("--consume=").unwrap_or("borrowed");
    if !["borrowed", "owned", "json"].contains(&mode) {
        return Err("unknown consumption mode".into());
    }
    let secure = !args.iter().any(|a| a == "--insecure");
    let mut archive_config =
        ArchiveConfig::new(host, ApiKey::new(std::env::var("JETSTREAM_API_KEY")?));
    archive_config.secure = secure;
    archive_config.limits.concurrency = concurrency;
    if args.iter().any(|a| a == "--single-stream") {
        archive_config.limits.stripe_bytes = u64::MAX;
    }
    let cancel = CancelToken::new();
    let signal = cancel.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal.cancel();
        }
    });
    let http = NativeHttpTransport::new()?;
    let archive = ClientArchive::new(ArchiveClient::new(http.clone(), archive_config)?);
    let mut live = LiveConfig::new(host, secure);
    let mut filter = Filter::new();
    for collection in args.iter().filter_map(|a| a.strip_prefix("--collection=")) {
        filter = filter.collection(collection)?;
    }
    live.filter = filter;
    let ws = NativeWsTransport::new(live.read_limit);
    let dictionary = HttpDictionarySource::new(http, host, secure, cancel.clone());
    let mut cfg = EngineConfig::new(live);
    cfg.after_seq = after;
    cfg.before_seq = Some(before);
    cfg.snapshot_only = true;
    let engine = Engine::new(Some(archive), ws, dictionary, cfg, cancel);
    let stats = engine.stats();
    let mut sink = Sink {
        mode: mode.into(),
        decoded: 0,
        errors: 0,
    };
    let start = Instant::now();
    engine.run(&mut sink).await?;
    let stats = stats.snapshot();
    println!(
        "{}",
        serde_json::json!({
            "delivered_events": stats.delivered_events,
            "last_processed_seq": stats.last_processed_seq,
            "residual_gap": stats.residual_gap,
            "elapsed_seconds": start.elapsed().as_secs_f64(),
            "consume": mode, "decoded": sink.decoded, "decode_errors": sink.errors,
            "typed_likes": false,
        })
    );
    Ok(())
}
