# Jetstream v2 client design and implementation plan

Date: 2026-09-18

Status: in progress; M0, M1, M2, M3, M4, M5 complete (M3 native complete + roasted/hardened; browser range/stream + CORS deferred to M6; M4 browser live headless testing deferred to M6, adapter compiles via wasm-check; M5 engine + independent-oracle model tests complete, native cancellation covered, WASM future/listener cleanup deferred to M6 headless testing). M6 next.

Shrike baseline: `56edf291116fe789e4af210b7872e19debe6ca73`

Jetstream reference baseline: `58c4d7f7a9130e53b40348ad3d1f7aafed0e4843`

## Work tracker

- [x] Read the Jetstream repository documentation, specifications, design notes, lexicons, client package, segment package, and example client.
- [x] Audit Shrike's existing legacy Jetstream client, XRPC client, DAG-CBOR implementation, lexicon generator, feature layout, native/WASM transports, and CLI.
- [x] Probe `jetstream.us-east.bsky.network`. Both `planSnapshot` and `getZstdDictionary` returned HTTP 503 on 2026-09-18. The probe downloaded no archive data and logged no credentials.
- [x] Confirm package isolation, native/WASM scope, correctness-first delivery, and deferred performance measurement.
- [x] Confirm that the `jetstream.us-east.bsky.network` proxy supports the browser demo's CORS needs. Direct deployments need equivalent CORS until Jetstream adds it.
- [x] Select Jiff as the date/time library.
- [x] Define the native/WASM test strategy.
- [x] Approve the remaining libraries in [Dependency recommendations](#dependency-recommendations). (zstd 0.14 native, ruzstd 0.9 wasm, twox-hash 2.1 approved for M0; jiff/bytes/secrecy approved, added in the milestones that use them.)
- [x] Add generated `network.bsky.jetstream` DTOs without hand-editing generated files.
- [x] Implement the segment and block decoders with limits, golden fixtures, fuzzing, and checksum verification.
- [x] Implement the authenticated planner and bounded archive downloads. (native complete; browser range/stream path + CORS deferred to M6.)
- [x] Implement proposal-0015 live streaming, optional dictionary zstd, and reconnect behavior.
- [x] Implement the ordered archive-to-live engine, batching, cursor semantics, and re-backfill.
- [ ] Add the `shrike jetstream` example/diagnostic command.
- [ ] Add a separate Jetstream v2 binding and live/bounded-replay UI to the WASM demo. Preserve the legacy path.
- [ ] Complete offline native/WASM integration, property, fault, fuzz, and compile coverage.
- [ ] Run the opt-in production smoke test, then `just check`.
- [ ] Document the public API, migration boundary, limitations, and operational guidance.

## Outcome

Add a native and WASM Rust client that merges sealed archive segments and the live WebSocket into one ordered Jetstream v2 stream. Support full-network replay, exact filters, cursor persistence, archive-to-live cutover, stale-live-cursor recovery, and all four durable event kinds.

Build this as a separate `shrike::jetstream` package. Leave the legacy `streaming::Client::jetstream()` API, types, transport, behavior, and tests unchanged. Do not redirect, wrap, or share protocol state with it.

Release requires correctness, bounded resources, recovery, and native/WASM parity. Design for shared record storage, streaming decode, bounded parallelism, and ordered reassembly. Defer benchmarks and tuning until reliable high-speed networking is available.

## Goals

- Present the same validated event model for archive and live data.
- Support pure live tail, live resume, sealed snapshot replay, and replay followed by live cutover.
- Preserve Jetstream sequence ordering while allowing parallel fetch and decode.
- Preserve `commit`, `identity`, `account`, and `sync` events. Collection filtering must never hide DID-level markers.
- Make cursor semantics explicit and easy to persist once per delivered batch.
- Scope bearer credentials to the three archive endpoints that accept them.
- Degrade safely from live dictionary compression to uncompressed live streaming.
- Bound response sizes, decompression, concurrency, retries, memory, and non-advancing recovery loops.
- Keep all automated tests local and deterministic.
- Add a CLI for examples, smoke tests, and later Go/Rust comparisons.
- Ship the same high-level replay semantics on native and browser/JS-hosted WASM, with transport injection for WASM hosts that do not provide browser Web APIs.

## Non-goals

- Reimplementing the Jetstream server, archive writer, planner, indexes, imports, or compaction.
- Changing, refactoring, deprecating, or removing the legacy `/subscribe` Shrike client.
- Calling production Jetstream from normal tests, examples, doctests, or library initialization.
- Exposing the operator-only `importTimestamps` and `getImportStatus` endpoints through the replay client.
- Using `listSegments` for replay planning; `planSnapshot` is the authoritative filtered and paginated planner.
- Folding account tombstones or sync markers into a materialized view. Consumers own folding policy.
- Assuming sequence numbers are contiguous or portable between Jetstream instances.
- Extensive performance benchmarking, Go/Rust performance comparisons, or final concurrency/stripe tuning during this implementation pass.

## Research basis

The Jetstream commit above is the contract for this plan. Key sources:

- `README.md`, `docs/README.md`, `specs/client.md`, `specs/architecture.md`, `specs/invariants.md`, `specs/glossary.md`, `specs/gotchas.md`, `specs/mutation.md`, and `specs/oracle.md`.
- Documents under `specs/notes/` about the segment format, Go client, filters, active cold replay, proposal-0015, endpoint rename, and sequence reuse.
- The oracle incident reports and mutation-testing material under `specs/oracle/` and `testing/mutation/`.
- The `network.bsky.jetstream.*` lexicons.
- Root client files `client.go`, `client_core.go`, `engine.go`, `options.go`, `event.go`, `errors.go`, `planner.go`, `filter.go`, `batcher.go`, `downloader.go`, `segmentfetch.go`, `decode.go`, `live.go`, `livedecode.go`, `typed.go`, and their tests.
- The `segment/` reader, block, header, footer, sentinel, compression, validation, golden, fuzz, and swarm implementations.
- `cmd/client`, which is the behavioral model for the Shrike CLI command.

When sources differ, current lexicons, `docs/README.md`, `specs/client.md`, and production Go code take precedence over historical notes.

### Endpoint inventory

| Endpoint | Replay-client use | Authentication |
|---|---|---|
| `network.bsky.jetstream.planSnapshot` | Required; paginate a pinned sealed snapshot | Archive bearer key |
| `network.bsky.jetstream.getSegment` | Required for whole-segment plan entries | Archive bearer key |
| `network.bsky.jetstream.getBlock` | Required for sparse block plan entries | Archive bearer key |
| `network.bsky.jetstream.getZstdDictionary` | Optional live compression setup/recovery | Never send archive key |
| `network.bsky.jetstream.subscribeEvents` | Required live tail and server replay | Never send archive key |
| `network.bsky.jetstream.listSegments` | Diagnostic/server API; not used by thick client | No client credential propagation |
| `network.bsky.jetstream.importTimestamps` | Operator administration; out of scope | Separate operator bearer auth |
| `network.bsky.jetstream.getImportStatus` | Operator administration; out of scope | Separate operator bearer auth |

## Current Shrike gap analysis

Shrike currently has a small JSON client for legacy `/subscribe` under `src/streaming/`:

- It parses legacy top-level `did`, `time_us`, and `kind` objects.
- It supports only commit, identity, and account; it has neither sync events nor a Jetstream sequence field.
- It resumes from `time_us` and sends legacy `wantedCollections` and `wantedDids` query parameters.
- It shares batching/reconnect configuration with the firehose client.
- Native and browser transports both support this legacy flow.

It cannot consume `subscribeEvents`, proposal-0015 envelopes, sequence cursors, sealed segment plans, archive blocks, dictionary zstd frames, or archive/live cutover.

Other relevant constraints:

- `src/xrpc::Client` buffers whole response bodies (5 MiB JSON, 512 MiB raw, and the cap is enforced only when the server sends `Content-Length`), adds its bearer to every request once set, and lacks range/ETag streaming. It cannot safely handle archive auth or large segments.
- `reqwest` already has its `stream` feature, and native `tokio-tungstenite`, browser `gloo-net`, Tokio, futures, URL, and strict DAG-CBOR support already exist behind features.
- Shrike's public DAG-CBOR `Value<'a>` borrows its input. The replay API needs an owning record-byte type.
- The lexicon cache contains `network/bsky/jetstream`, but `lexgen.json` omits `network.bsky`. Lexgen skips subscription clients but can generate their associated object types.
- Generated API records expose `from_cbor`, but there is no common typed-decode trait. Raw record bytes are sufficient for a staged typed fast path.
- The `wasm` feature excludes native sync/backfill modules. The new engine cannot depend on them. Browsers also differ in transport, CORS, scheduling, and 32-bit memory.
- WASM has no universal WebSocket API. Use narrow transport traits with native and browser/JS implementations.
- The `wasm/` demo's `connectJetstream` binding uses legacy `/subscribe`. Keep it and add a separate v2 binding.
- Jiff, zstd decoders, xxh3, shared byte storage, and secret wrappers are not direct Shrike dependencies. Repository policy requires approval before adding them; Jiff has been author-approved.

## Recommended architecture

### Public boundary

Add a `jetstream` feature and `shrike::jetstream` module to both `full` and `wasm`. Keep protocol, filtering, planning, decoding, state, retries, and integrity checks portable. Isolate HTTP, WebSocket, timers, task spawning, and environment access.

Do not modify `streaming::Client::jetstream()` or reuse its `JetstreamEvent` type for v2. The absence of a sequence cursor and sync payload makes apparent source compatibility misleading.

Suggested file layout:

```text
src/jetstream/
  mod.rs             public API and documentation
  client.rs          builder, config validation, stream ownership, close/cancel
  event.rs           Event, payloads, Record, Batch, Info
  error.rs           error kinds and fatal/recoverable classification
  filter.rs          exact client-side predicates and validation
  engine.rs          replay/live state machine and ordered delivery
  planner.rs         planSnapshot DTO adaptation and pagination checks
  transport.rs       portable HTTP/WebSocket/timer traits and wire responses
  transport_native.rs reqwest, tokio-tungstenite, Tokio spawning/timers
  transport_wasm.rs  Fetch, WebSocket, cooperative scheduling, JS-hosted WASM
  download.rs        block and whole-segment download scheduling
  segment.rs         sealed header/footer/frame validation
  block.rs           bounded columnar block decode
  live.rs            WebSocket dial/read/reconnect and proposal-0015 framing
  compression.rs     dictionary ID handling and bounded zstd decode
  json_cbor.rs       atproto JSON to canonical DAG-CBOR conversion
```

Combine small modules when useful. Do not create empty abstractions to match this sketch.

### Target and transport model

The supported matrix is:

| Target | Built-in transport | Contract |
|---|---|---|
| Native Tokio targets | `reqwest` + `tokio-tungstenite` | Full archive and live support; stream is `Send` where its inputs are `Send` |
| `wasm32-unknown-unknown` in browsers | Fetch + browser WebSocket through the existing WASM stack | Full archive and live support, subject to server CORS; cooperatively scheduled |
| JS-hosted WASM with compatible Fetch/WebSocket globals | Same WASM adapter | Supported and tested in at least one headless JS runtime |
| WASI or embedded hosts without browser Web APIs | Caller-supplied portable transports | Core replay/decoding works; the host supplies HTTP, WebSocket, timer, and secret access |

WASI has no universal WebSocket API. Expose narrow host transport traits so WASI and embedded runtimes can use the portable engine without platform branches in the state machine.

Prefer associated-future transport traits over unconditional `async_trait` or boxed futures. Keep `Send + Sync` off the portable core and require it on native clients where needed. Keep scheduling out of parsers and codecs so work can later move to worker pools or Web Workers.

Browser archive access requires server CORS support:

- allow the caller origin and GET/POST/OPTIONS;
- allow `Authorization`, `Content-Type`, `Range`, and `If-Range`;
- expose `ETag`, `Content-Range`, `Content-Length`, and `Retry-After`;
- accept WebSocket subprotocol `xrpc.v1.json`.

The `jetstream.us-east.bsky.network` proxy meets these needs. Direct deployments need an equivalent proxy until Jetstream adds CORS. Report missing CORS or hidden headers as a capability error, not corrupt data.

### Generated protocol types

Add a `network.bsky` package to `lexgen.json`, run `just lexgen`, and use the generated request/response and event-object types where they fit. Do not edit generated output. The dedicated client still owns:

- proposal-0015 envelope dispatch;
- pre-upgrade HTTP error parsing;
- secret-bearing archive transport;
- ranged/streaming binary responses;
- segment decoding and orchestration.

Do not use generated XRPC helpers as the thick client's transport layer. Keep subscription generation out of scope unless associated object generation exposes a bug.

### Proposed Rust API

Names may change. Fix the semantics before coding:

```rust
use futures::StreamExt;
use shrike::jetstream::{Client, Delivery, Filter, Kind};

let client = Client::builder("jetstream.us-east.bsky.network")
    .api_key_from_env("JETSTREAM_API_KEY")?
    .filter(Filter::new()
        .kinds([Kind::Commit])
        .collection("app.bsky.feed.post")?)
    .after_seq(0)
    .build()?;

let mut deliveries = Box::pin(client.events());
while let Some(delivery) = deliveries.next().await {
    match delivery? {
        Delivery::Batch(batch) => {
            process(batch.events()).await?;
            persist_cursor(batch.last_cursor()).await?;
        }
        Delivery::Info(info) => log_advisory(info),
    }
}
```

`api_key_from_env` is for native or host runtimes. Browser apps must supply keys at runtime. Compiled browser keys are not secret.

The builder supports:

- kinds, DIDs, and collections;
- exclusive `after_seq`, inclusive `before_seq`, snapshot-only mode, and pure-live resume cursor;
- `before_seq` is valid only with snapshot-only mode, as in Go: a live tail with an upper bound would silently drop every later event;
- "start live at the tip" is an explicit builder state, not cursor `0`. Go's `WithLiveCursor(0)` means tip while wire cursor `0` means everything; do not copy that footgun;
- maximum batch size and live partial-batch delay;
- archive decode concurrency, sparse block fetch concurrency, whole-segment prefetch, and range stripes;
- request attempt/backoff limits and size limits;
- optional archive API key;
- live dictionary compression, enabled by default;
- injectable portable transports for tests, WASI/embedded hosts, and advanced callers.

Use conservative target-specific defaults. Start with batches of 64 and a 20 ms live partial flush, matching Go. The other Go native defaults, for reference: decode workers = CPU count clamped to [4, 32]; block fetch pool = min(2 × decode workers, 64); whole-segment prefetch depth 2; 8 range stripes with 16 MiB parts; live reconnect backoff 250 ms doubling to 30 s. Use lower WASM concurrency and yield during long decode loops. Tune after measurement.

Each `Client` drives one event stream. Dropping the stream or client cancels tasks and closes sockets. Add an idempotent `close` or cancellation handle if the API stays simple.

### Event and record model

Use validated Shrike syntax types where the wire promises them:

```text
Event
  seq: u64                  Jetstream cursor
  did: Did
  time_us: i64              indexed/display time; witnessed time when not imported
  payload: EventPayload

EventPayload
  Commit { operation, collection: Nsid, rkey: RecordKey, rev: Tid,
           record: Option<Record> }
  Identity { upstream fields }
  Account { upstream fields }
  Sync { upstream fields }
```

Use an enum so invalid payload combinations cannot be built. Map segment kind 7 (`create-resync`) to commit/create, as the Go client does.

Identity, account, and sync payloads wrap the upstream `com.atproto.sync.subscribeRepos` event, which carries its own relay `seq` and `time`. Only the Jetstream envelope `seq` is the cursor; never persist or dedup on the wrapped values.

`Record` owns or shares canonical DAG-CBOR bytes and exposes:

- `as_cbor(&self) -> &[u8]`;
- lazy generic DAG-CBOR decode borrowing from `&self`;
- optional conversion to owned atproto JSON;
- lazy/cached CID calculation where the archive row did not carry a CID;
- a documented way to call generated `Type::from_cbor(record.as_cbor())`.

Use `bytes::Bytes` slices so archive records share one decompressed slab without `unsafe` or self-references. Convert live JSON to canonical DAG-CBOR once. Deletes have no record or CID. Hide storage behind `Record` so it can change without breaking callers.

Do not require eager generic JSON; it is too costly for full replay. Add typed adapters later, after the record ownership API is stable.

`Batch` owns its events and reports the highest sequence through `last_cursor()`. Consumers persist progress after a batch. A seq-less `#info` frame is `Delivery::Info` and never advances the cursor.

`Stats` is a cheap snapshot of pages, sealed tip, planned-through seq, residual gap, delivered events, and last processed seq. Do not add a metrics registry.

### Error contract

Use a structured `Error` with `is_fatal()`. The stream may continue after a recoverable error and must end after a fatal error. Preserve XRPC error names and HTTP status.

Fatal examples:

- invalid local configuration;
- rejected or malformed snapshot plan that prevents guaranteed progress;
- exhausted download/replan attempts for required archive work;
- non-advancing pagination or re-backfill beyond its bound;
- `CursorTooOld` on a pure-live stream, since there is no archive mode to re-enter;
- an archive/live cutover invariant that can no longer be satisfied;
- unsupported segment version or structural corruption when no safe retry/replan path remains.

Recoverable examples:

- a malformed row when valid sibling rows can still be delivered in order;
- a transient live read/dial failure while reconnect remains possible;
- dictionary fetch, negotiation, or decompression setup failure when uncompressed fallback works;
- advisory `#info`, represented as `Delivery::Info`, not an error. The Go client logs and skips `#info`; we deliver it because a clamped timestamp resume (`OutdatedCursor`) implies a gap the consumer may care about, and a library should not depend on a logger to surface it.

Keep valid rows decoded before a later failure. Emit the rows, then the ordered error, then continue or stop based on its class. Never expose the API key in errors, `Debug`, tracing fields, URLs, or stats.

## Protocol behavior

### Filters

The three filter dimensions are independent predicates and are AND-composed:

- `kinds`: commit, identity, account, sync; omitted/empty means all.
- `dids`: applies to every event kind; omitted/empty means all.
- `collections`: exact NSID or terminal `.*` namespace wildcard; applies only to commits.

Collection filters do not apply to identity, account, or sync events. DID and kind filters do. Thus `collections=app.bsky.feed.post` includes matching commits and allowed DID-level markers. Add `kinds=commit` for commits only. Reject collection filters when a non-empty kind filter excludes commit.

The planner may return false positives. Apply the same exact filter after archive and live decode.

Validate before I/O: at most 4 kinds, 10,000 DIDs, and 100 collections; valid DID/NSID syntax and wildcards; no legacy `wanted*` fields.

### Cursor model

- Jetstream v2 sequences are 1-based; `0` means “before the beginning”.
- Archive requests use `(afterSeq, beforeSeq]`.
- `subscribeEvents` replays inclusively from `cursor`; the client drops every `seq <= last_processed_seq`.
- An omitted cursor on a pure live subscription starts at the current tip.
- The server reads a v2 cursor `>= 10^15` as Unix microseconds, not a sequence. Use distinct sequence and timestamp resume APIs.
- An old sequence cursor is rejected pre-upgrade as `CursorTooOld`.
- An old timestamp cursor is clamped and starts with seq-less `#info`/`OutdatedCursor`.
- A future cursor enters tip mode.
- Sequence numbers can jump across registered crash vacancies. Never require `next == previous + 1`.
- A cursor is local to a Jetstream server instance. Include the normalized host/instance identity in persistence guidance.
- Validate values against the lexicon/XRPC signed-integer ceiling (`i64::MAX`) before serialization. A live sequence resume must additionally be below `10^15`, or the server would read it as a timestamp.

### Snapshot planning

For archive replay:

1. POST `planSnapshot` with exact requested filters and bounds.
2. On the first successful page, pin `sealedTipSeq = S`.
3. Validate every plan entry: name, index, 16-char hex checksum, sequence range, known mode, and non-empty ordered/in-range block ranges.
4. Process entries in returned order. For later pages send `afterSeq = plannedThroughSeq` and `beforeSeq = S`, even if the caller omitted `before_seq`.
5. Treat `plannedThroughSeq` as coverage, not “last event returned”. Empty/sparse pages still advance.
6. Reject a non-advancing page, `plannedThroughSeq > S`, or a later page whose `sealedTipSeq` differs from the pin. Pinning `beforeSeq = S` prevents tip movement server-side; the check catches a misbehaving server.
7. Finish when `plannedThroughSeq >= S`.

Plan entries are over-approximate in seq as well as content: a unit that straddles `afterSeq` is included whole. Apply the window `(afterSeq, min(beforeSeq, S)]` per row after decode, and advance the floor to the resume seq on re-backfill so a straddling unit does not re-emit delivered rows.

Snapshot-only excludes the active unsealed segment by definition. A replay that continues live cuts over exactly once at `max(S, last_processed_seq)`.

### Archive downloads

For `mode=blocks`, expand inclusive block ranges carefully, fetch `getBlock?segment=...&blockIndex=...` with bounded concurrency, and reassemble results in plan/block order.

For `mode=segment`:

- probe range support and a strong ETag. `getSegment`'s ETag is the quoted 16-char hex plan checksum, so an ETag that differs from the plan checksum means the segment was rewritten after planning; treat that as a generation change;
- pin the probe ETag and require it on every part via `If-Range`;
- expose a common internal `SegmentSource`/compressed-frame stream so download strategy is independent of segment parsing and ordered decode;
- use bounded parallel ranges with `If-Range`, a sequential streaming response, or metadata-plus-frame ranges according to target capabilities;
- validate 200/206 status, `Content-Range`, total length, overlap/gaps, response length, and ETag consistency;
- bound a segment at 1 GiB. This is a client allocation cap, as in Go; real sealed segments target roughly 256–280 MB;
- on a generation change, discard that attempt, restart the whole download with a fresh probe at most twice (Go's `maxGenerationAttempts = 2`; no replan is needed), and never splice bytes from different generations;
- retry 429 and all 5xx with bounded attempts (Go defaults to 3, 500 ms exponential backoff capped at 30 s) honoring bounded `Retry-After`/`RateLimit-Reset`; other 4xx are permanent;
- stream response bodies and decode per block instead of retaining multiple decoded segments.

On WASM, fetch and validate header and footer/index ranges before bounded compressed frame ranges. Do not assemble a 1 GiB segment in linear memory. Without Range or exposed headers, use a sequential response only if its declared and observed sizes fit target limits. Otherwise return a capability or resource error. Native may use wider range striping behind the same `SegmentSource` API.

Use separate policies for short control requests and bulk downloads. The general XRPC client's buffering and timeouts do not fit bulk downloads.

The plan checksum/ETag identifies a segment generation. After a whole download, validate the header/footer and recompute xxh3 over `header[12..] || footer`. HTTP success does not prove integrity. The Go client skips this recompute; we keep it because the hash covers only the header and footer and is cheap.

### Segment and block decoding

A `.jss` segment has a fixed 256-byte header: `jss0` magic, a u64 xxh3 checksum, version 1, counts, seq/timestamp ranges, and five section offsets, with the trailing header bytes zero. A zero checksum marks an unsealed, still-active segment; reject it. Compressed blocks occupy `[256, FooterOffset)`. The footer runs from `FooterOffset` to end of file and its first section is the block index (`BlockIndexOffset` must equal `FooterOffset`). Each file block has an 8-byte little-endian compressed-length prefix. `getBlock` returns the raw zstd frame without this prefix.

Validate offsets and counts before allocation or slicing. Use checked arithmetic. Reject offsets into the header, past `FooterOffset` or file length, or inconsistent with block indexes. An empty block encodes as exactly four zero bytes.

The decompressed columnar block is:

```text
event_count: u32 little-endian
seq[event_count]: u64
witnessed_at[event_count]: i64
indexed_at[event_count]: i64
kind[event_count]: u8
collection_len[event_count]: u8
did_len[event_count]: u16
rkey_len[event_count]: u8
rev_len[event_count]: u8
payload_len[event_count]: u32
collections || dids || rkeys || revs || payloads
```

Start with the Go limits: 262,144 rows and 1 GiB decompressed per block. Check aggregate lengths before slicing. Consume all columns and blob regions exactly; reject trailing or truncated data.

Kind mapping:

| Code | Meaning |
|---:|---|
| 1 | commit create |
| 2 | commit update |
| 3 | commit delete |
| 4 | identity |
| 5 | account |
| 6 | sync |
| 7 | create-resync, exposed as commit create |

Use nonzero `indexed_at` as display time; otherwise use `witnessed_at`. Identity, account, and sync payloads contain upstream event DAG-CBOR. Commit create/update payloads contain canonical record DAG-CBOR. Deletes have no record. Validate metadata, syntax, CBOR, and CID rules for each kind.

Workers may fetch and decode ahead. Only the ordered reassembly stage emits. WASM uses bounded concurrent futures, not OS threads, and yields during long loops. Bound memory by concurrency, prefetch depth, compressed/decompressed limits, target address space, and batch ownership.

### Live WebSocket

Dial:

```text
/xrpc/network.bsky.jetstream.subscribeEvents
Sec-WebSocket-Protocol: xrpc.v1.json
```

Use repeated `kinds`, `dids`, and `collections` query parameters, plus `cursor` and optional `zstdDictionary`. Verify the echoed subprotocol: accept `xrpc.v1.json` or an empty echo (the lexicon default, identical framing); fail on anything else. Do not request or negotiate `permessage-deflate`. The lexicon also defines `maxMessageSizeBytes`, but a nonzero value silently skips oversized events, markers included; never send it, matching the Go library.

Uncompressed frames are proposal-0015 JSON. The envelope `$type` is only ever `message` or `error`; `#commit`, `#identity`, `#account`, `#sync`, and `#info` are payload `$type`s inside a `message` envelope:

```json
{"$type":"message","payload":{"$type":"network.bsky.jetstream.subscribeEvents#commit"}}
{"$type":"error","error":"ConsumerTooSlow","message":"..."}
```

Dispatch payloads by exact `$type`. A frame with no envelope `$type` is a hard error (likely a legacy v1 endpoint); an unknown non-empty envelope or payload `$type` is skipped for forward compatibility, with bounded context kept. An `error` frame is terminal for the connection; the server closes after sending it. Parse pre-upgrade XRPC 400 errors, including `CursorTooOld`, `UnknownZstdDictionary`, and generic `InvalidRequest`.

Generated decoders do not enforce lexicon `required` fields; the client must. Reject frames with `seq <= 0`, an unparseable `time` (RFC 3339 UTC with exactly six fractional digits on the wire), or missing required commit fields, rather than emitting a zero-valued event that would advance the dedup cursor.

Default to a 32 MiB read limit that also caps decompressed frame size, matching Go's `defaultLiveReadLimit`; make it configurable. Handle ping, pong, close, and cancellation correctly on each transport. The server pings every 30 seconds; a client that never answers is dropped.

Reconnect from the last processed sequence. Server replay is inclusive, so drop `seq <= last_processed_seq`. Flush a partial batch before reporting a live error or returning to archive recovery.

### Dictionary zstd

Compression is an optimization and is enabled by default:

1. Fetch the current dictionary from `getZstdDictionary` without auth. The response is raw bytes (`application/octet-stream`). Omit the optional `id` parameter for the current dictionary; its lexicon minimum is 1, so do not send `id=0`.
2. Parse and validate the embedded zstd dictionary ID from the RFC 8878 §5 structured-dictionary header (magic `0xEC30A437`, little-endian ID at bytes 4–8). Reject content-only blobs without the header.
3. Dial with `zstdDictionary=<id>`.
4. Treat each binary WebSocket message as one complete zstd frame whose decompressed bytes are exactly one JSON text frame (message, info, and error frames alike), and cap decompressed output at the read limit before JSON parsing.
5. On an uncompressed connection, ignore stray binary frames; on a compressed connection, still accept text frames. This matches the Go client.
6. On `UnknownZstdDictionary`, refetch the current dictionary and reconnect with the new ID. If the refetch fails or returns the very ID just rejected, fall back to uncompressed for the client's lifetime.
7. On dictionary or decoder setup failure, log a redacted error and fall back to uncompressed mode. Treat a malformed compressed frame after upgrade as a stream error and recover within configured bounds.

Never attach the archive bearer key to dictionary fetch or WebSocket upgrade.

### Archive-to-live recovery state machine

```text
validate config
     |
     +-- pure live ------------------------------+
     |                                           v
     +-- plan pinned snapshot -> download -> ordered filter/batch
                                 ^                 |
                                 |                 +-- snapshot-only -> end
                                 |                 |
                                 +---- replan -----+-> live at max(S, processed)
                                                       |
                           CursorTooOld at cutover -----+
                           flush batch, backfill from processed
```

On `CursorTooOld`, flush valid pending rows, replay after the last processed seq, pin a new sealed tip, and retry cutover. Stop after 5 consecutive cycles that neither advance the cursor nor extend archive coverage (matches the Go client's `maxRebackfillStalls`). On a pure-live stream (no archive credentials), `CursorTooOld` is immediately fatal — there is no archive loop to re-enter.

The engine must not assume that a plan entry contains every sequence in its range, that a page contains events, or that the live cursor is adjacent to the sealed tip.

## Security and privacy

- Represent the archive key with a private redacting wrapper; implement only redacted `Debug`/`Display`.
- Accept the raw key, never a caller-built `Authorization` string.
- Add auth only in dedicated request constructors for `planSnapshot`, `getSegment`, and `getBlock`.
- Unit-test that the key is absent from dictionary, live upgrade, redirects, errors, logs, formatting, and injected-client state.
- Disable or strictly constrain cross-origin redirects for authenticated archive requests so a key cannot be forwarded to another host.
- Reject an archive key over cleartext except explicit loopback test/dev hosts. Do not infer that private RFC1918 networks are safe.
- Keep the CLI key in `JETSTREAM_API_KEY`; do not require it as a process-visible command-line argument.
- Browser users can extract bearer keys. Never embed long-lived keys in public bundles. Use short-lived/scoped keys or a trusted proxy.
- Treat browser CORS as part of the deployment contract and test preflight/header exposure. Never work around it with query-string credentials.
- Cap error bodies and never echo arbitrary huge or binary server responses.
- Use checked conversions/arithmetic throughout parser and range code; no `unsafe`, panics, unwraps, expects, or unreachable branches in production.
- Treat all downloaded offsets, lengths, counts, timestamps, CIDs, syntax strings, JSON, CBOR, and zstd frames as untrusted.

## CLI design

Add `tools/shrike/src/jetstream.rs` and a distinct `Jetstream` command in `tools/shrike/src/main.rs`. Keep the current `Subscribe` command as the firehose/legacy Jetstream tool.

Proposed usage:

```text
shrike jetstream \
  --host jetstream.us-east.bsky.network \
  --after-seq 0 \
  --kind commit \
  --collection app.bsky.feed.post \
  --duration 30s
```

Flags:

- host;
- repeated kind, collection, and DID;
- after-seq, before-seq, snapshot-only, and live-cursor;
- batch size, decode/download concurrency, segment stripes, max attempts;
- zstd on/off;
- duration and report interval;
- output mode: newline-delimited JSON or periodic throughput/progress stats.

Read archive auth from `JETSTREAM_API_KEY`. If needed, accept an environment variable name, not a key flag. JSON output includes seq and every marker kind. Stats include total events, events/sec, last cursor, sealed tip, planned-through seq, and residual gap.

Ctrl-C and duration expiry are successful cancellation, not stream failure. Fatal errors produce nonzero exit; recoverable errors are printed to stderr and consumption continues.

Use the CLI for production smoke tests. Require a host so normal use cannot start a production full replay by accident.

## Implementation milestones and acceptance criteria

### M0 — Dependency and cross-target spike

- [x] Resolve package isolation, target, correctness, and performance-measurement scope.
- [x] Choose Jiff for date/time parsing and formatting.
- [x] Approve the remaining dependency recommendations below.
- [x] Verify both selected zstd implementations against the same dictionary/frame/error corpus, window/output limits, native build, and `wasm32-unknown-unknown` build. (WASI is not in shrike's shipped feature matrix and its std is absent from the pinned Nix toolchain, so a WASI build is out of scope for M0; the `wasm` feature targets the browser.)
- [x] Confirm an xxh3 implementation against Jetstream golden checksums. (twox-hash XXH3-64 streaming verifies the golden seal; a tampered footer byte is rejected.)
- [x] Record dependency choices and approval in the implementing change. (`Cargo.toml` `jetstream` feature + per-target codec deps, documented inline.)
- [x] Capture/copy minimal Go-generated fixtures into `testdata/jetstream/` with provenance and generation instructions. (`testdata/jetstream/gen` reproduces the corpus; `manifest.json` pins the Jetstream commit and klauspost version with sha256s.)
- [x] Prove one full compressed block decode and one proposal-0015 dictionary frame in native and browser WASM tests. (12 native tests + 2 `wasm_bindgen_test`s over the shared golden corpus.)

Acceptance: record dependency, API, and target decisions. Decode and checksum a Go golden block. Run the portable codec offline on native and WASM. **Met.**

### M1 — Protocol DTOs and public value model

- [x] Add `network.bsky` to lexgen configuration and regenerate with `just lexgen`. (`lexgen.json` gains the `network.bsky` package; `src/api/network/bsky` is generated. lexgen `load_config` count test updated to 5.)
- [x] Add v2 filter/config validation and host normalization. (`filter.rs`: `Filter`/`Kind` with count limits + cross-field validation; `config.rs`: `normalize_host`, `Cursor` with live/archive validation and the 10^15 timestamp threshold.)
- [x] Add event, payload, record backing, batch, info, stats, and error types. (`event.rs`: `Event`/`EventPayload`/`Commit`/`Operation`/`Batch`/`Info`/`Delivery`/`Stats`/`LiveFrame`; `record.rs`: `Record` with `Bytes` backing and lazy cached CID; `error.rs` variants.)
- [x] Implement atproto JSON-to-DAG-CBOR canonicalization for live records. (`json_cbor.rs`: `record_json_to_dag_cbor`, `$bytes`/`$link` forms, canonical key order, integer-only numeric model.)
- [x] Unit-test proposal-0015 envelopes, all payload variants, invalid unions, timestamp conversion, CID parity, and JSON/CBOR parity. (64 jetstream unit tests: envelope dispatch, commit/identity/account/sync, unknown-$type skip, error/InvalidFrame, byte-for-byte JSON/CBOR + CID parity, generated-API decode.)
- [x] Document legacy/v2 type separation. (Module docstrings in `mod.rs` and per-file headers spell out the v1-vs-v2 boundary and the relay-`seq`-is-not-the-cursor rule.)
- [x] Add Jiff-backed exact conversion between live RFC 3339 timestamps and archive Unix microseconds. (`time.rs`: `rfc3339_to_micros`/`micros_to_rfc3339` via jiff `Timestamp`, six-digit fractional precision.)

Acceptance: map every live lexicon example to the event model. Typed-decode archive records with generated APIs. Public builders cannot create invalid states. **Met.**

### M2 — Segment/block decoder

- [x] Decode raw `getBlock` frames with strict compressed/decompressed limits. (`block.rs`: `decode_block_frame`/`decode_block` over `decompress_bounded` with `MAX_DECODED_BLOCK_BYTES`; columnar layout validated with checked arithmetic — capped event count, fixed region fit, exact blob accounting.)
- [x] Parse whole-segment header, footer, block index, length-prefixed frames, and checksum. (`segment.rs`: `SegmentReader::open` → `read_sealed_header` (256-byte header, xxh3 over `header[12..256] ++ file[footer_offset..]`) → `decode_block_index` (52-byte LE entries) → `validate_block_offsets` (monotonic, non-overlapping, in-bounds); `block_frame` strips the 8-byte length prefix and cross-checks the declared compressed size.)
- [x] Decode every event kind and exact filter it. (`decode.rs`: `decode_segment_filtered`/`raw_event_to_event` map wire kinds 1–7 to public commit/identity/account/sync events; `built_segment_round_trips_every_kind` covers all seven, wildcard/DID/kind filters covered by dedicated tests.)
- [x] Preserve valid sibling rows around recoverable row failures. (`convert_rows` drops only the offending row as `MalformedEvent`; `sibling_recovery_preserves_valid_rows` and the golden-seal sibling-drop test confirm valid neighbors survive an invalid `rev`/`did`.)
- [x] Add Go golden block/segment cross-language tests. (`golden_seal_iterates_raw_rows_matching_manifest` iterates the Go-produced `.jss` seal at the raw-row level against the manifest; the wasm suite decodes the golden block and dictionary frame byte-for-byte.)
- [x] Add fuzz targets for header, footer, frame, decompression, column lengths, payload decode, and filter wildcard logic. (`fuzz/fuzz_targets/jetstream_*.rs`: `read_header`, `decode_segment`, `decode_block_frame`, `decode_block_body`, `decompress` (asserts the `max_out` bound), `raw_event`, `filter_wildcard` — all compile-verified against the real public API via `cargo check --bins`. Instrumented `cargo fuzz run` requires the nightly toolchain from `just dev`.)
- [x] Add property tests for overflow-free layout calculations and ordered/filter equivalence. (`tests/jetstream_property_tests.rs`: `layout_validation_never_panics`, `block_offset_validation_never_panics`, `row_filter_equals_event_filter` — pre-conversion `matches_segment` selects exactly the post-conversion `matches` set, order-sensitive.)

Acceptance: malformed input cannot panic or exceed configured allocation limits. Golden output matches Go event for event.

### M3 — Planner and archive transport

- [x] Build a scripted local protocol server with deterministic gates, a request/fault ledger, and anti-vacuity checks. (`tests/jetstream_archive.rs`: a `Scripted` `HttpTransport` matching each request to a per-key FIFO of programmed responses, so retries, restarts, and concurrent stripe/block fetches are reproducible regardless of scheduling; a request ledger records URL/auth/range/if-range for assertions; each queue must be provisioned or the transport panics, so no case can silently no-op. CORS controls belong to the browser `fetch` transport and land with the WASM demo — `reqwest` ignores CORS.)
- [x] Implement scoped-auth `planSnapshot` calls and strict response validation. (`planner.rs`: bearer-scoped `control_request`; `validate_segment`/`validate_block_spans`/`validate_segment_name`/`validate_checksum` reject bad checksums, path traversal, inverted/oversized spans; integration tests cover accept + each rejection.)
- [x] Implement pinned pagination and empty-page progress. (`plan_snapshot` pins `sealedTipSeq` on the first page, advances `plannedThroughSeq`, and rejects tip drift, `plannedThroughSeq` past the tip, and non-advancing pages; `planner_pins_tip_and_accumulates_pages` and the rejection tests confirm.)
- [x] Implement `getBlock` pooling with ordered reassembly. (`download_blocks`: `stream::iter(...).buffered(concurrency)` preserves block order; `blocks_mode_reassembles_in_order`/`blocks_mode_applies_window`.)
- [x] Implement streamed whole downloads, range probing, striping, ETag/If-Range, resume, integrity validation, and generation restart. (`download_whole`/`try_download_whole`: `Range: bytes=0-0` probe, striped ranged reads pinned with `If-Range`, non-ranged/416 fallbacks, `SegmentReader` re-verification + plan-checksum cross-check, and a bounded generation-restart loop. A stripe that receives a non-206 success (an `If-Range` miss carrying the whole object) now restarts cleanly instead of failing the exact-length read — bugfix with regression test `generation_change_triggers_clean_restart`; budget bound covered by `generation_restart_budget_is_bounded`.)
- [x] Add bounded Retry-After-aware retries for network, 429, and eligible 5xx failures. (`download_fetch` over `with_retry`; `rate_limited_download_honors_retry_after_then_succeeds`, `interrupted_body_is_retried_then_succeeds`, `stalled_download_exhausts_retries`, `permanent_4xx_is_fatal_without_retry`, all deterministic under `tokio` `start_paused`.)
- [x] Add cancellation and clean worker shutdown. (`CancelToken` checked before every send and body read; `cancelled_download_never_touches_the_network` and `planner_cancellation_is_immediate`.)
- [ ] Implement the browser range/stream capability path and clear CORS/resource errors. (Deferred to the WASM demo milestone (M6): the native `reqwest` transport is complete here; the browser `fetch`/streams transport and its CORS/resource-error surface land with the demo.)

Acceptance: the scripted native server covers whole, sparse, ranged, non-ranged, interrupted, rate-limited, generation-changing, corrupt, truncated, oversized, and stalled cases; results are deterministic (paused-clock retries) and leak no secrets (the bearer key rides only the Authorization header — asserted absent from URLs, and redacted by construction from transport errors and `ApiKey`'s `Debug`). The browser-WASM server and CORS case are deferred with the browser transport to M6. **Met (native); browser deferred to M6.**

### M4 — Live v2 transport

- [x] Dial with the exact path and `xrpc.v1.json` subprotocol.
- [x] Parse proposal-0015 message and error frames.
- [x] Parse pre-upgrade XRPC errors.
- [x] Implement cursor deduplication, reconnect/backoff, partial batch flush, ping/pong/close, and cancellation.
- [x] Fetch/validate zstd dictionaries unauthenticated and decode bounded binary frames.
- [x] Implement rejected/stale dictionary recovery and uncompressed fallback.
- [x] Implement native and browser/JS-hosted WebSocket adapters with the same frame/error fixtures.

Acceptance: local native and browser/JS fixtures cover text and compressed frames, every event/info/error kind, duplicates, gaps, future/old cursors, slow consumers, malformed frames, disconnects, and dictionary rotation.

M4 notes: the portable `LiveConsumer` in `live.rs` drives a `WsTransport`/`WsConnection`/`DictionarySource`/`DeliverySink` set of RPITIT traits (no `Send` bound, so the browser's `!Send` socket satisfies them). Tail behavior is covered by the in-module tests over mock transports (dedup, gaps, slow consumer, malformed/corrupt frames, dirty disconnect, dictionary rotation, pre-upgrade HTTP error, unsupported subprotocol, uncompressed-fallback). The native adapter (`transport_native.rs`) adds a hermetic loopback tokio-tungstenite server test exercising dial + subprotocol negotiation + text/binary + transparent ping/pong + clean close, plus a wrong-subprotocol → fatal `DialError::Subprotocol` case. tokio-tungstenite enforces RFC-6455 step-6 subprotocol verification itself, so the adapter maps `SecWebSocketSubProtocolError` to the fatal variant rather than checking response headers by hand. The browser adapter (`transport_wasm.rs`, `gloo-net`) compiles under `just wasm-check`; headless browser live testing is deferred to M6 (with the deferred browser range/stream + CORS work), since the browser owns the handshake and exposes neither the pre-upgrade HTTP status (so a rejected upgrade degrades to a retryable `DialError::Transport`) nor a synchronous negotiated-subprotocol value (it relies on the browser's own RFC-6455 enforcement).

M4 roast fixes: a post-commit roast raised four confirmed findings, all fixed with regression tests: (A) dictionary fetches (initial and rotation recovery) now race `cancel.cancelled()` through a single `fetch_dict_cancelable` helper, so a stalled fetch cannot wedge shutdown; (B) every flush-then-continue site (dirty disconnect, post-decode stream error, and the reconnect/dict-rotation protocol-error paths) now honors `deliver_batch`'s "consumer gone" return and stops instead of reconnecting — a re-roast caught that the first fix only covered the disconnect path; (C) `decode_message` bounds text frames by `read_limit` (not just the binary decompress path), since `WsTransport` is public and injectable; (D) `classify_protocol` treats a permanent `InvalidRequest` as fatal rather than reconnecting forever, while unknown error names stay transient.

### M5 — Replay/live engine

- [x] Build an independent synchronous replay model and normalized test event type. Do not reuse production filter, batch, retry, or engine logic. (`tests/jetstream_engine.rs`: the `oracle` function reimplements windowing/filtering/dedup/cutover over the normalized `Me` event type; it calls no production filter, batch, retry, or engine code.)
- [x] Join planner, archive workers, ordered batching, and live tail. (`engine.rs`: `Engine::run` drives `replay_archive` (concurrent `buffered` segment downloads, order-preserving) then a `LiveBridge` over `LiveConsumer`; `ArchiveSource`/`EngineSink` traits seam the archive and sink.)
- [x] Pin the first sealed tip and cut over at `max(S, last_processed_seq)`. (`fetch_max` pins `sealed_tip_seq`; `resume_from = tip.max(processed).saturating_add(1)` sets `LiveCursor::Resume`; `cutover_overlap_dedups_boundary` proves no boundary double-delivery.)
- [x] Implement snapshot-only completion. (`config.snapshot_only` returns after replay; `snapshot_only_never_dials_live` asserts the live tail is never dialed.)
- [x] Re-enter archive replay on cutover `CursorTooOld`. (`LiveBridge` maps a cutover `CursorTooOld` to `LiveOutcome::Backfill`; `repeated_cursor_too_old_rebackfills` proves re-plan → replay → successful cutover with a grown tip.)
- [x] Bound no-progress recovery cycles. (`max_rebackfill_stalls` counts stalls where neither `processed` nor `tip` advanced, returning fatal `NoProgress`; `rebackfill_stall_returns_no_progress` proves the bound.)
- [x] Expose atomic stats and make task cleanup observable in tests. (`StatsHandle` over `AtomicU64`/`AtomicUsize`; `WorkerGuard` makes `active_downloads()` observable; `stats_reflect_progress_and_mutation` checks the snapshot.)
- [x] Test native task cancellation and WASM future/listener cleanup. (Native: `cancellation_cleans_up_workers` drives `tokio::join!` and asserts `active_downloads()` peaks then returns to zero; WASM future/listener cleanup deferred to the M6 headless browser suite alongside the browser transport work.)
- [x] Add structured property tests, small exhaustive partition/schedule checks, and deterministic interaction swarms against the independent model. (`engine_matches_oracle_snapshot` and `engine_matches_oracle_with_cutover` proptests drive random worlds/splits/filters/schedules through both the engine and the oracle under a paused clock.)

Acceptance: model tests prove ordered, duplicate-free delivery across pagination, parallel completion, retries, sparse filters, cutover overlap, seq gaps, repeated `CursorTooOld`, cancellation, and server mutation. **Met.**

M5 notes: `engine.rs` adds an `Engine<A, W, D>` that joins the sealed-archive replay (`ArchiveSource` — concurrent `buffered` downloads that preserve plan order and flush recoverable row drops in place) with the live tail (`LiveBridge` over the M4 `LiveConsumer`). The sink is a two-method `EngineSink` (`deliver` + `recoverable`) rather than the M4 `DeliverySink`, because `DeliverySink`'s "an Err is always terminal" contract conflicts with in-order recoverable errors; a fatal error is `Engine::run`'s return value only and is never delivered (the crate `Error` is not `Clone`). Cutover pins the first sealed tip and resumes the live cursor at `max(tip, last_processed_seq) + 1`. A cutover `CursorTooOld` re-enters archive replay, bounded by `max_rebackfill_stalls` (fatal `NoProgress` on repeated no-advance). `tests/jetstream_engine.rs` proves the acceptance list against an independent synchronous oracle over a normalized event type, plus two proptests; correctness holds under out-of-order download completion, sparse filters, sequence gaps, boundary overlap, server mutation across re-plans, and cancellation with observable worker teardown. The suite is gated `#![cfg(feature = "jetstream")]` (auto-discovered, matching `jetstream_archive.rs`).

### M6 — CLI, WASM demo, documentation, and smoke test

- [ ] Add `shrike jetstream` with JSON/stats modes and environment-only secret default.
- [ ] Keep the legacy `connectJetstream` WASM export and demo. Add a separate v2 export, such as `connectJetstreamV2`, backed only by `shrike::jetstream`.
- [ ] Add a v2 live demo for `jetstream.us-east.bsky.network` to `wasm/index.html` and `wasm/README.md`, with optional bounded archive replay.
- [ ] Accept a replay key for the browser session without persisting it or adding it to the URL. Never embed a long-lived key in checked-in HTML, JavaScript, WASM, or examples.
- [ ] Show v2 sequence cursors, event kinds, replay/cutover progress, cancellation, clear errors, and compression fallback in the demo.
- [ ] Test the v2 binding and UI in a local headless browser: live frames, bounded replay, CORS/header errors, cancellation, listener cleanup, and compression fallback.
- [ ] Add public rustdoc and a minimal README example.
- [ ] Document cursor persistence with host identity, marker folding responsibility, snapshot semantics, resource knobs, and recoverable/fatal handling.
- [ ] Add an ignored/explicit smoke target or documented command that requires both a host and `JETSTREAM_API_KEY`.
- [ ] When production is reachable, run small filtered live and bounded snapshot tests from the CLI and browser. Record no payloads or credentials.

Acceptance: compare the CLI with `cmd/client` against a local server. The browser demo runs v2 live and user-authorized bounded replay without changing the legacy binding or storing a key. Headless tests cover UI state and cleanup. `just test` and `just check` never run production smoke tests.

### Deferred post-flight performance work — not part of current completion

- Benchmark shared-slab records, copied records, lazy generic JSON, and typed decode.
- Measure block decode scaling, native worker strategy, browser main-thread latency, Web Workers, sparse fetch concurrency, range stripes, allocations, and memory high-water marks.
- Tune target-specific defaults and compare Rust with Go using the same host, filter, snapshot, and network path.
- Add higher-level typed adapters only after the record ownership contract is stable.

Apply low-risk efficiencies now. Do not set defaults or make performance claims from airplane-network measurements.

## Verification strategy

Automated tests are offline and hermetic. Test the replay contract with independent observations. Give each test layer a distinct job; repeating weak assertions adds little value.

### Verification work tracker

- [ ] Implement the test-only normalized event representation and independent synchronous replay model.
- [ ] Add a reviewed Go fixture generator, provenance/hash manifest, and compact checked-in cross-language corpus.
- [ ] Implement the declarative local HTTP/WebSocket server, deterministic gates, and request/fault ledger.
- [ ] Run shared golden/model/transport conformance cases on native and WASM.
- [ ] Add the focused unit, boundary, differential, property, exhaustive-schedule, and regression cases described below.
- [ ] Add short deterministic interaction swarms and a larger reproducible scheduled seed sweep.
- [ ] Add semantic fuzz targets, real-shaped seeds, strict resource limits, artifact retention, and regression promotion.
- [ ] Add local native CLI and headless-browser end-to-end acceptance gates.
- [ ] Add resource/cancellation instrumentation and prove configured high-water/cleanup bounds.
- [ ] Run an initial mutation campaign. Fix or document every oracle gap it finds.
- [ ] Add focused `just` recipes and CI tiers. Keep the default loop fast and offline.

### Principles

- **Test contracts, not line counts.** Name the bug class or invariant each test protects. Coverage finds untested code; it is not a release target.
- **Use independent oracles.** Derive expected events from a small model or a pinned Go manifest, never from Shrike code under test.
- **Test public paths.** Unit-test parsers, then test archive-to-live behavior through the public client over local HTTP and WebSocket servers.
- **Prove faults fired.** Give each injected fault an ID and hit counter. Fail if the expected fault or transition did not occur.
- **Control concurrency.** Use barriers, gated transports, paused time, acknowledgements, and fixed completion orders. Use wall-clock sleeps only in real-timer acceptance tests.
- **Reproduce random failures.** Record the seed, swarm axes, minimized action script, target, and limits. Shrink property failures.
- **Check bounds and cleanup.** Track requests, attempts, tasks, listeners, queue peaks, in-flight bytes, and decode limits as well as output.
- **Check native/WASM parity.** Run portable fixtures and model cases on both. Use a browser for Fetch, CORS, WebSocket, yielding, and listener cleanup.
- **Keep production opt-in.** Only explicit, bounded CLI/browser smoke tests use external services.
- **Keep every finding.** Add a focused regression test for each bug. Add escaped fuzz/property/swarm inputs to the permanent corpus.

### Risk-to-oracle map

| Risk | Strongest primary oracle | Supporting techniques |
|---|---|---|
| Segment/block wire incompatibility | Pinned Go-produced bytes plus independently recorded normalized events and hashes | Golden, differential, fuzz, boundary unit tests |
| Archive/live semantic mismatch | Same logical event history encoded independently as archive rows and live envelopes | Differential integration, property tests |
| Loss, duplication, reordering, or bad cutover | Simple sequential replay model over a generated logical history and cursor script | Model/property tests, schedule permutations, end-to-end acceptance |
| Retry, mutation, or generation handling | Scripted local server request ledger plus final byte/event equivalence | Fault injection, integration tests, swarms |
| Filter or marker loss | Small predicate model over logical events before wire encoding | Truth-table unit tests, properties, archive/live differential |
| Unbounded resource use or leaked work | Instrumented transports/queues/decoders with hard high-water assertions | Boundary tests, cancellation tests, compression-bomb fuzzing |
| Credential disclosure | Complete local request/redirect/error/log ledger that treats the key as a forbidden byte string | Security integration tests, formatting tests, browser tests |
| Target-specific divergence | Identical corpus manifest and scenario outcomes on native, Node-hosted WASM, and a real browser | Cross-target conformance and browser acceptance |
| Demo/API usability regressions | Public API/CLI/WASM binding driven as a consumer would use it | Compile tests, local end-to-end and UI acceptance tests |

### Test architecture and independent evidence

Build four shared test components:

1. **Logical replay model.** A small synchronous interpreter consumes events, filters, snapshot bounds, reconnect cursors, and faults. It returns expected events, batches, cursor, terminal class, and request limits. It must not call production planner, filter, decoder, batch, retry, or engine code.
2. **Cross-language corpus.** A Go generator emits small blocks, segments, dictionaries, proposal-0015 frames, plan pages, expected events, and a manifest with commit and file hashes. Commit outputs under `testdata/jetstream/`. Default tests do not require Go or a nearby checkout.
3. **Scripted protocol server.** One local fixture serves XRPC HTTP, ranged objects, dictionaries, and WebSockets. Scripts control bytes, gates, disconnects, status, headers, CORS, ETags, and live frames. A ledger records requests, concurrency, and fault hits.
4. **Instrumented host transports.** In-memory transports run engine/model cases quickly. Apply one conformance contract to native, browser, and caller-supplied WASI transports. Also test real sockets and browser APIs.

Keep expected data out of production DTOs. Normalize actual and expected events to seq, kind, DID, collection/rkey/rev, payload bytes/hash, and timestamps. Compare exact logs and folded state; folded state can hide missing updates or markers.

### Test tiers and gates

| Tier | Contents | When it runs |
|---|---|---|
| Fast/default | Unit, golden, focused regressions, modest property cases, portable integration, native local end-to-end | Every `just test`/`just check` and PR |
| WASM default | `wasm32` compile plus shared corpus/model tests in `wasm-bindgen-test`'s Node runner | Every PR; add it to the documented full check |
| Browser acceptance | Local cross-origin HTTP/WebSocket fixture and built demo in a real headless browser | CI and before release; no production host |
| Extended deterministic | Larger property counts, schedule permutations, interaction swarms, cancellation sweep, all target adapters | Scheduled CI and before release |
| Fuzz | Short seeded parser campaigns, then longer continuous/nightly campaigns with artifact retention | Short pre-merge where affordable; scheduled/continuous for depth |
| Targeted mutation | Curated realistic client bugs run against the relevant oracle tier | After the suite stabilizes, scheduled and before major release |
| Production smoke | Tiny filtered live tail and strictly bounded replay via CLI/browser | Manual opt-in only with explicit host/key |

Add `just test-jetstream`, `just test-jetstream-long`, and `just test-jetstream-browser`. Keep `just check` deterministic and fast. Set time budgets from local and CI measurements.

### Unit and boundary tests

Use table-driven tests for small pure functions:

- filter kind × DID × exact/wildcard collection behavior, especially marker pass-through;
- config conflicts, counts, syntax, cursor domains, host normalization, TLS policy, and checked integer conversions;
- proposal-0015 message/error dispatch, pre-upgrade XRPC errors, and stable error classification;
- Jiff RFC 3339/Unix-microsecond boundaries, offsets, precision, minimum/maximum supported instants, and rejected timestamps;
- header/footer/index sizes, offsets, checksums, length prefixes, kind-7 (create-resync) mapping, sentinel collection ids in the footer index, indexed/witnessed fallback, and malformed-row isolation;
- pagination progress, retry eligibility, `Retry-After`, backoff caps, `Content-Range`, ETag/If-Range, and no-progress accounting;
- batch partial/full flush, last-cursor semantics, inclusive-cursor deduplication, and cancellation precedence.

Test zero, one, limit−1, limit, limit+1, and integer maxima. Skip tests for trivial getters, setters, derived traits, and error prose. Test serialization only when wire shape, omission, tags, redaction, or compatibility matters.

### Golden and differential tests

- Decode every pinned Go raw block and whole segment and compare the complete normalized event log, segment metadata, checksum, and payload hashes with the manifest.
- Include every durable kind, sentinel collection ids (`$account`/`$identity`/`$sync`), empty fields, sparse/whole plans, dictionary frames, long valid identifiers, and malformed neighboring rows.
- Run the same zstd dictionary/frame/error corpus through native `zstd` and WASM `ruzstd`; accepted output and rejection class/limit behavior must agree even if exact error text differs.
- Encode one logical history into both archive and live representations using fixture code independent from Shrike; after normalization and filtering, outputs must be identical.
- Check live JSON record conversion to canonical DAG-CBOR against Go-produced CBOR/CID pairs and existing Shrike strict decoding.
- Regenerate the corpus only through a reviewed command. The manifest diff shows reference commit, format, output, and hash changes.

Keep golden files small. Do not commit production captures, credentials, large segments, or unstable debug/error snapshots.

### Property and model-based tests

Use `proptest` to generate valid logical scenarios:

- non-contiguous increasing sequences and all event kinds;
- exact/wildcard filters and matching/nonmatching markers;
- segment/block boundaries, sparse/whole entries, pagination (including empty pages), and sealed tips;
- batch sizes, partial flushes, inclusive reconnect overlap, live gaps, and cursor-too-old re-backfill;
- bounded transient/permanent fault scripts and worker completion orders.

The core properties are:

- actual output exactly equals the independent sequential model;
- delivered sequences strictly increase; gaps are allowed; no matching event is lost or duplicated;
- changing batch size, archive partitioning, page boundaries, legal worker concurrency, or completion order does not change concatenated output;
- stop at cursor `C`, persist it, and resume: output equals one uninterrupted run after boundary deduplication;
- archive-only and live-only encodings of the same logical history filter and normalize identically;
- cutover and every successful re-backfill start strictly after the last processed seq and never rewind observable output;
- retry and no-progress counters never exceed configuration, and permanent errors are never retried;
- cancellation has one terminal outcome and leaves no queued delivery after completion;
- all size/offset arithmetic either produces a valid in-bounds layout or a bounded error without wrapping.

For small histories, enumerate page splits, archive/live cut points, and worker completion orders. Save minimized failures as regression cases.

### Local integration and fault-injection tests

Drive the public native client against the scripted server. Test each fault alone before testing combinations:

- plans: multiple/empty pages, sparse and whole modes mixed, overlap, malformed bounds, cursor regression, changing sealed tip, and non-advancing continuation;
- HTTP bodies: ignored ranges, invalid/missing `Content-Range`, wrong lengths, early EOF, trailing bytes, slow/dribbled bodies, mid-body disconnect/resume, and oversized declared/observed bodies;
- object generations: missing ETag, ETag changes between probe/parts, stale If-Range, clean whole-download restart, and refusal to splice generations;
- retry: 429 with both `Retry-After` forms, eligible 5xx, transport timeout, permanent 4xx, per-part versus whole-operation budgets, and backoff cancellation;
- live: text/binary frames, ping/pong/close, malformed/control/info/error frames, duplicate reconnect boundary, seq vacancy, future/old cursor, consumer-too-slow, and reconnect exhaustion;
- compression: initial dictionary failure, corrupt/oversized frame, rejected/stale dictionary, rotation, refetch, bounded decode, and uncompressed fallback;
- authentication: archive endpoints receive exactly one scoped authorization header; live/dictionary/foreign redirects/errors/logs never receive or reveal it;
- cancellation: pause at each await boundary—plan, body read, range worker, decode handoff, blocked output, partial batch, reconnect timer, dictionary fetch, and live read—then require bounded shutdown and no live work.

Release gated workers in forward, reverse, and selected mixed orders. Check exact request/attempt counts, peak in-flight work, output order, and cleanup. An error alone does not prove retry bounds or task cleanup.

### Swarm and schedule testing

Use deterministic feature swarms for interaction bugs. Enable each axis with 50% probability, require one non-default axis, and record `seed + axes + action script`.

Axes: empty pages, sparse/whole plans, block size, filters, markers, seq gaps, duplicate boundaries, completion order, queue limits, range fallback, ETag rotation, truncation, 429/5xx, dictionary rotation, `CursorTooOld`, slow consumers, and cancellation phase. Run a short PR swarm and a large scheduled sweep. Count fault and transition hits to reject vacuous runs.

Generate swarms at the logical/protocol level. Leave byte corruption to fuzzing.

### Fuzzing

Extend the existing `cargo-fuzz` setup and seed generator. Use semantic checks, not only panic checks:

- **segment container:** arbitrary header/footer/index/frame bytes; accepted layouts stay within the input and configured limits, whole versus ranged readers agree, and reinspection is stable;
- **columnar block:** malformed lengths/counts/UTF-8/syntax and valid Go seeds; accepted rows satisfy structural invariants and alternate decode paths agree;
- **zstd:** dictionaries, frames, truncations, high-window frames, and compression bombs; decoder never exceeds configured window/output/work limits;
- **live framing:** arbitrary text/binary proposal-0015 and pre-upgrade errors; accepted frames normalize stably and never bypass size limits;
- **JSON-to-DAG-CBOR:** structured atproto JSON; canonical encode/decode/re-encode is a fixed point and known Go CID pairs agree;
- **HTTP metadata:** plan/error bodies, ETag, `Content-Range`, `Retry-After`, and numeric boundaries; parsing is panic-free, bounded, and canonical where applicable;
- **filters:** arbitrary structured events/filters; production predicate equals a simple test-only predicate;
- **engine scripts:** small arbitrary sequences of plan pages, decoded events, live frames, disconnects, and cancellations; output/termination equals the logical model with bounded steps.

Seed with golden files, boundary cases, and prior failures. Bound per-input time and memory. Keep CI artifacts and promote findings to regression tests. Do not fuzz through network servers.

### End-to-end and acceptance tests

Run a few broad tests through public APIs:

1. Native client: replay local whole and sparse pages, then cut over to live with a duplicate, seq gap, dictionary rotation, reconnect, markers, and cancellation. Compare the log and cursor with the model.
2. Recovery: disconnect and return `CursorTooOld`, extend the sealed archive, replan/re-backfill, and cut over again. Prove no loss/duplication and bounded no-progress termination.
3. Native CLI: run `shrike jetstream` against the local server in JSON and stats modes; validate exit status, cursor/progress fields, stderr separation, cancellation, and absence of secrets.
4. Browser client/demo: from another local origin, test preflight, exposed headers, Fetch streaming, WebSocket subprotocol, compression fallback, progress UI, session keys, cleanup, and the legacy binding.
5. Host adapter: run the portable conformance suite through at least one caller-injected transport representative of WASI/embedded use.

The production smoke runs a small filtered live tail and bounded replay against `jetstream.us-east.bsky.network`. It checks deployment integration, not correctness, and never replaces local gates.

### Resource, concurrency, and platform checks

- Use small test limits to hit queue, response, decompression, retry, and concurrency bounds without large allocations.
- Reject oversized declarations before allocation. Enforce observed-byte limits when peers lie or stream.
- Track compressed bytes, decompressed bytes, queued batches/events, active requests/decoders/tasks/listeners, and cooperative-yield counts with test instrumentation.
- On WASM, test 32-bit conversions and yielding without reordering. Run pure tests in Node and transport/CORS/lifecycle tests in a headless browser.
- Repeat native cancellation and close races under varied schedules. Add `loom` only if custom atomic or lock-free code needs it, and request approval first.
- Keep correctness gates for memory and concurrency. Defer throughput and RSS gates.

### Targeted mutation testing

After the oracle is stable, test its detection power with a small reviewed mutation set. Do not target a global mutation score. Include:

- changing an exclusive cursor boundary to inclusive or removing reconnect deduplication;
- dropping marker events when a collection filter is active;
- emitting worker completion order instead of sequence order;
- advancing the persisted cursor before delivery succeeds;
- ignoring ETag/If-Range changes and splicing object generations;
- retrying permanent errors or removing retry/no-progress limits;
- forwarding archive authorization to dictionary/live/redirect targets;
- removing decompression/output limits or cancellation cleanup;
- skipping `CursorTooOld` re-backfill or rewinding below the delivered cursor.

Record which tier kills each mutant. A survivor marks an oracle gap. Start with hand-written patches. Adding `cargo-mutants` to repository or CI tooling needs approval.

### Tests intentionally not written

- one assertion per trivial getter, builder setter, enum conversion, or derived trait;
- snapshots of internal structs, task ordering, debug formatting, or complete error prose unless that text is a public/security contract;
- mocks that duplicate the production algorithm and then assert their own configured return values;
- redundant parser cases at unit, integration, and end-to-end layers without a distinct layer-specific risk;
- probabilistic tests without printed seeds, shrinking/reproduction instructions, anti-vacuity assertions, and bounded runtime;
- tests whose success depends on wall-clock sleeps, public service availability, production event contents, or a developer's adjacent Jetstream checkout;
- giant fixtures when a minimal artifact exercises the same format boundary;
- benchmarks disguised as correctness tests during this phase.

Before adding a test, ask: what bug does it catch, is the expected result independent, and is this the cheapest useful layer? Skip it if those answers are unclear.

## Performance-ready design constraints

Preserve these properties before tuning:

- decode from borrowed/shared byte ranges and materialize JSON only on request;
- keep codec, transport, scheduling, and ordered emission behind narrow seams;
- stream bodies and frames instead of requiring whole-response copies;
- bound queues and use backpressure rather than unbounded task creation;
- reuse decoder contexts and allocation buffers where ownership stays clear;
- avoid trait-object or boxed-future dispatch inside per-row decode loops;
- keep exact filtering cheap and after structural validation;
- keep logging off hot paths and expose progress through `Stats`;
- keep target-specific concurrency behind an API that can later use native workers or Web Workers.

Defer Criterion, throughput, and RSS work. Keep correctness tests for allocation and size bounds.

## Resolved decisions

1. **Package compatibility:** add an independent `shrike::jetstream` v2 package. Leave the legacy implementation untouched.
2. **Target scope:** ship archive and live support for native and WASM. Provide built-in browser/JS-hosted transports and public host-transport injection for WASI/embedded runtimes.
3. **Delivery scope:** implement correctness and recovery now. Keep performance seams and defer tuning.
4. **Date/time:** use BurntSushi's Jiff for RFC 3339 parsing/formatting and Unix-microsecond conversion.

## Dependency recommendations

These additions require explicit approval before implementation:

| Crate | Recommended configuration | Why |
|---|---|---|
| `jiff` 0.2 | `default-features = false`, `features = ["std", "perf-inline"]` | Approved. Handles RFC 3339, offsets, and edge cases without an unused timezone database |
| `zstd` 0.14, native only | `default-features = false`; decode APIs only | Upstream zstd 1.5.7, prepared dictionaries, dictionary IDs, output caps, `WindowLogMax`, and fast native decode |
| `ruzstd` 0.9, WASM only | default decode features; no dictionary building | Pure Rust, fuzzed, tagged-dictionary decode, streaming output, window caps, and no C toolchain |
| `twox-hash` 2.1 | `default-features = false`, `features = ["xxhash3_64"]` | Small, pure Rust, native/WASM, and implements the segment XXH3-64 checksum |
| `bytes` 1 | default `std` feature | Shared immutable buffers and O(1) slices for block-slab/record ownership |
| `secrecy` 0.10 | no serde feature | Redaction and zeroization reduce accidental key exposure |

Reuse Shrike's existing `reqwest`, `tokio-tungstenite`, `gloo-net`, `futures`, `url`, `serde`, `serde_json`, `thiserror`, and platform/timer dependencies.

Hide both decoders behind a private `Decompressor` interface and require the same golden/error behavior. Use upstream zstd on native and pure-Rust `ruzstd` on WASM. A 2026-09-18 `zstd` WASM check reached `zstd-sys` but failed because Nix clang injected the host-only `-fzero-call-used-regs=used-gpr` flag. This was a toolchain error, not a codec failure.

Isolated `wasm32-unknown-unknown` checks passed for `ruzstd` 0.9, Jiff 0.2 with `std,perf-inline`, `twox-hash` 2.1 with XXH3-64, and `secrecy` 0.10. M0 still requires corpus and browser tests.

Do not start with `structured-zstd`; its `0.0.x` API is too young for untrusted input. Revisit it or C-backed zstd during tuning without changing the engine API.

Do not add general backoff, range-parser, executor, or logging crates. Existing code or dependencies cover these needs.

## Known risks

- **Memory amplification:** blocks may decompress to 1 GiB. Design limits, shared slabs, backpressure, and prefetch bounds together.
- **Safe zero-copy API:** Rust cannot store decoded borrowing values beside their owner without unsafe/self-reference. Expose owning bytes and borrow only during accessor calls.
- **HTTP generation safety:** striped downloads can silently combine generations unless every part is pinned and validated.
- **False-positive planning:** omitting exact post-decode filtering corrupts consumer views, especially around marker events.
- **Cursor ambiguity:** values at or above `10^15` are timestamps on the live endpoint. High-level sequence and timestamp resume APIs must not blur this distinction.
- **Credential propagation:** generic bearer middleware or redirects can leak the archive key to public/foreign endpoints.
- **Compression bombs/corruption:** enforce limits during decode, before full output allocation.
- **Lexicon/codegen drift:** the subscription main def is intentionally skipped today. Generated associated DTOs must be covered by a regeneration check.
- **WASM memory and responsiveness:** browsers have limited linear memory and usually decode on one thread. Use frame ranges, checked `usize` conversions, lower limits, backpressure, and yields.
- **WASM host fragmentation:** WASI has no universal WebSocket. Keep a tested host transport API and a precise target matrix.
- **Browser CORS and credentials:** replay needs auth and exposed range/generation headers. The us-east proxy provides them; direct deployments need equivalent CORS. The demo accepts session-only keys and ships none.
- **Reference evolution:** record the Jetstream commit in fixtures and rerun the cross-language corpus when updating lexicons or segment version support.

## Completion definition

This plan is complete when:

- all M0–M6 acceptance criteria pass on the applicable native and WASM target matrix;
- the verification tracker is complete and each release risk has a passing independent oracle;
- `just build`, `just test`, `just test-wasm`, `just lint`, `just check`, and local browser acceptance pass;
- the initial fuzz campaign passes; property/swarm failures reproduce; resource tests prove memory, concurrency, and cancellation bounds;
- the initial mutation campaign kills each required mutant or records the remaining oracle gap;
- normal tests make zero external requests;
- production checks are explicit, bounded, credential-safe, and user-invoked;
- legacy `/subscribe` remains compatible;
- the legacy client implementation has no diff;
- the legacy WASM binding remains available and the v2 demo passes browser lifecycle tests;
- public docs explain cursor locality, inclusive replay/dedup, marker semantics, secret scope, snapshot exclusion of the active segment, error continuation, and cancellation;
- no generated file is hand-edited and only the explicitly approved dependencies are added.
