# Jetstream v2 client design and implementation plan

Date: 2026-09-18

Status: revised after author review; dependency selection remains to approve

Shrike baseline: `56edf291116fe789e4af210b7872e19debe6ca73`

Jetstream reference baseline: `58c4d7f7a9130e53b40348ad3d1f7aafed0e4843`

## Work tracker

- [x] Read the Jetstream repository documentation, specifications, design notes, lexicons, client package, segment package, and example client.
- [x] Audit Shrike's existing legacy Jetstream client, XRPC client, DAG-CBOR implementation, lexicon generator, feature layout, native/WASM transports, and CLI.
- [x] Attempt a bounded production contract check against `jetstream.us-east.bsky.network`; both `planSnapshot` and `getZstdDictionary` reached the edge but returned HTTP 503 on 2026-09-18. No archive data was downloaded and no credential was logged.
- [x] Confirm package isolation, native/WASM scope, correctness-first delivery, and deferred performance measurement.
- [x] Confirm that the proxy serving `jetstream.us-east.bsky.network` currently provides the CORS behavior needed by the browser demo; direct/self-hosted deployments still own this requirement until Jetstream gains native CORS support.
- [x] Select Jiff as the date/time library.
- [x] Define a risk-driven native/WASM verification strategy with independent oracles, deterministic faults, cross-language fixtures, properties, swarms, fuzzing, acceptance tests, and targeted mutation checks.
- [ ] Approve the remaining libraries in [Dependency recommendations](#dependency-recommendations).
- [ ] Add generated `network.bsky.jetstream` DTOs without hand-editing generated files.
- [ ] Implement the segment and block decoders with limits, golden fixtures, fuzzing, and checksum verification.
- [ ] Implement the authenticated planner and robust archive download transports.
- [ ] Implement proposal-0015 live streaming, optional dictionary zstd, and reconnect behavior.
- [ ] Implement the ordered archive-to-live engine, batching, cursor semantics, and re-backfill.
- [ ] Add the `shrike jetstream` example/diagnostic command.
- [ ] Extend the existing WASM demo with a separate Jetstream v2 binding and live/bounded-replay UI while preserving its legacy Jetstream path.
- [ ] Complete offline native/WASM integration, property, fault, fuzz, and compile coverage.
- [ ] Run the opt-in production smoke test, then `just check`.
- [ ] Document the public API, migration boundary, limitations, and operational guidance.

## Outcome

Add a Rust client for native and WASM targets that presents one ordered stream of Jetstream v2 events whether they come from sealed archive segments or the live WebSocket. It must support full-network replay, exact filtering, safe cursor persistence, archive-to-live cutover, recovery when a live cursor ages out, and all four durable event kinds.

The client will be a dedicated `shrike::jetstream` API and implementation. Shrike's existing `streaming::Client::jetstream()` and its types, transport, behavior, and tests remain untouched as the backwards-compatible client for the wire-frozen legacy `/subscribe` endpoint. The new package must not silently redirect, wrap, or share protocol state with it.

Correctness, bounded resource use, recovery guarantees, and native/WASM consistency are release requirements. The architecture must retain clear fast paths—shared record storage, streaming decode, bounded parallelism, and ordered reassembly—but extensive benchmarking, comparative performance analysis, and fine tuning are explicitly deferred until reliable high-speed networking is available.

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
- Add a CLI client suitable for examples, manual smoke tests, and throughput comparisons with the Go client.
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

The authoritative contract for this plan is the Jetstream tree at the commit above, especially:

- `README.md`, `docs/README.md`, `specs/client.md`, `specs/architecture.md`, `specs/invariants.md`, `specs/glossary.md`, `specs/gotchas.md`, `specs/mutation.md`, and `specs/oracle.md`.
- All documents under `specs/notes/`, with particular weight on the current segment format, Go client, filtering audit, active cold replay, proposal-0015 v2 subscription, endpoint rename, and sequence reuse notes.
- The oracle incident reports and mutation-testing material under `specs/oracle/` and `testing/mutation/`.
- The `network.bsky.jetstream.*` lexicons.
- Root client files `client.go`, `client_core.go`, `engine.go`, `options.go`, `event.go`, `errors.go`, `planner.go`, `filter.go`, `batcher.go`, `downloader.go`, `segmentfetch.go`, `decode.go`, `live.go`, `livedecode.go`, `typed.go`, and their tests.
- The `segment/` reader, block, header, footer, sentinel, compression, validation, golden, fuzz, and swarm implementations.
- `cmd/client`, which is the behavioral model for the Shrike CLI command.

Historical notes are useful rationale, but the current lexicons, `docs/README.md`, `specs/client.md`, and production Go code win where history differs.

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

- `src/xrpc::Client` buffers raw responses, caps them at 512 MiB, attaches its stored bearer to every request, and has no range/ETag streaming interface. Reusing it directly would risk sending the archive key to public endpoints and cannot implement robust 1 GiB segment downloads.
- `reqwest` already has its `stream` feature, and native `tokio-tungstenite`, browser `gloo-net`, Tokio, futures, URL, and strict DAG-CBOR support already exist behind features.
- Shrike's DAG-CBOR decoder is zero-copy, but its public `Value<'a>` borrows the input. A safe replay API therefore needs an owning record-byte abstraction rather than self-referential decoded values.
- The cached lexicons already contain `network/bsky/jetstream`, but `lexgen.json` does not generate the `network.bsky` package. Lexgen deliberately skips subscription client generation while still generating the subscription's associated object definitions.
- Generated API records expose `from_cbor`, but there is no common typed-decode trait. Raw record bytes are sufficient for a staged typed fast path.
- The current `wasm` feature intentionally excludes sync/backfill-style native work, so the new engine must not depend on those modules. Browser Fetch/WebSocket, CORS, cooperative scheduling, and 32-bit memory behavior differ from native transports.
- No universal WebSocket API exists across browser JavaScript, WASI, and arbitrary embedded WASM hosts. The portable engine therefore needs narrow transport traits plus first-party native and browser/JS-hosted implementations.
- The existing `wasm/` demo exposes `connectJetstream` through the legacy client and points it at the legacy `/subscribe` service. Preserve that API and example; add v2 under a separately named binding so the compatibility boundary stays visible.
- Jiff, zstd decoders, xxh3, shared byte storage, and secret wrappers are not direct Shrike dependencies. Repository policy requires approval before adding them; Jiff has been author-approved.

## Recommended architecture

### Public boundary

Add a new `jetstream` feature and `shrike::jetstream` module. Include it in both `full` and `wasm`. The protocol, filter, planner, decoder, state machine, event model, retry policy, and integrity checks are platform-neutral. Only HTTP, WebSocket, timers/spawning, and environment-secret discovery are platform adapters.

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

Internal modules may be combined while small; this layout describes responsibilities, not a requirement to create empty abstractions.

### Target and transport model

The supported matrix is:

| Target | Built-in transport | Contract |
|---|---|---|
| Native Tokio targets | `reqwest` + `tokio-tungstenite` | Full archive and live support; stream is `Send` where its inputs are `Send` |
| `wasm32-unknown-unknown` in browsers | Fetch + browser WebSocket through the existing WASM stack | Full archive and live support, subject to server CORS; cooperatively scheduled |
| JS-hosted WASM with compatible Fetch/WebSocket globals | Same WASM adapter | Supported and tested in at least one headless JS runtime |
| WASI or embedded hosts without browser Web APIs | Caller-supplied portable transports | Core replay/decoding works; the host supplies HTTP, WebSocket, timer, and secret access |

This distinction is necessary: WASI does not currently define a universal WebSocket interface. A public transport injection point makes the client usable there without tying Shrike to one component runtime. It must be narrow enough to implement from host callbacks and stable enough that the state machine has no platform conditionals.

Prefer associated-future transport traits over an unconditional `async_trait`/boxed-future boundary in hot paths. Do not impose `Send + Sync` on the platform-neutral core; require it on the native concrete client where available. Keep scheduling outside parsers and codecs so CPU work can later move to native worker pools or browser Web Workers without changing event or engine APIs.

Browser archive support has an external server requirement. Cross-origin responses must allow the caller origin and methods GET/POST/OPTIONS, accept `Authorization`, `Content-Type`, `Range`, and `If-Range`, and expose at least `ETag`, `Content-Range`, `Content-Length`, and `Retry-After`. The WebSocket must accept `xrpc.v1.json`. The proxy currently serving `jetstream.us-east.bsky.network` supplies this CORS behavior and is suitable for the explicit browser demo/smoke path. Direct and self-hosted Jetstream deployments must configure an equivalent proxy until Jetstream itself gains native CORS support. Add a startup error that identifies missing CORS/header visibility rather than misclassifying it as corrupt archive data.

### Generated protocol types

Add a `network.bsky` package to `lexgen.json`, run `just lexgen`, and use the generated request/response and event-object types where they fit. Do not edit generated output. The dedicated client still owns:

- proposal-0015 envelope dispatch;
- pre-upgrade HTTP error parsing;
- secret-bearing archive transport;
- ranged/streaming binary responses;
- segment decoding and orchestration.

The generated generic XRPC convenience functions are not the thick client's transport layer. Subscription generation remains outside this project unless using the generated associated object types exposes a concrete generator bug.

### Proposed Rust API

The exact names can change during implementation, but the semantic shape should be fixed before coding:

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

`api_key_from_env` is a native/host convenience. Browser callers must receive any key through their application's host configuration; the client must not imply that a compiled-in browser key can be kept secret.

Builder operations should cover:

- kinds, DIDs, and collections;
- exclusive `after_seq`, inclusive `before_seq`, snapshot-only mode, and pure-live resume cursor;
- maximum batch size and live partial-batch delay;
- archive decode concurrency, sparse block fetch concurrency, whole-segment prefetch, and range stripes;
- request attempt/backoff limits and size limits;
- optional archive API key;
- live dictionary compression, enabled by default;
- injectable portable transports for tests, WASI/embedded hosts, and advanced callers.

Use conservative target-aware defaults. Batch size 64 and a 20 ms live partial flush are semantic/latency defaults worth retaining. Native may begin with the Go concurrency and range values as provisional caps; WASM must use lower bounded async concurrency and periodically yield during large decode loops so it cannot monopolize the browser event loop. Record the defaults as provisional rather than claiming they are optimal before measurement.

`Client` should drive one event stream at a time. Dropping the stream or client must cancel tasks and close sockets; an explicit idempotent `close`/cancellation handle is useful if it can be expressed without making ordinary use awkward.

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

Use an enum rather than parallel optional payload fields so invalid combinations are unrepresentable. Treat segment kind 7 (`create-resync`) as a public commit/create, matching the reference client.

`Record` should own or share canonical DAG-CBOR bytes and expose:

- `as_cbor(&self) -> &[u8]`;
- lazy generic DAG-CBOR decode borrowing from `&self`;
- optional conversion to owned atproto JSON;
- lazy/cached CID calculation where the archive row did not carry a CID;
- a documented way to call generated `Type::from_cbor(record.as_cbor())`.

A `bytes::Bytes`-style sliced backing permits all records in an archive block to share one decompressed slab without unsafe or self-referential values. Live JSON is canonicalized once to DAG-CBOR so both paths expose the same record contract. Deletes have no record or CID. Hide the concrete backing behind `Record` so storage can change without breaking callers.

Do not make eager generic JSON materialization the only API: it dominates full-network replay cost. A later typed adapter can add a trait or caller-supplied decode function after the base record ownership and lifetime contract is proven.

`Batch` owns its events and reports the highest sequence with `last_cursor()`. It is the unit after which consumers should atomically persist progress. A seq-less `#info` frame is a separate `Delivery::Info` and never advances the cursor.

`Stats` should be a cheap point-in-time snapshot containing at least pages, sealed tip, planned-through seq, residual gap, delivered events, and last processed seq. Avoid a metrics-registry dependency.

### Error contract

Use a structured `Error` with an explicit `is_fatal()` classification. The stream may yield a recoverable error and continue; after a fatal error it must end. Preserve endpoint XRPC error names and HTTP status.

Fatal examples:

- invalid local configuration;
- rejected or malformed snapshot plan that prevents guaranteed progress;
- exhausted download/replan attempts for required archive work;
- non-advancing pagination or re-backfill beyond its bound;
- an archive/live cutover invariant that can no longer be satisfied;
- unsupported segment version or structural corruption when no safe retry/replan path remains.

Recoverable examples:

- a malformed row when valid sibling rows can still be delivered in order;
- a transient live read/dial failure while reconnect remains possible;
- dictionary fetch, negotiation, or decompression setup failure when uncompressed fallback works;
- advisory `#info`, which should normally be a `Delivery::Info`, not an error.

Never discard a successfully decoded prefix because a later row or block failed. Deliver the prefix, then the ordered error, then continue or terminate according to classification. Error formatting, `Debug`, tracing fields, URLs, and stats must never contain the API key.

## Protocol behavior

### Filters

The three filter dimensions are independent predicates and are AND-composed:

- `kinds`: commit, identity, account, sync; omitted/empty means all.
- `dids`: applies to every event kind; omitted/empty means all.
- `collections`: exact NSID or terminal `.*` namespace wildcard; applies only to commits.

Identity, account, and sync events bypass collection matching but still obey DID and kind filters. Therefore `collections=app.bsky.feed.post` alone includes matching commits plus all permitted DID-level markers. Commits-only requires `kinds=commit` too. Reject a collection filter combined with a non-empty kinds filter that excludes commit.

The planner is intentionally one-sided and may return false positives. Apply the same exact filter after every archive decode and live decode. Never trust bloom/planner output as exact.

Validate locally before I/O: no more than 4 kinds, 10,000 DIDs, or 100 collections; validate DID/NSID syntax and wildcard placement; reject the legacy `wanted*` vocabulary on the v2 API.

### Cursor model

- Jetstream v2 sequences are 1-based; `0` means “before the beginning”.
- Archive requests use `(afterSeq, beforeSeq]`.
- `subscribeEvents` replays inclusively from `cursor`; the client drops every `seq <= last_processed_seq`.
- An omitted cursor on a pure live subscription starts at the current tip.
- A v2 cursor `>= 10^15` is interpreted by the server as Unix microseconds, not a sequence. The high-level API should prefer explicit sequence cursor methods and offer timestamp resume only if it can be named distinctly.
- An old sequence cursor is rejected pre-upgrade as `CursorTooOld`.
- An old timestamp cursor is clamped and starts with seq-less `#info`/`OutdatedCursor`.
- A future cursor enters tip mode.
- Sequence numbers can jump across registered crash vacancies. Never require `next == previous + 1`.
- A cursor is local to a Jetstream server instance. Include the normalized host/instance identity in persistence guidance.
- Validate values against the lexicon/XRPC signed-integer ceiling (`i64::MAX`) before serialization.

### Snapshot planning

For archive replay:

1. POST `planSnapshot` with exact requested filters and bounds.
2. On the first successful page, pin `sealedTipSeq = S`.
3. Validate every plan entry: name, index, 16-char hex checksum, sequence range, known mode, and non-empty ordered/in-range block ranges.
4. Process entries in returned order. For later pages send `afterSeq = plannedThroughSeq` and `beforeSeq = S`, even if the caller omitted `before_seq`.
5. Treat `plannedThroughSeq` as coverage, not “last event returned”. Empty/sparse pages still advance.
6. Reject regression, movement of the pinned sealed tip, or a non-advancing page before completion.
7. Finish when `plannedThroughSeq >= S`.

Snapshot-only excludes the active unsealed segment by definition. A replay that continues live cuts over exactly once at `max(S, last_processed_seq)`.

### Archive downloads

For `mode=blocks`, expand inclusive block ranges carefully, fetch `getBlock?segment=...&blockIndex=...` with bounded concurrency, and reassemble results in plan/block order.

For `mode=segment`:

- probe range support and a strong ETag;
- require the ETag generation to equal the plan checksum when supplied by the server;
- expose a common internal `SegmentSource`/compressed-frame stream so download strategy is independent of segment parsing and ordered decode;
- use bounded parallel ranges with `If-Range`, a sequential streaming response, or metadata-plus-frame ranges according to target capabilities;
- validate 200/206 status, `Content-Range`, total length, overlap/gaps, response length, and ETag consistency;
- bound a segment at 1 GiB;
- on a generation change, discard only that attempt, replan/restart at most twice, and never splice bytes from different generations;
- honor bounded `Retry-After` for 429 and retry eligible 5xx/network failures;
- stream response bodies and decode per block instead of retaining multiple decoded segments.

On memory-constrained WASM, prefer fetching the header and footer/index ranges first, validating the generation, then fetching bounded compressed frame ranges. This avoids assembling a potentially 1 GiB segment in linear WASM memory. When Range or the required exposed headers are unavailable, use a bounded sequential response only if its advertised/observed size fits target limits; otherwise return an actionable capability/resource error. The native implementation may use wider range striping behind the same `SegmentSource` seam.

Use separate short-control and bulk-download request policies by default. The current general XRPC client's response buffering and timeout model is not suitable for the bulk path.

The plan checksum/ETag identifies a segment generation. After a whole download, parse and validate the header/footer and recompute the segment metadata checksum (xxh3 over `header[12..] || footer`) instead of treating transport success as integrity success.

### Segment and block decoding

A whole `.jss` segment has a 256-byte reserved header, magic `jss0`, version 1, compressed block frames before `FooterOffset`, and footer indexes at/after that offset. Each file block frame is prefixed by an 8-byte little-endian compressed length. `getBlock` returns only the raw zstd frame, without that prefix.

Validate header/footer offsets and counts before allocation or slicing. In particular, use checked arithmetic and reject offsets into the header, beyond `FooterOffset`, beyond file length, or inconsistent with block indexes.

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

Hard limits should initially match the reference: 262,144 rows and 1 GiB decompressed bytes per block. Check every aggregate length before slicing. Require all columns and blob regions to be consumed exactly; reject trailing or truncated data.

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

Use `indexed_at` as display time when nonzero, otherwise `witnessed_at`. Identity/account/sync payloads are upstream event DAG-CBOR. Commit create/update payloads are canonical record DAG-CBOR. A delete carries no record payload. Validate required/forbidden metadata per kind, syntax fields, payload CBOR, and record CID behavior.

Parallel workers may fetch and decode ahead, but one ordered reassembly stage is the only component allowed to emit. On single-threaded WASM these are bounded concurrent futures, not an assumption of OS threads. Long block loops must yield cooperatively at deterministic work intervals. Memory is bounded by concurrency, prefetch depth, compressed limits, decompressed limits, target address space, and batch ownership.

### Live WebSocket

Dial:

```text
/xrpc/network.bsky.jetstream.subscribeEvents
Sec-WebSocket-Protocol: xrpc.v1.json
```

Use repeated `kinds`, `dids`, and `collections` query parameters, plus cursor, optional `maxMessageSizeBytes`, and optional `zstdDictionary`. Do not request or negotiate `permessage-deflate`.

Uncompressed frames are proposal-0015 JSON:

```json
{"$type":"message","payload":{"$type":"network.bsky.jetstream.subscribeEvents#commit"}}
{"$type":"error","error":"ConsumerTooSlow","message":"..."}
```

Dispatch the payload union by exact `$type`; preserve unknown-type context in a bounded error. Parse pre-upgrade XRPC JSON bodies, especially `CursorTooOld`, `UnknownZstdDictionary`, and implemented `InvalidRequest`.

Apply a 32 MiB default live message/decompressed-frame ceiling, configurable downward/upward within a hard safe maximum. Ping/pong/close handling must comply with tungstenite behavior and cancellation.

Reconnect from the last processed sequence, not merely the last received frame. Because server replay is inclusive, always deduplicate `<= last_processed_seq`. Flush a pending partial batch before surfacing a live error or switching back to archive recovery.

### Dictionary zstd

Compression is an optimization and is enabled by default:

1. Fetch the current raw structured dictionary from `getZstdDictionary` without auth.
2. Parse and validate its embedded zstd dictionary ID.
3. Dial with `zstdDictionary=<id>`.
4. Treat each binary WebSocket message as one complete zstd frame and cap decompressed output before JSON parsing.
5. Reject binary frames when compression was not successfully negotiated and reject text data frames when the compressed mode contract requires binary.
6. On `UnknownZstdDictionary`, refetch once. If the fetch fails or returns the same rejected ID, fall back to an uncompressed dial.
7. On dictionary/decode setup failure, log a redacted diagnostic and fall back uncompressed. A malformed compressed data frame after a successful upgrade is a stream error, followed by bounded recovery.

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

When a live/cutover cursor is too old, flush any pending valid batch, restart archive replay exclusively after the last processed seq, pin a new sealed tip, and retry cutover. Bound consecutive cycles that neither advance `last_processed_seq` nor change the useful archive coverage; terminate fatally rather than spin.

The engine must not assume that a plan entry contains every sequence in its range, that a page contains events, or that the live cursor is adjacent to the sealed tip.

## Security and privacy

- Represent the archive key with a private redacting wrapper; implement only redacted `Debug`/`Display`.
- Accept the raw key, never a caller-built `Authorization` string.
- Add auth only in dedicated request constructors for `planSnapshot`, `getSegment`, and `getBlock`.
- Unit-test that the key is absent from dictionary, live upgrade, redirects, errors, logs, formatting, and injected-client state.
- Disable or strictly constrain cross-origin redirects for authenticated archive requests so a key cannot be forwarded to another host.
- Reject an archive key over cleartext except explicit loopback test/dev hosts. Do not infer that private RFC1918 networks are safe.
- Keep the CLI key in `JETSTREAM_API_KEY`; do not require it as a process-visible command-line argument.
- Treat browser bearer keys as extractable by end users. Document that long-lived privileged keys must not be embedded in public bundles; use a narrowly scoped/ephemeral key or a trusted proxy when the deployment's threat model requires secrecy.
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

Read archive auth from `JETSTREAM_API_KEY` by default. If an override is needed, prefer an environment-variable-name option over a raw key flag. JSON output must include Jetstream seq and all marker kinds. Stats output should include total events, events/sec, last cursor, sealed tip, planned through, and residual gap.

Ctrl-C and duration expiry are successful cancellation, not stream failure. Fatal errors produce nonzero exit; recoverable errors are printed to stderr and consumption continues.

The CLI is the only checked-in production smoke vehicle. Normal invocations default to a caller-provided/local host rather than silently pulling a full production archive.

## Implementation milestones and acceptance criteria

### M0 — Dependency and cross-target spike

- [x] Resolve package isolation, target, correctness, and performance-measurement scope.
- [x] Choose Jiff for date/time parsing and formatting.
- [ ] Approve the remaining dependency recommendations below.
- [ ] Verify both selected zstd implementations against the same dictionary/frame/error corpus, window/output limits, native build, `wasm32-unknown-unknown` build, and one WASI build.
- [ ] Confirm an xxh3 implementation against Jetstream golden checksums.
- [ ] Record dependency choices and approval in the implementing change.
- [ ] Capture/copy minimal Go-generated fixtures into `testdata/jetstream/` with provenance and generation instructions.
- [ ] Prove one full compressed block decode and one proposal-0015 dictionary frame in native and browser WASM tests.

Acceptance: dependency/API/target decisions are explicit; a tiny Rust spike decodes a Go golden block, verifies a Go golden checksum, and compiles/runs the portable codec on native and WASM without network access.

### M1 — Protocol DTOs and public value model

- [ ] Add `network.bsky` to lexgen configuration and regenerate with `just lexgen`.
- [ ] Add v2 filter/config validation and host normalization.
- [ ] Add event, payload, record backing, batch, info, stats, and error types.
- [ ] Implement atproto JSON-to-DAG-CBOR canonicalization for live records.
- [ ] Unit-test proposal-0015 envelopes, all payload variants, invalid unions, timestamp conversion, CID parity, and JSON/CBOR parity.
- [ ] Document legacy/v2 type separation.
- [ ] Add Jiff-backed exact conversion between live RFC 3339 timestamps and archive Unix microseconds.

Acceptance: every live lexicon example maps to the proposed event model, archive record bytes can be typed-decoded through existing generated APIs, and invalid states cannot be constructed through public builders.

### M2 — Segment/block decoder

- [ ] Decode raw `getBlock` frames with strict compressed/decompressed limits.
- [ ] Parse whole-segment header, footer, block index, length-prefixed frames, and checksum.
- [ ] Decode every event kind and exact filter it.
- [ ] Preserve valid sibling rows around recoverable row failures.
- [ ] Add Go golden block/segment cross-language tests.
- [ ] Add fuzz targets for header, footer, frame, decompression, column lengths, payload decode, and filter wildcard logic.
- [ ] Add property tests for overflow-free layout calculations and ordered/filter equivalence.

Acceptance: no malformed input can panic or allocate beyond configured bounds; golden output matches the reference implementation event-for-event.

### M3 — Planner and archive transport

- [ ] Build the reusable scripted local protocol server with deterministic gates, request/fault ledger, CORS controls, and anti-vacuity assertions.
- [ ] Implement scoped-auth `planSnapshot` calls and strict response validation.
- [ ] Implement pinned pagination and empty-page progress.
- [ ] Implement `getBlock` pooling with ordered reassembly.
- [ ] Implement streamed whole downloads, range probing, striping, ETag/If-Range, resume, integrity validation, and generation restart.
- [ ] Add bounded Retry-After-aware retries for network, 429, and eligible 5xx failures.
- [ ] Add cancellation and clean worker shutdown.
- [ ] Implement the browser range/stream capability path and clear CORS/resource errors.

Acceptance: entirely local native and browser-WASM fault servers can exercise whole, sparse, ranged, non-ranged, interrupted, rate-limited, generation-changing, corrupt, truncated, oversized, CORS-constrained, and non-advancing cases with deterministic results and no secret leakage.

### M4 — Live v2 transport

- [ ] Dial with the exact path and `xrpc.v1.json` subprotocol.
- [ ] Parse proposal-0015 message and error frames.
- [ ] Parse pre-upgrade XRPC errors.
- [ ] Implement cursor deduplication, reconnect/backoff, partial batch flush, ping/pong/close, and cancellation.
- [ ] Fetch/validate zstd dictionaries unauthenticated and decode bounded binary frames.
- [ ] Implement rejected/stale dictionary recovery and uncompressed fallback.
- [ ] Implement native and browser/JS-hosted WebSocket adapters with the same frame/error fixtures.

Acceptance: local native and headless-browser/JS WebSocket fixtures cover text and compressed frames, every event/info/error kind, inclusive duplicates, gaps, future/old cursor paths, slow-consumer terminal errors, malformed frames, disconnects, and dictionary rotation.

### M5 — Replay/live engine

- [ ] Build the independent synchronous replay model and test-only normalized event representation without reusing production filtering, batching, retry, or engine logic.
- [ ] Join planner, archive workers, ordered batching, and live tail.
- [ ] Pin the first sealed tip and cut over at `max(S, last_processed_seq)`.
- [ ] Implement snapshot-only completion.
- [ ] Re-enter archive replay on cutover `CursorTooOld`.
- [ ] Bound no-progress recovery cycles.
- [ ] Expose atomic stats and make task cleanup observable in tests.
- [ ] Test native task cancellation and WASM future/listener cleanup.
- [ ] Add structured property tests, small exhaustive partition/schedule checks, and deterministic interaction swarms against the independent model.

Acceptance: deterministic model tests prove no duplicates and ordered delivery across pagination, parallel completion, retries, sparse filters, cutover overlap, sequence vacancies, repeated `CursorTooOld`, cancellation, and server mutation scenarios.

### M6 — CLI, WASM demo, documentation, and smoke test

- [ ] Add `shrike jetstream` with JSON/stats modes and environment-only secret default.
- [ ] Keep the existing legacy `connectJetstream` WASM export and demo path unchanged; add a distinctly named v2 export such as `connectJetstreamV2` backed only by `shrike::jetstream`.
- [ ] Update `wasm/index.html` and `wasm/README.md` with a Jetstream v2 live demo using `jetstream.us-east.bsky.network`, plus an optional small, explicitly bounded archive replay.
- [ ] Let a user provide a replay key for the current browser session without persisting it or placing it in the URL; never embed a long-lived `JETSTREAM_API_KEY` in checked-in HTML, JavaScript, generated WASM, or examples.
- [ ] Show v2 sequence cursors, event kinds, replay/cutover progress, cancellation, actionable errors, and dictionary-compression fallback in the demo.
- [ ] Add local headless-browser coverage for the v2 binding and UI lifecycle, including live frames, bounded replay, CORS/header failures, cancellation/listener cleanup, and compressed-to-uncompressed fallback.
- [ ] Add public rustdoc and a minimal README example.
- [ ] Document cursor persistence with host identity, marker folding responsibility, snapshot semantics, resource knobs, and recoverable/fatal handling.
- [ ] Add an ignored/explicit smoke target or documented command that requires both a host and `JETSTREAM_API_KEY`.
- [ ] When the service is reachable, run a tiny filtered live test and a tiny bounded snapshot test from both the native CLI and browser demo; record no event payloads or credentials in the repository.

Acceptance: the CLI behavior can be compared with `cmd/client` against a local server; the browser demo exercises v2 live streaming and user-authorized bounded replay through the production CORS proxy without changing the legacy binding or persisting a key; local headless tests verify its observable states and cleanup; and opt-in production smoke paths cannot run accidentally under `just test` or `just check`.

### Deferred post-flight performance work — not part of current completion

- Benchmark shared-slab records, copied records, lazy generic JSON, and typed decode.
- Measure block decode scaling, native worker strategy, browser main-thread latency, Web Workers, sparse fetch concurrency, range stripes, allocations, and memory high-water marks.
- Tune target-specific defaults and compare Rust with Go using the same host, filter, snapshot, and network path.
- Add higher-level typed adapters only after the record ownership contract is stable.

The current implementation may include obvious low-risk efficiencies, but it must not use airplane-network measurements to choose defaults or make performance claims.

## Verification strategy

All automated tests are offline and hermetic. The strategy follows Jetstream's strongest testing lesson: test the client-visible replay contract through independent observations, not merely individual implementation paths. Different techniques have different jobs; duplicating the same weak assertion at every layer does not improve confidence.

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
- [ ] Run and record an initial curated mutation campaign; close or explicitly disposition every surviving oracle blind spot.
- [ ] Add focused `just` recipes and CI tiers without introducing external requests or making the default loop impractically slow.

### Principles

- **Test contracts and failure modes, not line coverage.** Each test must name the bug class or invariant it protects. Coverage reports may locate unexercised code, but no numeric coverage target is a release criterion.
- **Prefer independent oracles.** Expected events come from a small logical model or pinned Go-generated manifest, never by decoding expected data with the same Shrike code under test.
- **Exercise public product paths.** Parser unit tests are necessary, but archive-to-live correctness must also be observed through the public client over real local HTTP and WebSocket transports.
- **Make faults non-vacuous.** Every injected fault has an ID and hit counter; a test fails if the intended fault, retry, cancellation point, or recovery transition did not occur.
- **Control concurrency rather than sleep.** Use barriers, gated transports, paused/mock time, explicit acknowledgements, and deterministic completion permutations. Wall-clock sleeps are reserved for a small real-timer acceptance tier.
- **Make randomized failures reproducible.** Print and persist the seed, enabled swarm axes, minimized action script, target, and relevant limits. Property failures must shrink to a focused regression case.
- **Assert resources and cleanup.** Tests observe request counts, attempts, active tasks/listeners, queue high-water marks, in-flight bytes, response limits, and decoder output limits—not just returned events.
- **Test native/WASM semantic parity.** Portable fixtures and model scenarios run against the shared core on both targets; actual browsers separately cover Fetch, CORS, WebSocket, event-loop yielding, and listener cleanup.
- **Keep production opt-in.** The only external checks are explicit, tightly bounded CLI/browser smoke tests. They are never invoked by default tests, doctests, examples, or library startup.
- **Turn discoveries into durable assets.** Every fixed bug gets the smallest focused regression test at the lowest layer that reproduces it; escaped fuzz/property/swarm inputs join the permanent seed or regression corpus.

### Risk-to-oracle map

| Risk | Strongest primary oracle | Supporting techniques |
|---|---|---|
| Segment/block wire incompatibility | Pinned Go-produced bytes plus independently recorded normalized events and hashes | Golden, differential, fuzz, boundary unit tests |
| Archive/live semantic mismatch | Same logical event history encoded independently as archive rows and live envelopes | Differential integration, property tests |
| Loss, duplication, reordering, or bad cutover | Simple sequential replay model over a generated logical history and cursor script | Model/property tests, schedule permutations, end-to-end acceptance |
| Retry, mutation, or generation handling | Scripted local server request ledger plus final byte/event equivalence | Fault injection, integration tests, swarms |
| Filter or marker loss | Obvious predicate model over logical events before wire encoding | Truth-table unit tests, properties, archive/live differential |
| Unbounded resource use or leaked work | Instrumented transports/queues/decoders with hard high-water assertions | Boundary tests, cancellation tests, compression-bomb fuzzing |
| Credential disclosure | Complete local request/redirect/error/log ledger that treats the key as a forbidden byte string | Security integration tests, formatting tests, browser tests |
| Target-specific divergence | Identical corpus manifest and scenario outcomes on native, Node-hosted WASM, and a real browser | Cross-target conformance and browser acceptance |
| Demo/API usability regressions | Public API/CLI/WASM binding driven as a consumer would use it | Compile tests, local end-to-end and UI acceptance tests |

### Test architecture and independent evidence

Build four reusable test components rather than bespoke mocks per test:

1. **Logical replay model.** A deliberately small synchronous interpreter consumes logical events, filters, snapshot bounds, live reconnect cursors, and a fault/recovery script. It produces normalized expected events, batches, final cursor, terminal classification, and request/attempt ceilings. It must not call the production planner, filter, decoder, batching, retry, or engine code.
2. **Pinned cross-language corpus.** A generator in the Jetstream Go checkout emits minimal raw blocks, whole segments, dictionaries, proposal-0015 frames, plan pages, expected normalized events, and a manifest containing the Jetstream commit and file hashes. Commit the immutable results under `testdata/jetstream/`, not the generator's build products. Default Rust tests never require Go or the adjacent checkout.
3. **Scripted protocol server.** One local fixture serves XRPC HTTP, ranged objects, dictionary responses, and WebSockets. A declarative script controls response bytes, gates, disconnect points, status/headers, CORS, ETag generations, and live frames. Its request ledger records ordering, ranges, cursors, subprotocols, auth presence, concurrency, and whether every planned fault fired.
4. **Instrumented host transports.** In-memory portable transport implementations drive exhaustive engine/model cases cheaply and deterministically. The same conformance contract applies to native, browser, and caller-injected WASI transports; these tests supplement rather than replace real sockets and Fetch/WebSocket tests.

Keep expected data outside production DTOs where practical. Normalize both actual and expected events into a test-only representation containing seq, kind, DID, collection/rkey/rev, payload bytes/hash, and relevant timestamps. Compare exact event logs as well as any folded final state: final state alone can hide a dropped intermediate update or marker.

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

Add focused recipes such as `just test-jetstream`, `just test-jetstream-long`, and `just test-jetstream-browser`; keep `just check` deterministic and reasonably fast. Exact time budgets should be measured locally/CI rather than guessed on airplane Wi-Fi.

### Unit and boundary tests

Use table-driven unit tests for pure logic whose complete contract fits in a small input/output table:

- filter kind × DID × exact/wildcard collection behavior, especially marker pass-through;
- config conflicts, counts, syntax, cursor domains, host normalization, TLS policy, and checked integer conversions;
- proposal-0015 message/error dispatch, pre-upgrade XRPC errors, and stable error classification;
- Jiff RFC 3339/Unix-microsecond boundaries, offsets, precision, minimum/maximum supported instants, and rejected timestamps;
- header/footer/index sizes, offsets, checksums, length prefixes, sentinel/kind 7 mapping, indexed/witnessed fallback, and malformed-row isolation;
- pagination progress, retry eligibility, `Retry-After`, backoff caps, `Content-Range`, ETag/If-Range, and no-progress accounting;
- batch partial/full flush, last-cursor semantics, inclusive-cursor deduplication, and cancellation precedence.

Use boundary values such as zero, one, limit−1, limit, limit+1, and integer maxima. Avoid one test per getter, builder setter, derived trait, or error string. Serialization tests are valuable only where exact wire shape, omission, union tagging, redaction, or compatibility is contractual.

### Golden and differential tests

- Decode every pinned Go raw block and whole segment and compare the complete normalized event log, segment metadata, checksum, and payload hashes with the manifest.
- Include every durable kind, sentinel rows, empty optionals, sparse/whole plans, dictionary frames, maximum realistic identifiers, and deliberately malformed neighboring rows.
- Run the same zstd dictionary/frame/error corpus through native `zstd` and WASM `ruzstd`; accepted output and rejection class/limit behavior must agree even if exact error text differs.
- Encode one logical history into both archive and live representations using fixture code independent from Shrike; after normalization and filtering, outputs must be identical.
- Check live JSON record conversion to canonical DAG-CBOR against Go-produced CBOR/CID pairs and existing Shrike strict decoding.
- Regenerate the corpus only through a reviewed explicit command. A manifest diff must make reference commit, format, expected output, and hash changes visible.

Golden files should be small and diagnostic. Do not commit production captures, credentials, giant segments, or snapshots of unstable debug/error text.

### Property and model-based tests

Use the existing `proptest` dependency to generate structured, valid logical scenarios rather than mostly-invalid byte noise. Generate:

- non-contiguous increasing sequences and all event kinds;
- exact/wildcard filters and matching/nonmatching markers;
- segment/block boundaries, sparse/whole entries, pagination (including empty pages), and sealed tips;
- batch sizes, partial flushes, inclusive reconnect overlap, live gaps, and cursor-too-old re-backfill;
- bounded transient/permanent fault scripts and worker completion orders.

The core properties are:

- actual output exactly equals the independent sequential model;
- delivered sequences are strictly increasing, with documented gaps allowed, and no matching event is lost or duplicated;
- changing batch size, archive partitioning, page boundaries, legal worker concurrency, or completion order does not change concatenated output;
- replaying to cursor `C`, persisting the delivered cursor, then resuming is equivalent to one uninterrupted run after inclusive-boundary deduplication;
- archive-only and live-only encodings of the same logical history filter and normalize identically;
- cutover and every successful re-backfill start strictly after the last processed seq and never rewind observable output;
- retry and no-progress counters never exceed configuration, and permanent errors are never retried;
- cancellation has one terminal outcome and leaves no queued delivery after completion;
- all size/offset arithmetic either produces a valid in-bounds layout or a bounded error without wrapping.

For small histories, exhaustively enumerate page splits, archive/live cut points, and worker completion permutations rather than relying only on randomness. Preserve minimized failing scripts as readable regression cases.

### Local integration and fault-injection tests

Drive the public native client against the scripted server and cover these fault families independently before combining them:

- plans: multiple/empty pages, sparse and whole modes mixed, overlap, malformed bounds, cursor regression, changing sealed tip, and non-advancing continuation;
- HTTP bodies: ignored ranges, invalid/missing `Content-Range`, wrong lengths, early EOF, trailing bytes, slow/dribbled bodies, mid-body disconnect/resume, and oversized declared/observed bodies;
- object generations: missing ETag, ETag changes between probe/parts, stale If-Range, clean whole-download restart, and refusal to splice generations;
- retry: 429 with both `Retry-After` forms, eligible 5xx, transport timeout, permanent 4xx, per-part versus whole-operation budgets, and backoff cancellation;
- live: text/binary frames, ping/pong/close, malformed/control/info/error frames, duplicate reconnect boundary, seq vacancy, future/old cursor, consumer-too-slow, and reconnect exhaustion;
- compression: initial dictionary failure, corrupt/oversized frame, rejected/stale dictionary, rotation, refetch, bounded decode, and uncompressed fallback;
- authentication: archive endpoints receive exactly one scoped authorization header; live/dictionary/foreign redirects/errors/logs never receive or reveal it;
- cancellation: pause at every meaningful await boundary—plan, body read, range worker, decode handoff, blocked output, partial batch, reconnect timer, dictionary fetch, and live read—then assert bounded shutdown and zero live work.

For concurrency tests, gate each worker and release completions in forward, reverse, and selected interleaved orders. Assert exact request/attempt counts, maximum in-flight work, ordered output, and cleanup. A returned error without these observables is insufficient because a retry path can appear correct while leaking tasks or exceeding its budget.

### Swarm and schedule testing

Use deterministic feature swarms for interaction bugs that isolated fault tests and unconstrained random generation rarely hit. Each iteration independently enables axes with roughly 50% probability, forces at least one non-default axis, and records `seed + axes + action script`.

Candidate axes include empty pages, mixed sparse/whole plans, tiny/large blocks, collection/DID filters, marker-heavy streams, seq gaps, duplicate boundaries, reversed completion, low queue limits, range fallback, ETag rotation, truncation, 429/5xx, dictionary rotation, cursor-too-old, slow consumer, and cancellation phase. Maintain a short PR swarm and a much larger scheduled seed sweep. Assert that requested faults and rare transitions actually fired, and track basic scenario coverage counters so thousands of vacuous happy paths cannot pass as stress testing.

Keep swarm generation at the logical/protocol level; byte-level corruption belongs in fuzzing. Swarm's purpose is combinatorial subsystem interaction, not raw input mutation.

### Fuzzing

Extend Shrike's existing `cargo-fuzz` setup and real-shaped seed generator. Favor strong semantic oracles over bare "does not panic":

- **segment container:** arbitrary header/footer/index/frame bytes; accepted layouts stay within the input and configured limits, whole versus ranged readers agree, and reinspection is stable;
- **columnar block:** malformed lengths/counts/UTF-8/syntax and valid Go seeds; accepted rows satisfy structural invariants and alternate decode paths agree;
- **zstd:** dictionaries, frames, truncations, high-window frames, and compression bombs; decoder never exceeds configured window/output/work limits;
- **live framing:** arbitrary text/binary proposal-0015 and pre-upgrade errors; accepted frames normalize stably and never bypass size limits;
- **JSON-to-DAG-CBOR:** structured atproto JSON; canonical encode/decode/re-encode is a fixed point and known Go CID pairs agree;
- **HTTP metadata:** plan/error bodies, ETag, `Content-Range`, `Retry-After`, and numeric boundaries; parsing is panic-free, bounded, and canonical where applicable;
- **filters:** arbitrary structured events/filters; production predicate equals a simple test-only predicate;
- **engine scripts:** small arbitrary sequences of plan pages, decoded events, live frames, disconnects, and cancellations; output/termination equals the logical model with bounded steps.

Seed with every golden artifact, hand-built boundary cases, and all prior failures. Set strict per-input time and memory limits, retain artifacts in CI, and turn meaningful findings into focused regression tests. Do not fuzz through real network servers or treat hours without a crash as proof of semantic correctness.

### End-to-end and acceptance tests

Run a small number of broad tests through only public consumer surfaces:

1. Native client: local authenticated multi-page replay containing whole and sparse entries, then live cutover with an inclusive duplicate, seq gap, dictionary rotation, reconnect, marker events, and graceful cancellation. Compare the exact log/cursor with the independent model.
2. Recovery: disconnect and return `CursorTooOld`, extend the sealed archive, replan/re-backfill, and cut over again. Prove no loss/duplication and bounded no-progress termination.
3. Native CLI: run `shrike jetstream` against the local server in JSON and stats modes; validate exit status, cursor/progress fields, stderr separation, cancellation, and absence of secrets.
4. Browser client/demo: from a different local origin, exercise preflight, exposed range/generation headers, Fetch streaming, WebSocket subprotocol, compressed-to-uncompressed fallback, progress rendering, session-only key handling, close/reconnect cleanup, and preservation of the legacy binding.
5. Host adapter: run the portable conformance suite through at least one caller-injected transport representative of WASI/embedded use.

The manual production smoke repeats only a tiny filtered live path and a strictly bounded replay against `jetstream.us-east.bsky.network`. It validates deployment integration, not correctness, and must not weaken or replace any hermetic acceptance gate.

### Resource, concurrency, and platform checks

- Configure tiny limits in tests so queue, response, decompression, retry, and concurrency boundaries are exercised without allocating huge objects.
- Assert rejection before allocation where a declared size is already excessive; assert observed-byte limits for lying or streaming peers.
- Track compressed bytes, decompressed bytes, queued batches/events, active requests/decoders/tasks/listeners, and cooperative-yield counts with test instrumentation.
- On WASM, test 32-bit conversion boundaries and ensure long decode loops yield while preserving order. Run shared pure tests in Node and browser-only transport/CORS/lifecycle tests in a real headless browser.
- Test native cancellation and close races repeatedly under deliberately varied schedules. Add `loom` or another concurrency-model dependency only if implementation introduces custom atomic/lock-free synchronization that deterministic gates cannot adequately cover; request approval first.
- Keep performance benchmarks deferred, but retain correctness gates on bounded memory/concurrency behavior. Throughput or RSS comparisons are not pass/fail criteria in this phase.

### Targeted mutation testing

After the main oracle is stable, measure whether it can actually detect realistic client bugs. Start with a small reviewed mutation scorecard rather than chasing a global mutation percentage. Mutants should include:

- changing an exclusive cursor boundary to inclusive or removing reconnect deduplication;
- dropping marker events when a collection filter is active;
- emitting worker completion order instead of sequence order;
- advancing the persisted cursor before delivery succeeds;
- ignoring ETag/If-Range changes and splicing object generations;
- retrying permanent errors or removing retry/no-progress limits;
- forwarding archive authorization to dictionary/live/redirect targets;
- removing decompression/output limits or cancellation cleanup;
- skipping `CursorTooOld` re-backfill or rewinding below the delivered cursor.

Record which exact tier kills each mutant. A survivor indicates an oracle blind spot to investigate, not a reason to tailor production code to the test. `cargo-mutants` may be evaluated as an external scheduled tool, but adding it to repository/CI tooling requires separate approval; hand-authored patches are sufficient for the first focused campaign.

### Tests intentionally not written

- one assertion per trivial getter, builder setter, enum conversion, or derived trait;
- snapshots of internal structs, task ordering, debug formatting, or complete error prose unless that text is a public/security contract;
- mocks that duplicate the production algorithm and then assert their own configured return values;
- redundant parser cases at unit, integration, and end-to-end layers without a distinct layer-specific risk;
- probabilistic tests without printed seeds, shrinking/reproduction instructions, anti-vacuity assertions, and bounded runtime;
- tests whose success depends on wall-clock sleeps, public service availability, production event contents, or a developer's adjacent Jetstream checkout;
- giant fixtures when a minimal artifact exercises the same format boundary;
- benchmarks disguised as correctness tests during this phase.

Every test should answer: what realistic defect makes this fail, is its expected result independently derived, and is this the cheapest layer that can catch it? If those answers are unclear, do not add the test.

## Performance-ready design constraints

Without doing comparative tuning now, preserve these properties:

- decode from borrowed/shared byte ranges and materialize JSON only on request;
- keep codec, transport, scheduling, and ordered emission behind narrow seams;
- stream bodies and frames instead of requiring whole-response copies;
- bound queues and use backpressure rather than unbounded task creation;
- reuse decoder contexts and allocation buffers where ownership stays clear;
- avoid trait-object or boxed-future dispatch inside per-row decode loops;
- keep exact filtering cheap and after structural validation;
- keep logging off hot paths and expose progress through `Stats`;
- use target-aware concurrency, allowing native worker pools and future browser Web Workers without changing the public API.

Criterion and end-to-end throughput/RSS work belongs to the deferred post-flight effort. Correctness tests may still assert allocation/size bounds where needed to prevent resource vulnerabilities.

## Resolved decisions

1. **Package compatibility:** add a completely independent `shrike::jetstream` v2 package. Leave the legacy implementation untouched.
2. **Target scope:** ship archive and live support for native and WASM. Provide built-in browser/JS-hosted transports and public host-transport injection for WASI/embedded runtimes.
3. **Delivery scope:** implement correctness and recovery parity now, preserve performance-ready seams, and defer extensive measurement/tuning until reliable networking is available.
4. **Date/time:** use BurntSushi's Jiff for RFC 3339 parsing/formatting and Unix-microsecond conversion.

## Dependency recommendations

These additions require explicit approval before implementation:

| Crate | Recommended configuration | Why |
|---|---|---|
| `jiff` 0.2 | `default-features = false`, `features = ["std", "perf-inline"]` | Author-approved, robust Temporal-inspired timestamp handling; avoids maintaining calendar/offset/leap-second code without bundling an unused timezone database |
| `zstd` 0.14, native only | `default-features = false`; use only its decode APIs | Mature bindings to upstream zstd 1.5.7, reusable/prepared dictionaries, dictionary-ID inspection, hard destination capacity, `WindowLogMax`, and the strongest initial native performance |
| `ruzstd` 0.9, WASM only | default decode features; do not enable dictionary building | Pure Rust, actively maintained and fuzzed, tagged-dictionary decode, streaming output, explicit maximum window size, and no C cross-toolchain requirement |
| `twox-hash` 2.1 | `default-features = false`, `features = ["xxhash3_64"]` | Small, MIT, pure Rust, no FFI, native/WASM portable; implements the exact XXH3-64 checksum needed by the segment format |
| `bytes` 1 | default `std` feature | Mature Tokio-ecosystem shared immutable buffers and O(1) slices; cleanly solves safe block-slab/record ownership |
| `secrecy` 0.10 | no serde feature | Redacted secret wrapper with zeroization; makes accidental API-key formatting/serialization harder |

`reqwest`, `tokio-tungstenite`, `gloo-net`, `futures`, `url`, `serde`, `serde_json`, `thiserror`, and the necessary platform/timer primitives already exist in Shrike and should be reused.

Put both implementations behind one private `Decompressor` interface and require identical golden/error behavior. `ruzstd`'s own documentation reports slower decoding than upstream zstd, which is why it is not the native default; reliable pure-Rust cross-compilation is the more important first-pass WASM property. A preliminary `zstd` 0.14 wasm32 compile on 2026-09-18 reached `zstd-sys` but was blocked by Shrike's local Nix-wrapped clang injecting the host-only `-fzero-call-used-regs=used-gpr` flag. This is an environment/toolchain failure rather than evidence of a codec bug, but it demonstrates the operational cost of making C cross-compilation mandatory for browser users.

Preliminary isolated `wasm32-unknown-unknown` checks succeeded for `ruzstd` 0.9 with its default checksum features, Jiff 0.2 with `std,perf-inline`, `twox-hash` 2.1 with only XXH3-64, and `secrecy` 0.10. These are compile checks, not substitutes for the Jetstream golden-corpus and browser-runtime acceptance tests in M0.

`structured-zstd` is promising and explicitly WASM/SIMD-oriented, but its current `0.0.x` maturity makes it a less conservative first choice for untrusted production input. Revisit it—or C-backed zstd on WASM—during the deferred measurement phase without changing the engine API.

No general-purpose backoff, range-parser, datetime, executor, or logging crate is recommended. Those needs are already small, security-sensitive, or covered by existing dependencies.

## Known risks

- **Memory amplification:** decompressed blocks may approach 1 GiB. Limits, shared slabs, ordered backpressure, and small prefetch bounds must be designed together, not added after parallelism.
- **Safe zero-copy API:** Rust cannot store decoded borrowing values beside their owner without unsafe/self-reference. Expose owning bytes and borrow only during accessor calls.
- **HTTP generation safety:** striped downloads can silently combine generations unless every part is pinned and validated.
- **False-positive planning:** omitting exact post-decode filtering corrupts consumer views, especially around marker events.
- **Cursor ambiguity:** values at or above `10^15` are timestamps on the live endpoint. High-level sequence and timestamp resume APIs must not blur this distinction.
- **Credential propagation:** generic bearer middleware or redirects can leak the archive key to public/foreign endpoints.
- **Compression bombs/corruption:** limits must be enforced by the decoder, not only checked after allocating a full output.
- **Lexicon/codegen drift:** the subscription main def is intentionally skipped today. Generated associated DTOs must be covered by a regeneration check.
- **WASM memory and responsiveness:** browser linear memory is constrained and decode is normally single-threaded. Range-to-frame fetching, checked `usize` conversions, lower target limits, backpressure, and cooperative yields are required.
- **WASM host fragmentation:** browser/JS transports do not imply a universal WASI WebSocket. Keep a conformance-tested injection API and state the built-in target matrix precisely.
- **Browser CORS and credentials:** full replay needs authorization and visible range/generation headers. The production us-east proxy currently provides them, but direct/self-hosted deployments remain responsible for equivalent CORS until Jetstream adds it natively. Browser-bundled bearer keys are extractable, so the demo accepts a session-only key and never ships one.
- **Reference evolution:** record the Jetstream commit in fixtures and rerun the cross-language corpus when updating lexicons or segment version support.

## Completion definition

This plan is complete when:

- all M0–M6 acceptance criteria pass on the applicable native and WASM target matrix;
- the cross-cutting verification tracker is complete and every release-critical risk in the risk-to-oracle map has a passing independent primary oracle;
- `just build`, `just test`, `just test-wasm`, `just lint`, and `just check` pass with the new feature included where appropriate, and the local headless-browser acceptance tier passes;
- fuzz targets have a clean initial seeded campaign, property/swarm failures are reproducible, and resource-bound tests establish safe memory/concurrency limits and clean cancellation;
- the initial curated mutation campaign kills each required mutant or records a reviewed blind spot and the additional oracle work needed to close it;
- normal tests make zero external requests;
- the only production exercise is explicit, bounded, credential-safe, and user-invoked;
- legacy `/subscribe` remains compatible;
- the legacy client implementation has no diff;
- the existing legacy WASM binding remains available and the separate v2 demo passes its local headless-browser lifecycle tests;
- public docs explain cursor locality, inclusive replay/dedup, marker semantics, secret scope, snapshot exclusion of the active segment, error continuation, and cancellation;
- no generated file is hand-edited and only the explicitly approved dependencies are added.
