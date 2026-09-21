# Jetstream replay follow-up

Starting point: the existing uncommitted general-replay work, matching the
server's `shrike-cli-general-20260921-final-v2` and `shrike-cli` (SHA-256
`d48d151f8fbcc01a42e847590546838516c3f0bc8d78e796e8a40ccba9ca7a08`).
Preserve those binaries and all earlier source changes. Local artifacts are in
`/tmp/shrike-next-20260921-UUV7M2`.

Remote runs are sequential, restricted to CPUs 2–9 (or 2–3), nice 19 and idle
I/O priority, with bounded snapshot windows and timeouts. No service changes,
package installations, cache drops, or system-wide profiling.

## Starting evidence

A fresh process-scoped profile puts 36.9% of sampled user cycles in zstd
sequence decompression, 7.2% in zstd multiframe decoding, 11.1% in row conversion,
and 10.0% in short libc comparisons. The profile contains roughly 1,000 samples;
use it to identify broad costs, not to claim small differences. Artifacts:
`/tmp/shrike-general-20260921/current-sept21.*`.

The previous acceptance run stopped because its final replay returned 51 fewer
events (34,520,054 instead of 34,520,105) without errors. Fresh runs consistently
return the smaller count with either download mode. Several early segment files
have modification time 20:39:59 UTC, after the earlier comparison began. The
server supports compaction that removes rows while retaining historical sequence
bounds. This is evidence of a changing corpus, not proof of a client defect;
keep strict result checks in the harness and do not combine these generations.

Six randomized pairs per exploratory experiment, excluding one warmup per
variant; same eight CPUs, unfiltered (0,100m], 34,520,054 events, final cursor
99,998,466, zero residual gap and no errors:

| Experiment | Throughput ratio, paired 95% interval | Median CPU before / after | Result |
| --- | --- | --- | --- |
| Existing single-stream flag vs stripes | 1.2132 [1.2069, 1.2209] | 11.055 / 10.455 s | Useful configuration on this server |
| Batch size 1024 vs 64, single stream | 0.9931 [0.9793, 1.0112] | 10.475 / 10.225 s | Keep default |
| Force owned row-conversion inlining | 0.9781 [0.9598, 0.9932] | 10.485 / 10.535 s | Rejected and removed |
| Defer shared record handle creation, after sparse batching | 1.0068 [0.9884, 1.0234] | 9.975 / 10.055 s | No reliable benefit; removed |

Single-stream median RSS was 910,976 KiB versus 1,176,908 KiB for stripes.
This is a local-server measurement, not grounds to remove configurable striping
for other network conditions.

## Sparse block batching experiment

Whole-segment preparation already constructs delivery-sized vectors. Sparse
block preparation still constructs one large vector per block, requiring the
delivery thread to copy every event into new vectors. Test using the same
validated-block batching routine in both paths. Keep full-block structural
failure atomicity, valid earlier blocks, entry-level error order, windowing,
filters, cancellation, and independently retained record ownership.

The new regression test compares batches of size 1, 7, 64, and 1024 with the
atomic downloader across malformed metadata, filtered rows, deletes, window
boundaries, and late structural corruption. It failed the batch-bound check
before the change. The archive, engine, and property suites pass with it.
The optional `prepared_sparse_matches_captured_corpus` test also compares every
normalized field, complete record bytes, and ordered errors against the atomic
block decoder after dropping the stream/source. With 36 captured real blocks,
three filters and batch sizes 1/64/1024, all 244,911 event comparisons passed.

Exploration (six pairs, same binary flags and CPU budget within each pair):

| Workload | Throughput ratio, paired 95% interval | Median CPU before / after |
| --- | --- | --- |
| Posts, (0,100m], eight CPUs | 1.0464 [1.0114, 1.0790] | 8.975 / 8.755 s |
| Unfiltered, (0,100m], eight CPUs | 1.0150 [0.9803, 1.0467] | 10.480 / 10.240 s |
| Likes, (0,20m], two CPUs | 1.0175 [0.9964, 1.0369] | 1.700 / 1.660 s |

Twelve-pair confirmation uses seeds 2026092195–2026092197 for posts with
single-stream downloads, unfiltered default striped downloads, and held-out
posts at (1,000m,1,100m], respectively. All pairs completed with matching counts,
cursors and errors; slow runs were retained.

| Workload | Throughput ratio, paired 95% interval | Median wall before / after | Median CPU before / after | Median peak RSS before / after, KiB |
| --- | --- | --- | --- | --- |
| Posts, (0,100m] | 1.0345 [1.0062, 1.0635] | 2.333 / 2.240 s | 8.905 / 8.665 s | 947,792 / 971,600 |
| Unfiltered, default stripes, (0,100m] | 1.0201 [0.9986, 1.0405] | 3.055 / 3.010 s | 11.005 / 10.755 s | 1,203,730 / 1,202,662 |
| Posts, (1,000m,1,100m] | 1.0405 [1.0221, 1.0598] | 2.222 / 2.113 s | 6.940 / 6.770 s | 603,682 / 578,258 |

The primary posts window delivers 3,689,326 events, ending at 99,998,457;
the later posts window delivers 2,994,875, ending at 1,099,990,066. Unfiltered
replay delivers 34,520,054, ending at 99,998,466. Every run has zero residual
gap and no recoverable errors. Unfiltered wall-time evidence is inconclusive;
do not claim a reliable unfiltered throughput gain from this code change.

Keep sparse batching: it removes the redundant move using the existing whole-
segment conversion path, modestly improves both measured post windows, and
reduces CPU work. Peak RSS varies by workload; this is not a general memory
reduction claim. The inlining and deferred-handle prototypes are absent from
the final source. The batch-size and striping defaults are unchanged.

The retained release binary is `shrike-cli-next-20260921-sparse-v1` in
`/data/jcalabro/jetstream-1/` on cpu3-pop3, SHA-256
`21c6fc2bb97267ca9f32cc1026b57d763e0d6a51ca7b0d930b799850ee7cf22f`.
`target/release/shrike-cli` matches it. The original remote `shrike-cli` remains
the starting binary, so comparisons can continue without reconstructing it.

Validation: `just build --release`, `just check`, and `just wasm-check` pass.
The corpus audit can be repeated with:

```sh
JETSTREAM_CORPUS=/path/to/captured/frames cargo test --features full \
  --test jetstream_archive prepared_sparse_matches_captured_corpus -- --ignored --nocapture
```

The final decoder fuzz smoke completed 15,042 executions in 31 seconds without
failures, including differential raw/filtered/mapped decoding. The Nix shell
does not expose rustup/nightly; the already installed cargo-fuzz was run with
`RUSTC_BOOTSTRAP=1` using the pinned compiler. The final source was rebuilt
before fuzz execution. The benchmark harness's three Python tests also pass.

## Current Rust versus Go with record consumption

Twelve randomized pairs, seed 2026092198, eight CPUs, unfiltered (0,100m],
single-stream downloads. Go uses its existing `client` binary with `GOGC=400`,
`GOMAXPROCS=8`, and no soft memory limit (the faster prior throughput control).
Rust uses `--decode-records`, which runs a scoped archive consumer that builds
owned atproto JSON and computes/formats each record CID. This is distinct from
ordinary lazy-record stats and from retaining every owned event in application
code. Validation contracts still differ between libraries.

| Client | Median wall | Median CPU | Median peak RSS, KiB |
| --- | --- | --- | --- |
| Go generic client | 7.762 s | 51.410 s | 2,233,158 |
| Rust scoped generic consumer | 5.543 s | 37.610 s | 935,876 |

Rust/Go throughput ratio: 1.3984, paired 95% interval [1.3787, 1.4187]. Both
accept 34,519,409 records and reject 645 in-window payloads; final cursor is
99,998,466. Go rejects those payloads before delivery, whereas Rust reports
34,520,054 envelopes and 645 consumer decode errors. The harness explicitly
checks this accounting and repeats both per-label error signatures.

This cross-language result includes all earlier performance work. Sparse owned
batching does not affect the scoped generic path, so the 39.8% lead is not an
incremental gain attributable to this round's code change.
