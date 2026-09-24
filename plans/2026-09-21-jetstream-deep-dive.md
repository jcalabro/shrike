# Jetstream deep performance exploration

## Confirmed result on the cleaned experimental branch

The scoped typed-like replay is 19–42% faster than the Go typed client across
seven matched workloads, with 24–29% less client CPU time. These measurements
use the final binary, not ratios chained across different prototype runs.

| Replay | Go median wall | Rust median wall | Rust throughput gain (95% paired CI) | Rust/Go peak RSS MiB (medians) |
| --- | ---: | ---: | --- | ---: |
| Primary (0,20m], 2 CPUs | 1.248s | 0.970s | 28.1% [26.9, 29.2] | 197/518 |
| Primary, 4 CPUs | 0.727s | 0.573s | 25.9% [24.1, 27.5] | 267/514 |
| Primary, 8 CPUs | 0.473s | 0.331s | 42.5% [40.2, 44.5] | 354/509 |
| Long (0,100m], 8 CPUs | 2.120s | 1.523s | 39.1% [38.0, 40.0] | 789/1955 |
| Validation (100m,120m], 8 CPUs | 0.500s | 0.391s | 27.4% [25.7, 29.2] | 449/510 |
| New (200m,220m], 8 CPUs | 0.442s | 0.360s | 22.4% [20.4, 24.6] | 325/510 |
| New (500m,520m], 8 CPUs | 0.449s | 0.369s | 18.9% [16.1, 21.7] | 379/511 |

Each row has 12 fresh randomized pairs and one excluded warmup per client.
Intervals are 10,000-resample paired bootstrap intervals for the geometric-mean
throughput ratio. Both clients have the same pinned CPU budget. Runs are
sequential, nice 19, idle I/O priority, time-bounded. Wall time includes process
startup and destruction. All results, including slow runs, are retained.
Go GOGC is explicitly 400 (its CLI default), with 512 MiB GOMEMLIMIT for short
ranges and no memory limit for the long replay: the faster measured heap
setting for each workload. Both use single-stream whole-segment downloads.
Rust uses 1/2/4 workers per segment for 2/4/8 CPU budgets. These choices were
frozen before the final runs. The two new ranges did not guide Rust tuning;
their typed error audits were clean, and 512 MiB beat unlimited Go heaps there.

The main range has 2,532,823 events; the long range has 17,186, 264. Counts, final
cursor, and zero residual gap agree in every pair. Typed parsing retains Rust's
existing required-CID and timezone validation: the primary range has one more
Rust typed rejection; the long range has 92 more (91 missing timezones plus one
missing CID). Owned and borrowed Rust agree on those errors. The other three
ranges have no typed-error delta. No validation was relaxed to match Go.

Final CLI SHA256:
`61dfab019689b0d1fda1fb636114413c8beb6b6faef295f2a34eaec264424835`.
Go SHA256:
`3332d933512979f556cfa460ace995ab2faa2e60239869621d4b9c6f49942926`.
Raw data and source artifacts are in `/tmp/shrike-deep-20260921/`:
`confirm-*.jsonl`, `confirmation-table.json`, `clean-final-source.*`,
`clean-final-source-hashes.json`, and `clean-final-fingerprints.json`.
The per-run files include command settings, hashes, CPU, RSS, faults, context
switches, load, event counts, and final cursors.

### What is retained and what the result means

- Generated borrowed CBOR views, with checked text/syntax and preserved unknown
  fields; scoped validated event conversion and owned mapped results.
- Shared UTF-8 validation over metadata with checked field boundaries and
  fallback; exact filters carry identifier validation proofs.
- Schema-generated key-prefix parsing with checked fallback; safe fixed-width
  column iteration; redundant URI scans removed without relaxing grammar.
- Single-stream archive CLI option, incremental ordered stripe assembly, and
  bounded allocation hints that do not control body acceptance.
- Simple native per-segment parallel decoding, and Thin LTO/one codegen unit
  in the normal release profile.

The benchmark fully decodes typed records and exposes every field to a scoped
callback, which returns an owned status for the CLI. Consumers may return their
own projections or explicitly call `to_owned`. This does not make independently
owned full records free. A transform can run concurrently, before window clipping,
or before later structural corruption invalidates a segment: external commit
effects belong in the ordered delivery sink. The owned event API is retained.
Scoped replay currently targets snapshots; these are archive replay results,
not measurements of live-tail latency or arbitrary downstream work.

No unsafe code or dependencies were added. The global decode pool, TLS caches,
smaller jobs, alternative native compiler, CPU-specific flags, and fresh PGO
combination did not justify their cost; rejected prototypes and their evidence
remain in the artifacts. The profile now assigns roughly 40% of client CPU to
native zstd and 9% to UTF-8 checks. Go GC was a small profile component; the
main gains came from ownership, validation work, transport, and scheduling.
There is no measured basis for promising another large jump from removing
checks or adding more threads.

### Reproduction and validation

`just build --release` now applies the measured release profile. For the
eight-CPU bounded replay on cpu3, the tested command is:

```sh
taskset -c 2-9 nice -n 19 ionice -c 3 \
  env JETSTREAM_API_KEY=local-benchmark TOKIO_WORKER_THREADS=8 \
  /lib64/ld-linux-x86-64.so.2 ./shrike-cli-deep-20260921-clean-final-v1 jetstream \
  --host=localhost:8080 --insecure --snapshot-only \
  --after-seq=0 --before-seq=100000000 --collection=app.bsky.feed.like \
  --stats --json --typed-likes --scoped --single-stream \
  --download-concurrency=8 --decode-workers=4
```

`just check` passes 1,135 tests, including doctests; `just wasm-check` passes.
Five fresh real-corpus fingerprints agree between owned and mapped-to-owned
results, including complete record bytes, across 42,680 mixed events. Likes, posts,
and profiles also have matching owned/borrowed typed acceptance counts.
Native worker tests cover ordered values, retention, cancellation, and whole
segment invalidation after late structural corruption. HTTP tests cover wrong
Content-Length hints, bounds, truncation, retries, and generation changes.
Final-source fuzzing completed with no failures (91 seconds per target, ASan/libFuzzer):

| Target | Executions |
| --- | ---: |
| Sealed segment, owned/scoped differential | 460,248 |
| CBOR, generic/bump/typed/borrowed differential | 2,181,901 |
| Compressed block, independent raw-row/filtered/scoped comparison | 38,297 |
| Decompressed columnar block | 3,305,773 |
| Syntax parsers | 7,692,023 |

The total is 13,678,242 executions. Segment fuzzing also repairs mutated
checksums, after testing the original bytes, so it reaches footer/index/row
validation. Meaningful valid segment seeds and real captured block seeds
exercise deeper paths. This is evidence of robustness, not a proof that no
remaining defect exists. Logs are `fuzz-*-transport-final.log` and
`fuzz-segment-final.log` in the artifact directory.

Two additional 12-pair comparisons against the branch's starting Rust binary
use the primary two-CPU workload. The retained owned-event path, with
single-stream fetches, is 1.3629× faster [1.3461, 1.3797]: median 1.369s versus
1.882s, CPU 2.275 versus 3.025s, approximately unchanged RSS. The scoped path
is 1.9376× faster [1.9068, 1.9722]: median 1.004s versus 1.926s, CPU 1.750
versus 3.070s, RSS 202,074 versus 710,068 KiB. The scoped comparison changes
where ownership is required, as described above; it is not the cost of retaining
full owned typed objects. Raw results: `confirm-start-owned.jsonl` and
`confirm-start-scoped.jsonl`. The owned path still trails the Go typed baseline
on this two-CPU workload; the 19–42% Go lead is specifically scoped processing.

The server's Jetstream remains PID 1976958, started September 16 at 23:19:02.
No experiment processes remain. No packages, restarts, shared configuration
changes, cache drops, or service modifications were performed. Only uniquely
named experiment binaries were uploaded; profiling and result files stayed
local. The implementation and report are on the experimental branch.



Experimental branch: `jc/jetstream-performance-deep-dive`, starting at
`de3d2dc`. The goal is to substantially outperform the Go typed client while
preserving actual correctness. API changes and scoped ownership are in scope;
we will not weaken validation or optimize only the known corpus.

## Measurement rules

Remote work uses CPUs 2/3, nice 19, idle I/O priority, sequential bounded runs,
and process-scoped profiling. No service changes, installations, cache drops,
or shared configuration changes. Artifacts live locally at
`/tmp/shrike-deep-20260921`. Candidate binary names are unique.

Exploration uses six randomized measured pairs plus an excluded warmup.
Acceptance requires independently seeded 12-pair confirmation, a later-sequence
holdout, and other collections where applicable. Bootstrap complete pairs;
report CPU, RSS, counts, cursors, decode errors, and wall time. Compiler-only
changes need separate controls from source changes.

## Reproduced starting point

Six pairs, seed 49371, likes in `(0, 20,000,000]`:

| Client | Median wall | Median CPU | Median RSS KiB |
| --- | ---: | ---: | ---: |
| Go typed | 1.2450 s | 2.285 s | 530,122 |
| Rust typed | 1.8956 s | 3.030 s | 699,846 |

Rust/Go throughput ratio: 0.6588, paired bootstrap 95% interval
`[0.6509, 0.6668]`. Counts agree, with the previously documented six versus five
typed failures: Rust requires the subject CID that Go permits missing.

## Hypotheses under investigation

1. Generated owned records plus intermediate owned event arrays cause allocation,
   copying, cross-thread deallocation, and a serial typed decode stage. Test
   generated borrowed views and fused scoped processing, retaining all unknown
   fields and validation. Lifetime restrictions must be explicit and enforced.
2. Work granularity is a whole segment in Rust versus blocks in Go. Measure
   head-of-line blocking, memory growth, and overlap separately. A block pipeline
   must retain ordering, cancellation, and documented corruption behavior.
3. Native zstd is a potential advantage: Go's older profile was mostly its Go
   decoder. Measure decompression independently on identical data; consider
   buffer/context reuse and compiler targeting only when measurable.
4. Default release code generation may leave substantial inlining opportunities.
   Test thin LTO with one codegen unit as an isolated control; consider PGO and
   portable SIMD targeting with held-out data, not training-set-only results.
5. Canonical typed CBOR and envelope syntax currently scan repeated strings.
   Investigate schema-guided key decoding, fused validation, and per-block
   dictionary validation while retaining strict rejection of malformed input.

Fresh starting profile: ten replays, 199 Hz `cycles:u`, ~5,000 samples, no lost
samples. About 21% self samples are native zstd sequence expansion; UTF-8 scans,
NSID validation, typed map decoding, and libc copies are prominent. This is not
evidence that Go is slower due to GC; its borrowing contract and pipeline matter.

## Compiler control: thin LTO / one codegen unit

Same source, separate target directory; no custom CPU target. Six paired runs,
seed 49372: 0.9780× throughput versus the starting binary, 95% interval
`[0.9570, 0.9982]`. Median CPU 3.035 versus 3.005 s. Not retained; compiler
settings alone do not explain the gap. Raw data: `thin.jsonl`.

## Borrowed representation prototype

The generator is being extended with borrowed CBOR views, generated for every
object rather than hand-specialized for likes. Text and nested object fields
borrow input; complex array/union fields initially use existing owned decoders.
Datetime and AT-URI borrowed wrappers share the original strict validators.
Unknown fields retain validated raw CBOR. A separate scoped archive transform
can inspect a complete envelope and choose an independently owned output,
avoiding the intermediate owned record copy when it is unnecessary.

This is experimental and not yet correctness-qualified or benchmarked end to
end. Retention must be explicit; callbacks are transformations, not externally
visible delivery, because a later corrupt block can invalidate their results.

## Early scoped results (exploratory, not acceptance)

Borrowed typed views on the owned envelope pipeline: 1.0601× throughput versus
original typed Rust, six pairs `[1.0234, 1.1025]`; medians 1.7704 versus 1.8603 s.

Fused scoped archive mapping: 1.3769 s median wall, 2.415 s CPU, 277,780 KiB RSS.
Contemporaneous Go: 1.2471 s, 2.290 s CPU, 529,926 KiB RSS. Rust/Go throughput
ratio 0.8952 `[0.8653, 0.9209]`. Counts, cursor, and the known typed-error delta
agree. This changes the consumption contract: all envelope/typed fields are
available to a scoped worker transform; the transform chooses the owned data
returned to ordered delivery. The stats transform returns only a decode status.
It is a general processing API, but does not promise independently retainable
full typed objects at no cost. Compare retained-output consumers separately.

All existing workspace unit/integration suites pass on the initial scoped
prototype. Added tests cover borrowed fields, unknown fields, truncation and
byte mutations, and explicitly retaining owned outputs after freeing input.
A newer whole-column UTF-8 prototype passed the archive/property/view suites.
Further differential fuzzing and full final checks remain necessary.

## Follow-up experiments

Each row uses six new randomized measured pairs, with a separate warmup.
These are exploratory comparisons between successive prototypes.

| Experiment | Throughput ratio | 95% paired interval | Candidate median wall/CPU |
| --- | ---: | --- | --- |
| Whole metadata-region SIMD UTF-8 | 1.0611 | [1.0375, 1.0855] | 1.3254 / 2.270 s |
| Borrowed byte-key dispatch/direct text | 1.0527 | [1.0163, 1.0921] | 1.2533 / 2.160 s |
| Four downloads instead of two | 1.0274 | [0.9977, 1.0614] | 1.2860 / 2.270 s |
| String filter storage | 0.9924 | [0.9772, 1.0070] | 1.2252 / 2.130 s |
| Explicit borrowed decoder inline hints | 0.9931 | [0.9503, 1.0344] | 1.2666 / 2.105 s |
| Schema-key prefix dispatch | 1.0492 | [1.0215, 1.0862] | 1.1827 / 2.000 s |
| Two-entry exact NSID validation cache | 0.9580 | [0.9308, 0.9884] | 1.2216 / 2.045 s |

NSID caching is rejected and removed: exact memoization was safe, but TLS and
lookup overhead outweighed saved validation. Filter storage and inline hints
have not shown isolated throughput wins; simplify them before final acceptance
unless later evidence supports them. Increasing downloads raised RSS without a
clear gain. The schema fast prefix remains general: every key is generated from
the schema, fully matched, and canonical order checked; any unrecognized layout
continues through the full checked unknown-field parser.

The new Go process-scoped profile (~4k samples, no loss) still places about 65%
in sequence expansion, Huffman decompression, and checksums. GC is a small cost.
This confirms the potential advantage is native decompression plus efficient
processing, not an assumed Go GC bottleneck.

An early 61-second seeded ASan/libFuzzer CBOR differential run completed
1,507,797 executions without failure. It covers the borrowed parser before the
latest schema-prefix changes; final-source fuzzing is still required.

## Further rejected experiments and test corrections

Six-pair comparisons, each with excluded warmup:

| Experiment | Throughput ratio | 95% paired interval | Decision |
| --- | ---: | --- | --- |
| Reuse decompression output | 0.978 | [0.957, 1.0004] | Removed |
| Shared CLI HTTP client | 0.9988 | [0.9853, 1.0124] | No speed claim; simpler setup |
| Two native decode workers/segment vs one | 1.0011 | [0.9724, 1.0266] | Removed |
| Independent vectorizable length-column reductions | 1.0026 | [0.9853, 1.0241] | Removed |

The worker experiment was measured with identical binary and two-core affinity,
so additional threads did not buy additional CPUs. It added complexity and no
measurable gain. The neutral String filter representation was also removed.
Worker prototype source/binaries remain in the local artifact directory.

Corrected a weakness in early view tests: golden_seal.bin has invalid revisions,
so its events are all dropped; ownership/order assertions were vacuous. Shared
fixture builders now produce valid nonempty multi-block segments. Cancellation
is triggered by a real mapped event, retention asserts three delivered events,
and late structural corruption invalidates forty otherwise valid events.
Generated to_owned clones/copies were cleaned up through lexgen, and the view's
raw input accessor is named original_cbor to distinguish it from mutable fields.

Compiler experiments now use a cleaned-source control, an x86-64-v3 build,
and PGO. Matching LLVM 22 profiling tools were obtained locally via Nix, with
no server installations. PGO training and acceptance workloads must be disjoint.

## Compiler and validation-proof results

| Experiment | Throughput ratio | 95% paired interval | Decision |
| --- | ---: | --- | --- |
| x86-64-v3, same clean source | 0.9697 | [0.9400, 1.0004] | Rejected |
| Force native zstd prefetch sequence decoder | 0.9046 | [0.8953, 0.9133] | Rejected |
| PGO on disjoint real replay ranges | 1.0447 | [1.0098, 1.0824] | Promising |
| Reuse exact-filter identifier validation | 1.0662 | [1.0455, 1.0786] | Retained for confirmation |
| Thin LTO / one CGU on new scoped architecture | 1.0425 | [1.0228, 1.0661] | Promising |

The original thin-LTO rejection used the original owned architecture. Retesting
on the much larger generated borrowing implementation now shows a benefit.
No project release defaults have been changed. Build controls remain separate.

PGO training used a local instrumented CLI through a bounded SSH forward:
likes (40m,60m], mixed (60m,65m], posts (65m,70m], owned likes (70m,75m].
Profile files were written only locally. The forward was closed after training.
The x86-64-v3 and zstd alternatives did not justify deployment or source changes.

Exact filter matching already proves DID/NSID validity. A private selection
result carries that proof into scoped conversion, including the filter's
normalized exact collection. Empty columns, wildcard matching, unconstrained
identifiers, and all other syntax/record checks retain their existing paths.

Latest plain-build profile (proof-v1): ~30% native sequence expansion, ~5.6%
frame decode, ~5.2% block traversal, ~4.9% small-string UTF-8 validation, with
remaining costs distributed across typed CBOR, syntax, and transport/startup.
No lost perf samples. Further gains now require several independent reductions.

Validation before the proof change: just check and just wasm-check passed;
CBOR differential fuzzing completed 1,836,440 executions in 91s; mapped frame
fuzzing completed 48,452 in 91s, with no failures. Proof-specific filter/archive/
property/view suites pass. A new test checks globally valid UTF-8 split across
invalid field boundaries, malformed-byte fallback, and mixed-case normalization.
Five real-corpus event/error fingerprints match between owned and mapped-to-owned
paths (42,680 events unfiltered); full record bytes enter the hashes.

## Fresh midpoint comparison against Go

Twelve randomized pairs, seed 62011, same two CPUs and primary likes window:

| Client | Median wall | Median CPU | Median RSS KiB |
| --- | ---: | ---: | ---: |
| Go typed, 512 MiB soft target | 1.2273 s | 2.265 s | 529,394 |
| Scoped Rust, filter proofs + thin LTO | 1.0869 s | 1.885 s | 281,368 |

Throughput ratio 1.1219, 95% paired bootstrap interval [1.1050, 1.1369].
Counts, final cursor, zero residual gap, and the known required-CID error delta
agree throughout. This is a midpoint result, not final-source acceptance or a
claim of a large lead on all workloads. A source archive, patch, and per-file
hash manifest were saved as proof-source.* for reproducibility.

Checked Go heap-limit sensitivity separately (six pairs, seed 49391): turning
GOMEMLIMIT off produced 0.9235x throughput [0.9161, 0.9297], 1.3208 s wall,
2.410 CPU s, and 1,392,640 KiB RSS. The 512 MiB control was 1.2146 s / 2.245 CPU s /
530,252 KiB. Therefore keep the faster 512 MiB Go configuration. The harness now
records configurable per-client Go memory limits instead of hiding a constant.

A standalone local character-class probe suggests a lookup table may improve
short record-key validation, while slowing long keys. A hybrid should retain
vectorized reductions for long strings. This is only a microbenchmark hypothesis,
not an end-to-end speedup. Separately, AT-URI's whole-string query/fragment scan
and trailing slash scan appear redundant with its strict component validators;
acceptance equivalence must be demonstrated before retaining their removal.

## Held-out range and further attempts

On likes (100m,120m], twelve pairs seed 62012, scoped filter-proof/thin-LTO Rust
retains a 1.0905x lead [1.0798, 1.1011]: 1.3649 s / 2.435 CPU s / 304,374 KiB,
versus Go 1.4838 s / 2.800 CPU s / 529,388 KiB. Typed counts agree exactly on
this range; no required-CID adjustment was needed.

| Additional experiment | Ratio | 95% paired interval | Decision |
| --- | ---: | --- | --- |
| Fresh PGO combined with proof source and thin LTO | 0.9965 | [0.9636, 1.0274] | Reject added PGO complexity |
| Remove redundant URI query/fragment/slash scans | 1.0242 | [0.9929, 1.0544] | Simplification; wall gain unconfirmed |
| Short record-key lookup table, SIMD for long keys | 1.0053 | [0.9722, 1.0404] | Removed |
| Select rows before reading remaining metadata | 1.0087 | [0.9880, 1.0306] | Removed |

The key lookup illustrates why microbenchmarks are insufficient: it improved
short-key classification in isolation, but did not improve replay. The URI
simplification relies on the component grammars rejecting all query/fragment
characters and additional slashes; insertion tests cover every boundary of
valid authority-only, collection-only, and complete URIs. Error text becomes
component-specific; acceptance is unchanged. Independent final confirmation is
still required. Extra columns selection code is saved outside the source tree.

Next scaling controls give both clients the same four, then eight, pinned CPU
budgets and matching archive concurrency. These remain short, sequential,
nice-19 / idle-I/O-priority runs (at most eight of 256 logical CPUs). This tests
whether parallel typed transformation changes scaling beyond the two-core case.

## Scaling, load interference, and a longer replay

Matched four-core budgets with archive concurrency four exposed a scheduling
weakness: midpoint Rust/Go ratio 0.8993 [0.8591, 0.9523], despite lower Rust CPU
cost (2.040 vs 2.465 s). Eight cores/concurrency eight were approximately tied:
0.9836 [0.9189, 1.0461]. These are six-pair explorations, not acceptance tests.

Reintroduced per-segment native workers to test the tail: worker2 vs worker1
at four cores improves 1.1271x [1.0766, 1.1917], but at eight cores is 0.9500x
[0.8965, 1.0043]. Reducing concurrent segments to two while increasing workers
also loses to Go: ratios 0.9622 at four cores and 0.8085 at eight cores. Thus
thread count alone does not fix the pipeline.

The sparse path formerly awaited one decode before polling further HTTP bodies.
A bounded fetch+decode stream permits overlap. A first six-pair four-core run
showed 0.9138x [0.8114, 1.0046], during a shared-server load spike (~100 vs the
usual teens); both controls slowed and later recovered. All data is preserved.
Fresh, predeclared repeats show no clear improvement: four cores 1.0158x
[0.9778, 1.0525], eight cores 1.0154x [0.9660, 1.0701]. This remains unqualified.

Stage traces explain the idle time. With two segment slots/eight CPUs, segment1
finishes around 123 ms but sparse segment0 occupies the first ordered slot until
278 ms; new whole downloads cannot start meanwhile. With four segment slots,
the last two whole decodes finish around 718/775 ms, each using only one worker.
The trace binary is separate from all timed candidates. No tracing is retained
in production source.

The longer likes interval (0,100m] delivers 17,186,264 events, cursor 99,998,443.
A diagnostic audit established that Rust's 97 typed failures are identical in
its owned and borrowed decoders: five non-map records, one missing required CID,
and 91 invalid datetimes lacking a timezone. Go reports only the five non-map
failures. We preserve Rust validation and predeclare delta92 for this range.
The typed-error audit is diagnostic, never included in benchmark timings.

Six pairs, seed49405, eight CPUs/concurrency8, existing scoped pipeline versus
Go: Rust 2.1656 s / 11.680 CPU s / 1,021,582 KiB; Go 2.5010 s / 16.715 CPU s /
523,524 KiB. Throughput ratio 1.1613 [1.1397, 1.1822]. Longer work amortizes the
Rust startup/tail, but its eight compressed segment buffers cost twice Go's RSS.
A larger lead needs better scheduling and memory bounds, not a GC explanation.

A global CPU-pool prototype divides whole segments into bounded block groups,
shares immutable compressed bytes, and retains ordered whole-segment rejection.
Initial tests cover a global concurrency limit across simultaneous segments,
owned output retention, row-drop order, cancellation, and competing structural
errors. A deliberately added regression caught early prefix verification
changing which of two structural errors is reported. Prefix failures now travel
with their frame and are selected in decode order; the regression passes.
This prototype is not yet benchmark-qualified.

## Pool, context reuse, and independent sparse fetch controls

The bounded global decode-pool prototype was neutral with 32-block / 8 MiB jobs:
4 CPUs 0.9991x [0.9789,1.0308], 8 CPUs 1.0036x [0.9759,1.0407]. Reducing the
segment count to four on eight CPUs reduced memory but slowed throughput to
0.9233x. Traces show the sparse first segment waiting behind bulk jobs while
later whole segments finish. Smaller 4-block / 2 MiB jobs add scheduling cost:
ratios 0.9030, 0.9063, and 0.9182 versus large jobs for (CPU,segments)=(4,4),
(8,8), and (8,4). Removed the pool API/CLI and its implementation. Prototype
source, tests (including the error-ordering regression), and binaries remain
outside the repository. No unsafe code or new dependencies were required.

Separately tested native zstd context reuse (not the earlier output-buffer
reuse): thread-local dictionary-less DCtx, with independent dictionary/streaming
contexts and fallback on nested/TLS-unavailable calls. Regression tests checked
recovery after bad checksums, bounds errors, dictionary failures, and nested
borrows. No measurable speed gain: 0.9918x [0.9554,1.0315] at two CPUs;
1.0013x [0.9922,1.0087] on the long eight-CPU replay. Removed the cache.

Go actually runs min(2*decode_workers,64) sparse fetches. A standalone adapter
lets us vary Rust's sparse fetch concurrency without changing its segment or
stripe concurrency. Same-binary six-pair comparisons: doubling from4 to8 fetches
at four CPUs gains 1.0276x [1.0147,1.0419], but raises RSS from306k to361k KiB.
Quadrupling is inconclusive, and doubling from8 to16 at eight CPUs is neutral
(0.9839x [0.9429,1.0266]). This small context-dependent result does not yet
justify another production knob. The adapter uses the real library pipeline;
its changes live only in the local artifacts, not the CLI.

A diagnostic forced-whole-file adapter retained primary-window counts/cursor/
errors, and suggests dense sparse plans can benefit from amortizing HTTP calls.
These single runs are not acceptance data. Blindly overriding a plan would need
careful pagination, generation-change, and corruption-contract handling before
it could be a correct general client policy; no such override is retained.

The Go typed path is already efficient: per-block commit slabs and borrowed
metadata/record strings avoid per-record heap objects. Its raw commit path does
not perform Shrike's DID/NSID/record-key/TID envelope validation, and typed text
fields do not enforce Shrike's URI/datetime syntax. We retain those checks.
This comparison measures useful application throughput under differing validation
contracts; equal success totals on a range alone are not proof of equal work.

## Go heap tuning at larger CPU budgets

At eight CPUs on (0,100m], increasing GOMEMLIMIT from512MiB to1GiB improves Go
1.0754x [1.0230,1.1274], with RSS roughly doubling. Removing the limit adds
1.0174x [1.0100,1.0243], with RSS near1.96m KiB. This reverses the two-CPU result
where the smaller target was faster. Future long/eight-CPU comparisons must
include this faster Go control, not extrapolate the earlier12–16% leads against
512MiB to an unrestricted Go process. These are separately randomized controls,
not ratios inferred across experiments at different times.

Current source after removing pool/context experiments passes just check and
just wasm-check. Fresh exact-filter block-frame differential fuzzing ran38,700
cases in91s without failure, using golden plus previously captured real frames.
Compiler exploration now isolates Clang21 vs GCC15 for native C dependencies,
with identical Rust source, thin LTO, one codegen unit, and no CPU-specific flags.
Both compilers were already present locally; no server software changed.

## Native compiler result and priority scheduling

Fresh GCC control reproduces the original block-pipeline binary exactly:
SHA256 f4ab6ad24d419ba28d01bf34c5f431fe0ff620df84208fb37448328adba54471.
Changing only the native C compiler to Clang21 loses throughput: two-core ratio
0.9660 [0.9515,0.9804], long eight-core ratio0.9568 [0.9430,0.9686]. GCC15 remains
the control. No repository compiler defaults changed.

Go heap tuning on the short eight-core range differs from the long range:
unlimited versus512MiB ratio0.8361 [0.8253,0.8463]; keep512MiB for that short
comparison, and unlimited for the long throughput-oriented control. Report the
extra memory cost rather than treating those configurations as interchangeable.

The next bounded-pool prototype prioritizes queued work by segment index, then
FIFO ticket, while letting later segments use otherwise idle workers. The earlier
pool's large jobs helped the final tail but delayed the first sparse segment;
priority targets the measured head-of-line delay without preempting work or
changing delivered order. Whole-segment failures still invalidate all its results.
The pool permits stay with running jobs even if their awaiting future is dropped.

Priority tests cover canceled queued acquisitions, canceled acquired permits,
simultaneous releases that must wake multiple successors, global capacity under
64 concurrent/canceled requests, and a real archive scenario where sparse segment0
arrives while whole segments1/2 are busy/queued. Earlier sparse work must execute
before queued segment2. All pass, as do the original pool's corruption/error-order/
retention tests and Clippy. The scheduler remains an unqualified experiment until
fresh comparisons establish a useful end-to-end gain.

Priority-pool exploration (six pairs each): versus FIFO, four CPUs1.0262x
[1.0117,1.0413], eight CPUs1.0330x [1.0034,1.0627]. Same-binary priority pool
versus serial-per-segment decoding at four CPUs:1.0462x [1.0167,1.0677], with
CPU cost rising1.925→1.995s. Cutting segment concurrency to4 on eight CPUs still
loses:0.9534x [0.9236,0.9847]. Prioritization fixes a real scheduling weakness,
but the gain is modest and the complexity is not yet justified for retention.

A further safe parser prototype replaces repeated fallible u64/u16/u32 reads
in the row loop with fixed-width array slices over the already-validated fixed
region. All five slices have exactly the declared row count; zipped iteration
must retain every row. Structural size/count/kind and UTF-8 checks remain.
This is separate from the previously rejected length-sum vectorization experiment.

## Download policy and safe column iteration

Fixed-width checked column slices: two CPUs 1.0188x [0.9928,1.0487], long
eight-CPU replay 1.0255x [1.0108,1.0393]. Tentatively keep the simpler iteration.
A fused result vector per priority-pool group did not help: four CPUs0.9879x
[0.9673,1.0075], eight CPUs0.9857x [0.9590,1.0096], seeds49431/49432.

A standalone adapter using the real scoped engine and the existing
`stripe_bytes=u64::MAX` configuration established a stronger transport lead.
Same-binary six-pair comparisons (seeds49428–49430), ordinary decoding:

| Workload | Single-stream/striped throughput ratio | 95% paired interval | RSS KiB, striped→single |
| --- | ---: | --- | ---: |
| Primary,2 CPUs | 1.0429 | [1.0240,1.0648] | 278766→207468 |
| Primary,8 CPUs | 1.2000 | [1.1625,1.2461] | 446120→425016 |
| Long,8 CPUs | 1.1524 | [1.1309,1.1741] | 1033334→875106 |

The adapter retains the normal probe, body bounds, validation, and windowing.
Go comparisons already use a single whole-file stream. Add an actual CLI
`--single-stream` option, preserving striping for other network conditions.
This policy win is separate from the observed extra copy/zero-fill in striped
assembly and geometric buffer growth during full HTTP body reads. Those memory
costs deserve isolated experiments after confirming the CLI comparison.

## Single-stream CLI and scheduling interaction

Actual CLI, no pool, six pairs per workload (seeds49436–49439):

| Workload | Rust/Go throughput | 95% paired interval | Rust/Go median wall |
| --- | ---: | --- | --- |
| Primary,2 CPUs | 1.2325 | [1.1986,1.2654] | 0.9965/1.2495s |
| Primary,8 CPUs | 1.1199 | [1.0837,1.1533] | 0.4182/0.4728s |
| Long,8 CPUs | 1.2445 | [1.2289,1.2587] | 1.7100/2.1347s |
| Held-out,8 CPUs | 1.0082 | [1.0016,1.0166] | 0.4961/0.5001s |

Long comparison uses unrestricted Go heap; other controls use512MiB. Long Rust
RSS887308KiB vsGo1981766KiB, CPU10.70 vs14.15s. Still exploration, not acceptance.
The primary two-core RSS is208568 vs529636KiB.

With single-stream fetches the priority pool adds5.0% at4CPUs and10.0% at8CPUs
on the short range, but loses~14% on the long range. Its held-out improvement
is12.5% [9.9,15.3]. Simpler two native workers per segment do better overall:
short eight-core1.1613x [1.1295,1.2015], long1.0637x [1.0435,1.0934],
held-out1.1563x [1.1244,1.1923], versus ordinary serial-per-segment decoding.
The pool is therefore a poor complexity/performance tradeoff so far.

Fresh process-only profile, five long single-stream replays,199Hz cycles:u,
12k samples and no loss:32.9% native zstd sequence expansion,6.4% multiframe
decode,8.8% combined UTF-8 functions,3.7% record-key validation,3.3% strong-ref
decode,3.0% block conversion. libc copy/move routines are another measurable
cost. Artifacts single-stream.perf.data / single-stream.profile.txt.

Incremental ordered stripe assembly now releases range buffers as they are
copied into reserved (uninitialized) Vec capacity; it avoids zero-filling and
retaining every part simultaneously. On failure it drains this generation and
preserves the first error in range order before restarting, matching the prior
request/error behavior. All45 archive tests pass. Next isolated experiment
uses bounded Content-Length allocation hints, without trusting them for body
length, to avoid geometric full-body buffer growth.

## Transport qualification and cleanup

Ordered stripe assembly: two-core1.027x [1.0020,1.0527], long eight-core1.0217x
[1.0002,1.0433]. Primary RSS drops284900→212196KiB; long1054830→1004106KiB.
Content-Length reserve hints, single-stream controls: two-core1.0066x
[0.9832,1.0363], long eight-core1.0303x [1.0058,1.0541]. Long CPU10.685→10.515s,
RSS887668→868100KiB. Keep both modest, general memory improvements.

Further native-worker sweep: at two CPUs1→2 workers is neutral/slightly worse
(0.9763x [0.9546,1.0028]); at four CPUs it adds16.7% [13.6,20.3]. At eight
CPUs2→4 workers adds6.6% short and8.0% previously held-out, neutral on long.
4→8 workers adds no reliable gain. Avoid more threads without evidence.

Removed the global pool and fused-group prototype; retained two/four native
worker configuration for independent confirmation. All removed files/tests
are archived under rejected-priority-*. No unsafe or dependencies added.
Thin LTO/one CGU is now the workspace release profile (standard just build).

The previously held-out100m–120m interval has now informed scheduling decisions,
so final evidence will additionally use untouched intervals200m–220m and
500m–520m. Audit typed error differences before predeclaring comparison deltas;
never silently equate different successful parses.
