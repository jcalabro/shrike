# Jetstream performance investigation

The objective is to improve throughput and CPU efficiency while preserving the
client's validation, ownership, ordering, cancellation, and native/WASM behavior.
Use measurements to choose work; Rust's lack of GC is not itself evidence that
this implementation should win. The current Go profile is predominantly
decompression, not GC.

## Evidence collected

The first cpu3-pop3 comparison used the existing binaries, two allowed CPUs,
nice 19, idle I/O priority, cached archive reads, and `(0, 20,000,000]` filtered
to likes. Three measured runs followed warmups. Both clients delivered
2,532,823 events, ending at cursor 19,999,654.

| Mode | Median events/s | CPU seconds/million events | Average cores | Peak RSS |
|---|---:|---:|---:|---:|
| Go typed | 2.043 million | 0.904 | 1.85 | 517 MiB |
| Shrike stats | 0.618 million | 1.638 | 1.01 | 1,440 MiB |

This is a baseline of the current CLIs, not equivalent typed decoding. Go
decoded likes, recording five typed failures. Shrike only materialized event
envelopes and record bytes. Go used download concurrency 2, one stripe, and a
512 MiB soft Go memory target; Shrike used its download defaults. The runs were
short. Client CPU was measured separately from server CPU. Full baseline
artifacts are local at `/tmp/shrike-jetstream-perf-20260921/`.

Separate process-scoped CPU profiles contain only 340 Rust and 201 Go samples:
enough to identify broad suspects, insufficient for precise small differences.
Rust shows decompression, malloc/free, NSID validation, UTF-8, and lowercase
conversion. Go is dominated by decompression. Shrike needs both less work per
event and parallel CPU work; merely allowing more Tokio threads does not fix
the synchronous decoder inside one polled engine task.

A local Valgrind audit used the existing optimized library, ten synthetic
4,096-row blocks, and the checked-in like record fixture. The same setup ran
in every process; totals below subtract its baseline. These count allocation
and reallocation operations, not throughput or peak retained bytes.

| Existing path | Operations/row |
|---|---:|
| Raw columnar row materialization | 5.0015 |
| Decompress, select, materialize matching events | 11.0061 |
| Same path, but reject every row by collection | 7.0034 |
| Parse one NSID | 2.0000 |
| Match one exact collection | 2.0000 |
| Decode a like into FeedLike (additional work) | 12.0000 |

The synthetic corpus repeats a payload and compresses unusually well. Use it
for allocation attribution only. All audit runs reported zero Valgrind memory
errors. The harness and raw logs are in the local artifact directory.

### First measured change: temporary identifier allocations

Implemented the three small identifier changes described below, preserving the
parsing fallback. Local allocation operations per matching row fell from 11.0061
to 8.0061; all-rejected rows fell from 7.0034 to 6.0034. Exact canonical collection
matching alone now allocates zero times; NSID parsing allocates once, down from
twice. The separate typed decoder remains unchanged.

Uploaded `shrike-cli-perf-20260921-alloc1-95ce85ab` alongside the original binary,
then interleaved three measured runs per binary after warmups, with the same
two-CPU settings and replay range:

| Binary | Wall times (seconds) | Median events/s | CPU seconds/million | Peak RSS |
|---|---|---:|---:|---:|
| Original | 4.10, 4.06, 4.13 | 617,762 | 1.638 | 1,439 MiB |
| Candidate | 3.63, 3.60, 3.56 | 703,562 | 1.445 | 1,404 MiB |

This is 13.9% higher throughput and 11.8% less CPU time per event in this workload.
All counts, final cursors, and zero residual gaps matched, with no client errors.
The DID-filter optimization is not exercised by this collection-only replay.
Memory only fell about 2.4%, reinforcing that transient identifier allocations
and bulk buffering are different problems. Raw data and the allocation audit are
in `alloc1-runs.jsonl` and `alloc1-report.md` in the local artifact directory.

Validation: `just build --release` and `just check` passed, including formatting,
Clippy, workspace unit/integration tests, and doctests. Filter regression cases
cover authority normalization, case-sensitive names, malformed strings,
wildcards, and kind/DID intersections; the existing filter-equivalence property
now includes mixed-case collections. All candidate Valgrind runs reported zero
memory errors. The uploaded candidate's SHA-256 is
`a080af95fec50d920a70073b35d7de29495082e5d8411cbc4e9f1df7d984a1e8`.
The original server binary's hash is unchanged, all benchmark processes exited,
and the existing Jetstream service retained its original PID.

## Measurement work, in order

### 1. A repeatable local corpus and stage benchmarks

Fetch a small bounded set of real compressed blocks/segments through existing
read-only endpoints, streaming to local files. Record hashes, byte sizes,
sequence bounds, expected selected counts, and error counts. Bound the initial
capture (for example, 16–64 MiB compressed, one request at a time), then expand
only if it fails to represent an important workload. Keep current golden and
malformed fixtures as correctness inputs; their tiny size is not representative
of performance. No record payloads are needed in diagnostic output.

Use the existing Criterion dependency for separate benchmarks:

1. Decompression only: compressed bytes to a decoded block.
2. Column layout validation and row selection on already decompressed bytes.
3. Event materialization from selected rows, including drop costs.
4. Typed FeedLike decoding, separate from envelope conversion.
5. Complete segment decoding, including buffers and checksums.
6. Engine delivery through an in-memory ArchiveSource and a counting sink.
7. Real HTTP replay against the existing server.

Preload corpus bytes outside timing loops. State whether buffer/context setup,
allocation, destruction, and record retention are included. Report ns/input row,
ns/selected event, compressed and decoded MiB/s, allocation operations/event,
and allocated bytes/event. Use black_box or a consumed output to prevent dead
work elimination. Do not compare wall times measured under Valgrind to normal
execution times.

Run both realistic corpus rotation and repeated-block tests: one shows normal
working-set effects, the other isolates instruction/allocation costs. Include
0%, sparse, and 100% selection; exact and wildcard collections; DID filtering;
likes and larger records; marker/delete events; and malformed siblings.

### 2. Low-overhead stage and memory accounting

Add opt-in diagnostics at block/batch boundaries, not per-row timestamps or
shared atomic increments. Accumulate local counters and emit once per second
plus a final snapshot:

- Raw rows, kind/DID/collection rejections, sequence-window rejections,
  materialized/delivered events, and typed successes/failures.
- Downloaded compressed bytes, decoded bytes, record bytes retained, and
  request/block/segment counts, retries, and mode (whole segment versus blocks).
- Download, decompression, layout/filtering, materialization, typed decode,
  delivery, and destruction durations, with explicit inclusive/exclusive labels.
- In-flight compressed bytes, decoded block storage, event-vector length and
  capacity, completed-but-undelivered bytes, and high-water marks.

Sample a small fraction of blocks into a timestamped timeline: request queued,
download started/completed, decode queued/started/completed, delivery started/
completed, backing storage released. This exposes executor starvation,
head-of-line waiting for an earlier segment, idle workers, and slow consumers.
Wall durations of overlapping stages must not be added as CPU time.

Report memory amplification as retained bytes divided by useful record bytes,
not just process RSS. A shared block slab may save copying yet retain an entire
block for one small surviving record. Benchmark consumers retaining no records,
one per block, and bounded batches before choosing storage policy.

### 3. Better external profiling

Build optimized diagnostic binaries with debug information; retain the exact
binary and build flags alongside every profile. Collect enough CPU samples
across repeated bounded local replays for stable major hotspots. Use separate
instrumented and timing runs; quantify instrumentation overhead with an A/B.

- `perf stat`: instructions, cycles, branch misses, cache misses, task-clock,
  context switches, and page faults, normalized per input/delivered event. Check
  availability/multiplexing and use small event groups.
- `perf record`: inclusive and self-time call graphs, broken down by thread.
- Existing local Valgrind: allocation totals now; Massif/Callgrind for controlled
  local memory lifetime and call-cost investigations. Avoid heavy instrumentation
  on the shared server. Heaptrack or an allocator experiment can be considered
  later if existing tools cannot answer the question; no new Cargo dependency
  is needed to start.
- Observe server CPU and physical reads separately. Client affinity does not
  bound server work. Never drop shared page caches, change service settings,
  restart services, or perform system-wide profiling for these comparisons.

### 4. Comparable end-to-end and scaling tests

Add typed-like mode with explicit decode counters, monotonic elapsed time,
interval and whole-run throughput, and once-per-second reporting. Expose
download concurrency, decode concurrency, stripes, batch size, and buffered-byte
budget separately; do not use one concurrency number for all memory terms.

Keep two comparisons: equivalent completed work under matched resource limits,
and separately documented best practical settings. Match validation/unknown-field
behavior where possible; disclose differences instead of weakening correctness
for a headline number. Compare output fingerprints, sequence order, and error
classification outside timed runs, not merely total counts.

Start with one/two/four allowed CPUs and an independently controlled worker
count on local data. Vary only one knob per experiment. Measure throughput,
CPU/event, RSS, and retained bytes together. Add slow-consumer and delayed-first-
segment tests to verify backpressure and ordered reassembly. Keep server trials
short, sequential, low priority, and scoped to fixed replay ranges. New candidate
binaries may be uploaded under unique names per the user's authorization; retain
the original binary for interleaved comparisons and capture results locally.

## Concrete profiling tools

Inventory checked on 2026-09-21. No profiling package installation is necessary
to start. Local machine: AMD Ryzen 9950X; server: AMD EPYC 9745, 128 physical
cores/256 threads. The local and server CPUs differ: local hardware timing is
not a substitute for server measurements.

| Tool | Availability | Question and intended use |
|---|---|---|
| perf stat | Server | Instructions/cycles/branch misses per event; task-clock, faults, switches. Small simultaneous groups avoid multiplexing. Establish whether a change removes work, changes IPC, or moves cost between user and kernel. |
| perf record, report, annotate, diff | Server | Sampled call stacks, inclusive/self cost, and hot machine instructions. Normalize by completed work and total CPU; profile percentages alone can rise when another component improves. |
| perf mem / AMD IBS | Server has ibs_op and ibs_fetch PMUs | Sample costly memory operations and instruction-fetch behavior, subject to the kernel/tool's precise-event support. Investigate load latency, cache/TLB misses, pointer chasing. A generic cache-miss counter does not identify the responsible structure. |
| perf c2c | Conditional AMD IBS support | Investigate cache-line contention/false sharing once parallel workers exist. Check precise data-source support first; not an immediate priority for the serial decoder. |
| Valgrind DHAT, heap mode | Local, already run | Allocation call stacks, cumulative bytes, lifetime, peak live blocks, and read/write use. Distinguish high-frequency transient allocations from large retained backing stores and unused capacity. |
| Valgrind DHAT, copy mode | Local, already run | Attribute memcpy/memmove traffic to call stacks, including intermediate event moves. It misses compiler-inlined/custom copies; not a complete memory-bandwidth meter. |
| Massif + ms_print | Local | Heap-growth timeline and allocation trees at peaks. Run local replay with slow consumers or retained records. Useful live-heap bytes differ from RSS and allocator fragmentation. Page profiling is a separate mode with a different interpretation. |
| Heaptrack | Not installed | Native allocation/lifetime profiling with less slowdown than Valgrind, useful if DHAT changes behavior too much. Optional local tooling; not required to proceed and not to be installed on the shared server. |
| Callgrind + callgrind_annotate | Local | Instrumented call graph and instruction counts for fixed-input stage benchmarks. More stable than short wall times; counts still reflect compiler/build changes and setup must be separated. |
| Cachegrind + cg_annotate | Local | Simulated cache/branch behavior for controlled layout changes. Its model is not the actual Zen 5 cache/prefetch hierarchy; confirm conclusions with real PMU data. |
| strace -f -c (or filtered -w -c) | Local and server | Count writes, reads, recv/send calls, mmap/munmap, futex and epoll activity. Quantify per-batch flushing and syscall amplification; wall-blocked versus CPU time have different meanings. Keep traced timing out of throughput comparisons. |
| bpftrace / scheduler tracepoints | Server | Short PID/TID-scoped off-CPU, wakeup, and syscall-latency histograms when waiting is the unresolved question. Do not attach high-rate per-allocation stack probes or broad system-wide tracing on the shared host. A PID predicate does not remove all global tracepoint overhead. |
| pidstat -t, /proc/PID/task/*/schedstat | Server | Per-thread CPU, switches, run time versus scheduler wait. Distinguish one busy decoder from idle workers, blocked I/O, or runnable threads being descheduled. |
| /proc/PID/smaps_rollup, numastat -p, numa_maps | Server | RSS/PSS/private memory and placement by NUMA node. NUMA tests matter only after checking the host topology; one socket alone does not establish the node count. |
| iostat, vmstat, sar, /proc/pressure | Server | Disk latency/physical reads, reclaim, and host contention. Correlate with client/server process metrics; these shared-host figures cannot be attributed to our run alone. |
| Criterion / Hyperfine | Criterion already a dependency; Hyperfine on server | Repeated stage/end-to-end measurements, warmups, distributions, and saved results. Use bounded workloads; never use a shared-cache-dropping prepare command. |
| objdump / rustc --emit=asm,llvm-ir | Existing toolchain | Check inlining, bounds checks, large enum/struct moves, vectorization and duplicated loads in already identified hotspots. cargo-show-asm is optional convenience, not necessary. |
| llvm-mca | Not installed | Static throughput/port-pressure analysis of a small hot loop once identified. It cannot model actual cache misses, allocator behavior or async scheduling; use a supported matching CPU model. |
| perf script + flamegraphs / Speedscope / Perfetto | Export possible; viewers optional | Interactive CPU and sampled stage timelines, preferably differential views. Flamegraphs explain sampled CPU, not time waiting. A block timeline explains download/decode/delivery overlap and ordered-buffer stalls. |
| Tokio console | Requires instrumentation/tooling changes | Poll duration, task busy/idle behavior and async resource waits. Useful if executor stalls remain unexplained; per-block timestamps and /proc thread data are the dependency-free first step. |
| Go pprof, GODEBUG=gctrace=1 | Go client exposes optional pprof; GC trace is per-process env | Measure the comparison client's GC CPU, allocations, live heap and blocking rather than inferring its costs from language choice. Distinguish alloc_space from inuse_space. Diagnostic settings belong in separate runs. |

Use expensive instruction/heap instrumentation locally on fixed corpora. Use
low-overhead process-scoped PMU measurements on cpu3-pop3. Profiles and reports
stay local; no service restarts, shared kernel setting changes, or server package
installations. Perf/BPF advanced sampling needs capability verification before
use; an advertised PMU does not prove every precise sampling mode works.

### Additional measurements already collected

Four bounded server perf-stat runs (original/candidate/candidate/original) used
the original and allocation-experiment binaries. All counters in the selected
group reported 100% running coverage, and every run delivered identical totals
and cursor. User instructions per delivered event decreased about 14.7%, with
IPC approximately unchanged at 3.38–3.39. This strengthens the evidence that the
first optimization removes executed work rather than relying on timing noise.

Local candidate DHAT profiles identified different costs than allocation counts
alone: 41.3 MB of cumulative requested allocation sizes growing decompression
output, 17.7 MB growing event vectors, and 14.5 MB of ZSTD stream allocations
across ten synthetic blocks. These are allocation/growth totals, not peak memory.
Copy mode identified 13.2 MB copied at the decompression output plus two event
conversion sites at 8.85 MB each. Those event moves deserve assembly inspection
alongside the known per-row payload copies. Confirm all findings on real blocks.

Raw artifacts and interpretations are in
`/tmp/shrike-jetstream-perf-20260921/additional-tools-report.md`.

## Opportunities identified in the code

### Small, immediately testable changes

1. **Avoid temporary NSIDs for exact canonical collection matches.**
   `Filter::matches_segment` currently parses/allocates an NSID which
   `raw_event_to_event` parses/allocates again. Equality with an already validated
   canonical exact filter proves validity. Preserve the parsing fallback for
   case normalization, nonmatches, and wildcard validation. This removes two
   allocation operations for the common matching row in the baseline.
2. **Normalize NSIDs in one allocation.** Copy the complete input once, lowercase
   only its authority in place, and reuse the last-dot position from validation.
   The current partial-string allocation grows when appending the name. Preserve
   case-sensitive names and all validity checks.
3. **Borrow DID keys for lookup.** `Did` already implements Borrow<str>; a valid
   filter's HashSet can reject or accept a raw DID without constructing a
   temporary Did. Invalid strings cannot equal a validated stored identifier.
4. **Throttle stats.** Current CLI stats format/flush once per 64-event batch.
   Make it time-based with an unconditional final report. Measure this separately;
   the initial CPU sample does not establish it as the dominant cost.

The first three form the first small allocation experiment. They need explicit
normalization, name-case, malformed-input, wildcard, and kind/DID intersection
coverage, followed by existing filter equivalence properties and end-to-end tests.

### Larger opportunities with stronger upside

**Stop copying rows before deciding to retain them.** `block::decode_block`
allocates five Vecs per row, plus five length arrays per block. The filtered path
first builds all RawEvents, then applies predicates. Introduce an internal
validated borrowed block view: validate all structural layout/kind constraints,
select rows, materialize selected metadata once, and make record Bytes slices
from a shared decompressed block. Preserve public owned RawEvent APIs as adapters
if needed. Borrow metadata while decoding rather than creating five refcounted
handles per row. Preserve malformed-row/drop behavior and sequence-window error
semantics; early filtering must not silently change which corruption is reported.

**Reduce full-segment buffering before increasing parallelism.** Whole-segment
range downloads collect all stripe buffers, allocate/zero a full destination,
then copy. Block downloads collect all frames before decoding. Decoded Events
are accumulated for a whole segment; window() builds another vector before the
engine rebatches into 64-event allocations. Consume bounded results incrementally,
reduce vector moves/growth, and introduce byte-based backpressure. Memory must
remain bounded when an earlier result is delayed or the sink retains batches.

**Add bounded native decode workers.** buffered() overlaps I/O but does not run
the synchronous decoder on separate CPUs. Use a bounded native worker mechanism
with worker-local decompressor context and scratch space, preserving ordered
delivery and the WASM path. Do not spawn one unbounded blocking task per row or
segment. Large current per-event buffers make this a poor first change in isolation.

**Direct generated typed decoding.** FeedLike::decode_cbor first materializes a
generic Value::Map; nested subject/via values are then encoded back into CBOR
and decoded again. The allocation audit measures twelve operations per fixture
record, additional to envelope work. Change the lexicon generator and necessary
decoder primitives, then regenerate; never hand-edit generated bindings. Preserve
unknown fields, CID handling, canonical rules, depth limits, required fields,
duplicate handling, and trailing-data rejection. This benefits the whole library
but is a separate, higher-risk project from the initial Jetstream allocation fix.

**Reuse decompression state and scratch buffers.** The native path builds a new
stream decoder per frame and copies through a 64 KiB stack buffer into a growing
Vec. Measure context setup, output growth, and copies before adopting safe bulk
or reusable-buffer APIs. Preserve concatenated/skippable frames, dictionary
behavior, checksum/trailing-byte rejection, window limits, and total output caps.

## Decision and validation discipline

One measured hypothesis per candidate. Save build revision/diff hash, compiler,
CPU assignment, all runtime knobs, corpus manifest, errors, raw measurements,
and profile provenance. Interleave original/candidate runs and report spread;
keep only improvements larger than measurement noise. A faster result with fewer
valid delivered events is a correctness failure, not a performance win.

Use existing syntax vectors, Jetstream property tests, engine/archive integration
tests, and fuzz targets. Changes to borrowed/shared storage additionally need
retention-after-batch-drop tests, cancellation with in-flight work, ordering under
out-of-order completion, bounded-memory slow consumers, and native/WASM parity.
Do not remove validation, introduce unsafe code, or add Cargo dependencies for
the initial work.

## Active-goal experiments (2026-09-21)

Captured 36 real getBlock frames (3,175,495 compressed bytes) from early and
later sequence ranges, with unfiltered/like/post queries. Provenance and SHA-256
hashes are in the local artifact directory's `corpus/manifest.json`. The corpus
contains 42,680 rows. New `examples/jetstream_bench.rs` preloads these files and
measures decompression, raw rows, filtered events, and typed likes separately;
its verification mode hashes full event metadata, record bytes, markers, errors,
and frame boundaries. Five filter fingerprints match the alloc1 baseline.

The first borrowed decoder inspected metadata and filtered without constructing
owned raw rows, sharing payload slices of each decompressed block. Twelve
randomized paired remote runs against alloc1 (one excluded warmup pair) showed
1.1461x throughput, paired-bootstrap 95% CI [1.1337, 1.1588]. Median time was
3.0746 versus 3.5527 seconds, but median peak RSS grew from 1,433,846 to 2,850,118
KiB. **Reject shared block storage as the default.** A retained small record can
also pin the whole slab. Keep borrowed metadata but copy accepted payloads into
independent allocations; this variant is being evaluated.

Raw data: `borrowed-slab-runs.jsonl`, adjacent summary, and saved exact binaries.
The reusable `scripts/bench-jetstream.py` records binary hashes, randomized
paired order, per-run counts/cursors/gaps, CPU, wall time, RSS, and load average.
It runs sequentially on CPUs 2 and 3 with nice 19, idle I/O priority, and hard
timeouts; it writes artifacts locally and installs nothing remotely.

Next experiment: native zstd bulk decoding for frames with declared sizes up to
8 MiB. Validate complete frame boundaries before reserving, enforce the same
window and cumulative output limits, and retain streaming for unknown/larger
sizes. The small reservation ceiling prevents a dishonest size header from
forcing a huge eager allocation. This must pass checksum/dictionary/truncation,
mixed concatenation/skippable/empty-frame, and threshold regression tests.

### Accepted borrowed-metadata / bounded bulk-decode candidate

`shrike-cli-perf-20260921-bulk-copy-v1` gives each selected payload independent
storage. Across 12 measured randomized pairs versus alloc1, likes `(0,20m]`
complete in median 2.8775 versus 3.5967 seconds: 1.2495x throughput, 95% paired
bootstrap CI [1.2456,1.2533]. Peak RSS is essentially unchanged (~1.36 GiB).
CPU medians are 2.920 versus 3.645 seconds. Local DHAT setup-subtracted counts
are 4.0032 allocation/reallocation operations per selected event (down from
8.0061 in alloc1); rejecting every row costs 1.0005 operations/input row.
That remaining rejected-row allocation is collection normalization.

Separate 12-pair workload checks, both `(0,5m]`:
- Posts: 1.3617x throughput, CI [1.3470,1.3735], 0.4950 vs 0.6763 seconds.
- Unfiltered: 1.0877x, CI [1.0689,1.1018], 1.0081 vs 1.1039 seconds.
These short runs include process startup. They validate transfer across filters,
not full equivalence to typed Go work. All final counters/cursors/gaps matched.

Checks: full `just check`, `just wasm-check`, checksum/dictionary/truncation/
concatenation/threshold tests, and five real-corpus fingerprints passed. A
5-replay process-scoped perf sample at 199 Hz collected ~2k samples with 63
lost samples (so small differences in percentages are not reliable). zstd's
sequence decoder is ~24% self time; NSID conversion ~4.3%, with about half from
filtering; allocations/free/copies and other syntax validation remain prominent.
Exact binaries, DHAT, perf stream and symbolized report are saved locally.

### Subsequent hypotheses under measurement

1. Exact collection comparisons can compare authority bytes case-insensitively
   and the name case-sensitively against a validated filter. Neither matches nor
   mismatches then require allocating a temporary NSID. Wildcard predicates
   still fully validate via the parser. Added a property check against the
   validating NSID parser, including arbitrary Unicode and mixed-case inputs.
2. Apply whole-segment sequence-window filtering in place with `Vec::retain`.
3. Consume bounded ordered block downloads incrementally, instead of collecting
   all compressed frames before decoding the first. Preserve prefix/error order.
   These form `shrike-cli-perf-20260921-stream-window-v1`, being compared with
   bulk-copy in 12 paired primary-workload runs.
4. Native decoding jobs on Tokio's blocking pool, with only owned bytes/filter
   crossing threads. Each active ordered segment has at most one job. Pending
   jobs are aborted on future drop; running segment jobs check cancellation at
   block boundaries. Browser/non-Tokio callers keep synchronous decoding. Unit
   tests cover result/error preservation, non-Tokio fallback, and cancellation
   on future drop. Archive/engine/property tests pass; release build in progress.

Do not conclude optimization is exhausted. Still to measure: native parallel
throughput/memory/CPU and holdouts; CLI reporting and equivalent typed mode;
generated typed decoder re-encoding; decoder-context/output reuse; stage and
memory profiles; broader retained-record/filter/concurrency workloads. The new
fuzz differential target compares owned and borrowed frame decoding, including
record bytes and row errors, but has not yet been executed in this environment
(cargo-fuzz/nightly are not on PATH).

### Measured follow-up results

All comparisons below use 12 randomized paired runs, exclude one warmup pair,
and resample complete pairs for the 95% bootstrap intervals. Remote work stays
on CPUs 2 and 3, nice 19, idle I/O priority, with process timeouts.

| Change | Baseline | Geometric speedup (95% CI) | Notes |
|---|---|---|---|
| Exact filters, in-place windows, incremental downloads | bulk-copy | 1.1058 [1.1004,1.1118] | 2.5016 vs 2.7627 s median |
| Native blocking decode workers | stream-window | 1.575 [1.5617,1.5892] | 1.6078 vs 2.5215 s; RSS rises about 10% |
| Rate-limited CLI progress | parallel | 1.0467 [1.0372,1.0574] | 1.5531 s untyped |
| Nested generated typed conversion without re-encoding | stats, typed, concurrency 2 | 1.1078 [1.0968,1.1189] | 2.9811 vs 3.3030 s |
| Allocation-free component syntax validation | typed-value, typed, concurrency 2 | 1.0013 [0.9914,1.0113] | No measurable remote throughput improvement |

Typed concurrency 2 is about 3.5% slower than 8, but reduces peak RSS from about
1.57 to 0.95 GiB. It is the setting for subsequent typed comparisons. The CLI
now exposes `--download-concurrency` and `--typed-likes` (requires `--stats`).
Typed decoding happens on the serial consumer; archive envelope decoding runs
on bounded blocking workers. These are different measurements and must not be
presented as equivalent workloads.

Generated nested decoding changes were made in lexgen and regenerated from the
exact existing lockfile commits. Required fields, syntax checks, unknown fields,
and canonical CBOR constraints remain enforced. Full checks and WASM checks
passed through the validate-v1 milestone. The real typed corpus fingerprint is
`2b04d91d26baebceb195c52500e60c398e7cebbc457dac32c75d07647af2a6d6`
(22,721 successful decodes, zero errors on this small corpus).

The primary remote replay contains six Rust typed failures. Five are non-map
records (seq 10716103, 10716104, 10716105, 10716109, 10716115), and seq 3384096
is missing the required subject `cid`. Go reports only five failures because
its strong-ref decoder does not check this required field; it also does not
validate the URI syntax to Rust's standard. Go uses borrowed record/string
lifetimes and parallel typed archive decoding. Keep these differences explicit
in comparisons; do not weaken Rust validation or retention guarantees.

The latest typed perf sample (five bounded process-scoped replays, 99 Hz) has
about 15.6% self samples in zstd sequence decoding, 8.4% in generic CBOR decode,
8.3% in FeedLike decode, 7.3% combined in DID validation, and 4% in record-key
validation. Temporary CBOR maps and branch-heavy ASCII validation are the next
hypotheses. Fewer allocations alone did not predict remote speed in validate-v1.

Current experiment: stream top-level typed CBOR map entries, avoiding the
materialized map vector while sharing canonical-key validation. Differential
property tests cover acceptance and decoded values, plus truncated real records,
key order/duplicates/UTF-8, limits, sequential values, and early drop. This
experiment is not yet accepted on performance evidence.

### Streaming CBOR, validation, and ownership experiments

Additional 12-pair comparisons on the primary replay:

| Candidate | Workload / baseline | Throughput ratio, paired 95% CI | Median wall seconds |
|---|---|---|---|
| map-v1: stream top-level typed CBOR fields | typed, validate-v1 | 1.0548 [1.0450,1.0658] | 2.8170 vs 2.9657 |
| fold-v1: vectorizable DID/rkey validation | typed, map-v1 | 1.0882 [1.0797,1.0959] | 2.5963 vs 2.8354 |
| direct-v1: nested typed structs decode in place | typed, fold-v1 | 1.0792 [1.0691,1.0874] | 2.3968 vs 2.5972 |
| reserve-v1: one reservation per output batch | untyped, direct-v1 | 1.0392 [1.0234,1.0553] | 1.5732 vs 1.6460 |
| cache-v1: thread-local bulk zstd context | untyped, reserve-v1 | 0.9807 [0.9582,1.0021] | 1.6331 vs 1.5883 |
| small-cache-v1: inline short DID/NSID/rkey storage | untyped, cache-v1 | 1.1993 [1.1862,1.2139] | 1.3261 vs 1.6054 |
| mapped-v1: two parallel typed workers per batch | typed, same binary, batch 4096, serial vs parallel | 1.0221 [1.0069,1.0369] | 2.1738 vs 2.2360 |

All these runs use archive concurrency 2. **Reject cache-v1**: no measured gain,
extra state and complexity. It has been removed. **Reject parallel batch mapping
as implemented**: only 2.2% faster while CPU grows from 3.05 to 3.33 seconds.
The experimental API, CLI decoding option, and tests were saved in the artifact
directory and removed from the implementation. The same benchmark binary is
retained for reproducibility. An explicit CLI batch-size option remains useful
for measuring delivery overhead; defaults are unchanged.

Inline identifier storage is independent owned storage, not an interner or a
borrowed reference into a slab. A private 32-byte inline buffer falls back to a
String for longer values. No unsafe code or dependency was introduced. Public
string access, ordering, hashing (including Borrow<str> compatibility), Debug,
serde, validation, and normalization remain unchanged. Property tests cover
Unicode, hashing/order, case normalization, cloning, and inline/heap boundaries.
Peak RSS in its paired comparison falls from 963,646 to 828,158 KiB. Event size
rises from 216 to 248 bytes but avoids three heap allocations for common short
identifiers. A URI-specific inline buffer is the next experiment, not yet
accepted on throughput evidence.

The generated streaming decoder and materialized typed decoder agree on every
single-byte mutation and truncation of a real like record, including canonical
keys, missing/invalid fields, and nested unknown values at depth boundaries.
Unknown fields remain preserved. All five real event-corpus fingerprints and
the typed corpus fingerprint still match. Full workspace checks and WASM checks
passed at the direct and mapped milestones (see artifact logs).

The fresh direct-v1 typed perf profile has zero lost samples. zstd sequence
expansion is ~18.3% self samples, FeedLike decoding ~4.6%, native malloc/free and
copying are prominent, and the former DID validation hotspot is substantially
reduced. Percentages are not normalized work costs: reduced CBOR work makes
zstd's share grow even without zstd getting slower.

The first bounded ASan/libFuzzer campaign completed roughly 99k compressed-frame,
29m block-body, 2.6m bounded-decompression, 3m syntax, and 2.5m CBOR differential
executions without a failure. The initial compressed-frame run started empty
and mostly tested rejection paths; do not overstate that coverage. Added golden
and real compressed frames, decompressed block bodies, and record CBOR seeds for
the next campaign. The seed generator now includes Jetstream goldens and typed
record fixtures. The CBOR differential target additionally checks generated
Like/Post/Profile acceptance against strict generic CBOR and typed round trips.

Benchmark metadata now includes context switches, faults, and filesystem I/O.
The harness can compare Go and Rust with an explicit predeclared typed-error
count difference, while requiring equal event/cursor coverage. This does not
make their ownership or validation contracts identical.

### Archive progress during delivery

The per-delivery parallel-mapping experiment exposed an upstream scheduling
limitation: pending archive HTTP/decoder futures were only polled when asking
for the next whole segment. Synchronous typed consumption could leave I/O idle.
`OrderedDownloads` now drives those futures while the sink handles each batch,
without spawning the !Send transport. Futures and completed queued results stay
ordered; the current delivered segment also occupies a concurrency slot. This
bounds memory even with a slow sink. The consumer's return value, errors,
cancellation, and cursor semantics are unchanged.

Against URI-v1 (same storage and typed work), twelve pairs give 1.1648x throughput
[1.1495,1.1786], median 2.0121 vs 2.3529 seconds. RSS falls from 872,068 to 755,234
KiB; CPU changes from 3.170 to 3.235 seconds. Keep this change. New unit tests
cover pending I/O progressing while the sink waits, strict ordering, !Send
futures, ready-result bounds, and one-slot behavior. All engine oracle tests,
full workspace checks, and WASM checks pass.

**Reject inline URI storage.** The larger owned value representation was slower:
ratio 0.9587 [0.9460,0.9720], median 2.3510 vs 2.2512 seconds, and higher CPU.
Restored AtUri's original String representation; short DID/NSID/rkey storage
remains inline. The accepted pipeline has also been rebuilt without URI storage
as `pump-small-v1`.

Next isolated candidates are strict direct text-field decoding (avoiding the
intermediate generic Value for known scalar fields) and short timestamp storage.
The real like corpus has timestamp lengths 24: 22,618; 27: 52; 32: 51. A 24-byte
inline timestamp representation can therefore avoid almost all timestamp heap
allocations without increasing every timestamp value as much as URI storage
did. Longer timestamps retain the existing heap representation and validation.
These two candidates remain experimental until their paired measurements finish.


### Final-stage measurements and diminishing-return experiments

Reject direct scalar text decoding: text-v1 / pump-small-v1 throughput ratio
1.0102 [0.9943,1.0280]. Reject inline 24-byte timestamp storage: date-text-v1 /
text-v1 ratio 1.0084 [0.9935,1.0236]. Neither shows a clear throughput benefit;
both experiments were removed. These comparisons do not establish equivalence,
but do not justify retaining additional implementation complexity.

The direct original-versus-pump-small-v1 untyped comparison confirms **3.1093x
[3.0392,3.1696]** throughput, median 1.3121 versus 4.0886 seconds. Median CPU is
2.150 versus 4.135 seconds, RSS 781,902 versus 1,474,792 KiB. The new client uses
archive concurrency 2; the original uses its defaults. All 2,532,823 events,
last cursor 19,999,654, and zero residual gap agree. Twelve randomized measured
pairs plus excluded warmup, same pinned CPUs, process time including teardown.

Go typed versus Rust typed: Go median 1.2317 seconds, Rust 1.8476; Rust/Go
throughput ratio 0.6678 [0.6577,0.6770]. CPU 2.270 versus 2.970 seconds and RSS
530,174 versus 785,838 KiB. Both use archive concurrency 2, CPUs 2/3, and one
Go stripe. Go has the documented 512 MiB soft memory target. Counts and cursor
agree; the predeclared one-record validation difference remains. Rust has
improved substantially but does **not** beat Go's fast typed client.

A fresh five-replay 99 Hz process-scoped perf sample has zero lost samples.
Zstd sequence expansion accounts for 19.5% self samples; another zstd frame
routine 4.3%; UTF-8 conversion appears on both decoder and consumer threads;
copying, typed strong refs/maps, and NSID validation remain visible. This
motivates checking redundant UTF-8 work and per-block event-vector copies.

Final-milestone DHAT (40,960 synthetic records, setup subtracted) measures
1.003 allocations per filtered event, down from about eleven originally, and
four allocations per typed like: owned type, CID text, URI, and timestamp.
Removing these through borrowed public values would change the contract;
inline URI/timestamp experiments already failed their throughput tests.

All five real event-corpus fingerprints and the typed fingerprint match at
pump-small. `just check` and `just wasm-check` passed again. The seeded fuzz
campaign is running; it is not yet counted as completed validation.


Further holdouts on pump-small versus original untyped (12 pairs each): posts
(0,20m] improve 2.7249x [2.6747,2.7724], median 1.0586 versus 2.9127 seconds;
unfiltered (0,5m] improves 1.9878x [1.9722,2.0056], 0.6085 versus 1.2085 seconds.
The shorter unfiltered run includes a larger startup fraction; do not compare
its absolute rate directly to the primary likes replay.

Reject reusing UTF-8 results between filtering and conversion: ratio 1.0111
[0.9933,1.0350], no clear throughput gain. Restored the simpler conversion
signature. Keep direct segment accumulation: avoid each block's temporary
`Vec<Event>` and its move into the segment vector. Isolated untyped comparison
(append-utf8 versus utf8) is 1.0227 [1.0074,1.0380], RSS 724,734 versus 779,138
KiB. Rebuilt without the rejected UTF-8 experiment as append-v1. Its typed
comparison against pump-small is 0.9954 [0.9801,1.0107], no detected throughput
change, but RSS falls from 771,110 to 724,096 KiB. A new multi-block integration
test compares whole-segment versus individual-block contents/errors, and checks
that a corrupt later block cannot return a successful prefix. All 38 archive
integration tests pass. The initial test fixture used an out-of-order zero
sequence; the structural parser correctly rejected it. Corrected the fixture
to test a recoverable invalid revision instead.

The bounded parallel-map experiment is being retried after the archive polling
change, using the same binary and batch 4096 for both serial and two-worker
cases. Source remains experimental until its new paired result is evaluated.


Reject the parallel mapping retry as well: after the pipeline fix, two workers
versus serial at batch 4096 give 0.9859x [0.9724,0.9991] throughput, median
1.9186 versus 1.8941 seconds, and CPU 3.235 versus 2.975 seconds. The experiment
has been removed again; no parallel-mapping public API is retained. Full
workspace checks and WASM checks pass on the accepted append-v1 source.


Final configuration check: concurrency 8 versus 2 on the two pinned CPUs gives
0.8816x [0.8678,0.8953] throughput, typed wall 2.0783 versus 1.8325 seconds, and
RSS 1,437,766 versus 730,162 KiB. Use concurrency 2 for this host/workload;
leave the library default unchanged for other machines and network conditions.

Later-range holdout, likes (20m,40m], accepted append-v1 versus original:
3.5519x [3.4863,3.6112] throughput, median 1.5062 versus 5.4106 seconds, CPU
2.665 versus 5.455 seconds, RSS 829,324 versus 2,207,050 KiB. Event/cursor/gap
checks agree. This range was not used to choose optimizations.

Rebuilt release after removing experimental mapping; its SHA-256 exactly
matches the measured append-v1 binary:
`bfd1680ad56002bd8edb27a213b0f7a75e55f15278fe4e80e7bba0cf97018cab`.
All five corpus fingerprints and the typed fingerprint match again.


### Accepted final binary: direct confirmation

Final direct comparisons use append-v1, twelve randomized measured pairs plus
one excluded warmup pair, CPUs 2/3, nice 19, idle I/O class, and hard deadlines.
All primary replays cover exactly 2,532,823 events with last cursor 19,999,654
and residual gap zero. Wall timings include process startup and teardown.

| Work | Baseline median | Accepted Rust median | Throughput ratio (paired bootstrap 95%) |
|---|---:|---:|---:|
| Untyped likes, original Rust versus accepted | 4.1032 s | 1.3239 s | 3.0930 [3.0251,3.1619] |
| Typed likes, Go versus accepted Rust | 1.2394 s | 1.8862 s | 0.6559 [0.6410,0.6689] |

Untyped CPU falls from 4.155 to 2.135 seconds; RSS from 1,472,236 to 709,532 KiB
(about 52% lower). Typed Rust uses 3.015 CPU seconds and 703,130 KiB, versus Go's
2.270 and 529,854 KiB. Go retains its lower-validation, borrowed-value contract
and 512 MiB soft memory target. Rust retains six typed errors versus Go's five;
no required validation is removed to manufacture equality or a speedup.

Four separate process-scoped perf-stat runs (original/accepted/accepted/original)
report 100% running coverage for the selected PMU group. Average user
instructions per event fall from 17,321.6 to 9,276.5 (46.4%); cycles from 5,109.2
to 2,441.8 (52.2%); branch misses from 17.96 to 12.86. These diagnostic runs are
separate from the throughput sample and all counters/cursors agree.

The stopping decision is based on diminishing measured returns, not a claim
of globally optimal code. Ownership/validation/decompression dominate the
remaining work. Context caching, extra typed workers, larger inline URI/date
values, direct scalar text decoding, and UTF-8 result reuse failed their
throughput/cost tests. General ownership and validation contracts remain intact.
These are warm-archive bounded replay results under a two-CPU budget, not a
whole-node saturation result, cold-storage result, or a live-tail latency claim.
Typed post/union workloads are not represented by the typed-like comparison.


Final validation completed: `just check` (1,121 successful unit/integration/doc
checks across its test groups), `just wasm-check`, changed fuzz-source formatting,
and `git diff --check` all pass. All five event-corpus fingerprints and the
typed-record fingerprint match the baseline. The seeded ASan/libFuzzer campaign
finished with no failures: {"cbor_decode_differential": 2543211, "jetstream_decode_block_body": 2385355, "jetstream_decode_block_frame": 53300, "jetstream_decompress": 2030514, "syntax_parsers": 5682097} —
12,694,477 executions in total, 61 seconds per target. The compressed
frame target compares owned versus borrowed conversion; CBOR differential fuzzing
also checks generated Like/Post/Profile acceptance and typed round trips.
Whole-segment accumulation is separately covered by multi-block integration
checks, including row errors and structural corruption after a valid prefix.

All remote benchmark/profile jobs have finished. The existing Jetstream process
is still PID 1976958, started September 16. No services were restarted, packages
installed on the server, shared configuration changed, or unrelated remote
files modified. Only the authorized uniquely named candidate binaries were
uploaded. No commits were made. Results and exact source/binary snapshots remain
under `/tmp/shrike-jetstream-perf-20260921/`; the concise user report is
`/home/jcalabro/progress.md`.
