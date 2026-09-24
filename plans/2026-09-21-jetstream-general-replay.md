# General Jetstream replay optimization

Starting source: `febd2d4` on `jc/jetstream-performance-deep-dive`.
The target is ordinary owned-event replay across arbitrary collections, including
archive-to-live cutover. Scoped typed-like snapshots are a regression workload,
not the primary acceptance criterion.

The starting unfiltered eight-CPU measurement completed (0,100m] in 4.264s
(34,520,105 delivered events), using 16.535 client CPU seconds and 4.617 GiB
peak RSS. Go completed the range in 7.509s but eagerly decoded records and
computed CIDs, rejecting 645 payloads that Rust retained for lazy consumption.
These contracts must remain visible in comparisons.

## Measurement and correctness rules

- Sequential remote runs, CPUs 2–9 at most, nice 19, idle I/O priority, and
  bounded windows/timeouts. No packages, restarts, shared configuration changes,
  cache drops, or remote profiling files. Upload uniquely named candidates.
- Preserve the starting binary. Separate exploratory six-pair experiments from
  twelve-pair randomized confirmation with excluded warmups and paired bootstrap
  intervals. Retain slow runs. Report wall, CPU, RSS, counts, cursors, and errors.
- Compare unfiltered replay, other sequence ranges, selective collections, and
  actual record-consuming workloads. Equal event counts alone are insufficient:
  compare complete event/error fingerprints and retention behavior as well.
- Preserve whole-segment structural failure atomicity, block-mode valid-prefix
  delivery, row-level error recovery, generation checks, order, filters, window
  clipping, cancellation, and archive/live boundary behavior.
- Keep the portable wasm path and support non-Send transports. Add no unsafe
  code or dependencies. Run relevant integration/property/fuzz tests and the full
  repository checks on the retained implementation.

## Experiments

1. Share immutable decompressed block bytes among owned records; allow an
   explicitly retained small record to detach from the block.
2. Separate structural block validation from event construction. Prepare a
   segment completely before exposing it, then construct and deliver bounded
   chunks instead of buffering all owned events. Investigate shared CPU budgets
   and overlapping a bounded number of prepared segments.
3. Follow profiles and comparative measurements for further changes. Avoid
   assuming that more threads or a global pool wins: previous scoped workloads
   did not justify that architecture.

Artifacts: `/tmp/shrike-general-20260921/`. Results will be recorded as the
experiments finish; the list above is not a claim of achieved improvements.

## Initial exploratory results

Six randomized pairs per comparison, unfiltered (0,100m], eight CPUs,
single-stream downloads. Every run delivered 34,520,105 events with the same
final cursor and zero remaining gap. These ratios are separate experiments;
the final result must be measured directly against the starting binary.

| Change | Throughput ratio, paired 95% interval | Median CPU, before/after | Peak RSS, before/after |
| --- | --- | --- | --- |
| Shared block storage | 1.3726 [1.3314,1.4313] | 17.62 / 15.97 s | 4.62 / 5.56 GiB |
| Prepare whole structure, construct bounded chunks | 1.1939 [1.1598,1.2266] | 15.69 / 12.53 s | 5.39 / 0.84 GiB |

The shared-only prototype is not an acceptable endpoint: it improves wall time
but increases retained memory. Bounded construction removes that regression.
The ordinary client now shares at most 32 CPU permits between preparation and
conversion, capped by configured concurrency, and prefetches at most two
segments. No whole-segment event is exposed until all its block structures have
passed validation; sparse failures still deliver their good prefix and then
ordered errors. Completed chunks remain bounded by the conversion window.

The complete baseline profile is `baseline.perf.data`; capture and report both
completed successfully. Approximately one third of sampled user cycles are
native zstd; identifier conversion/validation and libc allocation/copy/free
paths are also substantial. The profile used 99 Hz process-scoped sampling,
small buffers, and disabled build-ID cache writes.

| Block-local metadata validation cache | 1.1384 [1.1332,1.1442] | 12.42 / 10.76 s | 0.826 / 0.783 GiB |

The cache compares the entire original DID, NSID, or revision string before
reusing a parsed value. It is constant-size and block-local. Record keys still
validate individually. The cached profile attributes about 30% of user cycles
to ZSTD_decompressSequences, 8% to ZSTD_decompressMultiFrame, 10% to short libc
comparisons, 10% to row conversion, and 9% to event-sized libc copies.

A six-pair experiment replacing short metadata equality with checked overlapping
fixed-width slice comparisons did not help: 0.9667 [0.9165,1.0074], median CPU
10.765 vs 10.810 seconds. Rejected; ordinary slice equality remains. Raw results:
`compare-v1.jsonl`. Slow runs were retained.

The generic Go pilot exposed a benchmark-consumer bug: checking the JSON output
for an object also admitted top-level CBOR bytes/CIDs (wrapped as $bytes/$link).
The CLI now checks the CBOR map root before full decode, with regression tests.
This does not change Record::to_json, which deliberately supports those values.
