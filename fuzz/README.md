# shrike fuzz targets

Coverage-guided fuzzing for shrike's binary parsers, identifier parsers, and the
MST mutation/load paths, using
[`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer). Requires the
nightly toolchain. The nix dev shell (`just dev`) provides both: `cargo-fuzz`, and
a pinned nightly as `cargo-nightly` (stable stays the default `cargo`).

The targets favor **strong oracles** over bare no-panic checks — differential
equivalence between code paths, round-trip / fixed-point identity, and semantic
invariants — so a mutation that produces wrong (not just crashing) behavior is
caught.

## Running

```bash
# Seed the corpora with valid, real-shaped inputs first (fast; idempotent):
just fuzz-seed

# All targets, 30s each (from the repo root):
just fuzz
just fuzz 10        # 10s each

# A single target, indefinitely (nix shell):
cargo-nightly fuzz run cbor_decode_differential

# Outside nix, with rustup:
cargo install cargo-fuzz
cargo +nightly fuzz run cbor_decode_differential
```

## Targets & oracles

| Target | Oracle |
|--------|--------|
| `cbor_decode` | strict decoder never panics; accepted input re-encodes to **identical** (canonical) bytes |
| `cbor_decode_differential` | `decode` (heap) and `decode_bump` (arena, the firehose hot path) **must agree** — both accept with identical structure or both reject (the H1 bug class) |
| `cbor_encode_roundtrip` | structured (`arbitrary`) value → encode → decode → re-encode is a **fixed point** |
| `cbor_json_writer` | `drisl_to_json_into` writes **exactly** the JSON `serde_json` writes of `drisl_to_json`, or fails with the same error |
| `json_slice_to_drisl` | `json_slice_to_drisl` and `serde_json::from_slice` + `json_to_drisl` **must agree**, output and error, on raw bytes and on structured JSON |
| `cid_parse` | CID parse never panics; bytes/string forms are **fixed points** (no non-canonical aliases) |
| `car_read_all` | CAR v1 reader never panics on malformed framing |
| `repo_record_proof` | record proof verifier never panics, and never accepts a record the fixed signing key did not commit to |
| `repo_proofs` | multi-record proof verifiers (`verify_proofs`, `verify_records`) never panic, and never verify a claim or record the fixed signing key did not commit to |
| `repo_load_car` | `Repo::load_car` never panics; an accepted CAR exports and reloads **identically** and stays writable |
| `mst_decode_node_data` | node decoder never panics |
| `mst_decode_node_data_roundtrip` | accepted node blocks decode→encode→decode **stably** |
| `mst_load_and_walk` | `Tree::load` + traverse (the prefix-reslice / key-order path; H2/H3/H4) never panics |
| `mst_height_for_key` | height is panic-free, deterministic, in `[0,128]` |
| `mst_insert_get` | every inserted key is retrievable; **root CID is insertion-order-independent** |
| `mst_invert` | undoing a commit's ops from only the blocks an indigo-style or reference producer ships **restores the previous root** |
| `syntax_parsers` | all 9 identifier parsers never panic; normalization is **idempotent** (canonical form re-parses to itself) |
| `repo_commit_from_cbor` | commit decode never panics; signed commits round-trip |
| `firehose_frame` | `parse_firehose_frame` + `parse_raw_sync_frame` never panic; an accepted commit's records **hash to their CIDs** and agree with the raw parser's ops and blocks |
| `label_decode` | label decode never panics; accepted labels encode/decode **stably**; unsigned bytes deterministic |
| `k256_backends_differential` | K-256 keys, verifying with libsecp256k1 under the `secp256k1` feature, **must agree** with pure-Rust `k256`: key parsing and encoding, signatures, and strict and malleable verification of valid, high-S, mutated and arbitrary signatures |
| `lexicon_validate` | record validation against a kitchen-sink schema never panics on arbitrary JSON |

## Notes

- `gen_seeds` is a normal binary (not a fuzz target) that writes valid encoded
  artifacts into `corpus/<target>/`.
- This crate is intentionally **not** a member of the main workspace (it carries
  its own `[workspace]` table), so it does not affect normal `cargo build`/`test`.
- The generated `corpus/` and `artifacts/` directories are git-ignored.
