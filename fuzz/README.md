# shrike fuzz targets

Coverage-guided fuzzing for shrike's binary parsers and the MST load path,
using [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz) (libFuzzer).
Requires the nightly toolchain.

## Running

```bash
# All targets, 30s each (from the repo root):
just fuzz
just fuzz 10        # 10s each

# A single target, indefinitely:
cargo +nightly fuzz run mst_load_and_walk

# Install cargo-fuzz if needed:
cargo install cargo-fuzz
```

## Targets

| Target | What it asserts |
|--------|-----------------|
| `mst_decode_node_data` | `decode_node_data` never panics on arbitrary bytes |
| `mst_decode_node_data_roundtrip` | accepted node blocks decode→encode→decode stably |
| `mst_load_and_walk` | `Tree::load` + traverse (the prefix-reslice / key-order path) never panics, only errors |
| `mst_height_for_key` | height is panic-free, deterministic, and in `[0, 128]` |
| `cbor_decode` | the strict DRISL decoder never panics; accepted input re-encodes to identical (canonical) bytes |
| `car_read_all` | the CAR v1 reader never panics on malformed framing |

This crate is intentionally **not** a member of the main workspace (it carries
its own `[workspace]` table), so it does not affect normal `cargo build`/`test`.
The generated `corpus/` and `artifacts/` directories are git-ignored.
