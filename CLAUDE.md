# shrike

AT Protocol library for Rust. See design spec at `docs/superpowers/specs/2026-04-04-rat-atproto-library-design.md`.

## Build & Test

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

## Architecture

Cargo workspace of focused crates. See design spec for full dependency graph.

## Conventions

- All types validate on construction (newtype pattern with private inner field)
- `thiserror` for all error types
- `serde` Serialize/Deserialize on all public types
- Tests live in the same file as the code they test (unit) or in tests/ (integration)
- Fuzz tests go in fuzz/ directories using cargo-fuzz
- Copy test vectors from atmos where applicable
