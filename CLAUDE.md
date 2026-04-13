# shrike

AT Protocol library for Rust. See design spec at `docs/superpowers/specs/2026-04-04-rat-atproto-library-design.md`.

## Build & Test

```bash
cargo build --features full
cargo test --features full
cargo clippy --features full -- -D warnings
```

## Architecture

Single `shrike` library crate with feature-gated modules (`syntax`, `cbor`, `crypto`, `mst`, `repo`, `car`, `lexicon`, `xrpc`, `xrpc_server`, `identity`, `streaming`, `sync`, `backfill`, `labeling`, `oauth`, `api`). Tools (`lexgen`, `shrike-cli`) are separate workspace members.

## Conventions

- All types validate on construction (newtype pattern with private inner field)
- `thiserror` for all error types
- `serde` Serialize/Deserialize on all public types
- Tests live in the same file as the code they test (unit) or in tests/ (integration)
- Fuzz tests go in fuzz/ directories using cargo-fuzz
- Copy test vectors from atmos where applicable
