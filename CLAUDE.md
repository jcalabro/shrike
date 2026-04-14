# shrike

AT Protocol library for Rust. See documentation design spec at `docs/superpowers/specs/2026-04-14-documentation-design.md`.

## Build & Test

```bash
just --list # find all commands
just # runs the linter and all tests (run this often!)
just lint
just test
just fuzz
just bench
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
