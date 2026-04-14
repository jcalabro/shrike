# shrike

[![crates.io](https://img.shields.io/crates/v/shrike.svg)](https://crates.io/crates/shrike)
[![docs.rs](https://docs.rs/shrike/badge.svg)](https://docs.rs/shrike)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/jcalabro/shrike)

AT Protocol library for Rust. Designed to be correct, fast, and easy to use.

## Modules

| Module | Description |
|-|-|
| [`shrike::syntax`](https://docs.rs/shrike/latest/shrike/syntax) | core identifier types (DID, Handle, NSID, AT-URI, TID, RecordKey) |
| [`shrike::cbor`](https://docs.rs/shrike/latest/shrike/cbor) | DAG-CBOR encoding and decoding |
| [`shrike::crypto`](https://docs.rs/shrike/latest/shrike/crypto) | P-256 and secp256k1 signing, verification, and did:key encoding |
| [`shrike::mst`](https://docs.rs/shrike/latest/shrike/mst) | Merkle Search Tree implementation |
| [`shrike::repo`](https://docs.rs/shrike/latest/shrike/repo) | AT Protocol repository with signed commits |
| [`shrike::car`](https://docs.rs/shrike/latest/shrike/car) | CAR v1 archive reading and writing |
| [`shrike::lexicon`](https://docs.rs/shrike/latest/shrike/lexicon) | Lexicon schema loading and record validation |
| [`shrike::xrpc`](https://docs.rs/shrike/latest/shrike/xrpc) | XRPC HTTP client with retry and auth |
| [`shrike::xrpc_server`](https://docs.rs/shrike/latest/shrike/xrpc_server) | Axum-based XRPC server framework |
| [`shrike::identity`](https://docs.rs/shrike/latest/shrike/identity) | DID resolution and handle verification |
| [`shrike::streaming`](https://docs.rs/shrike/latest/shrike/streaming) | firehose and Jetstream WebSocket consumers |
| [`shrike::sync`](https://docs.rs/shrike/latest/shrike/sync) | repository download and verification |
| [`shrike::backfill`](https://docs.rs/shrike/latest/shrike/backfill) | concurrent bulk repo downloading |
| [`shrike::labeling`](https://docs.rs/shrike/latest/shrike/labeling) | label signing and verification |
| [`shrike::oauth`](https://docs.rs/shrike/latest/shrike/oauth) | OAuth 2.0 client with PKCE and DPoP |
| [`shrike::api`](https://docs.rs/shrike/latest/shrike/api) | generated types and functions for the `com.atproto.*`, `app.bsky.*`, etc. lexicons |

Each module is behind a feature flag. Enable `full` for everything, or pick what you need.

```toml
[dependencies]
shrike = { version = "0.1", features = ["full"] }
```

## License

Dual-licensed under MIT and Apache 2.0.
