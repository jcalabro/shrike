# shrike

AT Protocol library for Rust

[![crates.io](https://img.shields.io/crates/v/shrike.svg)](https://crates.io/crates/shrike)
[![docs.rs](https://docs.rs/shrike/badge.svg)](https://docs.rs/shrike)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](https://github.com/jcalabro/shrike)

shrike is a complete AT Protocol implementation in Rust. It provides everything you need to build clients, servers, crawlers, and infrastructure for the Bluesky network and the broader AT Protocol ecosystem. The library is modular and feature-gated so you only compile what you use.

## Installation

```bash
cargo add shrike --features full
```

Or add to your Cargo.toml:

```toml
[dependencies]
shrike = { version = "0.1", features = ["full"] }
```

## Features

Each module is behind a feature flag. Pick exactly what you need:

- syntax: Core identifier types (DID, Handle, NSID, AT-URI, TID, RecordKey)
- cbor: DAG-CBOR encoding and decoding
- crypto: P-256 and secp256k1 signing and verification
- mst: Merkle Search Tree implementation
- repo: In-memory AT Protocol repository with signed commits
- car: CAR v1 archive reading and writing
- lexicon: Lexicon schema loading and record validation
- xrpc: XRPC HTTP client with retry and auth
- xrpc-server: Axum-based XRPC server framework
- identity: DID resolution and handle verification
- streaming: Firehose and Jetstream WebSocket consumers
- sync: Repository download and verification
- backfill: Concurrent bulk repo downloading
- labeling: Label signing and verification
- oauth: OAuth2 client for AT Protocol authorization
- api: Generated types for all Bluesky and AT Protocol lexicons
- full: Everything above

## Where to start

The full documentation is at [docs.rs/shrike](https://docs.rs/shrike).

Major entry points:

- [xrpc::Client](https://docs.rs/shrike/latest/shrike/xrpc/struct.Client.html) - Make XRPC requests to PDS and other services
- [streaming::Client](https://docs.rs/shrike/latest/shrike/streaming/struct.Client.html) - Subscribe to the firehose or Jetstream
- [repo::Repo](https://docs.rs/shrike/latest/shrike/repo/struct.Repo.html) - Create and manage signed repositories
- [xrpc_server::Server](https://docs.rs/shrike/latest/shrike/xrpc_server/struct.Server.html) - Build XRPC servers
- [oauth::OAuthClient](https://docs.rs/shrike/latest/shrike/oauth/struct.OAuthClient.html) - Authenticate users with OAuth

## License

Licensed under either MIT or Apache-2.0, at your option.
