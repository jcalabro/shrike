# shrike

[![crates.io](https://img.shields.io/crates/v/shrike.svg)](https://crates.io/crates/shrike)
[![docs.rs](https://docs.rs/shrike/badge.svg)](https://docs.rs/shrike)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/jcalabro/shrike)

AT Protocol library for Rust. Designed to be correct, fast, and easy to use.

## Feature-Gated Modules

| Feature | Module | Published docs | Description |
|-|-|-|-|
| `syntax` | `shrike::syntax` | [`shrike::syntax`](https://docs.rs/shrike/latest/shrike/syntax/) | core identifier types (DID, Handle, NSID, AT-URI, TID, RecordKey) |
| `cbor` | `shrike::cbor` | [`shrike::cbor`](https://docs.rs/shrike/latest/shrike/cbor/) | DAG-CBOR encoding and decoding |
| `crypto` | `shrike::crypto` | [`shrike::crypto`](https://docs.rs/shrike/latest/shrike/crypto/) | P-256 and secp256k1 signing, verification, and did:key encoding |
| `mst` | `shrike::mst` | [`shrike::mst`](https://docs.rs/shrike/latest/shrike/mst/) | Merkle Search Tree implementation |
| `repo` | `shrike::repo` | [`shrike::repo`](https://docs.rs/shrike/latest/shrike/repo/) | AT Protocol repository with signed commits |
| `car` | `shrike::car` | [`shrike::car`](https://docs.rs/shrike/latest/shrike/car/) | CAR v1 archive reading and writing |
| `lexicon` | `shrike::lexicon` | pending next all-features docs publish | Lexicon schema loading and record validation |
| `xrpc` | `shrike::xrpc` | pending next all-features docs publish | XRPC HTTP client with retry and auth |
| `xrpc-server` | `shrike::xrpc_server` | pending next all-features docs publish | Axum-based XRPC server framework |
| `identity` | `shrike::identity` | pending next all-features docs publish | DID resolution and handle verification |
| `streaming` | `shrike::streaming` | pending next all-features docs publish | firehose and Jetstream WebSocket consumers |
| `sync` | `shrike::sync` | pending next all-features docs publish | repository download and verification |
| `backfill` | `shrike::backfill` | pending next all-features docs publish | concurrent bulk repo downloading |
| `labeling` | `shrike::labeling` | pending next all-features docs publish | label signing and verification |
| `oauth` | `shrike::oauth` | pending next all-features docs publish | OAuth 2.0 client with PKCE and DPoP |
| `api` | `shrike::api` | pending next all-features docs publish | generated types and functions for the `com.atproto.*`, `app.bsky.*`, etc. lexicons |

The default feature set enables `syntax`, `cbor`, `crypto`, `mst`, `repo`, and `car`.
Enable `full` for everything, or disable defaults and pick only what you need.

```toml
[dependencies]
shrike = { version = "0.1", features = ["full"] }
```

```toml
[dependencies]
shrike = { version = "0.1", default-features = false, features = ["syntax", "xrpc"] }
```

## License

Dual-licensed under MIT and Apache 2.0.
