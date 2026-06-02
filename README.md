# shrike

[![crates.io](https://img.shields.io/crates/v/shrike.svg)](https://crates.io/crates/shrike)
[![docs.rs](https://docs.rs/shrike/badge.svg)](https://docs.rs/shrike)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/jcalabro/shrike)

AT Protocol library for Rust. Designed to be correct, fast, and easy to use.

## Feature-Gated Modules

| Feature | Module | Description |
|-|-|-|
| `syntax` | `shrike::syntax` | core identifier types (DID, Handle, NSID, AT-URI, TID, RecordKey) |
| `cbor` | `shrike::cbor` | DAG-CBOR encoding and decoding |
| `crypto` | `shrike::crypto` | P-256 and secp256k1 signing, verification, and did:key encoding |
| `mst` | `shrike::mst` | Merkle Search Tree implementation |
| `repo` | `shrike::repo` | AT Protocol repository with signed commits |
| `car` | `shrike::car` | CAR v1 archive reading and writing |
| `lexicon` | `shrike::lexicon` | Lexicon schema loading and record validation |
| `xrpc` | `shrike::xrpc` | XRPC HTTP client with retry and auth |
| `xrpc-server` | `shrike::xrpc_server` | Axum-based XRPC server framework |
| `identity` | `shrike::identity` | DID resolution and handle verification |
| `streaming` | `shrike::streaming` | firehose and Jetstream WebSocket consumers |
| `sync` | `shrike::sync` | repository download and verification |
| `backfill` | `shrike::backfill` | concurrent bulk repo downloading |
| `labeling` | `shrike::labeling` | label signing and verification |
| `oauth` | `shrike::oauth` | OAuth 2.0 client with PKCE and DPoP |
| `api` | `shrike::api` | generated types and functions for the `com.atproto.*`, `app.bsky.*`, etc. lexicons |

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
