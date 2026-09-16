# shrike

[![crates.io](https://img.shields.io/crates/v/shrike.svg)](https://crates.io/crates/shrike)
[![docs.rs](https://docs.rs/shrike/badge.svg)](https://docs.rs/shrike)
[![License](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](https://github.com/jcalabro/shrike)

AT Protocol library for Rust. Designed to be correct, fast, robust, and easy to use.

## Feature-Gated Modules

Module links point to the canonical docs.rs pages for the next `shrike` release built with all
features enabled.

The default feature set enables `syntax`, `cbor`, `crypto`, `mst`, `repo`, and `car`. Enable `full` for everything, or disable defaults and pick only what you need.

| Feature | Module | Description |
|-|-|-|
| `syntax` | [`shrike::syntax`](https://docs.rs/shrike/latest/shrike/syntax/) | core identifier types (DID, Handle, NSID, AT-URI, TID, RecordKey) |
| `cbor` | [`shrike::cbor`](https://docs.rs/shrike/latest/shrike/cbor/) | DAG-CBOR encoding and decoding |
| `crypto` | [`shrike::crypto`](https://docs.rs/shrike/latest/shrike/crypto/) | P-256 and secp256k1 signing, verification, and did:key encoding |
| `mst` | [`shrike::mst`](https://docs.rs/shrike/latest/shrike/mst/) | Merkle Search Tree implementation |
| `repo` | [`shrike::repo`](https://docs.rs/shrike/latest/shrike/repo/) | AT Protocol repository with signed commits |
| `car` | [`shrike::car`](https://docs.rs/shrike/latest/shrike/car/) | CAR v1 archive reading and writing |
| `lexicon` | [`shrike::lexicon`](https://docs.rs/shrike/latest/shrike/lexicon/) | Lexicon schema loading and record validation |
| `xrpc` | [`shrike::xrpc`](https://docs.rs/shrike/latest/shrike/xrpc/) | XRPC HTTP client with retry and auth |
| `xrpc-server` | [`shrike::xrpc_server`](https://docs.rs/shrike/latest/shrike/xrpc_server/) | Axum-based XRPC server framework |
| `identity` | [`shrike::identity`](https://docs.rs/shrike/latest/shrike/identity/) | DID resolution and handle verification |
| `streaming` | [`shrike::streaming`](https://docs.rs/shrike/latest/shrike/streaming/) | firehose and Jetstream WebSocket consumers |
| `sync` | [`shrike::sync`](https://docs.rs/shrike/latest/shrike/sync/) | repository download and verification |
| `backfill` | [`shrike::backfill`](https://docs.rs/shrike/latest/shrike/backfill/) | concurrent bulk repo downloading |
| `labeling` | [`shrike::labeling`](https://docs.rs/shrike/latest/shrike/labeling/) | label signing and verification |
| `oauth` | [`shrike::oauth`](https://docs.rs/shrike/latest/shrike/oauth/) | OAuth 2.0 client with PKCE and DPoP |
| `api` | [`shrike::api`](https://docs.rs/shrike/latest/shrike/api/) | generated types and functions for the `com.atproto.*`, `app.bsky.*`, etc. lexicons |
| `wasm` | browser-safe subset | client-side features for `wasm32-unknown-unknown` (everything except `xrpc-server`, `sync`, and `backfill`) |

## WebAssembly

Shrike supports browser WebAssembly in two forms:

- Rust callers can build `shrike` for `wasm32-unknown-unknown` with
  `default-features = false, features = ["wasm"]`.
- JavaScript and TypeScript callers can run `just wasm` and import the generated
  package from `wasm/pkg`. It exposes syntax validation, DAG-CBOR, TIDs, CIDs,
  P-256/secp256k1 signing and verification, PKCE/DPoP helpers, identity
  resolution, firehose/Jetstream subscriptions, and generic JSON XRPC
  queries/procedures.

Run `just test-wasm` for the binding tests. Unlike atmos's Go build, this uses
`wasm-pack`, so the generated package includes the JavaScript loader and
TypeScript declarations without copying a separate `wasm_exec.js` runtime. The
recipe also writes a precompressed `.wasm.gz` asset for static hosting.

Browser networking remains subject to the browser security model. HTTP calls
need CORS support, handle resolution uses HTTPS well-known fallback because
browsers cannot issue DNS TXT queries, Fetch controls redirects and timeouts,
and WebSocket handshakes cannot set a custom User-Agent. Native-only servers,
repository sync verification, and backfill are intentionally not in the `wasm`
feature.

## License

Dual-licensed under MIT and Apache 2.0 at your choosing.
