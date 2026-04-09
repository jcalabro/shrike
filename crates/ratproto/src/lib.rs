//! # ratproto — AT Protocol Library for Rust
//!
//! A comprehensive, high-performance AT Protocol library.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use ratproto::{Did, Handle, Cid};
//! use ratproto::xrpc::Client;
//! ```
//!
//! ## Feature Flags
//!
//! By default, only the core crates are included. Enable additional features
//! for networking and higher-level functionality:
//!
//! - `xrpc` — XRPC HTTP client
//! - `xrpc-server` — XRPC HTTP server framework
//! - `identity` — DID resolution and handle verification
//! - `streaming` — Firehose and Jetstream consumers
//! - `sync` — Repository sync and verification
//! - `backfill` — Concurrent repo downloader
//! - `labeling` — Label creation and verification
//! - `api` — Generated Lexicon API types
//! - `full` — Everything

#[cfg(feature = "api")]
pub use ratproto_api as api;
#[cfg(feature = "backfill")]
pub use ratproto_backfill as backfill;
#[cfg(feature = "car")]
pub use ratproto_car as car;
#[cfg(feature = "cbor")]
pub use ratproto_cbor as cbor;
#[cfg(feature = "crypto")]
pub use ratproto_crypto as crypto;
#[cfg(feature = "identity")]
pub use ratproto_identity as identity;
#[cfg(feature = "labeling")]
pub use ratproto_labeling as labeling;
#[cfg(feature = "lexicon")]
pub use ratproto_lexicon as lexicon;
#[cfg(feature = "mst")]
pub use ratproto_mst as mst;
#[cfg(feature = "repo")]
pub use ratproto_repo as repo;
#[cfg(feature = "streaming")]
pub use ratproto_streaming as streaming;
#[cfg(feature = "sync")]
pub use ratproto_sync as sync;
#[cfg(feature = "syntax")]
pub use ratproto_syntax as syntax;
#[cfg(feature = "xrpc")]
pub use ratproto_xrpc as xrpc;
#[cfg(feature = "xrpc-server")]
pub use ratproto_xrpc_server as xrpc_server;

// Re-export common types at root for convenience
#[cfg(feature = "cbor")]
pub use ratproto_cbor::Cid;
#[cfg(feature = "syntax")]
pub use ratproto_syntax::{
    AtIdentifier, AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid, TidClock,
};
