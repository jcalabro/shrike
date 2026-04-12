//! # shrike — AT Protocol Library for Rust
//!
//! A comprehensive, high-performance AT Protocol library.
//!
//! ## Quick Start
//!
//! ```rust,ignore
//! use shrike::{Did, Handle, Cid};
//! use shrike::xrpc::Client;
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
pub use shrike_api as api;
#[cfg(feature = "backfill")]
pub use shrike_backfill as backfill;
#[cfg(feature = "car")]
pub use shrike_car as car;
#[cfg(feature = "cbor")]
pub use shrike_cbor as cbor;
#[cfg(feature = "crypto")]
pub use shrike_crypto as crypto;
#[cfg(feature = "identity")]
pub use shrike_identity as identity;
#[cfg(feature = "labeling")]
pub use shrike_labeling as labeling;
#[cfg(feature = "lexicon")]
pub use shrike_lexicon as lexicon;
#[cfg(feature = "mst")]
pub use shrike_mst as mst;
#[cfg(feature = "repo")]
pub use shrike_repo as repo;
#[cfg(feature = "streaming")]
pub use shrike_streaming as streaming;
#[cfg(feature = "sync")]
pub use shrike_sync as sync;
#[cfg(feature = "syntax")]
pub use shrike_syntax as syntax;
#[cfg(feature = "xrpc")]
pub use shrike_xrpc as xrpc;
#[cfg(feature = "xrpc-server")]
pub use shrike_xrpc_server as xrpc_server;

// Re-export common types at root for convenience
#[cfg(feature = "cbor")]
pub use shrike_cbor::Cid;
#[cfg(feature = "syntax")]
pub use shrike_syntax::{
    AtIdentifier, AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid, TidClock,
};
