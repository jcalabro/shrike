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
//! - `oauth` — OAuth authentication client
//! - `api` — Generated Lexicon API types
//! - `full` — Everything

#[cfg(feature = "syntax")]
pub mod syntax;

#[cfg(feature = "cbor")]
pub mod cbor;

#[cfg(feature = "crypto")]
pub mod crypto;

#[cfg(feature = "mst")]
pub mod mst;

#[cfg(feature = "repo")]
pub mod repo;

#[cfg(feature = "car")]
pub mod car;

#[cfg(feature = "lexicon")]
pub mod lexicon;

#[cfg(feature = "xrpc")]
pub mod xrpc;

#[cfg(feature = "xrpc-server")]
#[path = "xrpc_server/mod.rs"]
pub mod xrpc_server;

#[cfg(feature = "identity")]
pub mod identity;

#[cfg(feature = "streaming")]
pub mod streaming;

#[cfg(feature = "sync")]
pub mod sync;

#[cfg(feature = "backfill")]
pub mod backfill;

#[cfg(feature = "labeling")]
pub mod labeling;

#[cfg(feature = "oauth")]
pub mod oauth;

#[cfg(feature = "api")]
pub mod api;

// Re-export common types at root for convenience
#[cfg(feature = "cbor")]
pub use crate::cbor::Cid;
#[cfg(feature = "syntax")]
pub use crate::syntax::{
    AtIdentifier, AtUri, Datetime, Did, Handle, Language, Nsid, RecordKey, Tid, TidClock,
};
