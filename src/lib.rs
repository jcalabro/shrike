//! # shrike
//!
//! A comprehensive AT Protocol library for Rust. This library provides everything needed to interact with
//! AT Protocol networks like Bluesky, including identifier types, cryptographic operations, repository
//! management, XRPC client and server implementations, identity resolution, firehose streaming, and more.
//!
//! All identifier types in shrike validate on construction using the newtype pattern with private inner
//! fields. This means invalid identifiers like malformed DIDs or handles cannot be represented at all,
//! eliminating a large class of runtime errors.
//!
//! ## Where to start
//!
//! What you need depends on what you are building:
//!
//! - Bot or client app: Start with [`xrpc::Client`] and the [`api`] module to make authenticated requests
//!   to Bluesky or other AT Protocol services.
//! - Feed generator: Use [`streaming::Client`] to consume the firehose and [`xrpc::Client`] to serve your
//!   custom feed.
//! - Labeler: Combine [`streaming::Client`] for processing records, [`labeling`] for creating and signing
//!   labels, and [`xrpc_server::Server`] to host your labeler service.
//! - Full relay or PDS: You will need [`repo`], [`sync`], [`identity`], and most other modules to handle
//!   repository storage, commit verification, identity resolution, and federation.
//!
//! ## Feature flags
//!
//! By default, no features are enabled. Pick what you need:
//!
//! | Feature | Description |
//! |---------|-------------|
//! | `syntax` | Core identifier types ([`Did`], [`Handle`], [`Nsid`], [`AtUri`], [`Tid`], [`RecordKey`]) |
//! | `cbor` | DAG-CBOR encoding, decoding, and content-addressed hashing ([`cbor::Cid`]) |
//! | `crypto` | P-256 and secp256k1 signing and verification |
//! | `mst` | Merkle Search Tree for record storage |
//! | `repo` | In-memory AT Protocol repository with signed commits |
//! | `car` | Content Addressable aRchive (CAR v1) reading and writing |
//! | `lexicon` | Lexicon schema loading and record validation |
//! | `xrpc` | XRPC HTTP/2 client with retry, rate limiting, and auth |
//! | `xrpc-server` | Axum-based XRPC server framework |
//! | `identity` | DID resolution and handle verification |
//! | `streaming` | Firehose and Jetstream WebSocket consumers with reconnection |
//! | `sync` | Repository sync and commit verification |
//! | `backfill` | Concurrent bulk repo downloading |
//! | `labeling` | Label creation, signing, and verification |
//! | `oauth` | OAuth2 authorization client (DPoP, PKCE, session management) |
//! | `api` | Generated types for all Bluesky and AT Protocol lexicons |
//! | `full` | Everything above |
//!
//! ## Quick start
//!
//! ```rust,ignore
//! use shrike::xrpc::{Client, AuthInfo};
//! use shrike::api::app::bsky;
//!
//! // Create a client and make a query
//! let client = Client::new("https://bsky.social");
//! let params = bsky::ActorGetProfileParams {
//!     actor: "alice.bsky.social".into(),
//!     ..Default::default()
//! };
//! let profile = bsky::actor_get_profile(&client, &params).await?;
//! ```

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
