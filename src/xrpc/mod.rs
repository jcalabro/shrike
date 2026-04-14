//! XRPC HTTP client for AT Protocol.
//!
//! XRPC is AT Protocol's RPC system built on HTTP. Query methods use GET
//! with query parameters. Procedure methods use POST with JSON bodies.
//! Both return JSON responses.
//!
//! The Client type handles HTTP transport, authentication, retries, and
//! rate limiting. Construct it with base_url and optional auth credentials.
//! Use the auto-generated api module for typed method calls or use the
//! client directly for raw XRPC.
//!
//! ```ignore
//! use shrike::xrpc::Client;
//!
//! let client = Client::builder()
//!     .base_url("https://bsky.social")
//!     .build()?;
//!
//! // Use with generated API types:
//! use shrike::api::app::bsky::feed::get_timeline;
//! let timeline = get_timeline::query(&client, &params).await?;
//! ```

mod auth;
mod client;
mod error;
mod retry;

pub use auth::AuthInfo;
pub use client::Client;
pub use error::Error;
pub use retry::RetryPolicy;
