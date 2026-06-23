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
//! ```no_run
//! use shrike::xrpc::Client;
//! use shrike::api::app::bsky;
//!
//! # async fn example() -> Result<(), shrike::xrpc::Error> {
//! let client = Client::new("https://bsky.social");
//! // Use with generated API types:
//! let params = bsky::FeedGetTimelineParams::default();
//! let _timeline = bsky::feed_get_timeline(&client, &params).await?;
//! # Ok(())
//! # }
//! ```

mod auth;
mod client;
mod error;
mod ratelimit;
mod retry;

pub use auth::AuthInfo;
pub use client::Client;
pub use error::Error;
pub use ratelimit::RateLimit;
pub use retry::RetryPolicy;
