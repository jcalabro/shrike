//! Core AT Protocol identifier types with validation-on-construction.
//!
//! All types validate their inputs when constructed and maintain the newtype
//! pattern with a private inner field. All types implement TryFrom, FromStr,
//! Display, Serialize, and Deserialize.
//!
//! Types: Did, Handle, Nsid, AtUri, Tid, TidClock, RecordKey, Datetime,
//! Language, AtIdentifier.

mod at_identifier;
mod aturi;
mod datetime;
mod did;
mod handle;
mod language;
mod nsid;
mod recordkey;
mod tid;

pub use at_identifier::AtIdentifier;
pub use aturi::AtUri;
pub use datetime::Datetime;
pub use did::Did;
pub use handle::Handle;
pub use language::Language;
pub use nsid::Nsid;
pub use recordkey::RecordKey;
pub use tid::{Tid, TidClock};

use thiserror::Error;

#[derive(Debug, Error)]
#[allow(clippy::enum_variant_names)]
pub enum SyntaxError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("invalid handle: {0}")]
    InvalidHandle(String),
    #[error("invalid NSID: {0}")]
    InvalidNsid(String),
    #[error("invalid AT-URI: {0}")]
    InvalidAtUri(String),
    #[error("invalid TID: {0}")]
    InvalidTid(String),
    #[error("invalid datetime: {0}")]
    InvalidDatetime(String),
    #[error("invalid record key: {0}")]
    InvalidRecordKey(String),
    #[error("invalid language tag: {0}")]
    InvalidLanguage(String),
}
