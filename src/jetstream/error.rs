//! Error types for the Jetstream v2 client.
//!
//! This enum grows one milestone at a time. M0 covered the portable segment
//! codec (segment/block/compression decode). M1 adds the protocol value model,
//! so the variants here now also describe live-frame parsing, record
//! canonicalization, timestamp conversion, and local configuration/filter
//! validation. Transport, planning, and live-engine variants arrive with the
//! milestones that introduce them.
//!
//! [`Error::is_fatal`] gives the recoverable/fatal split the replay/live engine
//! relies on: the stream may continue after a recoverable error but must end
//! after a fatal one. The classification here covers only the *intrinsic*
//! fatality of each variant; the engine layers additional context on top (for
//! example, `CursorTooOld` on a pure-live stream is fatal because there is no
//! archive loop to re-enter, but the same protocol error is recoverable for a
//! stream that can fall back to backfill).

use thiserror::Error;

/// A Jetstream v2 error.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// The segment declares a format version this client does not implement.
    #[error("unsupported segment version {found} (expected {expected})")]
    UnsupportedSegmentVersion { found: u16, expected: u16 },

    /// The segment's checksum field is zero, marking a still-active (unsealed)
    /// segment. The archive only serves sealed segments, so this is corruption
    /// or a truncated/partial file.
    #[error("segment is active/unsealed (zero checksum field)")]
    ActiveSegment,

    /// The recomputed xxh3 checksum does not match the sealed header.
    #[error("segment checksum mismatch: computed {computed:#018x}, header {stored:#018x}")]
    ChecksumMismatch { computed: u64, stored: u64 },

    /// A structural invariant was violated (bad magic, invalid kind, offsets
    /// that do not describe a valid layout, and so on).
    #[error("corrupt segment: {0}")]
    CorruptSegment(&'static str),

    /// The input ended before a structure it promised was fully present.
    #[error("truncated segment: {0}")]
    Truncated(&'static str),

    /// A declared or accumulated size exceeded a configured decode limit. This
    /// bounds allocation and guards against decompression bombs.
    #[error("decode limit exceeded: {what} ({value} > {limit})")]
    LimitExceeded {
        what: &'static str,
        value: u64,
        limit: u64,
    },

    /// zstd decompression failed. The message is the underlying decoder's,
    /// which never contains caller data.
    #[error("zstd decode failed: {0}")]
    Compression(String),

    /// The bytes offered as a zstd dictionary are not a valid structured
    /// dictionary.
    #[error("invalid zstd dictionary: {0}")]
    InvalidDictionary(&'static str),

    /// A caller-supplied filter, cursor, or client configuration is invalid.
    /// Detected before any I/O; always fatal because it can never make progress.
    #[error("invalid configuration: {0}")]
    InvalidConfig(&'static str),

    /// A live WebSocket frame was structurally unusable: the JSON did not parse,
    /// or it carried no envelope `$type`. A missing envelope `$type` most often
    /// means the endpoint is a legacy v1 `/subscribe` firehose rather than a v2
    /// Jetstream, so this is treated as fatal for the connection.
    #[error("invalid live frame: {0}")]
    InvalidFrame(&'static str),

    /// A single event (row or live message) was semantically invalid — missing
    /// a required field, a non-positive `seq`, or a field that failed syntax
    /// validation. Recoverable: valid sibling events can still be delivered in
    /// order. The message is a fixed description and never echoes wire data.
    #[error("malformed event: {0}")]
    MalformedEvent(&'static str),

    /// A record's atproto JSON could not be canonicalized to DAG-CBOR — an
    /// invalid `$bytes` base64, an unparseable `$link` CID, a non-string map
    /// key, or a numeric value outside the atproto integer data model.
    /// Recoverable at the row level. The message never echoes wire data.
    #[error("invalid record: {0}")]
    InvalidRecord(&'static str),

    /// A wire timestamp could not be converted to/from Unix microseconds.
    /// Recoverable at the row level.
    #[error("invalid timestamp: {0}")]
    InvalidTimestamp(&'static str),

    /// A protocol-level error surfaced by the server: either a proposal-0015
    /// terminal `error` envelope frame or a pre-upgrade XRPC 400 error. The
    /// XRPC error name is preserved verbatim; the human-readable message is
    /// bounded and may be absent. Terminal for the current connection; whether
    /// the stream as a whole ends is decided by the engine and the error name.
    #[error("jetstream protocol error: {name}{}", .message.as_deref().map(|m| format!(": {m}")).unwrap_or_default())]
    Protocol {
        /// The XRPC error name, e.g. `ConsumerTooSlow` or `CursorTooOld`.
        name: String,
        /// The optional human-readable message, bounded in length.
        message: Option<String>,
    },

    /// A snapshot plan the server returned is malformed or cannot guarantee
    /// forward progress: a bad plan entry (name, index, checksum, sequence
    /// range, mode, or block ranges), a non-advancing page, a page whose
    /// `plannedThroughSeq` exceeds the pinned sealed tip, or a later page whose
    /// `sealedTipSeq` drifted from the pin. Fatal — there is no safe way to
    /// continue downloading against an untrustworthy plan.
    #[error("invalid snapshot plan: {0}")]
    PlanInvalid(&'static str),

    /// A transport-level failure reaching an archive endpoint: a connect,
    /// timeout, or body error, or an HTTP status the client cannot resolve into
    /// a structured XRPC error. The message is redacted and never contains the
    /// API key or an authorization header. `retryable` records whether a
    /// bounded retry could plausibly succeed; the engine decides whether
    /// exhausting the retry budget is ultimately fatal.
    #[error("archive transport error: {message}")]
    Transport {
        /// A redacted, bounded description of the failure. Never the API key.
        message: String,
        /// Whether a bounded retry could plausibly succeed.
        retryable: bool,
    },

    /// The target cannot satisfy a capability an archive download requires:
    /// HTTP range requests, exposed generation headers (`ETag`,
    /// `Content-Range`), or the CORS exposure a browser needs. Reported as a
    /// capability error rather than misinterpreted as corrupt data. Fatal on
    /// this target.
    #[error("archive capability unavailable: {0}")]
    Capability(&'static str),

    /// A whole-segment or block download could not be completed within its
    /// bounds: a `Content-Range`/length inconsistency, an unexpected status, a
    /// truncated or oversized body, or exhausted generation-restart attempts
    /// after the object was rewritten mid-download. The engine may replan.
    #[error("archive download failed: {0}")]
    DownloadFailed(&'static str),

    /// The caller cancelled the operation before it completed. Not a data error:
    /// the engine uses it to shut a worker down cleanly. Never retryable.
    #[error("operation canceled")]
    Canceled,

    /// The replay/live engine could not make forward progress across repeated
    /// archive re-backfill cycles: after a bounded number of `CursorTooOld`
    /// recoveries the cutover neither advanced the processed cursor nor extended
    /// archive coverage, so re-backfilling can never catch the live tail. Fatal —
    /// mirrors the Go client's `maxRebackfillStalls` guard against an infinite
    /// backfill loop.
    #[error("replay stalled: {0}")]
    NoProgress(&'static str),
}

/// The maximum number of bytes retained from a server-supplied protocol
/// message. Server responses are untrusted; caps keep an oversized or binary
/// body out of logs, `Debug`, and error chains.
pub const MAX_PROTOCOL_MESSAGE_LEN: usize = 512;

impl Error {
    /// Build a [`Error::Protocol`] from an XRPC error name and optional message,
    /// truncating the message to [`MAX_PROTOCOL_MESSAGE_LEN`] bytes on a UTF-8
    /// boundary. Both the name and message come from the (untrusted) server, so
    /// the name is capped too.
    pub fn protocol(name: impl Into<String>, message: Option<impl Into<String>>) -> Self {
        let mut name = name.into();
        truncate_on_char_boundary(&mut name, MAX_PROTOCOL_MESSAGE_LEN);
        let message = message.map(|m| {
            let mut m = m.into();
            truncate_on_char_boundary(&mut m, MAX_PROTOCOL_MESSAGE_LEN);
            m
        });
        Error::Protocol { name, message }
    }

    /// Whether this error is intrinsically fatal to the stream.
    ///
    /// Fatal errors can never make forward progress on their own: an invalid
    /// local configuration, a frame from a non-v2 endpoint, or a segment whose
    /// format version this client cannot parse. Everything else is reported as
    /// recoverable here; the engine may still escalate a recoverable error to
    /// fatal based on context it alone has (retry budgets, pure-live vs archive
    /// mode, cutover invariants). [`Error::Protocol`] is intentionally *not*
    /// intrinsically fatal — most protocol errors (e.g. `ConsumerTooSlow`) are
    /// resolved by reconnecting; the engine decides based on the name.
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Error::InvalidConfig(_)
                | Error::InvalidFrame(_)
                | Error::UnsupportedSegmentVersion { .. }
                | Error::PlanInvalid(_)
                | Error::Capability(_)
                | Error::NoProgress(_)
        )
    }
}

impl From<super::transport::TransportError> for Error {
    /// Lift a transport failure into the client error space. A missing-capability
    /// transport failure becomes a fatal [`Error::Capability`]; every other
    /// transport failure becomes an [`Error::Transport`] carrying the redacted
    /// message and the transport's retryable classification. The message is
    /// already bounded and free of the API key.
    fn from(err: super::transport::TransportError) -> Self {
        use super::transport::TransportErrorKind;
        match err.kind() {
            TransportErrorKind::Capability => {
                Error::Capability("transport lacks a required capability")
            }
            _ => Error::Transport {
                retryable: err.is_retryable(),
                message: err.message().to_owned(),
            },
        }
    }
}

/// Truncate `s` to at most `max` bytes, cutting on a UTF-8 char boundary so the
/// result is always valid UTF-8.
pub(crate) fn truncate_on_char_boundary(s: &mut String, max: usize) {
    if s.len() <= max {
        return;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s.truncate(end);
}

/// Convenience alias for results carrying a Jetstream [`Error`].
pub type Result<T> = core::result::Result<T, Error>;
