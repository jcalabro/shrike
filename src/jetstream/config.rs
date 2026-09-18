//! Local configuration primitives validated before any I/O: host normalization
//! and the resume [`Cursor`].
//!
//! A Jetstream cursor is local to one server instance and is not portable
//! between instances, so persistence must be keyed by the *normalized* host
//! identity [`normalize_host`] returns. The cursor model has two domains the
//! server distinguishes purely by magnitude — a value `>= 10^15` is read as
//! Unix microseconds, anything smaller as a sequence — so [`Cursor`] keeps the
//! two apart as distinct variants and validates each against the constraints its
//! domain imposes.

use super::error::{Error, Result};

/// The server reads a cursor value greater than or equal to this as Unix
/// microseconds rather than a sequence number (`10^15`). A live sequence resume
/// must stay strictly below it.
pub const TIMESTAMP_CURSOR_THRESHOLD: i64 = 1_000_000_000_000_000;

/// Normalize a user-supplied host into a bare authority (`host` or `host:port`),
/// lowercased, with any scheme, path, query, or fragment stripped.
///
/// The result is both the base for building `https`/`wss` URLs later and the
/// stable instance identity a persisted cursor must be keyed by. Embedded
/// credentials (`user:pass@host`) are rejected so a secret can never ride along
/// in the host, as are control characters, whitespace, and empty input.
pub fn normalize_host(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(Error::InvalidConfig("host is empty"));
    }

    // Strip an optional scheme; only web schemes are meaningful here.
    let after_scheme = match trimmed.split_once("://") {
        Some((scheme, rest)) => {
            match scheme.to_ascii_lowercase().as_str() {
                "http" | "https" | "ws" | "wss" => {}
                _ => return Err(Error::InvalidConfig("host has an unsupported URL scheme")),
            }
            rest
        }
        None => trimmed,
    };

    // Strip anything at or after the first path/query/fragment delimiter.
    let authority = after_scheme
        .split(['/', '?', '#'])
        .next()
        .unwrap_or(after_scheme);

    if authority.is_empty() {
        return Err(Error::InvalidConfig("host is empty"));
    }
    // Userinfo would carry credentials into the host; forbid it outright.
    if authority.contains('@') {
        return Err(Error::InvalidConfig("host must not contain credentials"));
    }
    // The authority alphabet: DNS names, ports, and bracketed IPv6 literals.
    for b in authority.bytes() {
        let ok = b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':' | b'[' | b']');
        if !ok {
            return Err(Error::InvalidConfig("host contains an invalid character"));
        }
    }

    Ok(authority.to_ascii_lowercase())
}

/// A resume position for a subscription: a sequence or a timestamp.
///
/// The two are different domains, not interchangeable numbers. "Start at the
/// current tip" is deliberately *not* representable here — it is a separate
/// builder state — so that a `Seq(0)` footgun (wire `0` means "everything",
/// while Go's `WithLiveCursor(0)` means "tip") cannot arise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Cursor {
    /// A 1-based Jetstream sequence. The server replays inclusively from it.
    Seq(u64),
    /// A Unix-microsecond timestamp. An old value is clamped by the server.
    Timestamp(i64),
}

impl Cursor {
    /// Validate the cursor for use as a **live** subscription resume position.
    ///
    /// A sequence must be `>= 1` (use tip mode to start at the tip), must not
    /// exceed the XRPC signed-integer ceiling, and must stay below
    /// [`TIMESTAMP_CURSOR_THRESHOLD`] or the server would misread it as a
    /// timestamp. A timestamp must be non-negative; being an `i64` it is already
    /// within the signed ceiling.
    pub fn validate_live(&self) -> Result<()> {
        match self {
            Cursor::Seq(0) => Err(Error::InvalidConfig(
                "live resume sequence must be >= 1; use tip mode to start at the tip",
            )),
            Cursor::Seq(n) => {
                if *n > i64::MAX as u64 {
                    return Err(Error::InvalidConfig("cursor sequence exceeds i64::MAX"));
                }
                if *n >= TIMESTAMP_CURSOR_THRESHOLD as u64 {
                    return Err(Error::InvalidConfig(
                        "live resume sequence must be below 10^15 or it reads as a timestamp",
                    ));
                }
                Ok(())
            }
            Cursor::Timestamp(us) => {
                if *us < 0 {
                    return Err(Error::InvalidConfig(
                        "timestamp cursor must be non-negative",
                    ));
                }
                Ok(())
            }
        }
    }

    /// Validate the cursor for use as an **archive** bound (`afterSeq` /
    /// `beforeSeq`). Archive bounds are sequences; `0` is the valid "before the
    /// beginning" floor. A timestamp is not an archive bound.
    pub fn validate_archive_seq(&self) -> Result<u64> {
        match self {
            Cursor::Seq(n) => {
                if *n > i64::MAX as u64 {
                    return Err(Error::InvalidConfig("cursor sequence exceeds i64::MAX"));
                }
                Ok(*n)
            }
            Cursor::Timestamp(_) => Err(Error::InvalidConfig(
                "archive bounds are sequences, not timestamps",
            )),
        }
    }

    /// The value the server expects on the wire, as a signed integer. Only
    /// meaningful after the appropriate `validate_*` call has succeeded.
    pub fn to_wire(self) -> i64 {
        match self {
            Cursor::Seq(n) => n as i64,
            Cursor::Timestamp(us) => us,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_scheme_path_and_case() {
        assert_eq!(
            normalize_host("https://Jetstream.US-East.bsky.network/xrpc/foo?x=1").unwrap(),
            "jetstream.us-east.bsky.network"
        );
        assert_eq!(
            normalize_host("wss://example.com:443").unwrap(),
            "example.com:443"
        );
        assert_eq!(
            normalize_host("  jetstream.us-east.bsky.network  ").unwrap(),
            "jetstream.us-east.bsky.network"
        );
    }

    #[test]
    fn preserves_ipv6_and_port() {
        assert_eq!(normalize_host("https://[::1]:3000/").unwrap(), "[::1]:3000");
    }

    #[test]
    fn rejects_bad_hosts() {
        assert!(normalize_host("").is_err());
        assert!(normalize_host("   ").is_err());
        assert!(normalize_host("ftp://example.com").is_err());
        assert!(normalize_host("https://user:pass@example.com").is_err());
        assert!(normalize_host("has space.com").is_err());
        assert!(normalize_host("https:///only-path").is_err());
    }

    #[test]
    fn live_seq_cursor_bounds() {
        assert!(Cursor::Seq(1).validate_live().is_ok());
        assert!(Cursor::Seq(0).validate_live().is_err());
        // At or above the timestamp threshold is rejected for a live sequence.
        assert!(
            Cursor::Seq(TIMESTAMP_CURSOR_THRESHOLD as u64)
                .validate_live()
                .is_err()
        );
        assert!(
            Cursor::Seq((TIMESTAMP_CURSOR_THRESHOLD as u64) - 1)
                .validate_live()
                .is_ok()
        );
        assert!(Cursor::Seq(u64::MAX).validate_live().is_err());
    }

    #[test]
    fn live_timestamp_cursor_bounds() {
        assert!(Cursor::Timestamp(0).validate_live().is_ok());
        assert!(
            Cursor::Timestamp(TIMESTAMP_CURSOR_THRESHOLD)
                .validate_live()
                .is_ok()
        );
        assert!(Cursor::Timestamp(-1).validate_live().is_err());
    }

    #[test]
    fn archive_seq_accepts_zero_rejects_timestamp() {
        assert_eq!(Cursor::Seq(0).validate_archive_seq().unwrap(), 0);
        assert_eq!(Cursor::Seq(42).validate_archive_seq().unwrap(), 42);
        assert!(Cursor::Timestamp(0).validate_archive_seq().is_err());
        assert!(Cursor::Seq(u64::MAX).validate_archive_seq().is_err());
    }
}
