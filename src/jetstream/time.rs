//! Exact conversion between the two time representations Jetstream v2 uses.
//!
//! The live wire carries an event's display time as an RFC-3339 UTC string with
//! microsecond precision (`network.bsky.jetstream.subscribeEvents#commit.time`),
//! while the archive stores witnessed/indexed time as Unix microseconds. The
//! engine needs to move between them without drift: a timestamp cursor is
//! expressed in Unix microseconds, and a live event's `time` must map to the
//! same instant an archive row would.
//!
//! [Jiff] performs the calendar arithmetic. We keep the surface tiny — parse an
//! instant and read its microseconds, or build an instant from microseconds and
//! format it with a fixed six-digit fraction — so there is no timezone database
//! or wall-clock dependency and the module compiles unchanged on wasm.
//!
//! [Jiff]: https://docs.rs/jiff

use super::error::{Error, Result};
use jiff::Timestamp;
use jiff::fmt::temporal::DateTimePrinter;

/// Prints an instant as RFC-3339 in Zulu time with exactly six fractional
/// digits, matching the microsecond precision Jetstream promises on the wire.
const MICROS_PRINTER: DateTimePrinter = DateTimePrinter::new().precision(Some(6));

/// Parse an RFC-3339 timestamp and return its Unix-microsecond instant.
///
/// Accepts any RFC-3339 instant Jiff understands (a `Z` or numeric offset); the
/// returned value is the absolute instant, so an offset is folded into UTC.
/// The Jetstream wire only ever sends six fractional digits, so this is exact
/// there; a hypothetical sub-microsecond input would be truncated toward the
/// epoch by Jiff's microsecond accessor.
pub fn rfc3339_to_micros(s: &str) -> Result<i64> {
    let ts: Timestamp = s
        .parse()
        .map_err(|_| Error::InvalidTimestamp("not an RFC-3339 instant"))?;
    Ok(ts.as_microsecond())
}

/// Format a Unix-microsecond instant as an RFC-3339 UTC string with exactly six
/// fractional digits (e.g. `2024-01-01T00:00:00.000000Z`).
pub fn micros_to_rfc3339(micros: i64) -> Result<String> {
    let ts = Timestamp::from_microsecond(micros)
        .map_err(|_| Error::InvalidTimestamp("microseconds out of representable range"))?;
    Ok(MICROS_PRINTER.timestamp_to_string(&ts))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn parses_zulu_microseconds() {
        assert_eq!(rfc3339_to_micros("1970-01-01T00:00:00.000000Z").unwrap(), 0);
        assert_eq!(rfc3339_to_micros("1970-01-01T00:00:00.000001Z").unwrap(), 1);
        assert_eq!(
            rfc3339_to_micros("2024-01-01T00:00:00.000000Z").unwrap(),
            1_704_067_200_000_000
        );
    }

    #[test]
    fn parses_negative_offset_to_utc_instant() {
        // 19:00 at -05:00 is the same instant as 00:00Z the next day.
        let a = rfc3339_to_micros("1970-01-01T00:00:00.000000Z").unwrap();
        let b = rfc3339_to_micros("1969-12-31T19:00:00.000000-05:00").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn formats_with_six_fractional_digits() {
        assert_eq!(micros_to_rfc3339(0).unwrap(), "1970-01-01T00:00:00.000000Z");
        assert_eq!(micros_to_rfc3339(1).unwrap(), "1970-01-01T00:00:00.000001Z");
        assert_eq!(
            micros_to_rfc3339(1_704_067_200_000_000).unwrap(),
            "2024-01-01T00:00:00.000000Z"
        );
    }

    #[test]
    fn round_trips_micros_through_string_and_back() {
        for micros in [
            0i64,
            1,
            -1,
            1_000_000,
            -1_000_000,
            1_704_067_200_123_456,
            -62_135_596_800_000_000,
        ] {
            let s = micros_to_rfc3339(micros).unwrap();
            assert_eq!(rfc3339_to_micros(&s).unwrap(), micros, "micros={micros}");
        }
    }

    #[test]
    fn rejects_non_rfc3339() {
        assert!(rfc3339_to_micros("").is_err());
        assert!(rfc3339_to_micros("not a date").is_err());
        // No timezone is not an instant.
        assert!(rfc3339_to_micros("2024-01-01T00:00:00.000000").is_err());
    }
}
