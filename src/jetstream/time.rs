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
/// The accepted grammar matches Go's `time.RFC3339Nano` parsing (which the
/// reference client uses), not Jiff's broader Temporal grammar: an uppercase
/// `T` separator, an uppercase `Z` or a `±hh:mm` numeric offset, and an
/// optional fraction. A space separator, lowercase `t`/`z`, or a colonless
/// offset — all of which Jiff would accept — are rejected so both clients
/// classify the same frames as malformed. An offset is folded into UTC. The
/// Jetstream wire only ever sends six fractional digits, so this is exact
/// there; a hypothetical sub-microsecond input would be truncated toward the
/// epoch by Jiff's microsecond accessor.
pub fn rfc3339_to_micros(s: &str) -> Result<i64> {
    if !has_go_rfc3339_shape(s) {
        return Err(Error::InvalidTimestamp("not an RFC-3339 instant"));
    }
    let ts: Timestamp = s
        .parse()
        .map_err(|_| Error::InvalidTimestamp("not an RFC-3339 instant"))?;
    Ok(ts.as_microsecond())
}

/// Whether `s` has the exact shape Go's `time.RFC3339Nano` accepts:
/// `YYYY-MM-DDThh:mm:ss[.fraction](Z|±hh:mm)`. Field *values* are validated by
/// the Jiff parse that follows; this only pins the byte-level grammar.
fn has_go_rfc3339_shape(s: &str) -> bool {
    let b = s.as_bytes();
    // Fixed prefix: date, 'T', time — 19 bytes before fraction/offset.
    if b.len() < 20 {
        return false;
    }
    let digits = |range: core::ops::Range<usize>| b[range].iter().all(u8::is_ascii_digit);
    if !(digits(0..4)
        && b[4] == b'-'
        && digits(5..7)
        && b[7] == b'-'
        && digits(8..10)
        && b[10] == b'T'
        && digits(11..13)
        && b[13] == b':'
        && digits(14..16)
        && b[16] == b':'
        && digits(17..19))
    {
        return false;
    }
    // Optional fraction: '.' followed by at least one digit.
    let mut i = 19;
    if b[i] == b'.' {
        let start = i + 1;
        i = start;
        while i < b.len() && b[i].is_ascii_digit() {
            i += 1;
        }
        if i == start {
            return false;
        }
    }
    // Offset: 'Z' or ±hh:mm, ending the string.
    match b.get(i) {
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+' | b'-') => {
            b.len() == i + 6 && digits(i + 1..i + 3) && b[i + 3] == b':' && digits(i + 4..i + 6)
        }
        _ => false,
    }
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

    #[test]
    fn rejects_jiff_extensions_go_would_reject() {
        // Regression: Jiff's Temporal grammar accepts these; Go's
        // time.RFC3339Nano (the reference client) does not. Both clients must
        // classify the same frames as malformed.
        assert!(rfc3339_to_micros("2024-01-01 00:00:00.000000Z").is_err()); // space
        assert!(rfc3339_to_micros("2024-01-01t00:00:00.000000Z").is_err()); // lowercase t
        assert!(rfc3339_to_micros("2024-01-01T00:00:00.000000z").is_err()); // lowercase z
        assert!(rfc3339_to_micros("2024-01-01T00:00:00+00").is_err()); // colonless offset
        assert!(rfc3339_to_micros("2024-01-01T00:00:00.Z").is_err()); // empty fraction
        // The plain and offset forms still parse.
        assert!(rfc3339_to_micros("2024-01-01T00:00:00Z").is_ok());
        assert!(rfc3339_to_micros("2024-01-01T00:00:00+05:30").is_ok());
    }
}
