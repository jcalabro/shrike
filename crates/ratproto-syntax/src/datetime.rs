use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// A validated AT Protocol datetime (RFC 3339 subset).
///
/// Rules:
/// - Date separator must be `T` (not space)
/// - Timezone required: `Z` (uppercase only) or `+HH:MM` / `-HH:MM`
/// - `-00:00` is rejected; use `+00:00` or `Z` instead
/// - Fractional seconds are optional
///
/// Use `TryFrom<&str>` / `.parse()` for strict parsing, or
/// [`Datetime::parse_lenient`] for compatibility with non-conforming inputs.
#[derive(Debug, Clone, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Datetime(String);

impl Datetime {
    /// Strict parse: validates the full AT Protocol datetime rules.
    pub fn parse(raw: &str) -> Result<Self, SyntaxError> {
        Datetime::try_from(raw)
    }

    /// Lenient parse: tries strict parsing first, then applies common fixes.
    ///
    /// Fixes applied (in order):
    /// 1. `-00:00` → `+00:00`
    /// 2. `-0000` / `+0000` → `+00:00`
    /// 3. Missing timezone → append `Z`
    pub fn parse_lenient(raw: &str) -> Result<Self, SyntaxError> {
        if let Ok(dt) = Datetime::try_from(raw) {
            return Ok(dt);
        }

        let mut fixed = raw.to_owned();

        // Convert -00:00 to +00:00.
        if fixed.ends_with("-00:00") {
            let end = fixed.len() - 6;
            fixed.truncate(end);
            fixed.push_str("+00:00");
        }

        // Convert -0000 or +0000 to +00:00.
        if fixed.ends_with("-0000") || fixed.ends_with("+0000") {
            let end = fixed.len() - 5;
            fixed.truncate(end);
            fixed.push_str("+00:00");
        }

        // Append Z if no timezone detected.
        if !has_timezone(&fixed) {
            fixed.push('Z');
        }

        Datetime::try_from(fixed.as_str())
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Datetime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for Datetime {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl Borrow<str> for Datetime {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Datetime {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidDatetime(format!("{raw:?}: {msg}"));

        if raw.is_empty() {
            return Err(err("empty"));
        }
        if raw.len() > 64 {
            return Err(err("too long"));
        }

        validate_datetime_syntax(raw).map_err(|_| err("invalid datetime syntax"))?;

        Ok(Datetime(raw.to_owned()))
    }
}

impl FromStr for Datetime {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Datetime::try_from(s)
    }
}

impl Serialize for Datetime {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Datetime {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Datetime::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Validation helpers
// ---------------------------------------------------------------------------

/// Validate the structural format: YYYY-MM-DDThh:mm:ss[.frac](Z|[+-]hh:mm)
fn validate_datetime_syntax(raw: &str) -> Result<(), ()> {
    let n = raw.len();
    // Minimum: "0000-01-01T00:00:00Z" = 20 chars
    if n < 20 {
        return Err(());
    }

    let b = raw.as_bytes();

    // YYYY
    if !b[0].is_ascii_digit()
        || !b[1].is_ascii_digit()
        || !b[2].is_ascii_digit()
        || !b[3].is_ascii_digit()
    {
        return Err(());
    }
    if b[4] != b'-' {
        return Err(());
    }
    // MM
    if !b[5].is_ascii_digit() || !b[6].is_ascii_digit() {
        return Err(());
    }
    if b[7] != b'-' {
        return Err(());
    }
    // DD
    if !b[8].is_ascii_digit() || !b[9].is_ascii_digit() {
        return Err(());
    }
    // T separator (must be uppercase)
    if b[10] != b'T' {
        return Err(());
    }
    // hh
    if !b[11].is_ascii_digit() || !b[12].is_ascii_digit() {
        return Err(());
    }
    if b[13] != b':' {
        return Err(());
    }
    // mm
    if !b[14].is_ascii_digit() || !b[15].is_ascii_digit() {
        return Err(());
    }
    if b[16] != b':' {
        return Err(());
    }
    // ss
    if !b[17].is_ascii_digit() || !b[18].is_ascii_digit() {
        return Err(());
    }

    // Calendar range checks
    let month = (b[5] - b'0') * 10 + (b[6] - b'0');
    if !(1..=12).contains(&month) {
        return Err(());
    }
    let day = (b[8] - b'0') * 10 + (b[9] - b'0');
    if !(1..=31).contains(&day) {
        return Err(());
    }
    let hour = (b[11] - b'0') * 10 + (b[12] - b'0');
    if hour > 23 {
        return Err(());
    }
    let minute = (b[14] - b'0') * 10 + (b[15] - b'0');
    if minute > 59 {
        return Err(());
    }
    let second = (b[17] - b'0') * 10 + (b[18] - b'0');
    // 60 is allowed for leap seconds
    if second > 60 {
        return Err(());
    }

    let mut i = 19usize;

    // Optional fractional seconds: .[digits]
    if i < n && b[i] == b'.' {
        i += 1;
        let frac_start = i;
        while i < n && b[i].is_ascii_digit() {
            i += 1;
        }
        let frac_len = i - frac_start;
        if frac_len == 0 || frac_len > 20 {
            return Err(());
        }
    }

    // Timezone: Z or [+-]hh:mm
    if i >= n {
        return Err(());
    }
    match b[i] {
        b'Z' => {
            i += 1;
        }
        b'+' | b'-' => {
            // Reject -00:00
            if &raw[i..] == "-00:00" {
                return Err(());
            }
            i += 1;
            if i + 5 > n {
                return Err(());
            }
            if !b[i].is_ascii_digit() || !b[i + 1].is_ascii_digit() {
                return Err(());
            }
            if b[i + 2] != b':' {
                return Err(());
            }
            if !b[i + 3].is_ascii_digit() || !b[i + 4].is_ascii_digit() {
                return Err(());
            }
            i += 5;
        }
        _ => return Err(()),
    }

    if i != n {
        return Err(());
    }

    Ok(())
}

fn has_timezone(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let b = s.as_bytes();
    if b.last().copied() == Some(b'Z') {
        return true;
    }
    if s.len() >= 6 {
        let c = b[s.len() - 6];
        if c == b'+' || c == b'-' {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use super::*;

    #[test]
    fn datetime_valid_z() {
        Datetime::try_from("2024-01-01T00:00:00Z").unwrap();
    }

    #[test]
    fn datetime_valid_offset() {
        Datetime::try_from("2024-01-01T00:00:00+00:00").unwrap();
    }

    #[test]
    fn datetime_reject_negative_zero() {
        assert!(Datetime::try_from("2024-01-01T00:00:00-00:00").is_err());
    }

    #[test]
    fn datetime_reject_lowercase_z() {
        assert!(Datetime::try_from("2024-01-01T00:00:00z").is_err());
    }

    #[test]
    fn datetime_reject_no_timezone() {
        assert!(Datetime::try_from("2024-01-01T00:00:00").is_err());
    }

    #[test]
    fn datetime_with_fractional() {
        Datetime::try_from("2024-01-01T00:00:00.123Z").unwrap();
    }

    #[test]
    fn datetime_serde_roundtrip() {
        let dt = Datetime::try_from("2024-01-01T12:30:00Z").unwrap();
        let json = serde_json::to_string(&dt).unwrap();
        let parsed: Datetime = serde_json::from_str(&json).unwrap();
        assert_eq!(dt, parsed);
    }

    #[test]
    fn datetime_lenient_negative_zero() {
        // -00:00 is invalid in strict mode but lenient converts it to +00:00
        assert!(Datetime::try_from("2024-01-01T00:00:00-00:00").is_err());
        Datetime::parse_lenient("2024-01-01T00:00:00-00:00").unwrap();
    }

    #[test]
    fn datetime_lenient_no_timezone() {
        // No timezone: lenient appends Z
        assert!(Datetime::try_from("2024-01-01T00:00:00").is_err());
        Datetime::parse_lenient("2024-01-01T00:00:00").unwrap();
    }

    #[test]
    fn datetime_reject_space_separator() {
        assert!(Datetime::try_from("2024-01-01 00:00:00Z").is_err());
    }

    #[test]
    fn datetime_reject_empty() {
        assert!(Datetime::try_from("").is_err());
    }
}
