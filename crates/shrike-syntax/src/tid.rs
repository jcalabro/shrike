use std::fmt;
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::SyntaxError;

/// Base32-sort alphabet used for TID encoding.
const ALPHABET: &[u8; 32] = b"234567abcdefghijklmnopqrstuvwxyz";

/// A Timestamp Identifier (TID) — a 64-bit value encoded as 13 base32-sort characters.
///
/// Layout:
/// - Bits 63–10: microsecond timestamp (54 bits, high bit always clear)
/// - Bits 9–0:   clock ID (10 bits)
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Tid(u64);

impl Tid {
    /// Construct a TID from a microsecond timestamp and a 10-bit clock ID.
    /// The high bit of the resulting u64 is always cleared.
    pub fn new(timestamp_micros: u64, clock_id: u16) -> Self {
        let v = (timestamp_micros << 10) | u64::from(clock_id & 0x3FF);
        // Clear high bit per the spec.
        Tid(v & !(1u64 << 63))
    }

    /// Extract the microsecond timestamp component.
    pub fn timestamp_micros(self) -> u64 {
        self.0 >> 10
    }

    /// Extract the 10-bit clock ID component.
    pub fn clock_id(self) -> u16 {
        (self.0 & 0x3FF) as u16
    }

    /// Return the raw 64-bit representation.
    pub fn as_u64(self) -> u64 {
        self.0
    }
}

impl fmt::Display for Tid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut v = self.0;
        let mut buf = [0u8; 13];
        for i in (0..13).rev() {
            buf[i] = ALPHABET[(v & 0x1F) as usize];
            v >>= 5;
        }
        // ALPHABET contains only ASCII bytes [2-7a-z], so buf is always valid UTF-8.
        let s = std::str::from_utf8(&buf).map_err(|_| fmt::Error)?;
        f.write_str(s)
    }
}

impl TryFrom<&str> for Tid {
    type Error = SyntaxError;

    fn try_from(raw: &str) -> Result<Self, Self::Error> {
        let err = |msg: &str| SyntaxError::InvalidTid(format!("{raw:?}: {msg}"));

        if raw.len() != 13 {
            return Err(err("must be exactly 13 characters"));
        }

        let bytes = raw.as_bytes();

        // First character must be in [234567abcdefghij] — the half of the alphabet
        // where bit 4 of the 5-bit value is clear (value 0–15), which keeps the
        // high bit of the u64 clear.
        if !is_tid_first_char(bytes[0]) {
            return Err(err("invalid first character (high bit would be set)"));
        }

        for &b in &bytes[1..] {
            if !is_tid_char(b) {
                return Err(err("invalid character"));
            }
        }

        // Decode the 13 × 5-bit groups into a u64.
        let mut v: u64 = 0;
        for &b in bytes {
            v = (v << 5) | u64::from(base32_decode(b));
        }

        Ok(Tid(v))
    }
}

impl FromStr for Tid {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Tid::try_from(s)
    }
}

impl Serialize for Tid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for Tid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let s = String::deserialize(deserializer)?;
        Tid::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

// ---------------------------------------------------------------------------
// Character helpers
// ---------------------------------------------------------------------------

/// Valid first character: [234567abcdefghij] — values 0–15 in the alphabet,
/// which keeps bit 63 of the decoded u64 clear.
#[inline]
fn is_tid_first_char(c: u8) -> bool {
    (b'2'..=b'7').contains(&c) || (b'a'..=b'j').contains(&c)
}

/// Any base32-sort character: [234567a-z].
#[inline]
fn is_tid_char(c: u8) -> bool {
    (b'2'..=b'7').contains(&c) || c.is_ascii_lowercase()
}

/// Decode a single base32-sort character to its 5-bit value.
///
/// Caller must ensure `c` is a valid base32-sort character.
#[inline]
fn base32_decode(c: u8) -> u8 {
    if (b'2'..=b'7').contains(&c) {
        c - b'2'
    } else {
        c - b'a' + 6
    }
}

// ---------------------------------------------------------------------------
// TidClock
// ---------------------------------------------------------------------------

/// Generates monotonically increasing [`Tid`] values.
///
/// Thread-safe: uses an `AtomicU64` for the last-seen timestamp so `next()`
/// can be called from multiple threads without a mutex.
pub struct TidClock {
    last: AtomicU64,
    clock_id: u16,
}

impl TidClock {
    /// Create a new clock with the given 10-bit clock ID.
    ///
    /// Returns an error if `clock_id >= 1024`.
    pub fn new(clock_id: u16) -> Result<Self, SyntaxError> {
        if clock_id >= 1024 {
            return Err(SyntaxError::InvalidTid(
                "clock_id must fit in 10 bits".into(),
            ));
        }
        Ok(TidClock {
            last: AtomicU64::new(0),
            clock_id,
        })
    }

    /// Return the next TID, guaranteed to be strictly greater than the previous.
    pub fn next(&self) -> Tid {
        loop {
            let prev = self.last.load(Ordering::SeqCst);
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_micros() as u64;
            let ts = if now > prev { now } else { prev + 1 };
            if self
                .last
                .compare_exchange_weak(prev, ts, Ordering::SeqCst, Ordering::Relaxed)
                .is_ok()
            {
                return Tid::new(ts, self.clock_id);
            }
        }
    }
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

    fn load_vectors(path: &str) -> Vec<String> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_valid_tids() {
        let vectors = load_vectors("testdata/tid_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            let tid = Tid::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid TID: {v:?}, got error: {e}"));
            assert_eq!(tid.to_string(), *v);
        }
    }

    #[test]
    fn parse_invalid_tids() {
        let vectors = load_vectors("testdata/tid_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            assert!(
                Tid::try_from(v.as_str()).is_err(),
                "should be invalid TID: {v:?}"
            );
        }
    }

    #[test]
    fn tid_roundtrip() {
        let tid = Tid::new(1_700_000_000_000_000, 0);
        let s = tid.to_string();
        assert_eq!(s.len(), 13);
        let parsed: Tid = s.parse().unwrap();
        assert_eq!(tid, parsed);
    }

    #[test]
    fn tid_timestamp_and_clock_id() {
        let tid = Tid::new(1_700_000_000_000_000, 42);
        assert_eq!(tid.timestamp_micros(), 1_700_000_000_000_000);
        assert_eq!(tid.clock_id(), 42);
    }

    #[test]
    fn tid_clock_monotonic() {
        let clock = TidClock::new(0).unwrap();
        let mut prev = clock.next();
        for _ in 0..100 {
            let next = clock.next();
            assert!(next > prev, "TIDs must be monotonically increasing");
            prev = next;
        }
    }

    #[test]
    fn tid_serde_roundtrip() {
        let tid = Tid::new(1_700_000_000_000_000, 0);
        let json = serde_json::to_string(&tid).unwrap();
        let parsed: Tid = serde_json::from_str(&json).unwrap();
        assert_eq!(tid, parsed);
    }

    #[test]
    fn tid_display_13_chars() {
        let tid = Tid::new(0, 0);
        assert_eq!(tid.to_string().len(), 13);
    }

    #[test]
    fn tid_integer_roundtrip() {
        let tid = Tid::new(0, 0);
        // Decode back from the string representation of a raw value.
        let v: u64 = 123_456_789;
        // Construct via raw integer (clear high bit as spec requires).
        let raw = v & !(1u64 << 63);
        // Encode manually.
        let mut buf = [0u8; 13];
        let mut tmp = raw;
        for i in (0..13).rev() {
            buf[i] = ALPHABET[(tmp & 0x1F) as usize];
            tmp >>= 5;
        }
        let s = std::str::from_utf8(&buf).unwrap();
        let parsed: Tid = s.parse().unwrap();
        assert_eq!(parsed.as_u64(), raw);

        // Zero TID encodes to all '2's.
        assert_eq!(tid.to_string(), "2222222222222");
    }

    #[test]
    fn tid_clock_concurrent_monotonic() {
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let clock = Arc::new(TidClock::new(0).unwrap());
        let mut handles = vec![];

        for _ in 0..4 {
            let clock = Arc::clone(&clock);
            handles.push(std::thread::spawn(move || {
                let mut tids = Vec::with_capacity(250);
                for _ in 0..250 {
                    tids.push(clock.next());
                }
                tids
            }));
        }

        let mut all_tids = BTreeSet::new();
        for h in handles {
            for tid in h.join().unwrap() {
                assert!(all_tids.insert(tid), "duplicate TID detected: {tid}");
            }
        }
        assert_eq!(all_tids.len(), 1000);
    }

    #[test]
    fn tid_high_bit_cleared_on_new() {
        // Feeding a timestamp that would overflow into bit 63 should have it cleared.
        let huge_ts = u64::MAX >> 10; // fills all 54 timestamp bits
        let tid = Tid::new(huge_ts, 0);
        // High bit must be clear.
        assert_eq!(tid.as_u64() >> 63, 0);
    }
}
