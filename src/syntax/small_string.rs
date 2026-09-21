//! Private owned storage for short identifiers. No interning or borrowed
//! lifetimes: every value remains independent, with a heap fallback at any size.

use std::{
    cmp::Ordering,
    fmt,
    hash::{Hash, Hasher},
    ops::Deref,
};

const INLINE: usize = 32;

#[derive(Clone)]
pub(super) struct SmallString(Storage);

#[derive(Clone)]
enum Storage {
    Inline { bytes: [u8; INLINE], len: u8 },
    Heap(String),
}

impl From<&str> for SmallString {
    fn from(value: &str) -> Self {
        if value.len() <= INLINE {
            let mut bytes = [0; INLINE];
            bytes[..value.len()].copy_from_slice(value.as_bytes());
            Self(Storage::Inline {
                bytes,
                len: value.len() as u8,
            })
        } else {
            Self(Storage::Heap(value.to_owned()))
        }
    }
}

impl SmallString {
    pub(super) fn as_str(&self) -> &str {
        match &self.0 {
            Storage::Inline { bytes, len } => {
                // Construction copies a complete str; the only mutation is
                // ASCII case conversion, which preserves UTF-8 and byte length.
                std::str::from_utf8(&bytes[..usize::from(*len)]).unwrap_or_default()
            }
            Storage::Heap(value) => value,
        }
    }

    pub(super) fn lowercase_prefix(&mut self, end: usize) {
        match &mut self.0 {
            Storage::Inline { bytes, .. } => bytes[..end].make_ascii_lowercase(),
            Storage::Heap(value) => value[..end].make_ascii_lowercase(),
        }
    }
}

impl Default for SmallString {
    fn default() -> Self {
        Self::from("")
    }
}
impl Deref for SmallString {
    type Target = str;
    fn deref(&self) -> &str {
        self.as_str()
    }
}
impl fmt::Debug for SmallString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_str(), f)
    }
}
impl PartialEq for SmallString {
    fn eq(&self, other: &Self) -> bool {
        self.as_str() == other.as_str()
    }
}
impl Eq for SmallString {}
impl PartialOrd for SmallString {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for SmallString {
    fn cmp(&self, other: &Self) -> Ordering {
        self.as_str().cmp(other.as_str())
    }
}
impl Hash for SmallString {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.as_str().hash(state);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::hash_map::DefaultHasher;

    fn hash(value: impl Hash) -> u64 {
        let mut state = DefaultHasher::new();
        value.hash(&mut state);
        state.finish()
    }

    proptest::proptest! {
        #[test]
        fn matches_string_contract(a in ".{0,100}", b in ".{0,100}") {
            let small = SmallString::from(a.as_str());
            let other = SmallString::from(b.as_str());
            proptest::prop_assert_eq!(small.as_str(), a.as_str());
            let cloned = small.clone();
            proptest::prop_assert_eq!(cloned.as_str(), a.as_str());
            proptest::prop_assert_eq!(hash(&small), hash(a.as_str()));
            proptest::prop_assert_eq!(small.cmp(&other), a.cmp(&b));
            proptest::prop_assert_eq!(format!("{small:?}"), format!("{a:?}"));
            for end in a.char_indices().map(|(i, _)| i).chain([a.len()]) {
                let mut normalized = small.clone();
                let mut expected = a.clone();
                normalized.lowercase_prefix(end);
                expected[..end].make_ascii_lowercase();
                proptest::prop_assert_eq!(normalized.as_str(), expected.as_str());
            }
        }
    }

    #[test]
    fn inline_boundary_and_heap_retention() {
        for size in [0, 1, INLINE - 1, INLINE, INLINE + 1, 317, 2048] {
            let source = "A".repeat(size);
            let value = SmallString::from(source.as_str());
            assert_eq!(matches!(&value.0, Storage::Inline { .. }), size <= INLINE);
            let retained = value.clone();
            drop(source);
            drop(value);
            assert_eq!(retained.as_str(), "A".repeat(size));
        }
    }
}
