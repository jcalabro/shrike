//! A redacting wrapper for the archive API key.
//!
//! The archive endpoints (`planSnapshot`, `getSegment`, `getBlock`) are
//! authenticated with a bearer key. That secret must never reach a log, a
//! `Debug` render, an error message, a tracing field, a URL, or a stats
//! snapshot — anywhere it could be captured. [`ApiKey`] enforces that by
//! construction: it owns the raw secret, exposes it only through the
//! crate-internal [`ApiKey::header_value`] used to build the one authorization
//! header, and renders as a fixed `<redacted>` placeholder under `Debug`. It
//! deliberately implements neither `Display` nor `Clone`-to-string, and its
//! `Debug` never varies with the secret's contents or length.
//!
//! This is a minimal, purpose-built wrapper rather than a general secret-
//! management crate: the library values few dependencies, and total control of
//! the redaction surface is exactly what the security tests assert.

/// An archive bearer key that never renders its secret.
///
/// Construct with [`ApiKey::new`]. The only way to read the secret back is
/// [`ApiKey::header_value`], which is crate-visible and returns a ready-to-send
/// `Bearer <key>` header value — callers cannot obtain the bare secret.
#[derive(Clone)]
pub struct ApiKey {
    raw: String,
}

impl ApiKey {
    /// Wrap a raw archive key. The surrounding whitespace is trimmed; the secret
    /// itself is stored verbatim.
    pub fn new(raw: impl Into<String>) -> Self {
        let mut raw = raw.into();
        let trimmed = raw.trim();
        if trimmed.len() != raw.len() {
            raw = trimmed.to_owned();
        }
        ApiKey { raw }
    }

    /// Whether the wrapped key is empty (no secret supplied).
    pub fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    /// The full `Authorization` header value, `Bearer <key>`.
    ///
    /// Crate-visible on purpose: this is the single point at which the secret
    /// leaves the wrapper, and it only ever does so to populate the outgoing
    /// authorization header. There is intentionally no accessor for the bare
    /// secret.
    pub(crate) fn header_value(&self) -> String {
        format!("Bearer {}", self.raw)
    }
}

impl core::fmt::Debug for ApiKey {
    /// Render a fixed placeholder that never depends on the secret's contents or
    /// length, so `{:?}` on an `ApiKey` (or any struct that contains one) can
    /// never leak the key.
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("ApiKey(<redacted>)")
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    const SECRET: &str = "sk-super-secret-value-12345";

    #[test]
    fn debug_never_reveals_the_secret() {
        let key = ApiKey::new(SECRET);
        let rendered = format!("{key:?}");
        assert_eq!(rendered, "ApiKey(<redacted>)");
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("12345"));
    }

    #[test]
    fn debug_is_constant_across_different_secrets() {
        // A constant-length placeholder that does not vary with the key means an
        // observer cannot even infer the key's length from Debug output.
        let a = format!("{:?}", ApiKey::new("short"));
        let b = format!("{:?}", ApiKey::new("a-much-longer-secret-key-value"));
        assert_eq!(a, b);
    }

    #[test]
    fn header_value_is_the_bearer_form() {
        let key = ApiKey::new(SECRET);
        assert_eq!(key.header_value(), format!("Bearer {SECRET}"));
    }

    #[test]
    fn new_trims_surrounding_whitespace() {
        let key = ApiKey::new("  padded-key  ");
        assert_eq!(key.header_value(), "Bearer padded-key");
        assert!(!key.is_empty());
    }

    #[test]
    fn empty_key_is_reported_empty() {
        assert!(ApiKey::new("").is_empty());
        assert!(ApiKey::new("   ").is_empty());
        assert!(!ApiKey::new("x").is_empty());
    }
}
