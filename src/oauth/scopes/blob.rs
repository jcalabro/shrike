use std::fmt;
use std::str::FromStr;

use super::InvalidScope;
use super::syntax::{self, Field, Syntax};

/// A `blob:` permission: uploading blobs whose MIME type matches one of the
/// `accept` patterns (`image/png`, `image/*` or `*/*`).
///
/// ```
/// use shrike::oauth::scopes::BlobPermission;
///
/// let perm: BlobPermission = "blob:image/*".parse().unwrap();
/// assert!(perm.matches("image/png"));
/// assert!(!perm.matches("video/mp4"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct BlobPermission {
    accept: Vec<String>,
}

const FIELDS: &[Field] = &[Field {
    name: "accept",
    multiple: true,
    required: true,
    validate: syntax::is_accept,
}];

impl BlobPermission {
    /// Builds a permission. Returns `None` when `accept` is empty or holds an
    /// invalid pattern.
    pub fn new<S: Into<String>>(accept: impl IntoIterator<Item = S>) -> Option<Self> {
        let accept: Vec<String> = accept.into_iter().map(Into::into).collect();
        (!accept.is_empty() && accept.iter().all(|a| syntax::is_accept(a)))
            .then_some(BlobPermission { accept })
    }

    /// The accepted MIME type patterns, as written.
    pub fn accept(&self) -> &[String] {
        &self.accept
    }

    /// Whether this permission allows uploading a blob of MIME type `mime`.
    /// Matching is case-sensitive and uses the patterns as written, while
    /// rendering lowercases them, as the reference implementation does.
    pub fn matches(&self, mime: &str) -> bool {
        self.accept.iter().any(|a| syntax::matches_accept(a, mime))
    }

    /// The scope that would allow uploading a blob of MIME type `mime`.
    pub fn scope_needed_for(mime: &str) -> String {
        BlobPermission {
            accept: vec![mime.to_string()],
        }
        .to_string()
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let accept = syntax::parse(syntax, FIELDS, "accept")?.pop()?.many()?;
        Some(BlobPermission { accept })
    }
}

impl FromStr for BlobPermission {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "blob")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for BlobPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The most concise equivalent list: `*/*` alone, or lowercased patterns
        // without those covered by a `type/*` wildcard, sorted.
        let accept = if self.accept.iter().any(|a| a == "*/*") {
            vec!["*/*".to_string()]
        } else {
            let lower: Vec<String> = self.accept.iter().map(|a| a.to_lowercase()).collect();
            let mut accept: Vec<String> = lower
                .iter()
                .filter(|a| {
                    let ty = a.split('/').next().unwrap_or_default();
                    a.ends_with("/*") || !lower.contains(&format!("{ty}/*"))
                })
                .cloned()
                .collect();
            accept.sort_by(|a, b| syntax::js_cmp(a, b));
            accept
        };

        let scope = match accept.as_slice() {
            [one] => syntax::format("blob", Some(one), &[]),
            _ => {
                let unique = syntax::unique(&accept);
                let params: Vec<_> = unique.iter().map(|a| ("accept", a.as_str())).collect();
                syntax::format("blob", None, &params)
            }
        };
        f.write_str(&scope)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(scope: &str) -> Option<BlobPermission> {
        scope.parse().ok()
    }

    fn fmt(accept: &[&str]) -> String {
        BlobPermission::new(accept.iter().copied())
            .unwrap()
            .to_string()
    }

    // Vectors from the reference `blob-permission.test.ts` and indigo's
    // permission scope fixtures.
    #[test]
    fn parses() {
        assert_eq!(parse("blob:image/png").unwrap().accept(), ["image/png"]);
        assert_eq!(
            parse("blob?accept=image/png&accept=image/jpeg")
                .unwrap()
                .accept(),
            ["image/png", "image/jpeg"]
        );
        assert_eq!(
            parse("blob?accept=image%2Fpng").unwrap().accept(),
            ["image/png"]
        );
        assert_eq!(parse("blob:IMAGE/PNG").unwrap().accept(), ["IMAGE/PNG"]);
        for invalid in [
            "blob",
            "blob:",
            "invalid",
            "scope",
            "blob:invalid",
            "blob?accept=invalid-mime",
            "blob?accept=invalid",
            "blob:*",
            "blob:/image",
            "blob:*/**",
            "blob:*/png",
            "blob?Accept=image/png",
            "Blob?accept=image/png",
            "blob:image/png?accept=image/jpeg",
            "blob?accept=image/svg+xml",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn matches() {
        let png = parse("blob:image/png").unwrap();
        assert!(png.matches("image/png"));
        assert!(!png.matches("image/jpeg"));
        let any = parse("blob:*/*").unwrap();
        assert!(any.matches("image/jpeg"));
        assert!(any.matches("application/json"));
        assert!(!any.matches("image"));
        assert!(parse("blob:image/*").unwrap().matches("image/gif"));
        let two = parse("blob?accept=image/png&accept=image/jpeg").unwrap();
        assert!(two.matches("image/png"));
        assert!(two.matches("image/jpeg"));
        assert!(!two.matches("image/gif"));
        // Matching uses the patterns as written, not their normalized form.
        let upper = parse("blob:IMAGE/PNG").unwrap();
        assert!(upper.matches("IMAGE/PNG"));
        assert!(!upper.matches("image/png"));
    }

    #[test]
    fn scope_needed_for() {
        assert_eq!(
            BlobPermission::scope_needed_for("image/png"),
            "blob:image/png"
        );
        assert_eq!(
            BlobPermission::scope_needed_for("application/json"),
            "blob:application/json"
        );
        assert_eq!(
            BlobPermission::scope_needed_for("IMAGE/Png"),
            "blob:image/png"
        );
    }

    #[test]
    fn formats() {
        assert_eq!(
            fmt(&["image/png", "image/jpeg"]),
            "blob?accept=image/jpeg&accept=image/png"
        );
        assert_eq!(fmt(&["*/*", "image/*"]), "blob:*/*");
        assert_eq!(fmt(&["*/*", "image/png"]), "blob:*/*");
        assert_eq!(fmt(&["image/*", "image/png"]), "blob:image/*");
        assert_eq!(fmt(&["image/png"]), "blob:image/png");
        assert_eq!(fmt(&["image/*"]), "blob:image/*");
        assert_eq!(fmt(&["*/*"]), "blob:*/*");
        assert_eq!(fmt(&["image/svg+xml"]), "blob:image/svg+xml");
        // Matches the reference: duplicates collapse after choosing the form.
        assert_eq!(fmt(&["image/png", "image/png"]), "blob?accept=image/png");
        // Deliberate deviation: the reference writes `svg+xml`, which decodes
        // to `svg xml` in a query.
        let svg = fmt(&["image/svg+xml", "image/png"]);
        assert_eq!(svg, "blob?accept=image/png&accept=image/svg%2Bxml");
        assert_eq!(
            parse(&svg).unwrap().accept(),
            ["image/png", "image/svg+xml"]
        );

        assert!(BlobPermission::new(Vec::<String>::new()).is_none());
        assert!(BlobPermission::new(["image"]).is_none());
    }
}
