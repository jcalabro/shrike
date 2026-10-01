use std::fmt;
use std::str::FromStr;

use super::InvalidScope;
use super::syntax::{self, Field, Syntax};

/// An `rpc:` permission: making authenticated (proxied or service-auth)
/// requests for some methods (`lxm`) to a service (`aud`).
///
/// `aud` is a DID reference with a service fragment, such as
/// `did:web:api.bsky.app#bsky_appview`, or `*` for any service. Either may be a
/// wildcard, but not both.
///
/// ```
/// use shrike::oauth::scopes::RpcPermission;
///
/// let perm: RpcPermission = "rpc:app.bsky.feed.getFeed?aud=*".parse().unwrap();
/// assert!(perm.matches("did:web:api.bsky.app#bsky_appview", "app.bsky.feed.getFeed"));
/// assert!(!perm.matches("did:web:api.bsky.app#bsky_appview", "app.bsky.feed.getTimeline"));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RpcPermission {
    aud: String,
    lxm: Vec<String>,
}

const FIELDS: &[Field] = &[
    Field {
        name: "lxm",
        multiple: true,
        required: true,
        validate: syntax::is_nsid_or_wildcard,
    },
    Field {
        name: "aud",
        multiple: false,
        required: true,
        validate: syntax::is_aud,
    },
];

impl RpcPermission {
    /// Builds a permission. Returns `None` when `lxm` is empty, a value is
    /// invalid, or both `aud` and `lxm` are wildcards.
    pub fn new<S: Into<String>>(
        aud: impl Into<String>,
        lxm: impl IntoIterator<Item = S>,
    ) -> Option<Self> {
        let aud = aud.into();
        let lxm: Vec<String> = lxm.into_iter().map(Into::into).collect();
        let valid = !lxm.is_empty()
            && syntax::is_aud(&aud)
            && lxm.iter().all(|l| syntax::is_nsid_or_wildcard(l))
            && !(aud == "*" && lxm.iter().any(|l| l == "*"));
        valid.then_some(RpcPermission { aud, lxm })
    }

    /// The service DID reference, or `*` for any service.
    pub fn aud(&self) -> &str {
        &self.aud
    }

    /// The method NSIDs (or `*` for any method), as written.
    pub fn lxm(&self) -> &[String] {
        &self.lxm
    }

    /// Whether this permission allows calling method `lxm` on service `aud`
    /// (e.g. `did:web:api.bsky.app#bsky_appview`). Both compare exactly.
    pub fn matches(&self, aud: &str, lxm: &str) -> bool {
        (self.aud == "*" || self.aud == aud) && self.lxm.iter().any(|l| l == "*" || l == lxm)
    }

    /// The scope that would allow calling method `lxm` on service `aud`.
    /// Neither is validated.
    pub fn scope_needed_for(aud: &str, lxm: &str) -> String {
        RpcPermission {
            aud: aud.to_string(),
            lxm: vec![lxm.to_string()],
        }
        .to_string()
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let mut values = syntax::parse(syntax, FIELDS, "lxm")?.into_iter();
        let lxm = values.next()?.many()?;
        let aud = values.next()?.one()?;
        // `rpc:*?aud=*` is forbidden.
        if aud == "*" && lxm.iter().any(|l| l == "*") {
            return None;
        }
        Some(RpcPermission { aud, lxm })
    }
}

impl FromStr for RpcPermission {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "rpc")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for RpcPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lxm = if self.lxm.len() > 1 && self.lxm.iter().any(|l| l == "*") {
            vec!["*".to_string()]
        } else {
            syntax::sorted_unique(&self.lxm)
        };
        let mut params = Vec::new();
        let positional = match lxm.as_slice() {
            [one] => Some(one.as_str()),
            many => {
                params.extend(many.iter().map(|l| ("lxm", l.as_str())));
                None
            }
        };
        params.push(("aud", self.aud.as_str()));
        f.write_str(&syntax::format("rpc", positional, &params))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn parse(scope: &str) -> Option<RpcPermission> {
        scope.parse().ok()
    }

    const SVC: &str = "did:web:example.com#service_id";

    // Vectors from the reference `rpc-permission.test.ts` and indigo's
    // permission scope fixtures.
    #[test]
    fn parses() {
        let p = parse("rpc:com.example.service?aud=did:web:example.com%23service_id").unwrap();
        assert_eq!(
            (p.aud(), p.lxm()),
            (SVC, &["com.example.service".to_string()][..])
        );
        assert_eq!(
            parse("rpc?lxm=com.example.method1&aud=*").unwrap(),
            RpcPermission::new("*", ["com.example.method1"]).unwrap()
        );
        assert_eq!(
            parse("rpc:com.example.method1?aud=*").unwrap(),
            RpcPermission::new("*", ["com.example.method1"]).unwrap()
        );
        let p = parse("rpc?aud=*&lxm=com.example.method1&lxm=com.example.method2").unwrap();
        assert_eq!(p.lxm(), ["com.example.method1", "com.example.method2"]);
        let p = parse("rpc?aud=did%3Aweb%3Aapi.example.com%23frag&lxm=com.example.query").unwrap();
        assert_eq!(p.aud(), "did:web:api.example.com#frag");
        assert!(parse("rpc:com.example.method1?aud=did:web:example.com#foo").is_some());
        assert!(parse("rpc:*?aud=did:web:example.com%23foo").is_some());
        assert!(parse("rpc?lxm=*&aud=did:web:api.example.com%23svc_appview").is_some());

        for invalid in [
            "rpc",
            "rpc:",
            "rpc:123",
            "rpc?aud=did:web:example.com%23service_id",
            "rpc:?aud=did:web:example.com%23service_id",
            "rpc?aud=did:web:example.com",
            "rpc?lxm=com.example.method1",
            "rpc:com.example.method1",
            "rpc:com.example.method1?aud=did:web:example.com&lxm=com.example.method2",
            "rpc:com.example.query?aud=api.example.com",
            "rpc?aud=*&lxm=*",
            "rpc:*?aud=*",
            "rpc?lxm=*&lxm=com.example.foo&aud=*",
            "rpc:com.example.service",
            "rpc:com.example.service?aud=invalid",
            "rpc:invalid",
            "rpc?lxm=invalid",
            "rpc:*",
            "rpc:*?lxm=*",
            "rpc:invalid?aud=did:web:example.com",
            "rpc:invalid?aud=did:web:example.com%23service_id",
            "rpc:foo.bar",
            "rpc:com.example.service?aud=did:web:example.com%23service_id&invalid=param",
            "rpc:foo.bar.baz?aud=did:web",
            "rpc:foo.bar.baz?aud=did:web%23service_id",
            "rpc:foo.bar.baz?aud=did:plc:111",
            "rpc:foo.bar.baz?aud=did:plc:111%23service_id",
            "rpc:foo.bar.baz?aud=did:foo:bar",
            "rpc:foo.bar.baz?aud=did:foo:bar%23service_id",
            "rpc:foo.bar.baz?aud=did:web:example.com%23service_id&lxm=foo.bar.baz",
            "rpc:foo.bar.baz?aud=invalid",
            "rpc:foo.bar.baz?aud=did:web:example.com%23a&aud=did:web:example.com%23b",
            "notrpc:com.example.service?aud=did:web:example.com%23service_id",
            "rpc?lxm=invalid&aud=invalid",
            "rpc?Lxm=com.example.method1&aud=*",
            "Rpc?lxm=com.example.method1&aud=*",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn matches() {
        let exact = parse("rpc:com.example.service?aud=did:web:example.com%23service_id").unwrap();
        assert!(exact.matches(SVC, "com.example.service"));
        assert!(!exact.matches(SVC, "com.example.OtherService"));
        assert!(!exact.matches("did:example:456#service_id", "com.example.service"));
        assert!(!exact.matches("did:web:example.com", "com.example.service"));

        assert!(
            parse("rpc:com.example.method1?aud=*")
                .unwrap()
                .matches(SVC, "com.example.method1")
        );
        let any_lxm = parse("rpc:*?aud=did:web:example.com%23service_id").unwrap();
        assert!(any_lxm.matches(SVC, "com.example.method1"));
        assert!(any_lxm.matches(SVC, "com.example.anyMethod"));
        assert!(!any_lxm.matches("did:web:example.com#other", "com.example.method1"));
    }

    #[test]
    fn scope_needed_for() {
        assert_eq!(
            RpcPermission::scope_needed_for(SVC, "com.example.service"),
            "rpc:com.example.service?aud=did:web:example.com%23service_id"
        );
        assert_eq!(
            RpcPermission::scope_needed_for("*", "com.example.method1"),
            "rpc:com.example.method1?aud=*"
        );
        assert_eq!(
            RpcPermission::scope_needed_for("did:web:a.com#b c", "x"),
            "rpc:x?aud=did:web:a.com%23b+c"
        );
    }

    #[test]
    fn formats() {
        let fmt = |aud: &str, lxm: &[&str]| {
            RpcPermission::new(aud, lxm.iter().copied())
                .unwrap()
                .to_string()
        };
        assert_eq!(
            fmt(SVC, &["com.example.service"]),
            "rpc:com.example.service?aud=did:web:example.com%23service_id"
        );
        assert_eq!(
            fmt("*", &["com.example.method1"]),
            "rpc:com.example.method1?aud=*"
        );
        assert_eq!(
            fmt(SVC, &["com.example.method2", "com.example.method1"]),
            "rpc?lxm=com.example.method1&lxm=com.example.method2&aud=did:web:example.com%23service_id"
        );
        assert_eq!(
            fmt(SVC, &["*"]),
            "rpc:*?aud=did:web:example.com%23service_id"
        );
        assert_eq!(
            fmt(SVC, &["*", "com.example.method1"]),
            "rpc:*?aud=did:web:example.com%23service_id"
        );
        assert!(RpcPermission::new("*", ["*"]).is_none());
        assert!(RpcPermission::new("*", Vec::<String>::new()).is_none());
        assert!(RpcPermission::new("did:web:example.com", ["a.b.c"]).is_none());

        for (input, expected) in [
            (
                "rpc:com.example.service?aud=did:web:example.com%23service_id",
                "rpc:com.example.service?aud=did:web:example.com%23service_id",
            ),
            (
                "rpc:com.example.service?aud=did:web:example.com#service_id",
                "rpc:com.example.service?aud=did:web:example.com%23service_id",
            ),
            (
                "rpc?lxm=com.example.method1&lxm=com.example.method2&aud=*",
                "rpc?lxm=com.example.method1&lxm=com.example.method2&aud=*",
            ),
            (
                "rpc?lxm=com.example.method1&lxm=com.example.method2&lxm=*&aud=did:web:example.com%23service_id",
                "rpc:*?aud=did:web:example.com%23service_id",
            ),
            (
                "rpc?aud=did:web:example.com%23foo&lxm=com.example.service",
                "rpc:com.example.service?aud=did:web:example.com%23foo",
            ),
            (
                "rpc?lxm=com.example.method1&aud=did:web:example.com#foo",
                "rpc:com.example.method1?aud=did:web:example.com%23foo",
            ),
            (
                "rpc:com.example.method1?&aud=*",
                "rpc:com.example.method1?aud=*",
            ),
            (
                "rpc:com.example.method1??aud=*",
                "rpc:com.example.method1?aud=*",
            ),
            (
                "rpc?aud=did%3Aweb%3Aapi.example.com%23frag&lxm=com.example.query&lxm=com.example.procedure",
                "rpc?lxm=com.example.procedure&lxm=com.example.query&aud=did:web:api.example.com%23frag",
            ),
        ] {
            assert_eq!(parse(input).unwrap().to_string(), expected, "{input}");
        }
    }

    #[test]
    fn localhost_aud_round_trips() {
        // Deliberate deviation: the reference renders the literal `%3A` as
        // `%3A`, which then decodes to `:` (a did:web path) and fails to parse.
        let p = parse("rpc:com.example.m?aud=did:web:localhost%253A3000%23svc").unwrap();
        assert_eq!(p.aud(), "did:web:localhost%3A3000#svc");
        let rendered = p.to_string();
        assert_eq!(
            rendered,
            "rpc:com.example.m?aud=did:web:localhost%253A3000%23svc"
        );
        assert_eq!(parse(&rendered).unwrap(), p);
    }
}
