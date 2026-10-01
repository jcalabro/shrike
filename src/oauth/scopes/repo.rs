use std::fmt;
use std::str::FromStr;

use super::syntax::{self, Field, Syntax};
use super::{InvalidScope, define_str_enum};

define_str_enum! {
    /// A record write action controlled by a [`RepoPermission`].
    RepoAction {
        Create => "create",
        Update => "update",
        Delete => "delete",
    }
}

/// A `repo:` permission: writing records in some collections (`*` for any).
///
/// Collections are compared exactly as written, so matching is case-sensitive.
///
/// ```
/// use shrike::oauth::scopes::{RepoAction, RepoPermission};
///
/// let perm: RepoPermission = "repo:app.bsky.feed.post?action=create".parse().unwrap();
/// assert!(perm.matches("app.bsky.feed.post", RepoAction::Create));
/// assert!(!perm.matches("app.bsky.feed.post", RepoAction::Delete));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RepoPermission {
    collection: Vec<String>,
    action: Vec<RepoAction>,
}

const FIELDS: &[Field] = &[
    Field {
        name: "collection",
        multiple: true,
        required: true,
        validate: syntax::is_nsid_or_wildcard,
    },
    Field {
        name: "action",
        multiple: true,
        required: false,
        validate: |v| RepoAction::from_name(v).is_some(),
    },
];

impl RepoPermission {
    /// Builds a permission. Returns `None` when either list is empty or a
    /// collection is neither an NSID nor `*`.
    pub fn new<S: Into<String>>(
        collection: impl IntoIterator<Item = S>,
        action: impl IntoIterator<Item = RepoAction>,
    ) -> Option<Self> {
        let collection: Vec<String> = collection.into_iter().map(Into::into).collect();
        let action: Vec<RepoAction> = action.into_iter().collect();
        (!collection.is_empty()
            && !action.is_empty()
            && collection.iter().all(|c| syntax::is_nsid_or_wildcard(c)))
        .then_some(RepoPermission { collection, action })
    }

    /// The collections (NSIDs, or `*` for any), as written.
    pub fn collection(&self) -> &[String] {
        &self.collection
    }

    /// The permitted actions (all of them when unspecified).
    pub fn action(&self) -> &[RepoAction] {
        &self.action
    }

    /// Whether this permission allows `action` on records of `collection`.
    pub fn matches(&self, collection: &str, action: RepoAction) -> bool {
        self.action.contains(&action) && self.collection.iter().any(|c| c == "*" || c == collection)
    }

    /// The scope that would allow `action` on records of `collection`. The
    /// collection is not validated.
    pub fn scope_needed_for(collection: &str, action: RepoAction) -> String {
        RepoPermission {
            collection: vec![collection.to_string()],
            action: vec![action],
        }
        .to_string()
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let mut values = syntax::parse(syntax, FIELDS, "collection")?.into_iter();
        let collection = values.next()?.many()?;
        let action = match values.next()? {
            syntax::Parsed::Absent => RepoAction::ALL.to_vec(),
            parsed => parsed
                .many()?
                .iter()
                .map(|v| RepoAction::from_name(v))
                .collect::<Option<_>>()?,
        };
        Some(RepoPermission { collection, action })
    }
}

impl FromStr for RepoPermission {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "repo")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for RepoPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let collection = match self.collection.as_slice() {
            [_] => self.collection.clone(),
            many if many.iter().any(|c| c == "*") => vec!["*".to_string()],
            many => syntax::sorted_unique(many),
        };
        let action: Vec<RepoAction> = RepoAction::ALL
            .into_iter()
            .filter(|a| self.action.contains(a))
            .collect();

        let mut params = Vec::new();
        let positional = match collection.as_slice() {
            [one] => Some(one.as_str()),
            many => {
                params.extend(many.iter().map(|c| ("collection", c.as_str())));
                None
            }
        };
        if action != RepoAction::ALL {
            params.extend(action.iter().map(|a| ("action", a.as_str())));
        }
        f.write_str(&syntax::format("repo", positional, &params))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::RepoAction::*;
    use super::*;

    fn parse(scope: &str) -> Option<RepoPermission> {
        scope.parse().ok()
    }

    // Vectors from the reference `repo-permission.test.ts` and indigo's
    // permission scope fixtures.
    #[test]
    fn parses() {
        let p = parse("repo:com.example.foo").unwrap();
        assert_eq!(p.collection(), ["com.example.foo"]);
        assert_eq!(p.action(), [Create, Update, Delete]);
        let p = parse("repo:com.example.foo?action=create&action=update").unwrap();
        assert_eq!(p.action(), [Create, Update]);
        let p = parse("repo:*?action=create").unwrap();
        assert_eq!(
            (p.collection(), p.action()),
            (&["*".to_string()][..], &[Create][..])
        );
        let p = parse("repo?action=create&collection=com.example.foo&collection=com.example.bar")
            .unwrap();
        assert_eq!(p.collection(), ["com.example.foo", "com.example.bar"]);
        // NSIDs are kept as written.
        assert_eq!(
            parse("repo:COM.Example.Foo").unwrap().collection(),
            ["COM.Example.Foo"]
        );

        for invalid in [
            "repo:foo bar",
            "repo:.foo",
            "repo:bar.",
            "repo:123",
            "repo",
            "repo:",
            "repo:*?action=*",
            "invalid",
            "scope",
            "repo:invalid",
            "repo:com.example.foo?action=invalid",
            "repo?collection=invalid&action=invalid",
            "Repo:com.example.foo",
            "repo:*?Action=create",
            "repo:*?action=Create",
            "repo:com.example.foo?action",
            "repo:com.example.foo?collection=com.example.bar",
            "repo:not-a-valid-nsid",
            "repo:%",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn matches() {
        let wildcard = parse("repo:*?action=create").unwrap();
        assert!(wildcard.matches("any.collection.here", Create));
        assert!(wildcard.matches("com.example.bar", Create));
        assert!(!wildcard.matches("com.example.bar", Update));
        assert!(!wildcard.matches("com.example.bar", Delete));

        let all = parse("repo:*").unwrap();
        for action in RepoAction::ALL {
            assert!(all.matches("app.bsky.feed.post", action));
        }

        let foo = parse("repo:com.example.foo?action=create&action=update").unwrap();
        assert!(foo.matches("com.example.foo", Create));
        assert!(foo.matches("com.example.foo", Update));
        assert!(!foo.matches("com.example.foo", Delete));
        assert!(!foo.matches("com.example.bar", Create));
        assert!(!foo.matches("COM.example.foo", Create));

        let default = parse("repo:com.example.foo").unwrap();
        for action in RepoAction::ALL {
            assert!(default.matches("com.example.foo", action));
        }
    }

    #[test]
    fn scope_needed_for() {
        assert_eq!(
            RepoPermission::scope_needed_for("com.example.foo", Create),
            "repo:com.example.foo?action=create"
        );
        assert_eq!(
            RepoPermission::scope_needed_for("*", Create),
            "repo:*?action=create"
        );
        // Not validated, like the reference.
        assert_eq!(
            RepoPermission::scope_needed_for("invalid", Create),
            "repo:invalid?action=create"
        );
        assert_eq!(
            RepoPermission::scope_needed_for("a b", Delete),
            "repo:a%20b?action=delete"
        );
    }

    #[test]
    fn formats() {
        let p = RepoPermission::new(["com.example.foo"], [Create, Update]).unwrap();
        assert_eq!(
            p.to_string(),
            "repo:com.example.foo?action=create&action=update"
        );
        let p = RepoPermission::new(["com.example.foo"], [Delete, Create, Delete]).unwrap();
        assert_eq!(
            p.to_string(),
            "repo:com.example.foo?action=create&action=delete"
        );
        assert!(RepoPermission::new(["com.example.foo"], []).is_none());
        assert!(RepoPermission::new(Vec::<String>::new(), [Create]).is_none());
        assert!(RepoPermission::new(["invalid"], [Create]).is_none());

        for (input, expected) in [
            ("repo:com.example.foo", "repo:com.example.foo"),
            (
                "repo:com.example.foo?action=create",
                "repo:com.example.foo?action=create",
            ),
            (
                "repo:com.example.foo?action=create&action=update",
                "repo:com.example.foo?action=create&action=update",
            ),
            ("repo:*?action=create&action=update&action=delete", "repo:*"),
            (
                "repo:com.example.foo?action=create&action=update&action=delete",
                "repo:com.example.foo",
            ),
            ("repo:*?action=create", "repo:*?action=create"),
            ("repo:*?action=update", "repo:*?action=update"),
            ("repo?collection=*&action=update", "repo:*?action=update"),
            (
                "repo?collection=*&collection=com.example.foo&action=update",
                "repo:*?action=update",
            ),
            ("repo?collection=*", "repo:*"),
            (
                "repo?collection=*&action=create&action=update&action=delete",
                "repo:*",
            ),
            ("repo?collection=*&collection=com.example.foo", "repo:*"),
            (
                "repo?action=create&collection=com.example.foo",
                "repo:com.example.foo?action=create",
            ),
            (
                "repo?collection=com.example.foo&action=create&action=update&action=delete",
                "repo:com.example.foo",
            ),
            (
                "repo?action=create&collection=com.example.foo&collection=com.example.bar",
                "repo?collection=com.example.bar&collection=com.example.foo&action=create",
            ),
            (
                "repo?collection=com.example.foo&collection=com.example.foo",
                "repo:com.example.foo",
            ),
            (
                "repo:*?action=delete&action=create&action=delete",
                "repo:*?action=create&action=delete",
            ),
            ("repo:com.example.foo?", "repo:com.example.foo"),
            ("repo:com.example.foo?&&", "repo:com.example.foo"),
        ] {
            assert_eq!(parse(input).unwrap().to_string(), expected, "{input}");
        }
    }
}
