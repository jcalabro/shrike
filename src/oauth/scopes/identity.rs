use std::fmt;
use std::str::FromStr;

use super::syntax::{self, Field, Syntax};
use super::{InvalidScope, define_str_enum};

define_str_enum! {
    /// An identity attribute controlled by an [`IdentityPermission`].
    IdentityAttr {
        /// The account's handle.
        Handle => "handle",
        /// Full control of the DID document (and handle).
        Any => "*",
    }
}

/// An `identity:` permission: control of the account's DID document and
/// handle.
///
/// ```
/// use shrike::oauth::scopes::{IdentityAttr, IdentityPermission};
///
/// let perm: IdentityPermission = "identity:handle".parse().unwrap();
/// assert!(perm.matches(IdentityAttr::Handle));
/// assert!(!perm.matches(IdentityAttr::Any));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IdentityPermission {
    attr: IdentityAttr,
}

const FIELDS: &[Field] = &[Field {
    name: "attr",
    multiple: false,
    required: true,
    validate: |v| IdentityAttr::from_name(v).is_some(),
}];

impl IdentityPermission {
    /// Builds a permission.
    pub fn new(attr: IdentityAttr) -> Self {
        IdentityPermission { attr }
    }

    /// The attribute this permission controls.
    pub fn attr(&self) -> IdentityAttr {
        self.attr
    }

    /// Whether this permission allows control of `attr`.
    pub fn matches(&self, attr: IdentityAttr) -> bool {
        self.attr == IdentityAttr::Any || self.attr == attr
    }

    /// The scope that would allow control of `attr`.
    pub fn scope_needed_for(attr: IdentityAttr) -> String {
        IdentityPermission { attr }.to_string()
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let attr = syntax::parse(syntax, FIELDS, "attr")?.pop()?.one()?;
        Some(IdentityPermission {
            attr: IdentityAttr::from_name(&attr)?,
        })
    }
}

impl FromStr for IdentityPermission {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "identity")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for IdentityPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&syntax::format("identity", Some(self.attr.as_str()), &[]))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::IdentityAttr::*;
    use super::*;

    fn parse(scope: &str) -> Option<IdentityPermission> {
        scope.parse().ok()
    }

    // Vectors from the reference `identity-permission.test.ts`.
    #[test]
    fn parses() {
        assert_eq!(parse("identity:handle").unwrap().attr(), Handle);
        assert_eq!(parse("identity:*").unwrap().attr(), Any);
        assert_eq!(parse("identity:*?").unwrap().attr(), Any);
        assert_eq!(parse("identity?attr=handle").unwrap().attr(), Handle);
        for invalid in [
            "identity:*?action=*",
            "identity:*?action=manage",
            "identity:*?action=submit",
            "identity:*?attr=*",
            "invalid",
            "identity",
            "identity:",
            "identity:invalid",
            "identity:Handle",
            "Identity:handle",
            "identity:handle?action=invalid",
            "identity?attribute=invalid&action=invalid",
            "identity?attr=handle&attr=*",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn matches_and_formats() {
        let handle = parse("identity:handle").unwrap();
        assert!(handle.matches(Handle));
        assert!(!handle.matches(Any));
        let any = parse("identity:*").unwrap();
        assert!(any.matches(Handle));
        assert!(any.matches(Any));

        assert_eq!(
            IdentityPermission::new(Handle).to_string(),
            "identity:handle"
        );
        assert_eq!(IdentityPermission::new(Any).to_string(), "identity:*");
        assert_eq!(
            IdentityPermission::scope_needed_for(Handle),
            "identity:handle"
        );
        assert_eq!(IdentityPermission::scope_needed_for(Any), "identity:*");
        assert_eq!(parse("identity?attr=*").unwrap().to_string(), "identity:*");
    }
}
