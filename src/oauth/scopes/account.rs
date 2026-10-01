use std::fmt;
use std::str::FromStr;

use super::syntax::{self, Field, Syntax};
use super::{InvalidScope, define_str_enum};

define_str_enum! {
    /// An account attribute controlled by an [`AccountPermission`].
    AccountAttr {
        Email => "email",
        Repo => "repo",
        Status => "status",
    }
}

define_str_enum! {
    /// An [`AccountPermission`] action. `Manage` implies `Read`.
    AccountAction {
        Read => "read",
        Manage => "manage",
    }
}

/// An `account:` permission: access to hosting details of the account, such as
/// its email or status.
///
/// ```
/// use shrike::oauth::scopes::{AccountAction, AccountAttr, AccountPermission};
///
/// let perm: AccountPermission = "account:email?action=manage".parse().unwrap();
/// assert!(perm.matches(AccountAttr::Email, AccountAction::Read));
/// assert!(!perm.matches(AccountAttr::Status, AccountAction::Read));
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AccountPermission {
    attr: AccountAttr,
    action: Vec<AccountAction>,
}

const FIELDS: &[Field] = &[
    Field {
        name: "attr",
        multiple: false,
        required: true,
        validate: |v| AccountAttr::from_name(v).is_some(),
    },
    Field {
        name: "action",
        multiple: true,
        required: false,
        validate: |v| AccountAction::from_name(v).is_some(),
    },
];

impl AccountPermission {
    /// Builds a permission. Returns `None` when `action` is empty.
    pub fn new(attr: AccountAttr, action: impl IntoIterator<Item = AccountAction>) -> Option<Self> {
        let action: Vec<_> = action.into_iter().collect();
        (!action.is_empty()).then_some(AccountPermission { attr, action })
    }

    /// The attribute this permission controls.
    pub fn attr(&self) -> AccountAttr {
        self.attr
    }

    /// The permitted actions (`read` when unspecified).
    pub fn action(&self) -> &[AccountAction] {
        &self.action
    }

    /// Whether this permission allows `action` on `attr`.
    pub fn matches(&self, attr: AccountAttr, action: AccountAction) -> bool {
        self.attr == attr
            && (self.action.contains(&AccountAction::Manage) || self.action.contains(&action))
    }

    /// The scope that would allow `action` on `attr`.
    pub fn scope_needed_for(attr: AccountAttr, action: AccountAction) -> String {
        AccountPermission {
            attr,
            action: vec![action],
        }
        .to_string()
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let mut values = syntax::parse(syntax, FIELDS, "attr")?.into_iter();
        let attr = AccountAttr::from_name(&values.next()?.one()?)?;
        let action = match values.next()? {
            syntax::Parsed::Absent => vec![AccountAction::Read],
            parsed => parsed
                .many()?
                .iter()
                .map(|v| AccountAction::from_name(v))
                .collect::<Option<_>>()?,
        };
        Some(AccountPermission { attr, action })
    }
}

impl FromStr for AccountPermission {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "account")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for AccountPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut params = Vec::new();
        if !syntax::same_values(&self.action, &[AccountAction::Read]) {
            for action in syntax::unique(&self.action) {
                params.push(("action", action.as_str()));
            }
        }
        f.write_str(&syntax::format(
            "account",
            Some(self.attr.as_str()),
            &params,
        ))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::AccountAction::*;
    use super::AccountAttr::*;
    use super::*;

    fn parse(scope: &str) -> Option<AccountPermission> {
        scope.parse().ok()
    }

    // Vectors from the reference `account-permission.test.ts`.
    #[test]
    fn parses() {
        let p = parse("account:email?action=read").unwrap();
        assert_eq!((p.attr(), p.action()), (Email, &[Read][..]));
        let p = parse("account:repo?action=manage").unwrap();
        assert_eq!((p.attr(), p.action()), (Repo, &[Manage][..]));
        let p = parse("account:status").unwrap();
        assert_eq!((p.attr(), p.action()), (Status, &[Read][..]));
        let p = parse("account?attr=email&action=manage").unwrap();
        assert_eq!((p.attr(), p.action()), (Email, &[Manage][..]));

        for invalid in [
            "account:invalid",
            "account:email?action=invalid",
            "invalid:email",
            "account",
            "",
            "account:",
            "account:Email",
            "Account:email",
            "account:email?action=Read",
            "account:email?attr=email",
            "account?attr=email&attr=repo",
            "account:email?extra=1",
            "accounts:email",
        ] {
            assert!(parse(invalid).is_none(), "{invalid}");
        }
    }

    #[test]
    fn scope_needed_for() {
        assert_eq!(
            AccountPermission::scope_needed_for(Email, Read),
            "account:email"
        );
        assert_eq!(
            AccountPermission::scope_needed_for(Repo, Read),
            "account:repo"
        );
        assert_eq!(
            AccountPermission::scope_needed_for(Status, Read),
            "account:status"
        );
        assert_eq!(
            AccountPermission::scope_needed_for(Email, Manage),
            "account:email?action=manage"
        );
        assert_eq!(
            AccountPermission::scope_needed_for(Repo, Manage),
            "account:repo?action=manage"
        );
        assert_eq!(
            AccountPermission::scope_needed_for(Status, Manage),
            "account:status?action=manage"
        );
    }

    #[test]
    fn matches() {
        let read = parse("account:email?action=read").unwrap();
        assert!(read.matches(Email, Read));
        assert!(!read.matches(Email, Manage));
        assert!(!read.matches(Repo, Read));

        let manage = parse("account:repo?action=manage").unwrap();
        assert!(manage.matches(Repo, Manage));
        assert!(manage.matches(Repo, Read));
        assert!(!manage.matches(Email, Read));

        let default = parse("account:email").unwrap();
        assert!(default.matches(Email, Read));
        assert!(!default.matches(Email, Manage));

        assert!(
            parse("account:status?action=read")
                .unwrap()
                .matches(Status, Read)
        );
        assert!(
            parse("account:email?action=manage")
                .unwrap()
                .matches(Email, Read)
        );
    }

    #[test]
    fn formats() {
        let fmt = |attr, action: &[AccountAction]| {
            AccountPermission::new(attr, action.iter().copied())
                .unwrap()
                .to_string()
        };
        assert_eq!(fmt(Email, &[Manage]), "account:email?action=manage");
        assert_eq!(fmt(Repo, &[Read]), "account:repo");
        assert_eq!(fmt(Status, &[Read]), "account:status");
        assert_eq!(fmt(Email, &[Read, Read]), "account:email");
        assert_eq!(
            fmt(Email, &[Manage, Read, Manage]),
            "account:email?action=manage&action=read"
        );
        assert!(AccountPermission::new(Email, []).is_none());

        for scope in [
            "account:email",
            "account:email?action=manage",
            "account:repo",
            "account:repo?action=manage",
            "account:status",
            "account:status?action=manage",
        ] {
            assert_eq!(parse(scope).unwrap().to_string(), scope);
        }
        assert_eq!(
            parse("account?action=read&attr=repo").unwrap().to_string(),
            "account:repo"
        );
    }
}
