//! AT Protocol OAuth scopes: parsing permission scopes and checking what a
//! granted scope allows.
//!
//! An atproto OAuth scope is a space-separated list of values: the static
//! `atproto` and `transition:*` scopes, and permissions written as
//! `resource[:positional][?param=value&...]`:
//!
//! | Resource | Example | Allows |
//! |----------|---------|--------|
//! | `repo` | `repo:app.bsky.feed.post?action=create` | Writing records in collections |
//! | `rpc` | `rpc:app.bsky.feed.getFeed?aud=did:web:api.bsky.app%23bsky_appview` | Authenticated requests to a service |
//! | `blob` | `blob:image/*` | Uploading blobs by MIME type |
//! | `account` | `account:email?action=manage` | Account hosting details |
//! | `identity` | `identity:handle` | The DID document and handle |
//! | `include` | `include:app.bsky.authFullApp` | The permissions of a lexicon permission set |
//!
//! [`ScopePermissions`] answers whether a granted scope allows an operation,
//! and [`ScopeMissingError`] names the scope that would. Authorization servers
//! resolve `include:` scopes to [`PermissionSet`]s and expand them with
//! [`IncludeScope::to_scopes`] or [`expand_include_scopes`].
//!
//! ```
//! use shrike::oauth::scopes::{RepoAction, ScopePermissions};
//!
//! let perms = ScopePermissions::new("atproto repo:app.bsky.feed.post?action=create blob:image/*");
//! assert!(perms.allows_repo("app.bsky.feed.post", RepoAction::Create));
//! assert!(perms.allows_blob("image/png"));
//!
//! let err = perms.assert_repo("app.bsky.feed.like", RepoAction::Create).unwrap_err();
//! assert_eq!(err.scope(), "repo:app.bsky.feed.like?action=create");
//! ```
//!
//! This follows the reference TypeScript `@atproto/oauth-scopes`: permissions
//! that are invalid, or that this version does not understand, are ignored
//! rather than rejected, and parsing is strict and case-sensitive. It differs
//! only where the reference is unsound: a value with a malformed
//! percent-escape is invalid (the reference throws), and rendering escapes a
//! literal `%` (or `+` in the query) that the reference leaves bare, so every
//! rendered scope parses back to the same permission.

mod account;
mod blob;
mod identity;
mod include;
mod permissions;
mod repo;
mod rpc;
mod syntax;

use std::fmt;
use std::str::FromStr;

pub use account::{AccountAction, AccountAttr, AccountPermission};
pub use blob::BlobPermission;
pub use identity::{IdentityAttr, IdentityPermission};
pub use include::{IncludeScope, IncludedPermission, LexPermission, PermissionSet};
pub use permissions::ScopePermissions;
pub use repo::{RepoAction, RepoPermission};
pub use rpc::RpcPermission;

/// Defines a fieldless enum with string names, `ALL`, `as_str`, `FromStr` and
/// `Display`.
macro_rules! define_str_enum {
    ($(#[$meta:meta])* $name:ident { $($(#[$vmeta:meta])* $variant:ident => $str:literal,)+ }) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$vmeta])* $variant,)+
        }

        impl $name {
            /// Every value, in canonical order.
            pub const ALL: [$name; [$($str),+].len()] = [$($name::$variant),+];

            /// The name used in scope strings.
            pub fn as_str(self) -> &'static str {
                match self {
                    $($name::$variant => $str,)+
                }
            }

            pub(crate) fn from_name(name: &str) -> Option<Self> {
                match name {
                    $($str => Some($name::$variant),)+
                    _ => None,
                }
            }
        }

        impl std::str::FromStr for $name {
            type Err = $crate::oauth::scopes::InvalidScope;

            fn from_str(s: &str) -> Result<Self, Self::Err> {
                Self::from_name(s).ok_or_else(|| $crate::oauth::scopes::InvalidScope::new(s))
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str(self.as_str())
            }
        }
    };
}
pub(crate) use define_str_enum;

/// A scope value that is not a valid (or not a supported) atproto scope.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid OAuth scope {0:?}")]
pub struct InvalidScope(String);

impl InvalidScope {
    pub(crate) fn new(scope: &str) -> Self {
        InvalidScope(scope.to_string())
    }

    /// The rejected value.
    pub fn scope(&self) -> &str {
        &self.0
    }
}

/// A request is not allowed by the granted scopes. Carries the scope that
/// would allow it. Servers respond with HTTP 403 and error name
/// `ScopeMissingError`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("Missing required scope \"{0}\"")]
pub struct ScopeMissingError(String);

impl ScopeMissingError {
    /// Creates an error for the missing `scope`.
    pub fn new(scope: impl Into<String>) -> Self {
        ScopeMissingError(scope.into())
    }

    /// The scope that would allow the request.
    pub fn scope(&self) -> &str {
        &self.0
    }
}

/// No permission set was found for an `include:` scope's NSID.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("missing permission set for NSID {0}")]
pub struct MissingPermissionSet(String);

impl MissingPermissionSet {
    /// The permission set's NSID.
    pub fn nsid(&self) -> &str {
        &self.0
    }
}

/// One value of an atproto OAuth scope.
///
/// Parsing accepts only values this version can fully interpret; `Display`
/// renders the normalized form.
///
/// ```
/// use shrike::oauth::scopes::AtprotoScope;
///
/// let scope: AtprotoScope = "repo?collection=*&action=create".parse().unwrap();
/// assert_eq!(scope.to_string(), "repo:*?action=create");
/// assert!("repo:not-an-nsid".parse::<AtprotoScope>().is_err());
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AtprotoScope {
    /// `atproto`, required in every atproto OAuth scope.
    Atproto,
    /// `transition:generic`: the access of a legacy app password.
    TransitionGeneric,
    /// `transition:email`: reading the account email.
    TransitionEmail,
    /// `transition:chat.bsky`: the `chat.bsky.*` methods.
    TransitionChatBsky,
    Account(AccountPermission),
    Blob(BlobPermission),
    Identity(IdentityPermission),
    Include(IncludeScope),
    Repo(RepoPermission),
    Rpc(RpcPermission),
}

impl FromStr for AtprotoScope {
    type Err = InvalidScope;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let invalid = || InvalidScope::new(value);
        Ok(match value {
            "atproto" => AtprotoScope::Atproto,
            "transition:generic" => AtprotoScope::TransitionGeneric,
            "transition:email" => AtprotoScope::TransitionEmail,
            "transition:chat.bsky" => AtprotoScope::TransitionChatBsky,
            _ => {
                let resource = value.split([':', '?']).next().unwrap_or_default();
                let syntax = syntax::Syntax::from_scope(value, resource).ok_or_else(invalid)?;
                match resource {
                    "account" => AccountPermission::from_syntax(&syntax).map(AtprotoScope::Account),
                    "blob" => BlobPermission::from_syntax(&syntax).map(AtprotoScope::Blob),
                    "identity" => {
                        IdentityPermission::from_syntax(&syntax).map(AtprotoScope::Identity)
                    }
                    "include" => IncludeScope::from_syntax(&syntax).map(AtprotoScope::Include),
                    "repo" => RepoPermission::from_syntax(&syntax).map(AtprotoScope::Repo),
                    "rpc" => RpcPermission::from_syntax(&syntax).map(AtprotoScope::Rpc),
                    _ => None,
                }
                .ok_or_else(invalid)?
            }
        })
    }
}

impl fmt::Display for AtprotoScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AtprotoScope::Atproto => f.write_str("atproto"),
            AtprotoScope::TransitionGeneric => f.write_str("transition:generic"),
            AtprotoScope::TransitionEmail => f.write_str("transition:email"),
            AtprotoScope::TransitionChatBsky => f.write_str("transition:chat.bsky"),
            AtprotoScope::Account(p) => p.fmt(f),
            AtprotoScope::Blob(p) => p.fmt(f),
            AtprotoScope::Identity(p) => p.fmt(f),
            AtprotoScope::Include(p) => p.fmt(f),
            AtprotoScope::Repo(p) => p.fmt(f),
            AtprotoScope::Rpc(p) => p.fmt(f),
        }
    }
}

/// Whether `value` is a single atproto scope value this version can fully
/// interpret.
pub fn is_atproto_oauth_scope(value: &str) -> bool {
    value.parse::<AtprotoScope>().is_ok()
}

/// Normalizes a space-separated scope: drops values that are not valid
/// atproto scopes, normalizes the rest, and sorts them. Duplicates are kept.
pub fn normalize_atproto_oauth_scope(scope: &str) -> String {
    let mut values: Vec<String> = scope
        .split(' ')
        .filter_map(|v| v.parse::<AtprotoScope>().ok())
        .map(|v| v.to_string())
        .collect();
    values.sort_by(|a, b| syntax::js_cmp(a, b));
    values.join(" ")
}

/// Rewrites a requested scope, replacing each `include:` value with the
/// permissions its set grants, followed by the other values unchanged.
///
/// `resolve` looks up the permission set for an NSID, and is called once per
/// distinct NSID; every one must resolve. A scope without `include:` values is
/// returned as-is.
pub fn expand_include_scopes<'a>(
    scope: &str,
    mut resolve: impl FnMut(&str) -> Option<&'a PermissionSet>,
) -> Result<String, MissingPermissionSet> {
    let mut includes = Vec::new();
    let mut others = Vec::new();
    for value in scope.split(' ') {
        match value.parse::<IncludeScope>() {
            Ok(include) => includes.push(include),
            Err(_) => others.push(value),
        }
    }
    if includes.is_empty() {
        return Ok(scope.to_string());
    }

    let mut sets: Vec<(&str, &PermissionSet)> = Vec::new();
    for include in &includes {
        if !sets.iter().any(|(nsid, _)| *nsid == include.nsid()) {
            let set = resolve(include.nsid())
                .ok_or_else(|| MissingPermissionSet(include.nsid().to_string()))?;
            sets.push((include.nsid(), set));
        }
    }

    let mut expanded = Vec::new();
    for include in &includes {
        if let Some((_, set)) = sets.iter().find(|(nsid, _)| *nsid == include.nsid()) {
            expanded.extend(include.to_scopes(set));
        }
    }
    expanded.extend(others.into_iter().map(str::to_string));
    Ok(expanded.join(" "))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn parses_every_kind_of_scope() {
        for (input, normalized) in [
            ("atproto", "atproto"),
            ("transition:generic", "transition:generic"),
            ("transition:email", "transition:email"),
            ("transition:chat.bsky", "transition:chat.bsky"),
            (
                "account?attr=email&action=manage",
                "account:email?action=manage",
            ),
            ("blob?accept=image%2Fpng", "blob:image/png"),
            ("identity:*?", "identity:*"),
            ("include?nsid=com.example.foo", "include:com.example.foo"),
            ("repo?collection=*", "repo:*"),
            ("rpc?lxm=com.example.foo&aud=*", "rpc:com.example.foo?aud=*"),
        ] {
            assert!(is_atproto_oauth_scope(input), "{input}");
            assert_eq!(
                input.parse::<AtprotoScope>().unwrap().to_string(),
                normalized
            );
        }
        for invalid in [
            "",
            " ",
            "openid",
            "transition:other",
            "transition",
            "Atproto",
            "atproto ",
            "atproto?",
            "atproto:x",
            "unknown:foo",
            "repo",
            "rpc:a.b.c",
            "repo:%E0%A4%A",
            "account:status?action=destroy",
        ] {
            assert!(!is_atproto_oauth_scope(invalid), "{invalid:?}");
            assert_eq!(
                invalid.parse::<AtprotoScope>().unwrap_err().scope(),
                invalid
            );
        }
    }

    #[test]
    fn normalizes_scopes() {
        assert_eq!(
            normalize_atproto_oauth_scope("rpc:a.b.c?aud=* atproto  atproto repo:* openid repo:%"),
            "atproto atproto repo:* rpc:a.b.c?aud=*"
        );
        assert_eq!(normalize_atproto_oauth_scope(""), "");
        assert_eq!(normalize_atproto_oauth_scope("bogus"), "");
    }

    #[test]
    fn str_enums() {
        assert_eq!(
            RepoAction::ALL,
            [RepoAction::Create, RepoAction::Update, RepoAction::Delete]
        );
        assert_eq!("delete".parse::<RepoAction>().unwrap(), RepoAction::Delete);
        assert!("Delete".parse::<RepoAction>().is_err());
        assert_eq!(IdentityAttr::Any.to_string(), "*");
        assert_eq!(AccountAttr::ALL.len(), 3);
    }

    #[test]
    fn errors() {
        let err = ScopeMissingError::new("repo:*");
        assert_eq!(err.to_string(), "Missing required scope \"repo:*\"");
        assert_eq!(err.scope(), "repo:*");
        assert_eq!(
            InvalidScope::new("x").to_string(),
            "invalid OAuth scope \"x\""
        );
    }

    #[test]
    fn expands_include_scopes() {
        let set: PermissionSet = serde_json::from_value(serde_json::json!({
            "type": "permission-set",
            "permissions": [
                { "type": "permission", "resource": "repo", "collection": ["com.example.cal.event"] },
                { "type": "permission", "resource": "rpc", "inheritAud": true, "lxm": ["com.example.cal.list"] },
            ],
        }))
        .unwrap();
        let mut calls = Vec::new();
        let expanded = expand_include_scopes(
            "atproto include:com.example.cal.auth?aud=did:web:x.com%23s blob:*/* include:com.example.cal.auth",
            |nsid| {
                calls.push(nsid.to_string());
                (nsid == "com.example.cal.auth").then_some(&set)
            },
        )
        .unwrap();
        assert_eq!(
            expanded,
            "repo:com.example.cal.event rpc:com.example.cal.list?aud=did:web:x.com%23s \
             repo:com.example.cal.event atproto blob:*/*"
        );
        assert_eq!(calls, ["com.example.cal.auth"]);

        assert_eq!(
            expand_include_scopes("atproto  repo:*", |_| None).unwrap(),
            "atproto  repo:*"
        );
        assert_eq!(
            expand_include_scopes("atproto include:com.example.cal.missing", |_| None)
                .unwrap_err()
                .nsid(),
            "com.example.cal.missing"
        );
        // Invalid include values are kept, like any other unrecognized value.
        assert_eq!(
            expand_include_scopes("include:nsid include:com.example.cal.auth", |_| Some(&set))
                .unwrap(),
            "repo:com.example.cal.event include:nsid"
        );
    }
}
