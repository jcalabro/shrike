use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};

use super::syntax::{self, Field, Param, Syntax};
use super::{InvalidScope, RepoPermission, RpcPermission};

/// An `include:` scope: a request for the permissions of a lexicon
/// [`PermissionSet`], optionally with a service `aud` that the set's `rpc`
/// permissions may inherit.
///
/// An authorization server resolves the set and replaces this scope with the
/// permissions it grants ([`IncludeScope::to_scopes`]); granted tokens carry
/// those, never `include:` itself.
///
/// ```
/// use shrike::oauth::scopes::{IncludeScope, PermissionSet};
///
/// let set: PermissionSet = serde_json::from_value(serde_json::json!({
///     "type": "permission-set",
///     "permissions": [
///         { "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"] },
///         { "type": "permission", "resource": "rpc", "inheritAud": true, "lxm": ["com.example.calendar.listEvents"] },
///         { "type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"] },
///     ],
/// })).unwrap();
///
/// let include: IncludeScope = "include:com.example.calendar.auth?aud=did:web:example.com%23cal"
///     .parse()
///     .unwrap();
/// assert_eq!(include.to_scopes(&set), [
///     "repo:com.example.calendar.event",
///     "rpc:com.example.calendar.listEvents?aud=did:web:example.com%23cal",
///     // `app.bsky.feed.post` is outside the set's namespace, so it is dropped.
/// ]);
/// ```
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct IncludeScope {
    nsid: String,
    aud: Option<String>,
}

const FIELDS: &[Field] = &[
    Field {
        name: "nsid",
        multiple: false,
        required: true,
        validate: syntax::is_nsid,
    },
    Field {
        name: "aud",
        multiple: false,
        required: false,
        validate: syntax::is_atproto_did_ref,
    },
];

/// A permission that a [`PermissionSet`] may grant.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum IncludedPermission {
    Repo(RepoPermission),
    Rpc(RpcPermission),
}

impl fmt::Display for IncludedPermission {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            IncludedPermission::Repo(p) => p.fmt(f),
            IncludedPermission::Rpc(p) => p.fmt(f),
        }
    }
}

impl IncludeScope {
    /// Builds an include scope. Returns `None` when `nsid` is not an NSID or
    /// `aud` is not a DID reference with a fragment.
    pub fn new(nsid: impl Into<String>, aud: Option<String>) -> Option<Self> {
        let nsid = nsid.into();
        (syntax::is_nsid(&nsid) && aud.as_deref().is_none_or(syntax::is_atproto_did_ref))
            .then_some(IncludeScope { nsid, aud })
    }

    /// The permission set's NSID, as written.
    pub fn nsid(&self) -> &str {
        &self.nsid
    }

    /// The service that the set's `inheritAud` RPC permissions apply to.
    pub fn aud(&self) -> Option<&str> {
        self.aud.as_deref()
    }

    /// The permissions this scope grants, given the resolved permission set
    /// for [`nsid`](Self::nsid).
    ///
    /// Only `repo` and `rpc` permissions within the set's namespace are
    /// granted. Permissions that are invalid, for other resources, or outside
    /// the namespace are skipped, as are `rpc` permissions naming a specific
    /// `aud` (they may only use `*` or `inheritAud`).
    pub fn to_permissions(&self, set: &PermissionSet) -> Vec<IncludedPermission> {
        set.permissions
            .iter()
            .filter_map(|p| self.included(p))
            .collect()
    }

    /// Like [`to_permissions`](Self::to_permissions), rendered as scopes.
    pub fn to_scopes(&self, set: &PermissionSet) -> Vec<String> {
        self.to_permissions(set)
            .iter()
            .map(ToString::to_string)
            .collect()
    }

    /// Whether `nsid` is under this set's namespace: it must share the set
    /// NSID's group (everything before its last segment). `*` never is.
    pub fn is_parent_authority_of(&self, nsid: &str) -> bool {
        let Some(group_end) = self.nsid.rfind('.') else {
            return false;
        };
        nsid != "*"
            && nsid.len() > group_end + 1
            && nsid.as_bytes()[..=group_end] == self.nsid.as_bytes()[..=group_end]
    }

    fn included(&self, permission: &LexPermission) -> Option<IncludedPermission> {
        let mut syntax = Syntax::from_lexicon(&permission.params);
        let included = match permission.resource.as_str() {
            "repo" => IncludedPermission::Repo(RepoPermission::from_syntax(&syntax)?),
            "rpc" => {
                let aud = permission.params.get("aud");
                if aud.is_some_and(|aud| aud != "*") {
                    return None;
                }
                if let (None, Some(Value::Bool(true)), Some(inherited)) =
                    (aud, permission.params.get("inheritAud"), &self.aud)
                {
                    syntax.remove("inheritAud");
                    syntax.set("aud", Param::Str(inherited.clone()));
                }
                IncludedPermission::Rpc(RpcPermission::from_syntax(&syntax)?)
            }
            _ => return None,
        };

        let allowed = match &included {
            IncludedPermission::Repo(p) => p
                .collection()
                .iter()
                .all(|c| self.is_parent_authority_of(c)),
            IncludedPermission::Rpc(p) => p.lxm().iter().all(|l| self.is_parent_authority_of(l)),
        };
        allowed.then_some(included)
    }

    pub(crate) fn from_syntax(syntax: &Syntax) -> Option<Self> {
        let mut values = syntax::parse(syntax, FIELDS, "nsid")?.into_iter();
        let nsid = values.next()?.one()?;
        let aud = match values.next()? {
            syntax::Parsed::Absent => None,
            parsed => Some(parsed.one()?),
        };
        Some(IncludeScope { nsid, aud })
    }
}

impl FromStr for IncludeScope {
    type Err = InvalidScope;

    fn from_str(scope: &str) -> Result<Self, Self::Err> {
        Syntax::from_scope(scope, "include")
            .and_then(|s| Self::from_syntax(&s))
            .ok_or_else(|| InvalidScope::new(scope))
    }
}

impl fmt::Display for IncludeScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let params: Vec<_> = self.aud.iter().map(|aud| ("aud", aud.as_str())).collect();
        f.write_str(&syntax::format("include", Some(&self.nsid), &params))
    }
}

/// A lexicon `permission-set` definition: the `defs.main` of the lexicon
/// named by an `include:` scope.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PermissionSet {
    #[serde(rename = "type")]
    kind: PermissionSetType,
    pub permissions: Vec<LexPermission>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(
        default,
        rename = "title:lang",
        skip_serializing_if = "Option::is_none"
    )]
    pub title_lang: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    #[serde(
        default,
        rename = "detail:lang",
        skip_serializing_if = "Option::is_none"
    )]
    pub detail_lang: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
enum PermissionSetType {
    #[serde(rename = "permission-set")]
    PermissionSet,
}

impl PermissionSet {
    /// A permission set without a title or description.
    pub fn new(permissions: Vec<LexPermission>) -> Self {
        PermissionSet {
            kind: PermissionSetType::PermissionSet,
            permissions,
            title: None,
            title_lang: None,
            detail: None,
            detail_lang: None,
            description: None,
        }
    }

    /// Extracts the permission set from a lexicon document, or `None` when its
    /// main definition is not a permission set.
    pub fn from_lexicon_document(doc: &Value) -> Option<Self> {
        serde_json::from_value(doc.get("defs")?.get("main")?.clone()).ok()
    }
}

/// One permission of a [`PermissionSet`]: a resource and its parameters,
/// kept as written so that unknown or invalid permissions can be skipped
/// rather than rejecting the whole set.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "Map<String, Value>", into = "Map<String, Value>")]
pub struct LexPermission {
    pub resource: String,
    /// Every other field except `type`.
    pub params: Map<String, Value>,
}

impl TryFrom<Map<String, Value>> for LexPermission {
    type Error = String;

    fn try_from(mut params: Map<String, Value>) -> Result<Self, Self::Error> {
        if params.remove("type").as_ref().and_then(Value::as_str) != Some("permission") {
            return Err("permission type must be \"permission\"".into());
        }
        match params.remove("resource") {
            Some(Value::String(resource)) if !resource.is_empty() => {
                Ok(LexPermission { resource, params })
            }
            _ => Err("permission resource must be a non-empty string".into()),
        }
    }
}

impl From<LexPermission> for Map<String, Value> {
    fn from(permission: LexPermission) -> Self {
        let mut map = Map::new();
        map.insert("type".into(), "permission".into());
        map.insert("resource".into(), permission.resource.into());
        map.extend(permission.params);
        map
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use serde_json::json;

    use super::*;

    fn parse(scope: &str) -> Option<IncludeScope> {
        scope.parse().ok()
    }

    fn compile(scope: &str, permissions: Value) -> Vec<String> {
        let set: PermissionSet =
            serde_json::from_value(json!({ "type": "permission-set", "permissions": permissions }))
                .unwrap();
        parse(scope).unwrap().to_scopes(&set)
    }

    const CAL: &str = "include:com.example.calendar.auth";

    // Vectors from the reference `include-scope.test.ts` and indigo's
    // permission scope fixtures.
    #[test]
    fn parses() {
        let cases = [
            ("include:com.example.bar", "com.example.bar", None),
            (
                "include:app.example.authBasics",
                "app.example.authBasics",
                None,
            ),
            (
                "include:com.example.baz?aud=did:web:example.com%23my_service",
                "com.example.baz",
                Some("did:web:example.com#my_service"),
            ),
            (
                "include:com.example.baz?aud=did:web:example.com#my_service",
                "com.example.baz",
                Some("did:web:example.com#my_service"),
            ),
            ("include?nsid=com.example.baz", "com.example.baz", None),
            (
                "include?aud=did:web:example.com%23my_service&nsid=com.example.baz",
                "com.example.baz",
                Some("did:web:example.com#my_service"),
            ),
        ];
        for (scope, nsid, aud) in cases {
            let p = parse(scope).unwrap();
            assert_eq!((p.nsid(), p.aud()), (nsid, aud), "{scope}");
        }

        for invalid in [
            "",
            "repo:com.example.baz",
            "include",
            "include#",
            "Include:app.example.authBasics",
            "include:",
            "include:#",
            "include:&",
            "include:com..example",
            "include:com",
            "include:com.example",
            "include:9com.example.foo",
            "include:com.example.-bar",
            "include:invalid^nsid",
            "include:nsid",
            "include:com.example.baz?aud=",
            "include:com.example.baz?aud=*",
            "include:com.example.baz?aud=did:web:example.com",
            "include:com.example.baz?aud=invalid^did",
            "include:com.example.baz?nsid=com.example.baz",
            "include:com.example.baz?extra=1",
        ] {
            assert!(parse(invalid).is_none(), "{invalid:?}");
        }
    }

    #[test]
    fn formats() {
        assert_eq!(
            IncludeScope::new("com.example.foo", None)
                .unwrap()
                .to_string(),
            "include:com.example.foo"
        );
        assert_eq!(
            IncludeScope::new(
                "com.example.foo",
                Some("did:web:example.com#my_service".into())
            )
            .unwrap()
            .to_string(),
            "include:com.example.foo?aud=did:web:example.com%23my_service"
        );
        assert!(IncludeScope::new("nsid", None).is_none());
        assert!(IncludeScope::new("com.example.foo", Some("*".into())).is_none());
        assert_eq!(
            parse("include?aud=did:web:example.com%23s&nsid=com.example.baz")
                .unwrap()
                .to_string(),
            "include:com.example.baz?aud=did:web:example.com%23s"
        );
    }

    #[test]
    fn parent_authority() {
        let scope = IncludeScope::new("com.example.foo.auth", None).unwrap();
        for ok in [
            "com.example.foo.identifier",
            "com.example.foo.bar.baz",
            "com.example.foo.bar.baz.quz",
        ] {
            assert!(scope.is_parent_authority_of(ok), "{ok}");
        }
        for bad in [
            "*",
            "com",
            "com.example",
            "com.example.foo",
            "com.example.foo.",
            "com.example.bar",
            "com.example.bar.foo",
            "com.example.bar.qux",
            "com.atproto.foo",
            "com.atproto.foo.auth",
            "com.atproto.foo.bar",
            "COM.example.foo.bar",
        ] {
            assert!(!scope.is_parent_authority_of(bad), "{bad}");
        }
    }

    #[test]
    fn blob_account_and_identity_are_never_included() {
        for perm in [
            json!({ "type": "permission", "resource": "blob", "accept": ["image/*"] }),
            json!({ "type": "permission", "resource": "blob", "accept": "image/*" }),
            json!({ "type": "permission", "resource": "blob", "accept": ["image/*"], "extra": "property" }),
            json!({ "type": "permission", "resource": "account", "attr": "email", "action": ["read"] }),
            json!({ "type": "permission", "resource": "identity", "attr": "handle" }),
            json!({ "type": "permission", "resource": "include", "nsid": "com.example.calendar.other" }),
            json!({ "type": "permission", "resource": "unknown", "foo": "bar" }),
        ] {
            assert_eq!(compile(CAL, json!([perm])), Vec::<String>::new(), "{perm}");
        }
        // The account permission itself is valid lexicon syntax.
        let account = Syntax::from_lexicon(
            json!({ "type": "permission", "resource": "account", "attr": "email", "action": ["read"] })
                .as_object()
                .unwrap(),
        );
        assert!(super::super::AccountPermission::from_syntax(&account).is_some());
    }

    #[test]
    fn rpc_permissions() {
        let perm = |extra: Value| {
            let mut p = json!({ "type": "permission", "resource": "rpc", "lxm": ["com.example.calendar.listEvents"] });
            p.as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            p
        };
        assert_eq!(
            compile(CAL, json!([perm(json!({ "aud": "*" }))])),
            ["rpc:com.example.calendar.listEvents?aud=*"]
        );
        assert_eq!(
            compile(
                "include:com.example.calendar.auth?aud=did:web:example.com#foo",
                json!([
                    perm(json!({ "inheritAud": true })),
                    { "type": "permission", "resource": "rpc", "inheritAud": true, "lxm": ["com.example.calendar.getEventDetails"] },
                ])
            ),
            [
                "rpc:com.example.calendar.listEvents?aud=did:web:example.com%23foo",
                "rpc:com.example.calendar.getEventDetails?aud=did:web:example.com%23foo",
            ]
        );

        let with_aud = "include:com.example.calendar.auth?aud=did:web:example.com#bar";
        for (scope, rejected) in [
            (CAL, perm(json!({ "aud": "did:web:example.com#foo" }))),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "did:web:example.com#foo", "lxm": "com.example.calendar.listEvents" }),
            ),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*", "lxm": "com.example.calendar.listEvents" }),
            ),
            (CAL, perm(json!({ "aud": "*", "extra": "property" }))),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*" }),
            ),
            (CAL, perm(json!({}))),
            (CAL, json!({ "type": "permission", "resource": "rpc" })),
            (
                with_aud,
                perm(json!({ "aud": "did:web:example.com#foo", "inheritAud": true })),
            ),
            (with_aud, perm(json!({ "aud": "*", "inheritAud": true }))),
            (with_aud, perm(json!({ "inheritAud": false }))),
            (with_aud, perm(json!({ "inheritAud": "true" }))),
            (with_aud, perm(json!({ "aud": null, "inheritAud": true }))),
            (CAL, perm(json!({ "inheritAud": true }))),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*", "lxm": ["com.atproto.moderation.createReport"] }),
            ),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*", "lxm": ["*"] }),
            ),
            (
                with_aud,
                json!({ "type": "permission", "resource": "rpc", "inheritAud": true, "lxm": ["*"] }),
            ),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*", "lxm": [] }),
            ),
            (
                CAL,
                json!({ "type": "permission", "resource": "rpc", "aud": "*", "lxm": [1] }),
            ),
        ] {
            assert_eq!(
                compile(scope, json!([rejected])),
                Vec::<String>::new(),
                "{scope} {rejected}"
            );
        }
    }

    #[test]
    fn repo_permissions() {
        assert_eq!(
            compile(
                CAL,
                json!([{ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": ["create", "update", "delete"] }])
            ),
            ["repo:com.example.calendar.event"]
        );
        assert_eq!(
            compile(
                CAL,
                json!([
                    { "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": ["delete", "update"] },
                    { "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event", "com.example.calendar.rsvp"], "action": ["delete", "create"] },
                ])
            ),
            [
                "repo:com.example.calendar.event?action=update&action=delete",
                "repo?collection=com.example.calendar.event&collection=com.example.calendar.rsvp&action=create&action=delete",
            ]
        );
        for rejected in [
            json!({ "type": "permission", "resource": "repo", "collection": "com.example.calendar.event", "action": ["create"] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": "all" }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": ["create", "update", "manage"] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["app.bsky.feed.post"] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event", "app.bsky.feed.post"] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["*"] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": [] }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "action": null }),
            json!({ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"], "nsid": "x" }),
        ] {
            assert_eq!(
                compile(CAL, json!([rejected])),
                Vec::<String>::new(),
                "{rejected}"
            );
        }
    }

    #[test]
    fn permission_set_documents() {
        let doc = json!({
            "lexicon": 1,
            "id": "com.example.calendar.auth",
            "defs": { "main": {
                "type": "permission-set",
                "title": "Calendar",
                "title:lang": { "fr": "Calendrier" },
                "detail": "Manage your calendar",
                "permissions": [{ "type": "permission", "resource": "repo", "collection": ["com.example.calendar.event"] }],
            }},
        });
        let set = PermissionSet::from_lexicon_document(&doc).unwrap();
        assert_eq!(set.title.as_deref(), Some("Calendar"));
        assert_eq!(set.title_lang.as_ref().unwrap()["fr"], "Calendrier");
        assert_eq!(set.permissions[0].resource, "repo");
        assert!(!set.permissions[0].params.contains_key("type"));
        let round_trip: PermissionSet =
            serde_json::from_value(serde_json::to_value(&set).unwrap()).unwrap();
        assert_eq!(round_trip, set);
        assert_eq!(serde_json::to_value(&set).unwrap(), doc["defs"]["main"]);

        for bad in [
            json!({ "defs": { "main": { "type": "query" } } }),
            json!({ "defs": { "main": { "type": "query", "permissions": [] } } }),
            json!({ "defs": { "main": { "permissions": [] } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": [{ "resource": "repo" }] } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": [{ "type": "permission", "resource": "" }] } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": [{ "type": "permission", "resource": 1 }] } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": ["repo:*"] } } }),
            json!({ "defs": { "main": { "type": "permission-set" } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": [{ "type": "nope", "resource": "repo" }] } } }),
            json!({ "defs": { "main": { "type": "permission-set", "permissions": [{ "type": "permission" }] } } }),
            json!({ "defs": {} }),
            json!({}),
        ] {
            assert!(
                PermissionSet::from_lexicon_document(&bad).is_none(),
                "{bad}"
            );
        }
    }
}
