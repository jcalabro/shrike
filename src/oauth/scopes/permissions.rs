use std::collections::HashSet;

use super::{
    AccountAction, AccountAttr, AccountPermission, AtprotoScope, BlobPermission, IdentityAttr,
    IdentityPermission, RepoAction, RepoPermission, RpcPermission, ScopeMissingError,
};

/// The permissions granted by an OAuth token's scope.
///
/// Values that are not valid permissions are ignored, as are `include:`
/// values: an authorization server expands those before issuing a token.
///
/// [`new`](Self::new) honors only granular permissions.
/// [`with_transition_scopes`](Self::with_transition_scopes) also honors the
/// legacy `transition:*` scopes, as the reference PDS does:
///
/// - `transition:generic` allows every `repo` and `blob` operation, and `rpc`
///   to any method outside `chat.bsky.*`;
/// - `transition:chat.bsky` allows `rpc` to `chat.bsky.*` methods;
/// - `transition:email` allows reading the account email.
///
/// ```
/// use shrike::oauth::scopes::{AccountAction, AccountAttr, ScopePermissions};
///
/// let scope = "atproto transition:generic transition:email";
/// let strict = ScopePermissions::new(scope);
/// let transitional = ScopePermissions::with_transition_scopes(scope);
///
/// let feed = ("did:web:api.bsky.app#bsky_appview", "app.bsky.feed.getTimeline");
/// assert!(!strict.allows_rpc(feed.0, feed.1));
/// assert!(transitional.allows_rpc(feed.0, feed.1));
/// assert!(!transitional.allows_rpc("did:web:api.bsky.chat#bsky_chat", "chat.bsky.convo.getLog"));
/// assert!(transitional.allows_account(AccountAttr::Email, AccountAction::Read));
/// ```
#[derive(Debug, Clone, Default)]
pub struct ScopePermissions {
    scopes: HashSet<String>,
    transition: bool,
    account: Vec<AccountPermission>,
    blob: Vec<BlobPermission>,
    identity: Vec<IdentityPermission>,
    repo: Vec<RepoPermission>,
    rpc: Vec<RpcPermission>,
}

impl ScopePermissions {
    /// The permissions granted by a space-separated `scope`.
    pub fn new(scope: &str) -> Self {
        Self::from_scopes(scope.split(' '))
    }

    /// The permissions granted by individual scope values.
    pub fn from_scopes<S: AsRef<str>>(scopes: impl IntoIterator<Item = S>) -> Self {
        let mut perms = ScopePermissions::default();
        for scope in scopes {
            let scope = scope.as_ref();
            if scope.is_empty() || !perms.scopes.insert(scope.to_string()) {
                continue;
            }
            match scope.parse() {
                Ok(AtprotoScope::Account(p)) => perms.account.push(p),
                Ok(AtprotoScope::Blob(p)) => perms.blob.push(p),
                Ok(AtprotoScope::Identity(p)) => perms.identity.push(p),
                Ok(AtprotoScope::Repo(p)) => perms.repo.push(p),
                Ok(AtprotoScope::Rpc(p)) => perms.rpc.push(p),
                _ => {}
            }
        }
        perms
    }

    /// Like [`new`](Self::new), also honoring the `transition:*` scopes.
    pub fn with_transition_scopes(scope: &str) -> Self {
        ScopePermissions {
            transition: true,
            ..Self::new(scope)
        }
    }

    /// Whether the scope contains exactly the value `scope` (e.g. `atproto`).
    pub fn has(&self, scope: &str) -> bool {
        self.scopes.contains(scope)
    }

    /// The distinct scope values, in no particular order.
    pub fn scopes(&self) -> impl Iterator<Item = &str> {
        self.scopes.iter().map(String::as_str)
    }

    /// Whether `transition:*` scopes are honored and `transition:generic` is
    /// granted.
    pub fn has_transition_generic(&self) -> bool {
        self.transition && self.has("transition:generic")
    }

    /// Whether `transition:*` scopes are honored and `transition:email` is
    /// granted.
    pub fn has_transition_email(&self) -> bool {
        self.transition && self.has("transition:email")
    }

    /// Whether `transition:*` scopes are honored and `transition:chat.bsky`
    /// is granted.
    pub fn has_transition_chat_bsky(&self) -> bool {
        self.transition && self.has("transition:chat.bsky")
    }

    /// Whether `action` on the account attribute `attr` is allowed.
    pub fn allows_account(&self, attr: AccountAttr, action: AccountAction) -> bool {
        (attr == AccountAttr::Email && action == AccountAction::Read && self.has_transition_email())
            || self.account.iter().any(|p| p.matches(attr, action))
    }

    /// Like [`allows_account`](Self::allows_account), naming the missing scope.
    pub fn assert_account(
        &self,
        attr: AccountAttr,
        action: AccountAction,
    ) -> Result<(), ScopeMissingError> {
        check(self.allows_account(attr, action), || {
            AccountPermission::scope_needed_for(attr, action)
        })
    }

    /// Whether control of the identity attribute `attr` is allowed.
    pub fn allows_identity(&self, attr: IdentityAttr) -> bool {
        self.identity.iter().any(|p| p.matches(attr))
    }

    /// Like [`allows_identity`](Self::allows_identity), naming the missing scope.
    pub fn assert_identity(&self, attr: IdentityAttr) -> Result<(), ScopeMissingError> {
        check(self.allows_identity(attr), || {
            IdentityPermission::scope_needed_for(attr)
        })
    }

    /// Whether uploading a blob of MIME type `mime` is allowed.
    pub fn allows_blob(&self, mime: &str) -> bool {
        self.has_transition_generic() || self.blob.iter().any(|p| p.matches(mime))
    }

    /// Like [`allows_blob`](Self::allows_blob), naming the missing scope.
    pub fn assert_blob(&self, mime: &str) -> Result<(), ScopeMissingError> {
        check(self.allows_blob(mime), || {
            BlobPermission::scope_needed_for(mime)
        })
    }

    /// Whether `action` on records of `collection` is allowed.
    pub fn allows_repo(&self, collection: &str, action: RepoAction) -> bool {
        self.has_transition_generic() || self.repo.iter().any(|p| p.matches(collection, action))
    }

    /// Like [`allows_repo`](Self::allows_repo), naming the missing scope.
    pub fn assert_repo(
        &self,
        collection: &str,
        action: RepoAction,
    ) -> Result<(), ScopeMissingError> {
        check(self.allows_repo(collection, action), || {
            RepoPermission::scope_needed_for(collection, action)
        })
    }

    /// Whether calling method `lxm` on service `aud` (a DID reference such as
    /// `did:web:api.bsky.app#bsky_appview`) is allowed.
    pub fn allows_rpc(&self, aud: &str, lxm: &str) -> bool {
        let chat = lxm.starts_with("chat.bsky.");
        (self.has_transition_generic() && !chat)
            || (self.has_transition_chat_bsky() && chat)
            || self.rpc.iter().any(|p| p.matches(aud, lxm))
    }

    /// Like [`allows_rpc`](Self::allows_rpc), naming the missing scope.
    pub fn assert_rpc(&self, aud: &str, lxm: &str) -> Result<(), ScopeMissingError> {
        check(self.allows_rpc(aud, lxm), || {
            RpcPermission::scope_needed_for(aud, lxm)
        })
    }
}

fn check(allowed: bool, needed: impl FnOnce() -> String) -> Result<(), ScopeMissingError> {
    if allowed {
        Ok(())
    } else {
        Err(ScopeMissingError::new(needed()))
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::super::AccountAction::*;
    use super::super::AccountAttr::*;
    use super::*;

    const WEB: &str = "did:web:example.com";

    // Vectors from the reference `scope-permissions.test.ts` and
    // `scopes-set.test.ts`.
    #[test]
    fn account() {
        let set = ScopePermissions::new("account:email");
        assert!(set.allows_account(Email, Read));
        for (attr, action) in [
            (Email, Manage),
            (Repo, Read),
            (Repo, Manage),
            (Status, Read),
            (Status, Manage),
        ] {
            assert!(!set.allows_account(attr, action), "{attr} {action}");
        }
        let set = ScopePermissions::new("transition:email");
        assert!(!set.allows_account(Email, Read));
        assert!(!set.allows_account(Email, Manage));
    }

    #[test]
    fn blob() {
        let set = ScopePermissions::new("blob:*/*");
        assert!(set.allows_blob("image/png"));
        assert!(set.allows_blob("application/json"));
        let set = ScopePermissions::new("blob:image/*");
        assert!(set.allows_blob("image/png"));
        assert!(!set.allows_blob("application/json"));
        for scope in ["blob:*", "blob:/image", "transition:generic"] {
            let set = ScopePermissions::new(scope);
            assert!(!set.allows_blob("image/png"), "{scope}");
            assert!(!set.allows_blob("application/json"), "{scope}");
        }
    }

    #[test]
    fn repo() {
        use RepoAction::*;
        let set = ScopePermissions::new("repo:*");
        assert!(set.allows_repo("com.example.foo", Create));
        assert!(set.allows_repo("com.example.foo", Update));
        assert!(set.allows_repo("app.bsky.feed.post", Delete));

        let set = ScopePermissions::new("repo:*?action=create");
        assert!(set.allows_repo("com.example.foo", Create));
        assert!(set.allows_repo("app.bsky.feed.post", Create));
        assert!(!set.allows_repo("com.example.foo", Update));
        assert!(!set.allows_repo("app.bsky.feed.post", Delete));

        let set = ScopePermissions::new("repo:com.example.foo?action=create");
        assert!(set.allows_repo("com.example.foo", Create));
        assert!(!set.allows_repo("com.example.foo", Update));
        assert!(!set.allows_repo("com.example.foo", Delete));
        assert!(!set.allows_repo("app.bsky.feed.post", Create));

        let set = ScopePermissions::new("repo:com.example.foo");
        assert!(set.allows_repo("com.example.foo", Create));
        assert!(!set.allows_repo("com.example.bar", Create));

        let set = ScopePermissions::new("repo:not-a-valid-nsid");
        assert!(!set.allows_repo("not-a-valid-nsid", Create));

        let set = ScopePermissions::new("transition:generic");
        for (collection, action) in [
            ("app.bsky.feed.post", Create),
            ("app.bsky.feed.post", Delete),
            ("com.example.foo", Update),
        ] {
            assert!(!set.allows_repo(collection, action));
        }
    }

    #[test]
    fn rpc() {
        let set = ScopePermissions::new("rpc:*?lxm=*");
        assert!(!set.allows_rpc(WEB, "com.example.method"));
        assert!(!set.allows_rpc(WEB, "app.bsky.feed.getFeed"));

        let set = ScopePermissions::new("rpc:app.bsky.feed.getFeed?aud=*");
        assert!(set.allows_rpc(WEB, "app.bsky.feed.getFeed"));
        assert!(set.allows_rpc("did:plc:blahbla", "app.bsky.feed.getFeed"));
        assert!(!set.allows_rpc(WEB, "com.example.method"));

        let set = ScopePermissions::new("rpc:*?aud=did:web:example.com%23foo");
        assert!(set.allows_rpc("did:web:example.com#foo", "com.example.method"));
        assert!(set.allows_rpc("did:web:example.com#foo", "app.bsky.feed.getFeed"));
        assert!(!set.allows_rpc("did:web:bar.com#foo", "com.example.method"));
        assert!(!set.allows_rpc(WEB, "com.example.method"));

        let set = ScopePermissions::new("rpc:app.bsky.feed.getFeed?aud=did:web:example.com%23foo");
        assert!(set.allows_rpc("did:web:example.com#foo", "app.bsky.feed.getFeed"));
        assert!(!set.allows_rpc(WEB, "com.example.method"));
        assert!(!set.allows_rpc("did:plc:blahbla", "app.bsky.feed.getFeed"));

        for scope in ["transition:generic", "transition:chat.bsky"] {
            let set = ScopePermissions::new(scope);
            for lxm in [
                "app.bsky.feed.getFeed",
                "com.example.method",
                "chat.bsky.message.send",
                "chat.bsky.conversation.get",
                "*",
            ] {
                assert!(!set.allows_rpc(WEB, lxm), "{scope} {lxm}");
            }
        }
    }

    #[test]
    fn assert_rpc_with_combined_aud() {
        let set = ScopePermissions::new(
            "rpc:app.bsky.feed.getFeed?aud=did:web:example.com%23bsky_appview",
        );
        assert!(
            set.assert_rpc("did:web:example.com#bsky_appview", "app.bsky.feed.getFeed")
                .is_ok()
        );
        assert_eq!(
            set.assert_rpc(WEB, "app.bsky.feed.getFeed")
                .unwrap_err()
                .scope(),
            "rpc:app.bsky.feed.getFeed?aud=did:web:example.com"
        );
        let set = ScopePermissions::new("rpc:app.bsky.feed.getFeed?aud=*");
        assert!(
            set.assert_rpc("did:web:example.com#bsky_appview", "app.bsky.feed.getFeed")
                .is_ok()
        );
    }

    #[test]
    fn identity() {
        let set = ScopePermissions::new("identity:handle");
        assert!(set.allows_identity(IdentityAttr::Handle));
        assert!(!set.allows_identity(IdentityAttr::Any));
        assert_eq!(
            set.assert_identity(IdentityAttr::Any).unwrap_err().scope(),
            "identity:*"
        );
        let set = ScopePermissions::new("identity:*");
        assert!(set.allows_identity(IdentityAttr::Handle));
        assert!(set.allows_identity(IdentityAttr::Any));
        assert!(!ScopePermissions::new("transition:generic").allows_identity(IdentityAttr::Handle));
        assert!(
            !ScopePermissions::with_transition_scopes("transition:generic")
                .allows_identity(IdentityAttr::Handle)
        );
    }

    #[test]
    fn asserts_name_the_missing_scope() {
        let set = ScopePermissions::new("atproto");
        let missing = |r: Result<(), ScopeMissingError>| r.unwrap_err().scope().to_string();
        assert_eq!(
            missing(set.assert_account(Email, Manage)),
            "account:email?action=manage"
        );
        assert_eq!(missing(set.assert_account(Status, Read)), "account:status");
        assert_eq!(missing(set.assert_blob("image/png")), "blob:image/png");
        assert_eq!(
            missing(set.assert_repo("app.bsky.feed.post", RepoAction::Create)),
            "repo:app.bsky.feed.post?action=create"
        );
        assert_eq!(
            missing(set.assert_rpc(
                "did:web:api.bsky.app#bsky_appview",
                "app.bsky.feed.getTimeline"
            )),
            "rpc:app.bsky.feed.getTimeline?aud=did:web:api.bsky.app%23bsky_appview"
        );
        assert_eq!(
            missing(set.assert_identity(IdentityAttr::Handle)),
            "identity:handle"
        );

        let all = ScopePermissions::new(
            "account:email?action=manage account:status identity:* blob:*/* repo:* rpc:*?aud=did:web:api.bsky.app%23bsky_appview",
        );
        assert!(all.assert_account(Email, Manage).is_ok());
        assert!(all.assert_account(Status, Read).is_ok());
        assert!(all.assert_identity(IdentityAttr::Handle).is_ok());
        assert!(all.assert_blob("video/mp4").is_ok());
        assert!(
            all.assert_repo("app.bsky.feed.post", RepoAction::Delete)
                .is_ok()
        );
        assert!(
            all.assert_rpc(
                "did:web:api.bsky.app#bsky_appview",
                "app.bsky.feed.getTimeline"
            )
            .is_ok()
        );
        assert!(
            all.assert_rpc("did:web:api.bsky.chat#bsky_chat", "chat.bsky.convo.getLog")
                .is_err()
        );
    }

    #[test]
    fn scope_set() {
        let set = ScopePermissions::from_scopes(["atproto", "", "repo:*", "repo:*", "bogus"]);
        assert!(set.has("atproto"));
        assert!(set.has("bogus"));
        assert!(!set.has(""));
        assert!(!set.has("repo"));
        let mut scopes: Vec<_> = set.scopes().collect();
        scopes.sort();
        assert_eq!(scopes, ["atproto", "bogus", "repo:*"]);
        assert!(set.allows_repo("a.b.c", RepoAction::Create));

        let empty = ScopePermissions::new("");
        assert_eq!(empty.scopes().count(), 0);
        assert!(!empty.allows_repo("a.b.c", RepoAction::Create));

        // `include:` scopes grant nothing by themselves.
        let set = ScopePermissions::new("atproto include:app.bsky.authFullApp");
        assert!(!set.allows_repo("app.bsky.feed.post", RepoAction::Create));
        assert!(!set.allows_rpc(
            "did:web:api.bsky.app#bsky_appview",
            "app.bsky.feed.getTimeline"
        ));
    }

    // Vectors from the reference `scope-permissions-transition.test.ts`.
    #[test]
    fn transition_scopes() {
        let set = ScopePermissions::with_transition_scopes("transition:email account:repo");
        assert!(set.has_transition_email());
        assert!(set.allows_account(Email, Read));
        assert!(!set.allows_account(Email, Manage));
        assert!(set.allows_account(Repo, Read));
        assert!(!set.allows_account(Repo, Manage));
        assert!(!set.allows_account(Status, Read));
        assert!(!set.allows_account(Status, Manage));

        let generic = ScopePermissions::with_transition_scopes("transition:generic");
        assert!(generic.has_transition_generic());
        assert!(!generic.has_transition_email());
        assert!(!generic.has_transition_chat_bsky());
        assert!(generic.allows_blob("foo/bar"));
        assert!(generic.allows_blob("not a mime"));
        for (collection, action) in [
            ("app.bsky.feed.post", RepoAction::Create),
            ("app.bsky.feed.post", RepoAction::Delete),
            ("com.example.foo", RepoAction::Create),
            ("com.example.foo", RepoAction::Update),
        ] {
            assert!(generic.allows_repo(collection, action));
        }
        assert!(generic.allows_rpc(WEB, "app.bsky.feed.post"));
        assert!(generic.allows_rpc(WEB, "com.example.foo"));
        assert!(generic.allows_rpc(WEB, "*"));
        assert!(!generic.allows_rpc(WEB, "chat.bsky.message.send"));
        assert!(!generic.allows_rpc(WEB, "chat.bsky.conversation.get"));
        assert!(!generic.allows_account(Email, Read));
        assert_eq!(
            generic
                .assert_rpc(WEB, "chat.bsky.convo.getLog")
                .unwrap_err()
                .scope(),
            "rpc:chat.bsky.convo.getLog?aud=did:web:example.com"
        );

        let chat = ScopePermissions::with_transition_scopes("transition:chat.bsky");
        assert!(chat.has_transition_chat_bsky());
        assert!(chat.allows_rpc(WEB, "chat.bsky.message.send"));
        assert!(chat.allows_rpc(WEB, "chat.bsky.conversation.get"));
        assert!(!chat.allows_rpc(WEB, "app.bsky.feed.post"));
        assert!(!chat.allows_rpc(WEB, "com.example.foo"));
        assert!(!chat.allows_rpc(WEB, "*"));
        assert!(!chat.allows_blob("image/png"));
        assert!(!chat.allows_repo("app.bsky.feed.post", RepoAction::Create));

        let both =
            ScopePermissions::with_transition_scopes("transition:generic transition:chat.bsky");
        assert!(both.allows_rpc(WEB, "chat.bsky.convo.getLog"));
        assert!(both.allows_rpc(WEB, "app.bsky.feed.getTimeline"));

        // Granular permissions still apply alongside transition scopes.
        let set = ScopePermissions::with_transition_scopes(
            "transition:chat.bsky rpc:app.bsky.feed.getFeed?aud=*",
        );
        assert!(set.allows_rpc(WEB, "app.bsky.feed.getFeed"));
        assert!(!set.allows_rpc(WEB, "app.bsky.feed.getTimeline"));
    }
}
