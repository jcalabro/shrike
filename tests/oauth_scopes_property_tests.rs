#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use proptest::prelude::*;
use shrike::oauth::scopes::{
    AccountAction, AccountAttr, AccountPermission, AtprotoScope, BlobPermission, IdentityAttr,
    IdentityPermission, IncludeScope, RepoAction, RepoPermission, RpcPermission, ScopePermissions,
};

fn nsid() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-zA-Z][a-z0-9-]{0,4}[a-z0-9](\\.[a-z0-9]{1,4}){1,3}\\.[a-zA-Z][a-zA-Z0-9]{0,6}",
        Just("app.bsky.feed.post".to_string()),
        Just("chat.bsky.convo.getLog".to_string()),
    ]
}

fn nsid_or_wildcard() -> impl Strategy<Value = String> {
    prop_oneof![4 => nsid(), 1 => Just("*".to_string())]
}

fn did_ref() -> impl Strategy<Value = String> {
    prop_oneof![
        "did:web:[a-z]{1,8}(\\.[a-z]{2,4}){1,2}#[a-zA-Z0-9_~.!$&'()*+,;=:@/?-]{1,10}",
        "did:web:localhost(%3A[1-9][0-9]{0,3})?#[a-z_]{1,8}",
        "did:plc:[a-z2-7]{24}#[a-z_]{1,8}",
    ]
}

fn aud() -> impl Strategy<Value = String> {
    prop_oneof![4 => did_ref(), 1 => Just("*".to_string())]
}

fn mime() -> impl Strategy<Value = String> {
    "[a-z]{1,6}/[a-z0-9+.%-]{1,8}"
}

fn accept() -> impl Strategy<Value = String> {
    prop_oneof![
        4 => "[a-zA-Z]{1,6}/[a-zA-Z0-9+.%-]{1,8}",
        2 => "[a-zA-Z]{1,6}/\\*",
        1 => Just("*/*".to_string()),
    ]
}

fn repo_action() -> impl Strategy<Value = RepoAction> {
    prop::sample::select(RepoAction::ALL.to_vec())
}

fn account_action() -> impl Strategy<Value = AccountAction> {
    prop::sample::select(AccountAction::ALL.to_vec())
}

fn account_attr() -> impl Strategy<Value = AccountAttr> {
    prop::sample::select(AccountAttr::ALL.to_vec())
}

fn reparse(scope: &impl ToString) -> AtprotoScope {
    let rendered = scope.to_string();
    rendered
        .parse()
        .unwrap_or_else(|_| panic!("rendered scope {rendered:?} does not parse"))
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    // Rendering is canonical (a fixed point) and keeps the same grants.
    #[test]
    fn repo_render_round_trips(
        collection in prop::collection::vec(nsid_or_wildcard(), 1..5),
        action in prop::collection::vec(repo_action(), 1..5),
        probe in nsid(),
    ) {
        let perm = RepoPermission::new(collection.clone(), action).unwrap();
        let AtprotoScope::Repo(again) = reparse(&perm) else { panic!() };
        prop_assert_eq!(again.to_string(), perm.to_string());
        for c in collection.iter().chain([&probe, &"*".to_string()]) {
            for a in RepoAction::ALL {
                prop_assert_eq!(perm.matches(c, a), again.matches(c, a));
            }
        }
    }

    #[test]
    fn rpc_render_round_trips(
        aud in aud(),
        lxm in prop::collection::vec(nsid_or_wildcard(), 1..5),
        probe_aud in did_ref(),
        probe_lxm in nsid(),
    ) {
        let Some(perm) = RpcPermission::new(aud.clone(), lxm.clone()) else {
            prop_assert!(aud == "*" && lxm.iter().any(|l| l == "*"));
            return Ok(());
        };
        let AtprotoScope::Rpc(again) = reparse(&perm) else { panic!() };
        prop_assert_eq!(again.to_string(), perm.to_string());
        prop_assert_eq!(again.aud(), aud.as_str());
        for a in [&aud, &probe_aud] {
            for l in lxm.iter().chain([&probe_lxm]) {
                prop_assert_eq!(perm.matches(a, l), again.matches(a, l));
            }
        }
    }

    #[test]
    fn account_identity_include_render_round_trip(
        attr in account_attr(),
        action in prop::collection::vec(account_action(), 1..4),
        handle in any::<bool>(),
        nsid in nsid(),
        aud in prop::option::of(did_ref()),
    ) {
        let perm = AccountPermission::new(attr, action).unwrap();
        let AtprotoScope::Account(again) = reparse(&perm) else { panic!() };
        prop_assert_eq!(again.to_string(), perm.to_string());
        for (attr, action) in AccountAttr::ALL.into_iter().flat_map(|a| AccountAction::ALL.map(|b| (a, b))) {
            prop_assert_eq!(perm.matches(attr, action), again.matches(attr, action));
        }

        let attr = if handle { IdentityAttr::Handle } else { IdentityAttr::Any };
        let AtprotoScope::Identity(again) = reparse(&IdentityPermission::new(attr)) else { panic!() };
        prop_assert_eq!(again.attr(), attr);

        let include = IncludeScope::new(nsid, aud).unwrap();
        prop_assert_eq!(reparse(&include), AtprotoScope::Include(include));
    }

    // Normalization lowercases accept patterns (like the reference), so grants
    // are kept for lowercase MIME types; rendering settles in one more step.
    #[test]
    fn blob_render_round_trips(
        accept in prop::collection::vec(accept(), 1..5),
        probe in mime(),
    ) {
        let perm = BlobPermission::new(accept.clone()).unwrap();
        let AtprotoScope::Blob(again) = reparse(&perm) else { panic!() };
        let AtprotoScope::Blob(thrice) = reparse(&again) else { panic!() };
        prop_assert_eq!(thrice.to_string(), again.to_string());
        let lower: Vec<String> = accept.iter().map(|a| a.to_lowercase()).collect();
        for mime in lower.iter().chain([&probe]) {
            if !mime.contains('*') {
                let lowered = BlobPermission::new(lower.clone()).unwrap();
                prop_assert_eq!(lowered.matches(mime), again.matches(mime));
            }
        }
    }

    // The scope named by a failed assertion grants what was asked for.
    #[test]
    fn needed_scope_is_sufficient(
        collection in nsid_or_wildcard(),
        repo_action in repo_action(),
        aud in aud(),
        lxm in nsid(),
        mime in mime(),
        attr in account_attr(),
        account_action in account_action(),
        identity in any::<bool>(),
    ) {
        let none = ScopePermissions::new("atproto");
        let granted = |r: Result<(), shrike::oauth::scopes::ScopeMissingError>| {
            ScopePermissions::new(r.unwrap_err().scope())
        };

        let perms = granted(none.assert_repo(&collection, repo_action));
        prop_assert!(perms.allows_repo(&collection, repo_action));
        let perms = granted(none.assert_rpc(&aud, &lxm));
        prop_assert!(perms.allows_rpc(&aud, &lxm));
        let perms = granted(none.assert_blob(&mime));
        prop_assert!(perms.allows_blob(&mime));
        let perms = granted(none.assert_account(attr, account_action));
        prop_assert!(perms.allows_account(attr, account_action));
        let identity = if identity { IdentityAttr::Handle } else { IdentityAttr::Any };
        let perms = granted(none.assert_identity(identity));
        prop_assert!(perms.allows_identity(identity));
    }

    // More scopes never grant less, and honoring transition scopes never
    // grants less.
    #[test]
    fn grants_are_monotonic(
        a in prop::collection::vec(scope_value(), 0..6),
        b in prop::collection::vec(scope_value(), 0..6),
        collection in nsid(),
        repo_action in repo_action(),
        aud in did_ref(),
        lxm in nsid(),
        mime in mime(),
    ) {
        let a_scope = a.join(" ");
        let ab_scope = format!("{a_scope} {}", b.join(" "));
        let checks = |p: &ScopePermissions| {
            let mut out = vec![
                p.allows_repo(&collection, repo_action),
                p.allows_rpc(&aud, &lxm),
                p.allows_rpc(&aud, "chat.bsky.convo.getLog"),
                p.allows_blob(&mime),
                p.allows_identity(IdentityAttr::Handle),
                p.allows_identity(IdentityAttr::Any),
            ];
            for attr in AccountAttr::ALL {
                for action in AccountAction::ALL {
                    out.push(p.allows_account(attr, action));
                }
            }
            out
        };
        let strict = checks(&ScopePermissions::new(&a_scope));
        let transition = checks(&ScopePermissions::with_transition_scopes(&a_scope));
        let more = checks(&ScopePermissions::new(&ab_scope));
        for i in 0..strict.len() {
            prop_assert!(!strict[i] || transition[i], "check {i}");
            prop_assert!(!strict[i] || more[i], "check {i}");
        }
    }

    // Arbitrary input never panics, and whatever parses renders to a scope
    // that parses and settles.
    #[test]
    fn arbitrary_strings(s in "\\PC{0,40}", t in "[a-z]{0,8}[:?][ -~]{0,40}") {
        for input in [&s, &t] {
            if let Ok(scope) = input.parse::<AtprotoScope>() {
                let again = reparse(&scope);
                prop_assert_eq!(reparse(&again).to_string(), again.to_string());
            }
            let perms = ScopePermissions::with_transition_scopes(input);
            perms.allows_repo(input, RepoAction::Create);
            perms.allows_rpc(input, input);
            perms.allows_blob(input);
        }
    }
}

fn scope_value() -> impl Strategy<Value = String> {
    prop_oneof![
        (
            prop::collection::vec(nsid_or_wildcard(), 1..3),
            prop::collection::vec(repo_action(), 1..3)
        )
            .prop_map(|(c, a)| RepoPermission::new(c, a).unwrap().to_string()),
        (did_ref(), prop::collection::vec(nsid_or_wildcard(), 1..3))
            .prop_map(|(aud, lxm)| RpcPermission::new(aud, lxm).unwrap().to_string()),
        prop::collection::vec(accept(), 1..3)
            .prop_map(|a| BlobPermission::new(a).unwrap().to_string()),
        (account_attr(), account_action()).prop_map(|(attr, action)| {
            AccountPermission::new(attr, [action]).unwrap().to_string()
        }),
        Just("identity:handle".to_string()),
        Just("identity:*".to_string()),
        Just("transition:generic".to_string()),
        Just("transition:email".to_string()),
        Just("transition:chat.bsky".to_string()),
        Just("atproto".to_string()),
        "[ -~]{0,12}",
    ]
}
