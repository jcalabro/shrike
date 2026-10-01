#![no_main]
//! OAuth scope parsing must never panic, and every scope that parses must
//! render to a scope that parses again, settles after one more round, and
//! keeps its grants. The input's first line is a scope; if the rest is a
//! permission set, `include:` expansion must only yield valid `repo`/`rpc`
//! scopes within the set's namespace.

use libfuzzer_sys::fuzz_target;
use shrike::oauth::scopes::{
    AccountAction, AccountAttr, AtprotoScope, IncludeScope, PermissionSet, RepoAction, ScopePermissions,
};

fn reparse(scope: &AtprotoScope) -> AtprotoScope {
    let rendered = scope.to_string();
    rendered
        .parse()
        .unwrap_or_else(|_| panic!("{scope:?} renders to {rendered:?}, which does not parse"))
}

fn check_value(value: &str) {
    let Ok(parsed) = value.parse::<AtprotoScope>() else {
        return;
    };
    let again = reparse(&parsed);
    assert_eq!(reparse(&again).to_string(), again.to_string(), "{value:?} does not settle");
    match (&parsed, &again) {
        (AtprotoScope::Repo(a), AtprotoScope::Repo(b)) => {
            for c in a.collection().iter().map(String::as_str).chain(["*", "x.y.z"]) {
                for action in RepoAction::ALL {
                    assert_eq!(a.matches(c, action), b.matches(c, action), "{value:?}");
                }
            }
        }
        (AtprotoScope::Rpc(a), AtprotoScope::Rpc(b)) => {
            for l in a.lxm().iter().map(String::as_str).chain(["*", "x.y.z"]) {
                for aud in [a.aud(), "did:web:x.com#y"] {
                    assert_eq!(a.matches(aud, l), b.matches(aud, l), "{value:?}");
                }
            }
        }
        (AtprotoScope::Account(a), AtprotoScope::Account(b)) => {
            for attr in AccountAttr::ALL {
                for action in AccountAction::ALL {
                    assert_eq!(a.matches(attr, action), b.matches(attr, action), "{value:?}");
                }
            }
        }
        (AtprotoScope::Blob(_), AtprotoScope::Blob(_)) => {}
        (a, b) => assert_eq!(a, b, "{value:?}"),
    }
}

fuzz_target!(|input: &str| {
    let (scope, rest) = input.split_once('\n').unwrap_or((input, ""));
    for value in scope.split(' ') {
        check_value(value);
    }

    let perms = ScopePermissions::with_transition_scopes(scope);
    for piece in scope.split([' ', '?', '&', '=', ':']) {
        perms.allows_repo(piece, RepoAction::Create);
        perms.allows_rpc(piece, piece);
        perms.allows_blob(piece);
    }

    if let Ok(set) = serde_json::from_str::<PermissionSet>(rest) {
        let include = scope.parse::<IncludeScope>().unwrap_or_else(|_| {
            IncludeScope::new("com.example.calendar.auth", Some("did:web:example.com#svc".into()))
                .expect("valid include scope")
        });
        for granted in include.to_scopes(&set) {
            match granted.parse::<AtprotoScope>() {
                Ok(AtprotoScope::Repo(p)) => {
                    assert!(p.collection().iter().all(|c| include.is_parent_authority_of(c)), "{granted}")
                }
                Ok(AtprotoScope::Rpc(p)) => {
                    assert!(p.lxm().iter().all(|l| include.is_parent_authority_of(l)), "{granted}")
                }
                other => panic!("{include} granted {granted:?}: {other:?}"),
            }
        }
    }
});
