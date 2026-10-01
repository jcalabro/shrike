//! Differential tests against the reference TypeScript `@atproto/oauth-scopes`.
//!
//! The vectors come from `scripts/oauth-scope-vectors.mjs`, which runs the
//! reference over every scope in its own and indigo's test suites, generated
//! and mutated scopes, scope sets with permission checks, and `include:`
//! expansions of the real permission-set lexicons and synthetic ones. Point
//! `SHRIKE_OAUTH_SCOPE_VECTORS` at a larger generated file for a deeper run.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

use serde::Deserialize;
use serde_json::{Value, json};
use shrike::oauth::scopes::{
    AccountAction, AccountAttr, AtprotoScope, IdentityAttr, IncludeScope, PermissionSet,
    RepoAction, ScopePermissions, is_atproto_oauth_scope, normalize_atproto_oauth_scope,
};

#[derive(Deserialize)]
struct Vectors {
    atproto: String,
    scopes: Vec<ScopeVector>,
    queries: Vec<Query>,
    sets: Vec<SetVector>,
    includes: Vec<IncludeVector>,
}

#[derive(Deserialize)]
struct ScopeVector {
    s: String,
    /// The reference's normalized form, or null when invalid.
    n: Option<String>,
    /// The reference threw instead of rejecting the value.
    #[serde(default)]
    t: bool,
    /// The reference's normalized form does not normalize to itself.
    #[serde(default)]
    b: bool,
    /// The reference's parsed fields.
    p: Option<Value>,
}

#[derive(Deserialize)]
struct Query {
    r: String,
    o: Value,
    /// The reference's `scopeNeededFor`.
    n: String,
}

#[derive(Deserialize)]
struct SetVector {
    s: String,
    strict: String,
    transition: String,
}

#[derive(Deserialize)]
struct IncludeVector {
    s: String,
    set: PermissionSet,
    scopes: Vec<String>,
}

fn vectors() -> Vectors {
    let path = std::env::var("SHRIKE_OAUTH_SCOPE_VECTORS").unwrap_or_else(|_| {
        concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/testdata/oauth_scopes/ts_vectors.json"
        )
        .to_string()
    });
    let raw = std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("{path}: {e}"));
    serde_json::from_str(&raw).unwrap()
}

/// Collects mismatches so one run reports all of them.
#[derive(Default)]
struct Failures(Vec<String>);

impl Failures {
    fn check(&mut self, ok: bool, msg: impl FnOnce() -> String) {
        if !ok {
            self.0.push(msg());
        }
    }

    fn finish(self, what: &str, total: usize, atproto: &str) {
        assert!(
            self.0.is_empty(),
            "{} of {total} {what} differ from @atproto/oauth-scopes ({atproto}):\n{}",
            self.0.len(),
            self.0
                .iter()
                .take(40)
                .cloned()
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

fn fields(scope: &AtprotoScope) -> Value {
    let strs = |v: &[String]| json!(v);
    match scope {
        AtprotoScope::Account(p) => {
            json!({ "attr": p.attr().as_str(), "action": p.action().iter().map(|a| a.as_str()).collect::<Vec<_>>() })
        }
        AtprotoScope::Blob(p) => json!({ "accept": strs(p.accept()) }),
        AtprotoScope::Identity(p) => json!({ "attr": p.attr().as_str() }),
        AtprotoScope::Include(p) => match p.aud() {
            Some(aud) => json!({ "nsid": p.nsid(), "aud": aud }),
            None => json!({ "nsid": p.nsid() }),
        },
        AtprotoScope::Repo(p) => json!({
            "collection": strs(p.collection()),
            "action": p.action().iter().map(|a| a.as_str()).collect::<Vec<_>>(),
        }),
        AtprotoScope::Rpc(p) => json!({ "aud": p.aud(), "lxm": strs(p.lxm()) }),
        other => json!(other.to_string()),
    }
}

/// Where the reference's rendering would not decode back to a value, shrike
/// escapes the value fully; otherwise the renderings are identical.
fn reference_rendering(rendered: &str) -> String {
    let mut out = String::new();
    let mut rest = rendered;
    while let Some(i) = rest.find('%') {
        out.push_str(&rest[..i]);
        let readable = match rest.get(i..i + 3) {
            Some("%25") => "%",
            Some("%2B") => "+",
            Some("%3A") => ":",
            Some("%2F") => "/",
            Some("%2C") => ",",
            Some("%40") => "@",
            _ => "",
        };
        if readable.is_empty() {
            out.push('%');
            rest = &rest[i + 1..];
        } else {
            out.push_str(readable);
            rest = &rest[i + 3..];
        }
    }
    out + rest
}

/// Node's `URLSearchParams` turns raw non-ASCII into U+FFFD when the same
/// value also holds a valid and an invalid percent escape (`a=é%2F%` decodes
/// to `�/%`, not `é/%` as the WHATWG URL standard and shrike have it).
fn node_query_decoding_bug(case: &ScopeVector) -> bool {
    !case.s.is_ascii()
        && !case.s.contains('\u{fffd}')
        && !case.s.contains("%EF%BF%BD")
        && case
            .p
            .as_ref()
            .is_some_and(|p| p.to_string().contains('\u{fffd}'))
}

#[test]
fn scope_parsing_and_normalization() {
    let v = vectors();
    let mut failures = Failures::default();
    for case in &v.scopes {
        if node_query_decoding_bug(case) {
            continue;
        }
        let parsed = case.s.parse::<AtprotoScope>();
        failures.check(is_atproto_oauth_scope(&case.s) == case.n.is_some(), || {
            format!("{:?}: is_atproto_oauth_scope", case.s)
        });
        let (parsed, expected) = match (parsed, &case.n) {
            (Err(_), None) => continue,
            (Ok(parsed), Some(expected)) => (parsed, expected),
            (parsed, _) => {
                let note = if case.t { " (reference throws)" } else { "" };
                failures.0.push(format!(
                    "{:?}: shrike {parsed:?}, reference {:?}{note}",
                    case.s, case.n
                ));
                continue;
            }
        };
        failures.check(Some(&fields(&parsed)) == case.p.as_ref(), || {
            format!("{:?}: fields {} != {:?}", case.s, fields(&parsed), case.p)
        });

        let rendered = parsed.to_string();
        if case.b {
            // The reference's rendering does not normalize to itself; shrike's
            // matches it but for escaping.
            failures.check(reference_rendering(&rendered) == *expected, || {
                format!("{:?}: {rendered:?} !~ {expected:?}", case.s)
            });
        } else {
            failures.check(&rendered == expected, || {
                format!("{:?}: {rendered:?} != {expected:?}", case.s)
            });
        }
        // Either way, shrike's rendering parses and reaches a fixed point in
        // one more step.
        let again = rendered.parse::<AtprotoScope>().map(|s| s.to_string());
        let thrice = again
            .as_ref()
            .ok()
            .and_then(|s| s.parse::<AtprotoScope>().ok())
            .map(|s| s.to_string());
        failures.check(
            again.is_ok() && again.as_ref().ok() == thrice.as_ref(),
            || {
                format!(
                    "{:?}: {rendered:?} does not stabilize ({again:?}, {thrice:?})",
                    case.s
                )
            },
        );
    }
    failures.finish("scopes", v.scopes.len(), &v.atproto);
}

#[test]
fn whole_scope_normalization() {
    let v = vectors();
    let mut failures = Failures::default();
    // Normalizing a scope made of many values keeps their (sorted) order and
    // duplicates, like the reference.
    for chunk in v.scopes.chunks(7) {
        if chunk
            .iter()
            .any(|c| c.t || c.b || c.s.contains(' ') || node_query_decoding_bug(c))
        {
            continue;
        }
        let scope = chunk
            .iter()
            .map(|c| c.s.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        let mut expected: Vec<&str> = chunk.iter().filter_map(|c| c.n.as_deref()).collect();
        expected.sort_by(|a, b| a.encode_utf16().cmp(b.encode_utf16()));
        let normalized = normalize_atproto_oauth_scope(&scope);
        failures.check(normalized == expected.join(" "), || {
            format!("{scope:?}: {normalized:?}")
        });
    }
    failures.finish("scope lists", v.scopes.len() / 7, &v.atproto);
}

fn check_query(perms: &ScopePermissions, q: &Query) -> (bool, Option<String>) {
    let s = |k: &str| q.o[k].as_str().unwrap();
    let result = match q.r.as_str() {
        "repo" => perms.assert_repo(s("collection"), s("action").parse::<RepoAction>().unwrap()),
        "rpc" => perms.assert_rpc(s("aud"), s("lxm")),
        "blob" => perms.assert_blob(s("mime")),
        "account" => perms.assert_account(
            s("attr").parse::<AccountAttr>().unwrap(),
            s("action").parse::<AccountAction>().unwrap(),
        ),
        "identity" => perms.assert_identity(s("attr").parse::<IdentityAttr>().unwrap()),
        other => panic!("unknown resource {other}"),
    };
    match result {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e.scope().to_string())),
    }
}

#[test]
fn permission_checks() {
    let v = vectors();
    let mut failures = Failures::default();
    let mut allowed = 0;
    for set in &v.sets {
        for (perms, expected, mode) in [
            (ScopePermissions::new(&set.s), &set.strict, "strict"),
            (
                ScopePermissions::with_transition_scopes(&set.s),
                &set.transition,
                "transition",
            ),
        ] {
            assert_eq!(expected.len(), v.queries.len());
            for (q, bit) in v.queries.iter().zip(expected.bytes()) {
                let (ok, needed) = check_query(&perms, q);
                allowed += usize::from(ok);
                failures.check(ok == (bit == b'1'), || {
                    format!("{mode} {:?}: {} {} => {ok}", set.s, q.r, q.o)
                });
                if let Some(needed) = needed {
                    failures.check(needed == q.n, || {
                        format!("{} {}: needs {needed:?}, not {:?}", q.r, q.o, q.n)
                    });
                }
            }
        }
    }
    failures.finish(
        "permission checks",
        v.sets.len() * v.queries.len() * 2,
        &v.atproto,
    );
    // Guard against a corpus that never grants anything.
    assert!(allowed > v.sets.len(), "only {allowed} checks allowed");
}

#[test]
fn include_expansion() {
    let v = vectors();
    let mut failures = Failures::default();
    for case in &v.includes {
        let include: IncludeScope = case.s.parse().unwrap();
        let scopes = include.to_scopes(&case.set);
        failures.check(scopes == case.scopes, || {
            format!(
                "{:?} with {}: {scopes:?} != {:?}",
                case.s,
                serde_json::to_string(&case.set).unwrap(),
                case.scopes
            )
        });
    }
    failures.finish("include expansions", v.includes.len(), &v.atproto);
    assert!(v.includes.iter().filter(|c| !c.scopes.is_empty()).count() > 20);
}

#[test]
fn malformed_escapes_are_ignored_not_fatal() {
    // The reference throws from every check on a scope holding one of these.
    let v = vectors();
    let throwing: Vec<&str> = v
        .scopes
        .iter()
        .filter(|c| c.t && !c.s.contains(' '))
        .map(|c| c.s.as_str())
        .collect();
    assert!(!throwing.is_empty());
    let mut scope = String::from("atproto repo:app.bsky.feed.post");
    for value in &throwing {
        scope.push(' ');
        scope.push_str(value);
    }
    let perms = ScopePermissions::new(&scope);
    assert!(perms.allows_repo("app.bsky.feed.post", RepoAction::Create));
    assert!(!perms.allows_repo("app.bsky.feed.like", RepoAction::Create));
    assert_eq!(
        normalize_atproto_oauth_scope(&scope),
        "atproto repo:app.bsky.feed.post"
    );
}
