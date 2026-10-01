//! The syntax shared by every permission: `resource[:positional][?query]`
//! scope strings and lexicon permission objects (from permission sets), plus
//! the value validators and the schema-driven parameter parser.
//!
//! This mirrors `lib/syntax-string.ts`, `lib/syntax-lexicon.ts`,
//! `lib/parser.ts` and `lib/mime.ts` from the reference `@atproto/oauth-scopes`.

use std::cmp::Ordering;

use serde_json::{Map, Value};

/// A parameter's raw value, before validation.
#[derive(Debug)]
pub(crate) enum Param {
    /// Every occurrence of a key in a scope string's query.
    Query(Vec<String>),
    /// A lexicon permission's string value.
    Str(String),
    /// A lexicon permission's array of strings.
    List(Vec<String>),
    /// A lexicon value no parameter accepts: a number, boolean, null, object,
    /// or an array holding one of those. Every validator rejects these.
    Invalid,
}

impl Param {
    /// A single value: one query occurrence, or a lexicon string.
    fn single(&self) -> Option<&str> {
        match self {
            Param::Query(values) if values.len() == 1 => Some(&values[0]),
            Param::Str(value) => Some(value),
            _ => None,
        }
    }

    /// Several values: every query occurrence, or a lexicon array.
    fn multi(&self) -> Option<&[String]> {
        match self {
            Param::Query(values) | Param::List(values) => Some(values),
            _ => None,
        }
    }
}

/// A scope value or lexicon permission split into its positional parameter and
/// named parameters (keyed uniquely, in order of first appearance).
#[derive(Debug)]
pub(crate) struct Syntax {
    positional: Option<String>,
    params: Vec<(String, Param)>,
}

impl Syntax {
    /// Splits a scope string for `resource`, or returns `None` when it is for
    /// another resource or its positional parameter is not decodable.
    ///
    /// Where the reference `decodeURIComponent` throws on a malformed escape,
    /// the scope is simply not a valid permission.
    pub(crate) fn from_scope(scope: &str, resource: &str) -> Option<Syntax> {
        let rest = scope.strip_prefix(resource)?;
        let (positional, query) = if let Some(rest) = rest.strip_prefix(':') {
            match rest.split_once('?') {
                Some((positional, query)) => (Some(positional), Some(query)),
                None => (Some(rest), None),
            }
        } else if let Some(query) = rest.strip_prefix('?') {
            (None, Some(query))
        } else if rest.is_empty() {
            (None, None)
        } else {
            return None;
        };

        let positional = match positional {
            Some(p) => Some(decode_uri_component(p)?),
            None => None,
        };
        let mut params: Vec<(String, Param)> = Vec::new();
        // Like `new URLSearchParams(query)`, which drops one leading "?".
        let query = query.map(|q| q.strip_prefix('?').unwrap_or(q));
        for (key, value) in url::form_urlencoded::parse(query.unwrap_or("").as_bytes()) {
            match params.iter_mut().find(|(k, _)| *k == key) {
                Some((_, Param::Query(values))) => values.push(value.into_owned()),
                _ => params.push((key.into_owned(), Param::Query(vec![value.into_owned()]))),
            }
        }
        Some(Syntax { positional, params })
    }

    /// Reads a lexicon permission object. Lexicon permissions have no
    /// positional parameter, and their `type` and `resource` keys are not
    /// parameters.
    pub(crate) fn from_lexicon(permission: &Map<String, Value>) -> Syntax {
        let params = permission
            .iter()
            .filter(|(key, _)| *key != "type" && *key != "resource")
            .map(|(key, value)| (key.clone(), lexicon_param(value)))
            .collect();
        Syntax {
            positional: None,
            params,
        }
    }

    /// Overrides (or adds) a parameter.
    pub(crate) fn set(&mut self, key: &str, param: Param) {
        self.params.retain(|(k, _)| k != key);
        self.params.push((key.to_string(), param));
    }

    /// Removes a parameter.
    pub(crate) fn remove(&mut self, key: &str) {
        self.params.retain(|(k, _)| k != key);
    }

    fn get(&self, key: &str) -> Option<&Param> {
        self.params.iter().find(|(k, _)| k == key).map(|(_, v)| v)
    }
}

fn lexicon_param(value: &Value) -> Param {
    match value {
        Value::String(s) => Param::Str(s.clone()),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::to_string))
            .collect::<Option<Vec<_>>>()
            .map_or(Param::Invalid, Param::List),
        _ => Param::Invalid,
    }
}

/// One parameter of a permission's schema.
pub(crate) struct Field {
    pub name: &'static str,
    pub multiple: bool,
    pub required: bool,
    pub validate: fn(&str) -> bool,
}

/// A parameter value accepted by [`parse`].
#[derive(Debug)]
pub(crate) enum Parsed {
    /// An optional parameter that was not given (the caller supplies its
    /// default).
    Absent,
    One(String),
    Many(Vec<String>),
}

impl Parsed {
    pub(crate) fn one(self) -> Option<String> {
        match self {
            Parsed::One(value) => Some(value),
            _ => None,
        }
    }

    pub(crate) fn many(self) -> Option<Vec<String>> {
        match self {
            Parsed::Many(values) => Some(values),
            _ => None,
        }
    }
}

/// Validates `syntax` against a permission schema, returning one value per
/// field (in field order), or `None` when the permission is invalid: unknown
/// parameters, a repeated single-valued parameter, a value that fails
/// validation, a missing required parameter, or a positional parameter that is
/// also given by name.
pub(crate) fn parse(syntax: &Syntax, fields: &[Field], positional: &str) -> Option<Vec<Parsed>> {
    if syntax
        .params
        .iter()
        .any(|(key, _)| !fields.iter().any(|f| f.name == key))
    {
        return None;
    }

    fields
        .iter()
        .map(|field| match (syntax.get(field.name), &syntax.positional) {
            (Some(_), Some(_)) if field.name == positional => None,
            (Some(param), _) if field.multiple => {
                let values = param.multi()?;
                (!values.is_empty() && values.iter().all(|v| (field.validate)(v)))
                    .then(|| Parsed::Many(values.to_vec()))
            }
            (Some(param), _) => {
                let value = param.single()?;
                (field.validate)(value).then(|| Parsed::One(value.to_string()))
            }
            (None, Some(value)) if field.name == positional => {
                (field.validate)(value).then(|| match field.multiple {
                    true => Parsed::Many(vec![value.clone()]),
                    false => Parsed::One(value.clone()),
                })
            }
            (None, _) if field.required => None,
            (None, _) => Some(Parsed::Absent),
        })
        .collect()
}

/// Renders a scope string. Callers pass already-normalized values, omitting
/// optional parameters equal to their defaults.
///
/// Like the reference, `:`, `/`, `,`, `@`, `%` and `+` are left unescaped for
/// readability. Unlike it, a value is escaped fully when that readable form
/// would not decode back to it (a `%` before two hex digits, or a `+` in the
/// query), so every rendered scope parses back to the same permission.
pub(crate) fn format(resource: &str, positional: Option<&str>, params: &[(&str, &str)]) -> String {
    let mut scope = resource.to_string();
    if let Some(positional) = positional {
        scope.push(':');
        push_component(&mut scope, positional, false);
    }
    for (i, (key, value)) in params.iter().enumerate() {
        scope.push(if i == 0 { '?' } else { '&' });
        push_component(&mut scope, key, true);
        scope.push('=');
        push_component(&mut scope, value, true);
    }
    scope
}

fn push_component(out: &mut String, value: &str, query: bool) {
    let readable = encode(value, query, true);
    let decoded = if query {
        url::form_urlencoded::parse(readable.as_bytes())
            .next()
            .map(|(decoded, _)| decoded.into_owned())
    } else {
        decode_uri_component(&readable)
    };
    if decoded.as_deref().unwrap_or_default() == value {
        out.push_str(&readable);
    } else {
        out.push_str(&encode(value, query, false));
    }
}

/// Percent-encodes `value` like `encodeURIComponent` (for the positional
/// part) or the `application/x-www-form-urlencoded` serializer (for the
/// query), leaving `:`, `/`, `,` and `@` and, if `readable`, `%` and `+`
/// unescaped.
fn encode(value: &str, query: bool, readable: bool) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(value.len());
    for &b in value.as_bytes() {
        let keep = b.is_ascii_alphanumeric()
            || b":/,@".contains(&b)
            || (readable && b"%+".contains(&b))
            || if query {
                b"*-._".contains(&b)
            } else {
                b"-_.!~*'()+".contains(&b)
            };
        if keep {
            out.push(char::from(b));
        } else if query && b == b' ' {
            out.push('+');
        } else {
            out.push('%');
            out.push(char::from(HEX[usize::from(b >> 4)]));
            out.push(char::from(HEX[usize::from(b & 15)]));
        }
    }
    out
}

/// Like JavaScript's `decodeURIComponent`: `None` for an incomplete escape or
/// escapes that do not form UTF-8.
fn decode_uri_component(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = bytes.get(i + 1..i + 3)?;
            // Not `from_str_radix`, which also accepts a sign ("+B").
            let digit = |b: u8| char::from(b).to_digit(16);
            out.push(u8::try_from(digit(hex[0])? * 16 + digit(hex[1])?).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

/// Orders strings by UTF-16 code units, like JavaScript's default sort.
pub(crate) fn js_cmp(a: &str, b: &str) -> Ordering {
    a.encode_utf16().cmp(b.encode_utf16())
}

/// Sorts and removes duplicates, like `[...new Set(values)].sort()`.
pub(crate) fn sorted_unique(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort_by(|a, b| js_cmp(a, b));
    values.dedup();
    values
}

/// Removes duplicates, keeping the first occurrence of each value.
pub(crate) fn unique<T: PartialEq + Clone>(values: &[T]) -> Vec<T> {
    let mut out: Vec<T> = Vec::with_capacity(values.len());
    for value in values {
        if !out.contains(value) {
            out.push(value.clone());
        }
    }
    out
}

/// Whether `a` and `b` hold the same values, ignoring order and duplicates.
pub(crate) fn same_values<T: PartialEq>(a: &[T], b: &[T]) -> bool {
    a.iter().all(|v| b.contains(v)) && b.iter().all(|v| a.contains(v))
}

/// Whether `value` is an NSID. Unlike [`crate::syntax::Nsid`], permissions keep
/// NSIDs exactly as written, so matching stays case-sensitive.
pub(crate) fn is_nsid(value: &str) -> bool {
    crate::syntax::Nsid::validate(value).is_ok()
}

/// Whether `value` is a NSID or the `*` wildcard.
pub(crate) fn is_nsid_or_wildcard(value: &str) -> bool {
    value == "*" || is_nsid(value)
}

fn is_type_slash_subtype(value: &str) -> bool {
    match value.split_once('/') {
        Some((ty, subtype)) => {
            !ty.is_empty() && !subtype.is_empty() && !subtype.contains('/') && !value.contains(' ')
        }
        None => false,
    }
}

/// Whether `value` is a concrete MIME type (no wildcards).
pub(crate) fn is_mime(value: &str) -> bool {
    is_type_slash_subtype(value) && !value.contains('*')
}

/// Whether `value` is a MIME type, `type/*` or `*/*`.
pub(crate) fn is_accept(value: &str) -> bool {
    value == "*/*"
        || is_type_slash_subtype(value) && (!value.contains('*') || value.ends_with("/*"))
}

/// Whether the MIME type `mime` matches the (valid) accept pattern `accept`.
pub(crate) fn matches_accept(accept: &str, mime: &str) -> bool {
    if !is_mime(mime) {
        return false;
    }
    if accept == "*/*" {
        return true;
    }
    match accept.strip_suffix('*') {
        Some(prefix) if accept.ends_with("/*") => mime.starts_with(prefix),
        _ => accept == mime,
    }
}

/// Whether `value` is an atproto DID reference with a fragment, e.g.
/// `did:web:api.example.com#svc` (`AtprotoDidRefAbsolute` in `@atproto/did`).
pub(crate) fn is_atproto_did_ref(value: &str) -> bool {
    let Some((did, fragment)) = value.split_once('#') else {
        return false;
    };
    !fragment.is_empty()
        && !fragment.contains('#')
        && is_fragment(fragment)
        && is_did(did)
        && (is_did_plc(did) || is_atproto_did_web(did))
}

/// Whether `value` is the `*` wildcard or an atproto DID reference.
pub(crate) fn is_aud(value: &str) -> bool {
    value == "*" || is_atproto_did_ref(value)
}

/// RFC 3986 `fragment`.
fn is_fragment(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3);
                if !hex.is_some_and(|h| h.iter().all(u8::is_ascii_hexdigit)) {
                    return false;
                }
                i += 2;
            }
            b if b.is_ascii_alphanumeric() || b"-._~!$&'()*+,;=:@/?".contains(&b) => {}
            _ => return false,
        }
        i += 1;
    }
    true
}

/// W3C DID syntax, as in `@atproto/did`.
fn is_did(value: &str) -> bool {
    let Some(rest) = value.strip_prefix("did:") else {
        return false;
    };
    let Some((method, msid)) = rest.split_once(':') else {
        return false;
    };
    value.len() <= 2048
        && !method.is_empty()
        && method
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && is_did_msid(msid)
}

/// A DID method-specific identifier. Percent escapes must use uppercase hex.
fn is_did_msid(msid: &str) -> bool {
    let bytes = msid.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' => {
                let hex = bytes.get(i + 1..i + 3);
                let upper_hex = |b: &u8| b.is_ascii_digit() || (b'A'..=b'F').contains(b);
                if !hex.is_some_and(|h| h.iter().all(upper_hex)) {
                    return false;
                }
                i += 2;
            }
            b':' if i == bytes.len() - 1 => return false,
            b if b.is_ascii_alphanumeric() || b"._-:".contains(&b) => {}
            _ => return false,
        }
        i += 1;
    }
    !bytes.is_empty()
}

fn is_did_plc(did: &str) -> bool {
    did.len() == 32
        && did.strip_prefix("did:plc:").is_some_and(|id| {
            id.bytes()
                .all(|b| b.is_ascii_lowercase() || (b'2'..=b'7').contains(&b))
        })
}

/// A `did:web` that atproto allows: no path, and no port except on localhost.
fn is_atproto_did_web(did: &str) -> bool {
    let Some(msid) = did.strip_prefix("did:web:") else {
        return false;
    };
    if msid.starts_with(':') || !is_did_msid(msid) || msid.contains(':') {
        return false;
    }
    let localhost = msid == "localhost" || msid.starts_with("localhost%3A");
    if !localhost && msid.contains("%3A") {
        return false;
    }
    // The DID must also map to a parseable URL, as in `buildDidWebUrl`.
    let host = msid.replace("%3A", ":");
    let scheme = match host.strip_prefix("localhost") {
        Some(rest) if rest.is_empty() || rest.starts_with(':') => "http",
        _ => "https",
    };
    url::Url::parse(&format!("{scheme}://{host}")).is_ok()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn syntax(scope: &str, resource: &str) -> Syntax {
        Syntax::from_scope(scope, resource).unwrap()
    }

    fn query(s: &Syntax, key: &str) -> Option<Vec<String>> {
        s.get(key).and_then(Param::multi).map(<[String]>::to_vec)
    }

    // Vectors from the reference `lib/syntax-string.test.ts` and indigo's
    // `generic_scopes_valid.json`, de-duplicated.
    #[test]
    fn splits_scope_strings() {
        type Case<'a> = (
            &'a str,
            &'a str,
            Option<&'a str>,
            &'a [(&'a str, &'a [&'a str])],
        );
        let cases: &[Case] = &[
            ("my-res", "my-res", None, &[]),
            ("my-res:my-pos", "my-res", Some("my-pos"), &[]),
            ("my-res:", "my-res", Some(""), &[]),
            ("my-res:?", "my-res", Some(""), &[]),
            ("my-res?", "my-res", None, &[]),
            ("my-res:&", "my-res", Some("&"), &[]),
            ("my-res:my:pos", "my-res", Some("my:pos"), &[]),
            ("my-res:my%20pos", "my-res", Some("my pos"), &[]),
            (
                "my-res?x=my%20value",
                "my-res",
                None,
                &[("x", &["my value"])],
            ),
            ("my-res?x=a+b", "my-res", None, &[("x", &["a b"])]),
            (
                "my-res:foo?x=value&y=value-y",
                "my-res",
                Some("foo"),
                &[("x", &["value"]), ("y", &["value-y"])],
            ),
            (
                "my-res?x=value&y=value-y",
                "my-res",
                None,
                &[("x", &["value"]), ("y", &["value-y"])],
            ),
            (
                "my-res?x=foo&x=bar&x=baz",
                "my-res",
                None,
                &[("x", &["foo", "bar", "baz"])],
            ),
            (
                "my-res:pos?thing&key=val",
                "my-res",
                Some("pos"),
                &[("thing", &[""]), ("key", &["val"])],
            ),
            (
                "my-res:pos?&&key=val&&",
                "my-res",
                Some("pos"),
                &[("key", &["val"])],
            ),
            (
                "my-res:pos??key=val",
                "my-res",
                Some("pos"),
                &[("key", &["val"])],
            ),
            ("res:pos?p=true", "res", Some("pos"), &[("p", &["true"])]),
            (
                "service:did:web:com.example#type?key=val",
                "service",
                Some("did:web:com.example#type"),
                &[("key", &["val"])],
            ),
            (
                "rpc:foo.bar?aud=did:foo:bar?lxm=bar.baz",
                "rpc",
                Some("foo.bar"),
                &[("aud", &["did:foo:bar?lxm=bar.baz"])],
            ),
        ];
        for (scope, resource, positional, params) in cases {
            let s = syntax(scope, resource);
            assert_eq!(s.positional.as_deref(), *positional, "{scope}");
            assert_eq!(s.params.len(), params.len(), "{scope}");
            for (key, values) in *params {
                assert_eq!(query(&s, key).unwrap(), *values, "{scope} {key}");
                let single = s.get(key).and_then(Param::single);
                assert_eq!(
                    single,
                    (values.len() == 1).then(|| values[0]),
                    "{scope} {key}"
                );
            }
            assert!(s.get("nonexistent").is_none());
        }
    }

    #[test]
    fn rejects_other_resources_and_bad_escapes() {
        for (scope, resource) in [
            ("prefix", "prefi"),
            ("prefix:pos", "prefi"),
            ("prefix?param=value", "prefi"),
            ("prefix", "fix"),
            ("prefix", "differentResource"),
            ("repo:%", "repo"),
            ("repo:%4", "repo"),
            ("repo:%zz", "repo"),
            ("repo:%C3", "repo"),
            // Regression: a sign is not a hex digit.
            ("repo:%+B", "repo"),
            ("repo:%-1", "repo"),
            ("repo:%+", "repo"),
            ("repo:%C0%80", "repo"),
            ("repo:%ED%A0%80", "repo"),
        ] {
            assert!(Syntax::from_scope(scope, resource).is_none(), "{scope}");
        }
        for (scope, resource) in [
            ("prefix", "prefix"),
            ("prefix:p", "prefix"),
            ("prefix?a=b", "prefix"),
        ] {
            assert!(Syntax::from_scope(scope, resource).is_some(), "{scope}");
        }
        // Query escapes are lenient, like URLSearchParams.
        let s = syntax("res?x=%zz&y=%C3", "res");
        assert_eq!(query(&s, "x").unwrap(), ["%zz"]);
        assert_eq!(query(&s, "y").unwrap(), ["\u{fffd}"]);
    }

    #[test]
    fn formats_like_the_reference() {
        assert_eq!(format("res", None, &[]), "res");
        assert_eq!(format("res", Some(""), &[]), "res:");
        assert_eq!(
            format("rpc", Some("a.b.c"), &[("aud", "did:web:x.com#svc")]),
            "rpc:a.b.c?aud=did:web:x.com%23svc"
        );
        assert_eq!(
            format("blob", Some("image/svg+xml"), &[]),
            "blob:image/svg+xml"
        );
        assert_eq!(
            format("res", Some("a b?&#é"), &[]),
            "res:a%20b%3F%26%23%C3%A9"
        );
        assert_eq!(
            format("res", None, &[("x", "a b~'!()")]),
            "res?x=a+b%7E%27%21%28%29"
        );
        // Like the reference, `%` and `+` stay readable when they decode back
        // to themselves...
        assert_eq!(
            format("res", None, &[("x", "50%"), ("y", "%zz")]),
            "res?x=50%&y=%zz"
        );
        assert_eq!(format("res", Some("a+b"), &[]), "res:a+b");
        // ...but unlike it, are escaped when they would not.
        assert_eq!(format("res", Some("50%"), &[]), "res:50%25");
        assert_eq!(format("res", Some("%3A"), &[]), "res:%253A");
        assert_eq!(
            format(
                "res",
                None,
                &[("x", "image/svg+xml"), ("y", "%3A"), ("z", "% é")]
            ),
            "res?x=image/svg%2Bxml&y=%253A&z=%+%C3%A9"
        );
    }

    #[test]
    fn format_round_trips_arbitrary_values() {
        let values = [
            "",
            "a b",
            "+",
            "%",
            "%25",
            "?&=#",
            "é☺",
            "did:web:localhost%3A3000#x",
        ];
        for value in values {
            let s = syntax(&format("res", Some(value), &[("k", value)]), "res");
            assert_eq!(s.positional.as_deref(), Some(value));
            assert_eq!(query(&s, "k").unwrap(), [value]);
        }
    }

    #[test]
    fn js_sort_order_is_utf16() {
        // U+FF61 sorts after U+10000 by code point but before it in UTF-16.
        assert_eq!(js_cmp("\u{ff61}", "\u{10000}"), Ordering::Greater);
        assert_eq!(js_cmp("B", "a"), Ordering::Less);
        assert_eq!(
            sorted_unique(&["b".into(), "a".into(), "b".into()]),
            ["a", "b"]
        );
        assert_eq!(unique(&[2, 1, 2, 3, 1]), [2, 1, 3]);
        assert!(same_values(&[1, 2, 2], &[2, 1]));
        assert!(!same_values(&[1, 2], &[1]));
    }

    // Vectors from the reference `lib/mime.test.ts` and indigo's
    // `TestValidBlobAccept`.
    #[test]
    fn mime_and_accept() {
        for v in [
            "image/png",
            "application/json",
            "text/html",
            "text/plain",
            "image/*",
            "text/*",
            "*/*",
        ] {
            assert!(is_accept(v), "{v}");
        }
        for v in [
            "",
            "image//png",
            "/png",
            "/plain",
            "image/",
            "text/",
            "image/**",
            "text/**",
            "*/png",
            "*",
            "image/png/extra",
        ] {
            assert!(!is_accept(v), "{v}");
        }
        for v in ["image/png", "application/json"] {
            assert!(is_mime(v), "{v}");
        }
        for v in [
            "image/*",
            "*/*",
            "image/png/extra",
            "*/mime",
            "/png",
            "image/",
            "image",
            "image/ png",
            "image//png",
        ] {
            assert!(!is_mime(v), "{v}");
        }
        for (accept, mime) in [
            ("image/png", "image/png"),
            ("image/*", "image/jpeg"),
            ("image/*", "image/gif"),
            ("*/*", "application/json"),
        ] {
            assert!(matches_accept(accept, mime), "{accept} {mime}");
        }
        for (accept, mime) in [
            ("image/png", "image/jpeg"),
            ("image/*", "text/html"),
            ("image/png", "*/mime"),
            ("image/png", "image"),
            ("image/*", "image//png"),
            ("image/*", "image/ png"),
            ("*/*", "image/"),
            ("*/*", "/mime"),
            ("image/*", "imagex/png"),
            ("image/png", "IMAGE/PNG"),
        ] {
            assert!(!matches_accept(accept, mime), "{accept} {mime}");
        }
    }

    #[test]
    fn atproto_did_refs() {
        for v in [
            "did:web:example.com#service_id",
            "did:web:api.example.com#svc_appview",
            "did:web:EXAMPLE.com#x",
            "did:web:localhost#x",
            "did:web:localhost%3A3000#x",
            "did:web:%41.com#x",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa#x",
            "did:plc:abcdefghijklmnopqrstuvwx#atproto_labeler",
            "did:web:example.com#a/b?c:d@e!$&'()*+,;=%2f",
        ] {
            assert!(is_atproto_did_ref(v), "{v}");
        }
        for v in [
            "did:web:example.com",
            "did:web:example.com#",
            "did:web:example.com#a#b",
            "did:web:example.com#a b",
            "did:web:example.com#%2",
            "did:web#x",
            "did:web:#x",
            "did:web::example.com#x",
            "did:web:example.com:path#x",
            "did:web:example.com%3A443#x",
            "did:web:localhost:path#x",
            "did:web:localhost%3A99999#x",
            "did:web:example.123#x",
            "did:web:exa%2Fmple.com#x",
            "did:web:a%3a#x",
            "did:web:a%#x",
            "did:plc:111#x",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaa1#x",
            "did:plc:aaaaaaaaaaaaaaaaaaaaaaaaa#x",
            "did:foo:bar#x",
            "did:WEB:example.com#x",
            "invalid#x",
            "#x",
            "",
        ] {
            assert!(!is_atproto_did_ref(v), "{v}");
        }
        // Hosts that the WHATWG URL standard rejects (Node accepts these
        // punycode labels; shrike follows the standard and refuses them).
        assert!(!is_atproto_did_ref("did:web:xn--a.com#x"));
        assert!(!is_atproto_did_ref("did:web:xn--.com#x"));
        assert!(is_aud("*"));
        assert!(!is_aud("**"));
    }
}
