//! XRPC query parameters.
//!
//! Arrays are repeated keys (`?uris=a&uris=b`). Bracketed keys (`uris[]=a`,
//! `uris[0]=a`), as sent by `qs`-style clients, are folded into the plain key
//! after any plain values, and empty values are ignored, as in the reference.

use serde::de::{self, DeserializeOwned, IntoDeserializer, Visitor};
use serde_json::{Map, Value};

use crate::lexicon::{FieldSchema, ParamsDef};
use crate::xrpc_server::error::ServerError;

/// Decoded query parameters for one request.
///
/// With a lexicon, [`Params::json`] holds the values decoded by their
/// declared types and validated, with defaults applied; undeclared keys are
/// kept as strings (or arrays of strings). Without one, values stay strings
/// until [`Params::deserialize`] parses them for the target type.
#[derive(Debug, Clone, Default)]
pub struct Params {
    /// `(key, values)` in first-seen key order.
    entries: Vec<(String, Vec<String>)>,
    json: Option<Map<String, Value>>,
}

impl Params {
    /// Parse a raw query string (without the leading `?`).
    pub fn from_query(query: &str) -> Self {
        let mut plain: Vec<(String, Vec<String>)> = Vec::new();
        let mut bracketed: Vec<(String, String)> = Vec::new();
        for (key, value) in url::form_urlencoded::parse(query.as_bytes()) {
            if value.is_empty() {
                continue;
            }
            match strip_brackets(&key) {
                Some(base) => bracketed.push((base.to_owned(), value.into_owned())),
                None => push(&mut plain, key.into_owned(), value.into_owned()),
            }
        }
        for (key, value) in bracketed {
            push(&mut plain, key, value);
        }
        Params {
            entries: plain,
            json: None,
        }
    }

    /// The first value for `key`.
    pub fn get(&self, key: &str) -> Option<&str> {
        self.get_all(key).first().map(String::as_str)
    }

    /// Every value for `key`, in order.
    pub fn get_all(&self, key: &str) -> &[String] {
        self.entries
            .iter()
            .find(|(k, _)| k == key)
            .map_or(&[], |(_, v)| v.as_slice())
    }

    /// Whether no parameters were given.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty() && self.json.as_ref().is_none_or(Map::is_empty)
    }

    /// The lexicon-decoded and validated values, if the method has a lexicon.
    pub fn json(&self) -> Option<&Map<String, Value>> {
        self.json.as_ref()
    }

    /// Deserialize into a parameters type, e.g. a generated `*Params` struct.
    ///
    /// Failures are 400 `InvalidRequest`.
    pub fn deserialize<T: DeserializeOwned>(&self) -> Result<T, ServerError> {
        let result = match &self.json {
            Some(json) => {
                serde_json::from_value(Value::Object(json.clone())).map_err(|e| e.to_string())
            }
            None => {
                T::deserialize(ParamsDe(&self.entries)).map_err(|e: de::value::Error| e.to_string())
            }
        };
        result.map_err(|e| ServerError::invalid_request(format!("Invalid params: {e}")))
    }

    /// Decode values by their declared lexicon types: integers must match
    /// `-?[0-9]+`, booleans must be `true` or `false`, and a declared scalar
    /// takes exactly one value. Validation is separate
    /// ([`crate::lexicon::validate_params`]).
    pub(crate) fn decode(&self, def: Option<&ParamsDef>) -> Result<Map<String, Value>, String> {
        let mut out = Map::new();
        for (key, values) in &self.entries {
            let value = match def.and_then(|d| d.properties.get(key)) {
                Some(FieldSchema::Array { items, .. }) => Value::Array(
                    values
                        .iter()
                        .map(|v| decode_scalar(key, items, v))
                        .collect::<Result<_, _>>()?,
                ),
                Some(field) => match values.as_slice() {
                    [single] => decode_scalar(key, field, single)?,
                    _ => return Err(format!("{key} must be a single value")),
                },
                None => match values.as_slice() {
                    [single] => Value::String(single.clone()),
                    many => Value::Array(many.iter().cloned().map(Value::String).collect()),
                },
            };
            out.insert(key.clone(), value);
        }
        Ok(out)
    }

    pub(crate) fn set_json(&mut self, json: Map<String, Value>) {
        self.json = Some(json);
    }
}

fn push(entries: &mut Vec<(String, Vec<String>)>, key: String, value: String) {
    match entries.iter_mut().find(|(k, _)| *k == key) {
        Some((_, values)) => values.push(value),
        None => entries.push((key, vec![value])),
    }
}

/// `name[]` or `name[123]` → `name`.
fn strip_brackets(key: &str) -> Option<&str> {
    let inner = key.strip_suffix(']')?;
    let (base, index) = inner.split_once('[')?;
    (!base.contains('[') && index.bytes().all(|b| b.is_ascii_digit())).then_some(base)
}

fn decode_scalar(key: &str, field: &FieldSchema, raw: &str) -> Result<Value, String> {
    Ok(match field {
        FieldSchema::Integer { .. } => {
            Value::from(parse_int::<i64>(raw).ok_or_else(|| format!("{key} must be an integer"))?)
        }
        FieldSchema::Boolean { .. } => {
            Value::Bool(parse_bool(raw).ok_or_else(|| format!("{key} must be a boolean"))?)
        }
        _ => Value::String(raw.to_owned()),
    })
}

fn parse_bool(raw: &str) -> Option<bool> {
    match raw {
        "true" => Some(true),
        "false" => Some(false),
        _ => None,
    }
}

/// Strict integer syntax: an optional `-` and ASCII digits, nothing else.
fn parse_int<T: std::str::FromStr>(raw: &str) -> Option<T> {
    let digits = raw.strip_prefix('-').unwrap_or(raw);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    raw.parse().ok()
}

/// Deserializes a struct or map from the raw query entries.
struct ParamsDe<'a>(&'a [(String, Vec<String>)]);

impl<'de, 'a: 'de> de::Deserializer<'de> for ParamsDe<'a> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_map(de::value::MapDeserializer::new(
            self.0.iter().map(|(k, v)| (k.as_str(), ValuesDe(v))),
        ))
    }

    fn deserialize_unit<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_unit()
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    serde::forward_to_deserialize_any! {
        bool i8 i16 i32 i64 i128 u8 u16 u32 u64 u128 f32 f64 char str string
        bytes byte_buf option seq tuple tuple_struct map struct enum identifier
        ignored_any
    }
}

/// Every value for one key. Scalars require exactly one value; sequences
/// take them all.
struct ValuesDe<'a>(&'a [String]);

impl<'a> ValuesDe<'a> {
    fn single(&self) -> Result<StrDe<'a>, de::value::Error> {
        match self.0 {
            [one] => Ok(StrDe(one)),
            _ => Err(de::Error::custom("expected a single value")),
        }
    }
}

impl<'de, 'a: 'de> IntoDeserializer<'de, de::value::Error> for ValuesDe<'a> {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

macro_rules! forward_to_single {
    ($($method:ident)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            self.single()?.$method(visitor)
        }
    )*};
}

impl<'de, 'a: 'de> de::Deserializer<'de> for ValuesDe<'a> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0 {
            [one] => visitor.visit_borrowed_str(one),
            _ => self.deserialize_seq(visitor),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_some(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_seq(de::value::SeqDeserializer::new(
            self.0.iter().map(|s| StrDe(s)),
        ))
    }

    fn deserialize_tuple<V: Visitor<'de>>(
        self,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_tuple_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _len: usize,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.deserialize_seq(visitor)
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        name: &'static str,
        variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.single()?.deserialize_enum(name, variants, visitor)
    }

    fn deserialize_unit_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.single()?.deserialize_unit_struct(name, visitor)
    }

    fn deserialize_struct<V: Visitor<'de>>(
        self,
        name: &'static str,
        fields: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        self.single()?.deserialize_struct(name, fields, visitor)
    }

    forward_to_single! {
        deserialize_bool deserialize_i8 deserialize_i16 deserialize_i32 deserialize_i64
        deserialize_i128 deserialize_u8 deserialize_u16 deserialize_u32 deserialize_u64
        deserialize_u128 deserialize_f32 deserialize_f64 deserialize_char deserialize_str
        deserialize_string deserialize_bytes deserialize_byte_buf deserialize_unit
        deserialize_map deserialize_identifier
    }

    fn deserialize_ignored_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        // Unknown params may repeat.
        visitor.visit_unit()
    }
}

/// One raw string value, parsed as whatever type is requested.
struct StrDe<'a>(&'a str);

impl<'de, 'a: 'de> IntoDeserializer<'de, de::value::Error> for StrDe<'a> {
    type Deserializer = Self;
    fn into_deserializer(self) -> Self {
        self
    }
}

macro_rules! parse_number {
    ($($method:ident $visit:ident $ty:ty)*) => {$(
        fn $method<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            match parse_int::<$ty>(self.0) {
                Some(n) => visitor.$visit(n),
                None => Err(de::Error::invalid_value(de::Unexpected::Str(self.0), &visitor)),
            }
        }
    )*};
}

impl<'de, 'a: 'de> de::Deserializer<'de> for StrDe<'a> {
    type Error = de::value::Error;

    fn deserialize_any<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_borrowed_str(self.0)
    }

    fn deserialize_bool<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match parse_bool(self.0) {
            Some(b) => visitor.visit_bool(b),
            None => Err(de::Error::invalid_value(
                de::Unexpected::Str(self.0),
                &visitor,
            )),
        }
    }

    parse_number! {
        deserialize_i8 visit_i8 i8
        deserialize_i16 visit_i16 i16
        deserialize_i32 visit_i32 i32
        deserialize_i64 visit_i64 i64
        deserialize_i128 visit_i128 i128
        deserialize_u8 visit_u8 u8
        deserialize_u16 visit_u16 u16
        deserialize_u32 visit_u32 u32
        deserialize_u64 visit_u64 u64
        deserialize_u128 visit_u128 u128
    }

    fn deserialize_f32<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        self.deserialize_f64(visitor)
    }

    fn deserialize_f64<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        match self.0.parse::<f64>() {
            Ok(f) if f.is_finite() => visitor.visit_f64(f),
            _ => Err(de::Error::invalid_value(
                de::Unexpected::Str(self.0),
                &visitor,
            )),
        }
    }

    fn deserialize_option<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_some(self)
    }

    fn deserialize_seq<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
        visitor.visit_seq(de::value::SeqDeserializer::new(std::iter::once(self)))
    }

    fn deserialize_newtype_struct<V: Visitor<'de>>(
        self,
        _name: &'static str,
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_newtype_struct(self)
    }

    fn deserialize_enum<V: Visitor<'de>>(
        self,
        _name: &'static str,
        _variants: &'static [&'static str],
        visitor: V,
    ) -> Result<V::Value, Self::Error> {
        visitor.visit_enum(self.0.into_deserializer())
    }

    serde::forward_to_deserialize_any! {
        char str string bytes byte_buf unit unit_struct tuple tuple_struct map struct
        identifier ignored_any
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use http::StatusCode;
    use serde::Deserialize;
    use serde_json::json;

    fn entries(p: &Params) -> Vec<(&str, Vec<&str>)> {
        p.entries
            .iter()
            .map(|(k, v)| (k.as_str(), v.iter().map(String::as_str).collect()))
            .collect()
    }

    fn raw(pairs: &[(&str, &[&str])]) -> Params {
        Params {
            entries: pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.iter().map(|s| s.to_string()).collect()))
                .collect(),
            json: None,
        }
    }

    fn def(schema: serde_json::Value) -> ParamsDef {
        serde_json::from_value(schema).unwrap()
    }

    #[test]
    fn from_query_repeated_keys() {
        let p = Params::from_query("str=hello&arr=one&arr=two");
        assert_eq!(
            entries(&p),
            vec![("str", vec!["hello"]), ("arr", vec!["one", "two"])]
        );
        assert_eq!(p.get("arr"), Some("one"));
        assert_eq!(p.get_all("arr"), ["one", "two"]);
        assert_eq!(p.get("missing"), None);
        assert!(p.get_all("missing").is_empty());
        assert!(!p.is_empty());
    }

    #[test]
    fn from_query_many_repeated_values() {
        let did = "did:plc:t76alsfrlr2zewmi2nsy6rls";
        let query = vec![format!("dids={did}"); 21].join("&");
        let p = Params::from_query(&query);
        assert_eq!(p.get_all("dids").len(), 21);
        assert!(p.get_all("dids").iter().all(|d| d == did));
    }

    #[test]
    fn from_query_bracket_folding() {
        let cases: &[(&str, &[&str])] = &[
            ("str=hello&arr[]=one&arr[]=two", &["one", "two"]),
            ("str=hello&arr[0]=one&arr[1]=two", &["one", "two"]),
            ("str=hello&arr[4]=one&arr[9]=two", &["one", "two"]),
            ("str=hello&arr=one&arr=two", &["one", "two"]),
            ("str=hello&arr[]=only", &["only"]),
            ("str=hello&arr[0]=only", &["only"]),
            ("str=hello&arr%5B%5D=enc", &["enc"]),
        ];
        for (query, arr) in cases {
            let p = Params::from_query(query);
            assert_eq!(p.get_all("str"), ["hello"], "{query}");
            assert_eq!(p.get_all("arr"), *arr, "{query}");
            assert!(p.get_all("arr[]").is_empty(), "{query}");
            assert!(p.get_all("arr[0]").is_empty(), "{query}");
        }
    }

    #[test]
    fn from_query_bracketed_values_follow_plain_ones() {
        let p = Params::from_query("arr[]=b&arr=a&str=s&arr[1]=c&arr=d");
        assert_eq!(
            entries(&p),
            vec![("arr", vec!["a", "d", "b", "c"]), ("str", vec!["s"])]
        );

        let p = Params::from_query("only[]=x&str=s");
        assert_eq!(entries(&p), vec![("str", vec!["s"]), ("only", vec!["x"])]);
    }

    #[test]
    fn from_query_non_index_brackets_not_folded() {
        let p = Params::from_query("a[b]=1&a[1x]=2&a[1][2]=3&a[-1]=4&a]=5&[]=6");
        assert_eq!(
            entries(&p),
            vec![
                ("a[b]", vec!["1"]),
                ("a[1x]", vec!["2"]),
                ("a[1][2]", vec!["3"]),
                ("a[-1]", vec!["4"]),
                ("a]", vec!["5"]),
                ("", vec!["6"]),
            ]
        );
        assert!(p.get_all("a").is_empty());
    }

    #[test]
    fn from_query_ignores_empty_values() {
        let p = Params::from_query("a=&b=1&a=2&c&arr[]=&d=");
        assert_eq!(entries(&p), vec![("b", vec!["1"]), ("a", vec!["2"])]);
        assert!(Params::from_query("").is_empty());
        assert!(Params::from_query("a=&b=").is_empty());
        assert!(Params::default().is_empty());
    }

    #[test]
    fn from_query_percent_and_plus_decoding() {
        let p = Params::from_query("q=hello+world&r=a%20b%2Bc&k%65y=%E2%9C%93&u=at%3A%2F%2Fdid");
        assert_eq!(p.get("q"), Some("hello world"));
        assert_eq!(p.get("r"), Some("a b+c"));
        assert_eq!(p.get("key"), Some("\u{2713}"));
        assert_eq!(p.get("u"), Some("at://did"));
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Ints {
        n: i64,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct OptInt {
        n: Option<i64>,
    }

    #[test]
    fn deserialize_strict_integers() {
        assert_eq!(
            Params::from_query("n=5").deserialize::<Ints>().unwrap(),
            Ints { n: 5 }
        );
        assert_eq!(
            Params::from_query("n=-5").deserialize::<Ints>().unwrap(),
            Ints { n: -5 }
        );
        assert_eq!(
            Params::from_query("n=007").deserialize::<Ints>().unwrap(),
            Ints { n: 7 }
        );
        for bad in [
            "%2B5", "5abc", "1.9", "-", "--5", "abc", "1e3", "0x10", "%205", "5%20",
        ] {
            let err = Params::from_query(&format!("n={bad}"))
                .deserialize::<Ints>()
                .unwrap_err();
            assert_eq!(err.status_code(), StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(err.error_name(), Some("InvalidRequest"));
            assert!(
                err.message().unwrap().starts_with("Invalid params:"),
                "{bad}"
            );
        }
        assert!(raw(&[("n", &[""])]).deserialize::<Ints>().is_err());
    }

    #[test]
    fn deserialize_integer_ranges() {
        let max = i64::MAX.to_string();
        assert_eq!(
            Params::from_query(&format!("n={max}"))
                .deserialize::<Ints>()
                .unwrap(),
            Ints { n: i64::MAX }
        );
        let min = i64::MIN.to_string();
        assert_eq!(
            Params::from_query(&format!("n={min}"))
                .deserialize::<Ints>()
                .unwrap(),
            Ints { n: i64::MIN }
        );
        assert!(
            Params::from_query("n=9223372036854775808")
                .deserialize::<Ints>()
                .is_err()
        );
        assert!(
            Params::from_query("n=-9223372036854775809")
                .deserialize::<Ints>()
                .is_err()
        );

        #[derive(Deserialize)]
        struct Small {
            #[allow(dead_code)]
            n: u8,
        }
        assert!(Params::from_query("n=255").deserialize::<Small>().is_ok());
        assert!(Params::from_query("n=256").deserialize::<Small>().is_err());
        assert!(Params::from_query("n=-1").deserialize::<Small>().is_err());
    }

    #[test]
    fn deserialize_strict_booleans() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct B {
            b: bool,
        }
        assert_eq!(
            Params::from_query("b=true").deserialize::<B>().unwrap(),
            B { b: true }
        );
        assert_eq!(
            Params::from_query("b=false").deserialize::<B>().unwrap(),
            B { b: false }
        );
        for bad in ["True", "TRUE", "1", "0", "yes", "foo", "t"] {
            assert!(
                Params::from_query(&format!("b={bad}"))
                    .deserialize::<B>()
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn deserialize_option_fields() {
        assert_eq!(
            Params::from_query("").deserialize::<OptInt>().unwrap(),
            OptInt { n: None }
        );
        assert_eq!(
            Params::from_query("n=").deserialize::<OptInt>().unwrap(),
            OptInt { n: None }
        );
        assert_eq!(
            Params::from_query("n=3").deserialize::<OptInt>().unwrap(),
            OptInt { n: Some(3) }
        );
        assert!(Params::from_query("n=x").deserialize::<OptInt>().is_err());
        assert!(Params::from_query("").deserialize::<Ints>().is_err());
    }

    #[test]
    fn deserialize_vecs() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct V {
            #[serde(default)]
            s: Vec<String>,
            #[serde(default)]
            n: Vec<i64>,
            o: Option<Vec<String>>,
        }
        assert_eq!(
            Params::from_query("s=a").deserialize::<V>().unwrap(),
            V {
                s: vec!["a".into()],
                n: vec![],
                o: None
            }
        );
        assert_eq!(
            Params::from_query("s=a&n=1&s=b&n=-2&o=x&o=y")
                .deserialize::<V>()
                .unwrap(),
            V {
                s: vec!["a".into(), "b".into()],
                n: vec![1, -2],
                o: Some(vec!["x".into(), "y".into()]),
            }
        );
        assert_eq!(
            Params::from_query("o=x").deserialize::<V>().unwrap().o,
            Some(vec!["x".into()])
        );
        assert_eq!(
            Params::from_query("s[]=a&s[0]=b")
                .deserialize::<V>()
                .unwrap()
                .s,
            vec!["a".to_string(), "b".to_string()]
        );
        assert!(Params::from_query("n=1&n=two").deserialize::<V>().is_err());
    }

    #[test]
    fn deserialize_repeated_scalar_is_error() {
        let err = Params::from_query("n=1&n=2")
            .deserialize::<Ints>()
            .unwrap_err();
        assert_eq!(err.status_code(), StatusCode::BAD_REQUEST);
        #[derive(Debug, Deserialize)]
        struct S {
            #[allow(dead_code)]
            s: String,
        }
        assert!(Params::from_query("s=a&s=b").deserialize::<S>().is_err());
        assert!(Params::from_query("s=a&s[]=b").deserialize::<S>().is_err());
    }

    #[test]
    fn deserialize_ignores_unknown_keys() {
        assert_eq!(
            Params::from_query("n=1&other=x")
                .deserialize::<Ints>()
                .unwrap(),
            Ints { n: 1 }
        );
        assert_eq!(
            Params::from_query("n=1&other=x&other=y&z[]=1")
                .deserialize::<Ints>()
                .unwrap(),
            Ints { n: 1 }
        );
    }

    #[test]
    fn deserialize_camel_case_and_enums() {
        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(rename_all = "lowercase")]
        enum Sort {
            Top,
            Latest,
        }
        #[derive(Debug, Deserialize, PartialEq)]
        #[serde(rename_all = "camelCase")]
        struct P {
            include_pins: Option<bool>,
            sort: Option<Sort>,
            #[serde(default)]
            sorts: Vec<Sort>,
        }
        assert_eq!(
            Params::from_query("includePins=true&sort=latest&sorts=top&sorts=latest")
                .deserialize::<P>()
                .unwrap(),
            P {
                include_pins: Some(true),
                sort: Some(Sort::Latest),
                sorts: vec![Sort::Top, Sort::Latest],
            }
        );
        assert_eq!(
            Params::from_query("include_pins=true")
                .deserialize::<P>()
                .unwrap()
                .include_pins,
            None
        );
        assert!(Params::from_query("sort=bogus").deserialize::<P>().is_err());
        assert!(Params::from_query("sort=Top").deserialize::<P>().is_err());
        assert!(
            Params::from_query("sort=top&sort=latest")
                .deserialize::<P>()
                .is_err()
        );
    }

    #[test]
    fn deserialize_floats() {
        #[derive(Debug, Deserialize, PartialEq)]
        struct F {
            f: f64,
        }
        assert_eq!(
            Params::from_query("f=1.5").deserialize::<F>().unwrap(),
            F { f: 1.5 }
        );
        assert_eq!(
            Params::from_query("f=-2").deserialize::<F>().unwrap(),
            F { f: -2.0 }
        );
        for bad in ["abc", "inf", "NaN", "1.5x"] {
            assert!(
                Params::from_query(&format!("f={bad}"))
                    .deserialize::<F>()
                    .is_err(),
                "{bad}"
            );
        }
    }

    #[test]
    fn deserialize_untyped() {
        let v: serde_json::Value = Params::from_query("a=1&b=x&b=y").deserialize().unwrap();
        assert_eq!(v, json!({"a": "1", "b": ["x", "y"]}));
        let m: std::collections::HashMap<String, Vec<String>> =
            Params::from_query("a=1&b=x&b=y").deserialize().unwrap();
        assert_eq!(m["a"], vec!["1"]);
        assert_eq!(m["b"], vec!["x", "y"]);
        let () = Params::from_query("a=1").deserialize().unwrap();
    }

    #[test]
    fn deserialize_uses_lexicon_json_when_set() {
        let mut p = Params::from_query("n=not-a-number");
        let mut m = Map::new();
        m.insert("n".into(), json!(42));
        p.set_json(m);
        assert_eq!(p.deserialize::<Ints>().unwrap(), Ints { n: 42 });
        assert_eq!(p.json().unwrap()["n"], json!(42));
    }

    fn test_def() -> ParamsDef {
        def(json!({
            "type": "params",
            "required": ["str"],
            "properties": {
                "str": {"type": "string"},
                "int": {"type": "integer"},
                "bool": {"type": "boolean"},
                "ints": {"type": "array", "items": {"type": "integer"}},
                "bools": {"type": "array", "items": {"type": "boolean"}},
                "tags": {"type": "array", "items": {"type": "string"}}
            }
        }))
    }

    #[test]
    fn decode_with_lexicon() {
        let d = test_def();
        let out = Params::from_query(
            "str=123&int=-5&bool=false&ints=1&ints=2&bools=true&tags=1&extra=3.14&num=1&num=2",
        )
        .decode(Some(&d))
        .unwrap();
        assert_eq!(
            Value::Object(out),
            json!({
                "str": "123",
                "int": -5,
                "bool": false,
                "ints": [1, 2],
                "bools": [true],
                "tags": ["1"],
                "extra": "3.14",
                "num": ["1", "2"],
            })
        );
    }

    #[test]
    fn decode_bracketed_arrays_with_lexicon() {
        let d = test_def();
        let out = Params::from_query("str=s&ints[]=3&ints[]=4")
            .decode(Some(&d))
            .unwrap();
        assert_eq!(out["ints"], json!([3, 4]));
    }

    #[test]
    fn decode_rejects_bad_types() {
        let d = test_def();
        for q in [
            "int=%2B5",
            "int=1.5",
            "int=five",
            "int=99999999999999999999",
            "bool=1",
            "bool=TRUE",
            "ints=1&ints=x",
            "bools=notabool",
        ] {
            assert!(Params::from_query(q).decode(Some(&d)).is_err(), "{q}");
        }
    }

    #[test]
    fn decode_scalar_given_twice_is_error() {
        let d = test_def();
        for q in [
            "str=a&str=b",
            "int=1&int=2",
            "bool=true&bool=false",
            "str=a&str[]=b",
        ] {
            let err = Params::from_query(q).decode(Some(&d)).unwrap_err();
            assert!(err.contains("single value"), "{q}: {err}");
        }
    }

    #[test]
    fn decode_without_lexicon_keeps_strings() {
        let out = Params::from_query("a=1&b=true&b=x").decode(None).unwrap();
        assert_eq!(Value::Object(out), json!({"a": "1", "b": ["true", "x"]}));
    }

    #[cfg(feature = "api")]
    #[test]
    fn deserialize_generated_params() {
        use crate::api::app::bsky::{FeedGetAuthorFeedParams, FeedGetPostsParams};

        let p: FeedGetPostsParams = Params::from_query(
            "uris=at://did:plc:a/app.bsky.feed.post/1&uris=at%3A%2F%2Fdid%3Aplc%3Ab%2Fapp.bsky.feed.post%2F2",
        )
        .deserialize()
        .unwrap();
        assert_eq!(
            p.uris,
            vec![
                "at://did:plc:a/app.bsky.feed.post/1".to_string(),
                "at://did:plc:b/app.bsky.feed.post/2".to_string(),
            ]
        );
        let p: FeedGetPostsParams = Params::from_query("uris=at://x").deserialize().unwrap();
        assert_eq!(p.uris, vec!["at://x".to_string()]);
        let p: FeedGetPostsParams = Params::from_query("").deserialize().unwrap();
        assert!(p.uris.is_empty());

        let p: FeedGetAuthorFeedParams =
            Params::from_query("actor=alice.test&limit=30&includePins=true&cursor=abc")
                .deserialize()
                .unwrap();
        assert_eq!(p.actor, "alice.test");
        assert_eq!(p.limit, Some(30));
        assert_eq!(p.include_pins, Some(true));
        assert_eq!(p.cursor.as_deref(), Some("abc"));
        assert_eq!(p.filter, None);
        assert!(
            Params::from_query("actor=a&limit=30.0")
                .deserialize::<FeedGetAuthorFeedParams>()
                .is_err()
        );
        assert!(
            Params::from_query("limit=1")
                .deserialize::<FeedGetAuthorFeedParams>()
                .is_err()
        );
    }
}
