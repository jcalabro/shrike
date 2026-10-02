//! Conversion between DRISL and the atproto JSON representation.
//!
//! JSON to DRISL follows the reference `@atproto/lex-json` parser in its
//! non-strict mode:
//!
//! - a map whose only key is `$link`, holding a CID string, is a CID link;
//! - a map whose only key is `$bytes`, holding base64 (padded or not), is a
//!   byte string;
//! - every other map, including a malformed `$link` or `$bytes`, stays a plain
//!   map, its keys in canonical order;
//! - numbers must be integers; see [`Integers`].
//!
//! `serde_json` keeps the last value of a duplicated key, as the reference does.
//! [`json_slice_to_drisl`] converts JSON text as [`json_to_drisl`] does after
//! `serde_json::from_slice`, without building a `serde_json::Value`.
//!
//! DRISL to JSON writes bytes as unpadded `$bytes` and CIDs as base32 `$link`.
//! The data model has no floats, so both directions reject them.
//! [`drisl_to_json_into`] writes JSON text straight from DRISL, without
//! building a [`serde_json::Value`].
//!
//! ```
//! use shrike::cbor::json::{Integers, drisl_to_json, json_to_drisl};
//!
//! let json = serde_json::json!({"text": "hi", "raw": {"$bytes": "aGk="}});
//! let bytes = json_to_drisl(&json, Integers::Safe)?;
//! let back = drisl_to_json(&bytes)?;
//! assert_eq!(back, serde_json::json!({"text": "hi", "raw": {"$bytes": "aGk"}}));
//! # Ok::<(), shrike::cbor::CborError>(())
//! ```

use std::cmp::Ordering;
use std::fmt;
use std::io::Write;

use serde::de::{self, DeserializeSeed, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Number, Value as Json};

use super::varint::decode_varint;
use super::{CborError, Cid, Encoder, Value, cbor_key_cmp};

/// The largest integer a JavaScript number holds exactly: 2^53 − 1.
pub const MAX_SAFE_INTEGER: i64 = (1 << 53) - 1;

/// The longest `$link` string parsed as a CID. Longer ones stay plain maps.
pub const MAX_LINK_LEN: usize = 2048;

/// Which JSON integers [`json_to_drisl`] accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Integers {
    /// Only |n| ≤ [`MAX_SAFE_INTEGER`], as the reference requires of records.
    Safe,
    /// Any `i64`.
    Any,
}

/// Convert atproto JSON to canonical DRISL bytes.
///
/// Fails on a float, an integer that `integers` does not allow, or a `$link`
/// holding a well-formed CID that [`Cid`] cannot represent (anything but
/// CIDv1, DRISL or raw, SHA-256).
pub fn json_to_drisl(json: &Json, integers: Integers) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::new();
    encode(&mut Encoder::new(&mut buf), json, integers)?;
    Ok(buf)
}

/// Convert atproto JSON text to canonical DRISL bytes.
///
/// The same as [`json_to_drisl`] over `serde_json::from_slice(json)`, with
/// the same output and errors, but it encodes as it parses instead of
/// building a [`serde_json::Value`]. If that fails, it takes those two steps
/// for their error.
pub fn json_slice_to_drisl(json: &[u8], integers: Integers) -> Result<Vec<u8>, JsonError> {
    match encode_json(json, integers) {
        Some(drisl) => Ok(drisl),
        None => Ok(json_to_drisl(&serde_json::from_slice(json)?, integers)?),
    }
}

/// Why [`json_slice_to_drisl`] failed.
#[derive(Debug, thiserror::Error)]
pub enum JsonError {
    /// `serde_json` cannot parse the input.
    #[error("invalid JSON: {0}")]
    Parse(#[from] serde_json::Error),
    /// The JSON parses, but [`json_to_drisl`] rejects it.
    #[error(transparent)]
    Drisl(#[from] CborError),
}

/// Decode DRISL bytes to atproto JSON.
pub fn drisl_to_json(bytes: &[u8]) -> Result<Json, CborError> {
    value_to_json(&super::decode(bytes)?)
}

/// Convert a decoded DRISL value to atproto JSON.
pub fn value_to_json(value: &Value<'_>) -> Result<Json, CborError> {
    Ok(match value {
        Value::Unsigned(n) if i64::try_from(*n).is_err() => {
            return Err(CborError::DataModel(format!("integer {n} exceeds i64")));
        }
        Value::Unsigned(n) => Json::Number((*n).into()),
        Value::Signed(n) => Json::Number((*n).into()),
        Value::Float(f) => return Err(CborError::DataModel(format!("float {f}"))),
        Value::Bool(b) => Json::Bool(*b),
        Value::Null => Json::Null,
        Value::Text(s) => Json::String((*s).to_owned()),
        Value::Bytes(b) => single("$bytes", data_encoding::BASE64_NOPAD.encode(b)),
        Value::Cid(cid) => single("$link", cid.to_string()),
        Value::Array(items) => {
            Json::Array(items.iter().map(value_to_json).collect::<Result<_, _>>()?)
        }
        Value::Map(entries) => Json::Object(
            entries
                .iter()
                .map(|(k, v)| Ok(((*k).to_owned(), value_to_json(v)?)))
                .collect::<Result<_, CborError>>()?,
        ),
    })
}

/// Convert DRISL bytes to atproto JSON text, appended to `out`: the bytes
/// `serde_json::to_vec(&drisl_to_json(bytes)?)` writes, compact and with each
/// object's keys in bytewise order (unless `serde_json`'s `preserve_order`
/// feature is on), in one pass without building either tree.
///
/// Fails as [`drisl_to_json`] does, leaving `out` as it was.
pub fn drisl_to_json_into(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), CborError> {
    let len = out.len();
    let result = JsonWriter::write_document(bytes, out);
    if result.is_err() {
        out.truncate(len);
    }
    result
}

/// [`drisl_to_json_into`] a buffer, then write it all to `writer`.
pub fn drisl_to_json_writer(bytes: &[u8], mut writer: impl Write) -> Result<(), CborError> {
    let mut out = Vec::new();
    drisl_to_json_into(bytes, &mut out)?;
    Ok(writer.write_all(&out)?)
}

/// Decode `$bytes` base64: the standard alphabet, padded or not.
pub fn decode_base64(s: &str) -> Option<Vec<u8>> {
    crate::base64::decode(s)
}

/// Parse a CID string as `$link` does: CIDv0 (`Q…`), or multibase base32
/// (`b`), base58btc (`z`) or base36 (`k`), at most [`MAX_LINK_LEN`] bytes.
///
/// Fails with [`CborError::InvalidCid`] if the string is malformed or the CID
/// is well-formed but not one [`Cid`] can represent.
pub fn parse_cid(s: &str) -> Result<Cid, CborError> {
    parse_link(s)?.ok_or_else(|| CborError::InvalidCid(format!("malformed CID string {s:?}")))
}

/// Whether `s` is a well-formed CID string of any version, codec or hash, as
/// `multiformats` `CID.parse` accepts it. Used for the lexicon `cid` format.
#[cfg(feature = "lexicon")]
pub(crate) fn is_cid_string(s: &str) -> bool {
    !matches!(parse_link(s), Ok(None))
}

fn single(key: &str, value: String) -> Json {
    let mut map = Map::with_capacity(1);
    map.insert(key.to_owned(), Json::String(value));
    Json::Object(map)
}

/// The state of [`drisl_to_json_into`].
struct JsonWriter<'o> {
    out: &'o mut Vec<u8>,
    /// The first float, an error only once the whole input has decoded, as in
    /// [`drisl_to_json`].
    float: Option<f64>,
}

/// A map entry, `"key":value,`, at `out[start..end]`.
#[derive(Clone, Copy)]
struct Entry<'a> {
    key: &'a [u8],
    start: usize,
    end: usize,
}

/// The most entries of a map kept on the stack while it is written.
const INLINE_ENTRIES: usize = 8;

impl JsonWriter<'_> {
    fn write_document(bytes: &[u8], out: &mut Vec<u8>) -> Result<(), CborError> {
        // JSON is usually about a third longer than DRISL, and sorting a map's
        // entries briefly needs room for a second copy of them. This is only
        // a hint: `out` grows as needed.
        let _ = out.try_reserve(bytes.len().saturating_mul(3).saturating_add(64));
        let mut writer = JsonWriter { out, float: None };
        let mut dec = super::Decoder::new(bytes);
        writer.write_value(&mut dec)?;
        if !dec.is_empty() {
            return Err(CborError::InvalidCbor("trailing data after value".into()));
        }
        match writer.float {
            Some(f) => Err(CborError::DataModel(format!("float {f}"))),
            None => Ok(()),
        }
    }

    /// Each array item and map entry is written with a trailing comma, so the
    /// entries can be reordered as units; the last comma becomes the bracket.
    fn write_value<'a>(&mut self, dec: &mut super::Decoder<'a>) -> Result<(), CborError> {
        use super::decode::Shallow;
        match dec.decode_shallow()? {
            Shallow::Text(text) => write_str(self.out, text),
            Shallow::Scalar(value) => self.write_scalar(value),
            Shallow::Array(len) => {
                self.out.push(b'[');
                for _ in 0..len {
                    self.write_value(dec)?;
                    self.out.push(b',');
                }
                dec.leave();
                self.close(len, b']');
            }
            Shallow::Map(len) => {
                self.out.push(b'{');
                let empty = Entry {
                    key: &[],
                    start: 0,
                    end: 0,
                };
                let mut inline = [empty; INLINE_ENTRIES];
                let mut heap = Vec::new();
                let mut previous = &[][..];
                // DRISL orders keys by length first, so JSON's bytewise order
                // often differs.
                let mut sorted = true;
                let mut last_key = None;
                for i in 0..len {
                    let key = dec.read_map_key_utf8(&mut previous)?;
                    sorted &= last_key.is_none_or(|last| key_cmp(last, key).is_lt());
                    last_key = Some(key);
                    let start = self.out.len();
                    write_str(self.out, key);
                    self.out.push(b':');
                    self.write_value(dec)?;
                    self.out.push(b',');
                    let entry = Entry {
                        key,
                        start,
                        end: self.out.len(),
                    };
                    match inline.get_mut(i) {
                        Some(slot) if len <= INLINE_ENTRIES => *slot = entry,
                        _ => heap.push(entry),
                    }
                }
                dec.leave();
                if !sorted {
                    let entries = if len <= INLINE_ENTRIES {
                        &mut inline[..len]
                    } else {
                        &mut heap[..]
                    };
                    sort_entries(self.out, entries);
                }
                self.close(len, b'}');
            }
        }
        Ok(())
    }

    fn close(&mut self, len: usize, bracket: u8) {
        if len > 0 {
            self.out.pop();
        }
        self.out.push(bracket);
    }

    fn write_scalar(&mut self, value: Value<'_>) {
        let out = &mut *self.out;
        match value {
            Value::Unsigned(n) => write_u64(out, n),
            Value::Signed(n) => {
                if n < 0 {
                    out.push(b'-');
                }
                write_u64(out, n.unsigned_abs());
            }
            Value::Float(f) => {
                self.float.get_or_insert(f);
            }
            Value::Bool(true) => out.extend_from_slice(b"true"),
            Value::Bool(false) => out.extend_from_slice(b"false"),
            Value::Null => out.extend_from_slice(b"null"),
            Value::Text(s) => write_str(out, s.as_bytes()),
            Value::Bytes(bytes) => {
                out.extend_from_slice(br#"{"$bytes":""#);
                let start = out.len();
                let base64 = data_encoding::BASE64_NOPAD;
                out.resize(start + base64.encode_len(bytes.len()), 0);
                if let Some(dst) = out.get_mut(start..) {
                    base64.encode_mut(bytes, dst);
                }
                out.extend_from_slice(br#""}"#);
            }
            Value::Cid(cid) => {
                out.extend_from_slice(br#"{"$link":""#);
                out.extend_from_slice(&cid.to_multibase());
                out.extend_from_slice(br#""}"#);
            }
            // `decode_shallow` yields arrays and maps as `Shallow`.
            Value::Array(_) | Value::Map(_) => {}
        }
    }
}

/// Rewrite a map's entries, which end `out`, in key order: copied in order
/// past the end of `out`, then back over the originals.
fn sort_entries(out: &mut Vec<u8>, entries: &mut [Entry<'_>]) {
    let Some(start) = entries.first().map(|e| e.start) else {
        return;
    };
    let end = out.len();
    entries.sort_unstable_by(|a, b| key_cmp(a.key, b.key));
    for entry in &*entries {
        out.extend_from_within(entry.start..entry.end);
    }
    out.copy_within(end.., start);
    out.truncate(end);
}

/// Bytewise order, mostly settled by the first byte without calling `memcmp`.
fn key_cmp(a: &[u8], b: &[u8]) -> std::cmp::Ordering {
    a.first().cmp(&b.first()).then_with(|| a.cmp(b))
}

fn write_u64(out: &mut Vec<u8>, mut n: u64) {
    let mut digits = [0; 20];
    let mut start = digits.len();
    loop {
        start -= 1;
        digits[start] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 {
            break;
        }
    }
    out.extend_from_slice(&digits[start..]);
}

/// Write UTF-8 `text` as a JSON string, escaped as `serde_json` does: `"` and
/// `\`, the short escapes of backspace, tab, newline, form feed and carriage
/// return, and `\u00xx` for the other control characters.
fn write_str(out: &mut Vec<u8>, text: &[u8]) {
    // Most keys are short and need no escapes: quote them in a buffer.
    let len = text.len();
    if len < 8 {
        let word = short_word(text);
        if first(escapes(word)) == len {
            let mut quoted = [b'"'; 10];
            quoted[1..9].copy_from_slice(&word.to_le_bytes());
            quoted[1 + len] = b'"';
            let start = out.len();
            out.extend_from_slice(&quoted);
            out.truncate(start + len + 2);
            return;
        }
    }
    out.push(b'"');
    let mut rest = text;
    loop {
        let (clean, tail) = rest.split_at(clean_len(rest));
        out.extend_from_slice(clean);
        let Some((&byte, tail)) = tail.split_first() else {
            break;
        };
        match byte {
            b'"' | b'\\' => out.extend_from_slice(&[b'\\', byte]),
            0x08 => out.extend_from_slice(b"\\b"),
            0x09 => out.extend_from_slice(b"\\t"),
            0x0a => out.extend_from_slice(b"\\n"),
            0x0c => out.extend_from_slice(b"\\f"),
            0x0d => out.extend_from_slice(b"\\r"),
            _ => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let (high, low) = (HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 15)]);
                out.extend_from_slice(&[b'\\', b'u', b'0', b'0', high, low]);
            }
        }
        rest = tail;
    }
    out.push(b'"');
}

/// The length of the longest prefix of `bytes` that needs no escapes, read a
/// word at a time: the last word overlaps the one before, and a slice shorter
/// than a word is padded with zeros.
fn clean_len(bytes: &[u8]) -> usize {
    let (words, tail) = bytes.as_chunks::<8>();
    for (i, word) in words.iter().enumerate() {
        let found = escapes(u64::from_le_bytes(*word));
        if found != 0 {
            return i * 8 + first(found);
        }
    }
    match bytes.last_chunk::<8>() {
        _ if tail.is_empty() => bytes.len(),
        Some(last) => bytes.len() - 8 + first(escapes(u64::from_le_bytes(*last))),
        None => first(escapes(short_word(tail))).min(tail.len()),
    }
}

/// The bytes of a slice shorter than eight, then zeros, without a loop.
fn short_word(bytes: &[u8]) -> u64 {
    let len = bytes.len();
    if let (Some(low), Some(high)) = (bytes.first_chunk::<4>(), bytes.last_chunk::<4>()) {
        return u64::from(u32::from_le_bytes(*low))
            | u64::from(u32::from_le_bytes(*high)) << (8 * (len - 4));
    }
    let byte = |i: usize| bytes.get(i).map_or(0, |&b| u64::from(b) << (8 * i));
    byte(0) | byte(len / 2) | byte(len.wrapping_sub(1))
}

/// The high bit of each byte of `word` (little-endian) below 0x20, or `"` or
/// `\`, and perhaps of bytes after the first such byte, but never before.
#[inline(always)]
fn escapes(word: u64) -> u64 {
    const ONES: u64 = u64::from_ne_bytes([1; 8]);
    // `v - 1` sets the high bit of each zero byte of `v`, and `v - 0x20` that
    // of each byte below 0x20; `& !word` drops bytes that had it already. A
    // byte that borrows can set it wrongly in later bytes, never earlier ones.
    let quote = word ^ (ONES * u64::from(b'"'));
    let backslash = word ^ (ONES * u64::from(b'\\'));
    (word.wrapping_sub(ONES * 0x20) | quote.wrapping_sub(ONES) | backslash.wrapping_sub(ONES))
        & !word
        & (ONES * 0x80)
}

/// The index of the first byte `escapes` found, or 8.
fn first(found: u64) -> usize {
    found.trailing_zeros() as usize / 8
}

fn encode<W: Write>(
    enc: &mut Encoder<W>,
    json: &Json,
    integers: Integers,
) -> Result<(), CborError> {
    match json {
        Json::Null => enc.encode_null(),
        Json::Bool(b) => enc.encode_bool(*b),
        Json::Number(n) => enc.encode_i64(integer(n, integers)?),
        Json::String(s) => enc.encode_text(s),
        Json::Array(items) => {
            enc.encode_array_header(items.len() as u64)?;
            items
                .iter()
                .try_for_each(|item| encode(enc, item, integers))
        }
        Json::Object(map) => match special(map)? {
            Some(Special::Cid(cid)) => enc.encode_cid(&cid),
            Some(Special::Bytes(bytes)) => enc.encode_bytes(&bytes),
            None => {
                let mut entries: Vec<_> = map.iter().collect();
                entries.sort_by(|a, b| cbor_key_cmp(a.0, b.0));
                enc.encode_map_header(entries.len() as u64)?;
                for (key, value) in entries {
                    enc.encode_text(key)?;
                    encode(enc, value, integers)?;
                }
                Ok(())
            }
        },
    }
}

fn integer(n: &Number, integers: Integers) -> Result<i64, CborError> {
    // JSON has one number type, so `123.0` and `1e10` are integers by value.
    let value = n.as_i64().or_else(|| {
        n.as_f64()
            .filter(|f| f.fract() == 0.0 && f.abs() <= MAX_SAFE_INTEGER as f64)
            .map(|f| f as i64)
    });
    match (value, integers) {
        (Some(v), Integers::Any) => Ok(v),
        (Some(v), Integers::Safe) if v.unsigned_abs() <= MAX_SAFE_INTEGER.unsigned_abs() => Ok(v),
        (Some(_), Integers::Safe) => Err(CborError::DataModel(format!(
            "{n} is outside the safe integer range"
        ))),
        (None, _) => Err(CborError::DataModel(format!(
            "{n} is not a signed 64-bit integer"
        ))),
    }
}

enum Special {
    Cid(Cid),
    Bytes(Vec<u8>),
}

fn special(map: &Map<String, Json>) -> Result<Option<Special>, CborError> {
    let mut entries = map.iter();
    let (Some((key, Json::String(s))), None) = (entries.next(), entries.next()) else {
        return Ok(None);
    };
    special_member(key.as_bytes(), s)
}

/// What an object whose only member is `key: s` stands for.
fn special_member(key: &[u8], s: &str) -> Result<Option<Special>, CborError> {
    Ok(match key {
        b"$link" => parse_link(s)?.map(Special::Cid),
        b"$bytes" => decode_base64(s).map(Special::Bytes),
        _ => None,
    })
}

/// [`json_slice_to_drisl`] without a `Value`, or `None` if it fails or needs
/// one.
fn encode_json(json: &[u8], integers: Integers) -> Option<Vec<u8>> {
    // Checking all the UTF-8 at once is faster than string by string.
    let text = std::str::from_utf8(json).ok()?;
    let mut writer = DrislWriter {
        out: Vec::with_capacity(json.len()),
        members: Vec::with_capacity(16),
        scratch: Vec::with_capacity(json.len()),
        integers,
    };
    let mut de = serde_json::Deserializer::from_str(text);
    let kind = ValueSeed(&mut writer).deserialize(&mut de).ok()?;
    de.end().ok()?;
    (kind != Encoded::Invalid).then_some(writer.out)
}

/// `serde_json`'s `Value` takes an object whose first key is one of its
/// private tokens for something else: a number (`arbitrary_precision`), or a
/// string to parse as JSON (`raw_value`). [`encode_json`] leaves those to it.
const PRIVATE_KEY: &str = "$serde_json::private::";

/// What a value encoded at the end of [`DrislWriter::out`] is.
#[derive(Clone, Copy, PartialEq)]
enum Encoded {
    /// A string, its UTF-8 from this offset to the end of the value.
    Text(usize),
    Other,
    /// Outside the data model, so [`json_to_drisl`] fails on it, unless a
    /// duplicate key replaces it.
    Invalid,
}

/// An object member in [`DrislWriter::out`]: the encoded key from `start`, its
/// UTF-8 from `key`, then the value from `value` to `end`.
#[derive(Clone, Copy)]
struct Member {
    start: usize,
    key: usize,
    value: usize,
    end: usize,
    kind: Encoded,
}

/// Encodes JSON as `serde_json` parses it, so the syntax, numbers and
/// recursion limit are those of `serde_json::from_slice`.
struct DrislWriter {
    out: Vec<u8>,
    /// The members of every unfinished object, innermost last.
    members: Vec<Member>,
    /// An object's members while they are written back in order.
    scratch: Vec<u8>,
    integers: Integers,
}

impl DrislWriter {
    /// Encode a value other than a string.
    fn write(
        &mut self,
        f: impl FnOnce(&mut Encoder<&mut Vec<u8>>) -> Result<(), CborError>,
    ) -> Encoded {
        match f(&mut Encoder::new(&mut self.out)) {
            Ok(()) => Encoded::Other,
            Err(_) => Encoded::Invalid,
        }
    }

    fn text(&mut self, s: &str) -> Encoded {
        match Encoder::new(&mut self.out).encode_text(s) {
            Ok(()) => Encoded::Text(self.out.len() - s.len()),
            Err(_) => Encoded::Invalid,
        }
    }

    fn number(&mut self, n: Number) -> Encoded {
        match integer(&n, self.integers) {
            Ok(n) => self.write(|enc| enc.encode_i64(n)),
            Err(_) => Encoded::Invalid,
        }
    }

    /// Fill in the one-byte head written at `start` for `len` items.
    fn finish_array(&mut self, start: usize, len: u64) -> Encoded {
        if len < 24 {
            self.out[start] |= len as u8;
        } else {
            self.scratch.clear();
            if Encoder::new(&mut self.scratch)
                .encode_array_header(len)
                .is_err()
            {
                return Encoded::Invalid;
            }
            self.out.splice(start..=start, self.scratch.iter().copied());
        }
        Encoded::Other
    }

    /// Finish the object written from `start`, whose members are
    /// `members[base..]`.
    fn finish_map(&mut self, start: usize, base: usize) -> Encoded {
        let kind = self.sort_map(start, base);
        self.members.truncate(base);
        kind
    }

    /// Keep the last value of each key, as `serde_json` does, then encode a
    /// `$link` or `$bytes`, or write the members back in key order.
    fn sort_map(&mut self, start: usize, base: usize) -> Encoded {
        let DrislWriter {
            out,
            members,
            scratch,
            ..
        } = self;
        let key = |m: &Member| &out[m.key..m.value];
        let in_order = members[base..]
            .windows(2)
            .all(|pair| drisl_key_cmp(key(&pair[0]), key(&pair[1])).is_lt());
        if !in_order {
            members[base..].sort_by(|a, b| drisl_key_cmp(key(a), key(b)));
        }
        if !in_order && members[base..].windows(2).any(|p| key(&p[0]) == key(&p[1])) {
            // The sort is stable, so the last of equal keys is the latest.
            let mut kept = base;
            for i in base..members.len() {
                if kept > base && key(&members[kept - 1]) == key(&members[i]) {
                    kept -= 1;
                }
                members[kept] = members[i];
                kept += 1;
            }
            members.truncate(kept);
        }
        let members = &members[base..];
        if let [m] = members
            && let Encoded::Text(text) = m.kind
            && let Ok(s) = std::str::from_utf8(&out[text..m.end])
        {
            match special_member(key(m), s) {
                Ok(None) => {}
                Ok(Some(special)) => {
                    out.truncate(start);
                    let mut enc = Encoder::new(&mut *out);
                    let encoded = match special {
                        Special::Cid(cid) => enc.encode_cid(&cid),
                        Special::Bytes(bytes) => enc.encode_bytes(&bytes),
                    };
                    return encoded.map_or(Encoded::Invalid, |()| Encoded::Other);
                }
                Err(_) => return Encoded::Invalid,
            }
        }
        if members.iter().any(|m| m.kind == Encoded::Invalid) {
            return Encoded::Invalid;
        }
        if in_order && members.len() < 24 {
            out[start] |= members.len() as u8;
        } else {
            scratch.clear();
            scratch.extend_from_slice(&out[start..]);
            out.truncate(start);
            if Encoder::new(&mut *out)
                .encode_map_header(members.len() as u64)
                .is_err()
            {
                return Encoded::Invalid;
            }
            for m in members {
                out.extend_from_slice(&scratch[m.start - start..m.end - start]);
            }
        }
        Encoded::Other
    }
}

/// [`cbor_key_cmp`] over UTF-8: a longer key never has a shorter head, so
/// encoded keys sort by length, then bytewise.
fn drisl_key_cmp(a: &[u8], b: &[u8]) -> Ordering {
    a.len().cmp(&b.len()).then_with(|| a.cmp(b))
}

/// Encodes any JSON value, as `serde_json`'s `Value` would parse it.
struct ValueSeed<'w>(&'w mut DrislWriter);

impl<'de> DeserializeSeed<'de> for ValueSeed<'_> {
    type Value = Encoded;

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<Encoded, D::Error> {
        de.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for ValueSeed<'_> {
    type Value = Encoded;

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("any valid JSON value")
    }

    fn visit_unit<E>(self) -> Result<Encoded, E> {
        Ok(self.0.write(|enc| enc.encode_null()))
    }

    fn visit_bool<E>(self, b: bool) -> Result<Encoded, E> {
        Ok(self.0.write(|enc| enc.encode_bool(b)))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Encoded, E> {
        Ok(self.0.number(n.into()))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Encoded, E> {
        Ok(self.0.number(n.into()))
    }

    fn visit_f64<E>(self, f: f64) -> Result<Encoded, E> {
        // No JSON parses to a float that is not finite.
        Ok(Number::from_f64(f).map_or(Encoded::Invalid, |n| self.0.number(n)))
    }

    fn visit_str<E>(self, s: &str) -> Result<Encoded, E> {
        Ok(self.0.text(s))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Encoded, A::Error> {
        let w = self.0;
        let start = w.out.len();
        w.out.push(0x80);
        let mut len = 0;
        let mut valid = true;
        while let Some(kind) = seq.next_element_seed(ValueSeed(w))? {
            len += 1;
            valid &= kind != Encoded::Invalid;
        }
        Ok(if valid {
            w.finish_array(start, len)
        } else {
            Encoded::Invalid
        })
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Encoded, A::Error> {
        let w = self.0;
        let start = w.out.len();
        let base = w.members.len();
        w.out.push(0xa0);
        let mut first = true;
        while let Some((member, key)) = map.next_key_seed(KeySeed(w, first))? {
            first = false;
            let value = w.out.len();
            let kind = map.next_value_seed(ValueSeed(w))?;
            w.members.push(Member {
                start: member,
                key,
                value,
                end: w.out.len(),
                kind,
            });
        }
        Ok(w.finish_map(start, base))
    }
}

/// Encodes an object key, giving where it starts and where its UTF-8 does.
/// The flag marks the first key, which must not start with [`PRIVATE_KEY`].
struct KeySeed<'w>(&'w mut DrislWriter, bool);

impl<'de> DeserializeSeed<'de> for KeySeed<'_> {
    type Value = (usize, usize);

    fn deserialize<D: Deserializer<'de>>(self, de: D) -> Result<(usize, usize), D::Error> {
        de.deserialize_str(self)
    }
}

impl<'de> Visitor<'de> for KeySeed<'_> {
    type Value = (usize, usize);

    fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("a string key")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<(usize, usize), E> {
        let KeySeed(w, first) = self;
        if first && s.starts_with(PRIVATE_KEY) {
            return Err(E::custom("serde_json private key"));
        }
        let start = w.out.len();
        Encoder::new(&mut w.out).encode_text(s).map_err(E::custom)?;
        Ok((start, w.out.len() - s.len()))
    }
}

/// `Ok(None)` if `s` is not a CID string, so the map stays plain.
fn parse_link(s: &str) -> Result<Option<Cid>, CborError> {
    if s.len() > MAX_LINK_LEN {
        return Ok(None);
    }
    let v0 = s.starts_with('Q');
    let bytes = if v0 {
        base_x(s, BASE58BTC).map(LinkBytes::Heap)
    } else if let Some(rest) = s.strip_prefix('z') {
        base_x(rest, BASE58BTC).map(LinkBytes::Heap)
    } else if let Some(rest) = s.strip_prefix('k') {
        base_x(rest, BASE36).map(LinkBytes::Heap)
    } else if let Some(rest) = s.strip_prefix('b') {
        base32_lower(rest)
    } else {
        None
    };
    let Some(parts) = bytes.as_deref().and_then(|b| CidParts::parse(b, v0)) else {
        return Ok(None);
    };
    let CidParts {
        version,
        codec,
        hash,
        digest,
    } = parts;
    if version == 1 && (codec == 0x71 || codec == 0x55) && hash == 0x12 && digest.len() == 32 {
        let mut canonical = [0; 36];
        canonical[..4].copy_from_slice(&[0x01, codec as u8, 0x12, 0x20]);
        canonical[4..].copy_from_slice(digest);
        return Cid::from_bytes(&canonical).map(Some);
    }
    Err(CborError::InvalidCid(format!(
        "unsupported CID: version {version}, codec {codec:#x}, hash {hash:#x}, {}-byte digest",
        digest.len()
    )))
}

/// A well-formed binary CID, as `multiformats` `CID.decode` accepts it.
struct CidParts<'a> {
    version: u64,
    codec: u64,
    hash: u64,
    digest: &'a [u8],
}

impl<'a> CidParts<'a> {
    /// A bare SHA-256 multihash is a CIDv0, allowed only from a `Q…` string.
    fn parse(bytes: &'a [u8], v0_allowed: bool) -> Option<Self> {
        let varint = |buf: &'a [u8]| {
            let (value, len) = decode_varint(buf).ok()?;
            Some((value, buf.get(len..)?))
        };
        let (first, rest) = varint(bytes)?;
        let (version, codec, multihash) = match first {
            0x12 if v0_allowed => (0, 0x70, bytes),
            1 => {
                let (codec, rest) = varint(rest)?;
                (1, codec, rest)
            }
            _ => return None,
        };
        let (hash, rest) = varint(multihash)?;
        let (len, digest) = varint(rest)?;
        (digest.len() as u64 == len).then_some(Self {
            version,
            codec,
            hash,
            digest,
        })
    }
}

const BASE58BTC: &[u8] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const BASE36: &[u8] = b"0123456789abcdefghijklmnopqrstuvwxyz";

/// Decode a base-x string (as the `base-x` package does): each leading zero
/// digit is a zero byte, and the rest is a big-endian number.
fn base_x(s: &str, alphabet: &[u8]) -> Option<Vec<u8>> {
    let base = alphabet.len() as u32;
    let zero = *alphabet.first()?;
    let zeros = s.bytes().take_while(|&c| c == zero).count();
    // Little-endian base 256.
    let mut num: Vec<u8> = Vec::new();
    for c in s.bytes() {
        let mut carry = alphabet.iter().position(|&a| a == c)? as u32;
        for byte in &mut num {
            carry += u32::from(*byte) * base;
            *byte = carry as u8;
            carry >>= 8;
        }
        while carry > 0 {
            num.push(carry as u8);
            carry >>= 8;
        }
    }
    let mut out = vec![0; zeros];
    out.extend(num.iter().rev());
    Some(out)
}

/// Room for a CID with a 64-byte digest.
const INLINE_LINK: usize = 72;

/// Binary CID decoded from a string: on the stack unless unusually long.
enum LinkBytes {
    Inline([u8; INLINE_LINK], usize),
    Heap(Vec<u8>),
}

impl std::ops::Deref for LinkBytes {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        match self {
            LinkBytes::Inline(buf, len) => buf.get(..*len).unwrap_or_default(),
            LinkBytes::Heap(bytes) => bytes,
        }
    }
}

/// Each byte's value as a lowercase base32 symbol, or 0xff.
const BASE32_LOWER: [u8; 256] = {
    let mut table = [0xff; 256];
    let mut i = 0;
    while i < 32 {
        let symbol = if i < 26 { b'a' + i } else { b'2' + i - 26 };
        table[symbol as usize] = i;
        i += 1;
    }
    table
};

/// Decode lowercase RFC 4648 base32. Like `multiformats`, trailing `=` are
/// ignored and trailing bits must be zero.
fn base32_lower(s: &str) -> Option<LinkBytes> {
    let s = s.trim_end_matches('=').as_bytes();
    // No byte count leaves 1, 3 or 6 symbols in the last group of 8.
    if matches!(s.len() % 8, 1 | 3 | 6) {
        return None;
    }
    let len = s.len() * 5 / 8;
    let mut out = if len <= INLINE_LINK {
        LinkBytes::Inline([0; INLINE_LINK], len)
    } else {
        LinkBytes::Heap(vec![0; len])
    };
    let bytes = match &mut out {
        LinkBytes::Inline(buf, len) => buf.get_mut(..*len)?,
        LinkBytes::Heap(bytes) => bytes,
    };
    // Each group of 8 symbols is 40 bits, 5 bytes. A shorter last group
    // fills fewer bytes and leaves spare bits, which must be zero.
    let mut symbols = 0;
    let mut group_bits = |group: &[u8]| {
        group.iter().fold(0u64, |bits, &c| {
            let value = BASE32_LOWER[usize::from(c)];
            symbols |= value;
            bits << 5 | u64::from(value & 31)
        })
    };
    let (groups, last) = s.as_chunks::<8>();
    let (whole, partial) = bytes.as_chunks_mut::<5>();
    for (group, out) in groups.iter().zip(whole) {
        out.copy_from_slice(&group_bits(group).to_be_bytes()[3..]);
    }
    let spare = last.len() * 5 - partial.len() * 8;
    let bits = group_bits(last);
    if bits & ((1 << spare) - 1) != 0 {
        return None;
    }
    partial.copy_from_slice(&(bits >> spare).to_be_bytes()[8 - partial.len()..]);
    (symbols < 32).then_some(out)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cbor::{Codec, decode, encode_value};
    use proptest::prelude::*;
    use serde_json::json;

    const CID: &str = "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a";

    fn safe(json: &Json) -> Result<Vec<u8>, CborError> {
        json_to_drisl(json, Integers::Safe)
    }

    fn link(s: &str) -> Json {
        json!({ "$link": s })
    }

    /// Asserts `json` converts to a plain map, keeping its keys.
    fn assert_plain_map(json: &Json) {
        let bytes = safe(json).unwrap();
        let Value::Map(entries) = decode(&bytes).unwrap() else {
            panic!("{json} did not stay a map");
        };
        let keys: Vec<&str> = entries.iter().map(|(k, _)| *k).collect();
        let want: Vec<&str> = json
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(keys.len(), want.len(), "{json}");
        assert!(want.iter().all(|k| keys.contains(k)), "{json}");
    }

    #[test]
    fn matches_the_canonical_encoder() {
        let cid = Cid::compute(Codec::Drisl, b"linked record");
        let json = json!({
            "text": "hello",
            "count": 5,
            "negative": -3,
            "flag": true,
            "nothing": null,
            "nested": {"bb": 2, "a": 1},
            "list": [1, "two", [3]],
            "blob": {"$bytes": "3q2+7w"},
            "ref": {"$link": cid.to_string()},
        });
        let value = Value::Map(vec![
            ("text", Value::Text("hello")),
            ("count", Value::Unsigned(5)),
            ("negative", Value::Signed(-3)),
            ("flag", Value::Bool(true)),
            ("nothing", Value::Null),
            (
                "nested",
                Value::Map(vec![("bb", Value::Unsigned(2)), ("a", Value::Unsigned(1))]),
            ),
            (
                "list",
                Value::Array(vec![
                    Value::Unsigned(1),
                    Value::Text("two"),
                    Value::Array(vec![Value::Unsigned(3)]),
                ]),
            ),
            ("blob", Value::Bytes(&[0xDE, 0xAD, 0xBE, 0xEF])),
            ("ref", Value::Cid(cid)),
        ]);
        let bytes = safe(&json).unwrap();
        assert_eq!(bytes, encode_value(&value).unwrap());
        assert_eq!(drisl_to_json(&bytes).unwrap(), json);
    }

    #[test]
    fn links_accept_every_reference_multibase() {
        let want = Value::Cid(CID.parse().unwrap());
        for s in [
            CID,
            "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTDh",
            "k2jvsl7wph2xec9tldt5guqsv8bqse480mslfjw2lyfdlxfws95udh3k",
            // multiformats ignores base32 padding.
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a======",
        ] {
            let bytes = safe(&link(s)).unwrap();
            assert_eq!(decode(&bytes).unwrap(), want, "{s}");
            assert_eq!(parse_cid(s).unwrap().to_string(), CID, "{s}");
            assert_eq!(drisl_to_json(&bytes).unwrap(), link(CID), "{s}");
        }
    }

    #[test]
    fn well_formed_cids_that_cid_cannot_hold_are_errors() {
        for s in [
            // v0
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            // dag-pb, in base32 and base36
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
            "k2jmtxw8rjh1z69c6not3wtdxb0u3urbzhyll1t9jg6ox26dhi5sfi1m",
            // sha2-512
            "bafyrgqfevpkejdcjkywyfaiv2e5b7thksj7vfngviwjjp6fuhzbnvcjdrpatmjxehxftrxnqqjeisj7msbh3iicxiq4yh2efqulz2ucvdl7ge",
            // identity hash
            "bafkqaa3bmjrq",
        ] {
            assert!(
                matches!(safe(&link(s)), Err(CborError::InvalidCid(_))),
                "{s}"
            );
            assert!(parse_cid(s).is_err(), "{s}");
        }
    }

    #[test]
    fn malformed_links_stay_plain_maps() {
        let long = format!("b{}", "a".repeat(MAX_LINK_LEN));
        for s in [
            "",
            ".",
            "bafy",
            "BAFYREIDFAYVFUWQA7QLNOPDJIQRXZS6BLMOEU4RUJCJTNCI5BELUDIRZ2A",
            "Bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            // trailing byte, truncated digest, version 2
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2aaa",
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz",
            "bajyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            // non-zero trailing bits
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2b",
            // v0 behind a multibase prefix
            "zQmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "bciqj23bl4uhxa2kti6nltxzm4pw4vefwqbj4aczqas37blgl4huo5xy",
            // unsupported multibase, stray characters
            "mAXESIGUGKlpaAPwW1zxpRCN8y8FbHEpyNEiTNokdCRdBojnQ",
            "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTD0",
            " bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a",
            &long,
        ] {
            assert_plain_map(&link(s));
            assert!(parse_cid(s).is_err(), "{s}");
        }
        for json in [
            json!({"$link": 1234}),
            json!({"$link": null}),
            json!({"$link": {"$link": CID}}),
            json!({"$link": CID, "other": 1}),
            json!({"$link": CID, "$bytes": ""}),
        ] {
            assert_plain_map(&json);
        }
    }

    #[test]
    fn bytes_accept_padded_and_unpadded_base64() {
        for (s, want) in [
            ("", &b""[..]),
            ("TQ", b"M"),
            ("TQ=", b"M"),
            ("TQ==", b"M"),
            ("TWE", b"Ma"),
            ("TWE=", b"Ma"),
            ("TWFu", b"Man"),
            ("+/+/", &[0xfb, 0xff, 0xbf]),
        ] {
            let bytes = safe(&json!({ "$bytes": s })).unwrap();
            assert_eq!(decode(&bytes).unwrap(), Value::Bytes(want), "{s}");
        }
        let bytes = safe(&json!({"$bytes": "TWE="})).unwrap();
        assert_eq!(drisl_to_json(&bytes).unwrap(), json!({"$bytes": "TWE"}));
    }

    /// Regression test: partially padded base64 stayed a plain map, so the
    /// same JSON hashed to a different CID than in the reference.
    #[test]
    fn partially_padded_bytes_decode() {
        let j = json!({"a": {"$bytes": "AQ="}});
        assert_eq!(
            json_to_drisl(&j, Integers::Any).unwrap(),
            [0xa1, 0x61, b'a', 0x41, 0x01]
        );
    }

    #[test]
    fn malformed_bytes_stay_plain_maps() {
        for json in [
            json!({"$bytes": "🐻"}),
            json!({"$bytes": "TQ==="}),
            json!({"$bytes": "TWE=="}),
            json!({"$bytes": "TWFu="}),
            json!({"$bytes": "-_"}),
            json!({"$bytes": [1, 2, 3]}),
            json!({"$bytes": "TQ", "other": 1}),
        ] {
            assert_plain_map(&json);
        }
    }

    #[test]
    fn integers_are_judged_by_value() {
        let max = MAX_SAFE_INTEGER;
        for (text, want) in [
            ("0", 0),
            ("-0", 0),
            ("-0.0", 0),
            ("123.0", 123),
            ("1e10", 10_000_000_000),
            ("9007199254740991", max),
            ("-9007199254740991", -max),
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            let expected = encode_value(&if want < 0 {
                Value::Signed(want)
            } else {
                Value::Unsigned(want as u64)
            })
            .unwrap();
            assert_eq!(safe(&json).unwrap(), expected, "{text}");
            assert_eq!(
                json_to_drisl(&json, Integers::Any).unwrap(),
                expected,
                "{text}"
            );
        }
    }

    #[test]
    fn unsafe_integers_need_any() {
        for text in [
            "9007199254740992",
            "-9007199254740992",
            "9223372036854775807",
            "-9223372036854775808",
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            assert!(
                matches!(safe(&json), Err(CborError::DataModel(_))),
                "{text}"
            );
            let bytes = json_to_drisl(&json, Integers::Any).unwrap();
            assert_eq!(drisl_to_json(&bytes).unwrap(), json, "{text}");
        }
    }

    #[test]
    fn floats_and_out_of_range_numbers_are_rejected() {
        for text in [
            "1.5",
            "-0.1",
            "1e20",
            "9007199254740992.0",
            "9223372036854775808",
            "18446744073709551616",
        ] {
            let json: Json = serde_json::from_str(text).unwrap();
            for integers in [Integers::Safe, Integers::Any] {
                assert!(
                    matches!(json_to_drisl(&json, integers), Err(CborError::DataModel(_))),
                    "{text}"
                );
            }
        }
        assert!(safe(&json!({"a": [{"b": 0.5}]})).is_err());
    }

    #[test]
    fn duplicate_keys_keep_the_last_value() {
        let json: Json = serde_json::from_str(r#"{"a": 1, "a": {"$bytes": "TQ"}}"#).unwrap();
        assert_eq!(
            safe(&json).unwrap(),
            safe(&json!({"a": {"$bytes": "TQ"}})).unwrap()
        );
    }

    const RAW_VALUE: &str = "$serde_json::private::RawValue";

    /// What `json_slice_to_drisl` must agree with.
    fn two_steps(json: &[u8], integers: Integers) -> Result<Vec<u8>, JsonError> {
        Ok(json_to_drisl(&serde_json::from_slice(json)?, integers)?)
    }

    /// Asserts `json_slice_to_drisl` gives what the two steps give, and does
    /// without them whenever it can.
    fn assert_agrees(json: &[u8]) {
        let text = String::from_utf8_lossy(json);
        for integers in [Integers::Safe, Integers::Any] {
            let want = two_steps(json, integers);
            let fast = encode_json(json, integers);
            if let Some(fast) = &fast {
                assert_eq!(Some(fast), want.as_ref().ok(), "{text}");
            }
            if !text.contains(PRIVATE_KEY) {
                assert_eq!(fast.is_some(), want.is_ok(), "{text}: {want:?}");
            }
            let got = json_slice_to_drisl(json, integers);
            assert_eq!(format!("{got:?}"), format!("{want:?}"), "{text}");
        }
    }

    #[test]
    fn json_slice_matches_the_two_steps() {
        let many = |n: usize, order: fn(usize) -> usize| {
            let members: Vec<_> = (0..n)
                .map(|i| format!(r#""k{:03}":{i}"#, order(i)))
                .collect();
            format!("{{{}}}", members.join(","))
        };
        let mut cases: Vec<String> = [
            "null",
            "[true, false]",
            r#"["", "\u00e9\ud83d\ude00\n"]"#,
            "[[], {}, [[{}]]]",
            r#"{"b": 1, "a": 2, "aa": 3, "$type": "t"}"#,
            r#"{"bb": 1, "a": [{"d": 1, "c": 2}]}"#,
            // Duplicates collapse first, so the last `$link` or `$bytes` counts.
            r#"{"$link": "x", "$link": "<cid>"}"#,
            r#"{"$link": "<cid>", "$link": "x"}"#,
            r#"{"$bytes": "TQ", "$bytes": 1}"#,
            r#"{"$bytes": 1, "a": 2, "$bytes": "TQ"}"#,
            r#"{"a": 1, "\u0061": 2, "a": 3}"#,
            r#"{"a": 1.5, "a": 1}"#,
            r#"{"a": {"$link": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}, "a": 0}"#,
            r#"{"$link": "<cid>", "a": 1}"#,
            r#"{"$link": {"$link": "<cid>"}}"#,
            r#"[{"$bytes": "+/+/"}, {"$bytes": "-_"}, {"$link": "bafy"}]"#,
            // Keys on either side of a longer head.
            r#"{"aaaaaaaaaaaaaaaaaaaaaaaa": 1, "bbbbbbbbbbbbbbbbbbbbbbb": 2, "c": 3}"#,
            // A first key `Value` treats specially, here or nested.
            r#"{"$serde_json::private::RawValue": "[3, {\"b\": 2, \"a\": 1}]"}"#,
            r#"{"$link": {"$serde_json::private::RawValue": "\"<cid>\""}}"#,
            r#"{"$serde_json::private::RawValue": "[1]", "a": 1}"#,
            r#"{"$serde_json::private::RawValue": 1}"#,
            r#"{"$serde_json::private::RawValue": "{"}"#,
            r#"{"$serde_json::private::Number": "1"}"#,
            r#"{"a": 1, "$serde_json::private::RawValue": "[1]"}"#,
        ]
        .map(|s| s.replace("<cid>", CID))
        .into();
        for n in [23, 24, 255, 256] {
            cases.push(format!("[{}]", vec!["0"; n].join(",")));
            cases.push(many(n, |i| i));
            cases.push(many(n, |i| 999 - i));
        }
        for number in [
            "0",
            "-0",
            "-0.0",
            "1.0",
            "1e10",
            "1E+2",
            "100e-2",
            "1.5",
            "1e400",
            "1e-400",
            "9007199254740991",
            "9007199254740992",
            "-9007199254740992",
            "9007199254740991.0",
            "9007199254740992.0",
            "9223372036854775807",
            "9223372036854775808",
            "-9223372036854775808",
            "-9223372036854775809",
            "18446744073709551616",
        ] {
            cases.push(number.to_owned());
            cases.push(format!(r#"{{"a": [{number}]}}"#));
        }
        for case in &cases {
            assert_agrees(case.as_bytes());
        }
    }

    #[test]
    fn json_slice_fails_as_the_two_steps_do() {
        let parse = |json: &[u8]| {
            matches!(
                json_slice_to_drisl(json, Integers::Any),
                Err(JsonError::Parse(_))
            )
        };
        for json in [
            "",
            "{",
            "[1,]",
            r#"{"a" 1}"#,
            "{1: 2}",
            "nul",
            "1 2",
            "01",
            "1e400",
            r#""\ud83d""#,
            "\"\u{1}\"",
            r#"{"$serde_json::private::RawValue": 1}"#,
            // A syntax error comes before an earlier float.
            "[1.5,",
        ] {
            assert!(parse(json.as_bytes()), "{json}");
        }
        assert!(parse(b"\"\xff\""));
        assert!(parse(b"[1] \xff"));

        let deep = |n| format!("{}{}", "[".repeat(n), "]".repeat(n));
        assert!(json_slice_to_drisl(deep(127).as_bytes(), Integers::Safe).is_ok());
        let err = json_slice_to_drisl(deep(128).as_bytes(), Integers::Safe).unwrap_err();
        assert!(
            err.to_string().contains("recursion limit exceeded"),
            "{err}"
        );

        let drisl = |json: &str, integers| match json_slice_to_drisl(json.as_bytes(), integers) {
            Err(JsonError::Drisl(err)) => err,
            other => panic!("{json}: {other:?}"),
        };
        for (json, integers) in [
            ("1.5", Integers::Any),
            (r#"{"a": [{"b": 0.5}]}"#, Integers::Any),
            ("9007199254740992", Integers::Safe),
            ("-9223372036854775809", Integers::Any),
        ] {
            assert!(matches!(drisl(json, integers), CborError::DataModel(_)));
        }
        let unsupported = r#"{"$link": "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG"}"#;
        assert!(matches!(
            drisl(unsupported, Integers::Safe),
            CborError::InvalidCid(_)
        ));
    }

    /// The reference vectors, and every block of a real repository.
    #[test]
    fn json_slice_agrees_on_real_documents() {
        let dir = env!("CARGO_MANIFEST_DIR");
        let vectors: Json = serde_json::from_slice(
            &std::fs::read(format!("{dir}/testdata/lex_json_vectors.json")).unwrap(),
        )
        .unwrap();
        for kind in ["special", "plain", "rejected"] {
            for v in vectors[kind].as_array().unwrap() {
                assert_agrees(&serde_json::to_vec(&v["json"]).unwrap());
                assert_agrees(&serde_json::to_vec_pretty(&v["json"]).unwrap());
            }
        }
        #[cfg(feature = "car")]
        {
            let car = std::fs::read(format!("{dir}/benches/fixtures/calabro.car")).unwrap();
            let (_, blocks) = crate::car::read_slice(&car).unwrap();
            assert!(blocks.len() > 4000);
            for block in blocks {
                assert_agrees(&serde_json::to_vec(&drisl_to_json(block.data).unwrap()).unwrap());
            }
        }
    }

    /// A JSON number, mostly well-formed, near every limit `integer` has.
    fn number_text() -> impl Strategy<Value = String> {
        prop_oneof![
            any::<i64>().prop_map(|n| n.to_string()),
            any::<u64>().prop_map(|n| n.to_string()),
            (-2i64..=2).prop_map(|d| (MAX_SAFE_INTEGER + d).to_string()),
            (-2i64..=2).prop_map(|d| (-MAX_SAFE_INTEGER - d).to_string()),
            any::<f64>().prop_map(|f| format!("{f:?}")),
            any::<f64>().prop_map(|f| format!("{f:e}")),
            "-?(0|[1-9][0-9]{0,21})(\\.[0-9]{1,3})?([eE][+-]?[0-9]{1,3})?",
            prop::sample::select(vec![
                "-0",
                "-0.0",
                "1.0",
                "9007199254740992.0",
                "9223372036854775808",
                "-9223372036854775809",
                "18446744073709551616",
                "1e400",
                "1e-400",
                "01",
                "1.",
                ".5",
                "+1",
                "-",
            ])
            .prop_map(str::to_owned),
        ]
    }

    /// A JSON string with escapes, now and then a bad one.
    fn string_text() -> impl Strategy<Value = String> {
        let piece = prop_oneof![
            8 => "[a-z$]{1,3}",
            4 => any::<char>().prop_map(|c| {
                let quoted = serde_json::to_string(&c).unwrap();
                quoted[1..quoted.len() - 1].to_owned()
            }),
            4 => prop::sample::select(vec![
                r"\n", r#"\""#, r"\\", r"\/", r"\u0061", r"\u00e9", r"\ud83d\ude00", r"\u0000",
                "é", "😀",
            ])
            .prop_map(str::to_owned),
            1 => prop::sample::select(vec![r"\ud83d", r"\ude00", "\u{1}", r"\x", "\""])
                .prop_map(str::to_owned),
        ];
        prop::collection::vec(piece, 0..5).prop_map(|parts| format!("\"{}\"", parts.concat()))
    }

    /// An object key, often one that repeats or that DRISL orders apart.
    fn key_text() -> impl Strategy<Value = String> {
        prop_oneof![
            12 => prop::sample::select(vec!["a", "b", "aa", "ab", "$link", "$bytes", "$type"])
                .prop_map(|k| format!("\"{k}\"")),
            2 => Just(r#""\u0061""#.to_owned()),
            2 => (prop::sample::select(vec![23, 24, 25, 255, 256]), "[ab]")
                .prop_map(|(n, c)| format!("\"{}\"", c.repeat(n))),
            6 => string_text(),
        ]
    }

    /// A string for `$link`, mostly a CID it takes.
    fn link_text() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            CID,
            CID,
            "zdpuAsDo7UZTXQtgvtq6uKnJCYMkEvf8XAgPxn8rtopYnpTDh",
            "k2jvsl7wph2xec9tldt5guqsv8bqse480mslfjw2lyfdlxfws95udh3k",
            "bafyreidfayvfuwqa7qlnopdjiqrxzs6blmoeu4rujcjtnci5beludirz2a==",
            "bafy",
            "QmYwAPJzv5CZsnA625s3Xf2nemtYgPpHdWEz79ojWnPbdG",
            "bafybeigdyrzt5sfp7udm7hu76uh7y26nf3efuylqabf3oclgtqy55fbzdi",
        ])
        .prop_map(|s| format!("\"{s}\""))
    }

    /// A string for `$bytes`, mostly base64 it takes.
    fn bytes_text() -> impl Strategy<Value = String> {
        prop::sample::select(vec![
            "", "TQ", "TQ=", "TQ==", "TWFu", "+/+/", "aGk", "TQ===", "-_", "🐻",
        ])
        .prop_map(|s| format!("\"{s}\""))
    }

    fn object(members: impl IntoIterator<Item = (String, String)>) -> String {
        let members: Vec<_> = members
            .into_iter()
            .map(|(k, v)| format!("{k}:{v}"))
            .collect();
        format!("{{{}}}", members.join(","))
    }

    fn json_text() -> impl Strategy<Value = String> {
        let leaf = prop_oneof![
            prop::sample::select(vec!["null", "true", "false"]).prop_map(str::to_owned),
            number_text(),
            string_text(),
            link_text(),
            bytes_text(),
        ];
        leaf.prop_recursive(4, 64, 6, |inner| {
            let members = || prop::collection::vec((key_text(), inner.clone()), 0..6);
            prop_oneof![
                12 => prop::collection::vec(inner.clone(), 0..6)
                    .prop_map(|items| format!("[{}]", items.join(","))),
                12 => members().prop_map(object),
                // `$link` or `$bytes`, perhaps repeated or with company.
                12 => (
                    prop_oneof![
                        Just("\"$link\"").prop_flat_map(|k| (Just(k), link_text())),
                        Just("\"$bytes\"").prop_flat_map(|k| (Just(k), bytes_text())),
                    ],
                    prop::collection::vec(inner.clone(), 0..2),
                    prop::collection::vec((key_text(), inner.clone()), 0..4),
                    any::<bool>(),
                )
                    .prop_map(|((key, value), before, rest, alone)| {
                        let first = before.into_iter().map(|v| (key.to_owned(), v));
                        let rest = rest.into_iter().filter(|_| !alone);
                        object(first.chain([(key.to_owned(), value)]).chain(rest))
                    }),
                2 => (inner.clone(), 20..30usize).prop_map(|(item, n)| format!("[{}]", vec![item; n].join(","))),
                // Many members, in DRISL order or not.
                2 => (members(), 20..30usize, any::<bool>()).prop_map(|(m, n, up)| object(
                    (0..n)
                        .map(|i| (format!("\"k{:02}\"", if up { i } else { n - i }), "0".to_owned()))
                        .chain(m)
                )),
                1 => inner.prop_map(|doc| format!(
                    "{{\"{RAW_VALUE}\":{}}}",
                    serde_json::to_string(&doc).unwrap()
                )),
            ]
        })
    }

    proptest::proptest! {
        #![proptest_config(ProptestConfig::with_cases(2048))]

        /// Generated JSON, sometimes with a byte changed or cut off.
        #[test]
        fn json_slice_matches_the_two_steps_on_generated_json(
            text in json_text(),
            edit in proptest::option::of((any::<prop::sample::Index>(), any::<u8>(), any::<bool>())),
        ) {
            let mut json = text.into_bytes();
            if let Some((at, byte, cut)) = edit
                && !json.is_empty()
            {
                let at = at.index(json.len());
                if cut {
                    json.truncate(at);
                } else {
                    json[at] = byte;
                }
            }
            assert_agrees(&json);
        }
    }

    #[test]
    fn drisl_floats_and_oversized_integers_are_rejected() {
        let float = encode_value(&Value::Map(vec![("a", Value::Float(1.5))])).unwrap();
        assert!(matches!(
            drisl_to_json(&float),
            Err(CborError::DataModel(_))
        ));
        assert!(matches!(
            value_to_json(&Value::Unsigned(u64::MAX)),
            Err(CborError::DataModel(_))
        ));
        assert!(matches!(
            drisl_to_json(&[0xff]),
            Err(CborError::InvalidCbor(_))
        ));
    }

    /// `drisl_to_json_into` against `serde_json::to_vec(&drisl_to_json(..))`.
    mod json_text {
        use super::*;
        use std::collections::BTreeMap;

        /// Asserts both conversions agree on `bytes`, output or error, and
        /// that `out` keeps what it held, gaining nothing on error.
        fn assert_same(bytes: &[u8]) {
            let mut out = b"held".to_vec();
            let actual = drisl_to_json_into(bytes, &mut out);
            match drisl_to_json(bytes) {
                Ok(json) => {
                    actual.unwrap_or_else(|e| panic!("{e} for {bytes:02x?}"));
                    assert_eq!(out[..4], *b"held");
                    let want = serde_json::to_vec(&json).unwrap();
                    assert_eq!(
                        String::from_utf8_lossy(&out[4..]),
                        String::from_utf8_lossy(&want),
                        "{bytes:02x?}"
                    );
                    assert_eq!(out[4..], want);
                }
                Err(want) => {
                    let got = actual
                        .err()
                        .unwrap_or_else(|| panic!("accepted {bytes:02x?}"));
                    assert_eq!(format!("{got:?}"), format!("{want:?}"), "{bytes:02x?}");
                    assert_eq!(out, b"held");
                }
            }
        }

        fn text(s: &str) -> Vec<u8> {
            encode_value(&Value::Text(s)).unwrap()
        }

        /// Every ASCII byte at every position of strings up to 24 bytes, which
        /// covers short strings, whole words and the overlapping last word, and
        /// next to multibyte characters, whose bytes are all above 0x7f.
        #[test]
        fn strings_escape_as_serde_json_does() {
            for len in 1..=24 {
                for at in 0..len {
                    for byte in 0..=0x7f_u8 {
                        let mut s = vec![b'a'; len];
                        s[at] = byte;
                        assert_same(&text(std::str::from_utf8(&s).unwrap()));
                    }
                }
            }
            for s in [
                "",
                "é",
                "😀",
                "/",
                "\u{7f}",
                "\u{80}",
                "\u{2028}",
                "\u{fffd}",
                "é\"",
                "😀\n",
                "\u{80}\u{80}\u{80}\u{1f}",
                "ééééé\\",
                "日本語のテキスト\t",
                "\"\\\"\\",
            ] {
                assert_same(&text(s));
                assert_same(&text(&s.repeat(9)));
            }
        }

        #[test]
        fn keys_are_written_in_bytewise_order() {
            let keys = [
                "b",
                "a",
                "aa",
                "$type",
                "createdAt",
                "subject",
                "",
                "Z",
                "é",
                "\n",
            ];
            for n in 0..=keys.len() {
                let map = Value::Map(keys[..n].iter().map(|k| (*k, Value::Text(k))).collect());
                assert_same(&encode_value(&map).unwrap());
            }
            // More entries than stay on the stack, which DRISL orders the
            // reverse of bytewise (`z`, `ya`, `xaa`, ...), around a nested map
            // of the same.
            let keys: Vec<String> = (0..20)
                .map(|i| format!("{}{}", char::from(b'z' - i), "a".repeat(i.into())))
                .collect();
            let nested = Value::Map(keys.iter().map(|k| (k.as_str(), Value::Null)).collect());
            let mut entries: Vec<_> = keys.iter().map(|k| (k.as_str(), Value::Null)).collect();
            entries.push(("nested", nested));
            assert_same(&encode_value(&Value::Map(entries)).unwrap());
        }

        #[test]
        fn scalars() {
            let cid = Cid::compute(Codec::Drisl, b"x");
            let raw = Cid::compute(Codec::Raw, b"x");
            let mut values = vec![
                Value::Null,
                Value::Bool(true),
                Value::Bool(false),
                Value::Cid(cid),
                Value::Cid(raw),
                Value::Array(vec![]),
                Value::Map(vec![]),
                Value::Array(vec![Value::Array(vec![]), Value::Map(vec![]), Value::Null]),
            ];
            for n in [
                0,
                1,
                9,
                10,
                23,
                24,
                255,
                256,
                65535,
                65536,
                u64::from(u32::MAX) + 1,
            ] {
                values.push(Value::Unsigned(n));
            }
            values.push(Value::Unsigned(i64::MAX as u64));
            for n in [-1, -10, -24, -25, -256, -257, i64::MIN + 1, i64::MIN] {
                values.push(Value::Signed(n));
            }
            let bytes = [0xfb_u8, 0xff, 0xbf, 0x00, 0x01, 0x80];
            for n in 0..=bytes.len() {
                values.push(Value::Bytes(&bytes[..n]));
            }
            for value in values {
                assert_same(&encode_value(&value).unwrap());
                assert_same(&encode_value(&Value::Map(vec![("k", value)])).unwrap());
            }
        }

        #[test]
        fn errors_match_drisl_to_json() {
            let float = |f: f64| {
                let mut b = vec![0xfb];
                b.extend_from_slice(&f.to_bits().to_be_bytes());
                b
            };
            let mut inputs: Vec<Vec<u8>> = vec![
                vec![],
                vec![0xff],
                vec![0x1c],
                vec![0x18, 0x17],
                vec![0x19, 0x00, 0xff],
                vec![0x01, 0x02],
                vec![0xa0, 0x00],
                vec![0x5f],
                vec![0x7f],
                vec![0x9f],
                vec![0xbf],
                vec![0xf7],
                vec![0xf8, 0x20],
                vec![0xf9, 0x00, 0x00],
                vec![0xfa, 0x00, 0x00, 0x00, 0x00],
                float(f64::NAN),
                float(f64::INFINITY),
                vec![0x1b, 0x80, 0, 0, 0, 0, 0, 0, 0],
                vec![0x3b, 0x80, 0, 0, 0, 0, 0, 0, 0],
                // keys: unsorted, duplicate, not text, invalid UTF-8
                vec![0xa2, 0x61, b'b', 0x01, 0x61, b'a', 0x02],
                vec![0xa2, 0x61, b'a', 0x01, 0x61, b'a', 0x02],
                vec![0xa2, 0x62, b'a', b'a', 0x01, 0x61, b'b', 0x02],
                vec![0xa1, 0x01, 0x02],
                vec![0xa1, 0x61, 0xff, 0x01],
                // text: invalid UTF-8, truncated, a length past the end
                vec![0x62, 0xc3, 0x28],
                vec![0x63, b'a', b'b'],
                vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
                // tags: not 42, wrapping an integer, bad prefix, bad codec
                vec![0xc1, 0x00],
                vec![0xd8, 0x2a, 0x01],
                [&[0xd8, 0x2a, 0x58, 0x25, 0x01][..], &[0; 36]].concat(),
                [
                    &[0xd8, 0x2a, 0x58, 0x25, 0x00, 0x01, 0x70, 0x12, 0x20][..],
                    &[0; 32],
                ]
                .concat(),
                // lengths past the limits and the input
                vec![0x9a, 0x00, 0x10, 0x00, 0x00],
                vec![0xba, 0x00, 0x10, 0x00, 0x00],
                vec![0x83, 0x01],
                vec![0xa2, 0x61, b'a', 0x01],
            ];
            // Long invalid UTF-8, which the SIMD validator checks.
            let mut long = vec![0x78, 100];
            long.extend(std::iter::repeat_n(b'a', 99));
            long.push(0xff);
            inputs.push(long);
            // A float is an error only after everything else decodes: the
            // first float in document order, or a later CBOR error first.
            let mut floats = vec![0x83];
            floats.extend(float(1.5));
            floats.extend(float(-0.25));
            floats.push(0x01);
            inputs.push(floats.clone());
            for tail in [&[0x18, 0x00][..], &[0x61, 0xff], &[0x01, 0x01]] {
                let mut bad = floats.clone();
                bad.pop();
                bad.extend_from_slice(tail);
                inputs.push(bad);
            }
            let mut map = vec![0xa2, 0x61, b'b'];
            map.extend(float(2.0));
            map.extend([0x61, b'a', 0x01]);
            inputs.push(map);
            // Nesting around the depth limit.
            for depth in 60..=66 {
                for open in [&[0x81][..], &[0xa1, 0x61, b'k']] {
                    let mut nested = open.repeat(depth);
                    nested.push(0x00);
                    inputs.push(nested.clone());
                    nested.pop();
                    nested.push(0x60);
                    inputs.push(nested);
                }
            }
            // Every truncation of a record with every kind of value.
            let cid = Cid::compute(Codec::Drisl, b"x");
            let record = encode_value(&Value::Map(vec![
                ("text", Value::Text("hi \"there\"\n")),
                ("n", Value::Signed(-300)),
                ("bytes", Value::Bytes(&[1, 2, 3])),
                ("link", Value::Cid(cid)),
                ("list", Value::Array(vec![Value::Null, Value::Bool(true)])),
                (
                    "aa",
                    Value::Map(vec![("z", Value::Unsigned(1)), ("yy", Value::Null)]),
                ),
            ]))
            .unwrap();
            for end in 0..=record.len() {
                inputs.push(record[..end].to_vec());
            }
            for input in &inputs {
                assert_same(input);
            }
        }

        #[test]
        fn writer_writes_once_or_not_at_all() {
            struct Failing;
            impl Write for Failing {
                fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                    Err(std::io::Error::other("full"))
                }
                fn flush(&mut self) -> std::io::Result<()> {
                    Ok(())
                }
            }
            let bytes =
                encode_value(&Value::Map(vec![("b", Value::Null), ("aa", Value::Null)])).unwrap();
            let mut out = Vec::new();
            drisl_to_json_writer(&bytes, &mut out).unwrap();
            assert_eq!(out, br#"{"aa":null,"b":null}"#);
            assert!(matches!(
                drisl_to_json_writer(&bytes, Failing),
                Err(CborError::Io(_))
            ));
            let mut out = Vec::new();
            assert!(drisl_to_json_writer(&[0x82, 0x01], &mut out).is_err());
            assert!(out.is_empty());
        }

        /// The byte-at-a-time scan `clean_len` replaces.
        fn clean_len_reference(bytes: &[u8]) -> usize {
            bytes
                .iter()
                .position(|&b| b < 0x20 || b == b'"' || b == b'\\')
                .unwrap_or(bytes.len())
        }

        /// Owned DRISL documents, whose maps have unique keys.
        #[derive(Debug, Clone)]
        enum Doc {
            Null,
            Bool(bool),
            Int(i64),
            Float(f64),
            Text(String),
            Bytes(Vec<u8>),
            Cid(bool, [u8; 32]),
            Array(Vec<Doc>),
            Map(BTreeMap<String, Doc>),
        }

        impl Doc {
            fn value(&self) -> Value<'_> {
                match self {
                    Doc::Null => Value::Null,
                    Doc::Bool(b) => Value::Bool(*b),
                    Doc::Int(n) if *n < 0 => Value::Signed(*n),
                    Doc::Int(n) => Value::Unsigned(*n as u64),
                    Doc::Float(f) => Value::Float(*f),
                    Doc::Text(s) => Value::Text(s),
                    Doc::Bytes(b) => Value::Bytes(b),
                    Doc::Cid(drisl, hash) => {
                        let codec = if *drisl { 0x71 } else { 0x55 };
                        let bytes = [&[0x01, codec, 0x12, 0x20][..], hash].concat();
                        Value::Cid(Cid::from_bytes(&bytes).unwrap())
                    }
                    Doc::Array(items) => Value::Array(items.iter().map(Doc::value).collect()),
                    Doc::Map(entries) => Value::Map(
                        entries
                            .iter()
                            .map(|(k, v)| (k.as_str(), v.value()))
                            .collect(),
                    ),
                }
            }
        }

        /// Text from every escape class, ASCII and multibyte characters.
        fn any_text(max: usize) -> impl Strategy<Value = String> {
            let char = prop_oneof![
                8 => proptest::char::range('a', 'z'),
                2 => (0u8..0x20).prop_map(char::from),
                1 => prop::sample::select(vec!['"', '\\', '/', '\u{7f}', ' ', '$']),
                1 => any::<char>(),
            ];
            prop::collection::vec(char, 0..max).prop_map(String::from_iter)
        }

        fn any_doc() -> impl Strategy<Value = Doc> {
            let int = prop_oneof![
                any::<i64>(),
                prop::sample::select(vec![0, -1, 23, 24, -24, -25, i64::MAX, i64::MIN]),
            ];
            let leaf = prop_oneof![
                2 => Just(Doc::Null),
                2 => any::<bool>().prop_map(Doc::Bool),
                4 => int.prop_map(Doc::Int),
                1 => any::<f64>()
                    .prop_filter("finite", |f| f.is_finite())
                    .prop_map(Doc::Float),
                8 => any_text(40).prop_map(Doc::Text),
                2 => prop::collection::vec(any::<u8>(), 0..12).prop_map(Doc::Bytes),
                2 => (any::<bool>(), any::<[u8; 32]>()).prop_map(|(d, h)| Doc::Cid(d, h)),
            ];
            leaf.prop_recursive(5, 64, 12, |inner| {
                // Short keys of mixed lengths, whose DRISL and bytewise
                // orders differ, and sometimes keys that need escapes.
                let key = prop_oneof![8 => "[a-c$]{0,3}", 1 => any_text(10)];
                prop_oneof![
                    prop::collection::vec(inner.clone(), 0..6).prop_map(Doc::Array),
                    prop::collection::btree_map(key, inner, 0..12).prop_map(Doc::Map),
                ]
            })
        }

        proptest! {
            #[test]
            fn clean_len_matches_a_bytewise_scan(
                bytes in prop_oneof![
                    prop::collection::vec(any::<u8>(), 0..40),
                    prop::collection::vec(
                        prop::sample::select(vec![b'a', b'a', b'a', 0x20, 0x7f, 0x80, 0xff, 0x00, 0x1f, b'"', b'\\']),
                        0..40,
                    ),
                ],
            ) {
                prop_assert_eq!(clean_len(&bytes), clean_len_reference(&bytes));
            }

            #[test]
            fn documents_match_drisl_to_json(doc in any_doc()) {
                assert_same(&encode_value(&doc.value()).unwrap());
            }

            /// Damaged documents fail as `drisl_to_json` does, or convert as
            /// it does when the damage leaves valid DRISL.
            #[test]
            fn damaged_documents_match_drisl_to_json(
                doc in any_doc(),
                at in any::<prop::sample::Index>(),
                byte in any::<u8>(),
                damage in 0..3,
            ) {
                let mut bytes = encode_value(&doc.value()).unwrap();
                let at = at.index(bytes.len() + 1);
                match damage {
                    0 => bytes.truncate(at),
                    1 => bytes.insert(at, byte),
                    _ => match bytes.get_mut(at) {
                        Some(b) => *b = byte,
                        None => bytes.push(byte),
                    },
                }
                assert_same(&bytes);
            }
        }
    }

    /// The `data-encoding` decoding `base32_lower` replaced.
    fn base32_lower_reference(s: &str) -> Option<Vec<u8>> {
        let s = s.trim_end_matches('=');
        if s.bytes().any(|b| b.is_ascii_uppercase()) {
            return None;
        }
        data_encoding::BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())
            .ok()
    }

    proptest::proptest! {
        /// Valid symbols of every length (across the inline/heap boundary)
        /// and every final-group size, with one symbol sometimes replaced by
        /// an arbitrary char.
        #[test]
        fn base32_lower_matches_data_encoding(
            s in "[a-z2-7]{0,200}=?",
            swap in proptest::option::of((0usize..200, proptest::char::any())),
        ) {
            let mut s = s;
            if let Some((at, c)) = swap
                && let Some((i, _)) = s.char_indices().nth(at % (s.len() + 1))
            {
                s.replace_range(i..i + 1, c.encode_utf8(&mut [0; 4]));
            }
            let decoded = base32_lower(&s).map(|b| b.to_vec());
            proptest::prop_assert_eq!(decoded, base32_lower_reference(&s), "{:?}", s);
        }
    }

    #[test]
    fn base32_lower_rejects_what_data_encoding_rejects() {
        for s in [
            "a", "aaa", "aaaaaa", "ab", "aaab", "aaaab", "aaaaaab", "A", "8", "a=a", "é",
        ] {
            assert_eq!(
                base32_lower(s).as_deref(),
                base32_lower_reference(s).as_deref(),
                "{s:?}"
            );
        }
        // Trailing bits set (`ab` is 0b00000_00001): a different encoding of
        // the same byte, which canonical decoders refuse.
        assert!(base32_lower("ab").is_none());
        assert_eq!(base32_lower("aa").as_deref(), Some(&[0][..]));
    }

    #[test]
    fn base_x_keeps_leading_zeros() {
        assert_eq!(base_x("", BASE58BTC), Some(vec![]));
        assert_eq!(base_x("11", BASE58BTC), Some(vec![0, 0]));
        assert_eq!(base_x("1z", BASE58BTC), Some(vec![0, 57]));
        assert_eq!(base_x("5R", BASE58BTC), Some(vec![1, 0]));
        assert_eq!(base_x("0zz", BASE36), Some(vec![0, 5, 15]));
        assert_eq!(base_x("0", BASE58BTC), None);
    }
}
