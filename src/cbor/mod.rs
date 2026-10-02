//! DAG-CBOR (DRISL) encoding and decoding for AT Protocol.
//!
//! Provides Cid, Decoder, Encoder, and Value types for working with
//! deterministic CBOR. Maps are automatically sorted by key.
//!
//! ```
//! use shrike::cbor::{decode, encode_value, Value};
//!
//! let val = Value::Map(vec![("key", Value::Text("value"))]);
//! let bytes = encode_value(&val)?;
//! let decoded = decode(&bytes)?;
//! assert_eq!(decoded, val);
//! # Ok::<(), shrike::cbor::CborError>(())
//! ```

pub mod cid;
pub mod decode;
pub mod encode;
pub mod json;
pub mod value;
pub mod varint;

pub mod bump;

pub use cid::{Cid, Codec};
pub use decode::Decoder;
pub use encode::{Encoder, cbor_key_cmp, encode_text_map};
pub use value::Value;

pub use bump::BumpValue;

use thiserror::Error;

/// Errors produced by CBOR encoding, decoding, and CID operations.
#[derive(Debug, Error)]
pub enum CborError {
    /// The CBOR data is malformed or violates DRISL canonicalization rules.
    #[error("invalid CBOR: {0}")]
    InvalidCbor(String),
    /// A CID has an unsupported version, codec, or hash function.
    #[error("invalid CID: {0}")]
    InvalidCid(String),
    /// The value is outside the atproto data model, such as a float.
    #[error("not in the atproto data model: {0}")]
    DataModel(String),
    /// An underlying I/O error from the reader or writer.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

/// Decode a single DRISL value from bytes.
pub fn decode(data: &[u8]) -> Result<Value<'_>, CborError> {
    let mut dec = Decoder::new(data);
    let val = dec.decode()?;
    if !dec.is_empty() {
        return Err(CborError::InvalidCbor("trailing data after value".into()));
    }
    Ok(val)
}

/// Encode a Value to DRISL bytes.
///
/// Allocates a new buffer sized to fit typical AT Protocol records without
/// reallocation. For hot loops, use [`encode_value_into`] to reuse a buffer.
pub fn encode_value(value: &Value) -> Result<Vec<u8>, CborError> {
    let mut buf = Vec::with_capacity(estimated_size(value));
    write_value(&mut buf, value)?;
    Ok(buf)
}

/// Encode a Value into an existing buffer, appending to any existing contents.
///
/// This avoids allocation when encoding in a loop — clear and reuse the same
/// buffer across iterations:
///
/// ```
/// # use shrike::cbor::{Value, encode_value_into};
/// let mut buf = Vec::with_capacity(1024);
/// # let values: Vec<Value> = vec![];
/// for value in &values {
///     buf.clear();
///     encode_value_into(value, &mut buf).unwrap();
///     // use buf...
/// }
/// ```
pub fn encode_value_into(value: &Value, buf: &mut Vec<u8>) -> Result<(), CborError> {
    write_value(buf, value)
}

/// Estimate the encoded size of a Value. Slightly over-estimates to avoid
/// reallocation, since CBOR headers are 1-9 bytes and we assume worst-case
/// for small types.
#[inline(always)]
fn estimated_size(value: &Value) -> usize {
    match value {
        Value::Unsigned(_) | Value::Signed(_) => 9,
        Value::Float(_) => 9,
        Value::Bool(_) | Value::Null => 1,
        Value::Text(s) => 5 + s.len(),
        Value::Bytes(b) => 5 + b.len(),
        Value::Cid(_) => 41,
        // Scalars are sized inline; only containers cost a call.
        Value::Array(items) => estimated_array_size(items),
        Value::Map(entries) => estimated_map_size(entries),
    }
}

fn estimated_array_size(items: &[Value]) -> usize {
    let mut size = 5;
    for item in items {
        size += estimated_size(item);
    }
    size
}

fn estimated_map_size(entries: &[(&str, Value)]) -> usize {
    let mut size = 5;
    for (key, value) in entries {
        size += 5 + key.len() + estimated_size(value);
    }
    size
}

/// Append the encoding of `value` to `buf`.
///
/// Values are written straight into the `Vec`, which cannot fail to accept
/// bytes, rather than through [`Encoder`]. The first pass assumes every map
/// is already in canonical key order, as decoded values always are, and
/// checks each key against the one before it as it goes. If a key is out of
/// order (or a float is not finite), it starts over with a pass that sorts
/// maps that need it, so the result, error included, is what that pass
/// alone would give.
fn write_value(buf: &mut Vec<u8>, value: &Value) -> Result<(), CborError> {
    let start = buf.len();
    if write_item::<false>(buf, value).is_ok() {
        return Ok(());
    }
    buf.truncate(start);
    write_item::<true>(buf, value).map_err(|Rejected| encode::non_finite())
}

/// Why a [`write_item`] pass stopped: a float was not finite, or, in a pass
/// that does not sort, a map key was out of order.
struct Rejected;

/// One pass of [`write_value`]; `SORT` selects the pass that sorts maps.
/// Scalars are written inline; only containers cost a call.
#[inline(always)]
fn write_item<const SORT: bool>(buf: &mut Vec<u8>, value: &Value) -> Result<(), Rejected> {
    use encode::{put_cid, put_head, put_text};
    match value {
        Value::Unsigned(n) => put_head(buf, 0, *n),
        Value::Signed(n) => {
            if *n >= 0 {
                put_head(buf, 0, *n as u64)
            } else {
                put_head(buf, 1, (-1 - *n) as u64)
            }
        }
        Value::Float(f) => {
            if !f.is_finite() {
                return Err(Rejected);
            }
            buf.push(0xfb);
            buf.extend_from_slice(&f.to_bits().to_be_bytes());
        }
        Value::Bool(b) => buf.push(if *b { 0xf5 } else { 0xf4 }),
        Value::Null => buf.push(0xf6),
        Value::Text(s) => put_text(buf, s),
        Value::Bytes(b) => {
            put_head(buf, 2, b.len() as u64);
            buf.extend_from_slice(b);
        }
        Value::Cid(c) => put_cid(buf, c),
        Value::Array(items) => return write_array::<SORT>(buf, items),
        Value::Map(entries) => return write_map::<SORT>(buf, entries),
    }
    Ok(())
}

fn write_array<const SORT: bool>(buf: &mut Vec<u8>, items: &[Value]) -> Result<(), Rejected> {
    encode::put_head(buf, 4, items.len() as u64);
    for item in items {
        write_item::<SORT>(buf, item)?;
    }
    Ok(())
}

fn write_map<const SORT: bool>(
    buf: &mut Vec<u8>,
    entries: &[(&str, Value)],
) -> Result<(), Rejected> {
    encode::put_head(buf, 5, entries.len() as u64);
    // Sorting allocates, so the sorting pass first checks whether it must.
    if SORT
        && !entries
            .windows(2)
            .all(|w| cbor_key_cmp(w[0].0, w[1].0).is_lt())
    {
        let mut sorted: Vec<_> = entries.iter().collect();
        sorted.sort_by(|a, b| cbor_key_cmp(a.0, b.0));
        for (key, value) in sorted {
            encode::put_text(buf, key);
            write_item::<SORT>(buf, value)?;
        }
        return Ok(());
    }
    let mut prev: Option<&str> = None;
    for (key, value) in entries {
        if !SORT && prev.is_some_and(|prev| !cbor_key_cmp(prev, key).is_lt()) {
            return Err(Rejected);
        }
        encode::put_text(buf, key);
        write_item::<SORT>(buf, value)?;
        prev = Some(key);
    }
    Ok(())
}
