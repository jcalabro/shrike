pub mod cid;
pub mod decode;
pub mod encode;
pub mod value;
pub mod varint;

pub mod bump;

pub use cid::{Cid, Codec};
pub use decode::Decoder;
pub use encode::{Encoder, cbor_key_cmp, encode_text_map};
pub use value::Value;

pub use bump::BumpValue;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum CborError {
    #[error("invalid CBOR: {0}")]
    InvalidCbor(String),
    #[error("invalid CID: {0}")]
    InvalidCid(String),
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
    encode_value_to(&mut Encoder::new(&mut buf), value)?;
    Ok(buf)
}

/// Encode a Value into an existing buffer, appending to any existing contents.
///
/// This avoids allocation when encoding in a loop — clear and reuse the same
/// buffer across iterations:
///
/// ```
/// # use shrike_cbor::{Value, encode_value_into};
/// let mut buf = Vec::with_capacity(1024);
/// # let values: Vec<Value> = vec![];
/// for value in &values {
///     buf.clear();
///     encode_value_into(value, &mut buf).unwrap();
///     // use buf...
/// }
/// ```
pub fn encode_value_into(value: &Value, buf: &mut Vec<u8>) -> Result<(), CborError> {
    buf.reserve(estimated_size(value));
    encode_value_to(&mut Encoder::new(buf), value)
}

/// Estimate the encoded size of a Value. Slightly over-estimates to avoid
/// reallocation, since CBOR headers are 1-9 bytes and we assume worst-case
/// for small types.
fn estimated_size(value: &Value) -> usize {
    match value {
        Value::Unsigned(_) | Value::Signed(_) => 9,
        Value::Float(_) => 9,
        Value::Bool(_) | Value::Null => 1,
        Value::Text(s) => 5 + s.len(),
        Value::Bytes(b) => 5 + b.len(),
        Value::Cid(_) => 41,
        Value::Array(items) => 5 + items.iter().map(|i| estimated_size(i)).sum::<usize>(),
        Value::Map(entries) => {
            5 + entries
                .iter()
                .map(|(k, v)| 5 + k.len() + estimated_size(v))
                .sum::<usize>()
        }
    }
}

#[inline]
fn encode_value_to<W: std::io::Write>(
    enc: &mut Encoder<W>,
    value: &Value,
) -> Result<(), CborError> {
    match value {
        Value::Unsigned(n) => enc.encode_u64(*n),
        Value::Signed(n) => enc.encode_i64(*n),
        Value::Float(f) => enc.encode_f64(*f),
        Value::Bool(b) => enc.encode_bool(*b),
        Value::Null => enc.encode_null(),
        Value::Text(s) => enc.encode_text(s),
        Value::Bytes(b) => enc.encode_bytes(b),
        Value::Cid(c) => enc.encode_cid(c),
        Value::Array(items) => {
            enc.encode_array_header(items.len() as u64)?;
            for item in items {
                encode_value_to(enc, item)?;
            }
            Ok(())
        }
        Value::Map(entries) => {
            enc.encode_map_header(entries.len() as u64)?;
            // Check if keys are already in canonical CBOR order (common case
            // for data that came through the decoder). If so, skip the sort
            // entirely — avoids a Vec allocation and O(n log n) comparisons.
            let already_sorted = entries
                .windows(2)
                .all(|w| crate::encode::cbor_key_cmp(w[0].0, w[1].0) == std::cmp::Ordering::Less);
            if already_sorted {
                for (key, value) in entries {
                    enc.encode_text(key)?;
                    encode_value_to(enc, value)?;
                }
            } else {
                let mut sorted: Vec<_> = entries.iter().collect();
                sorted.sort_by(|a, b| crate::encode::cbor_key_cmp(a.0, b.0));
                for (key, value) in sorted {
                    enc.encode_text(key)?;
                    encode_value_to(enc, value)?;
                }
            }
            Ok(())
        }
    }
}
