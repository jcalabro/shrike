use crate::cbor::Cid;

/// Decoded DRISL value. Text and bytes borrow from the input buffer (zero-copy).
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    /// Non-negative integer (CBOR major type 0).
    Unsigned(u64),
    /// Negative integer (CBOR major type 1, stored as the actual negative value).
    Signed(i64),
    /// IEEE 754 double-precision float (NaN and Infinity are rejected).
    Float(f64),
    /// Boolean value.
    Bool(bool),
    /// CBOR null.
    Null,
    /// UTF-8 text string, borrowed from the input buffer.
    Text(&'a str),
    /// Byte string, borrowed from the input buffer.
    Bytes(&'a [u8]),
    /// Content identifier (decoded from CBOR tag 42).
    Cid(Cid),
    /// Ordered array of values.
    Array(Vec<Value<'a>>),
    /// Ordered map with string keys (canonical DRISL key order).
    Map(Vec<(&'a str, Value<'a>)>),
}
