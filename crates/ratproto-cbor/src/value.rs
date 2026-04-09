use crate::Cid;

/// Decoded DRISL value. Text and bytes borrow from the input buffer (zero-copy).
#[derive(Debug, Clone, PartialEq)]
pub enum Value<'a> {
    Unsigned(u64),
    Signed(i64),
    Float(f64),
    Bool(bool),
    Null,
    Text(&'a str),
    Bytes(&'a [u8]),
    Cid(Cid),
    Array(Vec<Value<'a>>),
    Map(Vec<(&'a str, Value<'a>)>),
}
