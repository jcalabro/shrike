//! The record backing shared by archive and live commit events.
//!
//! Both transports converge on one representation: canonical DAG-CBOR bytes.
//! The archive already stores records that way; a live commit's dag-json
//! `record` is converted once at parse time (see [`super::json_cbor`]). Hiding
//! the storage behind [`Record`] lets the archive path hand out cheap
//! [`Bytes`] slices of one decompressed slab while the live path owns a fresh
//! buffer — without either leaking into the public API.
//!
//! A record exposes its bytes, decodes lazily into a borrowed generic value,
//! converts back to atproto JSON, and computes its CID on demand (cached), using
//! the wire-supplied CID when the commit carried one. Callers decode into a
//! generated lexicon type with [`Record::as_cbor`]:
//!
//! ```no_run
//! use shrike::api::app::bsky::FeedPost;
//! use shrike::jetstream::Record;
//!
//! fn decode(record: &Record) -> Result<FeedPost, Box<dyn std::error::Error>> {
//!     Ok(FeedPost::from_cbor(record.as_cbor())?)
//! }
//! ```

use std::sync::OnceLock;

use bytes::Bytes;

use super::error::{Error, Result};
use crate::cbor::{Cid, Codec, Decoder, Value};

/// A record's canonical DAG-CBOR body plus its (cached) CID.
///
/// Cloning is cheap: the CBOR body is a reference-counted [`Bytes`] handle, so
/// clones share the same allocation. A CID already computed or supplied by the
/// wire is carried across clones so it is never recomputed.
pub struct Record {
    /// Canonical DAG-CBOR bytes. Shared, never mutated after construction.
    cbor: Bytes,
    /// The record's CID. Seeded from the wire when the commit carried one,
    /// otherwise computed from `cbor` on first request and cached here.
    cid: OnceLock<Cid>,
}

impl Record {
    /// Build a record from canonical DAG-CBOR bytes with no known CID. The CID
    /// is computed lazily from the bytes on first request.
    ///
    /// The caller must pass *canonical* DAG-CBOR (the archive's on-disk form, or
    /// the output of [`super::json_cbor::record_json_to_dag_cbor`]); the CID is
    /// only meaningful for canonical bytes.
    pub fn from_canonical_cbor(cbor: impl Into<Bytes>) -> Self {
        Record {
            cbor: cbor.into(),
            cid: OnceLock::new(),
        }
    }

    /// Build a record from canonical DAG-CBOR bytes and a known CID (as the wire
    /// delivered it). The CID is used as-is and never recomputed.
    pub fn with_cid(cbor: impl Into<Bytes>, cid: Cid) -> Self {
        let cell = OnceLock::new();
        // Infallible: the cell was just created empty.
        let _ = cell.set(cid);
        Record {
            cbor: cbor.into(),
            cid: cell,
        }
    }

    /// Build a record from canonical DAG-CBOR and an optional wire CID string.
    ///
    /// A present `cid_hint` is parsed as a CIDv1 string; an unparseable value is
    /// rejected rather than silently recomputed, because a commit that carried a
    /// CID is asserting it. When absent, the CID is computed lazily.
    pub(crate) fn from_wire(cbor: impl Into<Bytes>, cid_hint: Option<&str>) -> Result<Self> {
        match cid_hint {
            Some(s) => {
                let cid: Cid = s
                    .parse()
                    .map_err(|_| Error::MalformedEvent("commit cid is not a valid CID"))?;
                Ok(Record::with_cid(cbor, cid))
            }
            None => Ok(Record::from_canonical_cbor(cbor)),
        }
    }

    /// The record's canonical DAG-CBOR bytes.
    ///
    /// Decode into a generated lexicon type with `Type::from_cbor(record.as_cbor())`.
    pub fn as_cbor(&self) -> &[u8] {
        &self.cbor
    }

    /// The record's CID, computed from its canonical bytes on first call and
    /// cached, or the wire-supplied CID when the commit carried one.
    pub fn cid(&self) -> Cid {
        *self
            .cid
            .get_or_init(|| Cid::compute(Codec::Drisl, &self.cbor))
    }

    /// Decode the record into a borrowed generic DAG-CBOR [`Value`].
    ///
    /// Text and byte strings borrow from the record's buffer (zero-copy). This
    /// is the untyped escape hatch; prefer a generated `Type::from_cbor` for a
    /// known schema.
    pub fn decode_value(&self) -> Result<Value<'_>> {
        Decoder::new(&self.cbor)
            .decode()
            .map_err(|_| Error::InvalidRecord("record is not valid DAG-CBOR"))
    }

    /// Convert the record to owned atproto dag-json.
    ///
    /// Byte strings become `{"$bytes":"<base64>"}` (unpadded, per the atproto
    /// data model) and CID links become `{"$link":"<cid>"}`, inverting
    /// [`super::json_cbor::record_json_to_dag_cbor`].
    pub fn to_json(&self) -> Result<serde_json::Value> {
        value_to_json(&self.decode_value()?)
    }
}

impl Clone for Record {
    fn clone(&self) -> Self {
        let cid = OnceLock::new();
        if let Some(known) = self.cid.get() {
            // Infallible: `cid` was just created empty.
            let _ = cid.set(*known);
        }
        Record {
            cbor: self.cbor.clone(),
            cid,
        }
    }
}

impl std::fmt::Debug for Record {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not dump the record body; show its size and whether a CID is known.
        f.debug_struct("Record")
            .field("cbor_len", &self.cbor.len())
            .field("cid", &self.cid.get())
            .finish()
    }
}

/// Map a decoded DAG-CBOR value to atproto dag-json.
fn value_to_json(value: &Value<'_>) -> Result<serde_json::Value> {
    use serde_json::Value as J;
    Ok(match value {
        Value::Unsigned(u) => J::Number((*u).into()),
        Value::Signed(i) => J::Number((*i).into()),
        // The atproto data model has no floats; canonical record bytes never
        // contain one, so encountering it means the bytes are not a record.
        Value::Float(_) => return Err(Error::InvalidRecord("float not in atproto data model")),
        Value::Bool(b) => J::Bool(*b),
        Value::Null => J::Null,
        Value::Text(s) => J::String((*s).to_owned()),
        Value::Bytes(b) => {
            let mut obj = serde_json::Map::with_capacity(1);
            obj.insert(
                "$bytes".to_owned(),
                J::String(data_encoding::BASE64_NOPAD.encode(b)),
            );
            J::Object(obj)
        }
        Value::Cid(c) => {
            let mut obj = serde_json::Map::with_capacity(1);
            obj.insert("$link".to_owned(), J::String(c.to_string()));
            J::Object(obj)
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                out.push(value_to_json(item)?);
            }
            J::Array(out)
        }
        Value::Map(entries) => {
            let mut obj = serde_json::Map::with_capacity(entries.len());
            for (k, v) in entries {
                obj.insert((*k).to_owned(), value_to_json(v)?);
            }
            J::Object(obj)
        }
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use crate::cbor::Encoder;

    /// A tiny canonical record: `{"hello": 5}`.
    fn hello_five() -> Vec<u8> {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_map_header(1).unwrap();
        enc.encode_text("hello").unwrap();
        enc.encode_i64(5).unwrap();
        buf
    }

    #[test]
    fn computes_and_caches_cid() {
        let bytes = hello_five();
        let record = Record::from_canonical_cbor(bytes.clone());
        let expected = Cid::compute(Codec::Drisl, &bytes);
        assert_eq!(record.cid(), expected);
        // Second call returns the cached value.
        assert_eq!(record.cid(), expected);
    }

    #[test]
    fn wire_cid_is_used_verbatim() {
        // A deliberately unrelated CID: `with_cid` must trust it, not recompute.
        let bytes = hello_five();
        let other = Cid::compute(Codec::Drisl, b"something else");
        let record = Record::with_cid(bytes, other);
        assert_eq!(record.cid(), other);
    }

    #[test]
    fn clone_shares_bytes_and_keeps_known_cid() {
        let bytes = hello_five();
        let record = Record::from_canonical_cbor(bytes);
        let cid = record.cid(); // force computation + cache
        let clone = record.clone();
        assert_eq!(clone.as_cbor(), record.as_cbor());
        // The clone carries the cached CID.
        assert_eq!(clone.cid.get(), Some(&cid));
    }

    #[test]
    fn from_wire_rejects_bad_cid() {
        let bytes = hello_five();
        assert!(matches!(
            Record::from_wire(bytes, Some("not-a-cid")),
            Err(Error::MalformedEvent(_))
        ));
    }

    #[test]
    fn decode_value_borrows_and_matches() {
        let record = Record::from_canonical_cbor(hello_five());
        let value = record.decode_value().unwrap();
        assert_eq!(value, Value::Map(vec![("hello", Value::Unsigned(5))]));
    }

    #[test]
    fn to_json_round_trips_scalars() {
        let record = Record::from_canonical_cbor(hello_five());
        assert_eq!(record.to_json().unwrap(), serde_json::json!({"hello": 5}));
    }
}
