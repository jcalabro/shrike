use crate::cbor::encode::{put_cid, put_head, put_text};
use crate::cbor::{CborError, Cid};

use crate::mst::MstError;

/// Maximum number of entries in a single MST node. Protects against OOM
/// from malicious CAR files containing nodes claiming millions of entries.
/// Real AT Protocol MST nodes typically have 4-32 entries.
const MAX_ENTRIES_PER_NODE: usize = 10_000;

/// Maximum MST key length. AT Protocol keys are `<collection-nsid>/<rkey>`,
/// bounded well under this (NSID <=317, rkey <=512). Bounding the prefix
/// length at decode time is defense-in-depth: it prevents a `p` of `u64::MAX`
/// (which would also decode differently on 32-bit via `n as usize`) from
/// reaching the load path, where it could only be caught by an incidental
/// `Vec::truncate` no-op. Matches atmos `maxKeyLen`.
pub(crate) const MAX_KEY_LEN: u64 = 1024;

/// On-disk CBOR representation of an MST node.
#[derive(Debug, Clone)]
pub struct NodeData {
    pub left: Option<Cid>,
    pub entries: Vec<EntryData>,
}

/// A single entry in an MST node's on-disk representation.
#[derive(Debug, Clone)]
pub struct EntryData {
    pub prefix_len: usize,
    pub key_suffix: Vec<u8>,
    pub value: Cid,
    pub right: Option<Cid>,
}

/// Encode a `NodeData` to DAG-CBOR bytes.
///
/// The on-wire format is a map with keys "e" (entries array) and "l" (left CID or null),
/// sorted in CBOR key order: "e" < "l".
#[inline]
pub fn encode_node_data(nd: &NodeData) -> Result<Vec<u8>, MstError> {
    // At most 49 bytes besides the entries, and 57 per entry besides its
    // suffix and subtree, while lengths are under 65536.
    let entries: usize = nd
        .entries
        .iter()
        .map(|e| 57 + e.key_suffix.len() + if e.right.is_some() { 41 } else { 1 })
        .sum();
    let mut buf = Vec::with_capacity(49 + entries);
    start_node(&mut buf, nd.entries.len());
    for e in &nd.entries {
        put_entry(
            &mut buf,
            e.prefix_len,
            &e.key_suffix,
            &e.value,
            e.right.as_ref(),
        );
    }
    finish_node(&mut buf, nd.left.as_ref());
    Ok(buf)
}

/// Begin a node block of `entries` entries in `buf`: the node map's
/// header, then "e" and the entries array's. Write the entries with
/// [`put_entry`], then end the block with [`finish_node`].
#[inline]
pub(crate) fn start_node(buf: &mut Vec<u8>, entries: usize) {
    // Map(2): keys "e" and "l" (already in CBOR sort order)
    put_head(buf, 5, 2);
    put_text(buf, "e");
    put_head(buf, 4, entries as u64);
}

/// Write a node entry: map(4) with keys in CBOR sort order "k", "p", "t",
/// "v".
#[inline]
pub(crate) fn put_entry(
    buf: &mut Vec<u8>,
    prefix_len: usize,
    key_suffix: &[u8],
    value: &Cid,
    right: Option<&Cid>,
) {
    put_head(buf, 5, 4);
    // "k" - key suffix as bytes
    put_text(buf, "k");
    put_head(buf, 2, key_suffix.len() as u64);
    buf.extend_from_slice(key_suffix);
    // "p" - prefix length
    put_text(buf, "p");
    put_head(buf, 0, prefix_len as u64);
    // "t" - right subtree CID or null
    put_text(buf, "t");
    put_cid_or_null(buf, right);
    // "v" - value CID
    put_text(buf, "v");
    put_cid(buf, value);
}

/// End a node block with "l" and the left subtree.
#[inline]
pub(crate) fn finish_node(buf: &mut Vec<u8>, left: Option<&Cid>) {
    put_text(buf, "l");
    put_cid_or_null(buf, left);
}

#[inline(always)]
fn put_cid_or_null(buf: &mut Vec<u8>, cid: Option<&Cid>) {
    match cid {
        Some(cid) => put_cid(buf, cid),
        None => buf.push(0xf6),
    }
}

/// Decode a `NodeData` from DAG-CBOR bytes.
#[inline]
pub fn decode_node_data(data: &[u8]) -> Result<NodeData, MstError> {
    use crate::cbor::Value;

    let val = crate::cbor::decode(data).map_err(cbor_err)?;
    let map = match val {
        Value::Map(m) => m,
        _ => return Err(MstError::InvalidNode("expected map".into())),
    };

    let mut nd = NodeData {
        left: None,
        entries: Vec::new(),
    };

    for (key, value) in map {
        match key {
            "e" => {
                let arr = match value {
                    Value::Array(a) => a,
                    _ => return Err(MstError::InvalidNode("expected array for 'e'".into())),
                };
                if arr.len() > MAX_ENTRIES_PER_NODE {
                    return Err(MstError::InvalidNode(format!(
                        "node has {} entries, exceeds maximum of {MAX_ENTRIES_PER_NODE}",
                        arr.len()
                    )));
                }
                nd.entries = Vec::with_capacity(arr.len());
                for item in arr {
                    nd.entries.push(decode_entry_data(item)?);
                }
            }
            "l" => match value {
                Value::Null => {}
                Value::Cid(c) => nd.left = Some(c),
                _ => return Err(MstError::InvalidNode("expected CID or null for 'l'".into())),
            },
            _ => return Err(MstError::InvalidNode(format!("unexpected key {key:?}"))),
        }
    }

    Ok(nd)
}

fn decode_entry_data(val: crate::cbor::Value<'_>) -> Result<EntryData, MstError> {
    use crate::cbor::Value;

    let map = match val {
        Value::Map(m) => m,
        _ => return Err(MstError::InvalidNode("expected map for entry".into())),
    };

    let mut prefix_len: Option<usize> = None;
    let mut key_suffix: Option<Vec<u8>> = None;
    let mut value: Option<Cid> = None;
    let mut right: Option<Cid> = None;

    for (key, v) in map {
        match key {
            "k" => match v {
                Value::Bytes(b) => key_suffix = Some(b.to_vec()),
                _ => return Err(MstError::InvalidNode("expected bytes for 'k'".into())),
            },
            "p" => match v {
                Value::Unsigned(n) => {
                    if n > MAX_KEY_LEN {
                        return Err(MstError::InvalidNode(format!(
                            "entry prefix length {n} exceeds max key length {MAX_KEY_LEN}"
                        )));
                    }
                    prefix_len = Some(n as usize);
                }
                _ => return Err(MstError::InvalidNode("expected uint for 'p'".into())),
            },
            "t" => match v {
                Value::Null => {}
                Value::Cid(c) => right = Some(c),
                _ => return Err(MstError::InvalidNode("expected CID or null for 't'".into())),
            },
            "v" => match v {
                Value::Cid(c) => value = Some(c),
                _ => return Err(MstError::InvalidNode("expected CID for 'v'".into())),
            },
            _ => {
                return Err(MstError::InvalidNode(format!(
                    "unexpected entry key {key:?}"
                )));
            }
        }
    }

    Ok(EntryData {
        prefix_len: prefix_len.ok_or_else(|| MstError::InvalidNode("missing 'p'".into()))?,
        key_suffix: key_suffix.ok_or_else(|| MstError::InvalidNode("missing 'k'".into()))?,
        value: value.ok_or_else(|| MstError::InvalidNode("missing 'v'".into()))?,
        right,
    })
}

fn cbor_err(e: CborError) -> MstError {
    MstError::Cbor(e.to_string())
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
pub(crate) mod tests {
    use super::*;
    use crate::cbor::Codec;
    use proptest::prelude::*;

    /// `encode_node_data` as it was, through `Encoder`: the oracle for the
    /// node encoding.
    pub(crate) fn reference_encode_node_data(nd: &NodeData) -> Vec<u8> {
        use crate::cbor::Encoder;
        fn cid_or_null(enc: &mut Encoder<&mut Vec<u8>>, cid: Option<Cid>) {
            match cid {
                Some(cid) => enc.encode_cid(&cid).unwrap(),
                None => enc.encode_null().unwrap(),
            }
        }
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_map_header(2).unwrap();
        enc.encode_text("e").unwrap();
        enc.encode_array_header(nd.entries.len() as u64).unwrap();
        for e in &nd.entries {
            enc.encode_map_header(4).unwrap();
            enc.encode_text("k").unwrap();
            enc.encode_bytes(&e.key_suffix).unwrap();
            enc.encode_text("p").unwrap();
            enc.encode_u64(e.prefix_len as u64).unwrap();
            enc.encode_text("t").unwrap();
            cid_or_null(&mut enc, e.right);
            enc.encode_text("v").unwrap();
            enc.encode_cid(&e.value).unwrap();
        }
        enc.encode_text("l").unwrap();
        cid_or_null(&mut enc, nd.left);
        buf
    }

    fn cid() -> impl Strategy<Value = Cid> {
        (any::<bool>(), any::<[u8; 4]>()).prop_map(|(raw, data)| {
            Cid::compute(if raw { Codec::Raw } else { Codec::Drisl }, &data)
        })
    }

    /// Entries whose lengths cross each head size boundary below 65536.
    fn entry() -> impl Strategy<Value = EntryData> {
        let len = prop_oneof![0usize..30, 250usize..260, 65530usize..65540];
        (
            len,
            prop::collection::vec(any::<u8>(), 0..300),
            cid(),
            prop::option::of(cid()),
        )
            .prop_map(|(prefix_len, key_suffix, value, right)| EntryData {
                prefix_len,
                key_suffix,
                value,
                right,
            })
    }

    proptest! {
        #[test]
        fn encode_node_data_matches_reference(
            left in prop::option::of(cid()),
            entries in prop::collection::vec(entry(), 0..30),
        ) {
            let nd = NodeData { left, entries };
            let data = encode_node_data(&nd).unwrap();
            prop_assert_eq!(&data, &reference_encode_node_data(&nd));
            // The capacity reserved up front is enough while the lengths
            // in the node are under 65536.
            let bound = 49 + nd.entries.iter()
                .map(|e| 57 + e.key_suffix.len() + if e.right.is_some() { 41 } else { 1 })
                .sum::<usize>();
            if nd.entries.iter().all(|e| e.prefix_len < 65536) {
                prop_assert!(data.len() <= bound, "{} > {}", data.len(), bound);
            }
        }
    }

    #[test]
    fn node_data_round_trip_empty() {
        let nd = NodeData {
            left: None,
            entries: vec![],
        };
        let data = encode_node_data(&nd).unwrap();
        let decoded = decode_node_data(&data).unwrap();
        assert!(decoded.left.is_none());
        assert!(decoded.entries.is_empty());
    }

    #[test]
    fn node_data_round_trip_with_entries() {
        let cid = Cid::compute(Codec::Drisl, b"test");
        let nd = NodeData {
            left: Some(cid),
            entries: vec![
                EntryData {
                    prefix_len: 0,
                    key_suffix: b"abc".to_vec(),
                    value: cid,
                    right: None,
                },
                EntryData {
                    prefix_len: 2,
                    key_suffix: b"d".to_vec(),
                    value: cid,
                    right: Some(cid),
                },
            ],
        };
        let data = encode_node_data(&nd).unwrap();
        let decoded = decode_node_data(&data).unwrap();
        assert_eq!(decoded.left, Some(cid));
        assert_eq!(decoded.entries.len(), 2);
        assert_eq!(decoded.entries[0].prefix_len, 0);
        assert_eq!(decoded.entries[0].key_suffix, b"abc");
        assert_eq!(decoded.entries[0].value, cid);
        assert!(decoded.entries[0].right.is_none());
        assert_eq!(decoded.entries[1].prefix_len, 2);
        assert_eq!(decoded.entries[1].key_suffix, b"d");
        assert_eq!(decoded.entries[1].value, cid);
        assert_eq!(decoded.entries[1].right, Some(cid));
    }

    #[test]
    fn decode_rejects_invalid_utf8_key_suffix() {
        // Build a NodeData with a key_suffix containing invalid UTF-8 bytes.
        // When populate_node tries to reconstruct the key, it should fail
        // with a clean error (not a panic).
        let cid = Cid::compute(Codec::Drisl, b"test");
        let nd = NodeData {
            left: None,
            entries: vec![EntryData {
                prefix_len: 0,
                key_suffix: vec![0xFF, 0xFE], // invalid UTF-8
                value: cid,
                right: None,
            }],
        };
        // Encoding should succeed (node.rs just writes raw bytes)
        let data = encode_node_data(&nd).unwrap();
        // Decoding should also succeed (it just stores raw bytes)
        let decoded = decode_node_data(&data).unwrap();
        assert_eq!(decoded.entries[0].key_suffix, &[0xFF, 0xFE]);
        // The UTF-8 validation happens in populate_node (tree.rs), not here.
        // But we verify the roundtrip preserves invalid bytes faithfully.
    }

    #[test]
    fn decode_rejects_prefix_len_overflow() {
        // Hand-build an entry whose "p" (prefix length) is u64::MAX. Decode must
        // reject it (bound at MAX_KEY_LEN) rather than carrying it through to a
        // 32-bit-truncating `n as usize` cast. Mirrors atmos
        // TestDecodeNodeData_PrefixLenOverflow_Rejected.
        let cid = Cid::compute(Codec::Drisl, b"v");
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            // map(2): "e" => [ entry ], "l" => null
            enc.encode_map_header(2).unwrap();
            enc.encode_text("e").unwrap();
            enc.encode_array_header(1).unwrap();
            // entry map(4): "k","p","t","v" in canonical order
            enc.encode_map_header(4).unwrap();
            enc.encode_text("k").unwrap();
            enc.encode_bytes(b"x").unwrap();
            enc.encode_text("p").unwrap();
            enc.encode_u64(u64::MAX).unwrap();
            enc.encode_text("t").unwrap();
            enc.encode_null().unwrap();
            enc.encode_text("v").unwrap();
            enc.encode_cid(&cid).unwrap();
            enc.encode_text("l").unwrap();
            enc.encode_null().unwrap();
        }
        let result = decode_node_data(&buf);
        assert!(result.is_err(), "p=u64::MAX must be rejected at decode");
    }

    #[test]
    fn decode_rejects_huge_entry_count() {
        // Craft CBOR that claims a massive entries array.
        // The CBOR itself is a map with "e" -> array(100_000_000).
        // Since CBOR decode limits collection size, this should fail.
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(2).unwrap();
            enc.encode_text("e").unwrap();
            // Array claiming 100 million entries — will be rejected by CBOR
            // collection size limit (MAX_COLLECTION_LEN = 500_000) before
            // MST's MAX_ENTRIES_PER_NODE kicks in.
            enc.encode_array_header(100_000_000).unwrap();
            enc.encode_text("l").unwrap();
            enc.encode_null().unwrap();
        }
        let result = decode_node_data(&buf);
        assert!(result.is_err());
    }
}
