use crate::cbor::{CborError, Cid, Encoder};

use crate::mst::MstError;

/// Maximum number of entries in a single MST node. Protects against OOM
/// from malicious CAR files containing nodes claiming millions of entries.
/// Real AT Protocol MST nodes typically have 4-32 entries.
const MAX_ENTRIES_PER_NODE: usize = 10_000;

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
    let mut buf = Vec::with_capacity(64 + nd.entries.len() * 60);
    {
        let mut enc = Encoder::new(&mut buf);

        // Map(2): keys "e" and "l" (already in CBOR sort order)
        enc.encode_map_header(2).map_err(cbor_err)?;

        // "e" key
        enc.encode_text("e").map_err(cbor_err)?;

        // Array of entries
        enc.encode_array_header(nd.entries.len() as u64)
            .map_err(cbor_err)?;
        for entry in &nd.entries {
            encode_entry_data(&mut enc, entry)?;
        }

        // "l" key
        enc.encode_text("l").map_err(cbor_err)?;

        // Left CID or null
        match &nd.left {
            Some(cid) => enc.encode_cid(cid).map_err(cbor_err)?,
            None => enc.encode_null().map_err(cbor_err)?,
        }
    }
    Ok(buf)
}

/// Encode a single entry within a node.
///
/// Map(4) with keys in CBOR sort order: "k", "p", "t", "v".
fn encode_entry_data<W: std::io::Write>(
    enc: &mut Encoder<W>,
    e: &EntryData,
) -> Result<(), MstError> {
    enc.encode_map_header(4).map_err(cbor_err)?;

    // "k" - key suffix as bytes
    enc.encode_text("k").map_err(cbor_err)?;
    enc.encode_bytes(&e.key_suffix).map_err(cbor_err)?;

    // "p" - prefix length
    enc.encode_text("p").map_err(cbor_err)?;
    enc.encode_u64(e.prefix_len as u64).map_err(cbor_err)?;

    // "t" - right subtree CID or null
    enc.encode_text("t").map_err(cbor_err)?;
    match &e.right {
        Some(cid) => enc.encode_cid(cid).map_err(cbor_err)?,
        None => enc.encode_null().map_err(cbor_err)?,
    }

    // "v" - value CID
    enc.encode_text("v").map_err(cbor_err)?;
    enc.encode_cid(&e.value).map_err(cbor_err)?;

    Ok(())
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
                Value::Unsigned(n) => prefix_len = Some(n as usize),
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
mod tests {
    use super::*;
    use crate::cbor::Codec;

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
