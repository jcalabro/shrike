use shrike_cbor::Cid;

use crate::MstError;
use crate::tree::Tree;

/// The result of diffing two MST trees.
#[derive(Debug, Default)]
pub struct Diff {
    /// Keys that exist in the right tree but not in the left.
    pub added: Vec<(String, Cid)>,
    /// Keys that exist in both trees but with different values: (key, old_cid, new_cid).
    pub updated: Vec<(String, Cid, Cid)>,
    /// Keys that exist in the left tree but not in the right.
    pub removed: Vec<(String, Cid)>,
}

/// Compute the differences between two MST trees.
///
/// Walks both trees in sorted key order. When all entries are enumerated,
/// computes added/removed/updated sets.
pub fn diff(left: &mut Tree, right: &mut Tree) -> Result<Diff, MstError> {
    let left_entries = left.entries()?;
    let right_entries = right.entries()?;

    let mut result = Diff::default();

    let mut li = 0;
    let mut ri = 0;

    while li < left_entries.len() && ri < right_entries.len() {
        let (lk, lv) = &left_entries[li];
        let (rk, rv) = &right_entries[ri];

        match lk.cmp(rk) {
            std::cmp::Ordering::Equal => {
                if lv != rv {
                    result.updated.push((lk.clone(), *lv, *rv));
                }
                li += 1;
                ri += 1;
            }
            std::cmp::Ordering::Less => {
                result.removed.push((lk.clone(), *lv));
                li += 1;
            }
            std::cmp::Ordering::Greater => {
                result.added.push((rk.clone(), *rv));
                ri += 1;
            }
        }
    }

    // Remaining left entries are removals.
    while li < left_entries.len() {
        let (k, v) = &left_entries[li];
        result.removed.push((k.clone(), *v));
        li += 1;
    }

    // Remaining right entries are additions.
    while ri < right_entries.len() {
        let (k, v) = &right_entries[ri];
        result.added.push((k.clone(), *v));
        ri += 1;
    }

    Ok(result)
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
    use crate::block_store::MemBlockStore;
    use shrike_cbor::Codec;

    #[test]
    fn diff_detects_changes() {
        let store1 = MemBlockStore::new();
        let store2 = MemBlockStore::new();
        let mut t1 = Tree::new(Box::new(store1));
        let mut t2 = Tree::new(Box::new(store2));
        let cid_a = Cid::compute(Codec::Raw, b"a");
        let cid_b = Cid::compute(Codec::Raw, b"b");
        let cid_c = Cid::compute(Codec::Raw, b"c");
        t1.insert("a".to_string(), cid_a).unwrap();
        t1.insert("b".to_string(), cid_b).unwrap();
        t2.insert("a".to_string(), cid_a).unwrap();
        t2.insert("c".to_string(), cid_c).unwrap();
        let d = diff(&mut t1, &mut t2).unwrap();
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].0, "b");
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].0, "c");
    }

    #[test]
    fn diff_detects_updates() {
        let store1 = MemBlockStore::new();
        let store2 = MemBlockStore::new();
        let mut t1 = Tree::new(Box::new(store1));
        let mut t2 = Tree::new(Box::new(store2));
        let cid_v1 = Cid::compute(Codec::Drisl, b"v1");
        let cid_v2 = Cid::compute(Codec::Drisl, b"v2");
        t1.insert("a".to_string(), cid_v1).unwrap();
        t1.insert("b".to_string(), cid_v1).unwrap();
        t1.insert("c".to_string(), cid_v1).unwrap();
        t2.insert("a".to_string(), cid_v1).unwrap(); // unchanged
        t2.insert("b".to_string(), cid_v2).unwrap(); // updated
        t2.insert("d".to_string(), cid_v1).unwrap(); // created
        let d = diff(&mut t1, &mut t2).unwrap();
        assert_eq!(d.updated.len(), 1);
        assert_eq!(d.updated[0].0, "b");
        assert_eq!(d.removed.len(), 1);
        assert_eq!(d.removed[0].0, "c");
        assert_eq!(d.added.len(), 1);
        assert_eq!(d.added[0].0, "d");
    }

    #[test]
    fn diff_identical_trees() {
        let store1 = MemBlockStore::new();
        let store2 = MemBlockStore::new();
        let mut t1 = Tree::new(Box::new(store1));
        let mut t2 = Tree::new(Box::new(store2));
        let val = Cid::compute(Codec::Raw, b"v");
        t1.insert("a".to_string(), val).unwrap();
        t2.insert("a".to_string(), val).unwrap();
        let d = diff(&mut t1, &mut t2).unwrap();
        assert!(d.added.is_empty());
        assert!(d.updated.is_empty());
        assert!(d.removed.is_empty());
    }

    #[test]
    fn diff_empty_trees() {
        let store1 = MemBlockStore::new();
        let store2 = MemBlockStore::new();
        let mut t1 = Tree::new(Box::new(store1));
        let mut t2 = Tree::new(Box::new(store2));
        let d = diff(&mut t1, &mut t2).unwrap();
        assert!(d.added.is_empty());
        assert!(d.updated.is_empty());
        assert!(d.removed.is_empty());
    }
}
