#![allow(
    clippy::too_many_arguments,
    clippy::unreachable,
    clippy::unwrap_used,
    dead_code
)]

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use shrike::car::Block;
use shrike::cbor::{Cid, Codec, Encoder, Value, encode_text_map};
use shrike::crypto::{P256SigningKey, SigningKey};
use shrike::mst::{BlockStore, MstError, Tree};
use shrike::repo::Commit;
use shrike::sync::{RawCommit, RawRepoOp};
use shrike::syntax::{Did, Tid};

const FIXTURE_DID: &str = "did:plc:test123456789abcdefghij";
const FIXTURE_PATH: &str = "app.bsky.feed.post/abc";
const FIXTURE_TIME: &str = "2026-06-09T15:00:00.000Z";
const RECORD_V1: &[u8] = b"\xa1\x64text\x65first";
const RECORD_V2: &[u8] = b"\xa1\x64text\x66second";

#[derive(Debug, Clone)]
pub struct CommitFixture {
    pub raw_commit: RawCommit,
    pub prev_data: Cid,
    pub post_data: Cid,
    pub prev_record: Option<Cid>,
    pub record: Option<Cid>,
    pub signing_key_bytes: [u8; 32],
    pub public_key_bytes: [u8; 33],
}

#[derive(Clone, Default)]
struct FixtureStore {
    blocks: Rc<RefCell<HashMap<Cid, Vec<u8>>>>,
}

impl FixtureStore {
    fn new() -> Self {
        Self::default()
    }

    fn insert_raw(&self, data: &[u8]) -> Cid {
        let cid = Cid::compute(Codec::Drisl, data);
        self.put_block(cid, data.to_vec()).unwrap();
        cid
    }

    fn blocks(&self) -> Vec<Block> {
        self.blocks
            .borrow()
            .iter()
            .map(|(cid, data)| Block {
                cid: *cid,
                data: data.clone(),
            })
            .collect()
    }
}

impl BlockStore for FixtureStore {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError> {
        self.blocks
            .borrow()
            .get(cid)
            .cloned()
            .ok_or_else(|| MstError::BlockNotFound(cid.to_string()))
    }

    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError> {
        self.blocks.borrow_mut().insert(cid, data);
        Ok(())
    }

    fn has_block(&self, cid: &Cid) -> Result<bool, MstError> {
        Ok(self.blocks.borrow().contains_key(cid))
    }
}

pub fn commit_fixture_create() -> CommitFixture {
    commit_fixture(CommitAction::Create)
}

pub fn commit_fixture_update() -> CommitFixture {
    commit_fixture(CommitAction::Update)
}

pub fn commit_fixture_delete() -> CommitFixture {
    commit_fixture(CommitAction::Delete)
}

/// Build a first-sighting create fixture for an arbitrary DID, re-signing the
/// commit with a fresh key. Useful for multi-DID streaming tests.
pub fn commit_fixture_create_for_did(did_str: &str, seq: i64) -> CommitFixture {
    let did = Did::try_from(did_str).unwrap();
    let old_cid = Cid::compute(Codec::Drisl, RECORD_V1);
    let (post_data, mut post_blocks) = tree_root(&[(FIXTURE_PATH, RECORD_V1)]);
    let rev = Tid::new(1_700_000_000_000_000, 0);
    let signed_commit = push_commit_block(&did, rev, post_data, &mut post_blocks);
    let car = shrike::car::write_all(&[signed_commit.cid], &post_blocks).unwrap();

    CommitFixture {
        raw_commit: RawCommit {
            repo: did,
            rev,
            seq,
            time: FIXTURE_TIME.to_owned(),
            since: None,
            commit: signed_commit.cid,
            blocks: car,
            ops: vec![RawRepoOp {
                action: "create".to_owned(),
                path: FIXTURE_PATH.to_owned(),
                cid: Some(old_cid),
                prev: None,
            }],
            blobs: Vec::new(),
            prev_data: Some(tree_root(&[]).0),
            too_big: false,
            rebase: false,
        },
        prev_data: tree_root(&[]).0,
        post_data,
        prev_record: None,
        record: Some(old_cid),
        signing_key_bytes: signed_commit.signing_key_bytes,
        public_key_bytes: signed_commit.public_key_bytes,
    }
}

/// Build a chain of `count` valid create-commits for one DID, all signed with
/// the same fresh key. Commit `i` creates a new record path and chains off
/// commit `i-1` (its `prev_data` equals the previous post-state root). The
/// returned fixtures' `public_key_bytes` are identical, so a single resolver
/// entry verifies the whole chain. Revs and seqs increase monotonically.
pub fn commit_chain_for_did(did_str: &str, count: usize) -> Vec<CommitFixture> {
    let did = Did::try_from(did_str).unwrap();
    let signing_key = P256SigningKey::generate();
    let public_key_bytes = signing_key.public_key().to_bytes();
    let signing_key_bytes = signing_key.to_bytes();

    let mut records: Vec<(String, Vec<u8>)> = Vec::new();
    let mut prev_root = tree_root(&[]).0;
    let mut out = Vec::with_capacity(count);

    for i in 0..count {
        let path = format!("app.bsky.feed.post/p{i}");
        let record = format!("\u{a1}dtextrec{i}").into_bytes();
        let record_cid = Cid::compute(Codec::Drisl, &record);
        records.push((path.clone(), record));

        let refs: Vec<(&str, &[u8])> = records
            .iter()
            .map(|(p, r)| (p.as_str(), r.as_slice()))
            .collect();
        let (post_data, mut post_blocks) = tree_root(&refs);

        let rev = Tid::new(1_700_000_000_000_000 + i as u64, 0);
        let mut commit = Commit {
            did: did.clone(),
            version: 3,
            rev,
            prev: None,
            data: post_data,
            sig: None,
        };
        commit.sign(&signing_key).unwrap();
        let commit_data = commit.to_cbor().unwrap();
        let commit_cid = Cid::compute(Codec::Drisl, &commit_data);
        post_blocks.push(Block {
            cid: commit_cid,
            data: commit_data,
        });
        let car = shrike::car::write_all(&[commit_cid], &post_blocks).unwrap();

        out.push(CommitFixture {
            raw_commit: RawCommit {
                repo: did.clone(),
                rev,
                seq: 100 + i as i64,
                time: FIXTURE_TIME.to_owned(),
                since: None,
                commit: commit_cid,
                blocks: car,
                ops: vec![RawRepoOp {
                    action: "create".to_owned(),
                    path,
                    cid: Some(record_cid),
                    prev: None,
                }],
                blobs: Vec::new(),
                prev_data: Some(prev_root),
                too_big: false,
                rebase: false,
            },
            prev_data: prev_root,
            post_data,
            prev_record: None,
            record: Some(record_cid),
            signing_key_bytes,
            public_key_bytes,
        });
        prev_root = post_data;
    }
    out
}

pub fn commit_fixture_multi_op_disjoint() -> CommitFixture {
    let did = Did::try_from(FIXTURE_DID).unwrap();
    let update_path = FIXTURE_PATH.to_owned();
    let create_path = "app.bsky.feed.post/new".to_owned();
    let old_cid = Cid::compute(Codec::Drisl, RECORD_V1);
    let new_cid = Cid::compute(Codec::Drisl, RECORD_V2);
    let created_cid = Cid::compute(Codec::Drisl, b"\xa1\x64text\x67created");

    let (prev_data, _) = tree_root(&[(FIXTURE_PATH, RECORD_V1)]);
    let (post_data, mut post_blocks) = tree_root(&[
        (FIXTURE_PATH, RECORD_V2),
        ("app.bsky.feed.post/new", b"\xa1\x64text\x67created"),
    ]);
    let rev = Tid::new(1_700_000_000_000_000, 1);
    let signed_commit = push_commit_block(&did, rev, post_data, &mut post_blocks);
    let car = shrike::car::write_all(&[signed_commit.cid], &post_blocks).unwrap();

    CommitFixture {
        raw_commit: RawCommit {
            repo: did,
            rev,
            seq: 43,
            time: FIXTURE_TIME.to_owned(),
            since: None,
            commit: signed_commit.cid,
            blocks: car,
            ops: vec![
                RawRepoOp {
                    action: "update".to_owned(),
                    path: update_path,
                    cid: Some(new_cid),
                    prev: Some(old_cid),
                },
                RawRepoOp {
                    action: "create".to_owned(),
                    path: create_path,
                    cid: Some(created_cid),
                    prev: None,
                },
            ],
            blobs: Vec::new(),
            prev_data: Some(prev_data),
            too_big: false,
            rebase: false,
        },
        prev_data,
        post_data,
        prev_record: Some(old_cid),
        record: Some(new_cid),
        signing_key_bytes: signed_commit.signing_key_bytes,
        public_key_bytes: signed_commit.public_key_bytes,
    }
}

pub fn commit_fixture_missing_commit_block() -> CommitFixture {
    let mut fixture = commit_fixture_create();
    let (roots, blocks) = shrike::car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let blocks_without_commit: Vec<Block> = blocks
        .into_iter()
        .filter(|block| block.cid != fixture.raw_commit.commit)
        .collect();
    fixture.raw_commit.blocks = shrike::car::write_all(&roots, &blocks_without_commit).unwrap();
    fixture
}

pub fn commit_fixture_root_mismatch() -> CommitFixture {
    let mut fixture = commit_fixture_create();
    let wrong_root = Cid::compute(Codec::Drisl, b"wrong-root");
    let (_, blocks) = shrike::car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    fixture.raw_commit.blocks = shrike::car::write_all(&[wrong_root], &blocks).unwrap();
    fixture
}

pub fn commit_fixture_cid_data_mismatch() -> CommitFixture {
    let mut fixture = commit_fixture_create();
    let (roots, mut blocks) = shrike::car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    let block = blocks
        .iter_mut()
        .find(|block| block.cid != fixture.raw_commit.commit)
        .unwrap();
    block.data.push(0xff);
    fixture.raw_commit.blocks = shrike::car::write_all(&roots, &blocks).unwrap();
    fixture
}

pub fn commit_fixture_duplicate_paths() -> CommitFixture {
    let mut fixture = commit_fixture_missing_commit_block();
    fixture
        .raw_commit
        .ops
        .push(fixture.raw_commit.ops[0].clone());
    fixture
}

/// Build the CAR a real `#sync` frame carries: only the signed commit block,
/// with the commit CID as the first root. No MST nodes, no records.
pub fn sync_commit_car(fixture: &CommitFixture) -> Vec<u8> {
    let (roots, blocks) = shrike::car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    assert_eq!(roots, vec![fixture.raw_commit.commit]);
    let commit_block = blocks
        .into_iter()
        .find(|block| block.cid == fixture.raw_commit.commit)
        .unwrap();
    shrike::car::write_all(
        &[fixture.raw_commit.commit],
        std::slice::from_ref(&commit_block),
    )
    .unwrap()
}

pub fn mutate_signed_commit(fixture: &mut CommitFixture, mutate: impl FnOnce(&mut Commit)) {
    let (roots, mut blocks) = shrike::car::read_all(&fixture.raw_commit.blocks[..]).unwrap();
    assert_eq!(roots, vec![fixture.raw_commit.commit]);
    let block = blocks
        .iter_mut()
        .find(|block| block.cid == fixture.raw_commit.commit)
        .unwrap();
    let mut commit = Commit::from_cbor(&block.data).unwrap();
    mutate(&mut commit);
    commit.sig = None;
    let signing_key = P256SigningKey::from_bytes(&fixture.signing_key_bytes).unwrap();
    commit.sign(&signing_key).unwrap();
    block.data = commit.to_cbor().unwrap();
    block.cid = Cid::compute(Codec::Drisl, &block.data);
    fixture.raw_commit.commit = block.cid;
    fixture.raw_commit.blocks = shrike::car::write_all(&[block.cid], &blocks).unwrap();
}

enum CommitAction {
    Create,
    Update,
    Delete,
}

fn commit_fixture(action: CommitAction) -> CommitFixture {
    let did = Did::try_from(FIXTURE_DID).unwrap();
    let path = FIXTURE_PATH.to_owned();
    let old_cid = Cid::compute(Codec::Drisl, RECORD_V1);
    let new_cid = Cid::compute(Codec::Drisl, RECORD_V2);

    let (prev_data, prev_record) = match action {
        CommitAction::Create => (tree_root(&[]).0, None),
        CommitAction::Update | CommitAction::Delete => {
            let (root, _) = tree_root(&[(FIXTURE_PATH, RECORD_V1)]);
            (root, Some(old_cid))
        }
    };

    let (post_data, mut post_blocks, record) = match action {
        CommitAction::Create => {
            let (root, blocks) = tree_root(&[(FIXTURE_PATH, RECORD_V1)]);
            (root, blocks, Some(old_cid))
        }
        CommitAction::Update => {
            let (root, blocks) = tree_root(&[(FIXTURE_PATH, RECORD_V2)]);
            (root, blocks, Some(new_cid))
        }
        CommitAction::Delete => {
            let (root, blocks) = tree_root(&[]);
            (root, blocks, None)
        }
    };

    let rev = Tid::new(1_700_000_000_000_000, 0);
    let signed_commit = push_commit_block(&did, rev, post_data, &mut post_blocks);
    let car = shrike::car::write_all(&[signed_commit.cid], &post_blocks).unwrap();

    let op = match action {
        CommitAction::Create => RawRepoOp {
            action: "create".to_owned(),
            path,
            cid: Some(old_cid),
            prev: None,
        },
        CommitAction::Update => RawRepoOp {
            action: "update".to_owned(),
            path,
            cid: Some(new_cid),
            prev: Some(old_cid),
        },
        CommitAction::Delete => RawRepoOp {
            action: "delete".to_owned(),
            path,
            cid: None,
            prev: Some(old_cid),
        },
    };

    CommitFixture {
        raw_commit: RawCommit {
            repo: did,
            rev,
            seq: 42,
            time: FIXTURE_TIME.to_owned(),
            since: None,
            commit: signed_commit.cid,
            blocks: car,
            ops: vec![op],
            blobs: Vec::new(),
            prev_data: Some(prev_data),
            too_big: false,
            rebase: false,
        },
        prev_data,
        post_data,
        prev_record,
        record,
        signing_key_bytes: signed_commit.signing_key_bytes,
        public_key_bytes: signed_commit.public_key_bytes,
    }
}

struct SignedCommitBlock {
    cid: Cid,
    signing_key_bytes: [u8; 32],
    public_key_bytes: [u8; 33],
}

fn push_commit_block(
    did: &Did,
    rev: Tid,
    post_data: Cid,
    blocks: &mut Vec<Block>,
) -> SignedCommitBlock {
    let mut commit = Commit {
        did: did.clone(),
        version: 3,
        rev,
        prev: None,
        data: post_data,
        sig: None,
    };
    let signing_key = P256SigningKey::generate();
    commit.sign(&signing_key).unwrap();
    let signing_key_bytes = signing_key.to_bytes();
    let public_key_bytes = signing_key.public_key().to_bytes();
    let commit_data = commit.to_cbor().unwrap();
    let commit_cid = Cid::compute(Codec::Drisl, &commit_data);
    blocks.push(Block {
        cid: commit_cid,
        data: commit_data,
    });
    SignedCommitBlock {
        cid: commit_cid,
        signing_key_bytes,
        public_key_bytes,
    }
}

fn tree_root(records: &[(&str, &[u8])]) -> (Cid, Vec<Block>) {
    let store = FixtureStore::new();
    let mut tree = Tree::new(Box::new(store.clone()));
    for (path, record) in records {
        let cid = store.insert_raw(record);
        tree.insert((*path).to_owned(), cid).unwrap();
    }
    let root = tree.root_cid().unwrap();
    (root, store.blocks())
}

pub struct RawOp {
    action: &'static str,
    path: &'static str,
    cid: Option<Cid>,
    prev: Option<Cid>,
}

#[derive(Clone, Copy)]
enum OptionalText<'a> {
    Missing,
    Null,
    Value(&'a str),
    InvalidInt,
}

#[derive(Clone, Copy)]
enum OptionalCid {
    Missing,
    Null,
    Value(Cid),
    InvalidText,
}

#[derive(Clone, Copy)]
enum RequiredBool {
    Missing,
    Null,
    Value(bool),
}

struct CommitOptions<'a> {
    since: OptionalText<'a>,
    prev_data: OptionalCid,
    too_big: RequiredBool,
    rebase: RequiredBool,
    unknown_fields: bool,
    op_prev_null: bool,
    op_prev_invalid_text: bool,
    op_unknown_fields: bool,
}

impl CommitOptions<'_> {
    fn standard(prev_data: Cid) -> Self {
        Self {
            since: OptionalText::Null,
            prev_data: OptionalCid::Value(prev_data),
            too_big: RequiredBool::Value(false),
            rebase: RequiredBool::Value(false),
            unknown_fields: false,
            op_prev_null: false,
            op_prev_invalid_text: false,
            op_unknown_fields: false,
        }
    }
}

pub fn raw_op(
    action: &'static str,
    path: &'static str,
    cid: Option<Cid>,
    prev: Option<Cid>,
) -> RawOp {
    RawOp {
        action,
        path,
        cid,
        prev,
    }
}

/// Encode a `#commit` firehose frame directly from a fixture's `RawCommit`,
/// preserving its real op paths/cids/prev links (unlike the `&'static str`
/// `RawOp` builder used by parser tests). Used by streaming integration tests
/// that need many distinct, chain-valid commits.
pub fn commit_frame_for_fixture(fixture: &CommitFixture) -> Vec<u8> {
    let raw = &fixture.raw_commit;
    let keys = [
        "blocks", "commit", "ops", "prevData", "rebase", "repo", "rev", "seq", "time", "tooBig",
    ];
    encode_frame("#commit", |enc| {
        encode_text_map(enc, &keys, |enc, key| match key {
            "blocks" => enc.encode_bytes(&raw.blocks),
            "commit" => enc.encode_cid(&raw.commit),
            "rebase" => enc.encode_bool(raw.rebase),
            "ops" => {
                enc.encode_array_header(raw.ops.len() as u64)?;
                for op in &raw.ops {
                    let mut op_keys = vec!["action", "path"];
                    if op.cid.is_some() {
                        op_keys.push("cid");
                    }
                    if op.prev.is_some() {
                        op_keys.push("prev");
                    }
                    encode_text_map(enc, &op_keys, |enc, k| match k {
                        "action" => enc.encode_text(&op.action),
                        "path" => enc.encode_text(&op.path),
                        "cid" => enc.encode_cid(&op.cid.unwrap()),
                        "prev" => enc.encode_cid(&op.prev.unwrap()),
                        _ => unreachable!(),
                    })?;
                }
                Ok(())
            }
            "prevData" => match raw.prev_data {
                Some(cid) => enc.encode_cid(&cid),
                None => enc.encode_null(),
            },
            "repo" => enc.encode_text(raw.repo.as_str()),
            "rev" => enc.encode_text(&raw.rev.to_string()),
            "seq" => enc.encode_i64(raw.seq),
            "time" => enc.encode_text(&raw.time),
            "tooBig" => enc.encode_bool(raw.too_big),
            _ => unreachable!(),
        })
    })
}

pub fn commit_frame_with_since_and_flags(
    did: &shrike::Did,
    rev: &str,
    since: &str,
    seq: i64,
    commit: Cid,
    prev_data: Cid,
    blocks: &[u8],
    too_big: bool,
    rebase: bool,
    ops: Vec<RawOp>,
) -> Vec<u8> {
    let options = CommitOptions {
        since: OptionalText::Value(since),
        prev_data: OptionalCid::Value(prev_data),
        too_big: RequiredBool::Value(too_big),
        rebase: RequiredBool::Value(rebase),
        unknown_fields: false,
        op_prev_null: false,
        op_prev_invalid_text: false,
        op_unknown_fields: false,
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            rev,
            seq,
            Some(commit),
            Value::Bytes(blocks),
            ops,
            options,
        )
    })
}

pub fn commit_frame_without_optional_links(
    did: &shrike::Did,
    null_optional_links: bool,
) -> Vec<u8> {
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let optional_text = if null_optional_links {
        OptionalText::Null
    } else {
        OptionalText::Missing
    };
    let optional_cid = if null_optional_links {
        OptionalCid::Null
    } else {
        OptionalCid::Missing
    };
    let options = CommitOptions {
        since: optional_text,
        prev_data: optional_cid,
        too_big: RequiredBool::Value(false),
        rebase: RequiredBool::Value(false),
        unknown_fields: false,
        op_prev_null: null_optional_links,
        op_prev_invalid_text: false,
        op_unknown_fields: false,
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![raw_op(
                "update",
                "app.bsky.feed.post/abc",
                Some(commit),
                None,
            )],
            options,
        )
    })
}

pub fn commit_frame_with_unknown_fields(did: &shrike::Did) -> Vec<u8> {
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let options = CommitOptions {
        unknown_fields: true,
        op_unknown_fields: true,
        ..CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"))
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![raw_op(
                "update",
                "app.bsky.feed.post/abc",
                Some(commit),
                None,
            )],
            options,
        )
    })
}

pub fn commit_frame_with_bad_since_type(did: &shrike::Did) -> Vec<u8> {
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let options = CommitOptions {
        since: OptionalText::InvalidInt,
        ..CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"))
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![],
            options,
        )
    })
}

pub fn commit_frame_with_bad_prev_data_type(did: &shrike::Did) -> Vec<u8> {
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let options = CommitOptions {
        prev_data: OptionalCid::InvalidText,
        ..CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"))
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![],
            options,
        )
    })
}

pub fn commit_frame_with_bad_op_prev_type(did: &shrike::Did) -> Vec<u8> {
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let options = CommitOptions {
        op_prev_invalid_text: true,
        ..CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"))
    };

    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![raw_op(
                "update",
                "app.bsky.feed.post/abc",
                Some(commit),
                None,
            )],
            options,
        )
    })
}

pub fn sync_frame(did: &shrike::Did, rev: &str, seq: i64, blocks: &[u8]) -> Vec<u8> {
    encode_frame("#sync", |enc| {
        encode_text_map(
            enc,
            &["blocks", "did", "rev", "seq", "time"],
            |enc, key| match key {
                "blocks" => enc.encode_bytes(blocks),
                "did" => enc.encode_text(did.as_str()),
                "rev" => enc.encode_text(rev),
                "seq" => enc.encode_i64(seq),
                "time" => enc.encode_text("2026-06-09T15:00:00.000Z"),
                _ => unreachable!(),
            },
        )
    })
}

pub fn sync_frame_with_unknown(did: &shrike::Did) -> Vec<u8> {
    encode_frame("#sync", |enc| {
        encode_text_map(
            enc,
            &["blocks", "did", "rev", "seq", "time", "unknownSyncField"],
            |enc, key| match key {
                "blocks" => enc.encode_bytes(b"sync-car"),
                "did" => enc.encode_text(did.as_str()),
                "rev" => enc.encode_text("3zzzzzzzzzzzz"),
                "seq" => enc.encode_i64(77),
                "time" => enc.encode_text("2026-06-09T15:00:00.000Z"),
                "unknownSyncField" => enc.encode_text("ignored"),
                _ => unreachable!(),
            },
        )
    })
}

pub fn account_frame(
    did: &shrike::Did,
    seq: i64,
    active: bool,
    status: Option<&str>,
    time: &str,
) -> Vec<u8> {
    let mut keys = vec!["active", "did", "seq", "time"];
    if status.is_some() {
        keys.push("status");
    }

    encode_frame("#account", |enc| {
        encode_text_map(enc, &keys, |enc, key| match key {
            "active" => enc.encode_bool(active),
            "did" => enc.encode_text(did.as_str()),
            "seq" => enc.encode_i64(seq),
            "status" => enc.encode_text(status.unwrap()),
            "time" => enc.encode_text(time),
            _ => unreachable!(),
        })
    })
}

pub fn account_frame_with_unknown(did: &shrike::Did) -> Vec<u8> {
    encode_frame("#account", |enc| {
        encode_text_map(
            enc,
            &["active", "did", "seq", "time", "unknownAccountField"],
            |enc, key| match key {
                "active" => enc.encode_bool(true),
                "did" => enc.encode_text(did.as_str()),
                "seq" => enc.encode_i64(88),
                "time" => enc.encode_text("2026-06-09T15:00:00.000Z"),
                "unknownAccountField" => enc.encode_text("ignored"),
                _ => unreachable!(),
            },
        )
    })
}

pub fn identity_frame(did: &shrike::Did, seq: i64, handle: Option<&str>, time: &str) -> Vec<u8> {
    let mut keys = vec!["did", "seq", "time"];
    if handle.is_some() {
        keys.push("handle");
    }

    encode_frame("#identity", |enc| {
        encode_text_map(enc, &keys, |enc, key| match key {
            "did" => enc.encode_text(did.as_str()),
            "handle" => enc.encode_text(handle.unwrap()),
            "seq" => enc.encode_i64(seq),
            "time" => enc.encode_text(time),
            _ => unreachable!(),
        })
    })
}

pub fn identity_frame_with_unknown(did: &shrike::Did) -> Vec<u8> {
    encode_frame("#identity", |enc| {
        encode_text_map(
            enc,
            &["did", "handle", "seq", "time", "unknownIdentityField"],
            |enc, key| match key {
                "did" => enc.encode_text(did.as_str()),
                "handle" => enc.encode_text("example.com"),
                "seq" => enc.encode_i64(89),
                "time" => enc.encode_text("2026-06-09T15:01:00.000Z"),
                "unknownIdentityField" => enc.encode_text("ignored"),
                _ => unreachable!(),
            },
        )
    })
}

pub fn info_frame() -> Vec<u8> {
    encode_frame("#info", |enc| enc.encode_map_header(0))
}

pub fn info_frame_with_unknown() -> Vec<u8> {
    encode_frame("#info", |enc| {
        encode_text_map(enc, &["unknownInfoField"], |enc, key| match key {
            "unknownInfoField" => enc.encode_text("ignored"),
            _ => unreachable!(),
        })
    })
}

pub fn commit_frame_with_bad_blocks_type() -> Vec<u8> {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let commit = Cid::compute(Codec::Drisl, b"commit");
    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            &did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Text("not-bytes"),
            vec![],
            CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data")),
        )
    })
}

pub fn commit_frame_without_commit() -> Vec<u8> {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            &did,
            "3zzzzzzzzzzzz",
            42,
            None,
            Value::Bytes(b"fake-car"),
            vec![],
            CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data")),
        )
    })
}

pub fn commit_frame_without_bool(field: &'static str) -> Vec<u8> {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let mut options = CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"));
    match field {
        "tooBig" => options.too_big = RequiredBool::Missing,
        "rebase" => options.rebase = RequiredBool::Missing,
        _ => unreachable!(),
    }
    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            &did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![],
            options,
        )
    })
}

pub fn commit_frame_with_null_bool(field: &'static str) -> Vec<u8> {
    let did = shrike::Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let commit = Cid::compute(Codec::Drisl, b"commit");
    let mut options = CommitOptions::standard(Cid::compute(Codec::Drisl, b"prev-data"));
    match field {
        "tooBig" => options.too_big = RequiredBool::Null,
        "rebase" => options.rebase = RequiredBool::Null,
        _ => unreachable!(),
    }
    encode_frame("#commit", |enc| {
        encode_commit_body(
            enc,
            &did,
            "3zzzzzzzzzzzz",
            42,
            Some(commit),
            Value::Bytes(b"fake-car"),
            vec![],
            options,
        )
    })
}

fn encode_frame<F>(tag: &str, encode_body: F) -> Vec<u8>
where
    F: FnOnce(&mut Encoder<&mut Vec<u8>>) -> Result<(), shrike::cbor::CborError>,
{
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    encode_text_map(&mut enc, &["op", "t"], |enc, key| match key {
        "op" => enc.encode_i64(1),
        "t" => enc.encode_text(tag),
        _ => unreachable!(),
    })
    .unwrap();
    encode_body(&mut enc).unwrap();
    buf
}

fn encode_commit_body(
    enc: &mut Encoder<&mut Vec<u8>>,
    did: &shrike::Did,
    rev: &str,
    seq: i64,
    commit: Option<Cid>,
    blocks: Value<'_>,
    ops: Vec<RawOp>,
    options: CommitOptions<'_>,
) -> Result<(), shrike::cbor::CborError> {
    let mut keys = vec![
        "blobs", "blocks", "ops", "rebase", "repo", "rev", "seq", "since", "time", "tooBig",
    ];
    if commit.is_some() {
        keys.push("commit");
    }
    if !matches!(options.prev_data, OptionalCid::Missing) {
        keys.push("prevData");
    }
    if matches!(options.since, OptionalText::Missing) {
        keys.retain(|key| *key != "since");
    }
    if matches!(options.too_big, RequiredBool::Missing) {
        keys.retain(|key| *key != "tooBig");
    }
    if matches!(options.rebase, RequiredBool::Missing) {
        keys.retain(|key| *key != "rebase");
    }
    if options.unknown_fields {
        keys.push("unknownCommitField");
    }

    encode_text_map(enc, &keys, |enc, key| match key {
        "blobs" => {
            enc.encode_array_header(1)?;
            enc.encode_cid(&Cid::compute(Codec::Drisl, b"blob"))
        }
        "blocks" => encode_value(enc, &blocks),
        "commit" => enc.encode_cid(&commit.unwrap()),
        "ops" => {
            enc.encode_array_header(ops.len() as u64)?;
            for op in &ops {
                encode_op(
                    enc,
                    op,
                    options.op_prev_null,
                    options.op_prev_invalid_text,
                    options.op_unknown_fields,
                )?;
            }
            Ok(())
        }
        "prevData" => encode_optional_cid(enc, options.prev_data),
        "rebase" => encode_required_bool(enc, options.rebase),
        "repo" => enc.encode_text(did.as_str()),
        "rev" => enc.encode_text(rev),
        "seq" => enc.encode_i64(seq),
        "since" => encode_optional_text(enc, options.since),
        "time" => enc.encode_text("2026-06-09T15:00:00.000Z"),
        "tooBig" => encode_required_bool(enc, options.too_big),
        "unknownCommitField" => enc.encode_text("ignored"),
        _ => unreachable!(),
    })
}

fn encode_op(
    enc: &mut Encoder<&mut Vec<u8>>,
    op: &RawOp,
    prev_null: bool,
    prev_invalid_text: bool,
    unknown_fields: bool,
) -> Result<(), shrike::cbor::CborError> {
    let mut keys = vec!["action", "path"];
    if op.cid.is_some() {
        keys.push("cid");
    }
    if op.prev.is_some() || prev_null || prev_invalid_text {
        keys.push("prev");
    }
    if unknown_fields {
        keys.push("unknownOpField");
    }

    encode_text_map(enc, &keys, |enc, key| match key {
        "action" => enc.encode_text(op.action),
        "cid" => enc.encode_cid(&op.cid.unwrap()),
        "path" => enc.encode_text(op.path),
        "prev" if prev_null => enc.encode_null(),
        "prev" if prev_invalid_text => enc.encode_text("not-a-cid"),
        "prev" => enc.encode_cid(&op.prev.unwrap()),
        "unknownOpField" => enc.encode_text("ignored"),
        _ => unreachable!(),
    })
}

fn encode_optional_text(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: OptionalText<'_>,
) -> Result<(), shrike::cbor::CborError> {
    match value {
        OptionalText::Missing => unreachable!(),
        OptionalText::Null => enc.encode_null(),
        OptionalText::Value(text) => enc.encode_text(text),
        OptionalText::InvalidInt => enc.encode_i64(7),
    }
}

fn encode_optional_cid(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: OptionalCid,
) -> Result<(), shrike::cbor::CborError> {
    match value {
        OptionalCid::Missing => unreachable!(),
        OptionalCid::Null => enc.encode_null(),
        OptionalCid::Value(cid) => enc.encode_cid(&cid),
        OptionalCid::InvalidText => enc.encode_text("not-a-cid"),
    }
}

fn encode_required_bool(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: RequiredBool,
) -> Result<(), shrike::cbor::CborError> {
    match value {
        RequiredBool::Missing => unreachable!(),
        RequiredBool::Null => enc.encode_null(),
        RequiredBool::Value(value) => enc.encode_bool(value),
    }
}

fn encode_value(
    enc: &mut Encoder<&mut Vec<u8>>,
    value: &Value<'_>,
) -> Result<(), shrike::cbor::CborError> {
    match value {
        Value::Bytes(bytes) => enc.encode_bytes(bytes),
        Value::Text(text) => enc.encode_text(text),
        _ => unreachable!(),
    }
}
