//! Roundtrip tests for generated CBOR encode/decode.
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[test]
fn strong_ref_cbor_roundtrip() {
    let sr = shrike::api::com::atproto::RepoStrongRef {
        uri: shrike::syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = sr.to_cbor().unwrap();
    let decoded = shrike::api::com::atproto::RepoStrongRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.uri, sr.uri);
    assert_eq!(decoded.cid, sr.cid);
    assert!(decoded.extra_cbor.is_empty());
}

#[test]
fn strong_ref_cbor_deterministic() {
    let sr = shrike::api::com::atproto::RepoStrongRef {
        uri: shrike::syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let first = sr.to_cbor().unwrap();
    for _ in 0..10 {
        assert_eq!(
            sr.to_cbor().unwrap(),
            first,
            "encoding must be deterministic"
        );
    }
}

#[test]
fn strong_ref_cbor_key_order() {
    // "cid" (3 chars) should sort before "uri" (3 chars) lexicographically
    let sr = shrike::api::com::atproto::RepoStrongRef {
        uri: shrike::syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = sr.to_cbor().unwrap();
    // Decode as raw CBOR value and verify key order
    let val = shrike::cbor::decode(&cbor).unwrap();
    if let shrike::cbor::Value::Map(entries) = val {
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].0, "cid");
        assert_eq!(entries[1].0, "uri");
    } else {
        panic!("expected map");
    }
}

#[test]
fn strong_ref_preserves_extra_cbor() {
    // Create a StrongRef, encode with extra unknown fields
    let mut sr = shrike::api::com::atproto::RepoStrongRef {
        uri: shrike::syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };

    // Add an extra CBOR field "x" with value 42
    let extra_value = shrike::cbor::encode_value(&shrike::cbor::Value::Unsigned(42)).unwrap();
    sr.extra_cbor.push(("x".to_string(), extra_value));

    let cbor = sr.to_cbor().unwrap();
    let decoded = shrike::api::com::atproto::RepoStrongRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.uri, sr.uri);
    assert_eq!(decoded.cid, sr.cid);
    assert_eq!(decoded.extra_cbor.len(), 1);
    assert_eq!(decoded.extra_cbor[0].0, "x");

    // Verify the extra value round-trips correctly
    let extra_decoded = shrike::cbor::decode(&decoded.extra_cbor[0].1).unwrap();
    assert_eq!(extra_decoded, shrike::cbor::Value::Unsigned(42));
}

#[test]
fn feed_post_reply_ref_roundtrip() {
    let reply = shrike::api::app::bsky::FeedPostReplyRef {
        parent: shrike::api::com::atproto::RepoStrongRef {
            uri: shrike::syntax::AtUri::try_from("at://did:plc:parent/app.bsky.feed.post/1")
                .unwrap(),
            cid: "bafyrei_parent".into(),
            extra: Default::default(),
            extra_cbor: Vec::new(),
        },
        root: shrike::api::com::atproto::RepoStrongRef {
            uri: shrike::syntax::AtUri::try_from("at://did:plc:root/app.bsky.feed.post/0").unwrap(),
            cid: "bafyrei_root".into(),
            extra: Default::default(),
            extra_cbor: Vec::new(),
        },
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = reply.to_cbor().unwrap();
    let decoded = shrike::api::app::bsky::FeedPostReplyRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.parent.uri, reply.parent.uri);
    assert_eq!(decoded.parent.cid, reply.parent.cid);
    assert_eq!(decoded.root.uri, reply.root.uri);
    assert_eq!(decoded.root.cid, reply.root.cid);
}

#[test]
fn feed_post_text_slice_roundtrip() {
    let slice = shrike::api::app::bsky::FeedPostTextSlice {
        start: 0,
        end: 42,
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = slice.to_cbor().unwrap();
    let decoded = shrike::api::app::bsky::FeedPostTextSlice::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.start, slice.start);
    assert_eq!(decoded.end, slice.end);
}

#[test]
fn embed_external_roundtrip() {
    let ext = shrike::api::app::bsky::EmbedExternalExternal {
        associated_refs: Vec::new(),
        description: "A test description".into(),
        title: "Test Title".into(),
        uri: "https://example.com".into(),
        thumb: None,
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = ext.to_cbor().unwrap();
    let decoded = shrike::api::app::bsky::EmbedExternalExternal::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.description, ext.description);
    assert_eq!(decoded.title, ext.title);
    assert_eq!(decoded.uri, ext.uri);
    assert!(decoded.associated_refs.is_empty());
    assert!(decoded.thumb.is_none());
}

#[test]
fn feed_post_minimal_roundtrip() {
    let post = shrike::api::app::bsky::FeedPost {
        r#type: "app.bsky.feed.post".into(),
        text: "Hello world!".into(),
        created_at: shrike::syntax::Datetime::try_from("2024-01-01T00:00:00.000Z").unwrap(),
        embed: None,
        entities: Vec::new(),
        facets: Vec::new(),
        labels: None,
        langs: Vec::new(),
        reply: None,
        tags: Vec::new(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = post.to_cbor().unwrap();
    // The encoded record must carry a $type discriminator equal to the NSID.
    if let shrike::cbor::Value::Map(entries) = shrike::cbor::decode(&cbor).unwrap() {
        let ty = entries
            .iter()
            .find(|(k, _)| *k == "$type")
            .expect("$type present");
        assert_eq!(ty.1, shrike::cbor::Value::Text("app.bsky.feed.post"));
    } else {
        panic!("expected map");
    }
    let decoded = shrike::api::app::bsky::FeedPost::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.r#type, "app.bsky.feed.post");
    assert_eq!(decoded.text, post.text);
    assert_eq!(decoded.created_at, post.created_at);
    assert!(decoded.embed.is_none());
    assert!(decoded.entities.is_empty());
    assert!(decoded.langs.is_empty());
    assert!(decoded.tags.is_empty());
}

#[test]
fn feed_post_with_langs_roundtrip() {
    let post = shrike::api::app::bsky::FeedPost {
        r#type: "app.bsky.feed.post".into(),
        text: "Hello!".into(),
        created_at: shrike::syntax::Datetime::try_from("2024-01-01T00:00:00.000Z").unwrap(),
        embed: None,
        entities: Vec::new(),
        facets: Vec::new(),
        labels: None,
        langs: vec![
            shrike::syntax::Language::try_from("en").unwrap(),
            shrike::syntax::Language::try_from("ja").unwrap(),
        ],
        reply: None,
        tags: vec!["test".into()],
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = post.to_cbor().unwrap();
    let decoded = shrike::api::app::bsky::FeedPost::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.text, post.text);
    assert_eq!(decoded.langs, post.langs);
    assert_eq!(decoded.tags, vec!["test"]);
}

#[test]
fn label_bytes_sig_encodes_as_cbor_byte_string() {
    // C2 regression: lexicon `bytes` fields must encode as a DAG-CBOR byte
    // string (major type 2), not a text string. The label `sig` is the
    // canonical example — encoding it as text breaks the label CID and makes
    // the signature unverifiable by any real labeler.
    use shrike::api::Bytes;
    use shrike::api::com::atproto::LabelDefsLabel;

    let sig_bytes: Vec<u8> = (0u8..64).collect();
    let label = LabelDefsLabel {
        ver: Some(1),
        src: shrike::syntax::Did::try_from("did:plc:labeler12345678901234").unwrap(),
        uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
        cid: None,
        val: "spam".into(),
        neg: None,
        cts: shrike::syntax::Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
        exp: None,
        sig: Some(Bytes(sig_bytes.clone())),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };

    let cbor = label.to_cbor().unwrap();
    // Find the "sig" entry in the decoded map and assert it is Bytes, not Text.
    let val = shrike::cbor::decode(&cbor).unwrap();
    let entries = match val {
        shrike::cbor::Value::Map(e) => e,
        _ => panic!("expected map"),
    };
    let sig_entry = entries
        .iter()
        .find(|(k, _)| *k == "sig")
        .expect("sig present");
    match &sig_entry.1 {
        shrike::cbor::Value::Bytes(b) => assert_eq!(*b, &sig_bytes[..]),
        other => panic!("sig must be a CBOR byte string, got {other:?}"),
    }

    // Round-trip preserves the raw bytes.
    let decoded = LabelDefsLabel::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.sig.as_ref().map(|b| b.0.clone()), Some(sig_bytes));
}

#[test]
fn label_bytes_sig_json_uses_dollar_bytes() {
    // C2 regression: JSON form of a `bytes` field must be {"$bytes": "<base64>"}.
    use shrike::api::Bytes;
    use shrike::api::com::atproto::LabelDefsLabel;

    let label = LabelDefsLabel {
        ver: Some(1),
        src: shrike::syntax::Did::try_from("did:plc:labeler12345678901234").unwrap(),
        uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
        cid: None,
        val: "spam".into(),
        neg: None,
        cts: shrike::syntax::Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
        exp: None,
        sig: Some(Bytes(vec![0xDE, 0xAD, 0xBE, 0xEF])),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let json: serde_json::Value = serde_json::to_value(&label).unwrap();
    let sig = &json["sig"];
    assert!(
        sig.get("$bytes").is_some(),
        "bytes JSON must be {{\"$bytes\": ...}}, got {sig}"
    );
    // Round-trips back to the same bytes.
    let decoded: LabelDefsLabel = serde_json::from_value(json).unwrap();
    assert_eq!(decoded.sig.unwrap().0, vec![0xDE, 0xAD, 0xBE, 0xEF]);
}

#[test]
fn repo_op_nullable_cid_encodes_null_and_roundtrips() {
    // M29 regression: repoOp.cid is required+nullable ("null" on deletes). The
    // key must always be present (CBOR null when None), and decode must accept
    // a CBOR null cid as None rather than rejecting it.
    use shrike::api::com::atproto::SyncSubscribeReposRepoOp;

    let delete_op = SyncSubscribeReposRepoOp {
        action: "delete".into(),
        cid: None,
        path: "app.bsky.feed.post/abc".into(),
        prev: None,
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = delete_op.to_cbor().unwrap();
    // The `cid` key must be present with a null value.
    let val = shrike::cbor::decode(&cbor).unwrap();
    if let shrike::cbor::Value::Map(entries) = val {
        let cid = entries
            .iter()
            .find(|(k, _)| *k == "cid")
            .expect("cid key must be present even when null");
        assert_eq!(cid.1, shrike::cbor::Value::Null);
        // `prev` (plain optional) must be omitted when None.
        assert!(entries.iter().all(|(k, _)| *k != "prev"));
    } else {
        panic!("expected map");
    }
    // Decode must accept the null cid as None.
    let decoded = SyncSubscribeReposRepoOp::from_cbor(&cbor).unwrap();
    assert!(decoded.cid.is_none());
    assert_eq!(decoded.action, "delete");

    // JSON: cid present as null, prev omitted.
    let json = serde_json::to_value(&delete_op).unwrap();
    assert!(json.get("cid").is_some(), "cid must be present in JSON");
    assert!(json["cid"].is_null(), "cid must be JSON null");
    assert!(json.get("prev").is_none(), "prev must be omitted in JSON");
}

#[test]
fn union_accepts_explicit_hash_main_type_alias() {
    // L27: a main-def union variant must accept both the conformant bare NSID
    // `$type` and the non-conformant explicit `nsid#main` form on deserialize
    // (matching the TS reference, which registers both). app.bsky.embed.images
    // is a main def used in EmbedRecordWithMediaMediaUnion.
    use shrike::api::app::bsky::EmbedRecordWithMediaMediaUnion as U;

    let bare = serde_json::json!({
        "$type": "app.bsky.embed.images",
        "images": [],
    });
    let explicit = serde_json::json!({
        "$type": "app.bsky.embed.images#main",
        "images": [],
    });

    let from_bare: U = serde_json::from_value(bare).unwrap();
    let from_explicit: U = serde_json::from_value(explicit).unwrap();

    assert!(
        matches!(from_bare, U::EmbedImages(_)),
        "bare NSID must map to EmbedImages"
    );
    assert!(
        matches!(from_explicit, U::EmbedImages(_)),
        "explicit #main must map to EmbedImages, not Unknown"
    );

    // And re-serialization must always emit the bare NSID, never `#main`.
    let reserialized = serde_json::to_value(&from_explicit).unwrap();
    assert_eq!(
        reserialized["$type"], "app.bsky.embed.images",
        "serializer must emit the bare NSID"
    );
}

#[test]
fn union_cbor_accepts_explicit_hash_main_type_alias() {
    // L27 (CBOR path): the same alias acceptance must hold for decode_cbor.
    use shrike::api::app::bsky::EmbedRecordWithMediaMediaUnion as U;
    use shrike::cbor::{Value, encode_value};

    // { "$type": "app.bsky.embed.images#main", "images": [] }. encode_value
    // canonicalizes key order, producing valid DRISL.
    let value = Value::Map(vec![
        ("$type", Value::Text("app.bsky.embed.images#main")),
        ("images", Value::Array(Vec::new())),
    ]);
    let buf = encode_value(&value).unwrap();

    let decoded = U::from_cbor(&buf).unwrap();
    assert!(
        matches!(decoded, U::EmbedImages(_)),
        "explicit #main must decode to EmbedImages over CBOR"
    );
}
