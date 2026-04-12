//! Roundtrip tests for generated CBOR encode/decode.
#![allow(clippy::unwrap_used, clippy::panic)]

#[test]
fn strong_ref_cbor_roundtrip() {
    let sr = shrike_api::com::atproto::RepoStrongRef {
        uri: shrike_syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = sr.to_cbor().unwrap();
    let decoded = shrike_api::com::atproto::RepoStrongRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.uri, sr.uri);
    assert_eq!(decoded.cid, sr.cid);
    assert!(decoded.extra_cbor.is_empty());
}

#[test]
fn strong_ref_cbor_deterministic() {
    let sr = shrike_api::com::atproto::RepoStrongRef {
        uri: shrike_syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
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
    let sr = shrike_api::com::atproto::RepoStrongRef {
        uri: shrike_syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = sr.to_cbor().unwrap();
    // Decode as raw CBOR value and verify key order
    let val = shrike_cbor::decode(&cbor).unwrap();
    if let shrike_cbor::Value::Map(entries) = val {
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
    let mut sr = shrike_api::com::atproto::RepoStrongRef {
        uri: shrike_syntax::AtUri::try_from("at://did:plc:abc/app.bsky.feed.post/123").unwrap(),
        cid: "bafyrei1234567890".into(),
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };

    // Add an extra CBOR field "x" with value 42
    let extra_value = shrike_cbor::encode_value(&shrike_cbor::Value::Unsigned(42)).unwrap();
    sr.extra_cbor.push(("x".to_string(), extra_value));

    let cbor = sr.to_cbor().unwrap();
    let decoded = shrike_api::com::atproto::RepoStrongRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.uri, sr.uri);
    assert_eq!(decoded.cid, sr.cid);
    assert_eq!(decoded.extra_cbor.len(), 1);
    assert_eq!(decoded.extra_cbor[0].0, "x");

    // Verify the extra value round-trips correctly
    let extra_decoded = shrike_cbor::decode(&decoded.extra_cbor[0].1).unwrap();
    assert_eq!(extra_decoded, shrike_cbor::Value::Unsigned(42));
}

#[test]
fn feed_post_reply_ref_roundtrip() {
    let reply = shrike_api::app::bsky::FeedPostReplyRef {
        parent: shrike_api::com::atproto::RepoStrongRef {
            uri: shrike_syntax::AtUri::try_from("at://did:plc:parent/app.bsky.feed.post/1")
                .unwrap(),
            cid: "bafyrei_parent".into(),
            extra: Default::default(),
            extra_cbor: Vec::new(),
        },
        root: shrike_api::com::atproto::RepoStrongRef {
            uri: shrike_syntax::AtUri::try_from("at://did:plc:root/app.bsky.feed.post/0").unwrap(),
            cid: "bafyrei_root".into(),
            extra: Default::default(),
            extra_cbor: Vec::new(),
        },
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = reply.to_cbor().unwrap();
    let decoded = shrike_api::app::bsky::FeedPostReplyRef::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.parent.uri, reply.parent.uri);
    assert_eq!(decoded.parent.cid, reply.parent.cid);
    assert_eq!(decoded.root.uri, reply.root.uri);
    assert_eq!(decoded.root.cid, reply.root.cid);
}

#[test]
fn feed_post_text_slice_roundtrip() {
    let slice = shrike_api::app::bsky::FeedPostTextSlice {
        start: 0,
        end: 42,
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = slice.to_cbor().unwrap();
    let decoded = shrike_api::app::bsky::FeedPostTextSlice::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.start, slice.start);
    assert_eq!(decoded.end, slice.end);
}

#[test]
fn embed_external_roundtrip() {
    let ext = shrike_api::app::bsky::EmbedExternalExternal {
        description: "A test description".into(),
        title: "Test Title".into(),
        uri: "https://example.com".into(),
        thumb: None,
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = ext.to_cbor().unwrap();
    let decoded = shrike_api::app::bsky::EmbedExternalExternal::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.description, ext.description);
    assert_eq!(decoded.title, ext.title);
    assert_eq!(decoded.uri, ext.uri);
    assert!(decoded.thumb.is_none());
}

#[test]
fn feed_post_minimal_roundtrip() {
    let post = shrike_api::app::bsky::FeedPost {
        text: "Hello world!".into(),
        created_at: shrike_syntax::Datetime::try_from("2024-01-01T00:00:00.000Z").unwrap(),
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
    let decoded = shrike_api::app::bsky::FeedPost::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.text, post.text);
    assert_eq!(decoded.created_at, post.created_at);
    assert!(decoded.embed.is_none());
    assert!(decoded.entities.is_empty());
    assert!(decoded.langs.is_empty());
    assert!(decoded.tags.is_empty());
}

#[test]
fn feed_post_with_langs_roundtrip() {
    let post = shrike_api::app::bsky::FeedPost {
        text: "Hello!".into(),
        created_at: shrike_syntax::Datetime::try_from("2024-01-01T00:00:00.000Z").unwrap(),
        embed: None,
        entities: Vec::new(),
        facets: Vec::new(),
        labels: None,
        langs: vec![
            shrike_syntax::Language::try_from("en").unwrap(),
            shrike_syntax::Language::try_from("ja").unwrap(),
        ],
        reply: None,
        tags: vec!["test".into()],
        extra: Default::default(),
        extra_cbor: Vec::new(),
    };
    let cbor = post.to_cbor().unwrap();
    let decoded = shrike_api::app::bsky::FeedPost::from_cbor(&cbor).unwrap();
    assert_eq!(decoded.text, post.text);
    assert_eq!(decoded.langs, post.langs);
    assert_eq!(decoded.tags, vec!["test"]);
}
