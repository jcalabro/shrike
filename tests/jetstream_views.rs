#![cfg(feature = "jetstream")]
#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

#[allow(dead_code)]
#[path = "support/jetstream_segment.rs"]
mod segment_fixture;

use shrike::api::app::bsky::{FeedLike, FeedLikeCborView};
use shrike::cbor::{Value, encode_value};
use shrike::jetstream::{Filter, decode_segment_filtered, decode_segment_mapped};

#[test]
fn borrowed_records_expose_every_field_and_unknowns_without_copying_text() {
    let mut expected =
        FeedLike::from_cbor(include_bytes!("../benches/fixtures/record_like.cbor")).unwrap();
    expected.via = Some(expected.subject.clone());
    expected.subject.extra_cbor.push((
        "future".into(),
        encode_value(&Value::Text("nested unknown")).unwrap(),
    ));
    expected.extra_cbor.push((
        "future".into(),
        encode_value(&Value::Array(vec![
            Value::Bytes(b"opaque"),
            Value::Bool(true),
        ]))
        .unwrap(),
    ));
    let data = expected.to_cbor().unwrap();
    let view = FeedLikeCborView::from_cbor(&data).unwrap();
    assert_eq!(view.r#type, expected.r#type);
    assert_eq!(view.created_at.as_str(), expected.created_at.as_str());
    assert_eq!(view.subject.cid, expected.subject.cid);
    assert_eq!(view.subject.uri.as_str(), expected.subject.uri.as_str());
    assert_eq!(
        view.via.as_ref().unwrap().uri.as_str(),
        expected.via.as_ref().unwrap().uri.as_str()
    );
    assert_eq!(
        view.subject.extra_cbor[0].1,
        expected.subject.extra_cbor[0].1
    );
    assert_eq!(view.extra_cbor[0].1, expected.extra_cbor[0].1);
    let backing = data.as_ptr_range();
    for text in [
        view.r#type,
        view.created_at.as_str(),
        view.subject.cid,
        view.subject.uri.as_str(),
    ] {
        assert!(backing.contains(&text.as_ptr()));
    }
    let owned = view.to_owned().unwrap();
    drop(data);
    assert_eq!(owned.to_cbor().unwrap(), expected.to_cbor().unwrap());
}

#[test]
fn borrowed_and_owned_reject_truncation_and_corruption_equally() {
    let bytes = include_bytes!("../benches/fixtures/record_like.cbor");
    let compare = |input: &[u8]| {
        assert_eq!(
            FeedLike::from_cbor(input).is_ok(),
            FeedLikeCborView::from_cbor(input).is_ok()
        );
    };
    for end in 0..bytes.len() {
        compare(&bytes[..end]);
    }
    for index in 0..bytes.len() {
        for value in [0, 23, 31, 127, 128, 160, 246, 255] {
            let mut changed = bytes.to_vec();
            changed[index] = value;
            compare(&changed);
        }
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    compare(&trailing);
}

#[test]
fn scoped_archive_outputs_can_retain_owned_events_after_the_segment_is_freed() {
    let data = segment_fixture::seal(&[
        vec![segment_fixture::row(1), segment_fixture::row(2)],
        vec![segment_fixture::row(3)],
    ])
    .0;
    let expected = decode_segment_filtered(&data, &Filter::new()).unwrap();
    let mapped =
        decode_segment_mapped(&data, &Filter::new(), &|event| event.to_owned().unwrap()).unwrap();
    drop(data);
    assert_eq!(expected.events.len(), 3);
    assert_eq!(expected.events.len(), mapped.events.len());
    assert_eq!(
        expected
            .dropped
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>(),
        mapped
            .dropped
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
    );
    for (owned, mapped) in expected.events.iter().zip(mapped.events) {
        assert_eq!(owned.seq, mapped.seq);
        assert_eq!(format!("{owned:?}"), format!("{:?}", mapped.value));
    }
}
