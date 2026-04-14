//! Label signing and verification for AT Protocol moderation.
//!
//! Labels are signed assertions about content (posts, accounts, media).
//! Each label has a source DID, target URI, label value, and optional
//! expiration. Labels can be positive (apply a label) or negative (remove
//! a label).
//!
//! All label fields except sig are encoded in deterministic CBOR order for
//! signing. Use sign_label to create a signature and verify_label to check
//! it. The encoding ensures that signatures are stable across serialization.

use crate::cbor::{CborError, Cid, Encoder};
use crate::crypto::{CryptoError, Signature, SigningKey, VerifyingKey};
use crate::syntax::{Datetime, Did};

/// Errors from label signing, verification, and serialization.
#[derive(Debug, thiserror::Error)]
pub enum LabelError {
    #[error("CBOR error: {0}")]
    Cbor(#[from] CborError),
    #[error("crypto error: {0}")]
    Crypto(#[from] CryptoError),
    #[error("invalid label: {0}")]
    Invalid(String),
}

/// A moderation label asserting something about a piece of content.
#[derive(Debug, Clone)]
pub struct Label {
    /// DID of the labeler that issued this label.
    pub src: Did,
    /// AT URI or DID of the labeled content.
    pub uri: String,
    /// Optional CID targeting a specific version of the content.
    pub cid: Option<Cid>,
    /// Label value (e.g., "spam", "nudity", "graphic-media").
    pub val: String,
    /// If true, this negates (removes) a previously applied label.
    pub neg: bool,
    /// Timestamp when the label was created.
    pub cts: Datetime,
    /// Optional expiration timestamp.
    pub exp: Option<Datetime>,
    /// 64-byte ECDSA signature over the unsigned label bytes.
    pub sig: Option<Vec<u8>>,
}

/// Encode label fields (except sig) to DRISL bytes for signing.
///
/// All field name keys are 3 characters long, so they sort alphabetically:
/// cid, cts, exp, neg, src, uri, val
pub fn unsigned_label_bytes(label: &Label) -> Result<Vec<u8>, LabelError> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);

    // Count non-None fields (always: src, uri, val, neg, cts; optionally: cid, exp)
    let mut field_count = 5u64;
    if label.cid.is_some() {
        field_count += 1;
    }
    if label.exp.is_some() {
        field_count += 1;
    }

    enc.encode_map_header(field_count)?;

    // Keys sorted alphabetically (all 3 chars, same CBOR encoded length):
    // cid, cts, exp, neg, src, uri, val
    if let Some(cid) = &label.cid {
        enc.encode_text("cid")?;
        enc.encode_cid(cid)?;
    }

    enc.encode_text("cts")?;
    enc.encode_text(label.cts.as_str())?;

    if let Some(exp) = &label.exp {
        enc.encode_text("exp")?;
        enc.encode_text(exp.as_str())?;
    }

    enc.encode_text("neg")?;
    enc.encode_bool(label.neg)?;

    enc.encode_text("src")?;
    enc.encode_text(label.src.as_str())?;

    enc.encode_text("uri")?;
    enc.encode_text(&label.uri)?;

    enc.encode_text("val")?;
    enc.encode_text(&label.val)?;

    Ok(buf)
}

/// Sign a label, populating the sig field.
pub fn sign_label(label: &mut Label, key: &dyn SigningKey) -> Result<(), LabelError> {
    let bytes = unsigned_label_bytes(label)?;
    let sig = key.sign(&bytes)?;
    label.sig = Some(sig.as_bytes().to_vec());
    Ok(())
}

/// Verify a label's signature.
pub fn verify_label(label: &Label, key: &dyn VerifyingKey) -> Result<(), LabelError> {
    let sig_bytes = label
        .sig
        .as_ref()
        .ok_or_else(|| LabelError::Invalid("no signature".into()))?;
    if sig_bytes.len() != 64 {
        return Err(LabelError::Invalid("signature must be 64 bytes".into()));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig_bytes);
    let sig = Signature::from_bytes(sig_arr);
    let bytes = unsigned_label_bytes(label)?;
    key.verify(&bytes, &sig)?;
    Ok(())
}

/// Encode a complete label (including sig) to DRISL bytes.
///
/// Key ordering (all 3-char keys, alphabetical):
/// cid, cts, exp, neg, sig, src, uri, val
pub fn encode_label(label: &Label) -> Result<Vec<u8>, LabelError> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);

    let mut field_count = 5u64;
    if label.cid.is_some() {
        field_count += 1;
    }
    if label.exp.is_some() {
        field_count += 1;
    }
    if label.sig.is_some() {
        field_count += 1;
    }

    enc.encode_map_header(field_count)?;

    if let Some(cid) = &label.cid {
        enc.encode_text("cid")?;
        enc.encode_cid(cid)?;
    }

    enc.encode_text("cts")?;
    enc.encode_text(label.cts.as_str())?;

    if let Some(exp) = &label.exp {
        enc.encode_text("exp")?;
        enc.encode_text(exp.as_str())?;
    }

    enc.encode_text("neg")?;
    enc.encode_bool(label.neg)?;

    // "sig" sorts between "neg" and "src" alphabetically
    if let Some(sig) = &label.sig {
        enc.encode_text("sig")?;
        enc.encode_bytes(sig)?;
    }

    enc.encode_text("src")?;
    enc.encode_text(label.src.as_str())?;

    enc.encode_text("uri")?;
    enc.encode_text(&label.uri)?;

    enc.encode_text("val")?;
    enc.encode_text(&label.val)?;

    Ok(buf)
}

/// Decode a label from DRISL bytes.
pub fn decode_label(data: &[u8]) -> Result<Label, LabelError> {
    let value = crate::cbor::decode(data)?;

    let entries = match value {
        crate::cbor::Value::Map(entries) => entries,
        _ => return Err(LabelError::Invalid("expected CBOR map".into())),
    };

    let mut src: Option<String> = None;
    let mut uri: Option<String> = None;
    let mut cid: Option<Cid> = None;
    let mut val: Option<String> = None;
    let mut neg: Option<bool> = None;
    let mut cts: Option<String> = None;
    let mut exp: Option<String> = None;
    let mut sig: Option<Vec<u8>> = None;

    for (key, v) in &entries {
        match *key {
            "src" => match v {
                crate::cbor::Value::Text(s) => src = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("src must be a text string".into())),
            },
            "uri" => match v {
                crate::cbor::Value::Text(s) => uri = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("uri must be a text string".into())),
            },
            "cid" => match v {
                crate::cbor::Value::Cid(c) => cid = Some(*c),
                _ => return Err(LabelError::Invalid("cid must be a CID".into())),
            },
            "val" => match v {
                crate::cbor::Value::Text(s) => val = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("val must be a text string".into())),
            },
            "neg" => match v {
                crate::cbor::Value::Bool(b) => neg = Some(*b),
                _ => return Err(LabelError::Invalid("neg must be a bool".into())),
            },
            "cts" => match v {
                crate::cbor::Value::Text(s) => cts = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("cts must be a text string".into())),
            },
            "exp" => match v {
                crate::cbor::Value::Text(s) => exp = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("exp must be a text string".into())),
            },
            "sig" => match v {
                crate::cbor::Value::Bytes(b) => sig = Some((*b).to_owned()),
                _ => return Err(LabelError::Invalid("sig must be bytes".into())),
            },
            _ => {} // ignore unknown fields
        }
    }

    let src_str = src.ok_or_else(|| LabelError::Invalid("missing field: src".into()))?;
    let src_did = Did::try_from(src_str.as_str())
        .map_err(|e| LabelError::Invalid(format!("invalid src DID: {e}")))?;

    let uri = uri.ok_or_else(|| LabelError::Invalid("missing field: uri".into()))?;
    let val = val.ok_or_else(|| LabelError::Invalid("missing field: val".into()))?;
    let neg = neg.ok_or_else(|| LabelError::Invalid("missing field: neg".into()))?;

    let cts_str = cts.ok_or_else(|| LabelError::Invalid("missing field: cts".into()))?;
    let cts = Datetime::try_from(cts_str.as_str())
        .map_err(|e| LabelError::Invalid(format!("invalid cts datetime: {e}")))?;

    let exp = exp
        .map(|s| {
            Datetime::try_from(s.as_str())
                .map_err(|e| LabelError::Invalid(format!("invalid exp datetime: {e}")))
        })
        .transpose()?;

    Ok(Label {
        src: src_did,
        uri,
        cid,
        val,
        neg,
        cts,
        exp,
        sig,
    })
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::unreachable
)]
mod tests {
    use crate::labeling::*;

    fn make_test_label() -> Label {
        Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: None,
            val: "spam".into(),
            neg: false,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        }
    }

    fn make_full_label() -> Label {
        Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: Some(Cid::compute(crate::cbor::Codec::Drisl, b"some-content")),
            val: "nudity".into(),
            neg: false,
            cts: Datetime::try_from("2024-06-15T12:30:00Z").unwrap(),
            exp: Some(Datetime::try_from("2025-01-01T00:00:00Z").unwrap()),
            sig: None,
        }
    }

    // -------------------------------------------------------------------------
    // Original tests
    // -------------------------------------------------------------------------

    #[test]
    fn sign_and_verify_label() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: None,
            val: "spam".into(),
            neg: false,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        };
        sign_label(&mut label, &sk).unwrap();
        assert!(label.sig.is_some());
        verify_label(&label, sk.public_key()).unwrap();
    }

    #[test]
    fn verify_tampered_label_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        label.val = "not-spam".into(); // tamper
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    #[test]
    fn verify_unsigned_label_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let label = make_test_label(); // no sig
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    #[test]
    fn encode_decode_roundtrip() {
        let label = make_test_label();
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(label.src, decoded.src);
        assert_eq!(label.uri, decoded.uri);
        assert_eq!(label.val, decoded.val);
        assert_eq!(label.neg, decoded.neg);
        assert_eq!(label.cts, decoded.cts);
    }

    #[test]
    fn negation_label() {
        let label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "did:plc:user1234567890123456".into(),
            cid: None,
            val: "spam".into(),
            neg: true,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        };
        assert!(label.neg);
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert!(decoded.neg);
    }

    #[test]
    fn label_with_cid() {
        let cid = Cid::compute(crate::cbor::Codec::Drisl, b"test");
        let label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: Some(cid),
            val: "spam".into(),
            neg: false,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        };
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.cid, Some(cid));
    }

    // -------------------------------------------------------------------------
    // Sign/verify edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn sign_and_verify_with_k256_key() {
        let sk = crate::crypto::K256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        let sig = label.sig.as_ref().unwrap();
        assert_eq!(sig.len(), 64);
        verify_label(&label, sk.public_key()).unwrap();
    }

    #[test]
    fn verify_with_wrong_key_fails() {
        let sk1 = crate::crypto::P256SigningKey::generate();
        let sk2 = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk1).unwrap();
        // Verifying with sk2's public key must fail.
        assert!(verify_label(&label, sk2.public_key()).is_err());
    }

    #[test]
    fn verify_with_tampered_src_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        label.src = Did::try_from("did:plc:differentlabeler1234").unwrap();
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    #[test]
    fn verify_with_tampered_uri_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        label.uri = "at://did:plc:user1234567890123456/app.bsky.feed.post/TAMPERED".into();
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    #[test]
    fn verify_with_tampered_cts_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        label.cts = Datetime::try_from("2099-12-31T23:59:59Z").unwrap();
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    #[test]
    fn verify_with_tampered_neg_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();
        sign_label(&mut label, &sk).unwrap();
        label.neg = !label.neg; // flip the neg field
        assert!(verify_label(&label, sk.public_key()).is_err());
    }

    // -------------------------------------------------------------------------
    // Encode/decode edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn encode_decode_label_with_all_optional_fields() {
        let cid = Cid::compute(crate::cbor::Codec::Drisl, b"some-content");
        let exp = Datetime::try_from("2025-01-01T00:00:00Z").unwrap();
        let sig_bytes = vec![0xabu8; 64];
        let label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: Some(cid),
            val: "nudity".into(),
            neg: false,
            cts: Datetime::try_from("2024-06-15T12:30:00Z").unwrap(),
            exp: Some(exp.clone()),
            sig: Some(sig_bytes.clone()),
        };
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.src, label.src);
        assert_eq!(decoded.uri, label.uri);
        assert_eq!(decoded.cid, Some(cid));
        assert_eq!(decoded.val, label.val);
        assert_eq!(decoded.neg, label.neg);
        assert_eq!(decoded.cts, label.cts);
        assert_eq!(decoded.exp, Some(exp));
        assert_eq!(decoded.sig, Some(sig_bytes));
    }

    #[test]
    fn encode_decode_label_with_no_optional_fields() {
        let label = make_test_label(); // cid=None, exp=None, sig=None
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.cid, None);
        assert_eq!(decoded.exp, None);
        assert_eq!(decoded.sig, None);
        assert_eq!(decoded.src, label.src);
        assert_eq!(decoded.uri, label.uri);
        assert_eq!(decoded.val, label.val);
        assert_eq!(decoded.neg, label.neg);
        assert_eq!(decoded.cts, label.cts);
    }

    #[test]
    fn encode_decode_label_with_only_cid_set() {
        let cid = Cid::compute(crate::cbor::Codec::Raw, b"raw-content");
        let label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: Some(cid),
            val: "spam".into(),
            neg: false,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        };
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.cid, Some(cid));
        assert_eq!(decoded.exp, None);
        assert_eq!(decoded.sig, None);
    }

    #[test]
    fn encode_decode_label_with_only_exp_set() {
        let exp = Datetime::try_from("2030-06-01T00:00:00Z").unwrap();
        let label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: None,
            val: "spam".into(),
            neg: false,
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: Some(exp.clone()),
            sig: None,
        };
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.cid, None);
        assert_eq!(decoded.exp, Some(exp));
        assert_eq!(decoded.sig, None);
    }

    #[test]
    fn roundtrip_preserves_all_field_values_exactly() {
        let cid = Cid::compute(crate::cbor::Codec::Drisl, b"exact-content");
        let src = Did::try_from("did:plc:labeler12345678901234").unwrap();
        let uri = "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".to_string();
        let val = "graphic-media".to_string();
        let cts = Datetime::try_from("2024-03-21T08:45:00.123Z").unwrap();
        let exp = Datetime::try_from("2024-12-31T23:59:59Z").unwrap();
        let sig_bytes = (0u8..64).collect::<Vec<u8>>();

        let label = Label {
            src: src.clone(),
            uri: uri.clone(),
            cid: Some(cid),
            val: val.clone(),
            neg: true,
            cts: cts.clone(),
            exp: Some(exp.clone()),
            sig: Some(sig_bytes.clone()),
        };

        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();

        assert_eq!(decoded.src, src);
        assert_eq!(decoded.uri, uri);
        assert_eq!(decoded.cid, Some(cid));
        assert_eq!(decoded.val, val);
        assert!(decoded.neg);
        assert_eq!(decoded.cts, cts);
        assert_eq!(decoded.exp, Some(exp));
        assert_eq!(decoded.sig, Some(sig_bytes));
    }

    // -------------------------------------------------------------------------
    // Full workflow tests
    // -------------------------------------------------------------------------

    #[test]
    fn full_pipeline_create_sign_encode_decode_verify() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_test_label();

        // Sign
        sign_label(&mut label, &sk).unwrap();
        assert!(label.sig.is_some());

        // Encode
        let encoded = encode_label(&label).unwrap();
        assert!(!encoded.is_empty());

        // Decode
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.src, label.src);
        assert_eq!(decoded.uri, label.uri);
        assert_eq!(decoded.val, label.val);
        assert_eq!(decoded.neg, label.neg);
        assert_eq!(decoded.cts, label.cts);
        assert!(decoded.sig.is_some());

        // Verify the decoded label
        verify_label(&decoded, sk.public_key()).unwrap();
    }

    #[test]
    fn full_pipeline_negation_label_sign_encode_decode_verify() {
        let sk = crate::crypto::K256SigningKey::generate();
        let mut label = Label {
            src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
            uri: "at://did:plc:user1234567890123456/app.bsky.feed.post/abc".into(),
            cid: None,
            val: "spam".into(),
            neg: true, // negation label
            cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
            exp: None,
            sig: None,
        };

        sign_label(&mut label, &sk).unwrap();
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();

        assert!(decoded.neg);
        verify_label(&decoded, sk.public_key()).unwrap();
    }

    #[test]
    fn cbor_encoding_is_deterministic() {
        let sk = crate::crypto::P256SigningKey::generate();
        let mut label = make_full_label();
        sign_label(&mut label, &sk).unwrap();

        let encoded1 = encode_label(&label).unwrap();
        let encoded2 = encode_label(&label).unwrap();
        assert_eq!(encoded1, encoded2);
    }

    #[test]
    fn unsigned_label_bytes_is_deterministic() {
        let label = make_test_label();
        let bytes1 = unsigned_label_bytes(&label).unwrap();
        let bytes2 = unsigned_label_bytes(&label).unwrap();
        assert_eq!(bytes1, bytes2);
    }

    // -------------------------------------------------------------------------
    // Error cases
    // -------------------------------------------------------------------------

    #[test]
    fn decode_label_with_empty_bytes_fails() {
        let result = decode_label(&[]);
        assert!(result.is_err());
    }

    #[test]
    fn decode_label_with_invalid_cbor_fails() {
        // 0xff is a CBOR "break" code and not a valid item start
        let garbage = &[0xff, 0xfe, 0xfd, 0x00, 0x01];
        let result = decode_label(garbage);
        assert!(result.is_err());
    }

    #[test]
    fn decode_label_with_non_map_cbor_fails() {
        // Encode a CBOR text string ("hello") instead of a map
        let mut buf = Vec::new();
        let mut enc = crate::cbor::Encoder::new(&mut buf);
        enc.encode_text("hello").unwrap();
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("expected CBOR map") || err_str.contains("CBOR"));
    }

    #[test]
    fn decode_label_missing_src_field_fails() {
        // Encode a map with all required fields except "src"
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(4).unwrap();
            enc.encode_text("cts").unwrap();
            enc.encode_text("2024-01-01T00:00:00Z").unwrap();
            enc.encode_text("neg").unwrap();
            enc.encode_bool(false).unwrap();
            enc.encode_text("uri").unwrap();
            enc.encode_text("at://did:plc:user1234567890123456/app.bsky.feed.post/abc")
                .unwrap();
            enc.encode_text("val").unwrap();
            enc.encode_text("spam").unwrap();
        }
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("src") || err_str.contains("missing"));
    }

    #[test]
    fn decode_label_missing_uri_field_fails() {
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(4).unwrap();
            enc.encode_text("cts").unwrap();
            enc.encode_text("2024-01-01T00:00:00Z").unwrap();
            enc.encode_text("neg").unwrap();
            enc.encode_bool(false).unwrap();
            enc.encode_text("src").unwrap();
            enc.encode_text("did:plc:labeler12345678901234").unwrap();
            enc.encode_text("val").unwrap();
            enc.encode_text("spam").unwrap();
        }
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("uri") || err_str.contains("missing"));
    }

    #[test]
    fn decode_label_missing_val_field_fails() {
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(4).unwrap();
            enc.encode_text("cts").unwrap();
            enc.encode_text("2024-01-01T00:00:00Z").unwrap();
            enc.encode_text("neg").unwrap();
            enc.encode_bool(false).unwrap();
            enc.encode_text("src").unwrap();
            enc.encode_text("did:plc:labeler12345678901234").unwrap();
            enc.encode_text("uri").unwrap();
            enc.encode_text("at://did:plc:user1234567890123456/app.bsky.feed.post/abc")
                .unwrap();
        }
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("val") || err_str.contains("missing"));
    }

    #[test]
    fn decode_label_missing_neg_field_fails() {
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(4).unwrap();
            enc.encode_text("cts").unwrap();
            enc.encode_text("2024-01-01T00:00:00Z").unwrap();
            enc.encode_text("src").unwrap();
            enc.encode_text("did:plc:labeler12345678901234").unwrap();
            enc.encode_text("uri").unwrap();
            enc.encode_text("at://did:plc:user1234567890123456/app.bsky.feed.post/abc")
                .unwrap();
            enc.encode_text("val").unwrap();
            enc.encode_text("spam").unwrap();
        }
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("neg") || err_str.contains("missing"));
    }

    #[test]
    fn decode_label_missing_cts_field_fails() {
        let mut buf = Vec::new();
        {
            let mut enc = crate::cbor::Encoder::new(&mut buf);
            enc.encode_map_header(4).unwrap();
            enc.encode_text("neg").unwrap();
            enc.encode_bool(false).unwrap();
            enc.encode_text("src").unwrap();
            enc.encode_text("did:plc:labeler12345678901234").unwrap();
            enc.encode_text("uri").unwrap();
            enc.encode_text("at://did:plc:user1234567890123456/app.bsky.feed.post/abc")
                .unwrap();
            enc.encode_text("val").unwrap();
            enc.encode_text("spam").unwrap();
        }
        let result = decode_label(&buf);
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("cts") || err_str.contains("missing"));
    }

    #[test]
    fn verify_label_with_no_sig_fails() {
        let sk = crate::crypto::P256SigningKey::generate();
        let label = make_test_label(); // sig is None
        let result = verify_label(&label, sk.public_key());
        assert!(result.is_err());
        let err_str = result.unwrap_err().to_string();
        assert!(err_str.contains("no signature") || err_str.contains("signature"));
    }
}
