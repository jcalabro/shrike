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
///
/// The signed/encoded CBOR form matches the `com.atproto.label.defs#label`
/// lexicon and the reference implementations: the `ver` field (1) is included,
/// `neg` is omitted when false, and `cid` is a text string (lexicon
/// `string`/`format:cid`), not a tag-42 CID link.
#[derive(Debug, Clone)]
pub struct Label {
    /// Label format version. The current value is 1; use [`Label::new`] to get
    /// the default. `None` is treated as "absent" on encode.
    pub ver: Option<i64>,
    /// DID of the labeler that issued this label.
    pub src: Did,
    /// AT URI or DID of the labeled content.
    pub uri: String,
    /// Optional CID targeting a specific version of the content. Encoded as a
    /// CBOR text string (the lexicon type is `string`/`format:cid`).
    pub cid: Option<Cid>,
    /// Label value (e.g., "spam", "nudity", "graphic-media").
    pub val: String,
    /// If true, this negates (removes) a previously applied label. When false,
    /// the `neg` key is omitted from the signed/encoded CBOR.
    pub neg: bool,
    /// Timestamp when the label was created.
    pub cts: Datetime,
    /// Optional expiration timestamp.
    pub exp: Option<Datetime>,
    /// 64-byte ECDSA signature over the unsigned label bytes.
    pub sig: Option<Vec<u8>>,
}

/// Current AT Protocol label format version.
pub const LABEL_VERSION: i64 = 1;

impl Label {
    /// Construct a positive label with the current version (`ver = 1`), no CID,
    /// no expiration, and no signature.
    pub fn new(src: Did, uri: String, val: String, cts: Datetime) -> Self {
        Label {
            ver: Some(LABEL_VERSION),
            src,
            uri,
            cid: None,
            val,
            neg: false,
            cts,
            exp: None,
            sig: None,
        }
    }
}

/// Encode label fields (except sig) to DRISL bytes for signing.
///
/// All field-name keys are 3 characters long, so canonical CBOR order is
/// alphabetical: `cid, cts, exp, neg, src, uri, val, ver`. Per the lexicon and
/// the reference implementations: `cid` is a text string, `neg` is omitted when
/// false, and `ver` (the label format version) is included.
pub fn unsigned_label_bytes(label: &Label) -> Result<Vec<u8>, LabelError> {
    encode_label_fields(label, false)
}

/// Shared encoder for both the unsigned (signing) and full (with-sig) forms.
fn encode_label_fields(label: &Label, include_sig: bool) -> Result<Vec<u8>, LabelError> {
    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);

    // Canonical key order (all 3-char keys, alphabetical):
    // cid, cts, exp, neg, sig, src, uri, val, ver
    let mut field_count = 3u64; // cts, src, uri are always present... plus val
    field_count += 1; // val
    if label.cid.is_some() {
        field_count += 1;
    }
    if label.exp.is_some() {
        field_count += 1;
    }
    if label.neg {
        field_count += 1;
    }
    if include_sig && label.sig.is_some() {
        field_count += 1;
    }
    if label.ver.is_some() {
        field_count += 1;
    }

    enc.encode_map_header(field_count)?;

    // "cid" — text string (lexicon type string/format:cid), NOT a tag-42 CID.
    if let Some(cid) = &label.cid {
        enc.encode_text("cid")?;
        enc.encode_text(&cid.to_string())?;
    }

    enc.encode_text("cts")?;
    enc.encode_text(label.cts.as_str())?;

    if let Some(exp) = &label.exp {
        enc.encode_text("exp")?;
        enc.encode_text(exp.as_str())?;
    }

    // "neg" — omitted entirely when false (matches ozone/atmos).
    if label.neg {
        enc.encode_text("neg")?;
        enc.encode_bool(true)?;
    }

    // "sig" sorts between "neg" and "src".
    if include_sig
        && let Some(sig) = &label.sig
    {
        enc.encode_text("sig")?;
        enc.encode_bytes(sig)?;
    }

    enc.encode_text("src")?;
    enc.encode_text(label.src.as_str())?;

    enc.encode_text("uri")?;
    enc.encode_text(&label.uri)?;

    enc.encode_text("val")?;
    enc.encode_text(&label.val)?;

    // "ver" sorts last among the 3-char keys.
    if let Some(ver) = label.ver {
        enc.encode_text("ver")?;
        enc.encode_i64(ver)?;
    }

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
/// `cid, cts, exp, neg, sig, src, uri, val, ver`. `neg` is omitted when false.
pub fn encode_label(label: &Label) -> Result<Vec<u8>, LabelError> {
    encode_label_fields(label, true)
}

/// Decode a label from DRISL bytes.
pub fn decode_label(data: &[u8]) -> Result<Label, LabelError> {
    let value = crate::cbor::decode(data)?;

    let entries = match value {
        crate::cbor::Value::Map(entries) => entries,
        _ => return Err(LabelError::Invalid("expected CBOR map".into())),
    };

    let mut ver: Option<i64> = None;
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
            "ver" => match v {
                crate::cbor::Value::Unsigned(n) => ver = Some(*n as i64),
                crate::cbor::Value::Signed(n) => ver = Some(*n),
                _ => return Err(LabelError::Invalid("ver must be an integer".into())),
            },
            "src" => match v {
                crate::cbor::Value::Text(s) => src = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("src must be a text string".into())),
            },
            "uri" => match v {
                crate::cbor::Value::Text(s) => uri = Some((*s).to_owned()),
                _ => return Err(LabelError::Invalid("uri must be a text string".into())),
            },
            // cid is a text string (lexicon string/format:cid), parsed into a Cid.
            "cid" => match v {
                crate::cbor::Value::Text(s) => {
                    cid = Some(
                        s.parse::<Cid>()
                            .map_err(|e| LabelError::Invalid(format!("invalid cid: {e}")))?,
                    )
                }
                _ => return Err(LabelError::Invalid("cid must be a text string".into())),
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
    // `neg` is omitted when false, so a missing key means false (not an error).
    let neg = neg.unwrap_or(false);

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
        ver,
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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

    /// Decode raw CBOR into the (sorted) list of top-level keys present, so
    /// tests can assert on the exact field set and types in the signed bytes.
    fn label_keys(bytes: &[u8]) -> Vec<String> {
        match crate::cbor::decode(bytes).unwrap() {
            crate::cbor::Value::Map(entries) => {
                entries.iter().map(|(k, _)| (*k).to_owned()).collect()
            }
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn positive_label_unsigned_bytes_have_ver_and_no_neg() {
        // H15/H16: a positive (neg=false) label must include `ver` and must NOT
        // include `neg` in the signed bytes, matching ozone/atmos. Otherwise
        // shrike-signed labels are unverifiable on the network.
        let label = make_test_label(); // neg=false, ver=Some(1)
        let bytes = unsigned_label_bytes(&label).unwrap();
        let keys = label_keys(&bytes);
        assert!(keys.contains(&"ver".to_string()), "ver must be present");
        assert!(
            !keys.contains(&"neg".to_string()),
            "neg must be omitted when false, got keys {keys:?}"
        );
        // ver must be an integer (value 1).
        match crate::cbor::decode(&bytes).unwrap() {
            crate::cbor::Value::Map(entries) => {
                let ver = entries.iter().find(|(k, _)| *k == "ver").unwrap();
                assert_eq!(ver.1, crate::cbor::Value::Unsigned(1));
            }
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn negation_label_includes_neg_true() {
        // H16: a negation label must include neg:true.
        let mut label = make_test_label();
        label.neg = true;
        let bytes = unsigned_label_bytes(&label).unwrap();
        match crate::cbor::decode(&bytes).unwrap() {
            crate::cbor::Value::Map(entries) => {
                let neg = entries
                    .iter()
                    .find(|(k, _)| *k == "neg")
                    .expect("neg must be present for a negation label");
                assert_eq!(neg.1, crate::cbor::Value::Bool(true));
            }
            _ => panic!("not a map"),
        }
    }

    #[test]
    fn label_cid_encoded_as_text_string() {
        // H17: `cid` must be a CBOR text string (lexicon string/format:cid), not
        // a tag-42 CID link. A text-encoded cid must also round-trip on decode.
        let label = make_full_label(); // has cid = Some(...)
        let bytes = unsigned_label_bytes(&label).unwrap();
        match crate::cbor::decode(&bytes).unwrap() {
            crate::cbor::Value::Map(entries) => {
                let cid_entry = entries.iter().find(|(k, _)| *k == "cid").unwrap();
                match &cid_entry.1 {
                    crate::cbor::Value::Text(s) => {
                        assert_eq!(*s, label.cid.unwrap().to_string());
                    }
                    other => panic!("cid must be a text string, got {other:?}"),
                }
            }
            _ => panic!("not a map"),
        }
        // Full encode/decode roundtrip preserves the cid.
        let encoded = encode_label(&label).unwrap();
        let decoded = decode_label(&encoded).unwrap();
        assert_eq!(decoded.cid, label.cid);
        assert_eq!(decoded.ver, Some(LABEL_VERSION));
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
            ver: Some(LABEL_VERSION),
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
    fn decode_label_missing_neg_field_defaults_false() {
        // `neg` is omitted from the canonical CBOR when false (matches
        // ozone/atmos), so a missing `neg` key must decode as false — NOT error.
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
        let label = decode_label(&buf).expect("missing neg must default to false");
        assert!(!label.neg);
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
