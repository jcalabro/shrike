//! JavaScript-facing browser bindings for Shrike.

use std::collections::BTreeMap;

use futures::future::{AbortHandle, Abortable};
use futures::{StreamExt, pin_mut};
use js_sys::{Function, Object, Reflect, Uint8Array};
use serde::Deserialize;
use shrike::crypto::{
    K256SigningKey, K256VerifyingKey, P256SigningKey, P256VerifyingKey, Signature, SigningKey,
    VerifyingKey,
};
use wasm_bindgen::prelude::*;

fn js_error(error: impl std::fmt::Display) -> JsValue {
    js_sys::Error::new(&error.to_string()).into()
}

/// Validate and canonicalize an AT Protocol identifier.
#[wasm_bindgen(js_name = validateSyntax)]
pub fn validate_syntax(kind: &str, value: &str) -> Result<String, JsValue> {
    let canonical = match kind {
        "did" => shrike::Did::try_from(value).map(|value| value.to_string()),
        "handle" => shrike::Handle::try_from(value).map(|value| value.to_string()),
        "nsid" => shrike::Nsid::try_from(value).map(|value| value.to_string()),
        "at-uri" | "aturi" => shrike::AtUri::try_from(value).map(|value| value.to_string()),
        "record-key" | "rkey" => shrike::RecordKey::try_from(value).map(|value| value.to_string()),
        "tid" => shrike::Tid::try_from(value).map(|value| value.to_string()),
        other => return Err(js_error(format!("unknown syntax kind: {other}"))),
    };
    canonical.map_err(js_error)
}

/// Parse a DID into its method and method-specific identifier.
#[wasm_bindgen(js_name = parseDid)]
pub fn parse_did(value: &str) -> Result<JsValue, JsValue> {
    let did = shrike::Did::try_from(value).map_err(js_error)?;
    to_js(&serde_json::json!({
        "method": did.method(),
        "identifier": did.identifier(),
    }))
}

/// Parse an AT URI into its components.
#[wasm_bindgen(js_name = parseAtUri)]
pub fn parse_at_uri(value: &str) -> Result<JsValue, JsValue> {
    let uri = shrike::AtUri::try_from(value).map_err(js_error)?;
    to_js(&serde_json::json!({
        "authority": uri.authority(),
        "collection": uri.collection(),
        "rkey": uri.rkey(),
    }))
}

/// Parse an NSID into its authority and name.
#[wasm_bindgen(js_name = parseNsid)]
pub fn parse_nsid(value: &str) -> Result<JsValue, JsValue> {
    let nsid = shrike::Nsid::try_from(value).map_err(js_error)?;
    to_js(&serde_json::json!({
        "authority": nsid.authority(),
        "name": nsid.name(),
    }))
}

/// Parse a TID into its integer, timestamp, and clock components.
#[wasm_bindgen(js_name = parseTid)]
pub fn parse_tid(value: &str) -> Result<JsValue, JsValue> {
    let tid = shrike::Tid::try_from(value).map_err(js_error)?;
    to_js(&serde_json::json!({
        "integer": tid.as_u64(),
        "timestampMicros": tid.timestamp_micros(),
        "clockId": tid.clock_id(),
    }))
}

/// A monotonically increasing AT Protocol TID generator.
#[wasm_bindgen(js_name = TidClock)]
pub struct WasmTidClock {
    inner: shrike::TidClock,
}

#[wasm_bindgen(js_class = TidClock)]
impl WasmTidClock {
    #[wasm_bindgen(constructor)]
    pub fn new(clock_id: u16) -> Result<WasmTidClock, JsValue> {
        Ok(Self {
            inner: shrike::TidClock::new(clock_id).map_err(js_error)?,
        })
    }

    /// Return the next TID from this clock.
    pub fn next(&self) -> String {
        self.inner.next().to_string()
    }
}

/// Compute a CIDv1 for DAG-CBOR (`"dag-cbor"`) or raw bytes (`"raw"`).
#[wasm_bindgen(js_name = cidForBytes)]
pub fn cid_for_bytes(codec: &str, bytes: &[u8]) -> Result<String, JsValue> {
    let codec = match codec {
        "dag-cbor" | "drisl" => shrike::cbor::Codec::Drisl,
        "raw" => shrike::cbor::Codec::Raw,
        other => return Err(js_error(format!("unknown CID codec: {other}"))),
    };
    Ok(shrike::Cid::compute(codec, bytes).to_string())
}

/// Encode a JSON-compatible JavaScript value as deterministic DAG-CBOR.
#[wasm_bindgen(js_name = cborEncode)]
pub fn cbor_encode(value: JsValue) -> Result<Vec<u8>, JsValue> {
    let value: serde_json::Value = serde_wasm_bindgen::from_value(value).map_err(js_error)?;
    let mut bytes = Vec::new();
    encode_json_value(&mut shrike::cbor::Encoder::new(&mut bytes), &value).map_err(js_error)?;
    Ok(bytes)
}

/// Decode DAG-CBOR into a JSON-compatible JavaScript value.
#[wasm_bindgen(js_name = cborDecode)]
pub fn cbor_decode(bytes: &[u8]) -> Result<JsValue, JsValue> {
    let value = shrike::cbor::decode(bytes).map_err(js_error)?;
    to_js(&cbor_value_to_json(&value).map_err(js_error)?)
}

fn encode_json_value<W: std::io::Write>(
    encoder: &mut shrike::cbor::Encoder<W>,
    value: &serde_json::Value,
) -> Result<(), shrike::cbor::CborError> {
    match value {
        serde_json::Value::Null => encoder.encode_null(),
        serde_json::Value::Bool(value) => encoder.encode_bool(*value),
        serde_json::Value::Number(number) => {
            if let Some(value) = number.as_u64() {
                encoder.encode_u64(value)
            } else if let Some(value) = number.as_i64() {
                encoder.encode_i64(value)
            } else if let Some(value) = number.as_f64() {
                encoder.encode_f64(value)
            } else {
                Err(shrike::cbor::CborError::InvalidCbor(
                    "unsupported JSON number".into(),
                ))
            }
        }
        serde_json::Value::String(value) => encoder.encode_text(value),
        serde_json::Value::Array(values) => {
            encoder.encode_array_header(values.len() as u64)?;
            for value in values {
                encode_json_value(encoder, value)?;
            }
            Ok(())
        }
        serde_json::Value::Object(values) => {
            let mut keys: Vec<&str> = values.keys().map(String::as_str).collect();
            keys.sort_by(|left, right| shrike::cbor::cbor_key_cmp(left, right));
            encoder.encode_map_header(keys.len() as u64)?;
            for key in keys {
                encoder.encode_text(key)?;
                if let Some(value) = values.get(key) {
                    encode_json_value(encoder, value)?;
                }
            }
            Ok(())
        }
    }
}

fn cbor_value_to_json(value: &shrike::cbor::Value<'_>) -> Result<serde_json::Value, String> {
    Ok(match value {
        shrike::cbor::Value::Unsigned(value) => serde_json::Value::from(*value),
        shrike::cbor::Value::Signed(value) => serde_json::Value::from(*value),
        shrike::cbor::Value::Float(value) => serde_json::Number::from_f64(*value)
            .map(serde_json::Value::Number)
            .ok_or_else(|| "non-finite CBOR float".to_owned())?,
        shrike::cbor::Value::Bool(value) => serde_json::Value::Bool(*value),
        shrike::cbor::Value::Null => serde_json::Value::Null,
        shrike::cbor::Value::Text(value) => serde_json::Value::String((*value).to_owned()),
        shrike::cbor::Value::Bytes(value) => serde_json::Value::Array(
            value
                .iter()
                .map(|byte| serde_json::Value::from(*byte))
                .collect(),
        ),
        shrike::cbor::Value::Cid(value) => serde_json::Value::String(value.to_string()),
        shrike::cbor::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(cbor_value_to_json)
                .collect::<Result<_, _>>()?,
        ),
        shrike::cbor::Value::Map(values) => serde_json::Value::Object(
            values
                .iter()
                .map(|(key, value)| Ok(((*key).to_owned(), cbor_value_to_json(value)?)))
                .collect::<Result<_, String>>()?,
        ),
    })
}

/// A P-256 keypair backed by Shrike's AT Protocol crypto implementation.
#[wasm_bindgen(js_name = P256Key)]
pub struct WasmP256Key {
    inner: P256SigningKey,
}

#[wasm_bindgen(js_class = P256Key)]
impl WasmP256Key {
    /// Generate a new key using `crypto.getRandomValues`.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: P256SigningKey::generate(),
        }
    }

    /// Restore a key from its 32-byte private scalar.
    #[wasm_bindgen(js_name = fromPrivateKey)]
    pub fn from_private_key(bytes: &[u8]) -> Result<WasmP256Key, JsValue> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| js_error("a P-256 private key must be exactly 32 bytes"))?;
        let inner = P256SigningKey::from_bytes(&bytes).map_err(js_error)?;
        Ok(Self { inner })
    }

    /// Export the 32-byte private scalar.
    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    /// Export the 33-byte compressed public key.
    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().to_bytes().to_vec()
    }

    /// Return this key's `did:key` identifier.
    #[wasm_bindgen(js_name = didKey)]
    pub fn did_key(&self) -> String {
        self.inner.public_key().did_key()
    }

    /// Sign bytes and return a compact 64-byte ECDSA signature.
    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign(message)
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(js_error)
    }

    /// Create an RFC 9449 DPoP proof with this key.
    #[wasm_bindgen(js_name = createDpopProof)]
    pub fn create_dpop_proof(
        &self,
        method: &str,
        target_url: &str,
        nonce: Option<String>,
        access_token: Option<String>,
    ) -> Result<String, JsValue> {
        shrike::oauth::dpop::create_dpop_proof(
            &self.inner,
            method,
            target_url,
            nonce.as_deref(),
            access_token.as_deref(),
        )
        .map_err(js_error)
    }
}

impl Default for WasmP256Key {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a compact P-256 signature.
#[wasm_bindgen(js_name = verifyP256)]
pub fn verify_p256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let public_key: [u8; 33] = public_key
        .try_into()
        .map_err(|_| js_error("a compressed P-256 public key must be exactly 33 bytes"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| js_error("a compact P-256 signature must be exactly 64 bytes"))?;
    let key = P256VerifyingKey::from_bytes(&public_key).map_err(js_error)?;
    Ok(key
        .verify(message, &Signature::from_bytes(signature))
        .is_ok())
}

/// A secp256k1 keypair backed by Shrike's AT Protocol crypto implementation.
#[wasm_bindgen(js_name = K256Key)]
pub struct WasmK256Key {
    inner: K256SigningKey,
}

#[wasm_bindgen(js_class = K256Key)]
impl WasmK256Key {
    /// Generate a new key using `crypto.getRandomValues`.
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            inner: K256SigningKey::generate(),
        }
    }

    /// Restore a key from its 32-byte private scalar.
    #[wasm_bindgen(js_name = fromPrivateKey)]
    pub fn from_private_key(bytes: &[u8]) -> Result<WasmK256Key, JsValue> {
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| js_error("a K-256 private key must be exactly 32 bytes"))?;
        let inner = K256SigningKey::from_bytes(&bytes).map_err(js_error)?;
        Ok(Self { inner })
    }

    #[wasm_bindgen(js_name = privateKeyBytes)]
    pub fn private_key_bytes(&self) -> Vec<u8> {
        self.inner.to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = publicKeyBytes)]
    pub fn public_key_bytes(&self) -> Vec<u8> {
        self.inner.public_key().to_bytes().to_vec()
    }

    #[wasm_bindgen(js_name = didKey)]
    pub fn did_key(&self) -> String {
        self.inner.public_key().did_key()
    }

    pub fn sign(&self, message: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.inner
            .sign(message)
            .map(|signature| signature.as_bytes().to_vec())
            .map_err(js_error)
    }
}

impl Default for WasmK256Key {
    fn default() -> Self {
        Self::new()
    }
}

/// Verify a compact secp256k1 signature.
#[wasm_bindgen(js_name = verifyK256)]
pub fn verify_k256(public_key: &[u8], message: &[u8], signature: &[u8]) -> Result<bool, JsValue> {
    let public_key: [u8; 33] = public_key
        .try_into()
        .map_err(|_| js_error("a compressed K-256 public key must be exactly 33 bytes"))?;
    let signature: [u8; 64] = signature
        .try_into()
        .map_err(|_| js_error("a compact K-256 signature must be exactly 64 bytes"))?;
    let key = K256VerifyingKey::from_bytes(&public_key).map_err(js_error)?;
    Ok(key
        .verify(message, &Signature::from_bytes(signature))
        .is_ok())
}

/// Parse a P-256 or secp256k1 `did:key`.
#[wasm_bindgen(js_name = parseDidKey)]
pub fn parse_did_key(value: &str) -> Result<JsValue, JsValue> {
    let key = shrike::crypto::parse_did_key(value).map_err(js_error)?;
    let encoded = value
        .strip_prefix("did:key:z")
        .ok_or_else(|| js_error("not a did:key"))?;
    let multicodec = bs58::decode(encoded).into_vec().map_err(js_error)?;
    let key_type = if multicodec.starts_with(&[0x80, 0x24]) {
        "p256"
    } else if multicodec.starts_with(&[0xe7, 0x01]) {
        "k256"
    } else {
        return Err(js_error("unsupported did:key multicodec"));
    };

    let object = Object::new();
    Reflect::set(&object, &"type".into(), &key_type.into())?;
    Reflect::set(
        &object,
        &"publicKey".into(),
        &Uint8Array::from(key.to_bytes().as_slice()),
    )?;
    Reflect::set(&object, &"didKey".into(), &key.did_key().into())?;
    Reflect::set(&object, &"multibase".into(), &key.multibase().into())?;
    Ok(object.into())
}

/// Convert a compressed P-256 public key into a public JWK.
#[wasm_bindgen(js_name = publicJwk)]
pub fn public_jwk(public_key: &[u8]) -> Result<JsValue, JsValue> {
    let public_key: [u8; 33] = public_key
        .try_into()
        .map_err(|_| js_error("a compressed P-256 public key must be exactly 33 bytes"))?;
    let jwk = shrike::oauth::jwk::p256_public_jwk(&public_key).map_err(js_error)?;
    to_js(&jwk)
}

/// Generate a PKCE S256 verifier/challenge pair.
#[wasm_bindgen(js_name = generatePkce)]
pub fn generate_pkce() -> Result<JsValue, JsValue> {
    let pkce = shrike::oauth::pkce::generate_pkce();
    serde_wasm_bindgen::to_value(&serde_json::json!({
        "verifier": pkce.verifier,
        "challenge": pkce.challenge,
        "method": pkce.method,
    }))
    .map_err(js_error)
}

/// Resolve a DID in the browser. Network access is subject to CORS.
#[wasm_bindgen(js_name = resolveDid)]
pub async fn resolve_did(did: &str) -> Result<JsValue, JsValue> {
    let did = shrike::Did::try_from(did).map_err(js_error)?;
    let identity = shrike::identity::Directory::new()
        .lookup_did(&did)
        .await
        .map_err(js_error)?;
    identity_to_js(&identity)
}

/// Resolve and bidirectionally verify a handle in the browser. Browser builds
/// use the HTTPS well-known method because JavaScript has no DNS TXT API.
#[wasm_bindgen(js_name = resolveHandle)]
pub async fn resolve_handle(handle: &str) -> Result<JsValue, JsValue> {
    let handle = shrike::Handle::try_from(handle).map_err(js_error)?;
    let identity = shrike::identity::Directory::new()
        .lookup_handle(&handle)
        .await
        .map_err(js_error)?;
    identity_to_js(&identity)
}

fn identity_to_js(identity: &shrike::identity::Identity) -> Result<JsValue, JsValue> {
    let keys: BTreeMap<&str, String> = identity
        .keys
        .iter()
        .map(|(id, key)| (id.as_str(), key.did_key()))
        .collect();
    let services: BTreeMap<&str, serde_json::Value> = identity
        .services
        .iter()
        .map(|(id, service)| {
            (
                id.as_str(),
                serde_json::json!({
                    "id": service.id,
                    "type": service.r#type,
                    "endpoint": service.endpoint,
                }),
            )
        })
        .collect();
    serde_wasm_bindgen::to_value(&serde_json::json!({
        "did": identity.did,
        "handle": identity.handle,
        "keys": keys,
        "services": services,
    }))
    .map_err(js_error)
}

#[derive(Default, Deserialize)]
#[serde(default, rename_all = "camelCase")]
struct StreamOptions {
    cursor: Option<i64>,
    collections: Option<Vec<String>>,
    dids: Option<Vec<String>>,
    batch_size: Option<usize>,
    batch_timeout_ms: Option<u64>,
    max_message_size: Option<usize>,
}

impl StreamOptions {
    fn from_js(value: JsValue) -> Result<Self, JsValue> {
        if value.is_null() || value.is_undefined() {
            Ok(Self::default())
        } else {
            serde_wasm_bindgen::from_value(value).map_err(js_error)
        }
    }

    fn config(self, url: String) -> shrike::streaming::Config {
        shrike::streaming::Config {
            url,
            cursor: self.cursor,
            collections: self.collections,
            dids: self.dids,
            batch_size: self.batch_size,
            batch_timeout: self.batch_timeout_ms.map(std::time::Duration::from_millis),
            max_message_size: self.max_message_size,
            ..Default::default()
        }
    }
}

/// Handle for a running browser stream. Calling `close()` aborts the task and
/// drops its WebSocket immediately.
#[wasm_bindgen(js_name = StreamSubscription)]
pub struct WasmStreamSubscription {
    abort: AbortHandle,
}

#[wasm_bindgen(js_class = StreamSubscription)]
impl WasmStreamSubscription {
    pub fn close(&self) {
        self.abort.abort();
    }
}

/// Connect to a CBOR firehose and invoke `onEvent` for each decoded event.
#[wasm_bindgen(js_name = connectFirehose)]
pub fn connect_firehose(
    url: String,
    options: JsValue,
    on_event: Function,
    on_error: Option<Function>,
) -> Result<WasmStreamSubscription, JsValue> {
    let client = shrike::streaming::Client::new(StreamOptions::from_js(options)?.config(url));
    let (abort, registration) = AbortHandle::new_pair();
    wasm_bindgen_futures::spawn_local(async move {
        let task = async move {
            let stream = client.subscribe();
            pin_mut!(stream);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(batch) => {
                        for event in batch {
                            match firehose_event_to_json(event).and_then(|value| to_js(&value)) {
                                Ok(value) => {
                                    let _ = on_event.call1(&JsValue::NULL, &value);
                                }
                                Err(error) => emit_stream_error(on_error.as_ref(), error),
                            }
                        }
                    }
                    Err(error) => emit_stream_error(on_error.as_ref(), js_error(error)),
                }
            }
        };
        let _ = Abortable::new(task, registration).await;
    });
    Ok(WasmStreamSubscription { abort })
}

/// Connect to a JSON Jetstream endpoint and invoke `onEvent` for each event.
#[wasm_bindgen(js_name = connectJetstream)]
pub fn connect_jetstream(
    url: String,
    options: JsValue,
    on_event: Function,
    on_error: Option<Function>,
) -> Result<WasmStreamSubscription, JsValue> {
    let client = shrike::streaming::Client::new(StreamOptions::from_js(options)?.config(url));
    let (abort, registration) = AbortHandle::new_pair();
    wasm_bindgen_futures::spawn_local(async move {
        let task = async move {
            let stream = client.jetstream();
            pin_mut!(stream);
            while let Some(item) = stream.next().await {
                match item {
                    Ok(batch) => {
                        for event in batch {
                            match to_js(&jetstream_event_to_json(event)) {
                                Ok(value) => {
                                    let _ = on_event.call1(&JsValue::NULL, &value);
                                }
                                Err(error) => emit_stream_error(on_error.as_ref(), error),
                            }
                        }
                    }
                    Err(error) => emit_stream_error(on_error.as_ref(), js_error(error)),
                }
            }
        };
        let _ = Abortable::new(task, registration).await;
    });
    Ok(WasmStreamSubscription { abort })
}

fn emit_stream_error(callback: Option<&Function>, error: JsValue) {
    if let Some(callback) = callback {
        let _ = callback.call1(&JsValue::NULL, &error);
    }
}

fn firehose_event_to_json(event: shrike::streaming::Event) -> Result<serde_json::Value, JsValue> {
    use shrike::streaming::Event;
    Ok(match event {
        Event::Commit {
            did,
            rev,
            seq,
            operations,
        } => serde_json::json!({
            "kind": "commit",
            "did": did,
            "rev": rev,
            "seq": seq,
            "operations": operations
                .into_iter()
                .map(operation_to_json)
                .collect::<Result<Vec<_>, _>>()?,
        }),
        Event::Identity { did, seq, handle } => serde_json::json!({
            "kind": "identity",
            "did": did,
            "seq": seq,
            "handle": handle,
        }),
        Event::Account { did, seq, active } => serde_json::json!({
            "kind": "account",
            "did": did,
            "seq": seq,
            "active": active,
        }),
        Event::Labels { seq, labels } => serde_json::json!({
            "kind": "labels",
            "seq": seq,
            "labels": labels.into_iter().map(|label| serde_json::json!({
                "src": label.src,
                "uri": label.uri,
                "val": label.val,
                "neg": label.neg,
            })).collect::<Vec<_>>(),
        }),
    })
}

fn operation_to_json(
    operation: shrike::streaming::Operation,
) -> Result<serde_json::Value, JsValue> {
    use shrike::streaming::Operation;
    let record_json = |record: Vec<u8>| -> Result<serde_json::Value, JsValue> {
        let value = shrike::cbor::decode(&record).map_err(js_error)?;
        cbor_value_to_json(&value).map_err(js_error)
    };
    Ok(match operation {
        Operation::Create {
            collection,
            rkey,
            cid,
            record,
        } => serde_json::json!({
            "operation": "create",
            "collection": collection,
            "rkey": rkey,
            "cid": cid,
            "record": record_json(record)?,
        }),
        Operation::Update {
            collection,
            rkey,
            cid,
            record,
        } => serde_json::json!({
            "operation": "update",
            "collection": collection,
            "rkey": rkey,
            "cid": cid,
            "record": record_json(record)?,
        }),
        Operation::Delete { collection, rkey } => serde_json::json!({
            "operation": "delete",
            "collection": collection,
            "rkey": rkey,
        }),
        Operation::Resync {
            collection,
            rkey,
            cid,
            record,
        } => serde_json::json!({
            "operation": "resync",
            "collection": collection,
            "rkey": rkey,
            "cid": cid,
            "record": record_json(record)?,
        }),
    })
}

fn jetstream_event_to_json(event: shrike::streaming::JetstreamEvent) -> serde_json::Value {
    use shrike::streaming::{JetstreamCommit, JetstreamEvent};
    match event {
        JetstreamEvent::Commit {
            did,
            time_us,
            collection,
            rkey,
            operation,
        } => {
            let (action, cid, record) = match operation {
                JetstreamCommit::Create { cid, record } => ("create", Some(cid), Some(record)),
                JetstreamCommit::Update { cid, record } => ("update", Some(cid), Some(record)),
                JetstreamCommit::Delete => ("delete", None, None),
            };
            serde_json::json!({
                "kind": "commit",
                "did": did,
                "timeUs": time_us,
                "collection": collection,
                "rkey": rkey,
                "operation": action,
                "cid": cid,
                "record": record,
            })
        }
        JetstreamEvent::Identity { did, time_us } => serde_json::json!({
            "kind": "identity",
            "did": did,
            "timeUs": time_us,
        }),
        JetstreamEvent::Account {
            did,
            time_us,
            active,
        } => serde_json::json!({
            "kind": "account",
            "did": did,
            "timeUs": time_us,
            "active": active,
        }),
    }
}

fn to_js(value: &serde_json::Value) -> Result<JsValue, JsValue> {
    serde_wasm_bindgen::to_value(value).map_err(js_error)
}

// === Jetstream v2 (sealed archive + live) browser binding ===================
//
// A separate export from the legacy `connectJetstream` above (which speaks
// Jetstream v1 line-delimited JSON over a single WebSocket and is left
// untouched). This one drives `shrike::jetstream::Engine`, merging sealed `.jss`
// archive segments with the live WebSocket into one ordered stream, using the
// browser transports (`WasmHttpTransport` for the archive/dictionary fetches and
// `WasmWsTransport` for the live tail).
//
// It is gated to `wasm32-unknown-unknown`: the browser transports it references
// exist only on that target, and this crate is also compiled for the host during
// a workspace build, where they are absent.
#[cfg(all(target_family = "wasm", target_os = "unknown"))]
mod jetstream_v2 {
    use super::js_error;
    use js_sys::Function;
    use serde::Deserialize;
    use wasm_bindgen::prelude::*;

    use shrike::jetstream::{
        ApiKey, ArchiveClient, ArchiveConfig, Batch, CancelToken, ClientArchive, Delivery, Engine,
        EngineConfig, EngineSink, Event, EventPayload, Filter, HttpDictionarySource, Info, Kind,
        LiveConfig, Operation, StatsHandle, WasmHttpTransport, WasmWsTransport,
    };

    /// The default public Jetstream v2 host, matching the CLI.
    const DEFAULT_HOST: &str = "jetstream.us-east.bsky.network";

    /// Serialize a value to a **plain** JavaScript object so consumers can use
    /// property access (`event.kind`, `stats.deliveredEvents`). The default
    /// `serde_wasm_bindgen` serializer emits an ES `Map` for a serde map, which
    /// reads as `undefined` under dotted access — a browser footgun this binding
    /// avoids by always going through the `json_compatible` serializer.
    fn to_plain_js(value: &serde_json::Value) -> Result<JsValue, JsValue> {
        use serde::Serialize;
        value
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .map_err(js_error)
    }

    /// Deliver a stream error to `on_error`, tagged so JavaScript can tell a
    /// fatal (stream-ending) error from a recoverable one without matching the
    /// message text: `error.fatal` is `true` only for the single terminal error,
    /// and `error.recoverable` is its inverse. A recoverable error is delivered
    /// in order and the stream keeps running; a fatal error is always paired with
    /// the terminal `onComplete` call below.
    fn emit_error(callback: Option<&Function>, error: JsValue, fatal: bool) {
        let Some(callback) = callback else {
            return;
        };
        // `error` is a `js_sys::Error` object (from `js_error`), so these tags
        // land as own properties; on the off chance it is not an object the
        // writes are simply dropped and the untagged error is still delivered.
        let _ = js_sys::Reflect::set(
            &error,
            &JsValue::from_str("fatal"),
            &JsValue::from_bool(fatal),
        );
        let _ = js_sys::Reflect::set(
            &error,
            &JsValue::from_str("recoverable"),
            &JsValue::from_bool(!fatal),
        );
        let _ = callback.call1(&JsValue::NULL, &error);
    }

    /// Fire the terminal completion signal exactly once, when the stream ends for
    /// any reason (snapshot finished, `close()` called, or a fatal error). The
    /// argument is `{ ok: boolean, error: string | null }`, so a UI can show a
    /// final state without having to also wire `onError`.
    fn emit_complete(callback: Option<&Function>, outcome: &Result<(), shrike::jetstream::Error>) {
        let Some(callback) = callback else {
            return;
        };
        let value = match outcome {
            Ok(()) => serde_json::json!({ "ok": true, "error": serde_json::Value::Null }),
            Err(error) => serde_json::json!({ "ok": false, "error": error.to_string() }),
        };
        if let Ok(js) = to_plain_js(&value) {
            let _ = callback.call1(&JsValue::NULL, &js);
        }
    }

    /// Options for [`connect_jetstream_v2`], deserialized from a plain JS object.
    ///
    /// `replayKey` is the archive bearer secret. It is read from this per-call
    /// object, held only in memory for the life of the subscription, and never
    /// persisted or placed in a URL — a browser session supplies it at runtime.
    #[derive(Default, Deserialize)]
    #[serde(default, rename_all = "camelCase")]
    struct Options {
        host: Option<String>,
        /// Use ws:// and http:// (loopback testing only; the archive key is
        /// refused over cleartext to a non-loopback host by `ArchiveClient`).
        insecure: bool,
        archive_host: Option<String>,
        collections: Vec<String>,
        dids: Vec<String>,
        kinds: Vec<String>,
        after_seq: Option<u64>,
        before_seq: Option<u64>,
        snapshot_only: bool,
        no_compression: bool,
        replay_key: Option<String>,
    }

    /// A running Jetstream v2 subscription. `close()` cancels the engine, which
    /// races cancellation against every blocking step (dial, read, backoff,
    /// dictionary fetch), so the WebSocket and its listeners are dropped promptly
    /// and any in-flight batch finishes cleanly. `stats()` snapshots replay and
    /// cutover progress for the UI.
    #[wasm_bindgen(js_name = JetstreamV2Subscription)]
    pub struct Subscription {
        cancel: CancelToken,
        stats: StatsHandle,
    }

    #[wasm_bindgen(js_class = JetstreamV2Subscription)]
    impl Subscription {
        /// Stop the stream and drop the underlying transport.
        pub fn close(&self) {
            self.cancel.cancel();
        }

        /// A snapshot of engine progress: sealed tip, planned-through sequence,
        /// residual gap, delivered events, last processed sequence, and active
        /// archive downloads. The UI polls this to show replay/cutover progress.
        pub fn stats(&self) -> Result<JsValue, JsValue> {
            let s = self.stats.snapshot();
            to_plain_js(&serde_json::json!({
                "pages": s.pages,
                "sealedTipSeq": s.sealed_tip_seq,
                "plannedThroughSeq": s.planned_through_seq,
                "residualGap": s.residual_gap,
                "deliveredEvents": s.delivered_events,
                "lastProcessedSeq": s.last_processed_seq,
                "activeDownloads": self.stats.active_downloads(),
            }))
        }
    }

    /// Connect a Jetstream v2 stream and invoke `onEvent` for each event.
    ///
    /// Three modes fall out of the options, matching the CLI: live tail (no
    /// archive), replay-then-cutover (`afterSeq`), and snapshot (`snapshotOnly`,
    /// optionally bounded by `beforeSeq`). Any archive mode requires `replayKey`.
    ///
    /// Every value handed to JavaScript — events, `#info` advisories, and
    /// `stats()` — is a plain object, so `event.kind` / `event.seq` work directly.
    ///
    /// Callbacks (all but `onEvent` optional):
    /// - `onEvent(event)` — one call per event.
    /// - `onInfo(info)` — `#info` advisories (`{ name, message }`).
    /// - `onError(error)` — stream errors. `error.recoverable === true` means the
    ///   stream kept running; `error.fatal === true` means it ended (and
    ///   `onComplete` also fires).
    /// - `onComplete(result)` — fires once when the stream ends for any reason,
    ///   with `{ ok: boolean, error: string | null }`.
    #[wasm_bindgen(js_name = connectJetstreamV2)]
    pub fn connect_jetstream_v2(
        options: JsValue,
        on_event: Function,
        on_info: Option<Function>,
        on_error: Option<Function>,
        on_complete: Option<Function>,
    ) -> Result<Subscription, JsValue> {
        let opts: Options = if options.is_null() || options.is_undefined() {
            Options::default()
        } else {
            serde_wasm_bindgen::from_value(options).map_err(js_error)?
        };

        let host = opts.host.unwrap_or_else(|| DEFAULT_HOST.to_owned());
        let secure = !opts.insecure;

        let mut live = LiveConfig::new(&host, secure);
        live.filter = build_filter(&opts.collections, &opts.dids, &opts.kinds)?;
        live.compression = !opts.no_compression;
        let read_limit = live.read_limit;

        let mut config = EngineConfig::new(live);
        config.after_seq = opts.after_seq.unwrap_or(0);
        config.before_seq = opts.before_seq;
        config.snapshot_only = opts.snapshot_only;

        let needs_archive =
            opts.after_seq.is_some() || opts.snapshot_only || opts.before_seq.is_some();

        let cancel = CancelToken::new();

        // The archive is built only when a replay window is requested. Its bearer
        // key comes from `replayKey` and never leaves this function except as an
        // Authorization header inside the transport; `ArchiveClient::new` refuses
        // to send it over cleartext http to a non-loopback host.
        let archive = if needs_archive {
            let key = opts.replay_key.unwrap_or_default();
            if key.is_empty() {
                return Err(js_error(
                    "archive replay (afterSeq/beforeSeq/snapshotOnly) requires a replayKey",
                ));
            }
            let archive_host = opts.archive_host.unwrap_or_else(|| host.clone());
            let mut archive_config = ArchiveConfig::new(archive_host, ApiKey::new(key));
            archive_config.secure = secure;
            let client =
                ArchiveClient::new(WasmHttpTransport::new(), archive_config).map_err(js_error)?;
            Some(ClientArchive::new(client))
        } else {
            None
        };

        // The dictionary source and live tail are unauthenticated; only the
        // archive carries the bearer key.
        let dict = HttpDictionarySource::new(
            WasmHttpTransport::new(),
            host.clone(),
            secure,
            cancel.clone(),
        );
        let ws = WasmWsTransport::new(read_limit);

        let engine = Engine::new(archive, ws, dict, config, cancel.clone());
        let stats = engine.stats();

        let mut sink = JsSink {
            on_event,
            on_info,
            on_error: on_error.clone(),
        };
        wasm_bindgen_futures::spawn_local(async move {
            let outcome = engine.run(&mut sink).await;
            // A fatal error surfaces on `onError` (tagged fatal) for consumers
            // wiring only that callback, and always as the terminal `onComplete`.
            if let Err(error) = &outcome {
                emit_error(on_error.as_ref(), js_error(error), true);
            }
            emit_complete(on_complete.as_ref(), &outcome);
        });

        Ok(Subscription { cancel, stats })
    }

    /// Assemble the event filter from the option arrays. An empty filter matches
    /// everything, mirroring the CLI.
    fn build_filter(
        collections: &[String],
        dids: &[String],
        kinds: &[String],
    ) -> Result<Filter, JsValue> {
        let mut filter = Filter::new();
        if !kinds.is_empty() {
            let mut parsed = Vec::with_capacity(kinds.len());
            for k in kinds {
                let kind = Kind::from_wire(k).ok_or_else(|| {
                    js_error(format!(
                        "unknown event kind: {k} (expected commit, identity, account, or sync)"
                    ))
                })?;
                parsed.push(kind);
            }
            filter = filter.kinds(parsed);
        }
        if !dids.is_empty() {
            filter = filter.dids(dids).map_err(js_error)?;
        }
        if !collections.is_empty() {
            filter = filter.collections(collections).map_err(js_error)?;
        }
        Ok(filter)
    }

    /// The engine sink that forwards deliveries to the JS callbacks. Returning
    /// `true` from both methods keeps the stream running (a recoverable error is
    /// delivered in order and the engine continues after it).
    struct JsSink {
        on_event: Function,
        on_info: Option<Function>,
        on_error: Option<Function>,
    }

    impl EngineSink for JsSink {
        async fn deliver(&mut self, delivery: Delivery) -> bool {
            match delivery {
                Delivery::Batch(batch) => self.emit_batch(&batch),
                Delivery::Info(info) => self.emit_info(&info),
            }
            true
        }

        async fn recoverable(&mut self, error: shrike::jetstream::Error) -> bool {
            emit_error(self.on_error.as_ref(), js_error(error), false);
            true
        }
    }

    impl JsSink {
        fn emit_batch(&self, batch: &Batch) {
            for event in batch.events() {
                match event_to_json(event).and_then(|value| to_plain_js(&value)) {
                    Ok(value) => {
                        let _ = self.on_event.call1(&JsValue::NULL, &value);
                    }
                    // A single event that will not serialize is recoverable: the
                    // stream keeps running, so report it as such rather than fatal.
                    Err(error) => emit_error(self.on_error.as_ref(), error, false),
                }
            }
        }

        fn emit_info(&self, info: &Info) {
            let Some(callback) = self.on_info.as_ref() else {
                return;
            };
            let value = serde_json::json!({ "name": info.name, "message": info.message });
            if let Ok(js) = to_plain_js(&value) {
                let _ = callback.call1(&JsValue::NULL, &js);
            }
        }
    }

    /// Convert an event to the JSON shape delivered to `onEvent`. Mirrors the
    /// CLI's `event_to_json`, but with camelCase keys for JS consumers.
    fn event_to_json(event: &Event) -> Result<serde_json::Value, JsValue> {
        let mut obj = serde_json::Map::new();
        obj.insert("seq".into(), event.seq.into());
        obj.insert("did".into(), event.did.as_str().into());
        obj.insert("timeUs".into(), event.time_us.into());
        obj.insert("kind".into(), event.kind().as_wire().into());
        match &event.payload {
            EventPayload::Commit(commit) => {
                obj.insert("operation".into(), operation_str(commit.operation).into());
                obj.insert("collection".into(), commit.collection.as_str().into());
                obj.insert("rkey".into(), commit.rkey.as_str().into());
                obj.insert("rev".into(), commit.rev.to_string().into());
                if let Some(record) = &commit.record {
                    obj.insert("record".into(), record.to_json().map_err(js_error)?);
                }
            }
            EventPayload::Identity(v) => {
                obj.insert(
                    "identity".into(),
                    serde_json::to_value(v).map_err(js_error)?,
                );
            }
            EventPayload::Account(v) => {
                obj.insert("account".into(), serde_json::to_value(v).map_err(js_error)?);
            }
            EventPayload::Sync(v) => {
                obj.insert("sync".into(), serde_json::to_value(v).map_err(js_error)?);
            }
        }
        Ok(serde_json::Value::Object(obj))
    }

    fn operation_str(op: Operation) -> &'static str {
        match op {
            Operation::Create => "create",
            Operation::Update => "update",
            Operation::Delete => "delete",
        }
    }
}

/// A JSON-oriented XRPC client for JavaScript.
#[wasm_bindgen(js_name = XrpcClient)]
pub struct WasmXrpcClient {
    inner: shrike::xrpc::Client,
}

#[wasm_bindgen(js_class = XrpcClient)]
impl WasmXrpcClient {
    #[wasm_bindgen(constructor)]
    pub fn new(host: &str) -> Self {
        Self {
            inner: shrike::xrpc::Client::new(host),
        }
    }

    /// Execute an unauthenticated JSON XRPC query.
    pub async fn query(&self, nsid: &str, params: JsValue) -> Result<JsValue, JsValue> {
        let params: serde_json::Value = serde_wasm_bindgen::from_value(params).map_err(js_error)?;
        let output: serde_json::Value = self.inner.query(nsid, &params).await.map_err(js_error)?;
        serde_wasm_bindgen::to_value(&output).map_err(js_error)
    }

    /// Execute an unauthenticated JSON XRPC procedure.
    pub async fn procedure(&self, nsid: &str, input: JsValue) -> Result<JsValue, JsValue> {
        let input: serde_json::Value = serde_wasm_bindgen::from_value(input).map_err(js_error)?;
        let output: serde_json::Value =
            self.inner.procedure(nsid, &input).await.map_err(js_error)?;
        serde_wasm_bindgen::to_value(&output).map_err(js_error)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;
    use wasm_bindgen_test::*;

    #[wasm_bindgen_test]
    fn syntax_and_tid_work() {
        assert_eq!(
            validate_syntax("handle", "Alice.Bsky.Social").unwrap_or_default(),
            "alice.bsky.social"
        );
        let clock = WasmTidClock::new(0).ok();
        assert_eq!(
            clock
                .as_ref()
                .map(WasmTidClock::next)
                .unwrap_or_default()
                .len(),
            13
        );
    }

    #[wasm_bindgen_test]
    fn crypto_uses_browser_randomness() {
        let key = WasmP256Key::new();
        let message = b"shrike wasm";
        let signature = key.sign(message).unwrap_or_default();
        assert!(verify_p256(&key.public_key_bytes(), message, &signature).unwrap_or(false));

        let key = WasmK256Key::new();
        let signature = key.sign(message).unwrap_or_default();
        assert!(verify_k256(&key.public_key_bytes(), message, &signature).unwrap_or(false));
        assert!(parse_did_key(&key.did_key()).is_ok());
    }

    #[wasm_bindgen_test]
    fn cid_is_stable() {
        let first = cid_for_bytes("raw", b"hello").unwrap_or_default();
        let second = cid_for_bytes("raw", b"hello").unwrap_or_default();
        assert_eq!(first, second);
    }

    // Jetstream v2 M0: prove the portable segment codec runs on the browser
    // target, where compression goes through `ruzstd` rather than libzstd. The
    // same golden corpus the native tests use is embedded here.
    #[wasm_bindgen_test]
    fn jetstream_golden_block_decodes_on_wasm() {
        const GOLDEN_BLOCK: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/jetstream/golden/golden_block.bin"
        ));
        let events =
            shrike::jetstream::decode_block_frame(GOLDEN_BLOCK).expect("golden block decodes");
        assert_eq!(events.len(), 3);
        assert_eq!(events[0].seq, 1);
        assert_eq!(events[0].did, b"did:plc:abcdefghijklmnopqrstuvwx");
        assert_eq!(events[0].collection, b"app.bsky.feed.post");
        assert_eq!(
            events[0].payload,
            [0xA1, 0x65, 0x68, 0x65, 0x6C, 0x6C, 0x6F, 0x05]
        );
        assert_eq!(events[2].kind, shrike::jetstream::SegmentKind::Delete);
    }

    #[wasm_bindgen_test]
    fn jetstream_dictionary_frame_decodes_on_wasm() {
        const LIVE_DICT: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/jetstream/golden/live_dict.bin"
        ));
        const LIVE_COMMIT_DICTZST: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/jetstream/golden/live_commit.dictzst"
        ));
        const LIVE_COMMIT_JSON: &[u8] = include_bytes!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../testdata/jetstream/golden/live_commit.json"
        ));
        let out =
            shrike::jetstream::decompress_bounded(LIVE_COMMIT_DICTZST, 32 << 20, Some(LIVE_DICT))
                .expect("dictionary frame decodes");
        assert_eq!(out, LIVE_COMMIT_JSON);
    }

    #[wasm_bindgen_test]
    fn cbor_json_roundtrip() {
        let expected = serde_json::json!({
            "text": "hello",
            "count": 3,
            "items": [true, null],
        });
        let input = serde_wasm_bindgen::to_value(&expected).unwrap_or(JsValue::NULL);
        let encoded = cbor_encode(input).unwrap_or_default();
        let decoded = cbor_decode(&encoded).unwrap_or(JsValue::NULL);
        let actual: Option<serde_json::Value> = serde_wasm_bindgen::from_value(decoded).ok();
        assert_eq!(actual.as_ref(), Some(&expected));
    }

    // === Jetstream v2 browser binding (`connectJetstreamV2`) ==================
    //
    // These exercise the binding's synchronous option-validation and the
    // subscription surface without touching the network. They are gated to the
    // wasm target because they name the `jetstream_v2` module, which only
    // exists there; on the native host (where `mod tests` still compiles under
    // `cargo test --workspace`) they are excluded entirely.

    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn noop_fn() -> js_sys::Function {
        js_sys::Function::new_no_args("")
    }

    // Build the options as a plain JS object, exactly as a browser caller would
    // pass a `{ ... }` literal. The default `serde_wasm_bindgen` serializer emits
    // an ES `Map` for a `serde_json::Value` map, which the binding's struct
    // deserialize would not recognize; `json_compatible` serializes maps as
    // objects so the test drives the same shape real callers send.
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn v2_options(value: serde_json::Value) -> JsValue {
        use serde::Serialize;
        value
            .serialize(&serde_wasm_bindgen::Serializer::json_compatible())
            .unwrap()
    }

    // Snapshot / range replay reads sealed archive segments, which require an
    // authenticated key. Asking for a snapshot without one must fail loudly at
    // the call site rather than silently degrade to a live-only tail.
    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_snapshot_requires_replay_key() {
        let result = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({ "snapshotOnly": true })),
            noop_fn(),
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "snapshotOnly without a replayKey must be rejected"
        );
    }

    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_after_seq_requires_replay_key() {
        let result = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({ "afterSeq": 10 })),
            noop_fn(),
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "afterSeq replay without a replayKey must be rejected"
        );
    }

    // An unrecognized wire kind is a caller mistake; surface it before wiring up
    // an engine that would silently match nothing.
    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_unknown_kind_is_rejected() {
        let result = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({ "kinds": ["bogus"] })),
            noop_fn(),
            None,
            None,
            None,
        );
        assert!(result.is_err(), "an unknown event kind must be rejected");
    }

    // Security regression: an archive key must never travel over cleartext to a
    // non-loopback host. `ArchiveClient::new` enforces this; the binding must
    // surface that rejection instead of dialing out with the key in the clear.
    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_archive_key_refused_over_cleartext() {
        let result = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({
                "snapshotOnly": true,
                "replayKey": "secret",
                "insecure": true,
                "host": "example.com",
            })),
            noop_fn(),
            None,
            None,
            None,
        );
        assert!(
            result.is_err(),
            "a cleartext archive key to a non-loopback host must be rejected"
        );
    }

    // A live-only subscription needs no archive key, returns immediately, and
    // exposes a zeroed stats snapshot with the documented camelCase shape.
    // `close()` must be idempotent so a double-cancel from the UI is harmless.
    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_live_subscription_reports_stats_and_closes() {
        let sub = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({ "host": "127.0.0.1:9", "insecure": true })),
            noop_fn(),
            None,
            None,
            None,
        )
        .expect("a live-only subscription needs no archive key");

        let stats = sub.stats().expect("stats snapshot serializes");
        let value: serde_json::Value = serde_wasm_bindgen::from_value(stats).unwrap();
        for key in [
            "pages",
            "sealedTipSeq",
            "plannedThroughSeq",
            "residualGap",
            "deliveredEvents",
            "lastProcessedSeq",
            "activeDownloads",
        ] {
            assert_eq!(value[key], serde_json::json!(0), "{key} starts at zero");
        }

        // Idempotent teardown: cancelling twice must not panic or double-free
        // the WebSocket listeners.
        sub.close();
        sub.close();
    }

    // Ergonomics regression: the default `serde_wasm_bindgen` serializer emits an
    // ES `Map` for a serde map, on which `value.pages` reads `undefined` — the
    // README and demo both use property access. `stats()` must hand back a plain
    // object so `Reflect::get` (i.e. `value.pages`) returns the value directly.
    #[wasm_bindgen_test]
    #[cfg(all(target_family = "wasm", target_os = "unknown"))]
    fn jetstream_v2_stats_is_a_plain_object_not_a_map() {
        use wasm_bindgen::JsCast;
        let sub = crate::jetstream_v2::connect_jetstream_v2(
            v2_options(serde_json::json!({ "host": "127.0.0.1:9", "insecure": true })),
            noop_fn(),
            None,
            None,
            None,
        )
        .expect("a live-only subscription needs no archive key");

        let stats = sub.stats().expect("stats snapshot serializes");
        assert!(
            !stats.is_instance_of::<js_sys::Map>(),
            "stats must be a plain object, not an ES Map"
        );
        let pages = js_sys::Reflect::get(&stats, &"pages".into())
            .expect("plain object exposes its keys as properties");
        assert!(
            !pages.is_undefined(),
            "property access (value.pages) must work on the returned object"
        );
        assert_eq!(pages.as_f64(), Some(0.0), "pages starts at zero");

        sub.close();
    }
}
