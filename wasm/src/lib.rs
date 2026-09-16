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
}
