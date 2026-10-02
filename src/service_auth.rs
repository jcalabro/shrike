//! Inter-service authentication JWTs.
//!
//! A service JWT is a short-lived token signed with an account's (or
//! service's) atproto signing key. `iss` is the signer's DID, optionally with a
//! `#service` fragment, `aud` is the receiving service's DID, and `lxm` binds
//! the token to one XRPC method. This follows the reference `@atproto/xrpc-server`
//! `createServiceJwt` and `verifyJwt`, including the order of checks, error
//! names and messages.
//!
//! ```
//! # async fn example() -> Result<(), shrike::service_auth::ServiceAuthError> {
//! use shrike::crypto::{P256SigningKey, SigningKey, VerifyingKey};
//! use shrike::service_auth::{ServiceJwtParams, ServiceJwtVerifier, create_service_jwt};
//!
//! let key = P256SigningKey::generate();
//! let did_key = key.public_key().did_key();
//! let mut params = ServiceJwtParams::new("did:example:alice", "did:web:feed.example.com");
//! params.lxm = Some("app.bsky.feed.getFeedSkeleton");
//! let jwt = create_service_jwt(&params, &key)?;
//!
//! // Resolve the issuer's signing key; real services use an identity::Directory.
//! let resolver = move |_iss: String, _force_refresh: bool| {
//!     let did_key = did_key.clone();
//!     async move { Ok(did_key) }
//! };
//! let verifier = ServiceJwtVerifier::new(Some("did:web:feed.example.com"), resolver);
//! let claims = verifier
//!     .verify(&jwt, Some("app.bsky.feed.getFeedSkeleton"))
//!     .await?;
//! assert_eq!(claims.iss, "did:example:alice");
//! # Ok(())
//! # }
//! ```

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use data_encoding::BASE64URL_NOPAD;
use serde_json::{Map, Value};

use crate::crypto::{Signature, SigningKey, parse_did_key};
use crate::syntax::Did;

/// Default token lifetime when [`ServiceJwtParams::exp`] is unset.
pub const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// A boxed, sendable future, as returned by [`SigningKeyResolver`].
#[cfg(not(target_arch = "wasm32"))]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// A boxed future, as returned by [`SigningKeyResolver`]. Not `Send` on
/// wasm, where browser futures never are.
#[cfg(target_arch = "wasm32")]
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + 'a>>;

/// A service-auth failure. Every variant maps to an HTTP 401
/// `AuthenticationRequired` response with the [`error_name`](Self::error_name)
/// as the XRPC `error` and the `Display` text as the `message`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ServiceAuthError {
    /// The token is not three base64url JSON segments with the required claims.
    #[error("poorly formatted jwt")]
    BadJwt,
    /// The header `typ` marks a token that must not be used as service auth.
    #[error("Invalid jwt type \"{0}\"")]
    BadJwtType(String),
    /// `exp` is in the past.
    #[error("jwt expired")]
    JwtExpired,
    /// `aud` is not this service.
    #[error("jwt audience does not match service did")]
    BadJwtAudience,
    /// `lxm` is missing or names a different method.
    #[error("{} jwt lexicon method (\"lxm\"). must match: {expected}", if *.present { "bad" } else { "missing" })]
    BadJwtLexiconMethod {
        /// The method the token must be bound to.
        expected: String,
        /// Whether the token carried an `lxm` at all.
        present: bool,
    },
    /// `iss` is not a DID, optionally with one non-empty `#fragment`.
    #[error("jwt iss is not a valid did")]
    BadJwtIss,
    /// The key could not check the signature (unparseable key, or its type
    /// does not match the header `alg`).
    #[error("could not verify jwt signature")]
    UnverifiableSignature,
    /// The signature does not verify, even with a freshly resolved key.
    #[error("jwt signature does not match jwt issuer")]
    BadSignature,
    /// The issuer's signing key could not be resolved. `error` becomes the
    /// XRPC error name (e.g. `UntrustedIss`).
    #[error("{message}")]
    KeyResolution {
        /// XRPC error name.
        error: String,
        /// Human-readable detail.
        message: String,
    },
    /// Creating a token failed.
    #[error("could not sign jwt: {0}")]
    Signing(String),
}

impl ServiceAuthError {
    /// The XRPC error name for this failure.
    pub fn error_name(&self) -> &str {
        match self {
            ServiceAuthError::BadJwt => "BadJwt",
            ServiceAuthError::BadJwtType(_) => "BadJwtType",
            ServiceAuthError::JwtExpired => "JwtExpired",
            ServiceAuthError::BadJwtAudience => "BadJwtAudience",
            ServiceAuthError::BadJwtLexiconMethod { .. } => "BadJwtLexiconMethod",
            ServiceAuthError::BadJwtIss => "BadJwtIss",
            ServiceAuthError::UnverifiableSignature | ServiceAuthError::BadSignature => {
                "BadJwtSignature"
            }
            ServiceAuthError::KeyResolution { error, .. } => error,
            ServiceAuthError::Signing(_) => "InternalServerError",
        }
    }

    /// A key-resolution failure with an XRPC error name and message.
    pub fn key_resolution(error: impl Into<String>, message: impl Into<String>) -> Self {
        ServiceAuthError::KeyResolution {
            error: error.into(),
            message: message.into(),
        }
    }
}

/// Parameters for [`create_service_jwt`].
#[derive(Debug, Clone)]
pub struct ServiceJwtParams<'a> {
    /// Issuer DID, optionally with a `#service` fragment.
    pub iss: &'a str,
    /// Audience: the receiving service's DID (with fragment, if it uses one).
    pub aud: &'a str,
    /// The XRPC method (NSID) this token is bound to.
    pub lxm: Option<&'a str>,
    /// Issued-at, in Unix seconds. Defaults to now.
    pub iat: Option<u64>,
    /// Expiry, in Unix seconds. Defaults to `iat` + [`DEFAULT_TTL`].
    pub exp: Option<u64>,
}

impl<'a> ServiceJwtParams<'a> {
    /// Parameters with no `lxm` and default timestamps.
    pub fn new(iss: &'a str, aud: &'a str) -> Self {
        ServiceJwtParams {
            iss,
            aud,
            lxm: None,
            iat: None,
            exp: None,
        }
    }
}

#[derive(serde::Serialize)]
struct Header<'a> {
    typ: &'a str,
    alg: &'a str,
}

#[derive(serde::Serialize)]
struct Payload<'a> {
    iat: u64,
    iss: &'a str,
    aud: &'a str,
    exp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    lxm: Option<&'a str>,
    jti: String,
}

/// Create a signed service JWT.
///
/// The header is `{"typ":"JWT","alg":...}` with `alg` taken from the key
/// (`ES256` or `ES256K`), and the payload carries `iat`, `iss`, `aud`, `exp`,
/// `lxm` (if set) and a random 128-bit hex `jti`. The signature is the compact,
/// low-S ECDSA signature over SHA-256 of `header.payload`.
pub fn create_service_jwt(
    params: &ServiceJwtParams<'_>,
    key: &dyn SigningKey,
) -> Result<String, ServiceAuthError> {
    use rand_core::{OsRng, RngCore};

    let iat = params
        .iat
        .unwrap_or_else(|| crate::platform::unix_time_millis() / 1000);
    let exp = params
        .exp
        .unwrap_or(iat.saturating_add(DEFAULT_TTL.as_secs()));
    let mut jti = [0u8; 16];
    OsRng.fill_bytes(&mut jti);
    let header = Header {
        typ: "JWT",
        alg: key.public_key().jwt_alg(),
    };
    let payload = Payload {
        iat,
        iss: params.iss,
        aud: params.aud,
        exp,
        lxm: params.lxm,
        jti: data_encoding::HEXLOWER.encode(&jti),
    };
    let signing_input = format!("{}.{}", b64_json(&header)?, b64_json(&payload)?);
    let sig = key
        .sign(signing_input.as_bytes())
        .map_err(|e| ServiceAuthError::Signing(e.to_string()))?;
    Ok(format!(
        "{signing_input}.{}",
        BASE64URL_NOPAD.encode(sig.as_bytes())
    ))
}

fn b64_json<T: serde::Serialize>(value: &T) -> Result<String, ServiceAuthError> {
    serde_json::to_vec(value)
        .map(|json| BASE64URL_NOPAD.encode(&json))
        .map_err(|e| ServiceAuthError::Signing(e.to_string()))
}

/// The verified claims of a service JWT.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceJwtClaims {
    /// The issuer, exactly as in the token (may include `#fragment`).
    pub iss: String,
    /// The issuer DID, without any fragment.
    pub did: Did,
    /// The issuer's service fragment (without `#`), if any.
    pub fragment: Option<String>,
    /// The audience.
    pub aud: String,
    /// Expiry, in (possibly fractional) Unix seconds.
    pub exp: f64,
    /// The method binding, if any.
    pub lxm: Option<String>,
    /// The token id, if any.
    pub jti: Option<String>,
    /// Every payload claim, including the ones above.
    pub claims: Map<String, Value>,
}

/// Resolves a token issuer to its signing key, as a `did:key` string.
///
/// `iss` is passed exactly as in the token, including any `#fragment`, so
/// the resolver can pick the right verification method. With
/// `force_refresh` the resolver must bypass any cache: verification calls it
/// that way once after a signature mismatch, in case the key was rotated.
///
/// Implemented for closures `Fn(String, bool) -> impl Future<Output =
/// Result<String, ServiceAuthError>>` and, with the `identity` feature, for
/// [`crate::identity::Directory`].
pub trait SigningKeyResolver: Send + Sync {
    /// Resolve `iss` to a `did:key` string.
    fn resolve_signing_key<'a>(
        &'a self,
        iss: &'a str,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<String, ServiceAuthError>>;
}

#[cfg(not(target_arch = "wasm32"))]
impl<F, Fut> SigningKeyResolver for F
where
    F: Fn(String, bool) -> Fut + Send + Sync,
    Fut: Future<Output = Result<String, ServiceAuthError>> + Send + 'static,
{
    fn resolve_signing_key<'a>(
        &'a self,
        iss: &'a str,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<String, ServiceAuthError>> {
        Box::pin(self(iss.to_owned(), force_refresh))
    }
}

#[cfg(target_arch = "wasm32")]
impl<F, Fut> SigningKeyResolver for F
where
    F: Fn(String, bool) -> Fut + Send + Sync,
    Fut: Future<Output = Result<String, ServiceAuthError>> + 'static,
{
    fn resolve_signing_key<'a>(
        &'a self,
        iss: &'a str,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<String, ServiceAuthError>> {
        Box::pin(self(iss.to_owned(), force_refresh))
    }
}

/// The verification method for an issuer: `#atproto_label` for a
/// `#atproto_labeler` issuer, `#atproto` otherwise (the reference PDS and
/// AppView convention).
#[cfg(feature = "identity")]
fn key_id_for_iss(fragment: Option<&str>) -> &'static str {
    match fragment {
        Some("atproto_labeler") => "#atproto_label",
        _ => "#atproto",
    }
}

#[cfg(feature = "identity")]
impl SigningKeyResolver for crate::identity::Directory {
    fn resolve_signing_key<'a>(
        &'a self,
        iss: &'a str,
        force_refresh: bool,
    ) -> BoxFuture<'a, Result<String, ServiceAuthError>> {
        Box::pin(async move {
            let (did, fragment) = split_iss(iss).ok_or(ServiceAuthError::BadJwtIss)?;
            if force_refresh {
                self.purge(&did).await;
            }
            let identity = self.lookup_did(&did).await.map_err(|e| {
                ServiceAuthError::key_resolution(
                    "AuthenticationRequired",
                    format!("could not resolve iss did: {e}"),
                )
            })?;
            identity
                .keys
                .get(key_id_for_iss(fragment.as_deref()))
                .map(|key| key.did_key())
                .ok_or_else(|| {
                    ServiceAuthError::key_resolution(
                        "AuthenticationRequired",
                        "missing or bad key in did doc",
                    )
                })
        })
    }
}

/// Split `did` or `did#fragment`. The fragment must be non-empty and the
/// value may hold only one `#`.
fn split_iss(iss: &str) -> Option<(Did, Option<String>)> {
    let (did, fragment) = match iss.split_once('#') {
        None => (iss, None),
        Some((_, frag)) if frag.is_empty() || frag.contains('#') => return None,
        Some((did, frag)) => (did, Some(frag.to_owned())),
    };
    Some((Did::try_from(did).ok()?, fragment))
}

/// Verifies service JWTs for one service.
pub struct ServiceJwtVerifier<R> {
    audience: Option<String>,
    resolver: R,
}

impl<R: SigningKeyResolver> ServiceJwtVerifier<R> {
    /// A verifier that requires `aud == audience`. `None` skips the audience
    /// check, for callers that accept several audiences and check `aud`
    /// themselves.
    pub fn new(audience: Option<&str>, resolver: R) -> Self {
        ServiceJwtVerifier {
            audience: audience.map(str::to_owned),
            resolver,
        }
    }

    /// The required audience, if any.
    pub fn audience(&self) -> Option<&str> {
        self.audience.as_deref()
    }

    /// The key resolver.
    pub fn resolver(&self) -> &R {
        &self.resolver
    }

    /// Verify `jwt` now. `lxm`, if set, must equal the token's `lxm`.
    pub async fn verify(
        &self,
        jwt: &str,
        lxm: Option<&str>,
    ) -> Result<ServiceJwtClaims, ServiceAuthError> {
        let now = UNIX_EPOCH + Duration::from_millis(crate::platform::unix_time_millis());
        self.verify_at(jwt, lxm, now).await
    }

    /// Verify `jwt` as of `now`.
    ///
    /// Checks run in the reference order, cheapest first: shape, `typ`, `exp`,
    /// `aud`, `lxm`, `iss`, then the signature. There is no clock-skew leeway,
    /// and `iat`, `nbf` and `jti` are not checked (replay protection is the
    /// caller's job). High-S signatures are accepted.
    pub async fn verify_at(
        &self,
        jwt: &str,
        lxm: Option<&str>,
        now: SystemTime,
    ) -> Result<ServiceJwtClaims, ServiceAuthError> {
        let mut parts = jwt.split('.');
        let (Some(header_b64), Some(payload_b64), Some(sig_b64), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(ServiceAuthError::BadJwt);
        };

        let header = decode_json_object(header_b64).ok_or(ServiceAuthError::BadJwt)?;
        let alg = header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(ServiceAuthError::BadJwt)?;
        // Tokens of these types (OAuth access tokens, refresh tokens, DPoP
        // proofs) must never be accepted as service auth.
        if let Some(typ @ ("at+jwt" | "refresh+jwt" | "dpop+jwt")) =
            header.get("typ").and_then(Value::as_str)
        {
            return Err(ServiceAuthError::BadJwtType(typ.to_owned()));
        }

        let claims = decode_json_object(payload_b64).ok_or(ServiceAuthError::BadJwt)?;
        let (Some(iss), Some(aud), Some(exp)) = (
            claims.get("iss").and_then(Value::as_str),
            claims.get("aud").and_then(Value::as_str),
            claims.get("exp").and_then(Value::as_f64),
        ) else {
            return Err(ServiceAuthError::BadJwt);
        };
        let token_lxm = optional_string(&claims, "lxm")?;
        optional_string(&claims, "nonce")?;

        let now_secs = now
            .duration_since(UNIX_EPOCH)
            .map_or(0.0, |d| d.as_secs_f64());
        if now_secs > exp {
            return Err(ServiceAuthError::JwtExpired);
        }
        if let Some(audience) = &self.audience
            && aud != audience
        {
            return Err(ServiceAuthError::BadJwtAudience);
        }
        if let Some(expected) = lxm
            && token_lxm.as_deref() != Some(expected)
        {
            return Err(ServiceAuthError::BadJwtLexiconMethod {
                expected: expected.to_owned(),
                present: token_lxm.is_some(),
            });
        }
        let (did, fragment) = split_iss(iss).ok_or(ServiceAuthError::BadJwtIss)?;

        let signing_input = &jwt[..header_b64.len() + 1 + payload_b64.len()];
        // Like the reference's lenient base64url decoding, an undecodable or
        // wrongly sized signature is a mismatch, not a malformed token.
        let sig = decode_b64url(sig_b64)
            .and_then(|b| <[u8; 64]>::try_from(b).ok())
            .map(Signature::from_bytes);

        let key = self.resolver.resolve_signing_key(iss, false).await?;
        let mut checked = check_signature(&key, signing_input.as_bytes(), sig.as_ref(), alg);
        if !matches!(checked, Ok(true)) {
            // The key may have been rotated since it was cached. Unlike the
            // reference, this includes a cached key of another type than the
            // token's `alg`, so a rotation to a new curve is picked up too.
            let fresh = self.resolver.resolve_signing_key(iss, true).await?;
            if fresh != key {
                checked = check_signature(&fresh, signing_input.as_bytes(), sig.as_ref(), alg);
            }
        }
        if !checked? {
            return Err(ServiceAuthError::BadSignature);
        }

        Ok(ServiceJwtClaims {
            iss: iss.to_owned(),
            did,
            fragment,
            aud: aud.to_owned(),
            exp,
            lxm: token_lxm,
            jti: claims.get("jti").and_then(Value::as_str).map(str::to_owned),
            claims,
        })
    }
}

/// `Ok(false)` for a signature that does not verify; `Err` if the key cannot
/// check it at all.
fn check_signature(
    did_key: &str,
    msg: &[u8],
    sig: Option<&Signature>,
    alg: &str,
) -> Result<bool, ServiceAuthError> {
    let key = parse_did_key(did_key).map_err(|_| ServiceAuthError::UnverifiableSignature)?;
    if key.jwt_alg() != alg {
        return Err(ServiceAuthError::UnverifiableSignature);
    }
    Ok(sig.is_some_and(|sig| key.verify_malleable(msg, sig).is_ok()))
}

/// A claim that, if present and set, must be a string. `null` counts as
/// absent.
fn optional_string(
    claims: &Map<String, Value>,
    key: &str,
) -> Result<Option<String>, ServiceAuthError> {
    match claims.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err(ServiceAuthError::BadJwt),
    }
}

fn decode_b64url(s: &str) -> Option<Vec<u8>> {
    BASE64URL_NOPAD
        .decode(s.trim_end_matches('=').as_bytes())
        .ok()
}

fn decode_json_object(segment: &str) -> Option<Map<String, Value>> {
    match serde_json::from_slice(&decode_b64url(segment)?) {
        Ok(Value::Object(map)) => Some(map),
        _ => None,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::crypto::{K256SigningKey, P256SigningKey};

    const ISS: &str = "did:example:iss";
    const AUD: &str = "did:example:aud";

    fn at(secs: u64) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(secs)
    }

    fn now_secs() -> u64 {
        crate::platform::unix_time_millis() / 1000
    }

    /// A resolver that returns the given keys in order (the last one repeats)
    /// and records each call.
    #[derive(Clone)]
    struct Keys {
        keys: Vec<String>,
        calls: Arc<Mutex<Vec<(String, bool)>>>,
    }

    impl Keys {
        fn new(keys: &[&dyn SigningKey]) -> Self {
            Keys {
                keys: keys.iter().map(|k| k.public_key().did_key()).collect(),
                calls: Arc::default(),
            }
        }

        fn calls(&self) -> Vec<(String, bool)> {
            self.calls.lock().unwrap().clone()
        }
    }

    impl SigningKeyResolver for Keys {
        fn resolve_signing_key<'a>(
            &'a self,
            iss: &'a str,
            force_refresh: bool,
        ) -> BoxFuture<'a, Result<String, ServiceAuthError>> {
            let mut calls = self.calls.lock().unwrap();
            calls.push((iss.to_owned(), force_refresh));
            let key = self.keys[(calls.len() - 1).min(self.keys.len() - 1)].clone();
            Box::pin(async move { Ok(key) })
        }
    }

    fn verifier(keys: &Keys) -> ServiceJwtVerifier<Keys> {
        ServiceJwtVerifier::new(Some(AUD), keys.clone())
    }

    fn b64(v: &serde_json::Value) -> String {
        BASE64URL_NOPAD.encode(v.to_string().as_bytes())
    }

    /// Sign an arbitrary header and payload.
    fn sign_raw(
        header: serde_json::Value,
        payload: serde_json::Value,
        key: &dyn SigningKey,
    ) -> String {
        let input = format!("{}.{}", b64(&header), b64(&payload));
        let sig = key.sign(input.as_bytes()).unwrap();
        format!("{input}.{}", BASE64URL_NOPAD.encode(sig.as_bytes()))
    }

    fn payload(exp: u64) -> serde_json::Value {
        serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp})
    }

    fn header(key: &dyn SigningKey) -> serde_json::Value {
        serde_json::json!({"typ": "JWT", "alg": key.public_key().jwt_alg()})
    }

    async fn verify_raw(
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> Result<ServiceJwtClaims, ServiceAuthError> {
        let key = P256SigningKey::generate();
        let jwt = sign_raw(header, payload, &key);
        verifier(&Keys::new(&[&key])).verify(&jwt, None).await
    }

    /// Fixed tokens from indigo `atproto/auth/jwt_test.go`, valid at
    /// 2024-01-01T00:00:00Z. They carry no `iat`, `jti` or `lxm`.
    const INDIGO_VECTORS: [(&str, &str, u64); 3] = [
        (
            "did:key:zQ3shscXNYZQZSPwegiv7uQZZV5kzATLBRtgJhs7uRY7pfSk4",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzEwMTJ9.J_In_PQCMjygeeoIKyjybORD89ZnEy1bZTd--sdq_78qv3KCO9181ZAh-2Pl0qlXZjfUlxgIa6wiak2NtsT98g",
            1713571012,
        ),
        (
            "did:key:zQ3shqKrpHzQ5HDfhgcYMWaFcpBK3SS39wZLdTjA5GeakX8G5",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NksifQ.eyJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJleHAiOjE3MTM1NzExMzJ9.itNeYcF5oFMZIGxtnbJhE4McSniv_aR-Yk1Wj8uWk1K8YjlS2fzuJMo0-fILV3payETxn6r45f0FfpTaqY0EZQ",
            1713571132,
        ),
        (
            "did:key:zDnaeXRDKRCEUoYxi8ZJS2pDsgfxUh3pZiu3SES9nbY4DoART",
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTppc3MiLCJhdWQiOiJkaWQ6ZXhhbXBsZTphdWQiLCJleHAiOjE3MTM1NzE1NTR9.FFRLm7SGbDUp6cL0WoCs0L5oqNkjCXB963TqbgI-KxIjbiqMQATVCalcMJx17JGTjMmfVHJP6Op_V4Z0TTjqog",
            1713571554,
        ),
    ];

    fn fixed_key(did_key: &'static str) -> impl SigningKeyResolver {
        move |_iss: String, _refresh: bool| async move { Ok(did_key.to_owned()) }
    }

    #[tokio::test]
    async fn indigo_fixed_vectors() {
        let jan_2024 = at(1704067200);
        for (did_key, jwt, exp) in INDIGO_VECTORS {
            let verifier = ServiceJwtVerifier::new(Some(AUD), fixed_key(did_key));
            let claims = verifier.verify_at(jwt, None, jan_2024).await.unwrap();
            assert_eq!(claims.iss, ISS);
            assert_eq!(claims.did.as_str(), ISS);
            assert_eq!(claims.fragment, None);
            assert_eq!(claims.aud, AUD);
            assert_eq!(claims.exp, exp as f64);
            assert_eq!((claims.lxm, claims.jti), (None, None));

            // Valid through the expiry second, expired after it.
            verifier.verify_at(jwt, None, at(exp)).await.unwrap();
            assert_eq!(
                verifier.verify_at(jwt, None, at(exp + 1)).await,
                Err(ServiceAuthError::JwtExpired)
            );

            let other_aud = ServiceJwtVerifier::new(Some("did:example:other"), fixed_key(did_key));
            assert_eq!(
                other_aud.verify_at(jwt, None, jan_2024).await,
                Err(ServiceAuthError::BadJwtAudience)
            );

            let mut tampered = jwt.to_owned().into_bytes();
            let last = tampered.len() - 5;
            tampered[last] = if tampered[last] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(tampered).unwrap();
            assert_eq!(
                verifier.verify_at(&tampered, None, jan_2024).await,
                Err(ServiceAuthError::BadSignature)
            );
        }
    }

    #[tokio::test]
    async fn create_and_verify_round_trip_both_curves() {
        let p256 = P256SigningKey::generate();
        let k256 = K256SigningKey::generate();
        for key in [&p256 as &dyn SigningKey, &k256] {
            let keys = Keys::new(&[key]);
            let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), key).unwrap();
            let claims = verifier(&keys).verify(&jwt, None).await.unwrap();
            let now = now_secs() as f64;
            assert!(claims.exp > now && claims.exp <= now + 61.0);
            assert_eq!(
                claims.claims["exp"].as_u64().unwrap(),
                claims.claims["iat"].as_u64().unwrap() + 60
            );
            assert_eq!(claims.lxm, None);
            let jti = claims.jti.unwrap();
            assert_eq!(jti.len(), 32);
            assert!(
                jti.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            );
            assert_eq!(keys.calls(), [(ISS.to_owned(), false)]);

            let header: serde_json::Value = serde_json::from_slice(
                &BASE64URL_NOPAD
                    .decode(jwt.split('.').next().unwrap().as_bytes())
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(
                header,
                serde_json::json!({"typ": "JWT", "alg": key.public_key().jwt_alg()})
            );
        }
    }

    #[tokio::test]
    async fn jti_is_random() {
        let key = P256SigningKey::generate();
        let params = ServiceJwtParams::new(ISS, AUD);
        let a = create_service_jwt(&params, &key).unwrap();
        let b = create_service_jwt(&params, &key).unwrap();
        let keys = Keys::new(&[&key]);
        let (a, b) = (
            verifier(&keys).verify(&a, None).await.unwrap(),
            verifier(&keys).verify(&b, None).await.unwrap(),
        );
        assert_ne!(a.jti, b.jti);
    }

    #[tokio::test]
    async fn explicit_timestamps() {
        let key = K256SigningKey::generate();
        let mut params = ServiceJwtParams::new(ISS, AUD);
        params.iat = Some(1000);
        params.exp = Some(5000);
        let jwt = create_service_jwt(&params, &key).unwrap();
        let v = verifier(&Keys::new(&[&key]));
        let claims = v.verify_at(&jwt, None, at(4999)).await.unwrap();
        assert_eq!(claims.claims["iat"], 1000);
        assert_eq!(claims.exp, 5000.0);
        assert_eq!(
            v.verify_at(&jwt, None, at(5001)).await,
            Err(ServiceAuthError::JwtExpired)
        );
        // The default lifetime is 60 seconds from iat.
        params.exp = None;
        let jwt = create_service_jwt(&params, &key).unwrap();
        assert_eq!(v.verify_at(&jwt, None, at(1060)).await.unwrap().exp, 1060.0);
    }

    #[tokio::test]
    async fn lxm_matrix() {
        // indigo testSigningValidation: (token lxm, required lxm, ok).
        let key = P256SigningKey::generate();
        let keys = Keys::new(&[&key]);
        let cases = [
            (None, None, Ok(())),
            (
                None,
                Some("com.example.api"),
                Err(ServiceAuthError::BadJwtLexiconMethod {
                    expected: "com.example.api".into(),
                    present: false,
                }),
            ),
            (Some("com.example.api"), None, Ok(())),
            (Some("com.example.api"), Some("com.example.api"), Ok(())),
            (
                Some("com.atproto.repo.createRecord"),
                Some("com.atproto.repo.putRecord"),
                Err(ServiceAuthError::BadJwtLexiconMethod {
                    expected: "com.atproto.repo.putRecord".into(),
                    present: true,
                }),
            ),
        ];
        for (token_lxm, required, expected) in cases {
            let mut params = ServiceJwtParams::new(ISS, "did:example:aud#svc");
            params.lxm = token_lxm;
            let jwt = create_service_jwt(&params, &key).unwrap();
            let v = ServiceJwtVerifier::new(Some("did:example:aud#svc"), keys.clone());
            let got = v.verify(&jwt, required).await;
            match expected {
                Ok(()) => assert_eq!(got.unwrap().lxm.as_deref(), token_lxm),
                Err(e) => assert_eq!(got.unwrap_err(), e),
            }
        }
        assert_eq!(
            ServiceAuthError::BadJwtLexiconMethod {
                expected: "a.b.c".into(),
                present: true
            }
            .to_string(),
            "bad jwt lexicon method (\"lxm\"). must match: a.b.c"
        );
        assert_eq!(
            ServiceAuthError::BadJwtLexiconMethod {
                expected: "a.b.c".into(),
                present: false
            }
            .to_string(),
            "missing jwt lexicon method (\"lxm\"). must match: a.b.c"
        );
    }

    #[tokio::test]
    async fn audience_check_can_be_skipped() {
        let key = P256SigningKey::generate();
        let jwt =
            create_service_jwt(&ServiceJwtParams::new(ISS, "did:web:anything"), &key).unwrap();
        let v = ServiceJwtVerifier::new(None, Keys::new(&[&key]));
        assert_eq!(v.verify(&jwt, None).await.unwrap().aud, "did:web:anything");
        assert_eq!(v.audience(), None);
        // The audience comparison is exact, fragment included.
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &key).unwrap();
        let v = ServiceJwtVerifier::new(Some("did:example:aud#svc"), Keys::new(&[&key]));
        assert_eq!(
            v.verify(&jwt, None).await,
            Err(ServiceAuthError::BadJwtAudience)
        );
    }

    #[tokio::test]
    async fn refreshes_key_once_after_mismatch() {
        let stale = P256SigningKey::generate();
        let current = P256SigningKey::generate();
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &current).unwrap();

        let keys = Keys::new(&[&stale, &current]);
        verifier(&keys).verify(&jwt, None).await.unwrap();
        assert_eq!(
            keys.calls(),
            [(ISS.to_owned(), false), (ISS.to_owned(), true)]
        );

        // Still wrong after the refresh.
        let other = P256SigningKey::generate();
        let keys = Keys::new(&[&stale, &other]);
        assert_eq!(
            verifier(&keys).verify(&jwt, None).await,
            Err(ServiceAuthError::BadSignature)
        );
        assert_eq!(keys.calls().len(), 2);

        // The same key again: not checked twice.
        let keys = Keys::new(&[&stale]);
        assert_eq!(
            verifier(&keys).verify(&jwt, None).await,
            Err(ServiceAuthError::BadSignature)
        );
        assert_eq!(keys.calls().len(), 2);
    }

    #[tokio::test]
    async fn claim_failures_never_resolve_keys() {
        let key = P256SigningKey::generate();
        let keys = Keys::new(&[&key]);
        let v = verifier(&keys);
        let expired = sign_raw(header(&key), payload(1), &key);
        // exp is checked before aud.
        let expired_bad_aud = sign_raw(
            header(&key),
            serde_json::json!({"iss": ISS, "aud": "did:example:nope", "exp": 1}),
            &key,
        );
        let far = now_secs() + 600;
        // aud is checked before lxm, and lxm before iss.
        let bad_aud_and_lxm = sign_raw(
            header(&key),
            serde_json::json!({"iss": "bad", "aud": "did:example:nope", "exp": far, "lxm": "a.b.c"}),
            &key,
        );
        let bad_lxm_and_iss = sign_raw(
            header(&key),
            serde_json::json!({"iss": "bad", "aud": AUD, "exp": far, "lxm": "a.b.c"}),
            &key,
        );
        assert_eq!(
            v.verify(&expired, None).await,
            Err(ServiceAuthError::JwtExpired)
        );
        assert_eq!(
            v.verify(&expired_bad_aud, None).await,
            Err(ServiceAuthError::JwtExpired)
        );
        assert_eq!(
            v.verify(&bad_aud_and_lxm, Some("x.y.z")).await,
            Err(ServiceAuthError::BadJwtAudience)
        );
        assert!(matches!(
            v.verify(&bad_lxm_and_iss, Some("x.y.z")).await,
            Err(ServiceAuthError::BadJwtLexiconMethod { .. })
        ));
        assert_eq!(
            v.verify(&bad_lxm_and_iss, None).await,
            Err(ServiceAuthError::BadJwtIss)
        );
        assert!(keys.calls().is_empty());
    }

    #[tokio::test]
    async fn forbidden_token_types() {
        let exp = now_secs() + 60;
        for typ in ["at+jwt", "refresh+jwt", "dpop+jwt"] {
            let key = P256SigningKey::generate();
            let got = verify_raw(
                serde_json::json!({"typ": typ, "alg": "ES256"}),
                payload(exp),
            )
            .await;
            assert_eq!(got, Err(ServiceAuthError::BadJwtType(typ.into())));
            assert_eq!(
                got.unwrap_err().to_string(),
                format!("Invalid jwt type \"{typ}\"")
            );
            let _ = key;
        }
        // Like the reference, other types (and case variants) are allowed.
        for header in [
            serde_json::json!({"alg": "ES256"}),
            serde_json::json!({"typ": "JWT", "alg": "ES256"}),
            serde_json::json!({"typ": "jwt", "alg": "ES256"}),
            serde_json::json!({"typ": "AT+JWT", "alg": "ES256"}),
            serde_json::json!({"typ": 5, "alg": "ES256", "kid": "x"}),
        ] {
            verify_raw(header.clone(), payload(exp))
                .await
                .unwrap_or_else(|e| panic!("{header}: {e}"));
        }
    }

    #[tokio::test]
    async fn malformed_tokens_are_bad_jwt() {
        let exp = now_secs() + 60;
        let key = P256SigningKey::generate();
        let v = verifier(&Keys::new(&[&key]));
        let good = sign_raw(header(&key), payload(exp), &key);
        let parts: Vec<&str> = good.split('.').collect();
        let not_json = BASE64URL_NOPAD.encode(b"{nope");
        for jwt in [
            String::new(),
            "abc".into(),
            "a.b".into(),
            format!("{good}.extra"),
            format!("!!!.{}.{}", parts[1], parts[2]),
            format!("{not_json}.{}.{}", parts[1], parts[2]),
            format!("{}.{not_json}.{}", parts[0], parts[2]),
            format!("{}.{}.{}", b64(&serde_json::json!([1])), parts[1], parts[2]),
            format!(
                "{}.{}.{}",
                b64(&serde_json::json!("ES256")),
                parts[1],
                parts[2]
            ),
        ] {
            assert_eq!(
                v.verify(&jwt, None).await,
                Err(ServiceAuthError::BadJwt),
                "{jwt}"
            );
        }

        let headers = [
            serde_json::json!({"typ": "JWT"}),
            serde_json::json!({"alg": 256}),
        ];
        for header in headers {
            assert_eq!(
                verify_raw(header, payload(exp)).await,
                Err(ServiceAuthError::BadJwt)
            );
        }
        let payloads = [
            serde_json::json!({"aud": AUD, "exp": exp}),
            serde_json::json!({"iss": ISS, "exp": exp}),
            serde_json::json!({"iss": ISS, "aud": AUD}),
            serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp.to_string()}),
            // golang-jwt's default single-element array audience.
            serde_json::json!({"iss": ISS, "aud": [AUD], "exp": exp}),
            serde_json::json!({"iss": 1, "aud": AUD, "exp": exp}),
            serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp, "lxm": 1}),
            serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp, "nonce": true}),
            serde_json::json!([ISS, AUD, exp]),
        ];
        for p in payloads {
            assert_eq!(
                verify_raw(serde_json::json!({"alg": "ES256"}), p.clone()).await,
                Err(ServiceAuthError::BadJwt),
                "{p}"
            );
        }
        // Null optional claims are treated as absent.
        verify_raw(
            serde_json::json!({"alg": "ES256"}),
            serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp, "lxm": null, "nonce": null}),
        )
        .await
        .unwrap();
        // Fractional expiry is allowed.
        verify_raw(
            serde_json::json!({"alg": "ES256"}),
            serde_json::json!({"iss": ISS, "aud": AUD, "exp": exp as f64 + 0.5}),
        )
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn issuer_forms() {
        let exp = now_secs() + 60;
        for iss in [
            "",
            "notadid",
            "did:plc:abc#",
            "did:plc:abc#a#b",
            "#atproto",
            "did:plc:ab c",
        ] {
            let got = verify_raw(
                serde_json::json!({"alg": "ES256"}),
                serde_json::json!({"iss": iss, "aud": AUD, "exp": exp}),
            )
            .await;
            assert_eq!(got, Err(ServiceAuthError::BadJwtIss), "{iss:?}");
        }

        let key = K256SigningKey::generate();
        let keys = Keys::new(&[&key]);
        let iss = "did:plc:labeler#atproto_labeler";
        let jwt = create_service_jwt(&ServiceJwtParams::new(iss, AUD), &key).unwrap();
        let claims = verifier(&keys).verify(&jwt, None).await.unwrap();
        assert_eq!(claims.iss, iss);
        assert_eq!(claims.did.as_str(), "did:plc:labeler");
        assert_eq!(claims.fragment.as_deref(), Some("atproto_labeler"));
        // The resolver sees the full issuer.
        assert_eq!(keys.calls(), [(iss.to_owned(), false)]);
    }

    #[tokio::test]
    async fn alg_must_match_key_type() {
        let exp = now_secs() + 60;
        let p256 = P256SigningKey::generate();
        let k256 = K256SigningKey::generate();
        for (alg, signer) in [
            ("ES256K", &p256 as &dyn SigningKey),
            ("ES256", &k256),
            ("none", &p256),
            ("HS256", &p256),
        ] {
            let keys = Keys::new(&[signer]);
            let jwt = sign_raw(serde_json::json!({"alg": alg}), payload(exp), signer);
            assert_eq!(
                verifier(&keys).verify(&jwt, None).await,
                Err(ServiceAuthError::UnverifiableSignature),
                "{alg}"
            );
            // A refresh is tried in case the key was rotated.
            assert_eq!(keys.calls().len(), 2);
        }

        let resolver = |_: String, _: bool| async { Ok("did:key:zNotAKey".to_owned()) };
        let jwt = sign_raw(header(&p256), payload(exp), &p256);
        let v = ServiceJwtVerifier::new(Some(AUD), resolver);
        assert_eq!(
            v.verify(&jwt, None).await,
            Err(ServiceAuthError::UnverifiableSignature)
        );
    }

    #[tokio::test]
    async fn rejects_a_compact_tagged_did_key() {
        // Regression: a did:key whose SEC1 tag was 0x05 ("compact") parsed as
        // the even-y point, so it verified that key's tokens.
        let mut even = Vec::new();
        for seed in 1..=8 {
            let keys: [Box<dyn SigningKey>; 2] = [
                Box::new(P256SigningKey::from_bytes(&[seed; 32]).unwrap()),
                Box::new(K256SigningKey::from_bytes(&[seed; 32]).unwrap()),
            ];
            for key in keys {
                let public = key.public_key();
                let mut multikey = bs58::decode(&public.multibase()[1..]).into_vec().unwrap();
                if multikey[2] == 0x02 {
                    even.push(public.jwt_alg());
                }
                multikey[2] = 0x05;
                let compact = Keys {
                    keys: vec![format!("did:key:z{}", bs58::encode(multikey).into_string())],
                    calls: Arc::default(),
                };
                let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &*key).unwrap();
                assert_eq!(
                    verifier(&compact).verify(&jwt, None).await,
                    Err(ServiceAuthError::UnverifiableSignature)
                );
                let canonical = Keys::new(&[&*key]);
                verifier(&canonical).verify(&jwt, None).await.unwrap();
            }
        }
        even.sort();
        even.dedup();
        assert_eq!(even, ["ES256", "ES256K"]);
    }

    #[tokio::test]
    async fn refreshes_a_cached_key_of_another_type() {
        // Regression: a key rotated to another curve was never refreshed,
        // because the cached key could not check the token's alg at all.
        let old = K256SigningKey::generate();
        let new = P256SigningKey::generate();
        let keys = Keys::new(&[&old, &new]);
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &new).unwrap();
        let claims = verifier(&keys).verify(&jwt, None).await.unwrap();
        assert_eq!(claims.iss, ISS);
        assert_eq!(
            keys.calls(),
            [(ISS.to_owned(), false), (ISS.to_owned(), true)]
        );

        // A fresh key that still cannot check it is unverifiable.
        let keys = Keys::new(&[&old, &old]);
        assert_eq!(
            verifier(&keys).verify(&jwt, None).await,
            Err(ServiceAuthError::UnverifiableSignature)
        );
    }

    #[tokio::test]
    async fn accepts_high_s_signatures() {
        let key = P256SigningKey::generate();
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &key).unwrap();
        let (input, sig) = jwt.rsplit_once('.').unwrap();
        let low =
            p256::ecdsa::Signature::from_slice(&BASE64URL_NOPAD.decode(sig.as_bytes()).unwrap())
                .unwrap();
        let high = p256::ecdsa::Signature::from_scalars(low.r().to_bytes(), (-*low.s()).to_bytes())
            .unwrap();
        let high_jwt = format!("{input}.{}", BASE64URL_NOPAD.encode(&high.to_bytes()));
        assert_ne!(high_jwt, jwt);
        verifier(&Keys::new(&[&key]))
            .verify(&high_jwt, None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn bad_signature_encodings_are_mismatches() {
        let key = P256SigningKey::generate();
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &key).unwrap();
        let (input, sig) = jwt.rsplit_once('.').unwrap();
        for bad in [
            "",
            "!!!!",
            "AAAA",
            &sig[..sig.len() - 4],
            &format!("{sig}AAAA"),
        ] {
            let keys = Keys::new(&[&key]);
            assert_eq!(
                verifier(&keys)
                    .verify(&format!("{input}.{bad}"), None)
                    .await,
                Err(ServiceAuthError::BadSignature),
                "{bad:?}"
            );
            assert_eq!(keys.calls().len(), 2);
        }
        // Base64url padding is tolerated.
        verifier(&Keys::new(&[&key]))
            .verify(&format!("{input}.{sig}=="), None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn resolver_errors_propagate() {
        let key = P256SigningKey::generate();
        let jwt = create_service_jwt(&ServiceJwtParams::new(ISS, AUD), &key).unwrap();
        let resolver = |_: String, _: bool| async {
            Err(ServiceAuthError::key_resolution(
                "UntrustedIss",
                "Untrusted issuer",
            ))
        };
        let err = ServiceJwtVerifier::new(Some(AUD), resolver)
            .verify(&jwt, None)
            .await
            .unwrap_err();
        assert_eq!(err.error_name(), "UntrustedIss");
        assert_eq!(err.to_string(), "Untrusted issuer");
    }

    #[test]
    fn error_names() {
        let cases = [
            (ServiceAuthError::BadJwt, "BadJwt", "poorly formatted jwt"),
            (ServiceAuthError::JwtExpired, "JwtExpired", "jwt expired"),
            (
                ServiceAuthError::BadJwtAudience,
                "BadJwtAudience",
                "jwt audience does not match service did",
            ),
            (
                ServiceAuthError::BadJwtIss,
                "BadJwtIss",
                "jwt iss is not a valid did",
            ),
            (
                ServiceAuthError::UnverifiableSignature,
                "BadJwtSignature",
                "could not verify jwt signature",
            ),
            (
                ServiceAuthError::BadSignature,
                "BadJwtSignature",
                "jwt signature does not match jwt issuer",
            ),
        ];
        for (err, name, message) in cases {
            assert_eq!(err.error_name(), name);
            assert_eq!(err.to_string(), message);
        }
    }

    #[cfg(feature = "identity")]
    #[test]
    fn labeler_issuers_use_the_label_key() {
        assert_eq!(key_id_for_iss(None), "#atproto");
        assert_eq!(key_id_for_iss(Some("atproto_labeler")), "#atproto_label");
        assert_eq!(key_id_for_iss(Some("atproto")), "#atproto");
        assert_eq!(key_id_for_iss(Some("bsky_appview")), "#atproto");
    }

    #[test]
    fn split_iss_forms() {
        assert_eq!(split_iss("did:web:a.com").unwrap().1, None);
        assert_eq!(
            split_iss("did:web:a.com#svc").unwrap().1.as_deref(),
            Some("svc")
        );
        assert!(split_iss("did:web:a.com#").is_none());
        assert!(split_iss("did:web:a.com#a#b").is_none());
        assert!(split_iss("web:a.com").is_none());
    }

    #[test]
    fn verifying_keys_report_jwt_alg() {
        assert_eq!(P256SigningKey::generate().public_key().jwt_alg(), "ES256");
        assert_eq!(K256SigningKey::generate().public_key().jwt_alg(), "ES256K");
    }
}
