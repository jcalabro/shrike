# shrike-oauth Design

AT Protocol OAuth 2.0 client implementing Authorization Code with PKCE,
DPoP (Demonstration of Proof-of-Possession), and PAR (Pushed Authorization
Request). Supports both public and confidential clients.

Reference implementations: TypeScript (`@atproto/oauth-client` in
`bluesky-social/atproto`) and Go (`atmos/oauth`).

## Crate Structure

```
crates/shrike-oauth/
├── Cargo.toml
└── src/
    ├── lib.rs           — public exports, OAuthError type
    ├── client.rs        — OAuthClient: authorize(), callback(), sign_out()
    ├── dpop.rs          — DPoP proof JWT creation, nonce store
    ├── pkce.rs          — PKCE code verifier/challenge generation
    ├── metadata.rs      — AS and protected resource metadata types + fetching
    ├── token.rs         — TokenSet, token exchange, token refresh
    ├── session.rs       — Session, AuthState, SessionStore/StateStore traits
    ├── client_auth.rs   — ClientAuth trait, PublicClientAuth, ConfidentialClientAuth
    ├── transport.rs     — DPoP HTTP transport with automatic refresh + nonce retry
    └── jwk.rs           — P-256 JWK encoding for DPoP proof headers
```

### Dependencies

```toml
[dependencies]
shrike-syntax = { path = "../shrike-syntax" }
shrike-crypto = { path = "../shrike-crypto" }
shrike-identity = { path = "../shrike-identity" }
shrike-xrpc = { path = "../shrike-xrpc" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
reqwest.workspace = true
tokio.workspace = true
sha2.workspace = true
data-encoding.workspace = true
rand.workspace = true
url.workspace = true
```

No JWT crate — JWTs are built manually (base64url header + payload +
ES256 signature). No new crypto dependencies beyond what shrike-crypto
already provides.

## OAuth Flow

### Phase 0: Service Discovery

1. Resolve user's handle/DID to a PDS endpoint via `shrike-identity`
2. Fetch protected resource metadata: `GET {pds}/.well-known/oauth-protected-resource`
3. Extract the authorization server URL from `authorization_servers[0]`
4. Fetch AS metadata: `GET {as}/.well-known/oauth-authorization-server`
5. Validate AS metadata (issuer match, required fields, ATProto requirements)

No HTTP redirects followed on metadata fetches (SSRF prevention).

### Phase 1: Authorization (PAR + Redirect)

1. Generate P-256 DPoP key pair
2. Generate PKCE challenge: `verifier` = base64url(32 random bytes),
   `challenge` = base64url(SHA-256(verifier)), `method` = "S256"
3. Generate state: base64url(16 random bytes)
4. Store `AuthState` (issuer, DPoP key, PKCE verifier, redirect URI, endpoints)
5. Send Pushed Authorization Request to PAR endpoint with DPoP proof
6. Handle `use_dpop_nonce` retry if needed
7. Build authorization URL: `{auth_endpoint}?client_id={id}&request_uri={uri}`
8. Return URL + state to caller

### Phase 2: Callback (Token Exchange)

1. Validate and consume state (one-time use, deleted immediately)
2. Validate `iss` parameter matches expected issuer (RFC 9207)
3. Exchange authorization code for tokens at token endpoint:
   - `grant_type=authorization_code`
   - `code`, `code_verifier`, `redirect_uri`
   - Client authentication (public or confidential)
   - DPoP proof with nonce retry
4. Validate token response: `sub` present, `atproto` in scope, token type is `DPoP`
5. Verify issuer: resolve `sub` DID → PDS → protected resource metadata → AS
   matches expected issuer
6. Store session (DPoP key + token set)
7. Return session

### Phase 3: Authenticated Requests

`authenticated_client(did)` returns an `xrpc::Client` with a DPoP transport
that automatically:
- Adds `Authorization: DPoP {access_token}` header
- Adds `DPoP: {proof_jwt}` header with `ath` claim
- Caches and updates nonces per origin
- Refreshes stale tokens (with process-local mutex)
- Retries on `use_dpop_nonce` errors

### Phase 4: Token Refresh

Triggered when access token is within 10-40 seconds of expiry (jittered).

1. Verify issuer still valid (resolve DID → PDS → AS chain)
2. Send refresh request with DPoP proof
3. Validate response (sub matches, atproto scope present)
4. Update session in store

Process-local mutex prevents concurrent refresh of single-use tokens.
The AS handles multi-server races with a short grace period on refresh
tokens. Documented as a known property for multi-server deployments.

### Phase 5: Sign Out

1. Revoke token at revocation endpoint (best-effort, errors ignored)
2. Delete session from store

## DPoP Proof Construction

JWT with ES256 signature over P-256 DPoP key.

**Header:**
```json
{
  "alg": "ES256",
  "typ": "dpop+jwt",
  "jwk": {"kty": "EC", "crv": "P-256", "x": "...", "y": "..."}
}
```

**Payload:**
```json
{
  "jti": "<base64url(16 random bytes)>",
  "htm": "POST",
  "htu": "https://server/path",
  "iat": 1234567890,
  "nonce": "<server-provided>",
  "ath": "<base64url(SHA-256(access_token))>"
}
```

- `nonce`: omitted if not provided by server
- `ath`: omitted for token endpoint requests, included for resource requests
- `htu`: normalized (no query string, no fragment)
- JWT encoding: `base64url(header).base64url(payload).base64url(signature)`

Nonces stored per-origin in a `NonceStore` (thread-safe `HashMap`).

## JWK Encoding

P-256 public keys encoded as JWK for the DPoP `jwk` header:
- Decompress 33-byte SEC1 compressed point to uncompressed (65 bytes: 0x04 || X || Y)
- Extract 32-byte X and Y coordinates
- Base64url-encode each
- Output: `{"kty":"EC","crv":"P-256","x":"...","y":"..."}`

Requires `p256` crate's point decompression (already a transitive dependency).

## PKCE

- Verifier: base64url(32 cryptographically random bytes) = 43 characters
- Challenge: base64url(SHA-256(verifier))
- Method: always "S256"

## Client Authentication

### Public Client (`token_endpoint_auth_method: "none"`)

Adds `client_id` to form parameters. No signing.

### Confidential Client (`token_endpoint_auth_method: "private_key_jwt"`)

Adds to form parameters:
- `client_id`
- `client_assertion_type`: `urn:ietf:params:oauth:client-assertion-type:jwt-bearer`
- `client_assertion`: signed JWT

**Client assertion JWT:**
```
Header: {"alg": "ES256", "kid": "<key-id>"}
Payload: {
  "iss": "<client_id>",
  "sub": "<client_id>",
  "aud": "<issuer>",
  "jti": "<random>",
  "iat": <now>,
  "exp": <now + 60>
}
```

Signed with the client's P-256 signing key (separate from the DPoP key).

## Metadata Types

### Protected Resource Metadata (RFC 9728)

Endpoint: `{pds}/.well-known/oauth-protected-resource`

```json
{
  "resource": "https://pds.example.com",
  "authorization_servers": ["https://auth.example.com"]
}
```

Validation: `resource` matches PDS origin, at least one AS listed.

### Authorization Server Metadata (RFC 8414)

Endpoint: `{issuer}/.well-known/oauth-authorization-server`

Required fields validated:
- `issuer` matches requested origin
- `authorization_endpoint` present
- `token_endpoint` present
- `pushed_authorization_request_endpoint` present
- `require_pushed_authorization_requests: true`
- `client_id_metadata_document_supported: true`
- `dpop_signing_alg_values_supported` includes "ES256"

## Storage Traits

```rust
#[async_trait]
pub trait SessionStore: Send + Sync {
    async fn get(&self, did: &str) -> Result<Option<Session>, OAuthError>;
    async fn set(&self, did: &str, session: &Session) -> Result<(), OAuthError>;
    async fn delete(&self, did: &str) -> Result<(), OAuthError>;
}

#[async_trait]
pub trait StateStore: Send + Sync {
    async fn get(&self, state: &str) -> Result<Option<AuthState>, OAuthError>;
    async fn set(&self, state: &str, data: &AuthState) -> Result<(), OAuthError>;
    async fn delete(&self, state: &str) -> Result<(), OAuthError>;
}
```

`Session` and `AuthState` implement `Serialize`/`Deserialize` for caller
persistence. P-256 private keys serialize as base64url of the 32-byte
scalar.

Provided implementations: `MemorySessionStore`, `MemoryStateStore`
(in-memory, tokio `RwLock`, for testing and CLI tools).

## Security Properties

**Issuer verification:** After token exchange, resolve `sub` DID → PDS
→ protected resource metadata → verify AS matches expected issuer. If
mismatch, revoke token and reject session. Prevents account hijacking.

**State parameter:** 16 random bytes, one-time use (deleted on callback),
prevents CSRF and replay.

**Issuer parameter (RFC 9207):** Callback `iss` verified against expected
issuer. Prevents mix-up attacks.

**No redirects on metadata:** Metadata fetched with redirect policy set to
error. Prevents SSRF.

**DPoP nonce:** Per-origin, updated from server responses, included in
proofs. Automatic retry on `use_dpop_nonce`. Prevents replay.

**Refresh mutex:** Process-local mutex prevents concurrent refresh of
single-use tokens. AS handles multi-server races with grace period.

**Token binding:** Every request includes DPoP proof bound to the session
key. Access tokens cannot be used without the corresponding private key.

## Public API

```rust
// Configure
let client = OAuthClient::new(OAuthClientConfig {
    metadata: ClientMetadata { client_id, redirect_uris, scope, .. },
    session_store: Box::new(MemorySessionStore::new()),
    state_store: Box::new(MemoryStateStore::new()),
    signing_key: None, // Some(key) for confidential clients
});

// Start auth flow
let result = client.authorize(AuthorizeOptions {
    input: "alice.bsky.social",
    redirect_uri: "https://app.example/callback",
    ..Default::default()
}).await?;
// result.url → redirect user, result.state → pass to callback

// Handle callback
let session = client.callback(CallbackParams {
    code: "...", state: "...", iss: Some("..."),
}).await?;

// Make authenticated requests
let xrpc = client.authenticated_client("did:plc:alice").await?;

// Sign out
client.sign_out("did:plc:alice").await?;
```

## Testing Strategy

### Unit tests (per module)

- `dpop`: valid JWT structure, correct claims, nonce inclusion, ath
  computation, signature verifiable
- `pkce`: verifier length, challenge is SHA-256 of verifier, roundtrip
- `jwk`: correct x/y coordinates from P-256 key
- `metadata`: parse real AS metadata, reject missing fields, reject
  issuer mismatch
- `token`: parse token response, reject missing sub, reject missing
  atproto scope
- `client_auth`: public adds only client_id, confidential produces
  valid JWT assertion
- `session`: memory stores get/set/delete, one-time state consumption

### Integration tests

Full flow with mock HTTP server (axum):
- Mock metadata, PAR, token, and resource endpoints
- Complete authorize → callback → authenticated request → refresh → sign out
- Verify DPoP proofs on every request
- Verify PKCE verifier matches challenge
- Verify nonce retry works

### Security tests

- State replay rejected
- Issuer mismatch rejected
- Missing issuer parameter rejected
- Wrong sub after refresh rejected and revoked
- Metadata redirect rejected
- Tampered DPoP proof fails

### Property tests

- PKCE: any verifier → SHA-256 roundtrips
- DPoP: any key + params → parseable JWT with valid signature

### Fuzz targets

- `fuzz_parse_as_metadata`: arbitrary bytes → metadata parsing, no panics
- `fuzz_parse_token_response`: arbitrary bytes → token parsing, no panics
- `fuzz_dpop_proof_roundtrip`: random params → proof creation, no panics,
  output parseable

## Configuration

Only P-256 for DPoP keys (matching atmos, sufficient for all real AS
deployments). K-256 support can be added later if needed.

Both public and confidential client authentication supported from the start.
