# shrike — AT Protocol Library for Rust

**Date:** 2026-04-04
**Status:** Draft
**Inspired by:** [atmos](https://github.com/jcalabro/atmos) (Go)

## Goals

- Extremely robust and well tested (fuzz testing, integration tests, property tests)
- Extremely high performance — pursue every last drop
- Feature rich and easy to use
- Minimal dependencies and fast compile times
- Idiomatic Rust — not a Go port

## Key Decisions

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Crate structure | Workspace of many small crates | Best compile times, independent publishability, minimal rebuilds |
| Async runtime | tokio (networking crates only) | De facto standard, best library ecosystem. Core crates stay sync. |
| Error handling | `thiserror` | Strongly typed, pattern-matchable, zero runtime cost |
| JSON serialization | `serde` | Ecosystem standard, near-zero cost |
| CBOR serialization | Hand-rolled DRISL codec | DASL's deterministic CBOR profile has strict rules that generic crates don't enforce |
| HTTP client | `reqwest` | Tokio-native, connection pooling, TLS, retry support |
| WebSocket | `tokio-tungstenite` | Mature, full RFC 6455, pairs with tokio |
| Crypto | RustCrypto (`p256`, `k256`) | Pure Rust, no C deps, both curves from same ecosystem |
| MSRV | N-2 stable | Support current stable and two previous releases |

## Workspace Structure

```
shrike/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── shrike/             # Facade crate — re-exports everything
│   ├── shrike-syntax/           # DID, Handle, NSID, AT-URI, TID, Datetime, RecordKey, Language
│   ├── shrike-cbor/             # DRISL codec + CID
│   ├── shrike-crypto/           # P-256 & K-256 ECDSA signing, did:key encoding
│   ├── shrike-mst/              # Merkle Search Tree
│   ├── shrike-repo/             # Repository operations (CRUD, signed commits)
│   ├── shrike-car/              # CAR v1 file I/O
│   ├── shrike-lexicon/          # Lexicon schema parsing + validation
│   ├── shrike-xrpc/             # XRPC HTTP client (reqwest + tokio)
│   ├── shrike-xrpc-server/      # XRPC HTTP server framework (axum)
│   ├── shrike-identity/         # DID resolution, handle verification, PLC client
│   ├── shrike-streaming/        # Firehose, label streams, Jetstream consumer
│   ├── shrike-sync/             # Repo sync & commit verification
│   ├── shrike-backfill/         # Concurrent repo downloader
│   ├── shrike-labeling/         # Label creation & verification
│   └── shrike-api/              # Generated types from Lexicon schemas
├── tools/
│   └── lexgen/             # Code generator binary (Lexicon JSON → Rust)
├── docs/
└── testdata/
```

## Dependency Graph

Each crate only depends on crates listed above it:

```
shrike-syntax          (no internal deps)
shrike-cbor            → shrike-syntax
shrike-crypto          → shrike-cbor
shrike-mst             → shrike-cbor
shrike-repo            → shrike-syntax, shrike-cbor, shrike-crypto, shrike-mst
shrike-car             → shrike-cbor
shrike-lexicon         → shrike-syntax
shrike-xrpc            → shrike-syntax, shrike-cbor (+ reqwest, tokio)
shrike-xrpc-server     → shrike-syntax, shrike-cbor (+ tokio, axum)
shrike-identity        → shrike-syntax, shrike-crypto, shrike-xrpc
shrike-streaming       → shrike-syntax, shrike-cbor (+ tokio, tokio-tungstenite)
shrike-sync            → shrike-syntax, shrike-cbor, shrike-mst, shrike-repo, shrike-car, shrike-identity, shrike-xrpc
shrike-backfill        → shrike-sync, shrike-xrpc
shrike-labeling        → shrike-syntax, shrike-cbor, shrike-crypto
shrike-api             → shrike-syntax, shrike-cbor, shrike-xrpc (generated)
shrike                 → re-exports all of the above
```

## Crate Designs

### shrike-syntax — Core Types

Zero external dependencies beyond `thiserror` and `serde`. All types are validated on construction and cheap to clone.

**Types:**

| Type | Representation | Key behavior |
|------|---------------|--------------|
| `Did` | `String` newtype | `TryFrom<&str>`, `Display`, fast-path for `did:plc:` (always 32 chars) |
| `Handle` | `String` newtype | `TryFrom<&str>`, RFC 1035 validation, normalized to lowercase |
| `Nsid` | `String` newtype | `TryFrom<&str>`, authority/name extraction |
| `AtUri` | `String` newtype | `TryFrom<&str>`, accessors for authority/collection/rkey |
| `Tid` | `u64` newtype | Microsecond timestamp + 10-bit clock ID, `Display` as 13-char base32-sort |
| `TidClock` | Atomic counter | `TidClock::next() -> Tid`, monotonic, thread-safe via `AtomicU64` |
| `Datetime` | `String` newtype | RFC 3339 subset validation, strict and lenient parse modes |
| `RecordKey` | `String` newtype | Validated per AT Protocol record key rules |
| `Language` | `String` newtype | BCP-47 language tag |
| `AtIdentifier` | `enum { Did(Did), Handle(Handle) }` | For APIs that accept either |

**Design patterns:**

- **Newtype pattern** — `pub struct Did(String)` with private inner field. Construction only through `TryFrom` or `parse()`. Guarantees validity at the type level.
- **`TidClock` uses `AtomicU64`** — Lock-free monotonic TID generation.
- **`serde::Serialize`/`Deserialize`** on all types, using validated string representation. Deserialization goes through validation.
- **`Borrow<str>`** implemented so types work as `HashMap` keys with `&str` lookups.
- **`Clone`, `Eq`, `Ord`, `Hash`** on all types.

**Error type:**

```rust
#[derive(Debug, thiserror::Error)]
pub enum SyntaxError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("invalid handle: {0}")]
    InvalidHandle(String),
    // ... one variant per type
}
```

### shrike-cbor — DRISL Codec & CID

Hand-rolled implementation of the DRISL serialization format (DASL's deterministic CBOR profile, built on CBOR/c-42). Depends on `shrike-syntax`, `sha2`, `unsigned-varint`, `multibase`.

**DRISL rules (what we enforce):**

| Type | Encoding rule |
|------|--------------|
| Integer | Minimal-length encoding. `int` for -2^64..2^64-1, `bigint` (tags 2/3) beyond that range |
| Float | Always 64-bit IEEE 754. -0.0 allowed. No NaN, no Infinity |
| Text string | UTF-8, definite-length only |
| Byte string | Definite-length only |
| Array | Definite-length only |
| Map | String keys only, sorted by bytewise lexicographic order of encoded key, no duplicates |
| Bool | `true` / `false` |
| Null | Allowed |
| Tag 42 | CID links — bytestring with 0x00 prefix + CID bytes. Only permitted tag |

**Rejected constructs:** All tags except 42, all simple values except true/false/null, indefinite-length anything, 16-bit and 32-bit floats, NaN/Infinity/-Infinity, non-string map keys, duplicate map keys, non-minimal integer encoding, bigints with leading zero bytes, CBOR sequences/streaming.

**Core types:**

```rust
/// Stack-allocated CID. 36 bytes: 4-byte prefix + 32-byte SHA-256.
pub struct Cid {
    codec: Codec,
    hash: [u8; 32],
}

pub enum Codec {
    Drisl,  // 0x71
    Raw,    // 0x55
}

/// Decoded DRISL value — borrows from input for text/bytes
pub enum Value<'a> {
    Unsigned(u64),
    Signed(i64),
    BigUnsigned(Vec<u8>),
    BigSigned(Vec<u8>),
    Float(f64),
    Bool(bool),
    Null,
    Text(&'a str),
    Bytes(&'a [u8]),
    Cid(Cid),
    Array(Vec<Value<'a>>),
    Map(Vec<(&'a str, Value<'a>)>),
}
```

**Key APIs:**

- `Encoder<W: Write>` — streaming writer with `encode_*` methods
- `Decoder<'a>` — strict parser, rejects non-canonical input, zero-copy for text/bytes
- `compute_cid(codec, data) -> Cid` — SHA-256 hash + CID construction
- `Cid::Display` — base32lower multibase (`b` prefix), `FromStr` for parsing
- `cbor_key!("fieldName")` — compile-time macro for pre-computed DRISL key bytes

**Performance:**

- `Cid` is stack-allocated (no heap)
- `Value` borrows from input buffer (zero-copy decode)
- Pre-computed key bytes eliminate allocation in generated code
- Inline varint encoding

### shrike-crypto — Signing & Verification

Depends on `shrike-cbor`, `p256`, `k256`.

**Traits:**

```rust
pub trait SigningKey: Send + Sync {
    fn public_key(&self) -> &dyn VerifyingKey;
    fn sign(&self, content: &[u8]) -> Result<Signature>;
}

pub trait VerifyingKey: Send + Sync {
    fn to_bytes(&self) -> [u8; 33];  // SEC1 compressed
    fn verify(&self, content: &[u8], sig: &Signature) -> Result<()>;
    fn did_key(&self) -> String;      // did:key:z...
    fn multibase(&self) -> String;    // z-prefixed base58btc
}

/// 64-byte compact signature [R || S], always low-S normalized
pub struct Signature([u8; 64]);
```

**Concrete types:**

| Type | Curve | Usage |
|------|-------|-------|
| `P256SigningKey` / `P256VerifyingKey` | NIST P-256 | Primary AT Protocol signing, repo commits |
| `K256SigningKey` / `K256VerifyingKey` | secp256k1 | Some `did:key` encodings |

**Design:**

- Trait-based for generic code, monomorphizable when curve is known
- Low-S normalization on sign, strict on verify
- `sign()` SHA-256 hashes internally — callers never handle raw digests
- `Signature` is a fixed 64-byte stack value
- `parse_did_key(s: &str) -> Box<dyn VerifyingKey>` for parsing `did:key:` strings

### shrike-mst — Merkle Search Tree

Depends on `shrike-cbor`.

**Core types:**

```rust
pub trait BlockStore: Send + Sync {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>>;
    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<()>;
    fn has_block(&self, cid: &Cid) -> Result<bool>;
}

pub struct MemBlockStore { /* HashMap<Cid, Vec<u8>> */ }

pub struct Tree<S: BlockStore> {
    store: S,
    root: Option<Node>,
}
```

**Operations:**

```rust
impl<S: BlockStore> Tree<S> {
    pub fn new(store: S) -> Self;
    pub fn load(store: S, root: Cid) -> Self;        // Lazy
    pub fn load_all(&mut self) -> Result<()>;          // Eager
    pub fn get(&self, key: &str) -> Result<Option<Cid>>;
    pub fn insert(&mut self, key: String, cid: Cid) -> Result<()>;
    pub fn remove(&mut self, key: &str) -> Result<Option<Cid>>;
    pub fn root_cid(&mut self) -> Result<Cid>;
    pub fn entries(&self) -> Result<impl Iterator<Item = (&str, &Cid)>>;
    pub fn diff(left: &Tree<S>, right: &Tree<S>) -> Result<Diff>;
}

pub struct Diff {
    pub added: Vec<(String, Cid)>,
    pub updated: Vec<(String, Cid, Cid)>,
    pub removed: Vec<(String, Cid)>,
}
```

**Design:**

- Generic over `BlockStore` — monomorphized for performance
- Lazy-load by default, nodes fetched on access
- Cached CIDs on nodes, invalidated on mutation
- Key height derived from SHA-256 hash of key (deterministic structure)
- Not thread-safe — callers synchronize externally
- Diff short-circuits when subtree CIDs match

### shrike-repo — Repository Operations

Depends on `shrike-syntax`, `shrike-cbor`, `shrike-crypto`, `shrike-mst`.

**Core types:**

```rust
pub struct Repo<S: BlockStore> {
    did: Did,
    clock: TidClock,
    store: S,
    tree: Tree<S>,
}

pub struct Commit {
    pub did: Did,
    pub version: u32,       // 3
    pub rev: Tid,
    pub prev: Option<Cid>,
    pub data: Cid,           // MST root
    pub sig: Signature,
}

pub enum Mutation {
    Create { collection: Nsid, rkey: RecordKey, cid: Cid },
    Update { collection: Nsid, rkey: RecordKey, cid: Cid },
    Delete { collection: Nsid, rkey: RecordKey },
}
```

**Operations:**

```rust
impl<S: BlockStore> Repo<S> {
    pub fn new(did: Did, store: S) -> Self;
    pub fn load(did: Did, store: S, commit: Cid) -> Result<Self>;
    pub fn get(&self, collection: &Nsid, rkey: &RecordKey) -> Result<Option<(Cid, Vec<u8>)>>;
    pub fn create(&mut self, collection: &Nsid, rkey: &RecordKey, record: &[u8]) -> Result<Cid>;
    pub fn update(&mut self, collection: &Nsid, rkey: &RecordKey, record: &[u8]) -> Result<Cid>;
    pub fn delete(&mut self, collection: &Nsid, rkey: &RecordKey) -> Result<()>;
    pub fn commit(&mut self, key: &dyn SigningKey) -> Result<Commit>;
    pub fn list(&self, collection: &Nsid) -> Result<Vec<(RecordKey, Cid)>>;
}
```

**Design:**

- MST keys are `{collection}/{rkey}` — repo layer handles concatenation
- Records are opaque DRISL bytes — higher layers give them meaning
- `commit()` finalizes pending mutations, signs, stores in block store
- Pre-computed DRISL keys for `Commit` field serialization
- `Commit::verify(&self, key: &dyn VerifyingKey) -> Result<()>` for signature verification

### shrike-car — CAR v1 File I/O

Depends on `shrike-cbor`.

```rust
pub struct Block { pub cid: Cid, pub data: Vec<u8> }

pub struct Reader<R: Read> { /* ... */ }
pub struct Writer<W: Write> { /* ... */ }

impl<R: Read> Reader<R> {
    pub fn new(reader: R) -> Result<Self>;
    pub fn roots(&self) -> &[Cid];
    pub fn next_block(&mut self) -> Result<Option<Block>>;
}

impl<W: Write> Writer<W> {
    pub fn new(writer: W, roots: &[Cid]) -> Result<Self>;
    pub fn write_block(&mut self, block: &Block) -> Result<()>;
    pub fn finish(self) -> Result<W>;
}

pub fn read_all(reader: impl Read) -> Result<(Vec<Cid>, Vec<Block>)>;
pub fn write_all(roots: &[Cid], blocks: &[Block]) -> Result<Vec<u8>>;
pub fn verify(reader: impl Read) -> Result<()>;
```

**Design:**

- Streaming by default — memory proportional to largest block, not whole file
- Sync I/O — CAR files read from already-buffered sources
- `verify()` recomputes every CID and checks match

### shrike-lexicon — Schema Parsing & Validation

Depends on `shrike-syntax`, `serde`, `serde_json`.

**Schema types:**

```rust
pub struct Schema {
    pub id: Nsid,
    pub revision: Option<u32>,
    pub description: Option<String>,
    pub defs: HashMap<String, Def>,
}

pub enum Def {
    Record(RecordDef),
    Query(QueryDef),
    Procedure(ProcedureDef),
    Subscription(SubscriptionDef),
    Object(ObjectDef),
    Token(TokenDef),
    String(StringDef),
    // ...
}

pub enum FieldSchema {
    String { min_length: Option<u64>, max_length: Option<u64>, known_values: Vec<String>, r#enum: Vec<String> },
    Integer { minimum: Option<i64>, maximum: Option<i64> },
    Boolean,
    Bytes { min_length: Option<u64>, max_length: Option<u64> },
    CidLink,
    Blob { accept: Vec<String>, max_size: Option<u64> },
    Array { items: Box<FieldSchema>, min_length: Option<u64>, max_length: Option<u64> },
    Object(ObjectDef),
    Ref(String),
    Union(Vec<String>),
    Unknown,
}
```

**Catalog & validation:**

```rust
pub struct Catalog { schemas: HashMap<Nsid, Schema> }

impl Catalog {
    pub fn new() -> Self;
    pub fn add_schema(&mut self, json: &[u8]) -> Result<()>;
    pub fn load_dir(&mut self, path: &Path) -> Result<()>;
}

pub fn validate_record(catalog: &Catalog, collection: &Nsid, record: &serde_json::Value) -> Result<()>;
pub fn validate_value(catalog: &Catalog, field: &FieldSchema, value: &serde_json::Value) -> Result<()>;
```

**Design:**

- Validates against `serde_json::Value` — flexible, works with any record type
- Path-aware errors (e.g. `record.embed.images[0].alt`)
- `Catalog` holds all schemas for `$ref` / union resolution
- Separate from code generation — this is runtime validation

### shrike-xrpc — XRPC HTTP Client

Depends on `shrike-syntax`, `shrike-cbor`, `reqwest`, `tokio`, `serde`.

```rust
pub struct Client {
    http: reqwest::Client,
    host: String,
    auth: RwLock<Option<AuthInfo>>,
    retry: RetryPolicy,
}
```

**Operations:**

```rust
impl Client {
    pub fn new(host: &str) -> Self;
    pub fn with_auth(host: &str, auth: AuthInfo) -> Self;
    pub async fn query<P, O>(&self, nsid: &str, params: &P) -> Result<O>;
    pub async fn procedure<I, O>(&self, nsid: &str, input: &I) -> Result<O>;
    pub async fn query_raw(&self, nsid: &str, params: &impl Serialize) -> Result<Vec<u8>>;
    pub async fn query_stream(&self, nsid: &str, params: &impl Serialize) -> Result<impl AsyncRead>;
    pub async fn procedure_raw(&self, nsid: &str, body: Vec<u8>, content_type: &str) -> Result<serde_json::Value>;
    pub async fn create_session(&self, identifier: &str, password: &str) -> Result<AuthInfo>;
    pub async fn refresh_session(&self) -> Result<AuthInfo>;
    pub async fn delete_session(&self) -> Result<()>;
}
```

**Design:**

- `tokio::sync::RwLock` for auth — shared reads, exclusive writes on refresh
- Exponential backoff + jitter retry, respects `RateLimit-Reset` / `Retry-After`
- Proactive rate limit tracking — avoids 429s rather than reacting
- Response size limits: 5 MB JSON, 512 MB binary
- NSID as `&str` for generated code ergonomics

### shrike-xrpc-server — XRPC HTTP Server

Depends on `shrike-syntax`, `shrike-cbor`, `serde`, `tokio`, `axum`.

```rust
pub struct Server { router: axum::Router }

impl Server {
    pub fn new() -> Self;
    pub fn query<P, O, F, Fut>(&mut self, nsid: &str, handler: F) -> &mut Self;
    pub fn procedure<I, O, F, Fut>(&mut self, nsid: &str, handler: F) -> &mut Self;
    pub fn into_router(self) -> axum::Router;
    pub async fn serve(self, listener: tokio::net::TcpListener) -> Result<()>;
}
```

**Design:**

- Built on `axum` — routing, middleware, extractors
- `into_router()` for composability with other routes
- Standard XRPC error envelope (`{"error": "...", "message": "..."}`)
- Typed handler functions with `RequestContext` (auth DID, headers)

### shrike-identity — DID Resolution & Handle Verification

Depends on `shrike-syntax`, `shrike-crypto`, `shrike-xrpc`, `serde`, `tokio`.

```rust
pub struct Identity {
    pub did: Did,
    pub handle: Option<Handle>,
    pub keys: HashMap<String, Box<dyn VerifyingKey>>,
    pub services: HashMap<String, ServiceEndpoint>,
}

pub struct Directory {
    plc_url: String,
    cache: Mutex<LruCache<Did, CachedIdentity>>,
    http: reqwest::Client,
}

impl Directory {
    pub fn new() -> Self;
    pub async fn lookup(&self, id: &AtIdentifier) -> Result<Identity>;
    pub async fn lookup_did(&self, did: &Did) -> Result<Identity>;
    pub async fn lookup_handle(&self, handle: &Handle) -> Result<Identity>;
}
```

**Design:**

- `identity.pds_endpoint()` and `identity.signing_key()` convenience methods
- LRU cache with configurable TTL and capacity
- Handle verification: resolve handle → DID, then verify handle in `alsoKnownAs`
- Supports `did:plc:` (PLC directory) and `did:web:` (`.well-known/did.json`)
- PLC client embedded (simple enough — 3 HTTP endpoints)

### shrike-streaming — Event Stream Consumer

Depends on `shrike-syntax`, `shrike-cbor`, `tokio`, `tokio-tungstenite`, `serde`.

**Event types (idiomatic Rust enums):**

```rust
pub enum Event {
    Commit {
        did: Did,
        rev: Tid,
        seq: i64,
        operations: Vec<Operation>,
    },
    Identity {
        did: Did,
        seq: i64,
        handle: Option<Handle>,
    },
    Account {
        did: Did,
        seq: i64,
        active: bool,
    },
    Labels {
        seq: i64,
        labels: Vec<Label>,
    },
}

pub enum Operation {
    Create { collection: Nsid, rkey: RecordKey, cid: Cid, record: Vec<u8> },
    Update { collection: Nsid, rkey: RecordKey, cid: Cid, record: Vec<u8> },
    Delete { collection: Nsid, rkey: RecordKey },
}

/// Separate type — different protocol (JSON over WebSocket)
pub enum JetstreamEvent {
    Commit {
        did: Did,
        time_us: i64,
        collection: Nsid,
        rkey: RecordKey,
        operation: JetstreamCommit,
    },
    Identity { did: Did, time_us: i64 },
    Account { did: Did, time_us: i64, active: bool },
}

pub enum JetstreamCommit {
    Create { cid: Cid, record: serde_json::Value },
    Update { cid: Cid, record: serde_json::Value },
    Delete,
}
```

**Consumer API:**

```rust
impl Client {
    pub fn subscribe(config: Config) -> impl Stream<Item = Result<Event>> + '_;
    pub fn jetstream(config: Config) -> impl Stream<Item = Result<JetstreamEvent>> + '_;
    pub fn cursor(&self) -> Option<i64>;
}
```

**Design:**

- Returns `futures::Stream` — idiomatic async Rust, composable with stream combinators
- Separate `Event` / `JetstreamEvent` types — different protocols, compile-time correctness
- Automatic reconnection with exponential backoff + jitter, resumes from cursor
- Cursor checkpointing is caller's responsibility
- Optional `DistributedLocker` trait for HA deployments

### shrike-sync — Repo Sync & Commit Verification

Depends on `shrike-syntax`, `shrike-cbor`, `shrike-mst`, `shrike-repo`, `shrike-car`, `shrike-identity`, `shrike-xrpc`, `tokio`.

```rust
pub struct SyncClient { xrpc: Client, identity: Option<Arc<Directory>> }

impl SyncClient {
    pub fn new(xrpc: Client) -> Self;
    pub fn with_identity(xrpc: Client, dir: Arc<Directory>) -> Self;
    pub async fn get_repo(&self, did: &Did) -> Result<DownloadedRepo>;
    pub async fn iter_records(&self, did: &Did) -> Result<Vec<Record>>;
    pub async fn list_repos(&self, cursor: Option<&str>) -> Result<(Vec<RepoEntry>, Option<String>)>;
    pub async fn verify(&self, repo: &DownloadedRepo) -> Result<()>;
}
```

**Design:**

- Verification is optional — `get_repo()` returns raw data, `verify()` validates
- Full chain verification: commit signature, block CIDs, MST integrity
- Pagination returns `(items, Option<cursor>)` tuple

### shrike-backfill — Concurrent Repo Downloader

Depends on `shrike-sync`, `shrike-xrpc`, `tokio`.

```rust
pub struct BackfillEngine { config: BackfillConfig }

impl BackfillEngine {
    pub fn new(config: BackfillConfig) -> Self;
    pub async fn run(&self, cancel: CancellationToken) -> Result<BackfillStats>;
}

pub trait Checkpoint: Send + Sync {
    fn save(&self, cursor: &str) -> BoxFuture<Result<()>>;
    fn load(&self) -> BoxFuture<Result<Option<String>>>;
}
```

**Design:**

- Batch shuffle (default 100K) for PDS load distribution
- `CancellationToken` for graceful shutdown with checkpoint save
- Async callbacks (`on_repo`, `on_error`) for backpressure
- Per-repo retry with exponential backoff
- Configurable worker count (default 50)

### shrike-labeling — Label Creation & Verification

Depends on `shrike-syntax`, `shrike-cbor`, `shrike-crypto`.

```rust
pub struct Label {
    pub src: Did,
    pub uri: String,
    pub cid: Option<Cid>,
    pub val: String,
    pub neg: bool,
    pub cts: Datetime,
    pub exp: Option<Datetime>,
    pub sig: Option<Vec<u8>>,
}

pub fn sign_label(label: &mut Label, key: &dyn SigningKey) -> Result<()>;
pub fn verify_label(label: &Label, key: &dyn VerifyingKey) -> Result<()>;
pub fn encode_label(label: &Label) -> Result<Vec<u8>>;
pub fn decode_label(data: &[u8]) -> Result<Label>;
```

### shrike-api — Generated Lexicon Types

Generated by `lexgen` tool from Lexicon JSON schemas.

**What's generated:**

- Structs for every record/object with `serde::Serialize`/`Deserialize`
- Enums for unions using `#[serde(tag = "$type")]`
- XRPC endpoint functions: `get_timeline(client, params) -> Result<Output>`
- `to_cbor()` methods with pre-computed DRISL key bytes
- `NSID` constants on record types
- `camelCase` serde renaming

**Module structure mirrors Lexicon namespaces:**

```
shrike-api/src/
├── com/atproto/{identity,label,repo,server,sync}.rs
├── app/bsky/{actor,feed,graph,notification,embed}.rs
├── chat/bsky/...
└── tools/ozone/...
```

### lexgen — Code Generator

Dev tool in `tools/lexgen/`. Reads Lexicon JSON files, outputs Rust source for `shrike-api`. Not a runtime dependency.

### rat — Facade Crate

```rust
pub use shrike_syntax as syntax;
pub use shrike_cbor as cbor;
// ... all crates

// Common types at root for convenience
pub use shrike_syntax::{Did, Handle, Nsid, AtUri, Tid, Datetime, RecordKey};
pub use shrike_cbor::Cid;
```

All sub-crates are optional features for selective dependency pulling.

## Build Order

Strict bottom-up, each crate fully tested before moving on:

1. `shrike-syntax`
2. `shrike-cbor`
3. `shrike-crypto`
4. `shrike-mst`
5. `shrike-repo`
6. `shrike-car`
7. `shrike-lexicon`
8. `shrike-xrpc`
9. `shrike-xrpc-server`
10. `shrike-identity`
11. `shrike-streaming`
12. `shrike-sync`
13. `shrike-backfill`
14. `shrike-labeling`
15. `shrike-api` + `lexgen`
16. `rat` (facade)

## Testing Strategy

- **Unit tests** in each crate
- **Fuzz tests** for parsing/encoding crates (syntax, cbor, crypto, mst, car, lexicon)
- **Integration tests** for network crates (xrpc, identity, streaming, sync)
- **Test vectors** from AT Protocol reference implementations and atmos
- **Property tests** where applicable (round-trip encoding, MST invariants)

## Deferred (Not In Scope)

- OAuth 2.0 (PKCE, PAR, DPoP)
- Service authentication (inter-service JWT)
- WASM bindings
