# rat — Full Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a complete AT Protocol library for Rust, inspired by atmos (Go), built bottom-up from syntax types through networking.

**Architecture:** Cargo workspace of small, focused crates. Core crates (syntax, cbor, crypto, mst, repo, car) are pure sync Rust with zero async runtime deps. Networking crates (xrpc, streaming, identity, sync, backfill) use tokio. Each crate is independently testable and publishable.

**Tech Stack:** Rust (N-2 MSRV), thiserror, serde/serde_json, sha2, p256/k256, reqwest, tokio, tokio-tungstenite, axum

**Design spec:** `docs/superpowers/specs/2026-04-04-rat-atproto-library-design.md`

**Reference implementation:** `/home/jcalabro/go/src/github.com/jcalabro/atmos` (Go)

**Detail gradient:** Tasks 1-12 (syntax, cbor, crypto) include full implementation code since they establish patterns. Tasks 13+ (mst through facade) include test code and type definitions but describe implementation in prose — the patterns are established and the atmos reference has the algorithms. Each task references the specific atmos source file to consult.

---

## File Structure

```
Cargo.toml                          # Workspace root
crates/
  ratproto-syntax/
    Cargo.toml
    src/lib.rs                      # Re-exports + SyntaxError
    src/did.rs                      # Did type
    src/handle.rs                   # Handle type
    src/nsid.rs                     # Nsid type
    src/aturi.rs                    # AtUri type
    src/tid.rs                      # Tid, TidClock
    src/datetime.rs                 # Datetime type
    src/recordkey.rs                # RecordKey type
    src/language.rs                 # Language type
    src/at_identifier.rs            # AtIdentifier enum
    testdata/
      did_syntax_valid.txt
      did_syntax_invalid.txt
      handle_syntax_valid.txt
      handle_syntax_invalid.txt
      nsid_syntax_valid.txt
      nsid_syntax_invalid.txt
      tid_syntax_valid.txt
      tid_syntax_invalid.txt
  ratproto-cbor/
    Cargo.toml
    src/lib.rs                      # Re-exports + CborError
    src/cid.rs                      # Cid, Codec
    src/value.rs                    # Value enum
    src/encode.rs                   # Encoder
    src/decode.rs                   # Decoder
    src/varint.rs                   # Unsigned varint helpers
    src/key.rs                      # cbor_key! macro
    testdata/                       # Test vectors (copied from atmos)
  ratproto-crypto/
    Cargo.toml
    src/lib.rs                      # Traits + re-exports
    src/p256.rs                     # P256SigningKey, P256VerifyingKey
    src/k256.rs                     # K256SigningKey, K256VerifyingKey
    src/signature.rs                # Signature type
    src/did_key.rs                  # did:key parsing
    testdata/                       # Signature fixtures
  ratproto-mst/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/tree.rs                     # Tree<S>
    src/node.rs                     # Node, Entry internals
    src/diff.rs                     # Diff
    src/block_store.rs              # BlockStore trait + MemBlockStore
    src/height.rs                   # Key height computation
    testdata/                       # Example keys, fixtures
  ratproto-repo/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/repo.rs                     # Repo<S>
    src/commit.rs                   # Commit, signing, verification
    testdata/                       # Real repo CAR fixtures
  ratproto-car/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/reader.rs                   # Reader<R>
    src/writer.rs                   # Writer<W>
    testdata/                       # CAR fixtures
  ratproto-lexicon/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/schema.rs                   # Schema, Def, FieldSchema
    src/catalog.rs                  # Catalog
    src/validate.rs                 # validate_record, validate_value
    src/error.rs                    # ValidationError
  ratproto-xrpc/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/client.rs                   # Client
    src/auth.rs                     # AuthInfo, session management
    src/retry.rs                    # RetryPolicy
    src/error.rs                    # Error enum
  ratproto-xrpc-server/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/server.rs                   # Server
    src/error.rs                    # ServerError
    src/context.rs                  # RequestContext
  ratproto-identity/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/identity.rs                 # Identity, DidDocument
    src/directory.rs                # Directory (cached resolver)
    src/plc.rs                      # PlcClient
    src/did_web.rs                  # did:web resolution
  ratproto-streaming/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/event.rs                    # Event, Operation enums
    src/jetstream.rs                # JetstreamEvent, JetstreamCommit
    src/client.rs                   # Client, subscribe/jetstream
    src/reconnect.rs                # Reconnection logic
  ratproto-sync/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/client.rs                   # SyncClient
    src/verify.rs                   # Verification logic
  ratproto-backfill/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/engine.rs                   # BackfillEngine
    src/checkpoint.rs               # Checkpoint trait
  ratproto-labeling/
    Cargo.toml
    src/lib.rs                      # Label, sign/verify/encode/decode
  ratproto-api/
    Cargo.toml
    src/lib.rs                      # Re-exports
    src/com/mod.rs                  # com namespace
    src/com/atproto/mod.rs          # com.atproto namespace
    src/app/mod.rs                  # app namespace
    src/app/bsky/mod.rs             # app.bsky namespace
    (generated files)
  rat/
    Cargo.toml
    src/lib.rs                      # Facade re-exports
tools/
  lexgen/
    Cargo.toml
    src/main.rs                     # Code generator
    src/generator.rs                # Rust code generation
```

---

## Task 1: Workspace Setup

**Files:**
- Create: `Cargo.toml` (workspace root)
- Create: `crates/ratproto-syntax/Cargo.toml`
- Create: `crates/ratproto-syntax/src/lib.rs`
- Create: `CLAUDE.md`

- [ ] **Step 1: Create workspace root Cargo.toml**

```toml
[workspace]
resolver = "2"
members = [
    "crates/ratproto-syntax",
]

[workspace.package]
version = "0.1.0"
edition = "2024"
license = "MIT OR Apache-2.0"
repository = "https://github.com/jcalabro/rat"

[workspace.dependencies]
thiserror = "2"
serde = { version = "1", features = ["derive"] }
serde_json = "1"
sha2 = "0.10"
```

- [ ] **Step 2: Create ratproto-syntax crate scaffold**

`crates/ratproto-syntax/Cargo.toml`:
```toml
[package]
name = "ratproto-syntax"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol syntax types — DID, Handle, NSID, AT-URI, TID, Datetime"

[dependencies]
thiserror.workspace = true
serde.workspace = true
```

`crates/ratproto-syntax/src/lib.rs`:
```rust
mod did;

pub use did::Did;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyntaxError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_compiles() {}
}
```

`crates/ratproto-syntax/src/did.rs`:
```rust
use std::fmt;

/// A validated AT Protocol DID (Decentralized Identifier).
///
/// Guaranteed to be valid on construction. Use `TryFrom<&str>` or `.parse()`.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Did(String);

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}
```

- [ ] **Step 3: Create CLAUDE.md**

```markdown
# rat

AT Protocol library for Rust. See design spec at `docs/superpowers/specs/2026-04-04-rat-atproto-library-design.md`.

## Build & Test

```bash
cargo build
cargo test
cargo clippy -- -D warnings
```

## Architecture

Cargo workspace of focused crates. See design spec for full dependency graph.

## Conventions

- All types validate on construction (newtype pattern with private inner field)
- `thiserror` for all error types
- `serde` Serialize/Deserialize on all public types
- Tests live in the same file as the code they test (unit) or in tests/ (integration)
- Fuzz tests go in fuzz/ directories using cargo-fuzz
- Copy test vectors from atmos where applicable
```

- [ ] **Step 4: Verify it builds and tests pass**

Run: `cargo build && cargo test`
Expected: Compiles, 1 test passes

- [ ] **Step 5: Commit**

```bash
git add Cargo.toml CLAUDE.md crates/ratproto-syntax/
git commit -m "feat: scaffold workspace with ratproto-syntax crate"
```

---

## Task 2: ratproto-syntax — Did Type

**Files:**
- Create: `crates/ratproto-syntax/src/did.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`
- Create: `crates/ratproto-syntax/testdata/did_syntax_valid.txt`
- Create: `crates/ratproto-syntax/testdata/did_syntax_invalid.txt`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/did.go` and `did_test.go`

- [ ] **Step 1: Copy test vectors from atmos**

```bash
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/did_syntax_valid.txt crates/ratproto-syntax/testdata/
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/did_syntax_invalid.txt crates/ratproto-syntax/testdata/
```

- [ ] **Step 2: Write the test vector loading helper and DID tests**

Add to `crates/ratproto-syntax/src/did.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    /// Load test vectors from a file, skipping blank lines and # comments
    fn load_vectors(path: &str) -> Vec<String> {
        let content = std::fs::read_to_string(path).unwrap();
        content
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_valid_dids() {
        let vectors = load_vectors("testdata/did_syntax_valid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            let did = Did::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid DID: {v:?}, got error: {e}"));
            assert_eq!(did.to_string(), *v);
        }
    }

    #[test]
    fn parse_invalid_dids() {
        let vectors = load_vectors("testdata/did_syntax_invalid.txt");
        assert!(!vectors.is_empty(), "no test vectors loaded");
        for v in &vectors {
            assert!(
                Did::try_from(v.as_str()).is_err(),
                "should be invalid DID: {v:?}"
            );
        }
    }

    #[test]
    fn did_method_and_identifier() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.method(), "plc");
        assert_eq!(did.identifier(), "z72i7hdynmk6r22z27h6tvur");
    }

    #[test]
    fn did_plc_fast_path() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        assert_eq!(did.to_string().len(), 32);
    }

    #[test]
    fn did_display_roundtrip() {
        let input = "did:web:example.com";
        let did = Did::try_from(input).unwrap();
        assert_eq!(did.to_string(), input);
    }

    #[test]
    fn did_serde_roundtrip() {
        let did = Did::try_from("did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
        let json = serde_json::to_string(&did).unwrap();
        let parsed: Did = serde_json::from_str(&json).unwrap();
        assert_eq!(did, parsed);
    }

    #[test]
    fn did_reject_empty() {
        assert!(Did::try_from("").is_err());
    }

    #[test]
    fn did_reject_no_method() {
        assert!(Did::try_from("did:").is_err());
    }

    #[test]
    fn did_reject_uppercase_method() {
        assert!(Did::try_from("did:PLC:abc123").is_err());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p ratproto-syntax`
Expected: FAIL — `Did::try_from`, `method()`, `identifier()` not implemented

- [ ] **Step 4: Implement Did type**

Replace `crates/ratproto-syntax/src/did.rs` with full implementation:
```rust
use std::borrow::Borrow;
use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

use crate::SyntaxError;

/// A validated AT Protocol DID (Decentralized Identifier).
///
/// Guaranteed to be valid on construction. Use `TryFrom<&str>` or `.parse()`.
///
/// Format: `did:<method>:<identifier>`
/// - Method: lowercase ASCII letters only
/// - Identifier: ASCII printable chars, percent-encoded where needed
/// - Max length: 2048
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Did(String);

impl Did {
    /// Extract the DID method (e.g., "plc" from "did:plc:abc123").
    pub fn method(&self) -> &str {
        let after_did = &self.0[4..]; // skip "did:"
        let colon = after_did.find(':').unwrap(); // validated on construction
        &after_did[..colon]
    }

    /// Extract the method-specific identifier.
    pub fn identifier(&self) -> &str {
        let after_did = &self.0[4..];
        let colon = after_did.find(':').unwrap();
        &after_did[colon + 1..]
    }

    /// Returns the inner string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<&str> for Did {
    type Error = SyntaxError;

    fn try_from(s: &str) -> Result<Self, Self::Error> {
        validate_did(s)?;
        Ok(Did(s.to_string()))
    }
}

impl FromStr for Did {
    type Err = SyntaxError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::try_from(s)
    }
}

impl fmt::Display for Did {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl Borrow<str> for Did {
    fn borrow(&self) -> &str {
        &self.0
    }
}

impl AsRef<str> for Did {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for Did {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Did::try_from(s.as_str()).map_err(serde::de::Error::custom)
    }
}

fn validate_did(s: &str) -> Result<(), SyntaxError> {
    let err = || SyntaxError::InvalidDid(s.to_string());

    // Max length
    if s.len() > 2048 {
        return Err(err());
    }

    // Must start with "did:"
    let rest = s.strip_prefix("did:").ok_or_else(err)?;

    // Find method (lowercase alpha only)
    let colon_pos = rest.find(':').ok_or_else(err)?;
    if colon_pos == 0 {
        return Err(err());
    }
    let method = &rest[..colon_pos];
    if !method.bytes().all(|b| b.is_ascii_lowercase()) {
        return Err(err());
    }

    // Identifier must be non-empty
    let identifier = &rest[colon_pos + 1..];
    if identifier.is_empty() {
        return Err(err());
    }

    // Identifier: valid chars are ASCII printable except [ ] { } < > and whitespace,
    // plus percent-encoding
    let id_bytes = identifier.as_bytes();
    let mut i = 0;
    while i < id_bytes.len() {
        let b = id_bytes[i];
        if b == b'%' {
            // Percent-encoded: must have exactly 2 hex digits following
            if i + 2 >= id_bytes.len() {
                return Err(err());
            }
            if !id_bytes[i + 1].is_ascii_hexdigit() || !id_bytes[i + 2].is_ascii_hexdigit() {
                return Err(err());
            }
            i += 3;
        } else if b.is_ascii_alphanumeric()
            || b"._-:".contains(&b)
        {
            i += 1;
        } else {
            return Err(err());
        }
    }

    // Must not end with ':'
    if s.ends_with(':') {
        return Err(err());
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    // ... (tests from Step 2 above)
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `cargo test -p ratproto-syntax`
Expected: All tests pass

- [ ] **Step 6: Update lib.rs exports**

```rust
mod did;

pub use did::Did;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SyntaxError {
    #[error("invalid DID: {0}")]
    InvalidDid(String),
    #[error("invalid handle: {0}")]
    InvalidHandle(String),
    #[error("invalid NSID: {0}")]
    InvalidNsid(String),
    #[error("invalid AT-URI: {0}")]
    InvalidAtUri(String),
    #[error("invalid TID: {0}")]
    InvalidTid(String),
    #[error("invalid datetime: {0}")]
    InvalidDatetime(String),
    #[error("invalid record key: {0}")]
    InvalidRecordKey(String),
    #[error("invalid language tag: {0}")]
    InvalidLanguage(String),
}
```

- [ ] **Step 7: Run clippy and tests**

Run: `cargo clippy -p ratproto-syntax -- -D warnings && cargo test -p ratproto-syntax`
Expected: No warnings, all tests pass

- [ ] **Step 8: Commit**

```bash
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement Did type with validation and test vectors"
```

---

## Task 3: ratproto-syntax — Handle Type

**Files:**
- Create: `crates/ratproto-syntax/src/handle.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`
- Create: `crates/ratproto-syntax/testdata/handle_syntax_valid.txt`
- Create: `crates/ratproto-syntax/testdata/handle_syntax_invalid.txt`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/handle.go` and `handle_test.go`

- [ ] **Step 1: Copy test vectors from atmos**

```bash
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/handle_syntax_valid.txt crates/ratproto-syntax/testdata/
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/handle_syntax_invalid.txt crates/ratproto-syntax/testdata/
```

- [ ] **Step 2: Write tests**

`crates/ratproto-syntax/src/handle.rs`:
```rust
#[cfg(test)]
mod tests {
    use super::*;

    fn load_vectors(path: &str) -> Vec<String> {
        let content = std::fs::read_to_string(path).unwrap();
        content.lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .map(String::from)
            .collect()
    }

    #[test]
    fn parse_valid_handles() {
        let vectors = load_vectors("testdata/handle_syntax_valid.txt");
        assert!(!vectors.is_empty());
        for v in &vectors {
            Handle::try_from(v.as_str())
                .unwrap_or_else(|e| panic!("should be valid handle: {v:?}, got: {e}"));
        }
    }

    #[test]
    fn parse_invalid_handles() {
        let vectors = load_vectors("testdata/handle_syntax_invalid.txt");
        assert!(!vectors.is_empty());
        for v in &vectors {
            assert!(Handle::try_from(v.as_str()).is_err(), "should be invalid: {v:?}");
        }
    }

    #[test]
    fn handle_normalize_lowercase() {
        let h = Handle::try_from("Alice.Bsky.Social").unwrap();
        assert_eq!(h.as_str(), "alice.bsky.social");
    }

    #[test]
    fn handle_serde_roundtrip() {
        let h = Handle::try_from("user.bsky.social").unwrap();
        let json = serde_json::to_string(&h).unwrap();
        let parsed: Handle = serde_json::from_str(&json).unwrap();
        assert_eq!(h, parsed);
    }

    #[test]
    fn handle_reject_single_label() {
        assert!(Handle::try_from("localhost").is_err());
    }

    #[test]
    fn handle_reject_hyphen_boundaries() {
        assert!(Handle::try_from("-alice.example.com").is_err());
        assert!(Handle::try_from("alice-.example.com").is_err());
    }
}
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `cargo test -p ratproto-syntax`
Expected: FAIL — Handle not implemented

- [ ] **Step 4: Implement Handle type**

`crates/ratproto-syntax/src/handle.rs`: Follow the same newtype pattern as Did. Handle validation rules:
- Max total length: 253
- At least 2 labels separated by dots
- Each label: 1-63 chars, alphanumeric + hyphens, no leading/trailing hyphens
- Normalized to lowercase on construction
- TLD must not start with a digit

Reference atmos's `handle.go` for the exact validation logic, adapting to idiomatic Rust (same `TryFrom`/`FromStr`/`Display`/`Borrow`/serde pattern as Did).

- [ ] **Step 5: Run tests, clippy**

Run: `cargo clippy -p ratproto-syntax -- -D warnings && cargo test -p ratproto-syntax`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement Handle type with normalization and test vectors"
```

---

## Task 4: ratproto-syntax — Nsid Type

**Files:**
- Create: `crates/ratproto-syntax/src/nsid.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`
- Create: `crates/ratproto-syntax/testdata/nsid_syntax_valid.txt`
- Create: `crates/ratproto-syntax/testdata/nsid_syntax_invalid.txt`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/nsid.go`

- [ ] **Step 1: Copy test vectors**

```bash
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/nsid_syntax_valid.txt crates/ratproto-syntax/testdata/
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/nsid_syntax_invalid.txt crates/ratproto-syntax/testdata/
```

- [ ] **Step 2: Write tests**

Tests for: parse valid vectors, parse invalid vectors, `authority()` (reversed domain), `name()` extraction, serde roundtrip. Same test vector loading pattern as Did/Handle. Note: Nsid normalizes to lowercase on construction (no separate `normalize()` method).

```rust
#[test]
fn nsid_authority() {
    let n = Nsid::try_from("app.bsky.feed.post").unwrap();
    assert_eq!(n.authority(), "bsky.app");
    assert_eq!(n.name(), "post");
}
```

- [ ] **Step 3: Run tests to verify failure, implement, verify pass**

Same TDD cycle as previous types. Nsid rules:
- At least 3 segments (2 authority + 1 name)
- Authority segments: lowercase alpha + digits + hyphens
- Name segment: starts with letter, alphanumeric only
- Max length: 317 chars
- Normalized to lowercase

- [ ] **Step 4: Commit**

```bash
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement Nsid type with authority/name parsing"
```

---

## Task 5: ratproto-syntax — AtUri Type

**Files:**
- Create: `crates/ratproto-syntax/src/aturi.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/aturi.go`

- [ ] **Step 1: Write tests**

```rust
#[test]
fn aturi_full_path() {
    let u = AtUri::try_from("at://did:plc:z72i7hdynmk6r22z27h6tvur/app.bsky.feed.post/3jui7kd2z3b2a").unwrap();
    assert_eq!(u.authority(), "did:plc:z72i7hdynmk6r22z27h6tvur");
    assert_eq!(u.collection(), Some("app.bsky.feed.post"));
    assert_eq!(u.rkey(), Some("3jui7kd2z3b2a"));
}

#[test]
fn aturi_authority_only() {
    let u = AtUri::try_from("at://did:plc:z72i7hdynmk6r22z27h6tvur").unwrap();
    assert_eq!(u.collection(), None);
    assert_eq!(u.rkey(), None);
}

#[test]
fn aturi_reject_trailing_slash() {
    assert!(AtUri::try_from("at://did:plc:abc/").is_err());
}

#[test]
fn aturi_reject_fragment() {
    assert!(AtUri::try_from("at://did:plc:abc#frag").is_err());
}

#[test]
fn aturi_reject_query() {
    assert!(AtUri::try_from("at://did:plc:abc?q=1").is_err());
}
```

- [ ] **Step 2: Implement AtUri**

Format: `at://<authority>[/<collection>[/<rkey>]]`
- Authority: DID or Handle
- Collection: NSID
- Rkey: RecordKey
- No fragments, no query params, no trailing slashes

- [ ] **Step 3: Run tests, clippy, commit**

```bash
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement AtUri type with path decomposition"
```

---

## Task 6: ratproto-syntax — Tid and TidClock

**Files:**
- Create: `crates/ratproto-syntax/src/tid.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`
- Create: `crates/ratproto-syntax/testdata/tid_syntax_valid.txt`
- Create: `crates/ratproto-syntax/testdata/tid_syntax_invalid.txt`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/tid.go`

- [ ] **Step 1: Copy test vectors**

```bash
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/tid_syntax_valid.txt crates/ratproto-syntax/testdata/
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/testdata/tid_syntax_invalid.txt crates/ratproto-syntax/testdata/
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn parse_valid_tids() {
    // Load from test vectors
}

#[test]
fn parse_invalid_tids() {
    // Load from test vectors
}

#[test]
fn tid_roundtrip() {
    let tid = Tid::new(1_700_000_000_000_000, 0);
    let s = tid.to_string();
    assert_eq!(s.len(), 13);
    let parsed = Tid::try_from(s.as_str()).unwrap();
    assert_eq!(tid, parsed);
}

#[test]
fn tid_clock_monotonic() {
    let clock = TidClock::new(0);
    let mut prev = clock.next();
    for _ in 0..100 {
        let next = clock.next();
        assert!(next > prev, "TIDs must be monotonically increasing");
        prev = next;
    }
}

#[test]
fn tid_timestamp_and_clock_id() {
    let tid = Tid::new(1_700_000_000_000_000, 42);
    assert_eq!(tid.timestamp_micros(), 1_700_000_000_000_000);
    assert_eq!(tid.clock_id(), 42);
}
```

- [ ] **Step 3: Implement Tid and TidClock**

`Tid` is a `u64` newtype encoding microsecond timestamp (54 bits) + clock ID (10 bits). Display as 13-char base32-sort string (alphabet: `234567abcdefghijklmnopqrstuvwxyz`).

`TidClock` uses `AtomicU64` to store the last timestamp. `next()` reads current time in microseconds, ensures it's greater than the previous value (bumps by 1 if clock hasn't advanced), and atomically updates.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement Tid and TidClock with atomic monotonic generation"
```

---

## Task 7: ratproto-syntax — Datetime, RecordKey, Language, AtIdentifier

**Files:**
- Create: `crates/ratproto-syntax/src/datetime.rs`
- Create: `crates/ratproto-syntax/src/recordkey.rs`
- Create: `crates/ratproto-syntax/src/language.rs`
- Create: `crates/ratproto-syntax/src/at_identifier.rs`
- Modify: `crates/ratproto-syntax/src/lib.rs`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/datetime.go`, `recordkey.go`, `language.go`, `at_identifier.go`

- [ ] **Step 1: Write tests for all four types**

Key test cases:
- **Datetime**: Valid RFC 3339 with `Z` or `+00:00`, reject `-00:00`, reject lowercase `z`, reject missing timezone
- **RecordKey**: Max 512 chars, no `/` or whitespace, allow `_~.:-`, reject `.` and `..`
- **Language**: BCP-47 validation, reject uppercase primary subtag, reject empty subtag after hyphen
- **AtIdentifier**: Parses as either Did or Handle, `is_did()`/`is_handle()` accessors

- [ ] **Step 2: Implement all four types**

Each follows the same newtype + `TryFrom` + serde pattern. `AtIdentifier` is an enum:
```rust
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AtIdentifier {
    Did(Did),
    Handle(Handle),
}

impl AtIdentifier {
    pub fn is_did(&self) -> bool { matches!(self, Self::Did(_)) }
    pub fn is_handle(&self) -> bool { matches!(self, Self::Handle(_)) }
}
```

- [ ] **Step 3: Update lib.rs to export everything**

```rust
mod did;
mod handle;
mod nsid;
mod aturi;
mod tid;
mod datetime;
mod recordkey;
mod language;
mod at_identifier;

pub use did::Did;
pub use handle::Handle;
pub use nsid::Nsid;
pub use aturi::AtUri;
pub use tid::{Tid, TidClock};
pub use datetime::Datetime;
pub use recordkey::RecordKey;
pub use language::Language;
pub use at_identifier::AtIdentifier;
```

- [ ] **Step 4: Run full test suite, clippy, commit**

```bash
cargo clippy -p ratproto-syntax -- -D warnings && cargo test -p ratproto-syntax
git add crates/ratproto-syntax/
git commit -m "feat(ratproto-syntax): implement Datetime, RecordKey, Language, AtIdentifier"
```

---

## Task 8: ratproto-cbor — Crate Setup, Varint, CID

**Files:**
- Create: `crates/ratproto-cbor/Cargo.toml`
- Create: `crates/ratproto-cbor/src/lib.rs`
- Create: `crates/ratproto-cbor/src/varint.rs`
- Create: `crates/ratproto-cbor/src/cid.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Create crate and add to workspace**

`crates/ratproto-cbor/Cargo.toml`:
```toml
[package]
name = "ratproto-cbor"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "DRISL (DASL deterministic CBOR) codec and CID for AT Protocol"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
thiserror.workspace = true
sha2.workspace = true

[dev-dependencies]
serde_json.workspace = true
```

Add `"crates/ratproto-cbor"` to workspace members.

- [ ] **Step 2: Write varint tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_roundtrip() {
        let values = [0u64, 1, 127, 128, 255, 256, 16383, 16384, u32::MAX as u64, u32::MAX as u64 + 1, i64::MAX as u64];
        for v in values {
            let mut buf = Vec::new();
            encode_varint(v, &mut buf);
            let (decoded, len) = decode_varint(&buf).unwrap();
            assert_eq!(decoded, v, "roundtrip failed for {v}");
            assert_eq!(len, buf.len());
        }
    }

    #[test]
    fn varint_empty_input() {
        assert!(decode_varint(&[]).is_err());
    }

    #[test]
    fn varint_truncated() {
        assert!(decode_varint(&[0x80]).is_err()); // continuation bit set, no next byte
    }
}
```

- [ ] **Step 3: Implement varint**

`crates/ratproto-cbor/src/varint.rs`: Standard unsigned varint (LEB128) encoding/decoding.

- [ ] **Step 4: Write CID tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compute_cid_drisl() {
        let data = b"hello world";
        let cid = Cid::compute(Codec::Drisl, data);
        assert_eq!(cid.codec(), Codec::Drisl);
        assert_eq!(cid.hash().len(), 32);
    }

    #[test]
    fn cid_string_roundtrip() {
        let cid = Cid::compute(Codec::Drisl, b"test data");
        let s = cid.to_string();
        assert!(s.starts_with('b')); // base32lower multibase prefix
        let parsed = s.parse::<Cid>().unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_bytes_roundtrip() {
        let cid = Cid::compute(Codec::Raw, b"raw data");
        let bytes = cid.to_bytes();
        let parsed = Cid::from_bytes(&bytes).unwrap();
        assert_eq!(cid, parsed);
    }

    #[test]
    fn cid_different_data_different_cid() {
        let a = Cid::compute(Codec::Drisl, b"hello");
        let b = Cid::compute(Codec::Drisl, b"world");
        assert_ne!(a, b);
    }

    #[test]
    fn cid_different_codec_different_cid() {
        let a = Cid::compute(Codec::Drisl, b"same");
        let b = Cid::compute(Codec::Raw, b"same");
        assert_ne!(a, b);
    }

    #[test]
    fn cid_reject_invalid_multibase_prefix() {
        assert!("zNotBase32".parse::<Cid>().is_err());
    }
}
```

- [ ] **Step 5: Implement Cid**

```rust
use sha2::{Sha256, Digest};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Codec {
    Drisl = 0x71,
    Raw = 0x55,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cid {
    codec: Codec,
    hash: [u8; 32],
}

impl Cid {
    pub fn compute(codec: Codec, data: &[u8]) -> Self {
        let hash: [u8; 32] = Sha256::digest(data).into();
        Cid { codec, hash }
    }

    pub fn codec(&self) -> Codec { self.codec }
    pub fn hash(&self) -> &[u8; 32] { &self.hash }

    /// Binary CID encoding: version(1) + codec + hash_type(0x12) + hash_len(0x20) + hash
    pub fn to_bytes(&self) -> Vec<u8> { /* encode with varints */ }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, CborError> { /* decode and validate */ }

    /// For tag 42 encoding: 0x00 prefix + binary CID
    pub fn to_tag42_bytes(&self) -> Vec<u8> { /* 0x00 + to_bytes() */ }
    pub fn from_tag42_bytes(bytes: &[u8]) -> Result<Self, CborError> { /* strip 0x00 + from_bytes() */ }
}

// Display: 'b' prefix + base32lower
// FromStr: strip 'b' prefix + base32lower decode
```

- [ ] **Step 6: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-cbor -- -D warnings && cargo test -p ratproto-cbor
git add Cargo.toml crates/ratproto-cbor/
git commit -m "feat(ratproto-cbor): implement CID and varint encoding"
```

---

## Task 9: ratproto-cbor — DRISL Encoder

**Files:**
- Create: `crates/ratproto-cbor/src/encode.rs`
- Create: `crates/ratproto-cbor/src/key.rs`
- Modify: `crates/ratproto-cbor/src/lib.rs`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/cbor/encoding.go`

- [ ] **Step 1: Write encoder tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_small_positive_int() {
        // 0-23 encoded in single byte
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_u64(0).unwrap();
        assert_eq!(buf, [0x00]);

        buf.clear();
        enc.encode_u64(23).unwrap();
        assert_eq!(buf, [0x17]);
    }

    #[test]
    fn encode_one_byte_int() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_u64(24).unwrap();
        assert_eq!(buf, [0x18, 0x18]);

        buf.clear();
        enc.encode_u64(255).unwrap();
        assert_eq!(buf, [0x18, 0xff]);
    }

    #[test]
    fn encode_negative_int() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_i64(-1).unwrap();
        assert_eq!(buf, [0x20]); // major type 1, value 0

        buf.clear();
        enc.encode_i64(-25).unwrap();
        assert_eq!(buf, [0x38, 0x18]); // major type 1, 1-byte additional, value 24
    }

    #[test]
    fn encode_text() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_text("hello").unwrap();
        assert_eq!(&buf[..1], &[0x65]); // major type 3, length 5
        assert_eq!(&buf[1..], b"hello");
    }

    #[test]
    fn encode_map_sorted() {
        // Keys must be sorted by CBOR-encoded bytes (length-first)
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        // Provide keys out of order; encoder must sort them
        enc.encode_sorted_map(&[
            ("aa", Value::Unsigned(2)),
            ("b", Value::Unsigned(1)),
            ("a", Value::Unsigned(0)),
        ]).unwrap();
        // Expected order: "a" (6161), "b" (6162), "aa" (626161) — shorter first
    }

    #[test]
    fn encode_float_always_64bit() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_f64(0.0).unwrap();
        assert_eq!(buf.len(), 9); // major type 7, 8 bytes IEEE 754
        assert_eq!(buf[0], 0xfb); // CBOR f64 prefix
    }

    #[test]
    fn encode_cid_tag42() {
        let cid = Cid::compute(Codec::Drisl, b"test");
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_cid(&cid).unwrap();
        assert_eq!(buf[0], 0xd8); // tag (1 byte follows)
        assert_eq!(buf[1], 42);   // tag number 42
    }

    #[test]
    fn encode_bool_and_null() {
        let mut buf = Vec::new();
        let mut enc = Encoder::new(&mut buf);
        enc.encode_bool(true).unwrap();
        assert_eq!(buf, [0xf5]);
        buf.clear();
        enc.encode_bool(false).unwrap();
        assert_eq!(buf, [0xf4]);
        buf.clear();
        enc.encode_null().unwrap();
        assert_eq!(buf, [0xf6]);
    }

    #[test]
    fn encode_deterministic_map_same_bytes() {
        // Encoding the same data 10 times must produce identical bytes
        let entries = [("name", Value::Text("alice")), ("age", Value::Unsigned(30))];
        let first = encode_map(&entries);
        for _ in 0..10 {
            assert_eq!(encode_map(&entries), first);
        }
    }
}
```

- [ ] **Step 2: Implement Encoder**

`crates/ratproto-cbor/src/encode.rs`:
```rust
pub struct Encoder<W: std::io::Write> {
    writer: W,
}

impl<W: std::io::Write> Encoder<W> {
    pub fn new(writer: W) -> Self { Encoder { writer } }

    pub fn encode_u64(&mut self, v: u64) -> Result<(), CborError> { /* minimal CBOR integer */ }
    pub fn encode_i64(&mut self, v: i64) -> Result<(), CborError> { /* major type 0 or 1 */ }
    pub fn encode_bool(&mut self, v: bool) -> Result<(), CborError> { /* 0xf5 / 0xf4 */ }
    pub fn encode_null(&mut self) -> Result<(), CborError> { /* 0xf6 */ }
    pub fn encode_f64(&mut self, v: f64) -> Result<(), CborError> { /* always 0xfb + 8 bytes, reject NaN/Inf */ }
    pub fn encode_text(&mut self, v: &str) -> Result<(), CborError> { /* major type 3 */ }
    pub fn encode_bytes(&mut self, v: &[u8]) -> Result<(), CborError> { /* major type 2 */ }
    pub fn encode_array_header(&mut self, len: u64) -> Result<(), CborError> { /* major type 4 */ }
    pub fn encode_map_header(&mut self, len: u64) -> Result<(), CborError> { /* major type 5 */ }
    pub fn encode_cid(&mut self, cid: &Cid) -> Result<(), CborError> { /* tag 42 + bytestring */ }

    /// Write a CBOR header (major type + additional info) with minimal encoding
    fn write_header(&mut self, major: u8, value: u64) -> Result<(), CborError> { /* ... */ }
}
```

Map key sorting: sort by the CBOR-encoded byte representation of each key (length-first ordering per RFC 7049 section 3.9).

- [ ] **Step 3: Implement cbor_key! macro**

`crates/ratproto-cbor/src/key.rs`:
```rust
/// Pre-compute the CBOR encoding of a text string key at compile time.
/// Used by generated code for zero-allocation map key encoding.
#[macro_export]
macro_rules! cbor_key {
    ($key:literal) => {{
        // CBOR text string: major type 3 + length + UTF-8 bytes
        // For keys < 24 bytes, this is a single header byte + the key bytes
        const KEY: &[u8] = $key.as_bytes();
        // Return the pre-computed bytes
        // (implementation computes header + key at const time)
    }};
}
```

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-cbor -- -D warnings && cargo test -p ratproto-cbor
git add crates/ratproto-cbor/
git commit -m "feat(ratproto-cbor): implement DRISL encoder with deterministic map sorting"
```

---

## Task 10: ratproto-cbor — DRISL Decoder

**Files:**
- Create: `crates/ratproto-cbor/src/decode.rs`
- Create: `crates/ratproto-cbor/src/value.rs`
- Modify: `crates/ratproto-cbor/src/lib.rs`

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/cbor/cbor.go` (Unmarshal)

- [ ] **Step 1: Write decoder tests**

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decode_unsigned_integers() {
        assert_eq!(decode(b"\x00"), Value::Unsigned(0));
        assert_eq!(decode(b"\x17"), Value::Unsigned(23));
        assert_eq!(decode(b"\x18\x18"), Value::Unsigned(24));
        assert_eq!(decode(b"\x18\xff"), Value::Unsigned(255));
        assert_eq!(decode(b"\x19\x01\x00"), Value::Unsigned(256));
    }

    #[test]
    fn decode_negative_integers() {
        assert_eq!(decode(b"\x20"), Value::Signed(-1));
        assert_eq!(decode(b"\x38\x18"), Value::Signed(-25));
    }

    #[test]
    fn decode_text() {
        let data = b"\x65hello";
        match decode(data) {
            Value::Text(s) => assert_eq!(s, "hello"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[test]
    fn decode_reject_indefinite_length() {
        // 0x5f = indefinite-length byte string
        assert!(Decoder::new(b"\x5f").decode().is_err());
    }

    #[test]
    fn decode_reject_non_minimal_int() {
        // 24 encoded as 2-byte when it fits in 1
        assert!(Decoder::new(b"\x19\x00\x18").decode().is_err());
    }

    #[test]
    fn decode_reject_unsorted_map() {
        // Map with keys "b", "a" (wrong order)
        let data = b"\xa2\x61b\x01\x61a\x02";
        assert!(Decoder::new(data).decode().is_err());
    }

    #[test]
    fn decode_reject_duplicate_map_keys() {
        let data = b"\xa2\x61a\x01\x61a\x02";
        assert!(Decoder::new(data).decode().is_err());
    }

    #[test]
    fn decode_reject_non_string_map_key() {
        // Map with integer key
        let data = b"\xa1\x01\x02";
        assert!(Decoder::new(data).decode().is_err());
    }

    #[test]
    fn decode_reject_16bit_float() {
        // 0xf9 = half-precision float
        assert!(Decoder::new(b"\xf9\x00\x00").decode().is_err());
    }

    #[test]
    fn decode_reject_nan() {
        // 64-bit NaN
        assert!(Decoder::new(b"\xfb\x7f\xf8\x00\x00\x00\x00\x00\x00").decode().is_err());
    }

    #[test]
    fn decode_reject_infinity() {
        assert!(Decoder::new(b"\xfb\x7f\xf0\x00\x00\x00\x00\x00\x00").decode().is_err());
    }

    #[test]
    fn decode_reject_tag_not_42() {
        // Tag 1 (datetime)
        assert!(Decoder::new(b"\xc1\x00").decode().is_err());
    }

    #[test]
    fn roundtrip_complex() {
        let original = Value::Map(vec![
            ("age", Value::Unsigned(30)),
            ("name", Value::Text("alice")),
        ]);
        let encoded = encode_value(&original).unwrap();
        let decoded = Decoder::new(&encoded).decode().unwrap();
        // Compare structure
    }
}
```

- [ ] **Step 2: Implement Value type**

`crates/ratproto-cbor/src/value.rs`:
```rust
#[derive(Debug, Clone, PartialEq)]
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

- [ ] **Step 3: Implement Decoder**

`crates/ratproto-cbor/src/decode.rs`:
```rust
pub struct Decoder<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Decoder<'a> {
    pub fn new(buf: &'a [u8]) -> Self { Decoder { buf, pos: 0 } }
    pub fn decode(&mut self) -> Result<Value<'a>, CborError> { /* ... */ }
}
```

Strict enforcement: reject non-minimal integers, unsorted/duplicate map keys, non-string map keys, indefinite lengths, 16/32-bit floats, NaN/Infinity, tags other than 42, simple values other than true/false/null.

- [ ] **Step 4: Add convenience functions to lib.rs**

```rust
pub fn encode(value: &Value) -> Result<Vec<u8>, CborError> { /* ... */ }
pub fn decode(data: &[u8]) -> Result<Value, CborError> { /* ... */ }
```

- [ ] **Step 5: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-cbor -- -D warnings && cargo test -p ratproto-cbor
git add crates/ratproto-cbor/
git commit -m "feat(ratproto-cbor): implement DRISL decoder with strict canonical validation"
```

---

## Task 11: ratproto-crypto — Crate Setup, Traits, P-256

**Files:**
- Create: `crates/ratproto-crypto/Cargo.toml`
- Create: `crates/ratproto-crypto/src/lib.rs`
- Create: `crates/ratproto-crypto/src/signature.rs`
- Create: `crates/ratproto-crypto/src/p256.rs`
- Modify: `Cargo.toml` (workspace members + deps)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/crypto/`

- [ ] **Step 1: Create crate**

`crates/ratproto-crypto/Cargo.toml`:
```toml
[package]
name = "ratproto-crypto"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol cryptography — P-256 and K-256 ECDSA signing"

[dependencies]
ratproto-cbor = { path = "../ratproto-cbor" }
thiserror.workspace = true
p256 = { version = "0.13", features = ["ecdsa"] }
sha2.workspace = true
bs58 = "0.5"

[dev-dependencies]
serde_json.workspace = true
```

- [ ] **Step 2: Implement Signature and traits**

`crates/ratproto-crypto/src/signature.rs`:
```rust
/// 64-byte compact ECDSA signature [R || S], always low-S normalized.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Signature([u8; 64]);

impl Signature {
    pub fn from_bytes(bytes: [u8; 64]) -> Self { Signature(bytes) }
    pub fn as_bytes(&self) -> &[u8; 64] { &self.0 }
}
```

`crates/ratproto-crypto/src/lib.rs`:
```rust
pub trait SigningKey: Send + Sync {
    fn public_key(&self) -> &dyn VerifyingKey;
    fn sign(&self, content: &[u8]) -> Result<Signature, CryptoError>;
}

pub trait VerifyingKey: Send + Sync {
    fn to_bytes(&self) -> [u8; 33];
    fn verify(&self, content: &[u8], sig: &Signature) -> Result<(), CryptoError>;
    fn did_key(&self) -> String;
    fn multibase(&self) -> String;
}
```

- [ ] **Step 3: Write P-256 tests**

```rust
#[test]
fn p256_generate_sign_verify() {
    let sk = P256SigningKey::generate();
    let msg = b"hello world";
    let sig = sk.sign(msg).unwrap();
    assert_eq!(sig.as_bytes().len(), 64);
    sk.public_key().verify(msg, &sig).unwrap();
}

#[test]
fn p256_verify_wrong_data() {
    let sk = P256SigningKey::generate();
    let sig = sk.sign(b"hello").unwrap();
    assert!(sk.public_key().verify(b"world", &sig).is_err());
}

#[test]
fn p256_compressed_bytes_roundtrip() {
    let sk = P256SigningKey::generate();
    let pk = sk.public_key();
    let bytes = pk.to_bytes();
    assert_eq!(bytes.len(), 33);
    let parsed = P256VerifyingKey::from_bytes(&bytes).unwrap();
    assert_eq!(pk.to_bytes(), parsed.to_bytes());
}

#[test]
fn p256_did_key_roundtrip() {
    let sk = P256SigningKey::generate();
    let did_key = sk.public_key().did_key();
    assert!(did_key.starts_with("did:key:z"));
    let parsed = parse_did_key(&did_key).unwrap();
    assert_eq!(sk.public_key().to_bytes(), parsed.to_bytes());
}

#[test]
fn p256_low_s_enforcement() {
    let sk = P256SigningKey::generate();
    for _ in 0..50 {
        let sig = sk.sign(b"test low-s").unwrap();
        let s_bytes = &sig.as_bytes()[32..];
        // Low-S means S <= N/2. For P-256, the high byte of high-S would be >= 0x80
        // This is a simplified check; real check compares against curve order/2
    }
}

#[test]
fn p256_serde_private_key_roundtrip() {
    let sk = P256SigningKey::generate();
    let bytes = sk.to_bytes();
    let restored = P256SigningKey::from_bytes(&bytes).unwrap();
    let sig = restored.sign(b"test").unwrap();
    sk.public_key().verify(b"test", &sig).unwrap();
}
```

- [ ] **Step 4: Implement P256SigningKey and P256VerifyingKey**

Use the `p256` crate. Key points:
- `sign()` does SHA-256 hash + ECDSA sign with low-S normalization
- `verify()` does SHA-256 hash + strict ECDSA verify (reject high-S)
- `to_bytes()` returns 33-byte SEC1 compressed point
- `did_key()` returns `did:key:z<base58btc(multicodec_prefix + compressed_point)>` where multicodec for P-256 is `0x8024`

- [ ] **Step 5: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-crypto -- -D warnings && cargo test -p ratproto-crypto
git add Cargo.toml crates/ratproto-crypto/
git commit -m "feat(ratproto-crypto): implement P-256 signing with low-S normalization"
```

---

## Task 12: ratproto-crypto — K-256 and did:key Parsing

**Files:**
- Create: `crates/ratproto-crypto/src/k256.rs`
- Create: `crates/ratproto-crypto/src/did_key.rs`
- Modify: `crates/ratproto-crypto/Cargo.toml` (add k256 dep)
- Modify: `crates/ratproto-crypto/src/lib.rs`

- [ ] **Step 1: Add k256 dependency**

Add to `crates/ratproto-crypto/Cargo.toml`:
```toml
k256 = { version = "0.13", features = ["ecdsa"] }
```

- [ ] **Step 2: Write K-256 tests and did:key parsing tests**

```rust
#[test]
fn k256_generate_sign_verify() {
    let sk = K256SigningKey::generate();
    let sig = sk.sign(b"test").unwrap();
    sk.public_key().verify(b"test", &sig).unwrap();
}

#[test]
fn k256_did_key_roundtrip() {
    let sk = K256SigningKey::generate();
    let did_key = sk.public_key().did_key();
    assert!(did_key.starts_with("did:key:z"));
    let parsed = parse_did_key(&did_key).unwrap();
    assert_eq!(sk.public_key().to_bytes(), parsed.to_bytes());
}

#[test]
fn cross_curve_cannot_verify() {
    let p256 = P256SigningKey::generate();
    let k256 = K256SigningKey::generate();
    let sig = p256.sign(b"test").unwrap();
    assert!(k256.public_key().verify(b"test", &sig).is_err());
}

#[test]
fn parse_did_key_detects_curve() {
    let p256 = P256SigningKey::generate();
    let k256 = K256SigningKey::generate();
    let p256_key = parse_did_key(&p256.public_key().did_key()).unwrap();
    let k256_key = parse_did_key(&k256.public_key().did_key()).unwrap();
    // Both should verify their own signatures
    let sig_p = p256.sign(b"test").unwrap();
    let sig_k = k256.sign(b"test").unwrap();
    p256_key.verify(b"test", &sig_p).unwrap();
    k256_key.verify(b"test", &sig_k).unwrap();
}

#[test]
fn parse_did_key_invalid_prefix() {
    assert!(parse_did_key("did:key:invalid").is_err());
    assert!(parse_did_key("not-a-did-key").is_err());
}
```

- [ ] **Step 3: Implement K-256 and parse_did_key**

Same pattern as P-256. `parse_did_key` detects curve from the multicodec prefix:
- `0x8024` → P-256
- `0xe7` → secp256k1 (K-256)

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-crypto -- -D warnings && cargo test -p ratproto-crypto
git add crates/ratproto-crypto/
git commit -m "feat(ratproto-crypto): implement K-256 and did:key parsing"
```

---

## Task 13: ratproto-mst — Merkle Search Tree

**Files:**
- Create: `crates/ratproto-mst/Cargo.toml`
- Create: `crates/ratproto-mst/src/lib.rs`
- Create: `crates/ratproto-mst/src/height.rs`
- Create: `crates/ratproto-mst/src/block_store.rs`
- Create: `crates/ratproto-mst/src/node.rs`
- Create: `crates/ratproto-mst/src/tree.rs`
- Create: `crates/ratproto-mst/src/diff.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/mst/`

- [ ] **Step 1: Create crate, copy test data**

```bash
mkdir -p crates/ratproto-mst/testdata
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/mst/testdata/example_keys.txt crates/ratproto-mst/testdata/
```

`crates/ratproto-mst/Cargo.toml`:
```toml
[package]
name = "ratproto-mst"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol Merkle Search Tree"

[dependencies]
ratproto-cbor = { path = "../ratproto-cbor" }
thiserror.workspace = true
sha2.workspace = true
```

- [ ] **Step 2: Write height computation tests**

```rust
#[test]
fn height_for_key_interop_vectors() {
    // From atproto-interop-tests
    let cases = [
        ("2653ae71", 0),
        ("blue", 0),
        ("app.bsky.feed.post/454aat2fqbfga", 0),
        ("app.bsky.feed.post/9adgao", 0),
        ("com.example.record/43", 1),
        ("com.example.record/9ba1c", 2),
    ];
    for (key, expected) in cases {
        assert_eq!(height_for_key(key), expected, "key: {key}");
    }
}

#[test]
fn height_for_example_keys() {
    // Load from atmos testdata
    let content = std::fs::read_to_string("testdata/example_keys.txt").unwrap();
    for line in content.lines() {
        // Parse "Letter Height/Number" format
    }
}
```

- [ ] **Step 3: Implement height_for_key**

SHA-256 hash of the key, count leading zeros in the hash (each zero bit is one level of height).

- [ ] **Step 4: Write BlockStore and MemBlockStore**

```rust
pub trait BlockStore: Send + Sync {
    fn get_block(&self, cid: &Cid) -> Result<Vec<u8>, MstError>;
    fn put_block(&self, cid: Cid, data: Vec<u8>) -> Result<(), MstError>;
    fn has_block(&self, cid: &Cid) -> Result<bool, MstError>;
}

pub struct MemBlockStore {
    blocks: std::collections::HashMap<Cid, Vec<u8>>,
}
```

- [ ] **Step 5: Write Tree tests**

```rust
#[test]
fn empty_tree_root_cid() {
    let store = MemBlockStore::new();
    let mut tree = Tree::new(store);
    let cid = tree.root_cid().unwrap();
    // Should match known empty tree CID from atmos
}

#[test]
fn insert_and_get() {
    let store = MemBlockStore::new();
    let mut tree = Tree::new(store);
    let val_cid = Cid::compute(Codec::Raw, b"value");
    tree.insert("app.bsky.feed.post/abc".to_string(), val_cid).unwrap();
    assert_eq!(tree.get("app.bsky.feed.post/abc").unwrap(), Some(val_cid));
    assert_eq!(tree.get("nonexistent").unwrap(), None);
}

#[test]
fn insert_and_remove() {
    let store = MemBlockStore::new();
    let mut tree = Tree::new(store);
    let cid = Cid::compute(Codec::Raw, b"v");
    tree.insert("key".to_string(), cid).unwrap();
    let removed = tree.remove("key").unwrap();
    assert_eq!(removed, Some(cid));
    assert_eq!(tree.get("key").unwrap(), None);
}

#[test]
fn entries_sorted() {
    let store = MemBlockStore::new();
    let mut tree = Tree::new(store);
    for key in ["c", "a", "b"] {
        tree.insert(key.to_string(), Cid::compute(Codec::Raw, key.as_bytes())).unwrap();
    }
    let entries: Vec<_> = tree.entries().unwrap().collect();
    assert_eq!(entries[0].0, "a");
    assert_eq!(entries[1].0, "b");
    assert_eq!(entries[2].0, "c");
}

#[test]
fn diff_detects_changes() {
    let store1 = MemBlockStore::new();
    let store2 = MemBlockStore::new();
    let mut t1 = Tree::new(store1);
    let mut t2 = Tree::new(store2);
    let cid_a = Cid::compute(Codec::Raw, b"a");
    let cid_b = Cid::compute(Codec::Raw, b"b");
    let cid_c = Cid::compute(Codec::Raw, b"c");
    t1.insert("a".to_string(), cid_a).unwrap();
    t1.insert("b".to_string(), cid_b).unwrap();
    t2.insert("a".to_string(), cid_a).unwrap();
    t2.insert("c".to_string(), cid_c).unwrap();
    let diff = Tree::diff(&t1, &t2).unwrap();
    assert_eq!(diff.removed.len(), 1); // "b" removed
    assert_eq!(diff.added.len(), 1);   // "c" added
}
```

- [ ] **Step 6: Implement Node, Tree, Diff**

This is the most complex data structure. Key implementation details:
- Nodes are DRISL-encoded with entries containing key prefix, CID value, and optional left subtree pointer
- Lazy loading: `Tree::load()` stores root CID, fetches nodes from BlockStore on first access
- `root_cid()` serializes all dirty (modified) nodes to the BlockStore and returns the root CID
- Diff walks both trees in parallel, skipping subtrees with matching CIDs

- [ ] **Step 7: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-mst -- -D warnings && cargo test -p ratproto-mst
git add Cargo.toml crates/ratproto-mst/
git commit -m "feat(ratproto-mst): implement Merkle Search Tree with lazy loading and diff"
```

---

## Task 14: ratproto-repo — Repository Operations

**Files:**
- Create: `crates/ratproto-repo/Cargo.toml`
- Create: `crates/ratproto-repo/src/lib.rs`
- Create: `crates/ratproto-repo/src/repo.rs`
- Create: `crates/ratproto-repo/src/commit.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/repo/`

- [ ] **Step 1: Create crate, copy test fixtures**

```bash
mkdir -p crates/ratproto-repo/testdata
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/repo/testdata/*.car crates/ratproto-repo/testdata/
```

`crates/ratproto-repo/Cargo.toml`:
```toml
[package]
name = "ratproto-repo"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol repository operations — CRUD and signed commits"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
ratproto-crypto = { path = "../ratproto-crypto" }
ratproto-mst = { path = "../ratproto-mst" }
thiserror.workspace = true
```

- [ ] **Step 2: Write Commit tests**

```rust
#[test]
fn commit_sign_and_verify_p256() {
    let sk = P256SigningKey::generate();
    let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let data_cid = Cid::compute(Codec::Drisl, b"tree root");
    let mut commit = Commit {
        did,
        version: 3,
        rev: Tid::new(1_700_000_000_000_000, 0),
        prev: None,
        data: data_cid,
        sig: Signature::from_bytes([0; 64]),
    };
    commit.sign(&sk).unwrap();
    assert_ne!(commit.sig.as_bytes(), &[0; 64]);
    commit.verify(sk.public_key()).unwrap();
}

#[test]
fn commit_verify_wrong_key() {
    let sk1 = P256SigningKey::generate();
    let sk2 = P256SigningKey::generate();
    let mut commit = make_test_commit();
    commit.sign(&sk1).unwrap();
    assert!(commit.verify(&*sk2.public_key()).is_err());
}

#[test]
fn commit_verify_tampered() {
    let sk = P256SigningKey::generate();
    let mut commit = make_test_commit();
    commit.sign(&sk).unwrap();
    commit.did = Did::try_from("did:plc:tampered12345678901234").unwrap();
    assert!(commit.verify(sk.public_key()).is_err());
}

#[test]
fn commit_cbor_roundtrip() {
    let sk = P256SigningKey::generate();
    let mut commit = make_test_commit();
    commit.sign(&sk).unwrap();
    let encoded = commit.to_cbor().unwrap();
    let decoded = Commit::from_cbor(&encoded).unwrap();
    assert_eq!(commit.did, decoded.did);
    assert_eq!(commit.version, decoded.version);
    assert_eq!(commit.rev, decoded.rev);
    assert_eq!(commit.data, decoded.data);
    assert_eq!(commit.sig, decoded.sig);
}
```

- [ ] **Step 3: Implement Commit**

Pre-computed DRISL key bytes for all fields. `unsigned_bytes()` encodes all fields except `sig` for signing. `sign()` calls `unsigned_bytes()` then `key.sign()`. `verify()` calls `unsigned_bytes()` then `key.verify()`.

- [ ] **Step 4: Write Repo tests**

```rust
#[test]
fn repo_create_and_get() {
    let store = MemBlockStore::new();
    let did = Did::try_from("did:plc:test123456789abcdefghij").unwrap();
    let mut repo = Repo::new(did, store);
    let collection = Nsid::try_from("app.bsky.feed.post").unwrap();
    let rkey = RecordKey::try_from("abc123").unwrap();
    let record = b"\xa1\x64text\x65hello"; // DRISL: {"text": "hello"}
    let cid = repo.create(&collection, &rkey, record).unwrap();
    let (got_cid, got_data) = repo.get(&collection, &rkey).unwrap().unwrap();
    assert_eq!(cid, got_cid);
    assert_eq!(got_data, record);
}

#[test]
fn repo_create_duplicate_fails() {
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    let rk = RecordKey::try_from("abc").unwrap();
    repo.create(&col, &rk, b"\xa0").unwrap();
    assert!(repo.create(&col, &rk, b"\xa0").is_err());
}

#[test]
fn repo_commit_produces_valid_signature() {
    let sk = P256SigningKey::generate();
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    repo.create(&col, &RecordKey::try_from("a").unwrap(), b"\xa0").unwrap();
    let commit = repo.commit(&sk).unwrap();
    commit.verify(sk.public_key()).unwrap();
}
```

- [ ] **Step 5: Write list and mutation tests**

```rust
#[test]
fn repo_list_collection() {
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    for key in ["a", "b", "c"] {
        repo.create(&col, &RecordKey::try_from(key).unwrap(), b"\xa0").unwrap();
    }
    let entries = repo.list(&col).unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].0.as_str(), "a");
}

#[test]
fn repo_update_existing() {
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    let rk = RecordKey::try_from("abc").unwrap();
    repo.create(&col, &rk, b"\xa0").unwrap();
    let new_cid = repo.update(&col, &rk, b"\xa1\x61v\x01").unwrap();
    let (got_cid, _) = repo.get(&col, &rk).unwrap().unwrap();
    assert_eq!(new_cid, got_cid);
}

#[test]
fn repo_update_nonexistent_fails() {
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    let rk = RecordKey::try_from("nope").unwrap();
    assert!(repo.update(&col, &rk, b"\xa0").is_err());
}

#[test]
fn repo_delete() {
    let mut repo = make_test_repo();
    let col = Nsid::try_from("app.bsky.feed.post").unwrap();
    let rk = RecordKey::try_from("abc").unwrap();
    repo.create(&col, &rk, b"\xa0").unwrap();
    repo.delete(&col, &rk).unwrap();
    assert!(repo.get(&col, &rk).unwrap().is_none());
}
```

- [ ] **Step 6: Implement Repo**

MST keys are `{collection}/{rkey}`. `create`/`update`/`delete` mutate the in-memory MST. `commit()` computes root CID, builds Commit, signs, stores. Also implement the `Mutation` enum for tracking changes:

```rust
pub enum Mutation {
    Create { collection: Nsid, rkey: RecordKey, cid: Cid },
    Update { collection: Nsid, rkey: RecordKey, cid: Cid },
    Delete { collection: Nsid, rkey: RecordKey },
}
```

- [ ] **Step 7: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-repo -- -D warnings && cargo test -p ratproto-repo
git add Cargo.toml crates/ratproto-repo/
git commit -m "feat(ratproto-repo): implement repository CRUD and signed commits"
```

---

## Task 15: ratproto-car — CAR v1 File I/O

**Files:**
- Create: `crates/ratproto-car/Cargo.toml`
- Create: `crates/ratproto-car/src/lib.rs`
- Create: `crates/ratproto-car/src/reader.rs`
- Create: `crates/ratproto-car/src/writer.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/car/`

- [ ] **Step 1: Create crate, copy test fixtures**

```bash
mkdir -p crates/ratproto-car/testdata
cp /home/jcalabro/go/src/github.com/jcalabro/atmos/car/testdata/*.car crates/ratproto-car/testdata/
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn read_greenground_car() {
    let data = std::fs::read("testdata/greenground.repo.car").unwrap();
    let reader = Reader::new(&data[..]).unwrap();
    assert_eq!(reader.roots().len(), 1);
    let blocks: Vec<_> = reader.collect::<Result<Vec<_>, _>>().unwrap();
    assert!(!blocks.is_empty());
    for block in &blocks {
        let recomputed = Cid::compute(Codec::Drisl, &block.data);
        // CID should match (may need to try both codecs)
    }
}

#[test]
fn roundtrip_greenground() {
    let original = std::fs::read("testdata/greenground.repo.car").unwrap();
    let (roots, blocks) = read_all(&original[..]).unwrap();
    let written = write_all(&roots, &blocks).unwrap();
    assert_eq!(original, written);
}

#[test]
fn write_and_read() {
    let blocks: Vec<Block> = (0..3).map(|i| {
        let data = format!("block {i}").into_bytes();
        Block { cid: Cid::compute(Codec::Raw, &data), data }
    }).collect();
    let written = write_all(&[blocks[0].cid], &blocks).unwrap();
    let (roots, read_blocks) = read_all(&written[..]).unwrap();
    assert_eq!(roots.len(), 1);
    assert_eq!(read_blocks.len(), 3);
}

#[test]
fn verify_checks_cids() {
    let data = std::fs::read("testdata/greenground.repo.car").unwrap();
    verify(&data[..]).unwrap(); // should pass
}
```

- [ ] **Step 3: Implement Reader and Writer**

Reader: parse varint header length, decode DRISL header for roots, then iterate blocks (varint length + CID + data). Writer: write header, then blocks. Both use unsigned varint framing.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-car -- -D warnings && cargo test -p ratproto-car
git add Cargo.toml crates/ratproto-car/
git commit -m "feat(ratproto-car): implement CAR v1 reader and writer"
```

---

## Task 16: ratproto-lexicon — Schema Parsing & Validation

**Files:**
- Create: `crates/ratproto-lexicon/Cargo.toml`
- Create: `crates/ratproto-lexicon/src/lib.rs`
- Create: `crates/ratproto-lexicon/src/schema.rs`
- Create: `crates/ratproto-lexicon/src/catalog.rs`
- Create: `crates/ratproto-lexicon/src/validate.rs`
- Create: `crates/ratproto-lexicon/src/error.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/lexicon/` and `/home/jcalabro/go/src/github.com/jcalabro/atmos/lexval/`

- [ ] **Step 1: Create crate**

```toml
[package]
name = "ratproto-lexicon"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol Lexicon schema parsing and record validation"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
```

- [ ] **Step 2: Write schema parsing tests**

```rust
#[test]
fn parse_simple_record_schema() {
    let json = r#"{
        "lexicon": 1,
        "id": "app.bsky.feed.post",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["text", "createdAt"],
                    "properties": {
                        "text": { "type": "string", "maxLength": 300, "maxGraphemes": 300 },
                        "createdAt": { "type": "string", "format": "datetime" }
                    }
                }
            }
        }
    }"#;
    let schema = Schema::from_json(json.as_bytes()).unwrap();
    assert_eq!(schema.id.as_str(), "app.bsky.feed.post");
    let main_def = schema.defs.get("main").unwrap();
    assert!(matches!(main_def, Def::Record(_)));
}
```

- [ ] **Step 3: Write validation tests**

```rust
#[test]
fn validate_valid_record() {
    let mut catalog = Catalog::new();
    catalog.add_schema(POST_SCHEMA_JSON).unwrap();
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello world",
        "createdAt": "2024-01-01T00:00:00Z"
    });
    let nsid = Nsid::try_from("app.bsky.feed.post").unwrap();
    validate_record(&catalog, &nsid, &record).unwrap();
}

#[test]
fn validate_missing_required_field() {
    let mut catalog = Catalog::new();
    catalog.add_schema(POST_SCHEMA_JSON).unwrap();
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "Hello"
        // missing createdAt
    });
    let nsid = Nsid::try_from("app.bsky.feed.post").unwrap();
    let err = validate_record(&catalog, &nsid, &record).unwrap_err();
    assert!(err.to_string().contains("createdAt"));
}

#[test]
fn validate_string_too_long() {
    let mut catalog = Catalog::new();
    catalog.add_schema(POST_SCHEMA_JSON).unwrap();
    let record = serde_json::json!({
        "$type": "app.bsky.feed.post",
        "text": "x".repeat(301),
        "createdAt": "2024-01-01T00:00:00Z"
    });
    let nsid = Nsid::try_from("app.bsky.feed.post").unwrap();
    assert!(validate_record(&catalog, &nsid, &record).is_err());
}
```

- [ ] **Step 4: Implement Schema, Catalog, validate**

Schema parsing uses serde_json to deserialize Lexicon JSON into the `Schema` struct. Validation walks the record against the schema, checking required fields, types, constraints.

- [ ] **Step 5: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-lexicon -- -D warnings && cargo test -p ratproto-lexicon
git add Cargo.toml crates/ratproto-lexicon/
git commit -m "feat(ratproto-lexicon): implement schema parsing and record validation"
```

---

## Task 17: ratproto-xrpc — XRPC HTTP Client

**Files:**
- Create: `crates/ratproto-xrpc/Cargo.toml`
- Create: `crates/ratproto-xrpc/src/lib.rs`
- Create: `crates/ratproto-xrpc/src/client.rs`
- Create: `crates/ratproto-xrpc/src/auth.rs`
- Create: `crates/ratproto-xrpc/src/retry.rs`
- Create: `crates/ratproto-xrpc/src/error.rs`
- Modify: `Cargo.toml` (workspace members + deps)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/xrpc/`

- [ ] **Step 1: Create crate**

Add to workspace deps in root `Cargo.toml`:
```toml
reqwest = { version = "0.12", features = ["json", "stream"] }
tokio = { version = "1", features = ["full"] }
```

`crates/ratproto-xrpc/Cargo.toml`:
```toml
[package]
name = "ratproto-xrpc"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol XRPC HTTP client"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
reqwest.workspace = true
tokio.workspace = true

[dev-dependencies]
tokio = { workspace = true, features = ["test-util"] }
```

- [ ] **Step 2: Write tests with mock server**

```rust
#[tokio::test]
async fn query_returns_json() {
    // Use a local mock HTTP server (e.g., wiremock or axum test server)
    let mock = start_mock_server().await;
    mock.expect_get("/xrpc/com.atproto.repo.describe")
        .returning(|| json!({"handle": "alice.bsky.social", "did": "did:plc:abc"}));

    let client = Client::new(&mock.url());
    let params = serde_json::json!({"repo": "alice.bsky.social"});
    let result: serde_json::Value = client.query("com.atproto.repo.describe", &params).await.unwrap();
    assert_eq!(result["handle"], "alice.bsky.social");
}

#[tokio::test]
async fn procedure_posts_json() {
    let mock = start_mock_server().await;
    mock.expect_post("/xrpc/com.atproto.server.createSession")
        .returning(|| json!({"accessJwt": "tok", "refreshJwt": "ref", "handle": "alice.bsky.social", "did": "did:plc:abc"}));

    let client = Client::new(&mock.url());
    let auth = client.create_session("alice.bsky.social", "password").await.unwrap();
    assert_eq!(auth.handle.as_str(), "alice.bsky.social");
}

#[tokio::test]
async fn xrpc_error_parsed() {
    let mock = start_mock_server().await;
    mock.expect_get("/xrpc/com.atproto.repo.describe")
        .returning_status(400, json!({"error": "InvalidRequest", "message": "bad repo"}));

    let client = Client::new(&mock.url());
    let err = client.query::<_, serde_json::Value>("com.atproto.repo.describe", &json!({})).await.unwrap_err();
    match err {
        Error::Xrpc { status, error, .. } => {
            assert_eq!(status, 400);
            assert_eq!(error, "InvalidRequest");
        }
        other => panic!("expected Xrpc error, got {other:?}"),
    }
}
```

- [ ] **Step 3: Implement Client, AuthInfo, RetryPolicy, Error**

Key implementation points:
- NSID maps to URL path: `/xrpc/{nsid}`
- Query params serialized to URL query string
- Procedure input serialized as JSON body
- Auth bearer token from `AuthInfo.access_jwt`
- Retry: exponential backoff with jitter on 5xx and network errors
- Rate limit: track `RateLimit-Remaining` / `RateLimit-Reset` headers
- Response size limits: 5 MB JSON, 512 MB binary

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-xrpc -- -D warnings && cargo test -p ratproto-xrpc
git add Cargo.toml crates/ratproto-xrpc/
git commit -m "feat(ratproto-xrpc): implement XRPC HTTP client with retry and rate limiting"
```

---

## Task 18: ratproto-xrpc-server — XRPC HTTP Server

**Files:**
- Create: `crates/ratproto-xrpc-server/Cargo.toml`
- Create: `crates/ratproto-xrpc-server/src/lib.rs`
- Create: `crates/ratproto-xrpc-server/src/server.rs`
- Create: `crates/ratproto-xrpc-server/src/error.rs`
- Create: `crates/ratproto-xrpc-server/src/context.rs`
- Modify: `Cargo.toml` (workspace members + deps)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/xrpcserver/`

- [ ] **Step 1: Create crate**

Add to workspace deps:
```toml
axum = "0.8"
```

`crates/ratproto-xrpc-server/Cargo.toml`:
```toml
[package]
name = "ratproto-xrpc-server"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol XRPC HTTP server framework"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
axum.workspace = true
http = "1"
```

- [ ] **Step 2: Write tests**

```rust
#[tokio::test]
async fn query_handler_returns_json() {
    let mut server = Server::new();
    server.query("com.example.ping", |_params: PingParams, _ctx| async {
        Ok(PingOutput { message: "pong".into() })
    });

    let app = server.into_router();
    let response = app.oneshot(
        Request::builder()
            .uri("/xrpc/com.example.ping?name=test")
            .body(Body::empty())
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn procedure_handler_accepts_post() {
    let mut server = Server::new();
    server.procedure("com.example.echo", |input: EchoInput, _ctx| async {
        Ok(EchoOutput { echoed: input.text })
    });

    let app = server.into_router();
    let response = app.oneshot(
        Request::builder()
            .method("POST")
            .uri("/xrpc/com.example.echo")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"text":"hello"}"#))
            .unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), 200);
}

#[tokio::test]
async fn error_returns_xrpc_envelope() {
    let mut server = Server::new();
    server.query::<(), (), _, _>("com.example.fail", |_params, _ctx| async {
        Err(ServerError::NotFound)
    });

    let app = server.into_router();
    let response = app.oneshot(
        Request::builder().uri("/xrpc/com.example.fail").body(Body::empty()).unwrap()
    ).await.unwrap();

    assert_eq!(response.status(), 404);
    // Body should be {"error": "NotFound", "message": "not found"}
}
```

- [ ] **Step 3: Implement Server, ServerError, RequestContext**

Route `/xrpc/{nsid}` to registered handlers. Queries accept GET with query params, procedures accept POST with JSON body. ServerError implements `axum::response::IntoResponse`.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-xrpc-server -- -D warnings && cargo test -p ratproto-xrpc-server
git add Cargo.toml crates/ratproto-xrpc-server/
git commit -m "feat(ratproto-xrpc-server): implement XRPC server framework on axum"
```

---

## Task 19: ratproto-identity — DID Resolution & Handle Verification

**Files:**
- Create: `crates/ratproto-identity/Cargo.toml`
- Create: `crates/ratproto-identity/src/lib.rs`
- Create: `crates/ratproto-identity/src/identity.rs`
- Create: `crates/ratproto-identity/src/directory.rs`
- Create: `crates/ratproto-identity/src/plc.rs`
- Create: `crates/ratproto-identity/src/did_web.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/identity/`

- [ ] **Step 1: Create crate**

```toml
[package]
name = "ratproto-identity"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol identity resolution — DID documents, handle verification"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-crypto = { path = "../ratproto-crypto" }
ratproto-xrpc = { path = "../ratproto-xrpc" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
reqwest.workspace = true
tokio.workspace = true
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn parse_did_document() {
    let json = r#"{
        "id": "did:plc:z72i7hdynmk6r22z27h6tvur",
        "alsoKnownAs": ["at://bsky.app"],
        "verificationMethod": [{
            "id": "#atproto",
            "type": "Multikey",
            "publicKeyMultibase": "zDnae..."
        }],
        "service": [{
            "id": "#atproto_pds",
            "type": "AtprotoPersonalDataServer",
            "serviceEndpoint": "https://bsky.social"
        }]
    }"#;
    let doc: DidDocument = serde_json::from_str(json).unwrap();
    let identity = Identity::from_document(doc).unwrap();
    assert_eq!(identity.pds_endpoint(), Some("https://bsky.social"));
}

#[test]
fn identity_extract_handle_from_also_known_as() {
    let doc = make_did_document(vec!["at://alice.bsky.social"]);
    let identity = Identity::from_document(doc).unwrap();
    assert_eq!(identity.handle.as_ref().unwrap().as_str(), "alice.bsky.social");
}
```

- [ ] **Step 3: Define types and implement resolution**

```rust
pub struct Identity {
    pub did: Did,
    pub handle: Option<Handle>,
    pub keys: HashMap<String, Box<dyn VerifyingKey>>,
    pub services: HashMap<String, ServiceEndpoint>,
}

pub struct ServiceEndpoint {
    pub id: String,
    pub r#type: String,
    pub endpoint: String,
}

impl Identity {
    pub fn from_document(doc: DidDocument) -> Result<Self> { /* ... */ }
    pub fn pds_endpoint(&self) -> Option<&str> { /* ... */ }
    pub fn signing_key(&self) -> Option<&dyn VerifyingKey> { /* ... */ }
}

struct CachedIdentity {
    identity: Identity,
    expires_at: Instant,
}

pub struct Directory {
    plc_url: String,
    cache: Mutex<LruCache<Did, CachedIdentity>>,
    http: reqwest::Client,
}
```

`Identity::from_document()` extracts handle from `alsoKnownAs`, signing key from `verificationMethod`, PDS from `service`. `Directory` wraps an LRU cache and dispatches `did:plc:` to PLC directory, `did:web:` to `.well-known/did.json`.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-identity -- -D warnings && cargo test -p ratproto-identity
git add Cargo.toml crates/ratproto-identity/
git commit -m "feat(ratproto-identity): implement DID resolution and handle verification"
```

---

## Task 20: ratproto-streaming — Event Stream Consumer

**Files:**
- Create: `crates/ratproto-streaming/Cargo.toml`
- Create: `crates/ratproto-streaming/src/lib.rs`
- Create: `crates/ratproto-streaming/src/event.rs`
- Create: `crates/ratproto-streaming/src/jetstream.rs`
- Create: `crates/ratproto-streaming/src/client.rs`
- Create: `crates/ratproto-streaming/src/reconnect.rs`
- Modify: `Cargo.toml` (workspace members + deps)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/streaming/`

- [ ] **Step 1: Create crate**

Add to workspace deps:
```toml
tokio-tungstenite = { version = "0.24", features = ["native-tls"] }
futures = "0.3"
```

`crates/ratproto-streaming/Cargo.toml`:
```toml
[package]
name = "ratproto-streaming"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol event streaming — firehose, labels, Jetstream"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
thiserror.workspace = true
serde.workspace = true
serde_json.workspace = true
tokio.workspace = true
tokio-tungstenite.workspace = true
futures.workspace = true
```

- [ ] **Step 2: Write event type tests**

```rust
#[test]
fn event_commit_pattern_match() {
    let event = Event::Commit {
        did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
        rev: Tid::new(1_700_000_000_000_000, 0),
        seq: 42,
        operations: vec![
            Operation::Create {
                collection: Nsid::try_from("app.bsky.feed.post").unwrap(),
                rkey: RecordKey::try_from("abc").unwrap(),
                cid: Cid::compute(Codec::Raw, b"test"),
                record: vec![],
            },
        ],
    };
    match &event {
        Event::Commit { did, operations, .. } => {
            assert_eq!(did.as_str(), "did:plc:test123456789abcdefghij");
            assert_eq!(operations.len(), 1);
        }
        _ => panic!("expected Commit"),
    }
}

#[test]
fn jetstream_event_separate_type() {
    let event = JetstreamEvent::Commit {
        did: Did::try_from("did:plc:test123456789abcdefghij").unwrap(),
        time_us: 1_700_000_000_000_000,
        collection: Nsid::try_from("app.bsky.feed.post").unwrap(),
        rkey: RecordKey::try_from("abc").unwrap(),
        operation: JetstreamCommit::Create {
            cid: Cid::compute(Codec::Raw, b"test"),
            record: serde_json::json!({"text": "hello"}),
        },
    };
    match &event {
        JetstreamEvent::Commit { operation, .. } => {
            assert!(matches!(operation, JetstreamCommit::Create { .. }));
        }
        _ => panic!("expected Commit"),
    }
}
```

- [ ] **Step 3: Implement Config, DistributedLocker, and Client**

```rust
pub struct Config {
    pub url: String,
    pub cursor: Option<i64>,
    pub max_reconnect_delay: Duration,
    pub locker: Option<Box<dyn DistributedLocker>>,
}

/// Optional distributed lock for HA — only the lock holder consumes events
pub trait DistributedLocker: Send + Sync {
    fn try_lock(&self) -> BoxFuture<Result<bool>>;
    fn unlock(&self) -> BoxFuture<Result<()>>;
    fn extend(&self) -> BoxFuture<Result<()>>;
}

pub struct Client { config: Config }

impl Client {
    pub fn subscribe(config: Config) -> impl Stream<Item = Result<Event>> + '_ { /* ... */ }
    pub fn jetstream(config: Config) -> impl Stream<Item = Result<JetstreamEvent>> + '_ { /* ... */ }
    pub fn cursor(&self) -> Option<i64> { /* ... */ }
}
```

Uses tokio-tungstenite for WebSocket. Reconnection: exponential backoff with jitter, resume from last cursor. `futures::Stream` for the async iterator pattern.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-streaming -- -D warnings && cargo test -p ratproto-streaming
git add Cargo.toml crates/ratproto-streaming/
git commit -m "feat(ratproto-streaming): implement firehose and Jetstream consumers"
```

---

## Task 21: ratproto-sync — Repo Sync & Verification

**Files:**
- Create: `crates/ratproto-sync/Cargo.toml`
- Create: `crates/ratproto-sync/src/lib.rs`
- Create: `crates/ratproto-sync/src/client.rs`
- Create: `crates/ratproto-sync/src/verify.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/sync/`

- [ ] **Step 1: Create crate**

```toml
[package]
name = "ratproto-sync"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol repository sync and commit verification"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
ratproto-mst = { path = "../ratproto-mst" }
ratproto-repo = { path = "../ratproto-repo" }
ratproto-car = { path = "../ratproto-car" }
ratproto-identity = { path = "../ratproto-identity" }
ratproto-xrpc = { path = "../ratproto-xrpc" }
thiserror.workspace = true
tokio.workspace = true
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn verify_car_fixture() {
    let data = std::fs::read("../ratproto-repo/testdata/greenground.repo.car").unwrap();
    let (roots, blocks) = ratproto_car::read_all(&data[..]).unwrap();
    // Build MemBlockStore from blocks
    // Parse commit from root
    // Verify MST structure
}

#[tokio::test]
async fn list_repos_pagination() {
    // Mock XRPC server returning paginated results
}
```

- [ ] **Step 3: Define types and implement SyncClient**

```rust
pub struct DownloadedRepo {
    pub did: Did,
    pub commit: Commit,
    pub blocks: Vec<ratproto_car::Block>,
}

pub struct Record {
    pub collection: Nsid,
    pub rkey: RecordKey,
    pub cid: Cid,
    pub data: Vec<u8>,
    pub rev: Tid,
}

pub struct RepoEntry {
    pub did: Did,
    pub head: Cid,
    pub rev: Tid,
}

pub struct SyncClient {
    xrpc: ratproto_xrpc::Client,
    identity: Option<Arc<Directory>>,
}
```

`get_repo` calls `com.atproto.sync.getRepo` via XRPC (returns CAR bytes), parses with ratproto-car. `verify` checks commit signature, recomputes all block CIDs, walks MST. `iter_records` downloads repo then walks the MST extracting individual records. `list_repos` paginates `com.atproto.sync.listRepos`.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-sync -- -D warnings && cargo test -p ratproto-sync
git add Cargo.toml crates/ratproto-sync/
git commit -m "feat(ratproto-sync): implement repo sync client and verification"
```

---

## Task 22: ratproto-backfill — Concurrent Repo Downloader

**Files:**
- Create: `crates/ratproto-backfill/Cargo.toml`
- Create: `crates/ratproto-backfill/src/lib.rs`
- Create: `crates/ratproto-backfill/src/engine.rs`
- Create: `crates/ratproto-backfill/src/checkpoint.rs`
- Modify: `Cargo.toml` (workspace members + deps)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/backfill/`

- [ ] **Step 1: Create crate**

Add to workspace deps:
```toml
tokio-util = { version = "0.7", features = ["rt"] }
rand = "0.9"
```

```toml
[package]
name = "ratproto-backfill"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol concurrent repo backfill engine"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-sync = { path = "../ratproto-sync" }
ratproto-xrpc = { path = "../ratproto-xrpc" }
thiserror.workspace = true
tokio.workspace = true
tokio-util.workspace = true
rand.workspace = true
futures.workspace = true
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn shuffle_distributes_across_batches() {
    let dids: Vec<Did> = (0..1000)
        .map(|i| Did::try_from(&format!("did:plc:{i:024}")).unwrap())
        .collect();
    let shuffled = shuffle_batch(&dids);
    assert_eq!(shuffled.len(), dids.len());
    // First and last elements should differ from input (probabilistically)
    assert_ne!(shuffled[0], dids[0]);
}

#[tokio::test]
async fn engine_respects_cancellation() {
    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();
    let engine = BackfillEngine::new(make_test_config());

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        cancel_clone.cancel();
    });

    let stats = engine.run(cancel).await.unwrap();
    // Should have stopped quickly
}
```

- [ ] **Step 3: Define types and implement BackfillEngine**

```rust
pub struct BackfillConfig {
    pub sync: SyncClient,
    pub workers: usize,               // default: 50
    pub batch_size: usize,            // default: 100_000
    pub collections: Option<Vec<Nsid>>,
    pub checkpoint: Box<dyn Checkpoint>,
    pub on_repo: Box<dyn Fn(DownloadedRepo) -> BoxFuture<'static, Result<()>> + Send + Sync>,
    pub on_error: Box<dyn Fn(Did, Error) -> BoxFuture<'static, Result<()>> + Send + Sync>,
}

pub struct BackfillStats {
    pub repos_downloaded: u64,
    pub repos_failed: u64,
    pub bytes_downloaded: u64,
    pub elapsed: Duration,
}

pub trait Checkpoint: Send + Sync {
    fn save(&self, cursor: &str) -> BoxFuture<Result<()>>;
    fn load(&self) -> BoxFuture<Result<Option<String>>>;
}
```

Worker pool with tokio tasks, batch accumulation + Fisher-Yates shuffle, CancellationToken for graceful shutdown, per-repo retry with backoff.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-backfill -- -D warnings && cargo test -p ratproto-backfill
git add Cargo.toml crates/ratproto-backfill/
git commit -m "feat(ratproto-backfill): implement concurrent repo downloader with shuffle"
```

---

## Task 23: ratproto-labeling — Label Creation & Verification

**Files:**
- Create: `crates/ratproto-labeling/Cargo.toml`
- Create: `crates/ratproto-labeling/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/labeling/`

- [ ] **Step 1: Create crate**

```toml
[package]
name = "ratproto-labeling"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol label creation and verification"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
ratproto-crypto = { path = "../ratproto-crypto" }
thiserror.workspace = true
```

- [ ] **Step 2: Write tests**

```rust
#[test]
fn sign_and_verify_label() {
    let sk = P256SigningKey::generate();
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
    let sk = P256SigningKey::generate();
    let mut label = make_test_label();
    sign_label(&mut label, &sk).unwrap();
    label.val = "not-spam".into();
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
}

#[test]
fn negation_label() {
    let label = Label {
        src: Did::try_from("did:plc:labeler12345678901234").unwrap(),
        uri: "did:plc:user1234567890123456".into(),
        cid: None,
        val: "spam".into(),
        neg: true, // negation
        cts: Datetime::try_from("2024-01-01T00:00:00Z").unwrap(),
        exp: None,
        sig: None,
    };
    assert!(label.neg);
}
```

- [ ] **Step 3: Implement Label, sign/verify/encode/decode**

Small crate. `encode_label` serializes all fields except `sig` to DRISL. `sign_label` encodes then signs. `verify_label` encodes then verifies signature.

- [ ] **Step 4: Run tests, clippy, commit**

```bash
cargo clippy -p ratproto-labeling -- -D warnings && cargo test -p ratproto-labeling
git add Cargo.toml crates/ratproto-labeling/
git commit -m "feat(ratproto-labeling): implement label sign/verify/encode/decode"
```

---

## Task 24: lexgen Tool & ratproto-api Generated Types

**Files:**
- Create: `tools/lexgen/Cargo.toml`
- Create: `tools/lexgen/src/main.rs`
- Create: `tools/lexgen/src/generator.rs`
- Create: `crates/ratproto-api/Cargo.toml`
- Create: `crates/ratproto-api/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

Reference: `/home/jcalabro/go/src/github.com/jcalabro/atmos/lexgen/` and `/home/jcalabro/go/src/github.com/jcalabro/atmos/cmd/lexgen/`

- [ ] **Step 1: Create lexgen tool crate**

```toml
[package]
name = "lexgen"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Code generator: AT Protocol Lexicon JSON → Rust types"

[dependencies]
ratproto-lexicon = { path = "../../crates/ratproto-lexicon" }
ratproto-syntax = { path = "../../crates/ratproto-syntax" }
serde.workspace = true
serde_json.workspace = true
```

- [ ] **Step 2: Write generator tests**

```rust
#[test]
fn generate_simple_record() {
    let schema_json = r#"{
        "lexicon": 1,
        "id": "com.example.post",
        "defs": {
            "main": {
                "type": "record",
                "key": "tid",
                "record": {
                    "type": "object",
                    "required": ["text"],
                    "properties": {
                        "text": { "type": "string" }
                    }
                }
            }
        }
    }"#;
    let output = generate_rust(schema_json).unwrap();
    assert!(output.contains("pub struct Post"));
    assert!(output.contains("pub text: String"));
    assert!(output.contains("serde::Serialize"));
    assert!(output.contains("serde::Deserialize"));
}

#[test]
fn generate_union_type() {
    let schema_json = r#"{
        "lexicon": 1,
        "id": "com.example.embed",
        "defs": {
            "main": {
                "type": "object",
                "properties": {
                    "media": {
                        "type": "union",
                        "refs": ["com.example.image", "com.example.video"]
                    }
                }
            }
        }
    }"#;
    let output = generate_rust(schema_json).unwrap();
    assert!(output.contains("#[serde(tag = \"$type\")]"));
    assert!(output.contains("pub enum"));
}

#[test]
fn generate_xrpc_query_function() {
    let schema_json = r#"{
        "lexicon": 1,
        "id": "com.example.getPost",
        "defs": {
            "main": {
                "type": "query",
                "parameters": {
                    "type": "params",
                    "required": ["uri"],
                    "properties": {
                        "uri": { "type": "string", "format": "at-uri" }
                    }
                },
                "output": {
                    "encoding": "application/json",
                    "schema": { "type": "ref", "ref": "#outputSchema" }
                }
            }
        }
    }"#;
    let output = generate_rust(schema_json).unwrap();
    assert!(output.contains("pub async fn get_post"));
    assert!(output.contains("client.query"));
}
```

- [ ] **Step 3: Implement code generator**

`generator.rs`: Takes parsed `Schema` (from ratproto-lexicon), outputs Rust source code string. Handles:
- Record → struct with serde derives + `NSID` constant + `to_cbor()` method
- Object → struct
- Union → enum with `#[serde(tag = "$type")]`
- Query → async function calling `client.query()`
- Procedure → async function calling `client.procedure()`
- Field types → Rust types (`string` → `String`, `integer` → `i64`, `cid-link` → `Cid`, etc.)
- `camelCase` → `snake_case` field names with `#[serde(rename_all = "camelCase")]`

`main.rs`: CLI that reads Lexicon JSON directory, runs generator, writes to output directory.

- [ ] **Step 4: Create ratproto-api scaffold**

```toml
[package]
name = "ratproto-api"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "Generated AT Protocol API types from Lexicon schemas"

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax" }
ratproto-cbor = { path = "../ratproto-cbor" }
ratproto-xrpc = { path = "../ratproto-xrpc" }
serde.workspace = true
serde_json.workspace = true
```

`crates/ratproto-api/src/lib.rs`:
```rust
// This crate contains generated code from AT Protocol Lexicon schemas.
// Regenerate with: cargo run --bin lexgen -- --input <lexicons-dir> --output crates/ratproto-api/src/

pub mod com;
pub mod app;
```

- [ ] **Step 5: Run lexgen against official Lexicon schemas to generate ratproto-api**

```bash
# Clone the official AT Protocol lexicons first
git clone https://github.com/bluesky-social/atproto.git /tmp/atproto-lexicons
cargo run --bin lexgen -- --input /tmp/atproto-lexicons/lexicons --output crates/ratproto-api/src/
```

- [ ] **Step 6: Verify generated code compiles**

```bash
cargo build -p ratproto-api
```

- [ ] **Step 7: Commit**

```bash
git add Cargo.toml tools/lexgen/ crates/ratproto-api/
git commit -m "feat: implement lexgen code generator and ratproto-api scaffold"
```

---

## Task 25: rat — Facade Crate

**Files:**
- Create: `crates/rat/Cargo.toml`
- Create: `crates/rat/src/lib.rs`
- Modify: `Cargo.toml` (workspace members)

- [ ] **Step 1: Create facade crate**

`crates/rat/Cargo.toml`:
```toml
[package]
name = "rat"
version.workspace = true
edition.workspace = true
license.workspace = true
description = "AT Protocol library for Rust"

[features]
default = ["syntax", "cbor", "crypto", "mst", "repo", "car"]
syntax = ["dep:ratproto-syntax"]
cbor = ["dep:ratproto-cbor"]
crypto = ["dep:ratproto-crypto"]
mst = ["dep:ratproto-mst"]
repo = ["dep:ratproto-repo"]
car = ["dep:ratproto-car"]
lexicon = ["dep:ratproto-lexicon"]
xrpc = ["dep:ratproto-xrpc"]
xrpc-server = ["dep:ratproto-xrpc-server"]
identity = ["dep:ratproto-identity"]
streaming = ["dep:ratproto-streaming"]
sync = ["dep:ratproto-sync"]
backfill = ["dep:ratproto-backfill"]
labeling = ["dep:ratproto-labeling"]
api = ["dep:ratproto-api"]
full = ["syntax", "cbor", "crypto", "mst", "repo", "car", "lexicon", "xrpc", "xrpc-server", "identity", "streaming", "sync", "backfill", "labeling", "api"]

[dependencies]
ratproto-syntax = { path = "../ratproto-syntax", optional = true }
ratproto-cbor = { path = "../ratproto-cbor", optional = true }
ratproto-crypto = { path = "../ratproto-crypto", optional = true }
ratproto-mst = { path = "../ratproto-mst", optional = true }
ratproto-repo = { path = "../ratproto-repo", optional = true }
ratproto-car = { path = "../ratproto-car", optional = true }
ratproto-lexicon = { path = "../ratproto-lexicon", optional = true }
ratproto-xrpc = { path = "../ratproto-xrpc", optional = true }
ratproto-xrpc-server = { path = "../ratproto-xrpc-server", optional = true }
ratproto-identity = { path = "../ratproto-identity", optional = true }
ratproto-streaming = { path = "../ratproto-streaming", optional = true }
ratproto-sync = { path = "../ratproto-sync", optional = true }
ratproto-backfill = { path = "../ratproto-backfill", optional = true }
ratproto-labeling = { path = "../ratproto-labeling", optional = true }
ratproto-api = { path = "../ratproto-api", optional = true }
```

- [ ] **Step 2: Create lib.rs**

```rust
#[cfg(feature = "syntax")]
pub use ratproto_syntax as syntax;
#[cfg(feature = "cbor")]
pub use ratproto_cbor as cbor;
#[cfg(feature = "crypto")]
pub use ratproto_crypto as crypto;
#[cfg(feature = "mst")]
pub use ratproto_mst as mst;
#[cfg(feature = "repo")]
pub use ratproto_repo as repo;
#[cfg(feature = "car")]
pub use ratproto_car as car;
#[cfg(feature = "lexicon")]
pub use ratproto_lexicon as lexicon;
#[cfg(feature = "xrpc")]
pub use ratproto_xrpc as xrpc;
#[cfg(feature = "xrpc-server")]
pub use ratproto_xrpc_server as xrpc_server;
#[cfg(feature = "identity")]
pub use ratproto_identity as identity;
#[cfg(feature = "streaming")]
pub use ratproto_streaming as streaming;
#[cfg(feature = "sync")]
pub use ratproto_sync as sync;
#[cfg(feature = "backfill")]
pub use ratproto_backfill as backfill;
#[cfg(feature = "labeling")]
pub use ratproto_labeling as labeling;
#[cfg(feature = "api")]
pub use ratproto_api as api;

// Re-export common types at root for convenience
#[cfg(feature = "syntax")]
pub use ratproto_syntax::{Did, Handle, Nsid, AtUri, Tid, TidClock, Datetime, RecordKey, Language, AtIdentifier};
#[cfg(feature = "cbor")]
pub use ratproto_cbor::Cid;
```

- [ ] **Step 3: Verify it builds with default features and full features**

```bash
cargo build -p rat
cargo build -p rat --features full
```

- [ ] **Step 4: Commit**

```bash
git add Cargo.toml crates/rat/
git commit -m "feat(rat): implement facade crate with feature-gated re-exports"
```

---

## Task 26: Final Integration & Cleanup

- [ ] **Step 1: Run full workspace build and tests**

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
```

- [ ] **Step 2: Fix any cross-crate issues**

Verify all dependency relationships work correctly. Fix any type mismatches or import issues.

- [ ] **Step 3: Run full test suite one more time**

```bash
cargo test --workspace
```

- [ ] **Step 4: Commit any fixes**

```bash
git add -A
git commit -m "fix: resolve cross-crate integration issues"
```
