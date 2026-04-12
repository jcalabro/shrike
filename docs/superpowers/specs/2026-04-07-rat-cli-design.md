# `rat` CLI Tool Design

A command-line tool for interacting with the AT Protocol, built on top of the
shrike library. Serves as both a practical utility and a manual testing
harness for the library crates.

Modeled after the existing Go-based `atp` CLI (which uses `atmos`), adapted to
idiomatic Rust.

## Crate Setup

Binary crate at `tools/rat` inside the shrike workspace. Not published to
crates.io — this is a development/testing tool.

```
tools/rat/
├── Cargo.toml
└── src/
    ├── main.rs          # clap top-level parser, dispatch
    ├── syntax.rs        # rat syntax <type> <value>
    ├── key.rs           # rat key generate / inspect
    ├── resolve.rs       # rat resolve <handle-or-did>
    ├── plc.rs           # rat plc resolve / history
    ├── repo.rs          # rat repo export / inspect / ls
    ├── validate.rs      # rat validate <collection> <json-file>
    ├── record.rs        # rat record get / list
    ├── account.rs       # rat account login / logout / status
    ├── subscribe.rs     # rat subscribe
    └── session.rs       # session.json load/save helper
```

### Dependencies

```toml
[dependencies]
clap = { version = "4", features = ["derive"] }
anyhow = "1"
serde = { workspace = true }
serde_json = { workspace = true }
tokio = { workspace = true, features = ["rt-multi-thread", "macros"] }
dirs = "6"

# Workspace crates
shrike-syntax = { path = "../../crates/shrike-syntax" }
shrike-crypto = { path = "../../crates/shrike-crypto" }
shrike-cbor = { path = "../../crates/shrike-cbor" }
shrike-car = { path = "../../crates/shrike-car" }
shrike-lexicon = { path = "../../crates/shrike-lexicon" }
shrike-identity = { path = "../../crates/shrike-identity" }
shrike-xrpc = { path = "../../crates/shrike-xrpc" }
shrike-streaming = { path = "../../crates/shrike-streaming" }
shrike-api = { path = "../../crates/shrike-api" }
```

## Commands

### Layer 1: No-Auth Commands (Implemented First)

These exercise the sync/core crates and identity resolution with no
credentials required.

#### `rat syntax <type> <value>`

Validate an AT Protocol syntax type and print the normalized form.

Supported types: `did`, `handle`, `nsid`, `at-uri`, `tid`, `record-key`
(alias `rkey`), `datetime`, `language`.

Flags: `--json`

Default output:
```
valid
  normalized: at://did:plc:xyz/app.bsky.feed.post/abc123
```

On invalid input:
```
invalid
  error: missing collection in AT-URI
```

JSON output:
```json
{
  "type": "at-uri",
  "input": "at://...",
  "valid": true,
  "normalized": "at://...",
  "error": null
}
```

Exercises: `shrike-syntax` (TryFrom/FromStr, Display).

#### `rat key generate [--type p256|k256]`

Generate a new signing key pair. Default type: `p256`.

Flags: `--json`

Default output:
```
type:     P-256
did:key:  did:key:z...
multibase: z...
public:   04ab...
```

JSON output: same fields as object.

Exercises: `shrike-crypto` (key generation, did:key encoding).

#### `rat key inspect <did-key-or-multibase>`

Parse and display a public key from did:key or multibase encoding.

Flags: `--json`

Output: same format as `key generate`.

Exercises: `shrike-crypto` (did:key parsing, multibase decoding).

#### `rat resolve <handle-or-did>`

Resolve a handle or DID to its full identity.

Flags: `--json`, `--did-only`

Default output:
```
did:     did:plc:xyz
handle:  alice.bsky.social
pds:     https://morel.us-east.host.bsky.network
signing: did:key:z...
```

`--did-only` prints just the DID string on a single line.

Exercises: `shrike-identity` (DID resolution, handle extraction),
`shrike-syntax` (DID/Handle parsing).

#### `rat plc resolve <did>`

Resolve a DID via the PLC directory.

Flags: `--json`

Default output: same labeled format as `resolve`.

Exercises: `shrike-identity` (PLC directory resolution).

#### `rat plc history <did>`

Show the PLC operation audit log for a DID.

Flags: `--json`

Default output:
```
1  2024-01-15T10:30:00Z  bafy...  (active)
2  2024-03-20T14:22:00Z  bafy...  (active)
```

Exercises: `shrike-xrpc` (raw GET to PLC directory).

#### `rat repo inspect <car-file>`

Inspect a local CAR file and show summary statistics.

Flags: `--json`

Default output:
```
did:         did:plc:xyz
revision:    bafy...
version:     3
records:     1,247
collections:
  app.bsky.feed.post:    823
  app.bsky.feed.like:    312
  app.bsky.actor.profile: 1
  ...
```

Exercises: `shrike-car` (CAR reader), `shrike-cbor` (commit/record
decoding), `shrike-repo` (commit structure).

#### `rat repo ls <car-file> [collection]`

List records in a local CAR file, optionally filtered by collection.

Flags: `--json`

Default output:
```
app.bsky.feed.post/3k...  bafy...
app.bsky.feed.post/3k...  bafy...
```

Exercises: `shrike-car`, `shrike-cbor`.

#### `rat validate <collection> <json-file>`

Validate a JSON record against a Lexicon schema.

Flags: `--json`, `--lexdir <path>`

If `--lexdir` is omitted, looks for `./lexicons` then `../atmos/lexicons`.

Default output:
```
valid
```

Or on error:
```
invalid
  error: field "text" is required (at /record/text)
```

Exercises: `shrike-lexicon` (schema loading, catalog, validation).

### Layer 2: Session Management

#### `rat account login <identifier> <password>`

Login via `com.atproto.server.createSession`. Saves session to
`~/.config/rat/session.json`.

Flags: `--host <url>` (default: `https://bsky.social`)

Output:
```
logged in as alice.bsky.social (did:plc:xyz)
```

#### `rat account logout`

Calls `com.atproto.server.deleteSession` (best-effort), then deletes
`session.json`.

Output:
```
logged out
```

#### `rat account status`

Display current session info from the stored session file.

Flags: `--json`

Default output:
```
host:    https://bsky.social
handle:  alice.bsky.social
did:     did:plc:xyz
```

If not logged in: `not logged in` to stderr, exit 1.

### Layer 3: Authenticated Commands & Streaming

#### `rat repo export <did-or-handle>`

Download a repository as a CAR file via
`com.atproto.sync.getRepo`.

Flags: `-o, --output <file>` (default: `<did>.car`)

Output:
```
exported did:plc:xyz to did:plc:xyz.car (2.3 MB)
```

Exercises: `shrike-xrpc` (authenticated binary download),
`shrike-syntax` (DID parsing).

#### `rat record get <at-uri>`

Fetch a single record by AT-URI via `com.atproto.repo.getRecord`.

Output: pretty-printed JSON of the record to stdout.

Exercises: `shrike-xrpc`, `shrike-syntax` (AT-URI parsing),
`shrike-api`.

#### `rat record list <did-or-handle> [collection]`

List records for a repo. If no collection is given, list collections
first (via `com.atproto.repo.describeRepo`), then list records within.

Flags: `--limit <n>` (default: 50), `--json`

Default output:
```
at://did:plc:xyz/app.bsky.feed.post/3k...  bafy...
at://did:plc:xyz/app.bsky.feed.post/3k...  bafy...
```

Exercises: `shrike-xrpc`, `shrike-syntax`, `shrike-api`.

#### `rat subscribe`

Stream live events from a WebSocket endpoint.

Flags:
- `--url <ws-url>` (default: `wss://bsky.network/xrpc/com.atproto.sync.subscribeRepos`)
- `--cursor <int>` — resume from cursor position
- `--collection <nsid>` — filter by collection
- `--action <create|update|delete>` — filter by action

Output: one compact JSON object per line to stdout. Ctrl-C to stop.

Exercises: `shrike-streaming` (WebSocket, event parsing, filtering).

## Output Conventions

- Default: plain text, human-readable, one value per line with labeled fields
- `--json`: pretty-printed JSON (2-space indent) to stdout
- Errors to stderr, exit code 1
- No colors, no TUI

## Session Management

**Storage location:** `~/.config/rat/session.json` (via `dirs::config_dir()`)

**File permissions:** 0o600 (owner read/write only)

**Session file format:**
```json
{
  "host": "https://bsky.social",
  "access_jwt": "...",
  "refresh_jwt": "...",
  "handle": "alice.bsky.social",
  "did": "did:plc:..."
}
```

**Behavior:**
- Directory created on first `login` if it doesn't exist
- `logout` always deletes the local file, server-side deletion is best-effort
- No automatic token refresh — if access token expires, user logs in again
- Authenticated commands that find no session file print
  `error: not logged in (run 'rat account login' first)` and exit 1

## Error Handling

- `anyhow::Result` throughout (application, not library)
- `.context()` on fallible operations for clear error chains
- Stub commands (before implementation) print
  `error: not yet implemented` to stderr and exit 1

## Implementation Layers

**Layer 1** — all no-auth commands fully working. This exercises:
`shrike-syntax`, `shrike-crypto`, `shrike-identity`, `shrike-car`,
`shrike-cbor`, `shrike-repo`, `shrike-lexicon`, `shrike-xrpc`.

**Layer 2** — `account login/logout/status` with session persistence.
This adds: session.json management, `shrike-xrpc` auth, `shrike-api`
(createSession/deleteSession).

**Layer 3** — authenticated commands and streaming. This adds:
`shrike-streaming`, authenticated XRPC calls.

## Crate Coverage

| Crate | Exercised by |
|-------|-------------|
| `shrike-syntax` | syntax, resolve, record, repo export |
| `shrike-crypto` | key generate, key inspect |
| `shrike-cbor` | repo inspect, repo ls |
| `shrike-car` | repo inspect, repo ls |
| `shrike-lexicon` | validate |
| `shrike-identity` | resolve, plc resolve |
| `shrike-xrpc` | plc history, account, record, repo export |
| `shrike-streaming` | subscribe |
| `shrike-api` | account, record get, record list |
| `shrike-repo` | repo inspect |

Not directly exercised (server-side/batch concerns):
`shrike-mst` (used internally by repo), `shrike-sync`,
`shrike-backfill`, `shrike-labeling`, `shrike-xrpc-server`.
