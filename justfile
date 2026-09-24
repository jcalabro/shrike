set shell := ["bash", "-cu"]

# Run the `lint` and `test` commands
default: lint test

# Run all checks (build + lint + tests + doctests)
check: build lint test test-docs

# Start the local nix development environment
dev:
    nix --extra-experimental-features "nix-command flakes" develop

# Build everything
build *ARGS:
    cargo build --workspace --features full {{ARGS}}

# Build browser-ready WebAssembly plus JavaScript/TypeScript bindings.
wasm:
    wasm-pack build wasm --target web --release --out-dir pkg
    gzip -9 -k -f wasm/pkg/shrike_wasm_bg.wasm

# Type-check the complete browser-safe Shrike feature set.
wasm-check:
    cargo check -p shrike-wasm --target wasm32-unknown-unknown

# Run the platform-independent binding tests in wasm-bindgen's Node runner.
test-wasm:
    wasm-pack test --node wasm

# Run unit and integration tests
test:
    cargo test --workspace --features full --lib --bins --tests

# Run Rust documentation examples
test-docs:
    cargo test --doc -p shrike --all-features

# Run format check + clippy on library and test code
lint:
    cargo fmt --all -- --check
    # `cargo publish` verifies the library's default feature set without tests.
    cargo clippy -p shrike --lib -- -D warnings
    cargo clippy --workspace --features full --tests -- -D warnings

# Format check
fmt:
    cargo fmt --all -- --check

# Seed the fuzz corpora with valid, real-shaped inputs (fast; idempotent).
fuzz-seed:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d "fuzz" ]]; then
        echo "error: no fuzz/ directory" >&2
        exit 1
    fi
    (cd fuzz && cargo run --quiet --bin gen_seeds)

# Runs fuzz tests for the given duration (default 30s per target).
# Targets are ordered by attack surface: network-facing binary parsers first,
# then user-facing string parsers, then lower-risk targets.
#
# Usage:
#   just fuzz              # all targets, 30s each
#   just fuzz 10           # all targets, 10s each
fuzz DURATION="30":
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ ! -d "fuzz" ]]; then
        echo "error: no fuzz/ directory" >&2
        exit 1
    fi
    # Exclude gen_seeds (a helper binary, not a fuzz target).
    targets=$(cargo +nightly fuzz list | grep -v '^gen_seeds$')
    if [[ -z "$targets" ]]; then
        echo "error: no fuzz targets found" >&2
        exit 1
    fi
    for t in $targets; do
        echo "=== FUZZ $t ==="
        cargo +nightly fuzz run "$t" -- -max_total_time={{DURATION}}
    done

# Regenerates all API types from the cached lexicon schemas
lexgen:
    test -d lexicons || { echo "lexicon cache is absent; run just update-lexicons" >&2; exit 1; }
    cargo run -p lexgen --bin lexgen -- --lexdir lexicons --config lexgen.json

# Fetches, caches, and generates from the latest upstream lexicons.
#
# `lexgen.lock` records the immutable upstream commits used to generate the
# checked-in API. The bsky repository is authoritative for the app.bsky and
# chat.bsky namespaces; atproto supplies every other namespace.
update-lexicons:
    ./scripts/update-lexicons.sh

# Run benchmarks
bench:
    cargo bench -p shrike --features full

# Run the shrike CLI (pass args after --)
shrike *ARGS:
    cargo run -p shrike-cli --bin shrike-cli -- {{ARGS}}

# Explicit production smoke test for the Jetstream v2 client. This is never run
# by `just test` or `just check`; it hits a live server and must be invoked by
# hand. It requires a reachable host and an API key, and replays a small,
# bounded, filtered snapshot, printing only progress stats — no event payloads
# or credentials are recorded.
#
# Usage:
#   JETSTREAM_HOST=jetstream.us-east.bsky.network \
#   JETSTREAM_API_KEY=... \
#   just jetstream-smoke <after_seq> <before_seq>
jetstream-smoke AFTER BEFORE:
    #!/usr/bin/env bash
    set -euo pipefail
    : "${JETSTREAM_HOST:?set JETSTREAM_HOST to a reachable Jetstream v2 host}"
    : "${JETSTREAM_API_KEY:?set JETSTREAM_API_KEY to an archive access key}"
    cargo run -p shrike-cli --bin shrike-cli -- jetstream \
        --host "$JETSTREAM_HOST" \
        --collection app.bsky.feed.post \
        --after-seq "{{AFTER}}" --before-seq "{{BEFORE}}" \
        --snapshot-only --stats

# Publish to crates.io (must be logged in with `cargo login`)
# Usage:
#   just publish           # publish
#   just publish --dry-run # preview what will be published
publish *ARGS: check
    cargo publish -p shrike {{ARGS}}
