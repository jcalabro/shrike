set shell := ["bash", "-cu"]

default: lint test

# Build everything
build:
    cargo build --workspace

# Run all tests (uses nextest for parallel execution)
test:
    cargo nextest run --workspace

# Run format check + clippy on library and test code
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --tests -- -D warnings

# Format check
fmt:
    cargo fmt --all -- --check

# Run all checks (build + lint + test)
check: build lint test

# Run tests for a specific crate
test-crate crate:
    cargo test -p {{crate}}

# Runs fuzz tests for the given duration (default 30s per target).
# Crates are ordered by attack surface: network-facing binary parsers first,
# then user-facing string parsers, then lower-risk targets.
#
# Usage:
#   just fuzz              # all targets, 30s each
#   just fuzz 10           # all targets, 10s each
#   just fuzz 60 shrike-cbor  # only shrike-cbor, 60s each
fuzz DURATION="30" *CRATES="shrike-cbor shrike-car shrike-mst shrike-syntax shrike-crypto shrike-lexicon":
    #!/usr/bin/env bash
    set -euo pipefail
    for crate in {{CRATES}}; do
        fuzz_dir="crates/${crate}/fuzz"
        if [[ ! -d "$fuzz_dir" ]]; then
            echo "skip: no fuzz/ dir for $crate"
            continue
        fi
        targets=$(cd "$fuzz_dir" && cargo +nightly fuzz list 2>/dev/null || true)
        for t in $targets; do
            echo "=== FUZZ $t ($crate) ==="
            (cd "$fuzz_dir" && cargo +nightly fuzz run "$t" -- -max_total_time={{DURATION}})
        done
    done

# Copy lexicons from local atproto checkout
update-lexicons:
    rm -rf lexicons/*
    mkdir -p lexicons
    cp -r ../../../bluesky-social/atproto/lexicons/* lexicons

# Run benchmarks (optionally for a specific crate)
bench *CRATE:
    #!/usr/bin/env bash
    set -euo pipefail
    if [[ -z "{{CRATE}}" ]]; then
        cargo bench --workspace
    else
        cargo bench -p {{CRATE}}
    fi

# Run the shrike CLI (pass args after --)
shrike *ARGS:
    cargo run -p shrike-cli --bin shrike -- {{ARGS}}

# Run the code generator
lexgen:
    cargo run --bin lexgen -- --lexdir lexicons --config lexgen.json

# Update lexicons and regenerate
update-api: update-lexicons lexgen
