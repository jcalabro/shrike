set shell := ["bash", "-cu"]

default: lint test

# Build everything
build:
    cargo build --workspace --features full

# Run all tests (uses nextest for parallel execution)
test:
    cargo nextest run --workspace --features full

# Run format check + clippy on library and test code
lint:
    cargo fmt --all -- --check
    cargo clippy --workspace --features full --tests -- -D warnings

# Format check
fmt:
    cargo fmt --all -- --check

# Run all checks (build + lint + test)
check: build lint test

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
    fuzz_dir="crates/shrike/fuzz"
    if [[ ! -d "$fuzz_dir" ]]; then
        echo "skip: no fuzz/ dir"
        exit 0
    fi
    targets=$(cd "$fuzz_dir" && cargo +nightly fuzz list 2>/dev/null || true)
    for t in $targets; do
        echo "=== FUZZ $t ==="
        (cd "$fuzz_dir" && cargo +nightly fuzz run "$t" -- -max_total_time={{DURATION}})
    done

# Copy lexicons from local atproto checkout
update-lexicons:
    rm -rf lexicons/*
    mkdir -p lexicons
    cp -r ../../../bluesky-social/atproto/lexicons/* lexicons

# Run benchmarks
bench:
    cargo bench -p shrike --features full

# Run the shrike CLI (pass args after --)
shrike *ARGS:
    cargo run -p shrike-cli --bin shrike -- {{ARGS}}

# Run the code generator
lexgen:
    cargo run --bin lexgen -- --lexdir lexicons --config lexgen.json

# Update lexicons and regenerate
update-api: update-lexicons lexgen

# Publish to crates.io (must be logged in with `cargo login`)
# Usage:
#   just publish           # publish
#   just publish --dry-run # preview what will be published
publish *ARGS:
    cargo publish -p shrike {{ARGS}}
