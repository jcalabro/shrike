# Publishing Shrike to crates.io

This guide covers the process for releasing shrike to the Rust package registry.

## Prerequisites

1. **Rust toolchain**: Latest stable version
2. **crates.io account**: Create one at https://crates.io
3. **API token**: Generate at https://crates.io/me
4. **Git access**: Commit and tag permissions on the repository

## Pre-Release Checklist

- [ ] All tests passing: `cargo test --workspace`
- [ ] All clippy checks pass: `cargo clippy --workspace -- -D warnings`
- [ ] Code is formatted: `cargo fmt --all`
- [ ] CI is green on main branch
- [ ] Update version numbers in all `Cargo.toml` files (currently 0.1.0)
- [ ] Update CHANGELOG (if you have one)
- [ ] Review git log since last release

## Step 1: Authenticate with crates.io

```bash
cargo login
```

Paste your crates.io API token when prompted. This creates `~/.cargo/credentials.toml`.

## Step 2: Update Versions

All crates share the same version in the workspace. Edit `Cargo.toml`:

```toml
[workspace.package]
version = "0.2.0"  # Update this
```

This automatically applies to all member crates via `version.workspace = true`.

## Step 3: Verify Everything

Run the full test suite:

```bash
just check  # Build + lint + test
```

Or individually:

```bash
cargo build --workspace
cargo test --workspace
cargo clippy --workspace -- -D warnings
cargo fmt --all -- --check
```

## Step 4: Publish to crates.io

### Option A: Using the convenience command (recommended)

```bash
just publish
```

This publishes all 16 crates in the correct dependency order with appropriate delays.

### Option B: Dry run (preview without uploading)

```bash
just publish --dry-run
```

This performs all checks but doesn't upload. Good for verifying documentation, metadata, etc.

### Option C: Manual publishing

Publish in this exact order:

```bash
cargo publish -p shrike-syntax
cargo publish -p shrike-cbor
cargo publish -p shrike-crypto
cargo publish -p shrike-mst
cargo publish -p shrike-car
cargo publish -p shrike-lexicon
cargo publish -p shrike-xrpc
cargo publish -p shrike-xrpc-server
cargo publish -p shrike-labeling
cargo publish -p shrike-identity
cargo publish -p shrike-streaming
cargo publish -p shrike-sync
cargo publish -p shrike-backfill
cargo publish -p shrike-oauth
cargo publish -p shrike-api
cargo publish -p shrike
```

## Step 5: Create a Git Tag

After successful publishing:

```bash
git tag -a v0.2.0 -m "Release v0.2.0"
git push origin v0.2.0
```

This signals the release to GitHub and archive services.

## Step 6: Verify on crates.io

- Visit https://crates.io/crates/shrike
- Check that documentation built: https://docs.rs/shrike
- Verify all crate versions are updated

## Dependency Publishing Order

The publish order is critical because crates depend on each other:

```
shrike-syntax (independent)
↓
shrike-cbor → syntax
shrike-crypto → cbor
shrike-mst → cbor
shrike-lexicon → syntax
↓
shrike-car → cbor
shrike-xrpc → syntax, cbor
shrike-xrpc-server → syntax, cbor
↓
shrike-identity → syntax, crypto, xrpc
shrike-streaming → syntax, cbor
shrike-sync → syntax, cbor, mst, repo, car, identity, xrpc
↓
shrike-labeling → syntax, cbor, crypto
shrike-oauth → crypto, identity, syntax
shrike-backfill → sync, xrpc
shrike-api → syntax, cbor, xrpc
↓
shrike (facade) — depends on all of the above
```

## Troubleshooting

### "crate already published with this version"

You've already published this version. Bump the version number and try again.

### "failed to authenticate"

Your API token may have expired or been revoked. Run `cargo login` again.

### "documentation failed to build"

docs.rs failed to build documentation for your crate. Check:
- Missing `//!` module-level docs
- Broken doc links (use `cargo doc --document-private-items` locally)
- Missing dependencies in `[lib]` vs `[package]` metadata

### "yank this version"

If you publish a broken version, you can yank it (hide it) without deleting:

```bash
cargo yank -p shrike --vers 0.2.0
```

This prevents new projects from depending on it while keeping existing projects working.

## Post-Release

1. **Announce the release** in relevant channels (GitHub, Discord, etc.)
2. **Update documentation** with new features
3. **Add release notes** to CHANGELOG
4. **Bump version** to next development version

## Release Frequency

Shrike follows semantic versioning:
- `0.1.0` → `0.2.0`: Minor changes to a pre-1.0 API
- `1.0.0` → `1.1.0`: New backwards-compatible features
- `1.0.0` → `1.0.1`: Bug fixes
- `1.0.0` → `2.0.0`: Breaking API changes

## CI/CD Integration

Publishing is manual but the following can be automated:
- Running `just publish` from CI after tagging
- Auto-generating GitHub release notes from CHANGELOG
- Building and uploading docs

Consider adding GitHub Actions workflows for:
```yaml
on:
  push:
    tags:
      - 'v*'
jobs:
  publish:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: just publish --token ${{ secrets.CARGO_REGISTRY_TOKEN }}
```

## References

- [Cargo Book: Publishing](https://doc.rust-lang.org/cargo/reference/publishing.html)
- [crates.io Help](https://crates.io/me)
- [docs.rs Build Process](https://docs.rs/about/metadata)
