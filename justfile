# InferaDB Common development commands
# Requires: just (https://github.com/casey/just)

# Default recipe: show available commands
default:
    @just --list

# Rust toolchain versions
rust := "1.92"
nightly := "nightly"

# ============================================================================
# Build
# ============================================================================

# Build all crates
build:
    cargo +{{rust}} build --workspace --all-targets

# ============================================================================
# Test
# ============================================================================

# Run unit and property tests
test:
    cargo +{{rust}} test --workspace

# Run stress tests — concurrency and load (gated behind `stress` feature)
test-stress:
    cargo +{{rust}} test -p inferadb-common-storage --features stress --test concurrent_stress
    cargo +{{rust}} test -p inferadb-common-authn --features stress

# Run fail-point tests — deterministic fault injection (gated behind `failpoints` feature)
test-failpoints:
    cargo +{{rust}} test -p inferadb-common-storage --features failpoints
    cargo +{{rust}} test -p inferadb-common-authn --features failpoints,testutil

# Run integration tests — requires a running Ledger server (gated behind `integration` feature)
test-integration:
    cargo +{{rust}} test -p inferadb-common-storage-ledger --features integration --test real_ledger_integration -- --test-threads=1

# Run fuzz tests — JWT parsing and claims (requires cargo-fuzz and nightly)
fuzz duration="60":
    cd crates/authn && cargo +{{nightly}} fuzz run fuzz_jwt_parsing -- -max_total_time={{duration}}
    cd crates/authn && cargo +{{nightly}} fuzz run fuzz_jwt_claims -- -max_total_time={{duration}}

# ============================================================================
# Code Quality
# ============================================================================

# Format code (requires nightly)
fmt:
    cargo +{{nightly}} fmt --all

# Check formatting without modifying files
fmt-check:
    cargo +{{nightly}} fmt --all -- --check

# Run clippy linter
clippy:
    cargo +{{rust}} clippy --workspace --all-targets -- -D warnings

# Run all checks (build + clippy + test + format) — use before committing
check: build clippy test fmt-check

# CI validation: build + clippy + test + format
ci: check

# ============================================================================
# Documentation
# ============================================================================

# Check documentation builds without warnings
doc-check:
    RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps

# ============================================================================
# Maintenance
# ============================================================================

# Clean build artifacts
clean:
    cargo clean

# Update dependencies to latest versions
update:
    ./scripts/update-dependencies.sh

# Check for unused dependencies (requires cargo-udeps)
udeps:
    cargo +{{nightly}} udeps --all-targets

# Run all checks including udeps and doc-check
check-all: check udeps doc-check
