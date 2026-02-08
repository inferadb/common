<div align="center">
    <p><a href="https://inferadb.com"><img src=".github/inferadb.png" width="100" alt="InferaDB Logo" /></a></p>
    <h1>InferaDB Common</h1>
    <p>
        <a href="https://discord.gg/inferadb"><img src="https://img.shields.io/badge/Discord-Join%20us-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
        <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License" /></a>
        <a href="https://github.com/inferadb/common/actions"><img src="https://img.shields.io/github/actions/workflow/status/inferadb/common/ci.yml?branch=main" alt="CI" /></a>
        <a href="https://crates.io/crates/inferadb-common-storage"><img src="https://img.shields.io/crates/v/inferadb-common-storage.svg" alt="crates.io" /></a>
    </p>
    <p><b>Shared storage abstractions and authentication for InferaDB services.</b></p>
</div>

> [!IMPORTANT]
> Under active development. Not production-ready.

This workspace provides the storage abstraction layer and JWT authentication library used by [InferaDB Engine](https://github.com/inferadb/engine) and [InferaDB Control](https://github.com/inferadb/control). It defines a common interface for persistent storage with pluggable backends and a hardened EdDSA-only JWT validator with three-tier key caching.

- [Overview](#overview)
- [Crates](#crates)
- [Prerequisites](#prerequisites)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Usage](#usage)
- [Development](#development)
- [Testing](#testing)
- [Benchmarks](#benchmarks)
- [Contributing](#contributing)
- [Community](#community)
- [License](#license)

## Overview

InferaDB Common consists of three crates that together provide:

- **Storage abstraction** (`StorageBackend` trait) with get, set, delete, range scans, compare-and-set, TTL, and transactions
- **In-memory backend** for testing and development
- **Ledger-backed backend** for production use with cryptographic auditability, retry/timeout, circuit breaking, and distributed tracing
- **JWT authentication** with EdDSA-only enforcement (per RFC 8725), three-tier key caching, replay detection, and key material zeroing

## Crates

| Crate                                            | Package                          | Description                                                                                           |
| ------------------------------------------------ | -------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [`crates/storage`](crates/storage)               | `inferadb-common-storage`        | Storage backend trait, in-memory implementation, batch writer, metrics, rate limiting, size limits    |
| [`crates/storage-ledger`](crates/storage-ledger) | `inferadb-common-storage-ledger` | [Ledger](https://github.com/inferadb/ledger)-backed storage with retry, timeout, circuit breaker, CAS |
| [`crates/authn`](crates/authn)                   | `inferadb-common-authn`          | JWT validation, signing key cache, replay detection, audit logging                                    |

## Prerequisites

- **Rust 1.92+** (stable) — for building and clippy
- **Rust nightly** — for `cargo fmt` only
- **[mise](https://mise.jdx.dev/)** — synchronized development tooling (`mise trust && mise install`)
- **[just](https://github.com/casey/just)** — task runner for common development commands
- **protobuf 29+** and **buf 1+** — for Ledger SDK proto compilation (installed via mise)

Install the Rust toolchains:

```bash
rustup install 1.92
rustup install nightly
```

## Quick Start

```bash
git clone https://github.com/inferadb/common.git
cd common
mise trust && mise install
just build
just test
```

That's it. `just check` runs the full CI suite (build + clippy + test + format check).

## Architecture

```text
inferadb-common-authn
  ├── inferadb-common-storage (PublicSigningKeyStore trait, error types)
  └── moka, jsonwebtoken, ed25519-dalek (JWT validation)

inferadb-common-storage-ledger
  ├── inferadb-common-storage (StorageBackend trait)
  └── inferadb-ledger-sdk (Ledger gRPC client)
```

### Key Abstractions

| Abstraction             | Location                         | Purpose                                                                    |
| ----------------------- | -------------------------------- | -------------------------------------------------------------------------- |
| `StorageBackend`        | `storage/src/backend.rs`         | Core trait — get, set, delete, range, CAS, TTL, transactions, health check |
| `Transaction`           | `storage/src/transaction.rs`     | Atomic multi-operation commit                                              |
| `MemoryBackend`         | `storage/src/memory.rs`          | In-memory implementation for tests                                         |
| `LedgerBackend`         | `storage-ledger/src/backend.rs`  | Production backend with retry, timeout, circuit breaker                    |
| `PublicSigningKeyStore` | `storage/src/auth/store.rs`      | Trait for key storage (memory and ledger implementations)                  |
| `SigningKeyCache`       | `authn/src/signing_key_cache.rs` | Three-tier cache: L1 (moka TTL) → L2 (Ledger) → L3 (bounded fallback)      |
| `JwtValidator`          | `authn/src/jwt.rs`               | EdDSA JWT validation with configurable claims, replay detection            |

### Data Flow

```text
JWT Request
  → JwtValidator::validate()
    → SigningKeyCache::get_decoding_key()
      → L1 (moka TTL cache, ~ms)
      → L2 (Ledger via PublicSigningKeyStore, ~10-100ms)
      → L3 (bounded fallback cache, disaster recovery)
    → signature verification (EdDSA only)
    → claims validation (exp, iat, aud, iss, kid)
    → replay detection (optional, JTI-based)
  → JwtClaims

Storage Operation
  → RateLimitedBackend (optional)
    → LedgerBackend
      → circuit breaker check
      → with_retry_timeout()
        → SDK call with W3C Trace Context
      → circuit breaker state update
```

### ID Newtypes

The workspace uses newtype wrappers for identifiers to prevent accidental mixing:

| Type          | Purpose                           |
| ------------- | --------------------------------- |
| `NamespaceId` | Tenant/namespace identifier       |
| `VaultId`     | Vault (key collection) identifier |
| `ClientId`    | API client identifier             |
| `CertId`      | Certificate identifier            |

## Usage

### In-Memory Backend (Testing)

```rust
use inferadb_common_storage::{StorageBackend, MemoryBackend};

let backend = MemoryBackend::new();

// Basic CRUD
backend.set(b"key".to_vec(), b"value".to_vec()).await?;
let value = backend.get(b"key").await?;
backend.delete(b"key").await?;

// Range queries
let entries = backend.get_range(b"prefix:".to_vec()..b"prefix:\xff".to_vec()).await?;

// Transactions
let mut tx = backend.transaction().await?;
tx.set(b"key1".to_vec(), b"value1".to_vec());
tx.set(b"key2".to_vec(), b"value2".to_vec());
tx.commit().await?;

// Compare-and-set
backend.set(b"counter".to_vec(), b"1".to_vec()).await?;
backend.compare_and_set(b"counter", Some(b"1".as_slice()), b"2".to_vec()).await?;
```

### Ledger Backend (Production)

```rust
use inferadb_common_storage_ledger::{LedgerBackend, LedgerBackendConfig};

let config = LedgerBackendConfig::builder()
    .servers(["http://ledger.example.com:50051"])
    .build()?;

let backend = LedgerBackend::new(config).await?;
```

### JWT Validation

```rust
use inferadb_common_authn::{verify_with_signing_key_cache, SigningKeyCache};

// Set up signing key cache with your key store
let cache = SigningKeyCache::new(key_store, l1_ttl, l3_capacity);

// Validate a JWT
let claims = verify_with_signing_key_cache(
    &token,
    &cache,
    &expected_audience,
    &expected_issuer,
).await?;

println!("org: {}, vault: {}", claims.org_id, claims.vault_id);
```

## Development

### Adding a New `StorageBackend` Implementation

1. Implement the `StorageBackend` trait from `inferadb-common-storage`
2. All 10 methods are required: `get`, `set`, `compare_and_set`, `delete`, `get_range`, `clear_range`, `set_with_ttl`, `transaction`, `health_check`
3. Run the conformance test suite against your implementation:

```rust
use inferadb_common_storage::conformance;

#[tokio::test]
async fn conformance() {
    let backend = MyBackend::new();
    conformance::run_all(&backend).await;
}
```

### Adding a New Error Variant

Error enums use `#[non_exhaustive]` and constructor methods:

1. Add the variant to the enum in the appropriate `error.rs` (include `span_id: Option<tracing::span::Id>`)
2. Add a constructor method that calls `current_span_id()` for automatic span capture
3. Update the manual `Display` impl
4. Update `is_transient()` classification
5. Update `detail()` if the variant carries internal context

### Code Style

- No `unsafe`, `.unwrap()`, `panic!()`, `todo!()`, `unimplemented!()`
- Builders via `bon` — use `#[builder(into)]` for `String` fields
- Fallible builders return `Result<Self, ConfigError>` with validation at construction
- Doc examples use ` ```no_run ` (skip execution, verify compilation)
- All errors carry optional `span_id` for distributed tracing correlation

## Testing

### Unit Tests

```bash
# Run all tests
just test

# Run tests for a specific crate
cargo +1.92 test -p inferadb-common-storage
cargo +1.92 test -p inferadb-common-authn
cargo +1.92 test -p inferadb-common-storage-ledger
```

### Property-Based Tests

The workspace uses `proptest` for property-based testing (key encoding round-trips, range bound normalization, size limit enforcement):

```bash
# Property tests run as part of the normal test suite
just test
```

### Fuzz Tests

JWT parsing fuzz targets live in `crates/authn/fuzz/`:

```bash
# Install cargo-fuzz
cargo install cargo-fuzz

# Run JWT parsing fuzzer
cd crates/authn
cargo +nightly fuzz run fuzz_jwt_parsing -- -max_total_time=60

# Run JWT claims fuzzer
cargo +nightly fuzz run fuzz_jwt_claims -- -max_total_time=60
```

### Fail-Point Tests

Deterministic fault injection tests are gated behind the `failpoints` feature:

```bash
cargo +1.92 test -p inferadb-common-storage --features failpoints
cargo +1.92 test -p inferadb-common-authn --features failpoints,testutil
```

### Stress Tests

Concurrency stress tests are `#[ignore]`-gated to avoid slowing CI:

```bash
# Run stress tests explicitly
cargo +1.92 test --all -- --ignored
```

### Integration Tests (Real Ledger)

Tests in `crates/storage-ledger/tests/real_ledger_integration.rs` require a running Ledger instance and are `#[ignore]`-gated:

```bash
# Start a local Ledger instance first, then:
cargo +1.92 test -p inferadb-common-storage-ledger -- --ignored
```

## Benchmarks

The `inferadb-common-storage` crate includes Criterion benchmarks:

```bash
# Run all benchmarks
cargo bench -p inferadb-common-storage

# Run a specific benchmark group
cargo bench -p inferadb-common-storage -- get_operations

# Save a baseline for comparison
cargo bench -p inferadb-common-storage -- --save-baseline main

# Compare against a baseline
cargo bench -p inferadb-common-storage -- --baseline main
```

### Benchmark Groups

| Group                    | Description                                             |
| ------------------------ | ------------------------------------------------------- |
| `get_operations`         | Single key lookups (existing, missing, varying sizes)   |
| `set_operations`         | Single key writes (new, overwrite, varying value sizes) |
| `delete_operations`      | Key deletion (existing, missing)                        |
| `get_range_operations`   | Range scans with varying result sizes                   |
| `clear_range_operations` | Range deletion with varying sizes                       |
| `transaction_operations` | Transaction commit with single/multiple operations      |
| `concurrent_operations`  | Parallel read/write workloads                           |
| `ttl_operations`         | Time-to-live key operations                             |
| `health_check`           | Backend health check overhead                           |

### Interpreting Results

```text
get_operations/get_existing_key
                        time:   [1.234 us 1.256 us 1.278 us]
                        change: [-2.34% +0.12% +2.56%] (p = 0.89 > 0.05)
                        No change in performance detected.
```

- **time**: [lower bound, estimate, upper bound] at 95% confidence
- **change**: percentage change from baseline
- **p-value**: p < 0.05 indicates statistically significant change

## Contributing

See the [Contributing Guide](https://github.com/inferadb/common/blob/main/../CLAUDE.md) for commit message conventions (Conventional Commits), PR process, and code of conduct.

### CI Checklist

Before submitting a PR, run the full check suite:

```bash
just check
```

This runs:

1. `cargo +1.92 build --all-targets` — compilation
2. `cargo +1.92 clippy --all-targets -- -D warnings` — lints (zero warnings)
3. `cargo +1.92 test --all` — all tests pass
4. `cargo +nightly fmt --check` — formatting

## Community

Join us on [Discord](https://discord.gg/inferadb) for questions and discussions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
