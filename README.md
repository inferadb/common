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

**InferaDB Common provides the storage abstraction layer, JWT authentication, and rate limiting used by [InferaDB Engine](https://github.com/inferadb/engine) and [InferaDB Control](https://github.com/inferadb/control).** It defines a pluggable `StorageBackend` trait for persistent storage, a hardened EdDSA-only JWT validator with three-tier key caching, and a distributed fixed-window rate limiter.

- [Crates](#crates)
- [Quick Start](#quick-start)
- [Usage](#usage)
- [Contributing](#contributing)
- [Community](#community)
- [License](#license)

## Crates

| Crate                                                     | Description                                                                                           |
| --------------------------------------------------------- | ----------------------------------------------------------------------------------------------------- |
| [`inferadb-common-storage`](crates/storage)               | Storage backend trait, in-memory implementation, batch writer, metrics, rate limiting, size limits    |
| [`inferadb-common-storage-ledger`](crates/storage-ledger) | [Ledger](https://github.com/inferadb/ledger)-backed storage with retry, timeout, circuit breaker, CAS |
| [`inferadb-common-authn`](crates/authn)                   | JWT validation, signing key cache, replay detection, audit logging                                    |
| [`inferadb-common-ratelimit`](crates/ratelimit)           | Distributed fixed-window rate limiter backed by any `StorageBackend`                                  |

## Quick Start

```bash
git clone https://github.com/inferadb/common.git
cd common
mise trust && mise install
just build
just test
```

## Usage

### In-Memory Backend (Testing)

```rust
use inferadb_common_storage::{MemoryBackend, StorageBackend, to_storage_range};

let backend = MemoryBackend::new();

backend.set(b"key".to_vec(), b"value".to_vec()).await?;
let value = backend.get(b"key").await?;
backend.delete(b"key").await?;

let entries = backend
    .get_range(to_storage_range(b"prefix:".to_vec()..b"prefix:\xff".to_vec()))
    .await?;
```

### Ledger Backend (Production)

```rust
use inferadb_common_storage_ledger::{
    ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
};

let client = ClientConfig::builder()
    .servers(ServerSource::from_static(["http://ledger.example.com:50051"]))
    .client_id("my-service")
    .build()?;

let config = LedgerBackendConfig::builder()
    .client(client)
    .organization(1)
    .build()?;

let backend = LedgerBackend::new(config).await?;
```

### JWT Validation

```rust
use std::sync::Arc;
use std::time::Duration;
use inferadb_common_authn::{SigningKeyCache, jwt::verify_with_signing_key_cache};
use inferadb_common_storage::auth::MemorySigningKeyStore;

let store = Arc::new(MemorySigningKeyStore::new());
let cache = SigningKeyCache::new(store, Duration::from_secs(300));

let claims = verify_with_signing_key_cache(token, &cache).await?;
println!("org: {}", claims.org.unwrap_or_default());
```

### Rate Limiting

```rust
use inferadb_common_storage::MemoryBackend;
use inferadb_common_ratelimit::{AppRateLimiter, RateLimitPolicy, RateLimitOutcome};

let limiter = AppRateLimiter::new(MemoryBackend::new());

let policy = RateLimitPolicy::per_hour(100)?;
let outcome = limiter.check("login_ip", "192.168.1.1", &policy).await?;
if let RateLimitOutcome::Allowed { remaining, .. } = outcome {
    println!("{remaining} requests remaining");
}
```

## Contributing

### Prerequisites

- Rust 1.92+ and nightly
- [mise](https://mise.jdx.dev/) for synchronized development tooling
- [just](https://github.com/casey/just) for development commands

### Build and Test

```bash
just build
just test
just check   # build + clippy + test + format
```

### Additional Test Suites

```bash
just test-failpoints    # deterministic fault injection
just test-stress        # concurrency stress tests
just test-integration   # requires a running Ledger server
just fuzz               # JWT parsing fuzz targets (requires cargo-fuzz)
```

See the [Contributing Guide](../CLAUDE.md) for commit conventions and PR process.

## Community

Join us on [Discord](https://discord.gg/inferadb) for questions and discussions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
