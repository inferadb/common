<div align="center">
    <p><a href="https://inferadb.com"><img src=".github/inferadb.png" width="100" alt="InferaDB Logo" /></a></p>
    <h1>InferaDB Common</h1>
    <p>
        <a href="https://discord.gg/inferadb"><img src="https://img.shields.io/badge/Discord-Join%20us-5865F2?logo=discord&logoColor=white" alt="Discord" /></a>
        <a href="#license"><img src="https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg" alt="License" /></a>
        <a href="https://github.com/inferadb/common/actions"><img src="https://img.shields.io/github/actions/workflow/status/inferadb/common/ci.yml?branch=main" alt="CI" /></a>
        <a href="https://crates.io/crates/inferadb-common-storage"><img src="https://img.shields.io/crates/v/inferadb-common-storage.svg" alt="crates.io" /></a>
    </p>
    <p><b>Shared storage abstractions for InferaDB services.</b></p>
</div>

> [!IMPORTANT]
> Under active development. Not production-ready.

This repository provides the storage abstraction layer used by [InferaDB Engine](https://github.com/inferadb/engine) and [InferaDB Control](https://github.com/inferadb/control). It defines a common interface for persistent storage with pluggable backends.

- [Crates](#crates)
- [Installation](#installation)
- [Usage](#usage)
- [Contributing](#contributing)
- [Community](#community)
- [License](#license)

## Crates

| Crate                                                                                       | Description                                                                |
| ------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------- |
| [`inferadb-common-storage`](https://crates.io/crates/inferadb-common-storage)               | Storage backend trait and in-memory implementation                         |
| [`inferadb-common-storage-ledger`](https://crates.io/crates/inferadb-common-storage-ledger) | [Ledger](https://github.com/inferadb/ledger)-backed storage implementation |

## Installation

```bash
cargo add inferadb-common-storage
cargo add inferadb-common-storage-ledger
```

## Usage

```rust
use inferadb_common_storage::{StorageBackend, MemoryBackend};

// Create an in-memory backend (useful for testing)
let backend = MemoryBackend::new();

// Basic operations
backend.set(b"key", b"value").await?;
let value = backend.get(b"key").await?;
backend.delete(b"key").await?;

// Range queries
let entries = backend.get_range(b"prefix:", b"prefix:\xff").await?;

// Transactions
let mut tx = backend.transaction();
tx.set(b"key1", b"value1");
tx.set(b"key2", b"value2");
tx.commit().await?;
```

For production use with cryptographic auditability, use the Ledger backend:

```rust
use inferadb_common_storage_ledger::{LedgerBackend, LedgerBackendConfig};

let config = LedgerBackendConfig::builder()
    .servers(["http://ledger.example.com:50051"])
    .build();

let backend = LedgerBackend::new(config).await?;
```

## Contributing

### Prerequisites

- Rust 1.92+
- [mise](https://mise.jdx.dev/) for synchronized development tooling
- [just](https://github.com/casey/just) for convenient development commands

### Build and Test

```bash
git clone https://github.com/inferadb/common.git
cd common

# Install development tools
mise trust && mise install

# Build
just build

# Run tests
just test

# Full check (build + clippy + test + format)
just check
```

## Community

Join us on [Discord](https://discord.gg/inferadb) for questions and discussions.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache 2.0](LICENSE-APACHE).
