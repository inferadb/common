# inferadb-storage-ledger

Ledger-backed implementation of `StorageBackend` for InferaDB.

## Overview

This crate provides `LedgerBackend`, a production-grade storage backend that implements the `StorageBackend` trait using InferaDB Ledger's blockchain database. This enables both Engine and Control services to use Ledger as their storage layer through a unified interface.

## Features

- **Unified storage**: Single implementation serves both Engine and Control
- **Cryptographic verification**: All data backed by Merkle proofs
- **Automatic idempotency**: Built-in duplicate detection via SDK
- **Strong consistency**: Linearizable reads available
- **TTL support**: Automatic key expiration via Ledger's native TTL
- **Transaction support**: Atomic multi-key operations

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                     Repository Layer                        │
│  OrganizationRepository │ VaultRepository │ RelationshipRepo│
├─────────────────────────────────────────────────────────────┤
│                   LedgerBackend                              │
│         (implements StorageBackend trait)                    │
├─────────────────────────────────────────────────────────────┤
│                   Ledger SDK                                 │
│   LedgerClient │ SequenceTracker │ ConnectionPool           │
├─────────────────────────────────────────────────────────────┤
│                   Ledger Service                             │
│   Blockchain consensus │ Merkle trees │ Replication         │
└─────────────────────────────────────────────────────────────┘
```

## Quick Start

```rust
use inferadb_storage_ledger::{LedgerBackend, LedgerBackendConfig};
use inferadb_storage::StorageBackend;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config = LedgerBackendConfig::builder()
        .with_endpoint("http://localhost:50051")
        .with_client_id("my-service")
        .with_namespace_id(1)
        .build()?;

    let backend = LedgerBackend::new(config).await?;

    // Use like any other StorageBackend
    backend.set(b"key".to_vec(), b"value".to_vec()).await?;
    let value = backend.get(b"key").await?;

    Ok(())
}
```

## Configuration

### Builder API

```rust
let config = LedgerBackendConfig::builder()
    .with_endpoint("http://localhost:50051")
    .with_client_id("engine-prod-001")
    .with_namespace_id(1)
    .with_vault_id(100)                    // Optional
    .with_timeout(Duration::from_secs(30)) // Optional
    .with_read_consistency(ReadConsistency::Linearizable) // Optional
    .build()?;
```

### Configuration Options

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `endpoint` | Yes | - | Ledger server URL (e.g., `http://localhost:50051`) |
| `client_id` | Yes | - | Unique client ID for idempotency tracking |
| `namespace_id` | Yes | - | Namespace ID for data scoping |
| `vault_id` | No | None | Vault ID for finer-grained scoping |
| `timeout` | No | 30s | Request timeout |
| `connect_timeout` | No | 10s | Connection timeout |
| `read_consistency` | No | Linearizable | Read consistency level |
| `compression` | No | false | Enable gRPC compression |

## Key Mapping

The backend maps byte keys to Ledger's string-based entity keys using hex encoding to preserve ordering:

| StorageBackend | Ledger SDK |
|----------------|------------|
| `get(key)` | `client.read_consistent(ns, vault, hex(key))` |
| `set(key, value)` | `client.write([SetEntity { key: hex(key), value }])` |
| `delete(key)` | `client.write([DeleteEntity { key: hex(key) }])` |
| `get_range(start..end)` | `client.list_entities(prefix)` + filter |
| `set_with_ttl(key, value, ttl)` | `SetEntity { expires_at: now + ttl }` |

## Consistency Model

By default, this backend uses **linearizable (strong) consistency** for reads to ensure correctness for authorization decisions. This guarantees:

- Reads always see the latest committed writes
- No stale data for permission checks
- Suitable for security-critical operations

For read-heavy workloads where staleness is acceptable, configure eventual consistency:

```rust
let config = LedgerBackendConfig::builder()
    .with_endpoint("http://localhost:50051")
    .with_client_id("my-service")
    .with_namespace_id(1)
    .with_read_consistency(ReadConsistency::Eventual)
    .build()?;
```

## Transactions

Transactions provide atomic multi-key operations with read-your-writes semantics:

```rust
let mut txn = backend.transaction().await?;

// Read-your-writes: reads see buffered writes
txn.set(b"key1".to_vec(), b"value1".to_vec());
txn.set(b"key2".to_vec(), b"value2".to_vec());

// Get sees the pending write
let value = txn.get(b"key1").await?;

// Commit atomically
txn.commit().await?;
```

## Error Handling

Ledger SDK errors are mapped to `StorageError`:

| Ledger Error | StorageError |
|--------------|--------------|
| Connection failed | `Connection` |
| Request timeout | `Timeout` |
| Key not found | `NotFound` |
| Transaction conflict | `Conflict` |
| Invalid argument | `Serialization` |
| Other errors | `Internal` |

## Integration Tests

Run integration tests against a real Ledger cluster:

```bash
# Start Ledger (requires Docker, run from this crate's directory)
cd docker
docker-compose -f docker-compose.integration.yml up -d

# Run tests
RUN_LEDGER_INTEGRATION_TESTS=1 cargo test -p inferadb-storage-ledger

# Cleanup
docker-compose -f docker-compose.integration.yml down
```

## License

Apache 2.0
