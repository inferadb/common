# inferadb-common-storage

Shared storage backend abstraction for InferaDB services.

## Overview

This crate provides the `StorageBackend` trait and related types that form the foundation for all storage operations in InferaDB. Both the Engine and Control services use this abstraction, enabling a unified storage layer across the platform.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Service Layer                            │
│         (Engine API handlers, Control API handlers)         │
├─────────────────────────────────────────────────────────────┤
│                   Repository Layer                          │
│  RelationshipRepository │ OrganizationRepository │ etc.     │
│         (Domain logic, serialization, indexing)             │
├─────────────────────────────────────────────────────────────┤
│                 inferadb-common-storage                     │
│              StorageBackend trait                           │
│    (get, set, delete, get_range, transaction)               │
├──────────────┬──────────────┬───────────────────────────────┤
│ MemoryBackend│       LedgerBackend           │
│   (testing)  │    (production)               │
└──────────────┴───────────────────────────────┘
```

## Quick Start

```rust
use inferadb_common_storage::{MemoryBackend, StorageBackend};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create an in-memory backend for testing
    let backend = MemoryBackend::new();

    // Store a value
    backend.set(b"user:123".to_vec(), b"Alice".to_vec()).await?;

    // Retrieve it
    let value = backend.get(b"user:123").await?;
    assert_eq!(value.map(|b| b.to_vec()), Some(b"Alice".to_vec()));

    // Use transactions for atomic operations
    let mut txn = backend.transaction().await?;
    txn.set(b"counter".to_vec(), b"1".to_vec());
    txn.set(b"updated".to_vec(), b"true".to_vec());
    txn.commit().await?;

    Ok(())
}
```

## Available Backends

| Backend | Crate | Use Case | Persistence |
|---------|-------|----------|-------------|
| `MemoryBackend` | `inferadb-common-storage` | Testing, development | No |
| `LedgerBackend` | `inferadb-common-storage-ledger` | Production | Yes |

## Core Traits

### StorageBackend

The main trait that all storage backends implement:

```rust
#[async_trait]
pub trait StorageBackend: Send + Sync + Clone + 'static {
    /// Get a value by key
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Set a key-value pair
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>;

    /// Delete a key
    async fn delete(&self, key: &[u8]) -> StorageResult<()>;

    /// Get a range of key-value pairs
    async fn get_range(&self, range: Range<Vec<u8>>) -> StorageResult<Vec<KeyValue>>;

    /// Clear all keys in a range
    async fn clear_range(&self, range: Range<Vec<u8>>) -> StorageResult<()>;

    /// Set a value with TTL (time-to-live)
    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()>;

    /// Begin a transaction
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>>;

    /// Check backend health
    async fn health_check(&self) -> StorageResult<bool>;
}
```

### Transaction

Provides atomic multi-key operations:

```rust
#[async_trait]
pub trait Transaction: Send + Sync {
    /// Get a value within the transaction
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Set a value (buffered until commit)
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>);

    /// Delete a key (buffered until commit)
    fn delete(&mut self, key: &[u8]);

    /// Commit all buffered operations atomically
    async fn commit(self: Box<Self>) -> StorageResult<()>;
}
```

## Error Handling

All operations return `StorageResult<T>`, which wraps `StorageError`:

| Error Variant | Description |
|---------------|-------------|
| `NotFound` | Key does not exist |
| `Conflict` | Transaction conflict or duplicate key |
| `Connection` | Backend connection failed |
| `Serialization` | Data serialization/deserialization failed |
| `Internal` | Internal backend error |
| `Timeout` | Operation timed out |

## Implementing a Backend

To implement a new storage backend:

1. Implement the `StorageBackend` trait
2. Implement a corresponding `Transaction` type
3. Map backend-specific errors to `StorageError`

See the `memory` module source for a reference implementation.

## License

Dual-licensed under MIT or Apache 2.0.
