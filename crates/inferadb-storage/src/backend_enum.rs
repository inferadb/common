//! Unified backend enum for InferaDB storage
//!
//! This module provides the [`Backend`] enum, a unified type that can represent
//! any available storage backend implementation. This enables runtime selection
//! of backends while maintaining static dispatch for performance.
//!
//! # Available Backends
//!
//! | Variant | Use Case |
//! |---------|----------|
//! | [`Backend::Memory`] | Testing, development |
//!
//! For production use with Ledger, see `inferadb-control-storage::Backend` which
//! extends this pattern with additional backend types.
//!
//! # Usage
//!
//! ```
//! use inferadb_storage::{Backend, MemoryBackend, StorageBackend};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Create a memory backend for testing
//! let backend = Backend::Memory(MemoryBackend::new());
//!
//! // Use it like any StorageBackend
//! backend.set(b"key".to_vec(), b"value".to_vec()).await?;
//! let value = backend.get(b"key").await?;
//! # Ok(())
//! # }
//! ```
//!
//! # Extending with Additional Backends
//!
//! Higher-level crates can create their own Backend enum that includes both
//! this crate's backends and additional ones like `LedgerBackend`:
//!
//! ```ignore
//! pub enum Backend {
//!     Memory(inferadb_storage::MemoryBackend),
//!     Ledger(inferadb_storage_ledger::LedgerBackend),
//! }
//! ```

use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{MemoryBackend, StorageBackend, StorageResult, Transaction, types::KeyValue};

/// Unified storage backend enum
///
/// This enum wraps available backend implementations, enabling runtime
/// selection while maintaining type safety. Use this when you need to choose
/// between backends at runtime (e.g., based on configuration).
///
/// For production deployments with Ledger support, use the extended Backend
/// enum from `inferadb-control-storage` which includes the Ledger variant.
#[derive(Clone)]
pub enum Backend {
    /// In-memory backend for testing and development
    Memory(MemoryBackend),
}

impl Backend {
    /// Create a new memory backend
    #[must_use]
    pub fn memory() -> Self {
        Self::Memory(MemoryBackend::new())
    }

    /// Returns true if this is a memory backend
    #[must_use]
    pub fn is_memory(&self) -> bool {
        matches!(self, Self::Memory(_))
    }
}

#[async_trait]
impl StorageBackend for Backend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        match self {
            Self::Memory(b) => b.get(key).await,
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        match self {
            Self::Memory(b) => b.set(key, value).await,
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        match self {
            Self::Memory(b) => b.delete(key).await,
        }
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Self::Memory(b) => b.get_range(range).await,
        }
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        match self {
            Self::Memory(b) => b.clear_range(range).await,
        }
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        match self {
            Self::Memory(b) => b.set_with_ttl(key, value, ttl_seconds).await,
        }
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        match self {
            Self::Memory(b) => b.transaction().await,
        }
    }

    async fn health_check(&self) -> StorageResult<()> {
        match self {
            Self::Memory(b) => b.health_check().await,
        }
    }
}

impl std::fmt::Debug for Backend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Memory(_) => write!(f, "Backend::Memory"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_memory_backend_via_enum() {
        let backend = Backend::memory();
        assert!(backend.is_memory());

        backend
            .set(b"test_key".to_vec(), b"test_value".to_vec())
            .await
            .expect("set failed");

        let value = backend.get(b"test_key").await.expect("get failed");
        assert_eq!(value.map(|b| b.to_vec()), Some(b"test_value".to_vec()));
    }

    #[tokio::test]
    async fn test_health_check() {
        let backend = Backend::memory();
        backend.health_check().await.expect("health check failed");
    }

    #[tokio::test]
    async fn test_debug_impl() {
        let backend = Backend::memory();
        let debug_str = format!("{:?}", backend);
        assert_eq!(debug_str, "Backend::Memory");
    }
}
