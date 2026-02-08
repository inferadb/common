//! Storage backend trait definition.
//!
//! This module defines the [`StorageBackend`] trait, which is the core abstraction
//! for key-value storage in InferaDB. All storage implementations (MemoryBackend,
//! LedgerBackend, etc.) implement this trait.
//!
//! # Design Philosophy
//!
//! The trait provides a minimal, generic key-value interface:
//! - **Keys and values are bytes**: No assumptions about serialization format
//! - **Async by default**: All operations are async for non-blocking I/O
//! - **Range queries supported**: Efficient prefix scans and ordered iteration
//! - **Transactional**: Atomic multi-key operations via transactions
//!
//! Domain-specific logic (e.g., organizations, relationships) lives in the
//! repository layer built on top of this trait, not in the storage backends.
//!
//! # Implementing a Backend
//!
//! To implement a new storage backend:
//!
//! 1. Implement the [`StorageBackend`] trait
//! 2. Implement a corresponding [`Transaction`] type
//! 3. Map backend-specific errors to [`StorageError`](crate::StorageError)
//!
//! See [`MemoryBackend`](crate::MemoryBackend) for a reference implementation.

use std::{ops::RangeBounds, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    error::StorageResult, health::HealthStatus, transaction::Transaction, types::KeyValue,
};

/// Abstract storage backend for key-value operations.
///
/// This trait defines the interface that all storage backends must implement.
/// Backends are expected to be thread-safe (`Send + Sync`) and support
/// concurrent operations.
///
/// # Key Operations
///
/// | Method | Description |
/// |--------|-------------|
/// | [`get`](StorageBackend::get) | Retrieve a single value by key |
/// | [`set`](StorageBackend::set) | Store a key-value pair |
/// | [`compare_and_set`](StorageBackend::compare_and_set) | Atomic compare-and-swap |
/// | [`delete`](StorageBackend::delete) | Remove a key |
/// | [`get_range`](StorageBackend::get_range) | Retrieve multiple keys in a range |
/// | [`clear_range`](StorageBackend::clear_range) | Delete multiple keys in a range |
/// | [`set_with_ttl`](StorageBackend::set_with_ttl) | Store with automatic expiration |
/// | [`transaction`](StorageBackend::transaction) | Begin an atomic transaction |
/// | [`health_check`](StorageBackend::health_check) | Verify backend availability |
///
/// # Example
///
/// ```
/// use bytes::Bytes;
/// use inferadb_common_storage::{StorageBackend, MemoryBackend};
///
/// # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
/// let backend = MemoryBackend::new();
///
/// backend.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
/// let value = backend.get(b"key").await.unwrap();
/// assert_eq!(value, Some(Bytes::from("value")));
/// # });
/// ```
#[async_trait]
pub trait StorageBackend: Send + Sync {
    /// Retrieves a value by key.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` if the key exists
    /// - `Ok(None)` if the key doesn't exist
    /// - `Err(...)` on storage errors
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Stores a key-value pair.
    ///
    /// If the key already exists, its value is overwritten.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to associate with the key
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>;

    /// Atomically sets a key's value if it matches the expected current value.
    ///
    /// This operation reads the current value and conditionally updates it in a
    /// single atomic step. It is useful for optimistic concurrency control,
    /// distributed locks, and leader election without the overhead of a full
    /// transaction.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to update
    /// * `expected` - The expected current value. Pass `None` to require the key does not exist
    ///   (insert-if-absent).
    /// * `new_value` - The value to store if the precondition holds
    ///
    /// # Errors
    ///
    /// Returns [`crate::error::StorageError::Conflict`] when the current value does not match
    /// `expected`.
    #[must_use = "compare-and-set may fail with a conflict and errors must be handled"]
    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()>;

    /// Deletes a key.
    ///
    /// If the key doesn't exist, this is a no-op (returns `Ok(())`).
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn delete(&self, key: &[u8]) -> StorageResult<()>;

    /// Retrieves all key-value pairs within a range.
    ///
    /// The range is defined using Rust's standard [`RangeBounds`] trait,
    /// allowing for flexible range specifications:
    /// - `start..end` (exclusive end)
    /// - `start..=end` (inclusive end)
    /// - `start..` (unbounded end)
    /// - `..end` (unbounded start)
    ///
    /// Results are returned in key order.
    ///
    /// # Arguments
    ///
    /// * `range` - The key range to query
    ///
    /// # Returns
    ///
    /// A vector of [`KeyValue`] pairs within the specified range.
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send;

    /// Deletes all keys within a range.
    ///
    /// Uses the same range semantics as [`get_range`](StorageBackend::get_range).
    ///
    /// # Arguments
    ///
    /// * `range` - The key range to clear
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send;

    /// Stores a key-value pair with automatic expiration.
    ///
    /// The key will be automatically deleted after the specified TTL duration.
    /// Not all backends support TTL natively; some may implement it
    /// via background cleanup tasks.
    ///
    /// The backend converts `ttl` to the appropriate internal representation
    /// at the implementation boundary (e.g., seconds for the Ledger SDK).
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to associate with the key
    /// * `ttl` - Time-to-live duration after which the key expires
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()>;

    /// Begins a new transaction.
    ///
    /// Returns a [`Transaction`] handle that can be used to perform
    /// multiple operations atomically.
    ///
    /// # Returns
    ///
    /// A boxed [`Transaction`] trait object.
    #[must_use = "storage operations may fail and errors must be handled"]
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>>;

    /// Checks backend health and returns detailed status information.
    ///
    /// Returns a [`HealthStatus`] indicating whether the backend is fully
    /// healthy, degraded (operational with reduced capability), or unhealthy.
    /// Each variant carries [`HealthMetadata`](crate::health::HealthMetadata)
    /// with check duration and backend-specific details.
    ///
    /// # Returns
    ///
    /// - `Ok(HealthStatus::Healthy(_))` — backend is fully operational
    /// - `Ok(HealthStatus::Degraded(_, reason))` — backend can serve traffic but with reduced
    ///   capability (e.g., circuit breaker half-open)
    /// - `Ok(HealthStatus::Unhealthy(_, reason))` — backend cannot serve traffic reliably
    /// - `Err(...)` — the health check itself failed (e.g., timeout)
    #[must_use = "health check results indicate backend availability and must be inspected"]
    async fn health_check(&self) -> StorageResult<HealthStatus>;
}
