//! Storage backend trait definition.
//!
//! This module defines the [`StorageBackend`] trait, which is the core abstraction
//! for key-value storage in InferaDB. All storage implementations (MemoryBackend,
//! FoundationDB, Ledger, etc.) implement this trait.
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

use std::ops::RangeBounds;

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::StorageResult;
use crate::transaction::Transaction;
use crate::types::KeyValue;

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
/// | [`delete`](StorageBackend::delete) | Remove a key |
/// | [`get_range`](StorageBackend::get_range) | Retrieve multiple keys in a range |
/// | [`clear_range`](StorageBackend::clear_range) | Delete multiple keys in a range |
/// | [`set_with_ttl`](StorageBackend::set_with_ttl) | Store with automatic expiration |
/// | [`transaction`](StorageBackend::transaction) | Begin an atomic transaction |
/// | [`health_check`](StorageBackend::health_check) | Verify backend availability |
///
/// # Example
///
/// ```ignore
/// use inferadb_storage::{StorageBackend, MemoryBackend};
///
/// async fn example() {
///     let backend = MemoryBackend::new();
///     
///     // Store and retrieve
///     backend.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
///     let value = backend.get(b"key").await.unwrap();
///     assert_eq!(value, Some(Bytes::from("value")));
/// }
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
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Stores a key-value pair.
    ///
    /// If the key already exists, its value is overwritten.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to associate with the key
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>;

    /// Deletes a key.
    ///
    /// If the key doesn't exist, this is a no-op (returns `Ok(())`).
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
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
    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send;

    /// Stores a key-value pair with automatic expiration.
    ///
    /// The key will be automatically deleted after the specified TTL.
    /// Not all backends support TTL natively; some may implement it
    /// via background cleanup tasks.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to store
    /// * `value` - The value to associate with the key
    /// * `ttl_seconds` - Time-to-live in seconds
    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()>;

    /// Begins a new transaction.
    ///
    /// Returns a [`Transaction`] handle that can be used to perform
    /// multiple operations atomically.
    ///
    /// # Returns
    ///
    /// A boxed [`Transaction`] trait object.
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>>;

    /// Checks if the backend is healthy and accepting requests.
    ///
    /// This method should perform a lightweight check to verify the
    /// backend is operational. It's used for health monitoring and
    /// readiness probes.
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the backend is healthy
    /// - `Err(...)` if the backend is unavailable or degraded
    async fn health_check(&self) -> StorageResult<()>;
}
