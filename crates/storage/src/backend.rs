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
//! 3. Map backend-specific errors to [`StorageError`]
//!
//! See [`MemoryBackend`](crate::MemoryBackend) for a reference implementation.

use std::{ops::RangeBounds, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use serde::{Serialize, de::DeserializeOwned};

use crate::{
    StorageError,
    error::StorageResult,
    health::{HealthProbe, HealthStatus},
    transaction::Transaction,
    types::KeyValue,
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
    /// Compare-and-set (CAS) reads the current value and conditionally updates it
    /// in a single atomic step. It is useful for optimistic concurrency control,
    /// distributed locks, and leader election without the overhead of a full
    /// transaction.
    ///
    /// # Semantics
    ///
    /// The `expected` parameter controls the precondition:
    ///
    /// - **`expected: None`** — insert-if-absent. Succeeds only when the key does not exist (or has
    ///   expired). Fails with [`Conflict`](crate::StorageError::Conflict) if any value is present.
    /// - **`expected: Some(value)`** — update-if-unchanged. Succeeds only when the current value is
    ///   an exact byte-for-byte match of `value`. Fails with
    ///   [`Conflict`](crate::StorageError::Conflict) if the key is absent or holds a different
    ///   value.
    ///
    /// On success the new value is stored and any existing TTL on the key is
    /// cleared (the key becomes non-expiring).
    ///
    /// # Byte Comparison Rules
    ///
    /// The comparison is an exact, length-sensitive byte equality check. Two values
    /// match if and only if they have the same length and identical bytes at every
    /// position. There is no normalization, canonicalization, or encoding-aware
    /// comparison — callers must ensure the expected value is byte-identical to the
    /// stored value.
    ///
    /// **Serialization warning**: If you serialize structured data (e.g., JSON,
    /// MessagePack) before storing it, the byte representation must be
    /// deterministic across serialization calls. `serde_json` serializes struct
    /// fields in declaration order (deterministic), but `HashMap` entries in
    /// arbitrary order (non-deterministic). Prefer `BTreeMap` or struct types for
    /// CAS values, or use [`compare_and_set_json`](StorageBackend::compare_and_set_json)
    /// which handles canonical serialization automatically.
    ///
    /// # Interaction with TTL
    ///
    /// A key whose TTL has elapsed is treated as absent:
    ///
    /// - `expected: None` succeeds on an expired key (insert-if-absent).
    /// - `expected: Some(old)` fails on an expired key even if `old` matches the stored bytes,
    ///   because the key is logically absent.
    ///
    /// # Behavior Within Transactions
    ///
    /// When called through [`Transaction::compare_and_set`], the operation is
    /// buffered — no comparison occurs immediately. The precondition is evaluated
    /// at [`Transaction::commit`] time under the backend's write lock. If any
    /// CAS precondition fails, the entire transaction is rejected with
    /// [`Conflict`](crate::StorageError::Conflict) and no operations are applied.
    ///
    /// See [`Transaction::compare_and_set`] for transaction-specific details.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Conflict`](crate::StorageError::Conflict) — the current value does not
    ///   match `expected`.
    /// - [`StorageError::SizeLimitExceeded`] — `key` or `new_value` exceeds the configured size
    ///   limits.
    ///
    /// # Retry Pattern
    ///
    /// `Conflict` is **not** transient
    /// ([`is_transient()`](crate::StorageError::is_transient) returns `false`),
    /// so automatic retry middleware will not retry it. Instead, implement an
    /// application-level CAS loop:
    ///
    /// ```no_run
    /// use inferadb_common_storage::{MemoryBackend, StorageBackend};
    /// use inferadb_common_storage::error::StorageError;
    ///
    /// async fn increment(backend: &MemoryBackend, key: &[u8]) -> Result<(), StorageError> {
    ///     loop {
    ///         let current = backend.get(key).await?;
    ///         let (expected, new_value) = match current {
    ///             Some(bytes) => {
    ///                 let n: u64 = String::from_utf8_lossy(&bytes).parse().unwrap_or(0);
    ///                 (Some(bytes.to_vec()), (n + 1).to_string().into_bytes())
    ///             },
    ///             None => (None, b"1".to_vec()),
    ///         };
    ///         match backend.compare_and_set(key, expected.as_deref(), new_value).await {
    ///             Ok(()) => return Ok(()),
    ///             Err(StorageError::Conflict { .. }) => continue, // retry
    ///             Err(e) => return Err(e),
    ///         }
    ///     }
    /// }
    /// ```
    ///
    /// # Examples
    ///
    /// Insert a key only if it does not already exist:
    ///
    /// ```no_run
    /// use inferadb_common_storage::{MemoryBackend, StorageBackend};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = MemoryBackend::new();
    ///
    /// // Insert-if-absent: succeeds because key is new
    /// backend.compare_and_set(b"lock", None, b"holder-1".to_vec()).await?;
    ///
    /// // Insert-if-absent again: fails with Conflict because key already exists
    /// let result = backend.compare_and_set(b"lock", None, b"holder-2".to_vec()).await;
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// Update a key only if its current value matches:
    ///
    /// ```no_run
    /// use inferadb_common_storage::{MemoryBackend, StorageBackend};
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = MemoryBackend::new();
    /// backend.set(b"version".to_vec(), b"1".to_vec()).await?;
    ///
    /// // Succeeds: current value is "1", expected is "1"
    /// backend.compare_and_set(b"version", Some(b"1"), b"2".to_vec()).await?;
    ///
    /// // Fails: current value is now "2", but expected is "1"
    /// let result = backend.compare_and_set(b"version", Some(b"1"), b"3".to_vec()).await;
    /// assert!(result.is_err());
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "compare-and-set may fail with a conflict and errors must be handled"]
    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()>;

    /// Atomically sets a key's JSON value if the current value deserializes to the
    /// expected value.
    ///
    /// This is a typed convenience wrapper around
    /// [`compare_and_set`](StorageBackend::compare_and_set). It serializes `expected` and
    /// `new_value` to canonical JSON bytes and delegates to the byte-level CAS. Because both
    /// sides use the same serializer, the comparison is deterministic regardless of the type's
    /// internal field ordering.
    ///
    /// # Canonical Serialization
    ///
    /// `serde_json` serializes struct fields in their declaration order, which is
    /// deterministic. However, this method does **not** sort map keys — if your
    /// type contains a `HashMap`, use `BTreeMap` instead to guarantee consistent
    /// byte output.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to update.
    /// * `expected` - The expected current value (deserialized form). Use `None` for
    ///   insert-if-absent.
    /// * `new_value` - The new value to set.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Serialization`](crate::StorageError) — `expected` or `new_value` cannot be
    ///   serialized to JSON.
    /// - [`StorageError::Conflict`](crate::StorageError) — the current value does not match
    ///   `expected`.
    /// - [`StorageError::SizeLimitExceeded`](crate::StorageError) — `key` or serialized `new_value`
    ///   exceeds configured size limits.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use inferadb_common_storage::{MemoryBackend, StorageBackend};
    /// use serde::{Deserialize, Serialize};
    ///
    /// #[derive(Serialize, Deserialize, Clone)]
    /// struct Config {
    ///     version: u32,
    ///     name: String,
    /// }
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let backend = MemoryBackend::new();
    /// let v1 = Config { version: 1, name: "app".into() };
    ///
    /// // Insert-if-absent
    /// backend.compare_and_set_json::<Config>(b"config", None, &v1).await?;
    ///
    /// // Update: version 1 → version 2
    /// let v2 = Config { version: 2, name: "app".into() };
    /// backend.compare_and_set_json(b"config", Some(&v1), &v2).await?;
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "compare-and-set may fail with a conflict and errors must be handled"]
    async fn compare_and_set_json<T>(
        &self,
        key: &[u8],
        expected: Option<&T>,
        new_value: &T,
    ) -> StorageResult<()>
    where
        T: Serialize + DeserializeOwned + Send + Sync,
    {
        let expected_bytes = expected
            .map(|v| serde_json::to_vec(v))
            .transpose()
            .map_err(|e: serde_json::Error| StorageError::serialization(e.to_string()))?;

        let new_bytes = serde_json::to_vec(new_value)
            .map_err(|e| StorageError::serialization(e.to_string()))?;

        self.compare_and_set(key, expected_bytes.as_deref(), new_bytes).await
    }

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

    /// Checks backend health for the given [`HealthProbe`] type.
    ///
    /// Different probes have different semantics:
    ///
    /// - **`Liveness`** — process is alive and not deadlocked. Should almost always succeed.
    /// - **`Readiness`** — backend can serve traffic (connection healthy, caches warm).
    /// - **`Startup`** — initial warm-up complete (first connection established).
    ///
    /// Returns a [`HealthStatus`] indicating whether the backend is fully
    /// healthy, degraded (operational with reduced capability), or unhealthy.
    /// Each variant carries [`HealthMetadata`](crate::health::HealthMetadata)
    /// with check duration and backend-specific details.
    ///
    /// # Returns
    ///
    /// - `Ok(HealthStatus::Healthy(_))` — probe passed
    /// - `Ok(HealthStatus::Degraded(_, reason))` — probe passed with caveats
    /// - `Ok(HealthStatus::Unhealthy(_, reason))` — probe failed
    /// - `Err(...)` — the health check itself failed (e.g., timeout)
    #[must_use = "health check results indicate backend availability and must be inspected"]
    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus>;
}
