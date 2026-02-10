//! Batch write operations for storage backends
//!
//! This module provides a generic [`BatchWriter`] that accumulates write operations
//! and flushes them in optimized batches. It automatically splits large batches
//! to respect transaction size limits.
//!
//! # Examples
//!
//! ```
//! use inferadb_common_storage::{MemoryBackend, batch::{BatchWriter, BatchConfig}};
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let backend = MemoryBackend::new();
//! let mut writer = BatchWriter::new(backend, BatchConfig::default());
//!
//! // Accumulate operations
//! writer.set(b"key1".to_vec(), b"value1".to_vec());
//! writer.set(b"key2".to_vec(), b"value2".to_vec());
//! writer.delete(b"old_key".to_vec());
//!
//! // Flush all at once
//! let stats = writer.flush_all().await.unwrap();
//! assert_eq!(stats.operations_count, 3);
//! # });
//! ```
//!
//! # Transaction Size Limits
//!
//! Many storage backends (particularly FoundationDB) have transaction size limits.
//! The default configuration uses 9MB as the effective limit to leave room for
//! metadata overhead, staying safely under the 10MB FoundationDB limit.

use std::{
    sync::Arc,
    time::{Duration, Instant},
};

use fail::fail_point;
use tracing::{debug, trace, warn};

use crate::{ConfigError, StorageBackend, StorageError, StorageResult};

/// Effective transaction size limit (9 MiB).
///
/// Leaves ~1 MiB headroom below the 10 MiB FoundationDB hard limit
/// for transaction metadata overhead.
pub const TRANSACTION_SIZE_LIMIT: usize = 9 * 1024 * 1024;

/// Default maximum batch size (number of operations).
pub const DEFAULT_MAX_BATCH_SIZE: usize = 1000;

/// Default maximum batch byte size (8MB to stay well under transaction limit).
pub const DEFAULT_MAX_BATCH_BYTES: usize = 8 * 1024 * 1024;

/// Configuration for batch writes.
///
/// # Validation
///
/// - `max_batch_size` must be `>= 1`
/// - `max_batch_bytes` must be `>= 1`
#[derive(Debug, Clone)]
pub struct BatchConfig {
    /// Maximum number of operations per batch.
    pub(crate) max_batch_size: usize,
    /// Maximum byte size per batch (should be under the 10MB transaction limit).
    pub(crate) max_batch_bytes: usize,
    /// Enable batching (can be disabled for testing).
    pub(crate) enabled: bool,
}

impl Default for BatchConfig {
    fn default() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            enabled: true,
        }
    }
}

#[bon::bon]
impl BatchConfig {
    /// Creates a new batch configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `max_batch_size` or `max_batch_bytes` is zero.
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_MAX_BATCH_SIZE)] max_batch_size: usize,
        #[builder(default = DEFAULT_MAX_BATCH_BYTES)] max_batch_bytes: usize,
        #[builder(default = true)] enabled: bool,
    ) -> Result<Self, ConfigError> {
        if max_batch_size == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_batch_size",
                min: "1".into(),
                value: "0".into(),
            });
        }
        if max_batch_bytes == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_batch_bytes",
                min: "1".into(),
                value: "0".into(),
            });
        }
        Ok(Self { max_batch_size, max_batch_bytes, enabled })
    }

    /// Creates a batch config with batching disabled.
    ///
    /// When disabled, [`should_flush`](BatchWriter::should_flush) returns `true` whenever
    /// there are pending operations.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            enabled: false,
        }
    }

    /// Creates a batch config optimized for large transactions.
    ///
    /// Uses [`TRANSACTION_SIZE_LIMIT`] (9 MB) as the maximum batch byte size,
    /// allowing sub-batches to fill up to the FoundationDB transaction limit.
    #[must_use]
    pub fn for_large_transactions() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: TRANSACTION_SIZE_LIMIT,
            enabled: true,
        }
    }

    /// Returns the maximum number of operations per batch.
    #[must_use]
    pub fn max_batch_size(&self) -> usize {
        self.max_batch_size
    }

    /// Returns the maximum byte size per batch.
    #[must_use]
    pub fn max_batch_bytes(&self) -> usize {
        self.max_batch_bytes
    }

    /// Returns whether batching is enabled.
    #[must_use]
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Single write operation in a batch.
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Stores a key-value pair. Overwrites any existing value for the key.
    Set {
        /// The key to store.
        key: Vec<u8>,
        /// The value to associate with the key.
        value: Vec<u8>,
    },
    /// Removes a key and its associated value. No-op if the key does not exist.
    Delete {
        /// The key to remove.
        key: Vec<u8>,
    },
}

impl BatchOperation {
    /// Calculates the approximate size of this operation in bytes.
    ///
    /// Includes an estimated 50-byte overhead for transaction encoding.
    #[must_use]
    pub fn size_bytes(&self) -> usize {
        match self {
            BatchOperation::Set { key, value } => {
                // Key + value + overhead for encoding (estimate ~50 bytes)
                key.len() + value.len() + 50
            },
            BatchOperation::Delete { key } => {
                // Key + overhead
                key.len() + 50
            },
        }
    }

    /// Returns the key associated with this operation.
    #[must_use]
    pub fn key(&self) -> &[u8] {
        match self {
            BatchOperation::Set { key, .. } | BatchOperation::Delete { key } => key,
        }
    }
}

/// Statistics from a batch flush operation.
#[derive(Debug, Clone, Default)]
pub struct BatchFlushStats {
    /// Number of operations flushed.
    pub operations_count: usize,
    /// Number of operations that succeeded.
    pub succeeded_count: usize,
    /// Number of operations that failed.
    pub failed_count: usize,
    /// Number of sub-batches created (due to size limits).
    pub batches_count: usize,
    /// Total bytes written.
    pub total_bytes: usize,
    /// Time taken to flush.
    pub duration: Duration,
}

/// Result of a batch flush with per-operation error reporting.
///
/// Each entry corresponds to one operation in the original batch, in the same
/// order they were added via [`BatchWriter::set`] or [`BatchWriter::delete`].
/// When a sub-batch (transaction) fails, all operations in that sub-batch share
/// the same error via `Arc`.
///
/// # Examples
///
/// ```no_run
/// # use inferadb_common_storage::batch::BatchResult;
/// # fn example(result: BatchResult) {
/// if result.has_failures() {
///     let failed = result.failed_indices();
///     // Retry only the failed operations
/// }
/// # }
/// ```
#[derive(Debug, Clone)]
pub struct BatchResult {
    /// Per-operation results, indexed by operation order.
    results: Vec<Result<(), Arc<StorageError>>>,
    /// Flush statistics.
    stats: BatchFlushStats,
}

impl BatchResult {
    /// Returns the per-operation results.
    #[must_use = "per-operation results indicate which operations succeeded or failed"]
    pub fn results(&self) -> &[Result<(), Arc<StorageError>>] {
        &self.results
    }

    /// Returns the flush statistics.
    #[must_use]
    pub fn stats(&self) -> &BatchFlushStats {
        &self.stats
    }

    /// Returns `true` if any operation failed.
    #[must_use]
    pub fn has_failures(&self) -> bool {
        self.results.iter().any(|r| r.is_err())
    }

    /// Returns `true` if all operations succeeded.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.results.iter().all(|r| r.is_ok())
    }

    /// Returns the indices of failed operations.
    #[must_use]
    pub fn failed_indices(&self) -> Vec<usize> {
        self.results
            .iter()
            .enumerate()
            .filter_map(|(i, r)| if r.is_err() { Some(i) } else { None })
            .collect()
    }

    /// Returns the number of operations that succeeded.
    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_ok()).count()
    }

    /// Returns the number of operations that failed.
    #[must_use]
    pub fn failed_count(&self) -> usize {
        self.results.iter().filter(|r| r.is_err()).count()
    }

    /// Converts this result into a single `StorageResult<BatchFlushStats>`,
    /// returning the first error if any operation failed.
    ///
    /// This is useful for callers that want the old all-or-nothing behavior.
    pub fn into_result(self) -> StorageResult<BatchFlushStats> {
        // Find the first error, then drop all remaining results to release Arc refs.
        let mut first_err: Option<Arc<StorageError>> = None;
        for result in self.results {
            if let Err(e) = result
                && first_err.is_none()
            {
                first_err = Some(e);
            }
            // Other errors are dropped here, decrementing Arc refcounts
        }
        match first_err {
            None => Ok(self.stats),
            Some(arc_err) => match Arc::try_unwrap(arc_err) {
                Ok(e) => Err(e),
                // Shouldn't happen since we dropped all other refs above,
                // but handle defensively. Use detail() to preserve the
                // internal diagnostic message rather than Display (which
                // is sanitized for external consumers).
                Err(arc_err) => Err(StorageError::internal(arc_err.detail())),
            },
        }
    }
}

/// Accumulates write operations and flushes them in optimized batches.
///
/// Automatically splits large batches to respect transaction size limits.
pub struct BatchWriter<B: StorageBackend> {
    backend: B,
    operations: Vec<BatchOperation>,
    current_size_bytes: usize,
    config: BatchConfig,
}

impl<B: StorageBackend + Clone> BatchWriter<B> {
    /// Creates a new batch writer backed by the given storage backend.
    ///
    /// The writer accumulates operations until [`flush`](Self::flush) or
    /// [`flush_all`](Self::flush_all) is called.
    #[must_use]
    pub fn new(backend: B, config: BatchConfig) -> Self {
        Self { backend, operations: Vec::new(), current_size_bytes: 0, config }
    }

    /// Adds a set operation to the batch.
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let op = BatchOperation::Set { key, value };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Adds a delete operation to the batch.
    pub fn delete(&mut self, key: Vec<u8>) {
        let op = BatchOperation::Delete { key };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Returns the number of pending operations.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.operations.len()
    }

    /// Returns the estimated size of pending operations in bytes.
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.current_size_bytes
    }

    /// Returns whether the batch should be flushed based on configured size limits.
    #[must_use]
    pub fn should_flush(&self) -> bool {
        if !self.config.enabled {
            return !self.operations.is_empty();
        }
        self.operations.len() >= self.config.max_batch_size
            || self.current_size_bytes >= self.config.max_batch_bytes
    }

    /// Returns the pending operations.
    #[must_use]
    pub fn pending_operations(&self) -> &[BatchOperation] {
        &self.operations
    }

    /// Split operations into sub-batches that fit within size limits
    #[cfg(test)]
    fn split_into_batches(&self) -> Vec<Vec<&BatchOperation>> {
        if self.operations.is_empty() {
            return Vec::new();
        }

        let max_bytes =
            if self.config.enabled { self.config.max_batch_bytes } else { TRANSACTION_SIZE_LIMIT };

        let max_ops = if self.config.enabled { self.config.max_batch_size } else { usize::MAX };

        let mut batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_bytes = 0usize;

        for op in &self.operations {
            let op_size = op.size_bytes();

            // If this single operation exceeds the limit, it goes in its own batch
            // (storage backend will reject it, but we let it through for proper error handling)
            if op_size > max_bytes {
                if !current_batch.is_empty() {
                    batches.push(current_batch);
                    current_batch = Vec::new();
                    current_bytes = 0;
                }
                batches.push(vec![op]);
                continue;
            }

            // Check if adding this operation would exceed limits
            if (current_bytes + op_size > max_bytes || current_batch.len() >= max_ops)
                && !current_batch.is_empty()
            {
                batches.push(current_batch);
                current_batch = Vec::new();
                current_bytes = 0;
            }

            current_batch.push(op);
            current_bytes += op_size;
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        batches
    }

    /// Split operations into sub-batches, preserving original operation indices.
    ///
    /// Each entry is `(original_index, &BatchOperation)`.
    fn split_into_indexed_batches(&self) -> Vec<Vec<(usize, &BatchOperation)>> {
        if self.operations.is_empty() {
            return Vec::new();
        }

        let max_bytes =
            if self.config.enabled { self.config.max_batch_bytes } else { TRANSACTION_SIZE_LIMIT };

        let max_ops = if self.config.enabled { self.config.max_batch_size } else { usize::MAX };

        let mut batches = Vec::new();
        let mut current_batch = Vec::new();
        let mut current_bytes = 0usize;

        for (idx, op) in self.operations.iter().enumerate() {
            let op_size = op.size_bytes();

            // If this single operation exceeds the limit, it goes in its own batch
            if op_size > max_bytes {
                if !current_batch.is_empty() {
                    batches.push(current_batch);
                    current_batch = Vec::new();
                    current_bytes = 0;
                }
                batches.push(vec![(idx, op)]);
                continue;
            }

            // Check if adding this operation would exceed limits
            if (current_bytes + op_size > max_bytes || current_batch.len() >= max_ops)
                && !current_batch.is_empty()
            {
                batches.push(current_batch);
                current_batch = Vec::new();
                current_bytes = 0;
            }

            current_batch.push((idx, op));
            current_bytes += op_size;
        }

        if !current_batch.is_empty() {
            batches.push(current_batch);
        }

        batches
    }

    /// Execute a single sub-batch as a transaction.
    async fn execute_batch(&self, entries: Vec<(usize, &BatchOperation)>) -> StorageResult<()> {
        let mut txn = self.backend.transaction().await?;

        for (_, op) in entries {
            match op {
                BatchOperation::Set { key, value } => {
                    txn.set(key.clone(), value.clone());
                },
                BatchOperation::Delete { key } => {
                    txn.delete(key.clone());
                },
            }
        }

        fail_point!("batch-before-commit", |_| {
            Err(StorageError::internal("injected failure before batch commit"))
        });
        txn.commit().await
    }

    /// Flush all pending operations, failing if any operation fails.
    ///
    /// This is a convenience wrapper around [`flush`](Self::flush) that returns
    /// the first error encountered, providing the simpler all-or-nothing API.
    ///
    /// # Errors
    ///
    /// Returns the first [`StorageError`] encountered across all sub-batches.
    #[must_use = "flush may fail and partial results must be handled"]
    pub async fn flush_all(&mut self) -> StorageResult<BatchFlushStats> {
        self.flush().await.into_result()
    }

    /// Flushes all buffered operations and prepares for shutdown.
    ///
    /// This is a convenience method for graceful shutdown sequences. It calls
    /// [`flush_all`](Self::flush_all) to drain all buffered writes and returns
    /// the flush statistics. After a successful shutdown, the writer is empty
    /// and can be safely dropped.
    ///
    /// # Errors
    ///
    /// Returns the first error encountered during flush, just like
    /// [`flush_all`](Self::flush_all).
    pub async fn shutdown(&mut self) -> StorageResult<BatchFlushStats> {
        self.flush_all().await
    }

    /// Flush all pending operations to the backend with per-operation error reporting.
    ///
    /// Operations are split into appropriately-sized sub-batches. Each sub-batch is
    /// committed in a separate transaction. If a sub-batch fails, the error is
    /// recorded for all operations in that sub-batch and processing continues with
    /// remaining sub-batches.
    ///
    /// Use [`flush_all`](Self::flush_all) for the simpler all-or-nothing API.
    #[must_use = "flush results contain per-operation errors that must be inspected"]
    pub async fn flush(&mut self) -> BatchResult {
        if self.operations.is_empty() {
            return BatchResult { results: Vec::new(), stats: BatchFlushStats::default() };
        }

        let start = Instant::now();
        let total_ops = self.operations.len();
        let total_bytes = self.current_size_bytes;

        // Build batches with original operation indices
        let batches = self.split_into_indexed_batches();
        let batches_count = batches.len();

        debug!(
            operations = total_ops,
            bytes = total_bytes,
            batches = batches_count,
            "Flushing batch writes"
        );

        // Per-operation results, initialized to Ok
        let mut results: Vec<Result<(), Arc<StorageError>>> = vec![Ok(()); total_ops];
        let mut succeeded_count = 0usize;
        let mut failed_count = 0usize;

        for (batch_idx, batch_entries) in batches.into_iter().enumerate() {
            let indices: Vec<usize> = batch_entries.iter().map(|&(idx, _)| idx).collect();

            match self.execute_batch(batch_entries).await {
                Ok(()) => {
                    succeeded_count += indices.len();
                    trace!(batch = batch_idx, ops = indices.len(), "Batch committed successfully");
                },
                Err(e) => {
                    let arc_err = Arc::new(e);
                    warn!(batch = batch_idx, error = %arc_err, "Batch commit failed");
                    failed_count += indices.len();
                    for idx in indices {
                        results[idx] = Err(Arc::clone(&arc_err));
                    }
                },
            }
        }

        // Clear the pending operations
        self.operations.clear();
        self.current_size_bytes = 0;

        let stats = BatchFlushStats {
            operations_count: total_ops,
            succeeded_count,
            failed_count,
            batches_count,
            total_bytes,
            duration: start.elapsed(),
        };

        debug!(
            operations = stats.operations_count,
            succeeded = stats.succeeded_count,
            failed = stats.failed_count,
            batches = stats.batches_count,
            duration_ms = stats.duration.as_millis(),
            "Batch flush complete"
        );

        BatchResult { results, stats }
    }

    /// Clears all pending operations without flushing.
    pub fn clear(&mut self) {
        self.operations.clear();
        self.current_size_bytes = 0;
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    #[test]
    fn test_batch_operation_size() {
        let set_op = BatchOperation::Set { key: vec![0; 10], value: vec![0; 100] };
        // 10 + 100 + 50 overhead = 160
        assert_eq!(set_op.size_bytes(), 160);

        let delete_op = BatchOperation::Delete { key: vec![0; 10] };
        // 10 + 50 overhead = 60
        assert_eq!(delete_op.size_bytes(), 60);
    }

    #[test]
    fn test_batch_config_default() {
        let config = BatchConfig::default();
        assert_eq!(config.max_batch_size(), DEFAULT_MAX_BATCH_SIZE);
        assert_eq!(config.max_batch_bytes(), DEFAULT_MAX_BATCH_BYTES);
        assert!(config.enabled());
    }

    #[test]
    fn test_batch_config_disabled() {
        let config = BatchConfig::disabled();
        assert!(!config.enabled());
    }

    #[test]
    fn test_batch_config_builder() {
        let config = BatchConfig::builder().max_batch_size(500).enabled(true).build().unwrap();
        assert_eq!(config.max_batch_size(), 500);
        assert_eq!(config.max_batch_bytes(), DEFAULT_MAX_BATCH_BYTES);
        assert!(config.enabled());
    }

    #[test]
    fn test_batch_config_builder_defaults() {
        let built = BatchConfig::builder().build().unwrap();
        let default = BatchConfig::default();
        assert_eq!(built.max_batch_size(), default.max_batch_size());
        assert_eq!(built.max_batch_bytes(), default.max_batch_bytes());
        assert_eq!(built.enabled(), default.enabled());
    }

    #[test]
    fn test_batch_config_builder_all_fields() {
        let config = BatchConfig::builder()
            .max_batch_size(100)
            .max_batch_bytes(1024)
            .enabled(false)
            .build()
            .unwrap();
        assert_eq!(config.max_batch_size(), 100);
        assert_eq!(config.max_batch_bytes(), 1024);
        assert!(!config.enabled());
    }

    #[test]
    fn test_batch_config_zero_batch_size_rejected() {
        let err = BatchConfig::builder().max_batch_size(0).build().unwrap_err();
        assert!(err.to_string().contains("max_batch_size"), "error should name the field: {err}");
    }

    #[test]
    fn test_batch_config_zero_batch_bytes_rejected() {
        let err = BatchConfig::builder().max_batch_bytes(0).build().unwrap_err();
        assert!(err.to_string().contains("max_batch_bytes"), "error should name the field: {err}");
    }

    #[tokio::test]
    async fn test_batch_writer_basic() {
        let backend = MemoryBackend::new();
        let mut writer = BatchWriter::new(backend.clone(), BatchConfig::default());

        writer.set(b"key1".to_vec(), b"value1".to_vec());
        writer.set(b"key2".to_vec(), b"value2".to_vec());

        assert_eq!(writer.pending_count(), 2);

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 2);
        assert_eq!(stats.batches_count, 1);

        // Verify data was written
        let v1 = backend.get(b"key1").await.expect("get failed");
        assert_eq!(v1.map(|b| b.to_vec()), Some(b"value1".to_vec()));

        let v2 = backend.get(b"key2").await.expect("get failed");
        assert_eq!(v2.map(|b| b.to_vec()), Some(b"value2".to_vec()));
    }

    #[tokio::test]
    async fn test_batch_writer_delete() {
        let backend = MemoryBackend::new();

        // Pre-populate
        backend.set(b"to_delete".to_vec(), b"value".to_vec()).await.expect("set failed");

        let mut writer = BatchWriter::new(backend.clone(), BatchConfig::default());
        writer.delete(b"to_delete".to_vec());

        writer.flush_all().await.expect("flush failed");

        let v = backend.get(b"to_delete").await.expect("get failed");
        assert!(v.is_none());
    }

    #[tokio::test]
    async fn test_batch_writer_split_by_count() {
        let backend = MemoryBackend::new();
        let config =
            BatchConfig::builder().max_batch_size(5).max_batch_bytes(usize::MAX).build().unwrap(); // Max 5 ops per batch
        let mut writer = BatchWriter::new(backend, config);

        // Add 12 operations - should split into 3 batches (5, 5, 2)
        for i in 0..12 {
            writer.set(format!("key{i}").into_bytes(), format!("value{i}").into_bytes());
        }

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 12);
        assert_eq!(stats.batches_count, 3);
    }

    #[tokio::test]
    async fn test_should_flush() {
        let backend = MemoryBackend::new();
        let config =
            BatchConfig::builder().max_batch_size(3).max_batch_bytes(usize::MAX).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        assert!(!writer.should_flush());

        writer.set(b"key1".to_vec(), b"value1".to_vec());
        writer.set(b"key2".to_vec(), b"value2".to_vec());
        assert!(!writer.should_flush());

        writer.set(b"key3".to_vec(), b"value3".to_vec());
        assert!(writer.should_flush());
    }

    #[tokio::test]
    async fn test_clear() {
        let backend = MemoryBackend::new();
        let mut writer = BatchWriter::new(backend, BatchConfig::default());

        writer.set(b"key1".to_vec(), b"value1".to_vec());
        writer.set(b"key2".to_vec(), b"value2".to_vec());
        assert_eq!(writer.pending_count(), 2);

        writer.clear();
        assert_eq!(writer.pending_count(), 0);
        assert_eq!(writer.pending_bytes(), 0);
    }

    #[test]
    fn test_batch_operation_key() {
        let set_op = BatchOperation::Set { key: vec![1, 2, 3], value: vec![4, 5, 6] };
        assert_eq!(set_op.key(), &[1, 2, 3]);

        let delete_op = BatchOperation::Delete { key: vec![7, 8, 9] };
        assert_eq!(delete_op.key(), &[7, 8, 9]);
    }

    #[test]
    fn test_batch_config_for_large_transactions() {
        let config = BatchConfig::for_large_transactions();
        assert_eq!(config.max_batch_bytes(), TRANSACTION_SIZE_LIMIT);
        assert!(config.enabled());
    }

    #[tokio::test]
    async fn test_pending_operations() {
        let backend = MemoryBackend::new();
        let mut writer = BatchWriter::new(backend, BatchConfig::default());

        writer.set(b"key1".to_vec(), b"value1".to_vec());
        writer.delete(b"key2".to_vec());

        let ops = writer.pending_operations();
        assert_eq!(ops.len(), 2);
        assert!(matches!(&ops[0], BatchOperation::Set { .. }));
        assert!(matches!(&ops[1], BatchOperation::Delete { .. }));
    }

    #[tokio::test]
    async fn test_flush_empty() {
        let backend = MemoryBackend::new();
        let mut writer = BatchWriter::new(backend, BatchConfig::default());

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 0);
        assert_eq!(stats.batches_count, 0);
    }

    #[tokio::test]
    async fn test_should_flush_disabled_config() {
        let backend = MemoryBackend::new();
        let config = BatchConfig::disabled();
        let mut writer = BatchWriter::new(backend, config);

        // With disabled config, should_flush returns true if there are any ops
        assert!(!writer.should_flush());

        writer.set(b"key".to_vec(), b"value".to_vec());
        assert!(writer.should_flush());
    }

    #[tokio::test]
    async fn test_should_flush_by_bytes() {
        let backend = MemoryBackend::new();
        // Set max_batch_bytes to a small value
        let config =
            BatchConfig::builder().max_batch_size(1000).max_batch_bytes(200).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        // Add operations that exceed byte limit (each set is ~160 bytes)
        writer.set(b"key1".to_vec(), vec![0; 100]);
        assert!(!writer.should_flush());

        writer.set(b"key2".to_vec(), vec![0; 100]);
        assert!(writer.should_flush());
    }

    #[tokio::test]
    async fn test_split_by_bytes() {
        let backend = MemoryBackend::new();
        // Small byte limit to force splits
        let config =
            BatchConfig::builder().max_batch_size(1000).max_batch_bytes(200).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        // Each operation is ~160 bytes, so 2 per batch max with 200 byte limit
        for i in 0..5 {
            writer.set(format!("k{i}").into_bytes(), vec![0; 100]);
        }

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 5);
        assert!(stats.batches_count >= 2); // Should be split into multiple batches
    }

    #[tokio::test]
    async fn test_oversized_single_operation() {
        let backend = MemoryBackend::new();
        // Very small byte limit
        let config =
            BatchConfig::builder().max_batch_size(1000).max_batch_bytes(50).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        // Add an operation that exceeds the byte limit by itself
        writer.set(b"key".to_vec(), vec![0; 100]);

        // This should still flush successfully (operation goes in its own batch)
        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 1);
        assert_eq!(stats.batches_count, 1);
    }

    #[tokio::test]
    async fn test_mixed_oversized_and_normal_operations() {
        let backend = MemoryBackend::new();
        let config =
            BatchConfig::builder().max_batch_size(1000).max_batch_bytes(100).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        // Add a normal operation
        writer.set(b"k1".to_vec(), b"v1".to_vec());
        // Add an oversized operation
        writer.set(b"big".to_vec(), vec![0; 200]);
        // Add another normal operation
        writer.set(b"k2".to_vec(), b"v2".to_vec());

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 3);
        // Should be split: [k1], [big], [k2]
        assert!(stats.batches_count >= 2);
    }

    #[tokio::test]
    async fn test_batch_with_disabled_config() {
        let backend = MemoryBackend::new();
        let config = BatchConfig::disabled();
        let mut writer = BatchWriter::new(backend.clone(), config);

        for i in 0..10 {
            writer.set(format!("key{i}").into_bytes(), format!("value{i}").into_bytes());
        }

        let stats = writer.flush_all().await.expect("flush failed");
        assert_eq!(stats.operations_count, 10);
        // With disabled config, uses TRANSACTION_SIZE_LIMIT and usize::MAX for ops
        // So all should fit in one batch
        assert_eq!(stats.batches_count, 1);
    }

    #[test]
    fn test_batch_flush_stats_default() {
        let stats = BatchFlushStats::default();
        assert_eq!(stats.operations_count, 0);
        assert_eq!(stats.succeeded_count, 0);
        assert_eq!(stats.failed_count, 0);
        assert_eq!(stats.batches_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.duration, std::time::Duration::ZERO);
    }

    #[test]
    fn test_batch_flush_stats_counts() {
        let stats = BatchFlushStats {
            operations_count: 10,
            succeeded_count: 7,
            failed_count: 3,
            batches_count: 2,
            total_bytes: 1000,
            duration: std::time::Duration::from_millis(50),
        };
        assert_eq!(stats.succeeded_count, 7);
        assert_eq!(stats.failed_count, 3);
        assert_eq!(stats.succeeded_count + stats.failed_count, stats.operations_count);
    }

    #[test]
    fn test_batch_result_all_success() {
        let result = BatchResult {
            results: vec![Ok(()), Ok(()), Ok(())],
            stats: BatchFlushStats {
                operations_count: 3,
                succeeded_count: 3,
                failed_count: 0,
                ..Default::default()
            },
        };
        assert!(result.is_success());
        assert!(!result.has_failures());
        assert_eq!(result.succeeded_count(), 3);
        assert_eq!(result.failed_count(), 0);
        assert!(result.failed_indices().is_empty());
    }

    #[test]
    fn test_batch_result_partial_failure() {
        let err = Arc::new(StorageError::connection("test failure"));
        let result = BatchResult {
            results: vec![Ok(()), Err(Arc::clone(&err)), Err(Arc::clone(&err)), Ok(())],
            stats: BatchFlushStats {
                operations_count: 4,
                succeeded_count: 2,
                failed_count: 2,
                ..Default::default()
            },
        };
        assert!(!result.is_success());
        assert!(result.has_failures());
        assert_eq!(result.succeeded_count(), 2);
        assert_eq!(result.failed_count(), 2);
        assert_eq!(result.failed_indices(), vec![1, 2]);
    }

    #[test]
    fn test_batch_result_into_result_success() {
        let result = BatchResult {
            results: vec![Ok(()), Ok(())],
            stats: BatchFlushStats {
                operations_count: 2,
                succeeded_count: 2,
                ..Default::default()
            },
        };
        let stats = result.into_result().unwrap();
        assert_eq!(stats.operations_count, 2);
    }

    #[test]
    fn test_batch_result_into_result_failure() {
        let err = Arc::new(StorageError::connection("batch failed"));
        let result =
            BatchResult { results: vec![Ok(()), Err(err)], stats: BatchFlushStats::default() };
        let e = result.into_result().unwrap_err();
        assert!(e.to_string().contains("Connection error"));
    }

    /// A test wrapper around `MemoryBackend` that fails specific transaction commits.
    ///
    /// The `fail_commits` set controls which transaction commits (by 0-based index)
    /// return an error. All other operations delegate transparently.
    #[derive(Clone)]
    struct FailOnCommitBackend {
        inner: MemoryBackend,
        commit_count: Arc<std::sync::atomic::AtomicUsize>,
        fail_commits: Arc<std::collections::HashSet<usize>>,
    }

    impl FailOnCommitBackend {
        fn new(fail_commits: std::collections::HashSet<usize>) -> Self {
            Self {
                inner: MemoryBackend::new(),
                commit_count: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                fail_commits: Arc::new(fail_commits),
            }
        }
    }

    /// Transaction wrapper that conditionally fails on commit.
    /// Only supports `set`, `delete`, and `commit` — sufficient for `BatchWriter` tests.
    struct FailOnCommitTransaction {
        inner: std::sync::Mutex<Box<dyn crate::Transaction>>,
        should_fail: bool,
    }

    #[async_trait::async_trait]
    impl crate::Transaction for FailOnCommitTransaction {
        async fn get(&self, _key: &[u8]) -> StorageResult<Option<bytes::Bytes>> {
            // BatchWriter never calls get on transactions
            Err(StorageError::internal("get not supported on FailOnCommitTransaction"))
        }

        fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
            self.inner.get_mut().expect("lock poisoned").set(key, value);
        }

        fn delete(&mut self, key: Vec<u8>) {
            self.inner.get_mut().expect("lock poisoned").delete(key);
        }

        fn compare_and_set(
            &mut self,
            key: Vec<u8>,
            expected: Option<Vec<u8>>,
            new_value: Vec<u8>,
        ) -> StorageResult<()> {
            self.inner.get_mut().expect("lock poisoned").compare_and_set(key, expected, new_value)
        }

        async fn commit(self: Box<Self>) -> StorageResult<()> {
            if self.should_fail {
                Err(StorageError::connection("simulated commit failure"))
            } else {
                self.inner.into_inner().expect("lock poisoned").commit().await
            }
        }
    }

    #[async_trait::async_trait]
    impl crate::StorageBackend for FailOnCommitBackend {
        async fn get(&self, key: &[u8]) -> StorageResult<Option<bytes::Bytes>> {
            self.inner.get(key).await
        }

        async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
            self.inner.set(key, value).await
        }

        async fn compare_and_set(
            &self,
            key: &[u8],
            expected: Option<&[u8]>,
            new_value: Vec<u8>,
        ) -> StorageResult<()> {
            self.inner.compare_and_set(key, expected, new_value).await
        }

        async fn delete(&self, key: &[u8]) -> StorageResult<()> {
            self.inner.delete(key).await
        }

        async fn get_range<R>(&self, range: R) -> StorageResult<Vec<crate::KeyValue>>
        where
            R: std::ops::RangeBounds<Vec<u8>> + Send,
        {
            self.inner.get_range(range).await
        }

        async fn clear_range<R>(&self, range: R) -> StorageResult<()>
        where
            R: std::ops::RangeBounds<Vec<u8>> + Send,
        {
            self.inner.clear_range(range).await
        }

        async fn set_with_ttl(
            &self,
            key: Vec<u8>,
            value: Vec<u8>,
            ttl: std::time::Duration,
        ) -> StorageResult<()> {
            self.inner.set_with_ttl(key, value, ttl).await
        }

        async fn transaction(&self) -> StorageResult<Box<dyn crate::Transaction>> {
            let idx = self.commit_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let should_fail = self.fail_commits.contains(&idx);
            let inner_txn = self.inner.transaction().await?;
            Ok(Box::new(FailOnCommitTransaction {
                inner: std::sync::Mutex::new(inner_txn),
                should_fail,
            }))
        }

        async fn health_check(
            &self,
            probe: crate::health::HealthProbe,
        ) -> StorageResult<crate::health::HealthStatus> {
            self.inner.health_check(probe).await
        }
    }

    #[tokio::test]
    async fn test_flush_all_succeeds_reports_all_ok() {
        let backend = MemoryBackend::new();
        let config = BatchConfig::builder().max_batch_size(2).build().unwrap();
        let mut writer = BatchWriter::new(backend.clone(), config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());
        writer.set(b"k3".to_vec(), b"v3".to_vec());

        let result = writer.flush().await;
        assert!(result.is_success());
        assert!(!result.has_failures());
        assert_eq!(result.stats().operations_count, 3);
        assert_eq!(result.stats().succeeded_count, 3);
        assert_eq!(result.stats().failed_count, 0);
        assert_eq!(result.stats().batches_count, 2); // 2 ops + 1 op
        assert_eq!(result.results().len(), 3);
    }

    #[tokio::test]
    async fn test_flush_partial_failure_continues_processing() {
        // Batch size of 2 → 3 ops make 2 batches: [k1,k2], [k3]
        // Fail the first batch (commit index 0), succeed the second
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(2).build().unwrap();
        let mut writer = BatchWriter::new(backend.clone(), config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());
        writer.set(b"k3".to_vec(), b"v3".to_vec());

        let result = writer.flush().await;
        assert!(result.has_failures());
        assert!(!result.is_success());
        assert_eq!(result.stats().succeeded_count, 1);
        assert_eq!(result.stats().failed_count, 2);
        assert_eq!(result.failed_indices(), vec![0, 1]);

        // k1, k2 should NOT be in the backend (batch 0 failed)
        assert!(backend.get(b"k1").await.unwrap().is_none());
        assert!(backend.get(b"k2").await.unwrap().is_none());

        // k3 SHOULD be in the backend (batch 1 succeeded)
        assert_eq!(backend.get(b"k3").await.unwrap().unwrap().as_ref(), b"v3");
    }

    #[tokio::test]
    async fn test_flush_all_batches_fail() {
        // Fail all commits
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        fail_set.insert(1);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(1).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());

        let result = writer.flush().await;
        assert!(result.has_failures());
        assert_eq!(result.stats().succeeded_count, 0);
        assert_eq!(result.stats().failed_count, 2);
        assert_eq!(result.failed_indices(), vec![0, 1]);
    }

    #[tokio::test]
    async fn test_flush_all_convenience_returns_error_on_partial_failure() {
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(2).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());
        writer.set(b"k3".to_vec(), b"v3".to_vec());

        // flush_all should return error because batch 0 failed
        let err = writer.flush_all().await.unwrap_err();
        assert!(
            err.to_string().contains("Connection error"),
            "expected 'Connection error', got: '{}'",
            err
        );
    }

    #[tokio::test]
    async fn test_flush_empty_returns_empty_result() {
        let backend = MemoryBackend::new();
        let mut writer = BatchWriter::new(backend, BatchConfig::default());

        let result = writer.flush().await;
        assert!(result.is_success());
        assert_eq!(result.results().len(), 0);
        assert_eq!(result.stats().operations_count, 0);
    }

    #[tokio::test]
    async fn test_flush_clears_pending_after_partial_failure() {
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(2).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());

        let result = writer.flush().await;
        assert!(result.has_failures());

        // After flush (even partial failure), pending operations are cleared
        assert_eq!(writer.pending_count(), 0);
        assert_eq!(writer.pending_bytes(), 0);
    }

    #[tokio::test]
    async fn test_retry_failed_operations() {
        // First flush: batch 0 fails, batch 1 succeeds
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(2).build().unwrap();
        let mut writer = BatchWriter::new(backend.clone(), config.clone());

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());
        writer.set(b"k3".to_vec(), b"v3".to_vec());
        writer.set(b"k4".to_vec(), b"v4".to_vec());

        let result = writer.flush().await;
        let failed = result.failed_indices();
        assert_eq!(failed, vec![0, 1]);

        // The caller can identify failed ops and retry them in a new writer.
        // Commit index 2 will succeed (only index 0 was configured to fail).
        let mut retry_writer = BatchWriter::new(backend.clone(), config);
        // Re-add only the operations that failed (k1, k2)
        retry_writer.set(b"k1".to_vec(), b"v1".to_vec());
        retry_writer.set(b"k2".to_vec(), b"v2".to_vec());

        let retry_result = retry_writer.flush().await;
        assert!(retry_result.is_success());

        // All keys should now exist
        assert_eq!(backend.get(b"k1").await.unwrap().unwrap().as_ref(), b"v1");
        assert_eq!(backend.get(b"k2").await.unwrap().unwrap().as_ref(), b"v2");
        assert_eq!(backend.get(b"k3").await.unwrap().unwrap().as_ref(), b"v3");
        assert_eq!(backend.get(b"k4").await.unwrap().unwrap().as_ref(), b"v4");
    }

    #[tokio::test]
    async fn test_flush_failed_ops_share_same_error_arc() {
        let mut fail_set = std::collections::HashSet::new();
        fail_set.insert(0);
        let backend = FailOnCommitBackend::new(fail_set);
        let config = BatchConfig::builder().max_batch_size(3).build().unwrap();
        let mut writer = BatchWriter::new(backend, config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());
        writer.set(b"k3".to_vec(), b"v3".to_vec());

        let result = writer.flush().await;
        // All 3 ops in one batch, batch fails → all 3 should have the same Arc
        assert_eq!(result.failed_count(), 3);
        let errors: Vec<_> =
            result.results().iter().filter_map(|r| r.as_ref().err().cloned()).collect();
        assert_eq!(errors.len(), 3);
        // All errors should point to the same allocation
        assert!(Arc::ptr_eq(&errors[0], &errors[1]));
        assert!(Arc::ptr_eq(&errors[1], &errors[2]));
    }

    #[tokio::test]
    async fn test_shutdown_flushes_buffered_operations() {
        let backend = MemoryBackend::new();
        let config = BatchConfig::default();
        let mut writer = BatchWriter::new(backend.clone(), config);

        writer.set(b"k1".to_vec(), b"v1".to_vec());
        writer.set(b"k2".to_vec(), b"v2".to_vec());

        let stats = writer.shutdown().await.expect("shutdown should succeed");
        assert_eq!(stats.succeeded_count, 2);
        assert_eq!(stats.failed_count, 0);

        // Verify data was flushed to backend
        let v1 = backend.get(b"k1").await.expect("get k1");
        assert_eq!(v1, Some(bytes::Bytes::from("v1")));
        let v2 = backend.get(b"k2").await.expect("get k2");
        assert_eq!(v2, Some(bytes::Bytes::from("v2")));
    }

    #[tokio::test]
    async fn test_shutdown_empty_writer() {
        let backend = MemoryBackend::new();
        let config = BatchConfig::default();
        let mut writer = BatchWriter::new(backend, config);

        let stats = writer.shutdown().await.expect("shutdown should succeed");
        assert_eq!(stats.succeeded_count, 0);
        assert_eq!(stats.failed_count, 0);
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        /// Generate a random `BatchOperation`.
        fn arb_batch_operation() -> impl Strategy<Value = BatchOperation> {
            prop_oneof![
                // Set with key 1..64 bytes, value 0..512 bytes
                (
                    proptest::collection::vec(any::<u8>(), 1..64),
                    proptest::collection::vec(any::<u8>(), 0..512),
                )
                    .prop_map(|(key, value)| BatchOperation::Set { key, value }),
                // Delete with key 1..64 bytes
                proptest::collection::vec(any::<u8>(), 1..64)
                    .prop_map(|key| BatchOperation::Delete { key }),
            ]
        }

        /// Create a `BatchWriter` backed by `MemoryBackend` inside a tokio runtime
        /// (required because `MemoryBackend::new()` spawns a background task).
        fn make_writer(config: BatchConfig) -> BatchWriter<MemoryBackend> {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let backend = rt.block_on(async { MemoryBackend::new() });
            BatchWriter::new(backend, config)
        }

        /// Populate a writer with the given operations.
        fn populate(writer: &mut BatchWriter<MemoryBackend>, ops: &[BatchOperation]) {
            for op in ops {
                match op {
                    BatchOperation::Set { key, value } => {
                        writer.set(key.clone(), value.clone());
                    },
                    BatchOperation::Delete { key } => {
                        writer.delete(key.clone());
                    },
                }
            }
        }

        proptest! {
            /// The union of all sub-batches must equal the original operations list.
            /// No operations should be dropped or duplicated during splitting.
            #[test]
            fn split_preserves_all_operations(
                ops in proptest::collection::vec(arb_batch_operation(), 0..100),
                max_batch_size in 1..50usize,
                max_batch_bytes in 100..2000usize,
            ) {
                let mut writer = make_writer(BatchConfig::builder().max_batch_size(max_batch_size).max_batch_bytes(max_batch_bytes).build().unwrap());
                populate(&mut writer, &ops);

                let batches = writer.split_into_batches();
                let total: usize = batches.iter().map(|b| b.len()).sum();
                prop_assert_eq!(total, ops.len());
            }

            /// Each sub-batch must respect the configured size limits,
            /// unless a single operation exceeds the limit (in which case it gets its own batch).
            #[test]
            fn split_respects_byte_limit(
                ops in proptest::collection::vec(arb_batch_operation(), 1..50),
                max_batch_bytes in 100..5000usize,
            ) {
                let mut writer = make_writer(
                    BatchConfig::builder()
                        .max_batch_size(usize::MAX)
                        .max_batch_bytes(max_batch_bytes)
                        .build()
                        .expect("valid config"),
                );
                populate(&mut writer, &ops);

                let batches = writer.split_into_batches();
                for batch in &batches {
                    let batch_bytes: usize = batch.iter().map(|op| op.size_bytes()).sum();
                    // If batch has more than one operation, it must be within limit
                    if batch.len() > 1 {
                        prop_assert!(
                            batch_bytes <= max_batch_bytes,
                            "batch of {} ops has {} bytes, limit is {}",
                            batch.len(),
                            batch_bytes,
                            max_batch_bytes,
                        );
                    }
                }
            }

            /// Each sub-batch must respect the configured operation count limit.
            #[test]
            fn split_respects_count_limit(
                ops in proptest::collection::vec(arb_batch_operation(), 1..100),
                max_batch_size in 1..20usize,
            ) {
                let mut writer = make_writer(
                    BatchConfig::builder()
                        .max_batch_size(max_batch_size)
                        .max_batch_bytes(usize::MAX)
                        .build()
                        .expect("valid config"),
                );
                populate(&mut writer, &ops);

                let batches = writer.split_into_batches();
                for batch in &batches {
                    prop_assert!(
                        batch.len() <= max_batch_size,
                        "batch has {} ops, limit is {}",
                        batch.len(),
                        max_batch_size,
                    );
                }
            }

            /// An empty writer must produce zero batches.
            #[test]
            fn empty_writer_produces_no_batches(
                max_batch_size in 1..100usize,
                max_batch_bytes in 100..10000usize,
            ) {
                let writer = make_writer(BatchConfig::builder().max_batch_size(max_batch_size).max_batch_bytes(max_batch_bytes).build().unwrap());
                let batches = writer.split_into_batches();
                prop_assert!(batches.is_empty());
            }
        }
    }
}
