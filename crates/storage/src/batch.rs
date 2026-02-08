//! Batch write operations for storage backends
//!
//! This module provides a generic [`BatchWriter`] that accumulates write operations
//! and flushes them in optimized batches. It automatically splits large batches
//! to respect transaction size limits.
//!
//! # Usage
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
//! let stats = writer.flush().await.unwrap();
//! assert_eq!(stats.operations_count, 3);
//! # });
//! ```
//!
//! # Transaction Size Limits
//!
//! Many storage backends (particularly FoundationDB) have transaction size limits.
//! The default configuration uses 9MB as the effective limit to leave room for
//! metadata overhead, staying safely under the 10MB FoundationDB limit.

use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

use crate::{ConfigError, StorageBackend, StorageResult};

/// Transaction size limit (10MB with safety margin).
/// We use 9MB as the effective limit to leave room for metadata overhead.
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

    /// Creates a disabled batch config.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            max_batch_size: DEFAULT_MAX_BATCH_SIZE,
            max_batch_bytes: DEFAULT_MAX_BATCH_BYTES,
            enabled: false,
        }
    }

    /// Creates a batch config optimized for large transactions.
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

/// Represents a single write operation in a batch
#[derive(Debug, Clone)]
pub enum BatchOperation {
    /// Set a key-value pair
    Set { key: Vec<u8>, value: Vec<u8> },
    /// Delete a key
    Delete { key: Vec<u8> },
}

impl BatchOperation {
    /// Calculate the approximate size of this operation in bytes
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

    /// Get the key for this operation
    #[must_use]
    pub fn key(&self) -> &[u8] {
        match self {
            BatchOperation::Set { key, .. } | BatchOperation::Delete { key } => key,
        }
    }
}

/// Statistics from a batch flush operation
#[derive(Debug, Clone, Default)]
pub struct BatchFlushStats {
    /// Number of operations flushed
    pub operations_count: usize,
    /// Number of sub-batches created (due to size limits)
    pub batches_count: usize,
    /// Total bytes written
    pub total_bytes: usize,
    /// Time taken to flush
    pub duration: Duration,
}

/// Batch writer for accumulating and flushing write operations
///
/// This writer accumulates write operations and flushes them in optimized batches.
/// It automatically splits large batches to respect transaction size limits.
pub struct BatchWriter<B: StorageBackend> {
    backend: B,
    operations: Vec<BatchOperation>,
    current_size_bytes: usize,
    config: BatchConfig,
}

impl<B: StorageBackend + Clone> BatchWriter<B> {
    /// Create a new batch writer
    #[must_use]
    pub fn new(backend: B, config: BatchConfig) -> Self {
        Self { backend, operations: Vec::new(), current_size_bytes: 0, config }
    }

    /// Add a set operation to the batch
    pub fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let op = BatchOperation::Set { key, value };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Add a delete operation to the batch
    pub fn delete(&mut self, key: Vec<u8>) {
        let op = BatchOperation::Delete { key };
        self.current_size_bytes += op.size_bytes();
        self.operations.push(op);
    }

    /// Get the current number of pending operations
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.operations.len()
    }

    /// Get the current estimated size in bytes
    #[must_use]
    pub fn pending_bytes(&self) -> usize {
        self.current_size_bytes
    }

    /// Check if the batch should be flushed based on size limits
    #[must_use]
    pub fn should_flush(&self) -> bool {
        if !self.config.enabled {
            return !self.operations.is_empty();
        }
        self.operations.len() >= self.config.max_batch_size
            || self.current_size_bytes >= self.config.max_batch_bytes
    }

    /// Get a reference to pending operations
    #[must_use]
    pub fn pending_operations(&self) -> &[BatchOperation] {
        &self.operations
    }

    /// Split operations into sub-batches that fit within size limits
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

    /// Flush all pending operations to the backend
    ///
    /// This method splits operations into appropriately-sized batches and
    /// commits each batch in a separate transaction for optimal performance.
    pub async fn flush(&mut self) -> StorageResult<BatchFlushStats> {
        if self.operations.is_empty() {
            return Ok(BatchFlushStats::default());
        }

        let start = Instant::now();
        let total_ops = self.operations.len();
        let total_bytes = self.current_size_bytes;

        let batches = self.split_into_batches();
        let batches_count = batches.len();

        debug!(
            operations = total_ops,
            bytes = total_bytes,
            batches = batches_count,
            "Flushing batch writes"
        );

        // Execute each sub-batch in its own transaction
        for (batch_idx, batch_ops) in batches.into_iter().enumerate() {
            let mut txn = self.backend.transaction().await?;

            for op in batch_ops {
                match op {
                    BatchOperation::Set { key, value } => {
                        txn.set(key.clone(), value.clone());
                    },
                    BatchOperation::Delete { key } => {
                        txn.delete(key.clone());
                    },
                }
            }

            txn.commit().await.map_err(|e| {
                warn!(batch = batch_idx, error = %e, "Batch commit failed");
                e
            })?;

            trace!(batch = batch_idx, "Batch committed successfully");
        }

        // Clear the pending operations
        self.operations.clear();
        self.current_size_bytes = 0;

        let stats = BatchFlushStats {
            operations_count: total_ops,
            batches_count,
            total_bytes,
            duration: start.elapsed(),
        };

        debug!(
            operations = stats.operations_count,
            batches = stats.batches_count,
            duration_ms = stats.duration.as_millis(),
            "Batch flush complete"
        );

        Ok(stats)
    }

    /// Clear all pending operations without flushing
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

        let stats = writer.flush().await.expect("flush failed");
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

        writer.flush().await.expect("flush failed");

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

        let stats = writer.flush().await.expect("flush failed");
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

        let stats = writer.flush().await.expect("flush failed");
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

        let stats = writer.flush().await.expect("flush failed");
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
        let stats = writer.flush().await.expect("flush failed");
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

        let stats = writer.flush().await.expect("flush failed");
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

        let stats = writer.flush().await.expect("flush failed");
        assert_eq!(stats.operations_count, 10);
        // With disabled config, uses TRANSACTION_SIZE_LIMIT and usize::MAX for ops
        // So all should fit in one batch
        assert_eq!(stats.batches_count, 1);
    }

    #[test]
    fn test_batch_flush_stats_default() {
        let stats = BatchFlushStats::default();
        assert_eq!(stats.operations_count, 0);
        assert_eq!(stats.batches_count, 0);
        assert_eq!(stats.total_bytes, 0);
        assert_eq!(stats.duration, std::time::Duration::ZERO);
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
