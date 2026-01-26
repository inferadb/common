//! In-memory storage backend implementation.
//!
//! This module provides [`MemoryBackend`], an in-memory implementation of
//! [`StorageBackend`] suitable for testing and development.
//!
//! # Features
//!
//! - **Thread-safe**: Uses [`parking_lot::RwLock`] for concurrent access
//! - **Ordered storage**: Keys are stored in a [`BTreeMap`] for efficient range queries
//! - **TTL support**: Background task cleans up expired keys
//! - **Transaction support**: MVCC-like semantics with read-your-writes
//!
//! # Example
//!
//! ```
//! use inferadb_storage::{MemoryBackend, StorageBackend};
//!
//! #[tokio::main]
//! async fn main() {
//!     let backend = MemoryBackend::new();
//!     
//!     backend.set(b"greeting".to_vec(), b"hello".to_vec()).await.unwrap();
//!     let value = backend.get(b"greeting").await.unwrap();
//!     
//!     assert_eq!(value.unwrap().as_ref(), b"hello");
//! }
//! ```
//!
//! # Performance Characteristics
//!
//! | Operation | Complexity |
//! |-----------|------------|
//! | get | O(log n) |
//! | set | O(log n) |
//! | delete | O(log n) |
//! | get_range | O(log n + k) where k is result size |
//!
//! # Limitations
//!
//! - Data is not persisted; all data is lost when the process exits
//! - No replication or distributed features
//! - TTL cleanup runs every second, so expiration is not precise

use std::{
    collections::BTreeMap,
    ops::{Bound, RangeBounds},
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::RwLock;
use tokio::time::sleep;

use crate::backend::StorageBackend;
use crate::error::StorageResult;
use crate::transaction::Transaction;
use crate::types::KeyValue;

/// In-memory storage backend using [`BTreeMap`].
///
/// This backend is primarily intended for testing but can also be used
/// for development or small-scale deployments where persistence is not required.
///
/// # Cloning
///
/// `MemoryBackend` is cheaply cloneable via [`Arc`]. All clones share the
/// same underlying data store.
#[derive(Clone)]
pub struct MemoryBackend {
    data: Arc<RwLock<BTreeMap<Vec<u8>, Bytes>>>,
    ttl_data: Arc<RwLock<BTreeMap<Vec<u8>, Instant>>>,
}

impl MemoryBackend {
    /// Creates a new in-memory storage backend.
    ///
    /// This also spawns a background task that periodically cleans up
    /// expired keys (those set with TTL via [`set_with_ttl`](StorageBackend::set_with_ttl)).
    ///
    /// # Example
    ///
    /// ```
    /// use inferadb_storage::MemoryBackend;
    ///
    /// #[tokio::main]
    /// async fn main() {
    ///     let backend = MemoryBackend::new();
    ///     // backend is now ready for use
    /// }
    /// ```
    pub fn new() -> Self {
        let backend = Self {
            data: Arc::new(RwLock::new(BTreeMap::new())),
            ttl_data: Arc::new(RwLock::new(BTreeMap::new())),
        };

        // Start background TTL cleanup task
        let backend_clone = backend.clone();
        tokio::spawn(async move {
            backend_clone.cleanup_expired_keys().await;
        });

        backend
    }

    /// Background task to clean up expired keys.
    ///
    /// Runs every second, scanning for and removing keys whose TTL has elapsed.
    async fn cleanup_expired_keys(&self) {
        loop {
            sleep(Duration::from_secs(1)).await;

            let now = Instant::now();
            let mut expired_keys = Vec::new();

            // Find expired keys
            {
                let ttl_guard = self.ttl_data.read();
                for (key, expiry) in ttl_guard.iter() {
                    if *expiry <= now {
                        expired_keys.push(key.clone());
                    }
                }
            }

            // Remove expired keys
            if !expired_keys.is_empty() {
                let mut data_guard = self.data.write();
                let mut ttl_guard = self.ttl_data.write();
                for key in expired_keys {
                    data_guard.remove(&key);
                    ttl_guard.remove(&key);
                }
            }
        }
    }

    /// Checks if a key has expired.
    fn is_expired(&self, key: &[u8]) -> bool {
        let ttl_guard = self.ttl_data.read();
        if let Some(expiry) = ttl_guard.get(key) {
            return *expiry <= Instant::now();
        }
        false
    }
}

impl Default for MemoryBackend {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl StorageBackend for MemoryBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check if key is expired
        if self.is_expired(key) {
            return Ok(None);
        }

        let data = self.data.read();
        Ok(data.get(key).cloned())
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let mut data = self.data.write();
        data.insert(key.clone(), Bytes::from(value));

        // Remove TTL if exists (set without TTL clears any existing TTL)
        {
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(&key);
        }

        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let mut data = self.data.write();
        data.remove(key);

        // Remove TTL if exists
        {
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(key);
        }

        Ok(())
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let data = self.data.read();

        let start = match range.start_bound() {
            Bound::Included(b) => Bound::Included(b.as_slice()),
            Bound::Excluded(b) => Bound::Excluded(b.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };

        let end = match range.end_bound() {
            Bound::Included(b) => Bound::Included(b.as_slice()),
            Bound::Excluded(b) => Bound::Excluded(b.as_slice()),
            Bound::Unbounded => Bound::Unbounded,
        };

        let results: Vec<KeyValue> = data
            .range::<[u8], _>((start, end))
            .filter(|(key, _)| !self.is_expired(key))
            .map(|(k, v)| KeyValue::new(Bytes::copy_from_slice(k), v.clone()))
            .collect();

        Ok(results)
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        let mut data = self.data.write();

        let keys_to_remove: Vec<Vec<u8>> = data.range(range).map(|(k, _)| k.clone()).collect();

        for key in keys_to_remove {
            data.remove(&key);
            let mut ttl_guard = self.ttl_data.write();
            ttl_guard.remove(&key);
        }

        Ok(())
    }

    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let mut data = self.data.write();
        let mut ttl_data = self.ttl_data.write();

        let expiry = Instant::now() + Duration::from_secs(ttl_seconds);

        data.insert(key.clone(), Bytes::from(value));
        ttl_data.insert(key, expiry);

        Ok(())
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        Ok(Box::new(MemoryTransaction::new(self.clone())))
    }

    async fn health_check(&self) -> StorageResult<()> {
        // Try to acquire read lock to verify we're not deadlocked
        let _unused = self.data.read();
        Ok(())
    }
}

/// In-memory transaction implementation.
///
/// Buffers writes and deletes until commit, providing read-your-writes
/// semantics within the transaction.
struct MemoryTransaction {
    backend: MemoryBackend,
    pending_writes: BTreeMap<Vec<u8>, Option<Vec<u8>>>,
}

impl MemoryTransaction {
    fn new(backend: MemoryBackend) -> Self {
        Self {
            backend,
            pending_writes: BTreeMap::new(),
        }
    }
}

#[async_trait]
impl Transaction for MemoryTransaction {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check pending writes first (read-your-writes)
        if let Some(value) = self.pending_writes.get(key) {
            return Ok(value.as_ref().map(|v| Bytes::copy_from_slice(v)));
        }

        // Otherwise, read from backend
        self.backend.get(key).await
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.pending_writes.insert(key, Some(value));
    }

    fn delete(&mut self, key: Vec<u8>) {
        self.pending_writes.insert(key, None);
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        let mut data = self.backend.data.write();

        // Apply all pending writes atomically
        for (key, value) in self.pending_writes {
            match value {
                Some(v) => {
                    data.insert(key, Bytes::from(v));
                }
                None => {
                    data.remove(&key);
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_basic_operations() {
        let backend = MemoryBackend::new();

        // Set and get
        backend
            .set(b"key1".to_vec(), b"value1".to_vec())
            .await
            .unwrap();
        let value = backend.get(b"key1").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value1")));

        // Delete
        backend.delete(b"key1").await.unwrap();
        let value = backend.get(b"key1").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_range_operations() {
        let backend = MemoryBackend::new();

        backend.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        backend.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        backend.set(b"c".to_vec(), b"3".to_vec()).await.unwrap();

        let range = backend
            .get_range(b"a".to_vec()..b"c".to_vec())
            .await
            .unwrap();
        assert_eq!(range.len(), 2);
        assert_eq!(range[0].key, Bytes::from("a"));
        assert_eq!(range[1].key, Bytes::from("b"));
    }

    #[tokio::test]
    async fn test_clear_range() {
        let backend = MemoryBackend::new();

        backend.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        backend.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        backend.set(b"c".to_vec(), b"3".to_vec()).await.unwrap();

        backend
            .clear_range(b"a".to_vec()..b"c".to_vec())
            .await
            .unwrap();

        assert_eq!(backend.get(b"a").await.unwrap(), None);
        assert_eq!(backend.get(b"b").await.unwrap(), None);
        assert_eq!(backend.get(b"c").await.unwrap(), Some(Bytes::from("3")));
    }

    #[tokio::test]
    async fn test_ttl() {
        let backend = MemoryBackend::new();

        backend
            .set_with_ttl(b"temp".to_vec(), b"value".to_vec(), 1)
            .await
            .unwrap();

        // Should exist immediately
        let value = backend.get(b"temp").await.unwrap();
        assert!(value.is_some());

        // Wait for expiry
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should be gone
        let value = backend.get(b"temp").await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_transaction() {
        let backend = MemoryBackend::new();

        backend
            .set(b"key1".to_vec(), b"value1".to_vec())
            .await
            .unwrap();

        let mut txn = backend.transaction().await.unwrap();

        // Read within transaction
        let value = txn.get(b"key1").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value1")));

        // Write within transaction
        txn.set(b"key2".to_vec(), b"value2".to_vec());

        // Read-your-writes: see uncommitted write
        let value = txn.get(b"key2").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value2")));

        // Delete within transaction
        txn.delete(b"key1".to_vec());

        // Read-your-writes: see uncommitted delete
        let value = txn.get(b"key1").await.unwrap();
        assert_eq!(value, None);

        // Commit transaction
        txn.commit().await.unwrap();

        // Verify changes are persisted
        let value1 = backend.get(b"key1").await.unwrap();
        assert_eq!(value1, None);

        let value2 = backend.get(b"key2").await.unwrap();
        assert_eq!(value2, Some(Bytes::from("value2")));
    }

    #[tokio::test]
    async fn test_health_check() {
        let backend = MemoryBackend::new();
        assert!(backend.health_check().await.is_ok());
    }

    #[tokio::test]
    async fn test_overwrite_clears_ttl() {
        let backend = MemoryBackend::new();

        // Set with TTL
        backend
            .set_with_ttl(b"key".to_vec(), b"temp".to_vec(), 1)
            .await
            .unwrap();

        // Overwrite without TTL
        backend
            .set(b"key".to_vec(), b"permanent".to_vec())
            .await
            .unwrap();

        // Wait past original TTL
        tokio::time::sleep(Duration::from_secs(2)).await;

        // Should still exist (TTL was cleared)
        let value = backend.get(b"key").await.unwrap();
        assert_eq!(value, Some(Bytes::from("permanent")));
    }

    #[tokio::test]
    async fn test_clone_shares_data() {
        let backend1 = MemoryBackend::new();
        let backend2 = backend1.clone();

        backend1
            .set(b"key".to_vec(), b"value".to_vec())
            .await
            .unwrap();

        let value = backend2.get(b"key").await.unwrap();
        assert_eq!(value, Some(Bytes::from("value")));
    }
}
