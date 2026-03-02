//! Write-buffering wrapper for atomic multi-key commits.
//!
//! [`BufferedBackend`] wraps any [`StorageBackend`] and buffers all writes
//! in memory. Writes are only persisted to the underlying storage when
//! [`commit`](BufferedBackend::commit) is called, applying all changes in a
//! single atomic transaction.
//!
//! This is designed for callers that create multiple entities across different
//! repositories and need all-or-nothing semantics. Without this, each repo's
//! `create()` commits its own transaction independently — a failure partway
//! through leaves orphaned records.
//!
//! # Usage
//!
//! ```no_run
//! # use inferadb_common_storage::{BufferedBackend, MemoryBackend, StorageBackend};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let inner = MemoryBackend::new();
//! let buffered = BufferedBackend::new(inner.clone());
//!
//! buffered.set(b"user:1".to_vec(), b"alice".to_vec()).await?;
//! buffered.set(b"email:1".to_vec(), b"alice@test.com".to_vec()).await?;
//!
//! // All writes applied atomically:
//! buffered.commit().await?;
//! # Ok(())
//! # }
//! ```
//!
//! If any operation fails (or `commit()` is never called), nothing is
//! persisted — the buffer is simply dropped.

use std::{ops::RangeBounds, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use tokio::sync::Mutex;

use crate::{
    StorageBackend,
    error::StorageResult,
    health::{HealthProbe, HealthStatus},
    transaction::Transaction,
    types::KeyValue,
};

/// A write operation buffered for deferred commit.
#[derive(Debug, Clone)]
enum BufferedWrite {
    Set {
        key: Vec<u8>,
        value: Vec<u8>,
        ttl: Option<Duration>,
    },
    Delete {
        key: Vec<u8>,
    },
    CompareAndSet {
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
        ttl: Option<Duration>,
    },
}

/// A storage backend that buffers all writes for atomic commit.
///
/// Reads check the buffer first (most-recent-write-wins), then fall through
/// to the underlying storage. Writes accumulate in a shared buffer until
/// [`commit`](BufferedBackend::commit) flushes them all in one transaction.
///
/// # Range Queries
///
/// `get_range` and `clear_range` pass through to the inner backend and do
/// **not** reflect buffered writes. This is a documented limitation — callers
/// that need range-consistent reads should commit first.
#[derive(Clone)]
pub struct BufferedBackend<S: StorageBackend> {
    inner: S,
    buffer: Arc<Mutex<Vec<BufferedWrite>>>,
}

impl<S: StorageBackend + Clone + 'static> BufferedBackend<S> {
    /// Creates a new buffered backend wrapping the given storage.
    pub fn new(inner: S) -> Self {
        Self { inner, buffer: Arc::new(Mutex::new(Vec::new())) }
    }

    /// Commits all buffered writes to the underlying storage atomically.
    ///
    /// Opens a single transaction on the inner storage, applies every buffered
    /// set/delete/CAS, and commits. If the commit fails, no writes are persisted.
    ///
    /// After a successful commit the buffer is drained. Calling `commit()` on
    /// an empty buffer is a no-op.
    pub async fn commit(&self) -> StorageResult<()> {
        let mut buffer = self.buffer.lock().await;
        if buffer.is_empty() {
            return Ok(());
        }

        let mut txn = self.inner.transaction().await?;
        for write in buffer.iter() {
            match write {
                BufferedWrite::Set { key, value, ttl: None } => {
                    txn.set(key.clone(), value.clone());
                },
                BufferedWrite::Set { key, value, ttl: Some(ttl) } => {
                    txn.set_with_ttl(key.clone(), value.clone(), *ttl);
                },
                BufferedWrite::Delete { key } => txn.delete(key.clone()),
                BufferedWrite::CompareAndSet { key, expected, new_value, ttl: None } => {
                    txn.compare_and_set(key.clone(), expected.clone(), new_value.clone())?;
                },
                BufferedWrite::CompareAndSet { key, expected, new_value, ttl: Some(ttl) } => {
                    txn.compare_and_set_with_ttl(
                        key.clone(),
                        expected.clone(),
                        new_value.clone(),
                        *ttl,
                    )?;
                },
            }
        }
        txn.commit().await?;
        buffer.clear();
        Ok(())
    }

    /// Looks up a key in the buffer (most-recent-write-wins).
    ///
    /// Returns `Some(Some(bytes))` for a buffered set, `Some(None)` for a
    /// buffered delete, or `None` if the key is not in the buffer.
    async fn buffer_lookup(&self, key: &[u8]) -> Option<Option<Bytes>> {
        let buffer = self.buffer.lock().await;
        for write in buffer.iter().rev() {
            match write {
                BufferedWrite::Set { key: k, value, .. }
                | BufferedWrite::CompareAndSet { key: k, new_value: value, .. }
                    if k.as_slice() == key =>
                {
                    return Some(Some(Bytes::from(value.clone())));
                },
                BufferedWrite::Delete { key: k } if k.as_slice() == key => {
                    return Some(None);
                },
                _ => {},
            }
        }
        None
    }
}

#[async_trait]
impl<S: StorageBackend + Clone + 'static> StorageBackend for BufferedBackend<S> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        if let Some(result) = self.buffer_lookup(key).await {
            return Ok(result);
        }
        self.inner.get(key).await
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        self.buffer.lock().await.push(BufferedWrite::Set { key, value, ttl: None });
        Ok(())
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.buffer.lock().await.push(BufferedWrite::Delete { key: key.to_vec() });
        Ok(())
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.inner.get_range(range).await
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.inner.clear_range(range).await
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        self.buffer.lock().await.push(BufferedWrite::Set { key, value, ttl: Some(ttl) });
        Ok(())
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        Ok(Box::new(BufferedTransaction {
            inner: self.inner.clone(),
            parent_buffer: Arc::clone(&self.buffer),
            local_writes: Vec::new(),
        }))
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        self.buffer.lock().await.push(BufferedWrite::CompareAndSet {
            key: key.to_vec(),
            expected: expected.map(|e| e.to_vec()),
            new_value,
            ttl: None,
        });
        Ok(())
    }

    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        self.buffer.lock().await.push(BufferedWrite::CompareAndSet {
            key: key.to_vec(),
            expected: expected.map(|e| e.to_vec()),
            new_value,
            ttl: Some(ttl),
        });
        Ok(())
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.inner.health_check(probe).await
    }
}

/// A virtual transaction that accumulates writes and flushes them to the
/// parent [`BufferedBackend`]'s buffer on commit (instead of committing to
/// real storage).
struct BufferedTransaction<S: StorageBackend> {
    inner: S,
    parent_buffer: Arc<Mutex<Vec<BufferedWrite>>>,
    local_writes: Vec<BufferedWrite>,
}

#[async_trait]
impl<S: StorageBackend + 'static> Transaction for BufferedTransaction<S> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        // Check local transaction writes first
        for write in self.local_writes.iter().rev() {
            match write {
                BufferedWrite::Set { key: k, value, .. }
                | BufferedWrite::CompareAndSet { key: k, new_value: value, .. }
                    if k.as_slice() == key =>
                {
                    return Ok(Some(Bytes::from(value.clone())));
                },
                BufferedWrite::Delete { key: k } if k.as_slice() == key => {
                    return Ok(None);
                },
                _ => {},
            }
        }
        // Check parent buffer
        let buffer = self.parent_buffer.lock().await;
        for write in buffer.iter().rev() {
            match write {
                BufferedWrite::Set { key: k, value, .. }
                | BufferedWrite::CompareAndSet { key: k, new_value: value, .. }
                    if k.as_slice() == key =>
                {
                    return Ok(Some(Bytes::from(value.clone())));
                },
                BufferedWrite::Delete { key: k } if k.as_slice() == key => {
                    return Ok(None);
                },
                _ => {},
            }
        }
        drop(buffer);
        // Fall through to real storage
        self.inner.get(key).await
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        self.local_writes.push(BufferedWrite::Set { key, value, ttl: None });
    }

    fn delete(&mut self, key: Vec<u8>) {
        self.local_writes.push(BufferedWrite::Delete { key });
    }

    fn compare_and_set(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        self.local_writes.push(BufferedWrite::CompareAndSet {
            key,
            expected,
            new_value,
            ttl: None,
        });
        Ok(())
    }

    fn set_with_ttl(&mut self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) {
        self.local_writes.push(BufferedWrite::Set { key, value, ttl: Some(ttl) });
    }

    fn compare_and_set_with_ttl(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        self.local_writes.push(BufferedWrite::CompareAndSet {
            key,
            expected,
            new_value,
            ttl: Some(ttl),
        });
        Ok(())
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        let mut buffer = self.parent_buffer.lock().await;
        buffer.extend(self.local_writes);
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    #[tokio::test]
    async fn writes_not_visible_before_commit() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner.clone());

        buffered.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();

        // Visible through the buffered backend (read-your-writes)
        assert_eq!(buffered.get(b"key").await.unwrap(), Some(Bytes::from("value")));

        // NOT visible on the inner storage
        assert_eq!(inner.get(b"key").await.unwrap(), None);
    }

    #[tokio::test]
    async fn commit_persists_to_inner() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner.clone());

        buffered.set(b"k1".to_vec(), b"v1".to_vec()).await.unwrap();
        buffered.set(b"k2".to_vec(), b"v2".to_vec()).await.unwrap();
        buffered.commit().await.unwrap();

        assert_eq!(inner.get(b"k1").await.unwrap(), Some(Bytes::from("v1")));
        assert_eq!(inner.get(b"k2").await.unwrap(), Some(Bytes::from("v2")));
    }

    #[tokio::test]
    async fn uncommitted_writes_dropped() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner.clone());

        buffered.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
        drop(buffered);

        assert_eq!(inner.get(b"key").await.unwrap(), None);
    }

    #[tokio::test]
    async fn transaction_writes_buffered_not_committed() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner.clone());

        let mut txn = buffered.transaction().await.unwrap();
        txn.set(b"entity:1".to_vec(), b"data".to_vec());
        txn.set(b"index:1".to_vec(), b"1".to_vec());
        txn.commit().await.unwrap(); // Flushes to buffer, NOT to inner

        // Visible through buffered backend
        assert_eq!(buffered.get(b"entity:1").await.unwrap(), Some(Bytes::from("data")));

        // NOT visible on inner storage
        assert_eq!(inner.get(b"entity:1").await.unwrap(), None);

        // Now commit to inner
        buffered.commit().await.unwrap();
        assert_eq!(inner.get(b"entity:1").await.unwrap(), Some(Bytes::from("data")));
    }

    #[tokio::test]
    async fn delete_buffered() {
        let inner = MemoryBackend::new();
        inner.set(b"existing".to_vec(), b"data".to_vec()).await.unwrap();

        let buffered = BufferedBackend::new(inner.clone());

        buffered.delete(b"existing").await.unwrap();

        // Buffered backend sees the delete
        assert_eq!(buffered.get(b"existing").await.unwrap(), None);

        // Inner still has the key
        assert_eq!(inner.get(b"existing").await.unwrap(), Some(Bytes::from("data")));
    }

    #[tokio::test]
    async fn transaction_read_your_writes() {
        let inner = MemoryBackend::new();
        inner.set(b"pre".to_vec(), b"existing".to_vec()).await.unwrap();

        let buffered = BufferedBackend::new(inner.clone());

        buffered.set(b"buffered".to_vec(), b"val".to_vec()).await.unwrap();

        let txn = buffered.transaction().await.unwrap();

        // From parent buffer
        assert_eq!(txn.get(b"buffered").await.unwrap(), Some(Bytes::from("val")));

        // From inner storage
        assert_eq!(txn.get(b"pre").await.unwrap(), Some(Bytes::from("existing")));

        // Not found
        assert_eq!(txn.get(b"missing").await.unwrap(), None);
    }

    #[tokio::test]
    async fn multiple_transactions_accumulate() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner.clone());

        let mut txn1 = buffered.transaction().await.unwrap();
        txn1.set(b"user:1".to_vec(), b"alice".to_vec());
        txn1.commit().await.unwrap();

        let mut txn2 = buffered.transaction().await.unwrap();
        txn2.set(b"email:1".to_vec(), b"alice@test.com".to_vec());
        txn2.commit().await.unwrap();

        // Both visible through buffered backend
        assert_eq!(buffered.get(b"user:1").await.unwrap(), Some(Bytes::from("alice")));
        assert_eq!(buffered.get(b"email:1").await.unwrap(), Some(Bytes::from("alice@test.com")));

        // Neither visible on inner
        assert_eq!(inner.get(b"user:1").await.unwrap(), None);
        assert_eq!(inner.get(b"email:1").await.unwrap(), None);

        // Commit all atomically
        buffered.commit().await.unwrap();

        assert_eq!(inner.get(b"user:1").await.unwrap(), Some(Bytes::from("alice")));
        assert_eq!(inner.get(b"email:1").await.unwrap(), Some(Bytes::from("alice@test.com")));
    }

    #[tokio::test]
    async fn empty_commit_is_noop() {
        let inner = MemoryBackend::new();
        let buffered = BufferedBackend::new(inner);
        buffered.commit().await.unwrap();
    }
}
