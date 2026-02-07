//! Transaction trait for atomic storage operations.
//!
//! This module defines the [`Transaction`] trait that enables atomic
//! multi-operation commits to storage backends.
//!
//! # Transaction Semantics
//!
//! Transactions provide:
//! - **Atomicity**: All operations in a transaction either succeed together or fail together
//! - **Read-your-writes**: Reads within a transaction see pending writes
//! - **Buffering**: Writes are buffered until commit
//!
//! # Example
//!
//! ```
//! use inferadb_common_storage::{MemoryBackend, StorageBackend};
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let backend = MemoryBackend::new();
//!
//! // Seed initial data
//! backend.set(b"account:alice".to_vec(), b"100".to_vec()).await.unwrap();
//! backend.set(b"account:bob".to_vec(), b"50".to_vec()).await.unwrap();
//!
//! // Atomic transfer via transaction
//! let mut txn = backend.transaction().await.unwrap();
//! txn.set(b"account:alice".to_vec(), b"80".to_vec());
//! txn.set(b"account:bob".to_vec(), b"70".to_vec());
//! txn.commit().await.unwrap();
//!
//! // Verify both writes applied atomically
//! let alice = backend.get(b"account:alice").await.unwrap().unwrap();
//! assert_eq!(&alice[..], b"80");
//! # });
//! ```

use async_trait::async_trait;
use bytes::Bytes;

use crate::error::StorageResult;

/// Transaction handle for atomic multi-operation commits.
///
/// A transaction buffers operations (sets and deletes) until [`commit`](Transaction::commit)
/// is called, at which point all operations are applied atomically.
///
/// Transactions support read-your-writes semantics: a [`get`](Transaction::get) call
/// will return data from pending writes within the same transaction.
///
/// # Concurrency
///
/// Transactions implement optimistic concurrency control. If another transaction
/// modifies the same keys and commits first, this transaction's commit will fail
/// with [`StorageError::Conflict`](crate::StorageError::Conflict).
#[async_trait]
pub trait Transaction: Send {
    /// Gets a value within the transaction.
    ///
    /// This method first checks pending writes within the transaction,
    /// then falls back to reading from the underlying storage if the
    /// key hasn't been modified in this transaction.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to look up
    ///
    /// # Returns
    ///
    /// - `Ok(Some(bytes))` if the key exists
    /// - `Ok(None)` if the key doesn't exist or was deleted in this transaction
    /// - `Err(...)` on storage errors
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>;

    /// Buffers a set operation within the transaction.
    ///
    /// The write is not immediately applied to storage; it is buffered
    /// and will be applied atomically when [`commit`](Transaction::commit) is called.
    ///
    /// Subsequent [`get`](Transaction::get) calls for this key within the
    /// same transaction will return the buffered value.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to set
    /// * `value` - The value to store
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>);

    /// Buffers a delete operation within the transaction.
    ///
    /// The delete is not immediately applied to storage; it is buffered
    /// and will be applied atomically when [`commit`](Transaction::commit) is called.
    ///
    /// Subsequent [`get`](Transaction::get) calls for this key within the
    /// same transaction will return `None`.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to delete
    fn delete(&mut self, key: Vec<u8>);

    /// Buffers a compare-and-set operation within the transaction.
    ///
    /// This is a conditional set that will only succeed if the current value
    /// of the key matches the expected value at commit time. If the condition
    /// fails, the entire transaction commit will fail.
    ///
    /// # Arguments
    ///
    /// * `key` - The key to update
    /// * `expected` - The expected current value. Use `None` to require the key doesn't exist.
    /// * `new_value` - The new value to set if the comparison succeeds
    ///
    /// # Returns
    ///
    /// - `Ok(())` if the operation was buffered successfully
    /// - `Err(...)` if the operation could not be buffered
    ///
    /// # Note
    ///
    /// The condition is checked at commit time, not when this method is called.
    /// If the condition fails at commit time, the entire transaction fails.
    fn compare_and_set(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> StorageResult<()>;

    /// Commits all buffered operations atomically.
    ///
    /// This method applies all pending sets and deletes to the underlying
    /// storage backend. If all operations succeed, they become visible to
    /// other transactions and reads.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Conflict`](crate::StorageError::Conflict) if another transaction modified
    ///   the same keys and committed first
    /// - Other [`StorageError`](crate::StorageError) variants on backend failures
    ///
    /// # Consumes
    ///
    /// This method consumes the transaction. After commit (successful or not),
    /// the transaction cannot be used further.
    async fn commit(self: Box<Self>) -> StorageResult<()>;
}
