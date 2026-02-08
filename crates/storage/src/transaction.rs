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
/// A transaction buffers operations (sets, deletes, and compare-and-sets)
/// until [`commit`](Transaction::commit) is called, at which point all
/// operations are applied atomically — either all succeed or none do.
///
/// # Isolation Model
///
/// Transactions provide **read-committed** isolation with **optimistic
/// concurrency control**:
///
/// - **Read-your-writes**: A [`get`](Transaction::get) call returns pending writes from the same
///   transaction. A [`set`](Transaction::set) followed by [`get`](Transaction::get) on the same key
///   returns the buffered value without hitting the backend.
///
/// - **Read-committed reads**: Reads of keys *not* modified in the transaction go directly to the
///   underlying storage and reflect the latest committed state. This means reads are **not
///   snapshot-isolated** — another transaction committing between two reads within this transaction
///   can cause the second read to return a different value.
///
/// - **Optimistic conflict detection**: No locks are held during the transaction. Conflicts are
///   detected at [`commit`](Transaction::commit) time. If a compare-and-set condition fails
///   (because another writer modified the key), the entire transaction is rejected with
///   [`StorageError::Conflict`](crate::StorageError).
///
/// - **All-or-nothing commit**: On success, all buffered operations become visible atomically. On
///   failure (CAS conflict, backend error), no operations are applied — the backend state is
///   unchanged.
///
/// # Concurrency
///
/// Concurrent transactions on overlapping keys behave as follows:
///
/// - **Unconditional writes** (`set`, `delete`) without CAS: the last transaction to commit wins.
///   No conflict is raised.
/// - **Compare-and-set** operations: if the key's value changed between CAS buffering and commit,
///   the commit fails with `Conflict`.
/// - **Aborted transactions** (dropped without commit) leave no trace.
///
/// # Comparison with SQL Isolation Levels
///
/// | Property | This Implementation |
/// |----------|---------------------|
/// | Dirty reads | Not possible (only committed data + own writes) |
/// | Non-repeatable reads | Possible (reads go to live storage) |
/// | Phantom reads | Possible (no range locks) |
/// | Write skew | Possible (only CAS-protected keys are checked) |
///
/// For stronger isolation, protect critical keys with
/// [`compare_and_set`](Transaction::compare_and_set) operations.
#[async_trait]
pub trait Transaction: Send {
    /// Gets a value within the transaction.
    ///
    /// This method first checks pending writes within the transaction,
    /// then falls back to reading from the underlying storage if the
    /// key hasn't been modified in this transaction.
    ///
    /// Because reads fall back to live storage (not a snapshot), the
    /// value returned may change between calls if another transaction
    /// commits a write to the same key. See [Isolation Model](Transaction)
    /// for details.
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
    #[must_use = "transaction operations may fail and errors must be handled"]
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
    /// fails, the entire transaction commit will fail with
    /// [`StorageError::Conflict`](crate::StorageError).
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
    /// - `Err(...)` if the operation could not be buffered (e.g., size limit exceeded)
    ///
    /// # Note
    ///
    /// The condition is checked at commit time, not when this method is called.
    /// If the condition fails at commit time, the entire transaction fails
    /// and no operations are applied.
    #[must_use = "compare-and-set may fail with a size limit error and must be handled"]
    fn compare_and_set(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> StorageResult<()>;

    /// Commits all buffered operations atomically.
    ///
    /// All pending sets, deletes, and compare-and-sets are applied to the
    /// underlying storage. If all operations succeed, they become visible
    /// to other transactions and reads atomically.
    ///
    /// # Atomicity
    ///
    /// - On success, all operations are applied. There is no partial commit.
    /// - On failure, no operations are applied. The backend state is unchanged.
    ///
    /// # Errors
    ///
    /// - [`StorageError::Conflict`](crate::StorageError) if a compare-and-set condition failed
    ///   (another writer modified the key)
    /// - Other [`StorageError`](crate::StorageError) variants on backend failures
    ///
    /// # Consumes
    ///
    /// This method consumes the transaction. After commit (successful or not),
    /// the transaction cannot be used further.
    #[must_use = "transaction commit may fail and errors must be handled"]
    async fn commit(self: Box<Self>) -> StorageResult<()>;
}
