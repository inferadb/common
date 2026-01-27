//! Transaction implementation for the Ledger storage backend.
//!
//! This module provides [`LedgerTransaction`], which implements the
//! [`Transaction`](inferadb_common_storage::Transaction) trait for atomic
//! multi-operation commits to Ledger.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{StorageError, StorageResult, Transaction};
use inferadb_ledger_sdk::{LedgerClient, Operation, ReadConsistency};

use crate::error::LedgerStorageError;

/// Transaction for atomic operations on Ledger.
///
/// This transaction implementation buffers all writes (sets and deletes)
/// until [`commit`](Transaction::commit) is called. It provides read-your-writes
/// semantics within the transaction.
///
/// # Buffering
///
/// Operations are buffered in memory:
/// - `set(key, value)` stores the value in `pending_sets`
/// - `delete(key)` adds the key to `pending_deletes` and removes from `pending_sets`
///
/// When reading, the transaction first checks pending writes before
/// consulting the underlying storage.
///
/// # Commit Semantics
///
/// All buffered operations are submitted atomically via `client.write()`.
/// Either all operations succeed, or none are applied. If the commit fails
/// due to a conflict (e.g., another transaction modified the same keys),
/// a `StorageError::Conflict` is returned.
///
/// # Example
///
/// ```no_run
/// use inferadb_common_storage::{StorageBackend, Transaction};
/// use inferadb_common_storage_ledger::LedgerBackend;
///
/// # async fn example(backend: &LedgerBackend) -> Result<(), Box<dyn std::error::Error>> {
/// let mut txn = backend.transaction().await?;
///
/// // Buffer writes
/// txn.set(b"key1".to_vec(), b"value1".to_vec());
/// txn.set(b"key2".to_vec(), b"value2".to_vec());
///
/// // Read sees pending write
/// let value = txn.get(b"key1").await?;
/// assert_eq!(value, Some(bytes::Bytes::from("value1")));
///
/// // Commit atomically
/// txn.commit().await?;
/// # Ok(())
/// # }
/// ```
pub struct LedgerTransaction {
    /// The SDK client for reads and final commit.
    client: Arc<LedgerClient>,

    /// Namespace ID.
    namespace_id: i64,

    /// Optional vault ID.
    vault_id: Option<i64>,

    /// Read consistency level.
    read_consistency: ReadConsistency,

    /// Pending set operations: hex-encoded key -> value.
    pending_sets: HashMap<String, Vec<u8>>,

    /// Pending delete operations: hex-encoded keys.
    pending_deletes: HashSet<String>,
}

impl std::fmt::Debug for LedgerTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerTransaction")
            .field("namespace_id", &self.namespace_id)
            .field("vault_id", &self.vault_id)
            .field("pending_sets", &self.pending_sets.len())
            .field("pending_deletes", &self.pending_deletes.len())
            .finish()
    }
}

impl LedgerTransaction {
    /// Creates a new transaction.
    pub(crate) fn new(
        client: Arc<LedgerClient>,
        namespace_id: i64,
        vault_id: Option<i64>,
        read_consistency: ReadConsistency,
    ) -> Self {
        Self {
            client,
            namespace_id,
            vault_id,
            read_consistency,
            pending_sets: HashMap::new(),
            pending_deletes: HashSet::new(),
        }
    }

    /// Performs a read with the configured consistency level.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => {
                self.client
                    .read_consistent(self.namespace_id, self.vault_id, key)
                    .await
            }
            ReadConsistency::Eventual => {
                self.client
                    .read(self.namespace_id, self.vault_id, key)
                    .await
            }
        };

        result.map_err(LedgerStorageError::from)
    }
}

#[async_trait]
impl Transaction for LedgerTransaction {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let encoded_key = encode_key(key);

        // First, check if the key was deleted in this transaction
        if self.pending_deletes.contains(&encoded_key) {
            return Ok(None);
        }

        // Then, check if the key was set in this transaction
        if let Some(value) = self.pending_sets.get(&encoded_key) {
            return Ok(Some(Bytes::from(value.clone())));
        }

        // Finally, read from underlying storage
        match self.do_read(&encoded_key).await {
            Ok(Some(value)) => Ok(Some(Bytes::from(value))),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let encoded_key = encode_key(&key);

        // Remove from pending deletes if it was marked for deletion
        self.pending_deletes.remove(&encoded_key);

        // Add to pending sets
        self.pending_sets.insert(encoded_key, value);
    }

    fn delete(&mut self, key: Vec<u8>) {
        let encoded_key = encode_key(&key);

        // Remove from pending sets if it was set in this transaction
        self.pending_sets.remove(&encoded_key);

        // Add to pending deletes
        self.pending_deletes.insert(encoded_key);
    }

    async fn commit(self: Box<Self>) -> StorageResult<()> {
        // If there are no pending operations, this is a no-op
        if self.pending_sets.is_empty() && self.pending_deletes.is_empty() {
            return Ok(());
        }

        // Build the list of operations
        let mut operations =
            Vec::with_capacity(self.pending_sets.len() + self.pending_deletes.len());

        // Add set operations
        for (key, value) in self.pending_sets {
            operations.push(Operation::set_entity(key, value));
        }

        // Add delete operations
        for key in self.pending_deletes {
            operations.push(Operation::delete_entity(key));
        }

        // Submit all operations atomically
        self.client
            .write(self.namespace_id, self.vault_id, operations)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        Ok(())
    }
}

/// Encodes a key as a hexadecimal string.
fn encode_key(key: &[u8]) -> String {
    hex::encode(key)
}

// Note: Transaction tests are in tests/integration.rs using MockLedgerServer
// The tests there cover:
// - test_transaction_basic
// - test_transaction_delete
// - test_transaction_read_your_writes
// - test_transaction_delete_then_set
// - test_transaction_set_then_delete
// - test_transaction_empty_commit
