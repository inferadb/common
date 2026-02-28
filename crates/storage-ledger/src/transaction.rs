//! Transaction implementation for the Ledger storage backend.
//!
//! This module provides [`LedgerTransaction`], which implements the
//! [`Transaction`](inferadb_common_storage::Transaction) trait for atomic
//! multi-operation commits to Ledger.

use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    OrganizationSlug, StorageError, StorageResult, Transaction, VaultSlug,
};
use inferadb_ledger_sdk::{LedgerClient, Operation, ReadConsistency, SetCondition};

use crate::{error::LedgerStorageError, keys::encode_key};

/// Compare-and-set operation to be verified at commit time.
#[derive(Debug, Clone)]
struct CasOperation {
    /// Hex-encoded key.
    key: String,
    /// Expected current value (None means key should not exist).
    expected: Option<Vec<u8>>,
    /// New value to set if condition is met.
    new_value: Vec<u8>,
    /// Optional TTL for the new value.
    ttl: Option<Duration>,
}

/// Transaction for atomic operations on the Ledger backend.
///
/// This transaction implementation buffers all writes (sets, deletes, and
/// compare-and-sets) in memory until [`commit`](Transaction::commit) is
/// called, at which point all operations are submitted to the ledger in a
/// single atomic `client.write()` call.
///
/// # Isolation Guarantees
///
/// `LedgerTransaction` implements the [`Transaction`] trait's
/// **read-committed** isolation model:
///
/// - **Read-your-writes**: Reads check pending sets and deletes before consulting the ledger. A
///   [`set`](Transaction::set) followed by [`get`](Transaction::get) on the same key returns the
///   buffered value without a network round-trip.
///
/// - **Live reads**: Reads of unmodified keys go directly to the ledger with the configured
///   [`ReadConsistency`] level. With [`Linearizable`](ReadConsistency::Linearizable) consistency,
///   reads see the latest committed value. With [`Eventual`](ReadConsistency::Eventual)
///   consistency, reads may return stale data.
///
/// - **No snapshot isolation**: Two reads of the same unmodified key within one transaction may
///   return different values if another writer commits between them.
///
/// # Commit Semantics
///
/// All buffered operations are submitted to the ledger in a single
/// `client.write()` call, which provides **all-or-nothing** atomicity:
///
/// - If any compare-and-set condition fails (the ledger returns `FailedPrecondition`), the entire
///   write is rejected and [`StorageError::Conflict`] is returned. No operations are applied.
///
/// - On backend errors, no operations are applied.
///
/// - Unconditional set and delete operations within the same transaction always succeed together —
///   there is no partial commit.
///
/// # Limitations
///
/// - **No cross-transaction conflict detection for unconditional writes**: Two concurrent
///   transactions writing to the same key with [`set`](Transaction::set) (not
///   [`compare_and_set`](Transaction::compare_and_set)) will both succeed. The last one to commit
///   wins. Use [`compare_and_set`](Transaction::compare_and_set) to detect concurrent
///   modifications.
///
/// - **CAS conditions checked server-side**: The expected value in a compare-and-set is evaluated
///   by the ledger at commit time, not locally. This means CAS detects conflicts even from other
///   clients.
///
/// # Examples
///
/// ```no_run
/// // Requires a running Ledger server.
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
/// // Commit atomically — both writes succeed or neither does
/// txn.commit().await?;
/// # Ok(())
/// # }
/// ```
pub struct LedgerTransaction {
    /// The SDK client for reads and final commit.
    client: Arc<LedgerClient>,

    /// Organization ID.
    organization: OrganizationSlug,

    /// Optional vault ID.
    vault: Option<VaultSlug>,

    /// Read consistency level.
    read_consistency: ReadConsistency,

    /// Pending set operations: hex-encoded key -> value.
    pending_sets: HashMap<String, Vec<u8>>,

    /// Pending delete operations: hex-encoded keys.
    pending_deletes: HashSet<String>,

    /// Pending TTLs for set operations: hex-encoded key -> duration.
    pending_ttls: HashMap<String, Duration>,

    /// Pending compare-and-set operations.
    pending_cas: Vec<CasOperation>,
}

impl std::fmt::Debug for LedgerTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerTransaction")
            .field("organization", &self.organization)
            .field("vault", &self.vault)
            .field("pending_sets", &self.pending_sets.len())
            .field("pending_deletes", &self.pending_deletes.len())
            .field("pending_cas", &self.pending_cas.len())
            .finish()
    }
}

impl LedgerTransaction {
    /// Creates a new transaction.
    pub(crate) fn new(
        client: Arc<LedgerClient>,
        organization: OrganizationSlug,
        vault: Option<VaultSlug>,
        read_consistency: ReadConsistency,
    ) -> Self {
        Self {
            client,
            organization,
            vault,
            read_consistency,
            pending_sets: HashMap::new(),
            pending_deletes: HashSet::new(),
            pending_ttls: HashMap::new(),
            pending_cas: Vec::new(),
        }
    }

    /// Performs a read with the configured consistency level.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => {
                self.client.read_consistent(self.organization, self.vault, key).await
            },
            ReadConsistency::Eventual => self.client.read(self.organization, self.vault, key).await,
        };

        result.map_err(LedgerStorageError::from)
    }
}

#[async_trait]
impl Transaction for LedgerTransaction {
    /// Returns the buffered value for a key, falling back to the backend if not buffered.
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

    /// Buffers a set operation for atomic commit.
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let encoded_key = encode_key(&key);

        // Remove from pending deletes if it was marked for deletion
        self.pending_deletes.remove(&encoded_key);

        // Clear any pending TTL — a plain set produces a non-expiring key
        self.pending_ttls.remove(&encoded_key);

        // Add to pending sets
        self.pending_sets.insert(encoded_key, value);
    }

    /// Buffers a delete operation for atomic commit.
    fn delete(&mut self, key: Vec<u8>) {
        let encoded_key = encode_key(&key);

        // Clear any pending TTL
        self.pending_ttls.remove(&encoded_key);

        // Remove from pending sets if it was set in this transaction
        self.pending_sets.remove(&encoded_key);

        // Add to pending deletes
        self.pending_deletes.insert(encoded_key);
    }

    /// Buffers a compare-and-set operation for atomic commit.
    fn compare_and_set(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let encoded_key = encode_key(&key);

        // Buffer the CAS operation - it will be applied at commit time
        self.pending_cas.push(CasOperation { key: encoded_key, expected, new_value, ttl: None });
        Ok(())
    }

    /// Buffers a set operation with TTL for atomic commit.
    fn set_with_ttl(&mut self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) {
        let encoded_key = encode_key(&key);

        // Remove from pending deletes if it was marked for deletion
        self.pending_deletes.remove(&encoded_key);

        // Track the TTL for this key
        self.pending_ttls.insert(encoded_key.clone(), ttl);

        // Add to pending sets
        self.pending_sets.insert(encoded_key, value);
    }

    /// Buffers a compare-and-set operation with TTL for atomic commit.
    fn compare_and_set_with_ttl(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        let encoded_key = encode_key(&key);

        self.pending_cas.push(CasOperation {
            key: encoded_key,
            expected,
            new_value,
            ttl: Some(ttl),
        });
        Ok(())
    }

    /// Commits all buffered operations as a single atomic Ledger write.
    async fn commit(self: Box<Self>) -> StorageResult<()> {
        // If there are no pending operations, this is a no-op
        if self.pending_sets.is_empty()
            && self.pending_deletes.is_empty()
            && self.pending_cas.is_empty()
        {
            return Ok(());
        }

        // Capture SDK params before consuming fields via into_iter
        let organization = self.organization;
        let vault = self.vault;

        // Build the list of operations
        let mut operations = Vec::with_capacity(
            self.pending_sets.len() + self.pending_deletes.len() + self.pending_cas.len(),
        );

        // Add CAS operations first (they typically have ordering requirements)
        for cas in self.pending_cas {
            let condition = match cas.expected {
                None => SetCondition::NotExists,
                Some(expected_value) => SetCondition::ValueEquals(expected_value),
            };
            let expires_at =
                cas.ttl.map(crate::LedgerBackend::compute_expiration_timestamp).transpose()?;
            operations.push(Operation::SetEntity {
                key: cas.key,
                value: cas.new_value,
                expires_at,
                condition: Some(condition),
            });
        }

        // Add regular set operations
        for (key, value) in self.pending_sets {
            if let Some(ttl) = self.pending_ttls.get(&key) {
                let expires_at = crate::LedgerBackend::compute_expiration_timestamp(*ttl)?;
                operations.push(Operation::set_entity_with_expiry(key, value, expires_at));
            } else {
                operations.push(Operation::set_entity(key, value));
            }
        }

        // Add delete operations
        for key in self.pending_deletes {
            operations.push(Operation::delete_entity(key));
        }

        // Submit all operations atomically
        // If any CAS condition fails, the whole transaction fails
        use inferadb_ledger_sdk::SdkError;
        use tonic::Code;

        match self.client.write(organization, vault, operations).await {
            Ok(_) => Ok(()),
            Err(SdkError::Rpc { code: Code::FailedPrecondition, .. }) => {
                // CAS condition failed
                Err(StorageError::conflict())
            },
            Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
        }
    }
}

// Note: Transaction tests are in tests/integration.rs using MockLedgerServer
// The tests there cover:
// - test_transaction_basic
// - test_transaction_delete
// - test_transaction_read_your_writes
// - test_transaction_delete_then_set
// - test_transaction_set_then_delete
// - test_transaction_empty_commit

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_ledger_sdk::{ClientConfig, ServerSource, mock::MockLedgerServer};

    use super::*;

    async fn create_test_transaction(
        server: &MockLedgerServer,
        consistency: ReadConsistency,
    ) -> LedgerTransaction {
        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint()]))
            .client_id("test-client")
            .build()
            .expect("valid config");

        let client = Arc::new(LedgerClient::new(config).await.expect("client"));
        LedgerTransaction::new(
            client,
            OrganizationSlug::from(1),
            Some(VaultSlug::from(100)),
            consistency,
        )
    }

    #[tokio::test]
    async fn test_transaction_debug_impl() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let mut txn = create_test_transaction(&server, ReadConsistency::Linearizable).await;

        txn.set(b"key1".to_vec(), b"value1".to_vec());
        txn.set(b"key2".to_vec(), b"value2".to_vec());
        txn.delete(b"key3".to_vec());

        let debug_str = format!("{:?}", txn);

        assert!(debug_str.contains("LedgerTransaction"));
        assert!(debug_str.contains("organization: OrganizationSlug(1)"));
        assert!(debug_str.contains("vault: Some(VaultSlug(100))"));
        assert!(debug_str.contains("pending_sets: 2"));
        assert!(debug_str.contains("pending_deletes: 1"));
    }

    #[tokio::test]
    async fn test_transaction_with_eventual_consistency() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let mut txn = create_test_transaction(&server, ReadConsistency::Eventual).await;

        // Write a value
        txn.set(b"key".to_vec(), b"value".to_vec());

        // Read it back (should use pending_sets, not do_read)
        let value = txn.get(b"key").await.expect("get");
        assert_eq!(value.map(|b| b.to_vec()), Some(b"value".to_vec()));

        // Read a nonexistent key (should use eventual consistency do_read path)
        let value = txn.get(b"nonexistent").await.expect("get");
        assert!(value.is_none());
    }
}
