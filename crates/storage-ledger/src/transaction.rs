//! Transaction implementation for the Ledger storage backend.
//!
//! This module provides [`LedgerTransaction`], which implements the
//! [`Transaction`](inferadb_common_storage::Transaction) trait for atomic
//! multi-operation commits to Ledger.

use std::{collections::HashMap, sync::Arc, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    OrganizationSlug, StorageError, StorageResult, Transaction, VaultSlug,
};
use inferadb_ledger_sdk::{LedgerClient, Operation, ReadConsistency, SetCondition};

use crate::{error::LedgerStorageError, keys::encode_key};

/// A buffered operation awaiting commit.
#[derive(Debug, Clone)]
enum PendingOp {
    /// Unconditional set (with optional TTL).
    Set { value: Vec<u8>, ttl: Option<Duration> },
    /// Unconditional delete.
    Delete,
    /// Compare-and-set (with optional TTL). The expected value is checked
    /// server-side at commit time.
    Cas { expected: Option<Vec<u8>>, new_value: Vec<u8>, ttl: Option<Duration> },
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
/// - **Read-your-writes**: Reads check pending operations (sets, deletes, and compare-and-sets)
///   before consulting the ledger. A [`set`](Transaction::set) or
///   [`compare_and_set`](Transaction::compare_and_set) followed by [`get`](Transaction::get) on the
///   same key returns the buffered value without a network round-trip. For CAS operations, the
///   speculative `new_value` is returned; this is safe because if the CAS condition fails at commit
///   time, the entire transaction is rejected atomically.
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

    /// Optional cancellation token for cooperative shutdown.
    cancellation_token: Option<tokio_util::sync::CancellationToken>,

    /// All pending operations keyed by hex-encoded storage key.
    pending: HashMap<String, PendingOp>,
}

impl std::fmt::Debug for LedgerTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let sets = self.pending.values().filter(|op| matches!(op, PendingOp::Set { .. })).count();
        let deletes = self.pending.values().filter(|op| matches!(op, PendingOp::Delete)).count();
        let cas = self.pending.values().filter(|op| matches!(op, PendingOp::Cas { .. })).count();

        f.debug_struct("LedgerTransaction")
            .field("organization", &self.organization)
            .field("vault", &self.vault)
            .field("pending_sets", &sets)
            .field("pending_deletes", &deletes)
            .field("pending_cas", &cas)
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
        cancellation_token: Option<tokio_util::sync::CancellationToken>,
    ) -> Self {
        Self {
            client,
            organization,
            vault,
            read_consistency,
            cancellation_token,
            pending: HashMap::new(),
        }
    }

    /// Performs a read with the configured consistency level and cancellation token.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        self.client
            .read(
                self.organization,
                self.vault,
                key,
                Some(self.read_consistency),
                self.cancellation_token.clone(),
            )
            .await
            .map_err(LedgerStorageError::from)
    }
}

#[async_trait]
impl Transaction for LedgerTransaction {
    /// Returns the buffered value for a key, falling back to the backend if not buffered.
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let encoded_key = encode_key(key);

        // Check pending operations for this key
        if let Some(op) = self.pending.get(&encoded_key) {
            return match op {
                PendingOp::Set { value, .. } => Ok(Some(Bytes::from(value.clone()))),
                PendingOp::Delete => Ok(None),
                PendingOp::Cas { new_value, .. } => Ok(Some(Bytes::from(new_value.clone()))),
            };
        }

        // Read from underlying storage
        match self.do_read(&encoded_key).await {
            Ok(Some(value)) => Ok(Some(Bytes::from(value))),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    /// Buffers a set operation for atomic commit.
    fn set(&mut self, key: Vec<u8>, value: Vec<u8>) {
        let encoded_key = encode_key(&key);
        self.pending.insert(encoded_key, PendingOp::Set { value, ttl: None });
    }

    /// Buffers a delete operation for atomic commit.
    fn delete(&mut self, key: Vec<u8>) {
        let encoded_key = encode_key(&key);
        self.pending.insert(encoded_key, PendingOp::Delete);
    }

    /// Buffers a compare-and-set operation for atomic commit.
    fn compare_and_set(
        &mut self,
        key: Vec<u8>,
        expected: Option<Vec<u8>>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let encoded_key = encode_key(&key);
        self.pending.insert(encoded_key, PendingOp::Cas { expected, new_value, ttl: None });
        Ok(())
    }

    /// Buffers a set operation with TTL for atomic commit.
    fn set_with_ttl(&mut self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) {
        let encoded_key = encode_key(&key);
        self.pending.insert(encoded_key, PendingOp::Set { value, ttl: Some(ttl) });
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
        self.pending.insert(encoded_key, PendingOp::Cas { expected, new_value, ttl: Some(ttl) });
        Ok(())
    }

    /// Commits all buffered operations as a single atomic Ledger write.
    async fn commit(self: Box<Self>) -> StorageResult<()> {
        if self.pending.is_empty() {
            return Ok(());
        }

        let organization = self.organization;
        let vault = self.vault;

        let mut operations = Vec::with_capacity(self.pending.len());

        for (key, op) in self.pending {
            match op {
                PendingOp::Set { value, ttl: None } => {
                    operations.push(Operation::set_entity(key, value, None, None));
                },
                PendingOp::Set { value, ttl: Some(ttl) } => {
                    let expires_at = crate::LedgerBackend::compute_expiration_timestamp(ttl)?;
                    operations.push(Operation::set_entity(key, value, Some(expires_at), None));
                },
                PendingOp::Delete => {
                    operations.push(Operation::delete_entity(key));
                },
                PendingOp::Cas { expected, new_value, ttl } => {
                    let condition = SetCondition::from_expected(expected);
                    let expires_at =
                        ttl.map(crate::LedgerBackend::compute_expiration_timestamp).transpose()?;
                    operations.push(Operation::SetEntity {
                        key,
                        value: new_value,
                        expires_at,
                        condition: Some(condition),
                    });
                },
            }
        }

        // Submit all operations atomically.
        // If any CAS condition fails, the whole transaction fails.
        match self.client.write(organization, vault, operations, self.cancellation_token).await {
            Ok(_) => Ok(()),
            Err(e) if e.is_cas_conflict() => Err(StorageError::conflict()),
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
            None,
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

        // Read it back (should use pending op, not do_read)
        let value = txn.get(b"key").await.expect("get");
        assert_eq!(value.map(|b| b.to_vec()), Some(b"value".to_vec()));

        // Read a nonexistent key (should use eventual consistency do_read path)
        let value = txn.get(b"nonexistent").await.expect("get");
        assert!(value.is_none());
    }
}
