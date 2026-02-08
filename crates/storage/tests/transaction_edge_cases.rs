//! Transaction conflict detection, isolation, and edge case tests.
//!
//! Tests cover: CAS-based conflict detection, oversized batch handling,
//! empty transactions, mixed CAS + unconditional operations, abort isolation,
//! and transaction isolation model verification (read-committed semantics,
//! read-your-writes, commit atomicity, concurrent conflict detection).
//! These tests run against `MemoryBackend`.

#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use bytes::Bytes;
use inferadb_common_storage::{
    BatchConfig, BatchWriter, MemoryBackend, StorageBackend, StorageError,
};
use tokio::task::JoinSet;

// ============================================================================
// Conflict Detection Tests
// ============================================================================

/// Two transactions with CAS on the same key — one must receive `StorageError::Conflict`.
///
/// Security property: optimistic concurrency control prevents lost updates when
/// two transactions race on the same key.
#[tokio::test]
async fn test_two_transactions_same_key_cas_conflict() {
    let backend = MemoryBackend::new();
    backend.set(b"counter".to_vec(), b"0".to_vec()).await.expect("initial set");

    // Transaction A: read current value, CAS to "1"
    let mut txn_a = backend.transaction().await.expect("txn_a creation");
    txn_a
        .compare_and_set(b"counter".to_vec(), Some(b"0".to_vec()), b"1".to_vec())
        .expect("txn_a CAS buffer");

    // Transaction B: same key, CAS from "0" to "2"
    let mut txn_b = backend.transaction().await.expect("txn_b creation");
    txn_b
        .compare_and_set(b"counter".to_vec(), Some(b"0".to_vec()), b"2".to_vec())
        .expect("txn_b CAS buffer");

    // Commit A first — should succeed
    let result_a = txn_a.commit().await;
    assert!(result_a.is_ok(), "first transaction should commit successfully");

    // Commit B — should conflict because the value is now "1", not "0"
    let result_b = txn_b.commit().await;
    assert!(
        matches!(result_b, Err(StorageError::Conflict { .. })),
        "second transaction should get Conflict, got: {result_b:?}"
    );

    // Final value should be from txn_a
    let final_value = backend.get(b"counter").await.expect("final get");
    assert_eq!(final_value, Some(Bytes::from("1")));
}

/// Multiple concurrent transactions racing on CAS — exactly one winner per round.
#[tokio::test]
async fn test_concurrent_transaction_cas_exactly_one_winner() {
    const CONCURRENCY: usize = 8;
    const ROUNDS: usize = 10;

    let backend = MemoryBackend::new();

    for round in 0..ROUNDS {
        let initial = format!("round-{round}");
        backend
            .set(b"race-key".to_vec(), initial.as_bytes().to_vec())
            .await
            .expect("reset key for round");

        let mut set = JoinSet::new();
        for task_id in 0..CONCURRENCY {
            let backend = backend.clone();
            let expected = initial.clone();
            set.spawn(async move {
                let mut txn = backend.transaction().await.expect("txn creation");
                txn.compare_and_set(
                    b"race-key".to_vec(),
                    Some(expected.into_bytes()),
                    format!("winner-{task_id}").into_bytes(),
                )
                .expect("CAS buffer");
                txn.commit().await
            });
        }

        let mut successes = 0usize;
        let mut conflicts = 0usize;
        while let Some(result) = set.join_next().await {
            match result.expect("task should not panic") {
                Ok(()) => successes += 1,
                Err(StorageError::Conflict { .. }) => conflicts += 1,
                Err(e) => panic!("unexpected error in round {round}: {e}"),
            }
        }

        assert_eq!(successes, 1, "round {round}: exactly one should succeed");
        assert_eq!(conflicts, CONCURRENCY - 1, "round {round}: rest should conflict");
    }
}

/// Insert-if-absent conflict: two transactions both try to insert the same new key.
#[tokio::test]
async fn test_two_transactions_insert_if_absent_conflict() {
    let backend = MemoryBackend::new();

    // Transaction A: insert "new-key" if absent
    let mut txn_a = backend.transaction().await.expect("txn_a creation");
    txn_a
        .compare_and_set(b"new-key".to_vec(), None, b"value-a".to_vec())
        .expect("txn_a CAS buffer");

    // Transaction B: same key, insert if absent
    let mut txn_b = backend.transaction().await.expect("txn_b creation");
    txn_b
        .compare_and_set(b"new-key".to_vec(), None, b"value-b".to_vec())
        .expect("txn_b CAS buffer");

    // A commits first
    txn_a.commit().await.expect("txn_a commit");

    // B should conflict because the key now exists
    let result_b = txn_b.commit().await;
    assert!(
        matches!(result_b, Err(StorageError::Conflict { .. })),
        "insert-if-absent should conflict when key was created, got: {result_b:?}"
    );

    assert_eq!(backend.get(b"new-key").await.expect("final get"), Some(Bytes::from("value-a")));
}

// ============================================================================
// Oversized Transaction / Batch Splitting Tests
// ============================================================================

/// Batch exceeding the default byte limit is split into multiple sub-transactions.
#[tokio::test]
async fn test_oversized_batch_splits_correctly() {
    let backend = MemoryBackend::new();

    // Use a small batch config to make splitting testable without 9MB of data
    let config = BatchConfig::builder()
        .max_batch_bytes(1024) // 1KB per batch
        .max_batch_size(100)
        .build()
        .expect("valid batch config");
    let mut writer = BatchWriter::new(backend.clone(), config);

    // Write 10 operations each ~200 bytes → ~2KB total, should split into 2+ batches
    for i in 0..10 {
        let key = format!("batch-key-{i:04}");
        let value = vec![0xABu8; 200];
        writer.set(key.into_bytes(), value);
    }

    let stats = writer.flush_all().await.expect("flush should succeed");

    // Should have split into multiple batches
    assert!(stats.batches_count >= 2, "expected multiple batches, got {}", stats.batches_count);
    assert_eq!(stats.operations_count, 10);

    // All values should be present after flush
    for i in 0..10 {
        let key = format!("batch-key-{i:04}");
        let val = backend.get(key.as_bytes()).await.expect("get after flush");
        assert!(val.is_some(), "key {key} should exist after batch flush");
        assert_eq!(val.expect("checked above").len(), 200);
    }
}

/// Batch split by operation count limit.
#[tokio::test]
async fn test_batch_split_by_count_limit() {
    let backend = MemoryBackend::new();

    let config = BatchConfig::builder()
        .max_batch_size(5) // Only 5 ops per batch
        .max_batch_bytes(usize::MAX)
        .build()
        .expect("valid batch config");
    let mut writer = BatchWriter::new(backend.clone(), config);

    // 20 operations should split into 4 batches of 5
    for i in 0..20 {
        writer.set(format!("key-{i}").into_bytes(), b"value".to_vec());
    }

    let stats = writer.flush_all().await.expect("flush should succeed");
    assert_eq!(stats.batches_count, 4);
    assert_eq!(stats.operations_count, 20);

    // All 20 keys present
    for i in 0..20 {
        assert!(
            backend.get(format!("key-{i}").as_bytes()).await.expect("get").is_some(),
            "key-{i} should exist"
        );
    }
}

/// Single operation exceeding byte limit gets its own batch.
#[tokio::test]
async fn test_oversized_single_operation_in_own_batch() {
    let backend = MemoryBackend::new();

    let config = BatchConfig::builder()
        .max_batch_bytes(100) // Very small limit
        .max_batch_size(1000)
        .build()
        .expect("valid batch config");
    let mut writer = BatchWriter::new(backend.clone(), config);

    // Small op, large op, small op
    writer.set(b"small-1".to_vec(), b"tiny".to_vec());
    writer.set(b"large".to_vec(), vec![0xFFu8; 500]); // Exceeds 100B limit
    writer.set(b"small-2".to_vec(), b"tiny".to_vec());

    let stats = writer.flush_all().await.expect("flush");

    // Large op gets its own batch; small ops may share or get separate batches
    assert!(
        stats.batches_count >= 2,
        "oversized op should force a batch split, got {} batches",
        stats.batches_count
    );

    assert!(backend.get(b"small-1").await.expect("get").is_some());
    assert!(backend.get(b"large").await.expect("get").is_some());
    assert!(backend.get(b"small-2").await.expect("get").is_some());
}

// ============================================================================
// Empty Transaction Tests
// ============================================================================

/// Empty MemoryBackend transaction commit is a no-op.
#[tokio::test]
async fn test_empty_transaction_commit_noop() {
    let backend = MemoryBackend::new();

    // Pre-populate to verify nothing changes
    backend.set(b"existing".to_vec(), b"untouched".to_vec()).await.expect("setup");

    let txn = backend.transaction().await.expect("empty txn");
    txn.commit().await.expect("empty commit should succeed");

    // Existing data unchanged
    assert_eq!(backend.get(b"existing").await.expect("get"), Some(Bytes::from("untouched")));
}

/// Empty BatchWriter flush produces zero batches.
#[tokio::test]
async fn test_empty_batch_flush_noop() {
    let backend = MemoryBackend::new();
    let mut writer =
        BatchWriter::new(backend, BatchConfig::builder().build().expect("valid batch config"));

    let stats = writer.flush_all().await.expect("empty flush");
    assert_eq!(stats.operations_count, 0);
    assert_eq!(stats.batches_count, 0);
}

// ============================================================================
// Mixed CAS + Unconditional Operations
// ============================================================================

/// Transaction with both CAS and regular set/delete operations.
#[tokio::test]
async fn test_mixed_cas_and_unconditional_operations() {
    let backend = MemoryBackend::new();
    backend.set(b"cas-key".to_vec(), b"original".to_vec()).await.expect("setup");
    backend.set(b"uncond-key".to_vec(), b"old-value".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn creation");

    // CAS operation: conditional update
    txn.compare_and_set(b"cas-key".to_vec(), Some(b"original".to_vec()), b"cas-updated".to_vec())
        .expect("CAS buffer");

    // Unconditional set: always succeeds
    txn.set(b"uncond-key".to_vec(), b"new-value".to_vec());

    // Unconditional delete
    txn.delete(b"delete-me".to_vec());

    // New key via unconditional set
    txn.set(b"new-key".to_vec(), b"brand-new".to_vec());

    txn.commit().await.expect("mixed commit");

    // Verify all operations applied
    assert_eq!(backend.get(b"cas-key").await.expect("get"), Some(Bytes::from("cas-updated")));
    assert_eq!(backend.get(b"uncond-key").await.expect("get"), Some(Bytes::from("new-value")));
    assert_eq!(backend.get(b"delete-me").await.expect("get"), None);
    assert_eq!(backend.get(b"new-key").await.expect("get"), Some(Bytes::from("brand-new")));
}

/// When CAS fails in a mixed transaction, unconditional operations are also rolled back.
///
/// This verifies atomicity: either all operations in a transaction succeed or none do.
#[tokio::test]
async fn test_mixed_transaction_cas_failure_rolls_back_unconditional() {
    let backend = MemoryBackend::new();
    backend.set(b"cas-key".to_vec(), b"original".to_vec()).await.expect("setup");
    backend.set(b"uncond-key".to_vec(), b"old-value".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn creation");

    // CAS with wrong expected value — will fail at commit
    txn.compare_and_set(
        b"cas-key".to_vec(),
        Some(b"WRONG_VALUE".to_vec()),
        b"should-not-apply".to_vec(),
    )
    .expect("CAS buffer");

    // Unconditional operations that should NOT apply if CAS fails
    txn.set(b"uncond-key".to_vec(), b"should-not-appear".to_vec());
    txn.set(b"new-key".to_vec(), b"should-not-exist".to_vec());

    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::Conflict { .. })),
        "CAS mismatch should cause Conflict: {result:?}"
    );

    // All state should be unchanged — atomicity guarantee
    assert_eq!(
        backend.get(b"cas-key").await.expect("get"),
        Some(Bytes::from("original")),
        "CAS key should be unchanged after failed transaction"
    );
    assert_eq!(
        backend.get(b"uncond-key").await.expect("get"),
        Some(Bytes::from("old-value")),
        "unconditional key should be unchanged after failed transaction"
    );
    assert_eq!(
        backend.get(b"new-key").await.expect("get"),
        None,
        "new key should not exist after failed transaction"
    );
}

/// Transaction with multiple CAS operations — all must hold for commit.
#[tokio::test]
async fn test_multiple_cas_operations_all_must_hold() {
    let backend = MemoryBackend::new();
    backend.set(b"key-a".to_vec(), b"a-value".to_vec()).await.expect("setup");
    backend.set(b"key-b".to_vec(), b"b-value".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // Both CAS operations match
    txn.compare_and_set(b"key-a".to_vec(), Some(b"a-value".to_vec()), b"a-new".to_vec())
        .expect("CAS a");
    txn.compare_and_set(b"key-b".to_vec(), Some(b"b-value".to_vec()), b"b-new".to_vec())
        .expect("CAS b");

    txn.commit().await.expect("both CAS should succeed");

    assert_eq!(backend.get(b"key-a").await.expect("get"), Some(Bytes::from("a-new")));
    assert_eq!(backend.get(b"key-b").await.expect("get"), Some(Bytes::from("b-new")));
}

/// If any one CAS operation fails, the entire transaction fails.
#[tokio::test]
async fn test_one_failed_cas_aborts_entire_transaction() {
    let backend = MemoryBackend::new();
    backend.set(b"key-a".to_vec(), b"a-value".to_vec()).await.expect("setup");
    backend.set(b"key-b".to_vec(), b"b-value".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // First CAS matches
    txn.compare_and_set(b"key-a".to_vec(), Some(b"a-value".to_vec()), b"a-new".to_vec())
        .expect("CAS a");
    // Second CAS does NOT match
    txn.compare_and_set(b"key-b".to_vec(), Some(b"WRONG".to_vec()), b"b-new".to_vec())
        .expect("CAS b");

    let result = txn.commit().await;
    assert!(matches!(result, Err(StorageError::Conflict { .. })));

    // Neither key should be modified — all-or-nothing
    assert_eq!(
        backend.get(b"key-a").await.expect("get"),
        Some(Bytes::from("a-value")),
        "key-a should be unchanged when sibling CAS fails"
    );
    assert_eq!(
        backend.get(b"key-b").await.expect("get"),
        Some(Bytes::from("b-value")),
        "key-b should be unchanged"
    );
}

// ============================================================================
// Abort Isolation Tests
// ============================================================================

/// Dropping a transaction without committing leaves no trace in the backend.
///
/// This is the fundamental isolation property: uncommitted writes must be invisible.
#[tokio::test]
async fn test_abort_isolation_uncommitted_writes_invisible() {
    let backend = MemoryBackend::new();
    backend.set(b"existing".to_vec(), b"original".to_vec()).await.expect("setup");

    {
        let mut txn = backend.transaction().await.expect("txn creation");

        // Buffer several writes
        txn.set(b"new-key".to_vec(), b"should-not-persist".to_vec());
        txn.set(b"existing".to_vec(), b"overwrite-should-not-persist".to_vec());
        txn.delete(b"existing".to_vec());

        // Read-your-writes works within the transaction
        assert_eq!(
            txn.get(b"new-key").await.expect("ryw"),
            Some(Bytes::from("should-not-persist"))
        );
        assert_eq!(txn.get(b"existing").await.expect("ryw"), None);

        // Drop the transaction without committing
    }

    // Backend should be completely unaffected
    assert_eq!(
        backend.get(b"existing").await.expect("get"),
        Some(Bytes::from("original")),
        "existing key should be unchanged after aborted transaction"
    );
    assert_eq!(
        backend.get(b"new-key").await.expect("get"),
        None,
        "new key should not exist after aborted transaction"
    );
}

/// CAS operations in an aborted transaction leave no state.
#[tokio::test]
async fn test_abort_isolation_cas_operations_invisible() {
    let backend = MemoryBackend::new();
    backend.set(b"key".to_vec(), b"original".to_vec()).await.expect("setup");

    {
        let mut txn = backend.transaction().await.expect("txn");
        txn.compare_and_set(b"key".to_vec(), Some(b"original".to_vec()), b"cas-value".to_vec())
            .expect("CAS buffer");
        // Drop without committing
    }

    assert_eq!(
        backend.get(b"key").await.expect("get"),
        Some(Bytes::from("original")),
        "CAS from aborted transaction should have no effect"
    );
}

/// Multiple transactions: one aborts, one commits — only the committed one persists.
#[tokio::test]
async fn test_abort_and_commit_isolation() {
    let backend = MemoryBackend::new();
    backend.set(b"shared".to_vec(), b"initial".to_vec()).await.expect("setup");

    // Transaction A: will abort
    let mut txn_a = backend.transaction().await.expect("txn_a");
    txn_a.set(b"shared".to_vec(), b"from-a".to_vec());
    txn_a.set(b"only-a".to_vec(), b"a-data".to_vec());
    // Drop txn_a without committing

    // Transaction B: will commit
    let mut txn_b = backend.transaction().await.expect("txn_b");
    txn_b.set(b"shared".to_vec(), b"from-b".to_vec());
    txn_b.set(b"only-b".to_vec(), b"b-data".to_vec());
    txn_b.commit().await.expect("txn_b commit");

    // Only B's changes should be visible
    assert_eq!(backend.get(b"shared").await.expect("get"), Some(Bytes::from("from-b")));
    assert_eq!(backend.get(b"only-a").await.expect("get"), None);
    assert_eq!(backend.get(b"only-b").await.expect("get"), Some(Bytes::from("b-data")));
}

// ============================================================================
// Additional Edge Cases
// ============================================================================

/// Transaction with CAS on a key that has a TTL — expired keys behave as absent.
#[tokio::test]
async fn test_transaction_cas_on_expired_ttl_key() {
    let backend = MemoryBackend::new();

    // Set a key with very short TTL
    backend
        .set_with_ttl(b"ttl-key".to_vec(), b"ephemeral".to_vec(), Duration::from_millis(50))
        .await
        .expect("set_with_ttl");

    // Wait for expiry
    tokio::time::sleep(Duration::from_millis(100)).await;

    // CAS with expected=None should succeed (key is logically absent)
    let mut txn = backend.transaction().await.expect("txn");
    txn.compare_and_set(b"ttl-key".to_vec(), None, b"new-value".to_vec()).expect("CAS buffer");
    txn.commit().await.expect("CAS insert-if-absent on expired key should succeed");

    assert_eq!(backend.get(b"ttl-key").await.expect("get"), Some(Bytes::from("new-value")));
}

/// Large transaction with many operations (no CAS) commits successfully.
#[tokio::test]
async fn test_large_transaction_many_operations() {
    let backend = MemoryBackend::new();

    let mut txn = backend.transaction().await.expect("txn");

    // Buffer 1000 operations
    for i in 0..1000 {
        txn.set(format!("bulk-{i:05}").into_bytes(), format!("value-{i}").into_bytes());
    }

    txn.commit().await.expect("large commit should succeed");

    // Spot-check a few values
    assert_eq!(backend.get(b"bulk-00000").await.expect("get"), Some(Bytes::from("value-0")));
    assert_eq!(backend.get(b"bulk-00500").await.expect("get"), Some(Bytes::from("value-500")));
    assert_eq!(backend.get(b"bulk-00999").await.expect("get"), Some(Bytes::from("value-999")));
}

/// Transaction that only contains CAS operations (no regular sets/deletes).
#[tokio::test]
async fn test_transaction_only_cas_operations() {
    let backend = MemoryBackend::new();
    backend.set(b"a".to_vec(), b"1".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");
    txn.compare_and_set(b"a".to_vec(), Some(b"1".to_vec()), b"2".to_vec()).expect("CAS");
    txn.compare_and_set(b"b".to_vec(), None, b"new".to_vec()).expect("CAS insert");

    txn.commit().await.expect("CAS-only commit");

    assert_eq!(backend.get(b"a").await.expect("get"), Some(Bytes::from("2")));
    assert_eq!(backend.get(b"b").await.expect("get"), Some(Bytes::from("new")));
}

/// Transaction that only deletes keys (no sets or CAS).
#[tokio::test]
async fn test_transaction_only_deletes() {
    let backend = MemoryBackend::new();
    backend.set(b"x".to_vec(), b"1".to_vec()).await.expect("setup");
    backend.set(b"y".to_vec(), b"2".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");
    txn.delete(b"x".to_vec());
    txn.delete(b"y".to_vec());
    txn.delete(b"nonexistent".to_vec()); // Deleting nonexistent key is a no-op

    txn.commit().await.expect("delete-only commit");

    assert_eq!(backend.get(b"x").await.expect("get"), None);
    assert_eq!(backend.get(b"y").await.expect("get"), None);
}

// ============================================================================
// Transaction Isolation Tests (Task 14)
// ============================================================================

/// Transaction reads its own uncommitted writes for all operation types.
///
/// Verifies the read-your-writes guarantee: `set`, `delete`, and overwrite
/// within a transaction are all visible to subsequent `get` calls in the
/// same transaction, while the backend is unaffected until commit.
#[tokio::test]
async fn test_transaction_reads_own_uncommitted_writes_comprehensively() {
    let backend = MemoryBackend::new();
    backend.set(b"pre-existing".to_vec(), b"original".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // 1. New key: set then read
    txn.set(b"new-key".to_vec(), b"new-value".to_vec());
    assert_eq!(
        txn.get(b"new-key").await.expect("ryw set"),
        Some(Bytes::from("new-value")),
        "set followed by get should return buffered value"
    );

    // 2. Overwrite: set existing key then read
    txn.set(b"pre-existing".to_vec(), b"overwritten".to_vec());
    assert_eq!(
        txn.get(b"pre-existing").await.expect("ryw overwrite"),
        Some(Bytes::from("overwritten")),
        "overwrite should be visible within the transaction"
    );

    // 3. Delete: delete then read
    txn.delete(b"pre-existing".to_vec());
    assert_eq!(
        txn.get(b"pre-existing").await.expect("ryw delete"),
        None,
        "deleted key should return None within the transaction"
    );

    // 4. Re-set after delete: set the deleted key again
    txn.set(b"pre-existing".to_vec(), b"resurrected".to_vec());
    assert_eq!(
        txn.get(b"pre-existing").await.expect("ryw re-set"),
        Some(Bytes::from("resurrected")),
        "re-setting a deleted key should be visible"
    );

    // Backend is still unaffected (uncommitted)
    assert_eq!(
        backend.get(b"new-key").await.expect("backend check"),
        None,
        "uncommitted write should not be visible outside transaction"
    );
    assert_eq!(
        backend.get(b"pre-existing").await.expect("backend check"),
        Some(Bytes::from("original")),
        "backend should still have original value"
    );

    // Commit and verify persistence
    txn.commit().await.expect("commit");

    assert_eq!(backend.get(b"new-key").await.expect("post-commit"), Some(Bytes::from("new-value")));
    assert_eq!(
        backend.get(b"pre-existing").await.expect("post-commit"),
        Some(Bytes::from("resurrected"))
    );
}

/// Reads within a transaction see concurrent commits (read-committed, not snapshot).
///
/// This test proves that transactions are NOT snapshot-isolated: a read of an
/// unmodified key returns the latest committed value, which may change between
/// reads within the same transaction.
#[tokio::test]
async fn test_reads_are_not_snapshot_isolated() {
    let backend = MemoryBackend::new();
    backend.set(b"shared".to_vec(), b"v1".to_vec()).await.expect("setup");

    let txn = backend.transaction().await.expect("txn");

    // First read: sees v1
    let first_read = txn.get(b"shared").await.expect("first read");
    assert_eq!(first_read, Some(Bytes::from("v1")));

    // Another writer commits a change while our transaction is open
    backend.set(b"shared".to_vec(), b"v2".to_vec()).await.expect("concurrent write");

    // Second read: sees v2 (read-committed, not snapshot)
    let second_read = txn.get(b"shared").await.expect("second read");
    assert_eq!(
        second_read,
        Some(Bytes::from("v2")),
        "read-committed isolation: second read should see the concurrent commit"
    );
}

/// Concurrent unconditional writes to overlapping keys — last commit wins.
///
/// Without compare-and-set, two transactions writing to the same key both
/// succeed. The final value is from whichever transaction committed last.
/// No `StorageError::Conflict` is raised.
#[tokio::test]
async fn test_concurrent_unconditional_writes_last_commit_wins() {
    let backend = MemoryBackend::new();
    backend.set(b"key".to_vec(), b"initial".to_vec()).await.expect("setup");

    // Both transactions read and prepare unconditional writes
    let mut txn_a = backend.transaction().await.expect("txn_a");
    let mut txn_b = backend.transaction().await.expect("txn_b");

    txn_a.set(b"key".to_vec(), b"from-A".to_vec());
    txn_b.set(b"key".to_vec(), b"from-B".to_vec());

    // Commit A first, then B
    txn_a.commit().await.expect("txn_a commit should succeed (no CAS)");
    txn_b.commit().await.expect("txn_b commit should succeed (no CAS)");

    // B committed last, so its value wins
    assert_eq!(
        backend.get(b"key").await.expect("get"),
        Some(Bytes::from("from-B")),
        "last-commit-wins for unconditional writes"
    );
}

/// CAS protects against concurrent modification — exactly one transaction wins.
///
/// Two transactions both read the same value and attempt CAS. Only the first
/// to commit succeeds; the second receives `StorageError::Conflict`.
/// This verifies optimistic concurrency control.
#[tokio::test]
async fn test_concurrent_cas_exactly_one_winner_with_state_check() {
    let backend = MemoryBackend::new();
    backend.set(b"counter".to_vec(), b"0".to_vec()).await.expect("setup");

    let mut txn_a = backend.transaction().await.expect("txn_a");
    let mut txn_b = backend.transaction().await.expect("txn_b");

    // Both read the same current value
    let val_a = txn_a.get(b"counter").await.expect("read A");
    let val_b = txn_b.get(b"counter").await.expect("read B");
    assert_eq!(val_a, val_b, "both should read the same initial value");

    // Both prepare CAS: 0 -> 1
    txn_a
        .compare_and_set(b"counter".to_vec(), Some(b"0".to_vec()), b"1".to_vec())
        .expect("CAS A buffer");
    txn_b
        .compare_and_set(b"counter".to_vec(), Some(b"0".to_vec()), b"1".to_vec())
        .expect("CAS B buffer");

    // A commits first — succeeds
    txn_a.commit().await.expect("txn_a commit");
    assert_eq!(
        backend.get(b"counter").await.expect("get"),
        Some(Bytes::from("1")),
        "A's CAS should have updated the value"
    );

    // B commits second — fails because the value is now "1", not "0"
    let result = txn_b.commit().await;
    assert!(
        matches!(result, Err(StorageError::Conflict { .. })),
        "B's CAS should conflict: {result:?}"
    );

    // Value remains "1" (A's write), B had no effect
    assert_eq!(
        backend.get(b"counter").await.expect("get"),
        Some(Bytes::from("1")),
        "value should remain from A's commit, B was rejected"
    );
}

/// Transaction commit is atomic: CAS failure prevents ALL operations.
///
/// A transaction containing both unconditional writes and a failing CAS
/// must not apply any of the unconditional writes. The backend state
/// must be completely unchanged after a failed commit.
#[tokio::test]
async fn test_commit_atomicity_no_partial_writes_on_cas_failure() {
    let backend = MemoryBackend::new();
    backend.set(b"guarded".to_vec(), b"original".to_vec()).await.expect("setup");
    backend.set(b"unguarded-1".to_vec(), b"old-1".to_vec()).await.expect("setup");
    backend.set(b"unguarded-2".to_vec(), b"old-2".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // Unconditional writes that should NOT be applied if CAS fails
    txn.set(b"unguarded-1".to_vec(), b"new-1".to_vec());
    txn.set(b"unguarded-2".to_vec(), b"new-2".to_vec());
    txn.set(b"brand-new".to_vec(), b"should-not-exist".to_vec());
    txn.delete(b"unguarded-2".to_vec());

    // CAS with wrong expected value — will cause commit to fail
    txn.compare_and_set(b"guarded".to_vec(), Some(b"WRONG".to_vec()), b"should-not-apply".to_vec())
        .expect("CAS buffer");

    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::Conflict { .. })),
        "commit should fail due to CAS mismatch: {result:?}"
    );

    // Verify NOTHING changed — atomicity guarantee
    assert_eq!(
        backend.get(b"guarded").await.expect("get"),
        Some(Bytes::from("original")),
        "guarded key unchanged"
    );
    assert_eq!(
        backend.get(b"unguarded-1").await.expect("get"),
        Some(Bytes::from("old-1")),
        "unguarded-1 unchanged despite unconditional set"
    );
    assert_eq!(
        backend.get(b"unguarded-2").await.expect("get"),
        Some(Bytes::from("old-2")),
        "unguarded-2 unchanged despite unconditional delete"
    );
    assert_eq!(
        backend.get(b"brand-new").await.expect("get"),
        None,
        "brand-new key should not exist after failed commit"
    );
}

/// Concurrent async tasks confirm that exactly one CAS winner emerges.
///
/// Spawns multiple concurrent tasks each attempting a CAS on the same key.
/// Validates: exactly one succeeds, the others get `Conflict`, and the
/// final value is consistent.
#[tokio::test]
async fn test_concurrent_async_cas_tasks_exactly_one_winner() {
    let backend = MemoryBackend::new();
    backend.set(b"race".to_vec(), b"start".to_vec()).await.expect("setup");

    let mut join_set = JoinSet::new();
    let num_tasks = 10;

    for i in 0..num_tasks {
        let backend = backend.clone();
        join_set.spawn(async move {
            let mut txn = backend.transaction().await.expect("txn");
            txn.compare_and_set(
                b"race".to_vec(),
                Some(b"start".to_vec()),
                format!("task-{i}").into_bytes(),
            )
            .expect("CAS buffer");
            txn.commit().await
        });
    }

    let mut successes = 0;
    let mut conflicts = 0;

    while let Some(result) = join_set.join_next().await {
        match result.expect("task panicked") {
            Ok(()) => successes += 1,
            Err(StorageError::Conflict { .. }) => conflicts += 1,
            Err(e) => panic!("unexpected error: {e}"),
        }
    }

    assert_eq!(successes, 1, "exactly one task should succeed");
    assert_eq!(conflicts, num_tasks - 1, "all other tasks should get Conflict");

    // The final value should be from the winning task
    let final_value = backend.get(b"race").await.expect("get");
    assert!(final_value.is_some(), "key should have a value");
    let value_str = String::from_utf8(final_value.expect("some").to_vec()).expect("utf8");
    assert!(value_str.starts_with("task-"), "value should be from one of the tasks: {value_str}");
}
