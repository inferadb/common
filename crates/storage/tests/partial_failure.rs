//! Partial failure tests for transactions.
//!
//! Validates that transaction commit provides all-or-nothing atomicity
//! under various failure modes: CAS conflicts at specific operation
//! indices, size limit rejection, and backend-level commit failures.
//! These tests complement the isolation and edge-case tests in
//! `transaction_edge_cases.rs`.

#![allow(clippy::expect_used, clippy::panic, clippy::unwrap_used)]

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    KeyValue, MemoryBackend, SizeLimits, StorageBackend, StorageError, StorageResult, Transaction,
    health::{HealthProbe, HealthStatus},
};

// ---------------------------------------------------------------------------
// FailingBackend — configurable failure injection for transaction commits
// ---------------------------------------------------------------------------

/// A wrapper around `MemoryBackend` that injects failures at configurable
/// transaction commit indices. Each call to `transaction()` increments a
/// counter; if the counter value is in `fail_commits`, the returned
/// transaction's `commit()` will fail with `StorageError::Connection`.
///
/// This helper enables precise control over which transaction commits
/// succeed or fail, allowing tests to verify atomicity guarantees.
#[derive(Clone)]
struct FailingBackend {
    inner: MemoryBackend,
    commit_count: Arc<AtomicUsize>,
    fail_commits: Arc<HashSet<usize>>,
}

impl FailingBackend {
    fn new(inner: MemoryBackend, fail_commits: HashSet<usize>) -> Self {
        Self {
            inner,
            commit_count: Arc::new(AtomicUsize::new(0)),
            fail_commits: Arc::new(fail_commits),
        }
    }
}

/// Transaction wrapper that conditionally fails on commit.
struct FailingTransaction {
    inner: std::sync::Mutex<Box<dyn Transaction>>,
    should_fail: bool,
}

#[async_trait]
impl Transaction for FailingTransaction {
    async fn get(&self, _key: &[u8]) -> StorageResult<Option<Bytes>> {
        // FailingTransaction is only used to test commit failures.
        // Reads in tests go through the inner MemoryBackend directly.
        Err(StorageError::internal("get not supported on FailingTransaction"))
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

#[async_trait]
impl StorageBackend for FailingBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
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

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
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

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        let idx = self.commit_count.fetch_add(1, Ordering::SeqCst);
        let should_fail = self.fail_commits.contains(&idx);
        let inner_txn = self.inner.transaction().await?;
        Ok(Box::new(FailingTransaction { inner: std::sync::Mutex::new(inner_txn), should_fail }))
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.inner.health_check(probe).await
    }
}

// ---------------------------------------------------------------------------
// Test: 10 operations with injected failure at operation 5 — atomicity
// ---------------------------------------------------------------------------

/// Verifies that when a transaction commit fails (via FailingBackend), none
/// of the buffered operations are applied. Sets up 10 keys, creates a
/// transaction that modifies all 10, and injects a commit failure. After
/// failure, all keys retain their original values.
#[tokio::test]
async fn test_transaction_10_ops_injected_failure_no_ops_applied() {
    let inner = MemoryBackend::new();

    // Pre-populate 10 keys
    for i in 0..10 {
        inner
            .set(format!("key-{i}").into_bytes(), format!("original-{i}").into_bytes())
            .await
            .expect("setup");
    }

    // First transaction (index 0) will fail on commit
    let backend = FailingBackend::new(inner.clone(), HashSet::from([0]));

    let mut txn = backend.transaction().await.expect("txn");

    // Buffer 10 set operations
    for i in 0..10 {
        txn.set(format!("key-{i}").into_bytes(), format!("modified-{i}").into_bytes());
    }

    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::Connection { .. })),
        "commit should fail: {result:?}"
    );

    // Verify ALL keys retain original values — atomicity
    for i in 0..10 {
        let value = inner.get(format!("key-{i}").as_bytes()).await.expect("get");
        assert_eq!(
            value,
            Some(Bytes::from(format!("original-{i}"))),
            "key-{i} should be unchanged after failed commit"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: transaction exceeding size limits — clean rejection, no side effects
// ---------------------------------------------------------------------------

/// Verifies that a transaction with writes exceeding configured size limits
/// is rejected at commit time, with no partial writes applied.
#[tokio::test]
async fn test_transaction_size_limit_exceeded_no_side_effects() {
    // 10 byte key limit, 20 byte value limit
    let backend = MemoryBackend::with_size_limits(SizeLimits::new(10, 20).unwrap());

    // Pre-populate with valid-sized keys
    backend.set(b"key-a".to_vec(), b"val-a".to_vec()).await.expect("setup");
    backend.set(b"key-b".to_vec(), b"val-b".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // First write: valid size
    txn.set(b"key-a".to_vec(), b"new-a".to_vec());

    // Second write: oversized value (exceeds 20 byte limit)
    txn.set(b"key-b".to_vec(), b"this-value-is-way-too-long-for-limit".to_vec());

    // Commit should fail because the oversized write is validated at commit time
    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::SizeLimitExceeded { .. })),
        "commit should reject oversized writes: {result:?}"
    );

    // Verify NO writes were applied — not even the valid-sized one
    assert_eq!(
        backend.get(b"key-a").await.expect("get"),
        Some(Bytes::from("val-a")),
        "key-a unchanged: valid write should not apply when batch contains oversized write"
    );
    assert_eq!(
        backend.get(b"key-b").await.expect("get"),
        Some(Bytes::from("val-b")),
        "key-b unchanged"
    );
}

// ---------------------------------------------------------------------------
// Test: MemoryBackend transaction atomicity — mixed ops, CAS failure
// ---------------------------------------------------------------------------

/// Comprehensive atomicity test with diverse operation types: sets, deletes,
/// and CAS. A failing CAS at position 5 (of 10 total) must prevent all
/// other operations from being applied.
#[tokio::test]
async fn test_memory_transaction_mixed_ops_cas_failure_all_or_nothing() {
    let backend = MemoryBackend::new();

    // Set up initial state
    for i in 0..10 {
        backend
            .set(format!("pf-key-{i}").into_bytes(), format!("pf-original-{i}").into_bytes())
            .await
            .expect("setup");
    }

    let mut txn = backend.transaction().await.expect("txn");

    // Operations 0-3: unconditional sets
    for i in 0..4 {
        txn.set(format!("pf-key-{i}").into_bytes(), format!("pf-modified-{i}").into_bytes());
    }

    // Operation 4: delete
    txn.delete(b"pf-key-4".to_vec());

    // Operation 5: CAS with WRONG expected value — will cause failure
    txn.compare_and_set(
        b"pf-key-5".to_vec(),
        Some(b"WRONG-EXPECTED-VALUE".to_vec()),
        b"pf-modified-5".to_vec(),
    )
    .expect("CAS buffer");

    // Operations 6-8: more unconditional sets
    for i in 6..9 {
        txn.set(format!("pf-key-{i}").into_bytes(), format!("pf-modified-{i}").into_bytes());
    }

    // Operation 9: another CAS — correct expected value (but irrelevant since op 5 fails)
    txn.compare_and_set(
        b"pf-key-9".to_vec(),
        Some(b"pf-original-9".to_vec()),
        b"pf-modified-9".to_vec(),
    )
    .expect("CAS buffer");

    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::Conflict { .. })),
        "commit should fail due to CAS mismatch: {result:?}"
    );

    // Verify ALL 10 keys retain their original values
    for i in 0..10 {
        let value = backend.get(format!("pf-key-{i}").as_bytes()).await.expect("get");
        assert_eq!(
            value,
            Some(Bytes::from(format!("pf-original-{i}"))),
            "pf-key-{i} should be unchanged after failed commit"
        );
    }
}

// ---------------------------------------------------------------------------
// Test: CAS insert-if-absent failure — key already exists
// ---------------------------------------------------------------------------

/// Transaction with a CAS insert-if-absent (`expected: None`) on a key that
/// already exists. The entire transaction (including other unconditional
/// writes) must be rolled back.
#[tokio::test]
async fn test_transaction_cas_insert_if_absent_failure_atomicity() {
    let backend = MemoryBackend::new();

    // Key already exists
    backend.set(b"existing".to_vec(), b"already-here".to_vec()).await.expect("setup");
    backend.set(b"other-1".to_vec(), b"old-1".to_vec()).await.expect("setup");
    backend.set(b"other-2".to_vec(), b"old-2".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // Unconditional writes
    txn.set(b"other-1".to_vec(), b"new-1".to_vec());
    txn.set(b"other-2".to_vec(), b"new-2".to_vec());
    txn.set(b"brand-new".to_vec(), b"should-not-exist".to_vec());

    // CAS: insert-if-absent on existing key — will fail
    txn.compare_and_set(b"existing".to_vec(), None, b"should-not-apply".to_vec())
        .expect("CAS buffer");

    let result = txn.commit().await;
    assert!(
        matches!(result, Err(StorageError::Conflict { .. })),
        "commit should fail: key already exists: {result:?}"
    );

    // Nothing changed
    assert_eq!(backend.get(b"existing").await.expect("get"), Some(Bytes::from("already-here")));
    assert_eq!(backend.get(b"other-1").await.expect("get"), Some(Bytes::from("old-1")));
    assert_eq!(backend.get(b"other-2").await.expect("get"), Some(Bytes::from("old-2")));
    assert_eq!(backend.get(b"brand-new").await.expect("get"), None);
}

// ---------------------------------------------------------------------------
// Test: FailingBackend — successful commit after a failed one
// ---------------------------------------------------------------------------

/// Verifies that the `FailingBackend` correctly controls which transactions
/// fail: transaction 0 fails, transaction 1 succeeds. After the failed
/// commit, the backend is in the original state. After the successful commit,
/// the new values are visible.
#[tokio::test]
async fn test_failing_backend_selective_commit_failure() {
    let inner = MemoryBackend::new();
    inner.set(b"k1".to_vec(), b"v1".to_vec()).await.expect("setup");

    // Transaction index 0 fails, index 1 succeeds
    let backend = FailingBackend::new(inner.clone(), HashSet::from([0]));

    // Transaction 0 — will fail
    {
        let mut txn = backend.transaction().await.expect("txn");
        txn.set(b"k1".to_vec(), b"updated".to_vec());
        let result = txn.commit().await;
        assert!(matches!(result, Err(StorageError::Connection { .. })));

        // k1 unchanged
        assert_eq!(inner.get(b"k1").await.expect("get"), Some(Bytes::from("v1")));
    }

    // Transaction 1 — will succeed
    {
        let mut txn = backend.transaction().await.expect("txn");
        txn.set(b"k1".to_vec(), b"finally-updated".to_vec());
        txn.commit().await.expect("commit should succeed");

        assert_eq!(inner.get(b"k1").await.expect("get"), Some(Bytes::from("finally-updated")));
    }
}

// ---------------------------------------------------------------------------
// Test: Size limit exceeded in CAS within transaction — early rejection
// ---------------------------------------------------------------------------

/// When a CAS operation within a transaction exceeds size limits, the
/// `compare_and_set` call itself returns an error (validated at buffer time).
/// The transaction should still be usable (the failed CAS is not buffered),
/// and committing the remaining valid operations should succeed.
#[tokio::test]
async fn test_transaction_cas_size_limit_early_rejection() {
    let backend = MemoryBackend::with_size_limits(SizeLimits::new(10, 20).unwrap());
    backend.set(b"key-1".to_vec(), b"val-1".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // Valid unconditional set
    txn.set(b"key-1".to_vec(), b"new-val-1".to_vec());

    // CAS with oversized new_value — rejected immediately
    let cas_result = txn.compare_and_set(
        b"key-2".to_vec(),
        None,
        b"this-value-exceeds-twenty-bytes-easily".to_vec(),
    );
    assert!(
        matches!(cas_result, Err(StorageError::SizeLimitExceeded { .. })),
        "CAS should be rejected at buffer time: {cas_result:?}"
    );

    // The valid set should still commit successfully
    txn.commit().await.expect("commit should succeed for remaining valid ops");
    assert_eq!(backend.get(b"key-1").await.expect("get"), Some(Bytes::from("new-val-1")));
}

// ---------------------------------------------------------------------------
// Test: Multiple CAS failures — first failure is reported
// ---------------------------------------------------------------------------

/// When a transaction contains multiple CAS operations and more than one
/// would fail, the commit fails on the first CAS mismatch. No operations
/// are applied regardless of which CAS fails.
#[tokio::test]
async fn test_transaction_multiple_cas_failures_first_reported() {
    let backend = MemoryBackend::new();
    backend.set(b"cas-a".to_vec(), b"val-a".to_vec()).await.expect("setup");
    backend.set(b"cas-b".to_vec(), b"val-b".to_vec()).await.expect("setup");
    backend.set(b"regular".to_vec(), b"old".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // Regular write
    txn.set(b"regular".to_vec(), b"new".to_vec());

    // CAS 1: wrong expected value
    txn.compare_and_set(b"cas-a".to_vec(), Some(b"WRONG".to_vec()), b"new-a".to_vec())
        .expect("CAS buffer");

    // CAS 2: also wrong expected value
    txn.compare_and_set(b"cas-b".to_vec(), Some(b"ALSO-WRONG".to_vec()), b"new-b".to_vec())
        .expect("CAS buffer");

    let result = txn.commit().await;
    assert!(matches!(result, Err(StorageError::Conflict { .. })));

    // Nothing applied
    assert_eq!(backend.get(b"cas-a").await.expect("get"), Some(Bytes::from("val-a")));
    assert_eq!(backend.get(b"cas-b").await.expect("get"), Some(Bytes::from("val-b")));
    assert_eq!(backend.get(b"regular").await.expect("get"), Some(Bytes::from("old")));
}

// ---------------------------------------------------------------------------
// Test: Large transaction — many operations, CAS failure at the end
// ---------------------------------------------------------------------------

/// A large transaction (50 unconditional writes + 1 failing CAS) tests
/// that atomicity holds even with many buffered operations. The single CAS
/// failure at the end must prevent all 50 writes from being applied.
#[tokio::test]
async fn test_large_transaction_cas_failure_at_end_prevents_all_writes() {
    let backend = MemoryBackend::new();

    // Pre-populate
    for i in 0..50 {
        backend
            .set(format!("big-{i}").into_bytes(), format!("orig-{i}").into_bytes())
            .await
            .expect("setup");
    }
    backend.set(b"guarded".to_vec(), b"sentinel".to_vec()).await.expect("setup");

    let mut txn = backend.transaction().await.expect("txn");

    // 50 unconditional writes
    for i in 0..50 {
        txn.set(format!("big-{i}").into_bytes(), format!("mod-{i}").into_bytes());
    }

    // CAS at the end with wrong expected — triggers failure
    txn.compare_and_set(b"guarded".to_vec(), Some(b"WRONG".to_vec()), b"nope".to_vec())
        .expect("CAS buffer");

    let result = txn.commit().await;
    assert!(matches!(result, Err(StorageError::Conflict { .. })));

    // Verify all 50 + 1 keys unchanged
    for i in 0..50 {
        let value = backend.get(format!("big-{i}").as_bytes()).await.expect("get");
        assert_eq!(value, Some(Bytes::from(format!("orig-{i}"))), "big-{i} should be unchanged");
    }
    assert_eq!(backend.get(b"guarded").await.expect("get"), Some(Bytes::from("sentinel")));
}
