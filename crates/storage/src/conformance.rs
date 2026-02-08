//! Conformance test suite for [`StorageBackend`] implementations.
//!
//! This module provides a comprehensive set of async test functions that
//! validate whether a [`StorageBackend`] implementation correctly satisfies
//! the trait contract. Every backend — whether in-memory, ledger-backed,
//! or third-party — can run the same suite to ensure interoperability.
//!
//! # Usage
//!
//! Enable the `testutil` feature and call each conformance function with
//! a fresh backend instance:
//!
//! ```no_run
//! use inferadb_common_storage::conformance;
//! use inferadb_common_storage::MemoryBackend;
//!
//! #[tokio::test]
//! async fn crud_get_returns_none_for_missing_key() {
//!     conformance::crud_get_returns_none_for_missing_key(&MemoryBackend::new()).await;
//! }
//! ```
//!
//! # Test Categories
//!
//! | Category | Functions | Contract aspect |
//! |----------|-----------|-----------------|
//! | CRUD | 8 tests | Basic get/set/delete semantics |
//! | Range | 5 tests | `get_range` / `clear_range` ordering and boundaries |
//! | TTL | 4 tests | `set_with_ttl` expiration behavior |
//! | Transaction | 6 tests | Atomic commit, read-your-writes, isolation |
//! | CAS | 4 tests | `compare_and_set` precondition checks |
//! | Concurrent | 3 tests | Thread-safety under parallel access |
//! | Error semantics | 4 tests | Error variant classification |

use std::{sync::Arc, time::Duration};

use bytes::Bytes;

use crate::{assert_storage_error, backend::StorageBackend, error::StorageError};

// ============================================================================
// CRUD — Basic get/set/delete semantics (8 tests)
// ============================================================================

/// `get` on a nonexistent key returns `Ok(None)`.
pub async fn crud_get_returns_none_for_missing_key<B: StorageBackend>(backend: &B) {
    let result = backend.get(b"nonexistent").await;
    assert!(result.is_ok(), "get should not error on missing key: {result:?}");
    assert_eq!(result.expect("checked above"), None, "missing key should return None");
}

/// `set` then `get` round-trips the value.
pub async fn crud_set_then_get_returns_value<B: StorageBackend>(backend: &B) {
    backend.set(b"k1".to_vec(), b"v1".to_vec()).await.expect("set should succeed");
    let val = backend.get(b"k1").await.expect("get should succeed");
    assert_eq!(val, Some(Bytes::from("v1")));
}

/// `set` on an existing key overwrites the value.
pub async fn crud_set_overwrites_existing<B: StorageBackend>(backend: &B) {
    backend.set(b"k1".to_vec(), b"original".to_vec()).await.expect("set");
    backend.set(b"k1".to_vec(), b"updated".to_vec()).await.expect("overwrite");
    let val = backend.get(b"k1").await.expect("get");
    assert_eq!(val, Some(Bytes::from("updated")));
}

/// `delete` on a nonexistent key is a silent no-op.
pub async fn crud_delete_nonexistent_is_noop<B: StorageBackend>(backend: &B) {
    let result = backend.delete(b"ghost").await;
    assert!(result.is_ok(), "delete of nonexistent key should not error: {result:?}");
}

/// `delete` removes a previously-set key.
pub async fn crud_delete_removes_key<B: StorageBackend>(backend: &B) {
    backend.set(b"k2".to_vec(), b"val".to_vec()).await.expect("set");
    backend.delete(b"k2").await.expect("delete");
    let val = backend.get(b"k2").await.expect("get after delete");
    assert_eq!(val, None, "key should be gone after delete");
}

/// Keys are byte-level distinct — `"key"` and `"key\x00"` are different.
pub async fn crud_keys_are_byte_distinct<B: StorageBackend>(backend: &B) {
    backend.set(b"key".to_vec(), b"a".to_vec()).await.expect("set key");
    backend.set(b"key\x00".to_vec(), b"b".to_vec()).await.expect("set key+null");
    let a = backend.get(b"key").await.expect("get key");
    let b = backend.get(b"key\x00").await.expect("get key+null");
    assert_eq!(a, Some(Bytes::from("a")));
    assert_eq!(b, Some(Bytes::from("b")));
}

/// Empty key and empty value are valid.
pub async fn crud_empty_key_and_value<B: StorageBackend>(backend: &B) {
    backend.set(Vec::new(), Vec::new()).await.expect("set empty key+value");
    let val = backend.get(b"").await.expect("get empty key");
    assert_eq!(val, Some(Bytes::new()), "empty key should have empty value");
}

/// Large values (1 MiB) round-trip correctly.
pub async fn crud_large_value_roundtrip<B: StorageBackend>(backend: &B) {
    let big = vec![0xCDu8; 1_048_576];
    backend.set(b"big".to_vec(), big.clone()).await.expect("set large value");
    let val = backend.get(b"big").await.expect("get large value");
    assert_eq!(val.as_ref().map(|b| b.len()), Some(big.len()), "large value length mismatch");
    assert_eq!(val, Some(Bytes::from(big)));
}

// ============================================================================
// Range — get_range / clear_range ordering and boundaries (5 tests)
// ============================================================================

/// `get_range` returns results in key order.
pub async fn range_results_are_ordered<B: StorageBackend>(backend: &B) {
    for key in [b"r:c", b"r:a", b"r:b"] {
        backend.set(key.to_vec(), b"v".to_vec()).await.expect("set");
    }
    let results = backend.get_range(b"r:".to_vec()..b"r:~".to_vec()).await.expect("get_range");
    let keys: Vec<&[u8]> = results.iter().map(|kv| kv.key.as_ref()).collect();
    assert_eq!(keys, vec![b"r:a".as_slice(), b"r:b", b"r:c"], "range results must be sorted");
}

/// `get_range` with exclusive end excludes the boundary key.
pub async fn range_exclusive_end<B: StorageBackend>(backend: &B) {
    for (k, v) in [(b"e:a", b"1"), (b"e:b", b"2"), (b"e:c", b"3")] {
        backend.set(k.to_vec(), v.to_vec()).await.expect("set");
    }
    let results =
        backend.get_range(b"e:a".to_vec()..b"e:c".to_vec()).await.expect("get_range exclusive");
    let keys: Vec<&[u8]> = results.iter().map(|kv| kv.key.as_ref()).collect();
    assert_eq!(keys, vec![b"e:a".as_slice(), b"e:b"], "exclusive end must not include boundary");
}

/// `get_range` with inclusive end includes the boundary key.
pub async fn range_inclusive_end<B: StorageBackend>(backend: &B) {
    for (k, v) in [(b"i:a", b"1"), (b"i:b", b"2"), (b"i:c", b"3")] {
        backend.set(k.to_vec(), v.to_vec()).await.expect("set");
    }
    let results =
        backend.get_range(b"i:a".to_vec()..=b"i:b".to_vec()).await.expect("get_range inclusive");
    let keys: Vec<&[u8]> = results.iter().map(|kv| kv.key.as_ref()).collect();
    assert_eq!(keys, vec![b"i:a".as_slice(), b"i:b"], "inclusive end must include boundary");
}

/// `get_range` on an empty range returns an empty vec.
pub async fn range_empty_range_returns_empty<B: StorageBackend>(backend: &B) {
    backend.set(b"x:a".to_vec(), b"v".to_vec()).await.expect("set");
    // Exclusive range where start == end → empty
    let results =
        backend.get_range(b"x:a".to_vec()..b"x:a".to_vec()).await.expect("get_range empty");
    assert!(results.is_empty(), "start==end exclusive range should be empty");
}

/// `clear_range` removes all keys in the specified range.
pub async fn range_clear_range_removes_keys<B: StorageBackend>(backend: &B) {
    for i in 0u8..5 {
        let key = format!("cr:{i:02}");
        backend.set(key.into_bytes(), b"v".to_vec()).await.expect("set");
    }
    backend.clear_range(b"cr:01".to_vec()..b"cr:04".to_vec()).await.expect("clear_range");

    // Keys 00 and 04 should survive; 01, 02, 03 should be gone.
    let remaining =
        backend.get_range(b"cr:".to_vec()..b"cr:~".to_vec()).await.expect("get_range after clear");
    let keys: Vec<&[u8]> = remaining.iter().map(|kv| kv.key.as_ref()).collect();
    assert_eq!(
        keys,
        vec![b"cr:00".as_slice(), b"cr:04"],
        "clear_range should remove interior keys"
    );
}

// ============================================================================
// TTL — set_with_ttl expiration behavior (4 tests)
// ============================================================================

/// A key set with a very short TTL eventually expires.
pub async fn ttl_key_expires<B: StorageBackend>(backend: &B) {
    backend
        .set_with_ttl(b"ttl:a".to_vec(), b"ephemeral".to_vec(), Duration::from_millis(50))
        .await
        .expect("set_with_ttl");

    // Key should exist immediately.
    let before = backend.get(b"ttl:a").await.expect("get before expiry");
    assert!(before.is_some(), "key should exist before TTL expires");

    // Wait past expiry.
    tokio::time::sleep(Duration::from_millis(150)).await;

    let after = backend.get(b"ttl:a").await.expect("get after expiry");
    assert_eq!(after, None, "key should be expired after TTL");
}

/// A zero-duration TTL means the key is immediately expired.
pub async fn ttl_zero_is_immediately_expired<B: StorageBackend>(backend: &B) {
    backend
        .set_with_ttl(b"ttl:zero".to_vec(), b"gone".to_vec(), Duration::ZERO)
        .await
        .expect("set_with_ttl zero");
    let val = backend.get(b"ttl:zero").await.expect("get");
    assert_eq!(val, None, "zero-TTL key should be immediately expired");
}

/// Overwriting a TTL key with a plain `set` clears the TTL (key persists).
pub async fn ttl_overwrite_clears_ttl<B: StorageBackend>(backend: &B) {
    backend
        .set_with_ttl(b"ttl:ow".to_vec(), b"temp".to_vec(), Duration::from_millis(50))
        .await
        .expect("set_with_ttl");
    // Overwrite with permanent set.
    backend.set(b"ttl:ow".to_vec(), b"permanent".to_vec()).await.expect("set overwrite");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let val = backend.get(b"ttl:ow").await.expect("get after original TTL");
    assert_eq!(
        val,
        Some(Bytes::from("permanent")),
        "plain set should clear TTL, making key permanent"
    );
}

/// Expired keys do not appear in range query results.
pub async fn ttl_expired_keys_excluded_from_range<B: StorageBackend>(backend: &B) {
    backend.set(b"tr:a".to_vec(), b"permanent".to_vec()).await.expect("set");
    backend
        .set_with_ttl(b"tr:b".to_vec(), b"temp".to_vec(), Duration::from_millis(50))
        .await
        .expect("set_with_ttl");
    backend.set(b"tr:c".to_vec(), b"permanent".to_vec()).await.expect("set");

    tokio::time::sleep(Duration::from_millis(150)).await;

    let results = backend.get_range(b"tr:".to_vec()..b"tr:~".to_vec()).await.expect("get_range");
    let keys: Vec<&[u8]> = results.iter().map(|kv| kv.key.as_ref()).collect();
    assert_eq!(keys, vec![b"tr:a".as_slice(), b"tr:c"], "expired key must not appear in range");
}

// ============================================================================
// Transaction — atomic commit, read-your-writes, isolation (6 tests)
// ============================================================================

/// Transaction can read its own uncommitted writes.
pub async fn tx_read_your_writes<B: StorageBackend>(backend: &B) {
    let mut tx = backend.transaction().await.expect("transaction");
    tx.set(b"tx:ryw".to_vec(), b"buffered".to_vec());
    let val = tx.get(b"tx:ryw").await.expect("get in tx");
    assert_eq!(val, Some(Bytes::from("buffered")), "transaction should see own writes");
}

/// Transaction reads for unmodified keys go to the backend.
pub async fn tx_reads_committed_data<B: StorageBackend>(backend: &B) {
    backend.set(b"tx:cd".to_vec(), b"committed".to_vec()).await.expect("set");
    let tx = backend.transaction().await.expect("transaction");
    let val = tx.get(b"tx:cd").await.expect("get in tx");
    assert_eq!(val, Some(Bytes::from("committed")), "tx should read committed data");
}

/// Transaction commit applies all operations atomically.
pub async fn tx_commit_applies_all<B: StorageBackend>(backend: &B) {
    backend.set(b"tx:del".to_vec(), b"old".to_vec()).await.expect("set");

    let mut tx = backend.transaction().await.expect("transaction");
    tx.set(b"tx:new1".to_vec(), b"val1".to_vec());
    tx.set(b"tx:new2".to_vec(), b"val2".to_vec());
    tx.delete(b"tx:del".to_vec());
    tx.commit().await.expect("commit");

    assert_eq!(backend.get(b"tx:new1").await.expect("get"), Some(Bytes::from("val1")));
    assert_eq!(backend.get(b"tx:new2").await.expect("get"), Some(Bytes::from("val2")));
    assert_eq!(backend.get(b"tx:del").await.expect("get"), None);
}

/// Dropping a transaction without commit leaves no trace.
pub async fn tx_drop_without_commit_is_noop<B: StorageBackend>(backend: &B) {
    let mut tx = backend.transaction().await.expect("transaction");
    tx.set(b"tx:phantom".to_vec(), b"should-not-exist".to_vec());
    drop(tx);

    let val = backend.get(b"tx:phantom").await.expect("get");
    assert_eq!(val, None, "uncommitted transaction writes must not be visible");
}

/// Transaction delete within a transaction makes the key invisible to subsequent reads.
pub async fn tx_delete_then_get_returns_none<B: StorageBackend>(backend: &B) {
    backend.set(b"tx:dg".to_vec(), b"exists".to_vec()).await.expect("set");
    let mut tx = backend.transaction().await.expect("transaction");
    tx.delete(b"tx:dg".to_vec());
    let val = tx.get(b"tx:dg").await.expect("get after tx delete");
    assert_eq!(val, None, "deleted key should return None within the same transaction");
}

/// Transaction CAS at commit time detects conflicts.
pub async fn tx_cas_conflict_rejects_commit<B: StorageBackend>(backend: &B) {
    backend.set(b"tx:cas".to_vec(), b"v1".to_vec()).await.expect("set");

    let mut tx = backend.transaction().await.expect("transaction");
    tx.compare_and_set(b"tx:cas".to_vec(), Some(b"v1".to_vec()), b"v2".to_vec())
        .expect("buffer CAS");

    // Concurrent write changes the value before commit.
    backend.set(b"tx:cas".to_vec(), b"v_concurrent".to_vec()).await.expect("concurrent set");

    let result = tx.commit().await;
    assert_storage_error!(result, Conflict, "CAS conflict should reject commit");

    // Backend should retain the concurrent writer's value.
    let val = backend.get(b"tx:cas").await.expect("get");
    assert_eq!(val, Some(Bytes::from("v_concurrent")));
}

// ============================================================================
// CAS — compare_and_set precondition checks (4 tests)
// ============================================================================

/// `compare_and_set` with `expected: None` succeeds on absent key (insert-if-absent).
pub async fn cas_insert_if_absent<B: StorageBackend>(backend: &B) {
    let result = backend.compare_and_set(b"cas:new", None, b"created".to_vec()).await;
    assert!(result.is_ok(), "CAS insert-if-absent should succeed: {result:?}");
    assert_eq!(backend.get(b"cas:new").await.expect("get"), Some(Bytes::from("created")));
}

/// `compare_and_set` with `expected: None` fails if the key exists.
pub async fn cas_insert_if_absent_fails_when_key_exists<B: StorageBackend>(backend: &B) {
    backend.set(b"cas:exists".to_vec(), b"val".to_vec()).await.expect("set");
    let result = backend.compare_and_set(b"cas:exists", None, b"nope".to_vec()).await;
    assert_storage_error!(result, Conflict, "CAS insert on existing key should conflict");
}

/// `compare_and_set` with matching expected value succeeds.
pub async fn cas_update_with_matching_value<B: StorageBackend>(backend: &B) {
    backend.set(b"cas:upd".to_vec(), b"v1".to_vec()).await.expect("set");
    backend
        .compare_and_set(b"cas:upd", Some(b"v1"), b"v2".to_vec())
        .await
        .expect("CAS with matching value should succeed");
    assert_eq!(backend.get(b"cas:upd").await.expect("get"), Some(Bytes::from("v2")));
}

/// `compare_and_set` with mismatched expected value returns `Conflict`.
pub async fn cas_update_with_mismatched_value<B: StorageBackend>(backend: &B) {
    backend.set(b"cas:mm".to_vec(), b"actual".to_vec()).await.expect("set");
    let result = backend.compare_and_set(b"cas:mm", Some(b"wrong"), b"nope".to_vec()).await;
    assert_storage_error!(result, Conflict, "CAS mismatch should return Conflict");
    // Value should be unchanged.
    assert_eq!(backend.get(b"cas:mm").await.expect("get"), Some(Bytes::from("actual")));
}

// ============================================================================
// Concurrent access — thread-safety under parallel access (3 tests)
// ============================================================================

/// Concurrent sets to different keys all succeed.
///
/// Requires `B: 'static` so the backend can be shared across spawned tasks
/// via `Arc`.
pub async fn concurrent_sets_to_different_keys<B: StorageBackend + 'static>(backend: Arc<B>) {
    let mut handles = Vec::new();
    for i in 0u32..50 {
        let backend = Arc::clone(&backend);
        let key = format!("conc:{i:04}").into_bytes();
        let value = format!("val:{i}").into_bytes();
        handles.push(tokio::spawn(async move {
            backend.set(key, value).await.expect("concurrent set");
        }));
    }
    for handle in handles {
        handle.await.expect("task join");
    }

    // Verify all keys exist.
    for i in 0u32..50 {
        let key = format!("conc:{i:04}");
        let val = backend.get(key.as_bytes()).await.expect("get");
        assert!(val.is_some(), "key {key} should exist after concurrent sets");
    }
}

/// Concurrent reads of the same key all return the same value.
pub async fn concurrent_reads_return_consistent_value<B: StorageBackend + 'static>(
    backend: Arc<B>,
) {
    backend.set(b"cread:k".to_vec(), b"stable".to_vec()).await.expect("set");

    let mut handles = Vec::new();
    for _ in 0..50 {
        let backend = Arc::clone(&backend);
        handles.push(tokio::spawn(async move {
            backend.get(b"cread:k").await.expect("concurrent get")
        }));
    }

    for handle in handles {
        let val = handle.await.expect("task join");
        assert_eq!(val, Some(Bytes::from("stable")));
    }
}

/// Concurrent CAS on the same key — exactly one writer wins per round.
pub async fn concurrent_cas_exactly_one_winner<B: StorageBackend + 'static>(backend: Arc<B>) {
    backend.compare_and_set(b"ccas:k", None, b"v0".to_vec()).await.expect("initial CAS");

    let mut handles = Vec::new();
    for i in 0u32..10 {
        let backend = Arc::clone(&backend);
        let new_val = format!("writer-{i}").into_bytes();
        handles.push(tokio::spawn(async move {
            backend.compare_and_set(b"ccas:k", Some(b"v0"), new_val).await
        }));
    }

    let mut successes = 0u32;
    let mut conflicts = 0u32;
    for handle in handles {
        match handle.await.expect("task join") {
            Ok(()) => successes += 1,
            Err(StorageError::Conflict { .. }) => conflicts += 1,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }

    assert_eq!(successes, 1, "exactly one CAS writer should win");
    assert_eq!(conflicts, 9, "remaining writers should get Conflict");
}

// ============================================================================
// Error semantics — error variant classification (4 tests)
// ============================================================================

/// `health_check` succeeds on a healthy backend for all probe types.
pub async fn health_check_returns_healthy<B: StorageBackend>(backend: &B) {
    use crate::health::HealthProbe;

    for probe in [HealthProbe::Liveness, HealthProbe::Readiness, HealthProbe::Startup] {
        let status = backend.health_check(probe).await.expect("health_check");
        assert!(
            status.is_healthy() || status.is_degraded(),
            "fresh backend health_check({probe}) should be healthy or degraded, got: {status:?}"
        );
    }
}

/// `get` on a deleted key returns `None`, not `NotFound` error.
pub async fn get_deleted_key_returns_none_not_error<B: StorageBackend>(backend: &B) {
    backend.set(b"err:del".to_vec(), b"v".to_vec()).await.expect("set");
    backend.delete(b"err:del").await.expect("delete");
    let result = backend.get(b"err:del").await;
    assert!(result.is_ok(), "get after delete should be Ok, not error: {result:?}");
    assert_eq!(result.expect("checked above"), None);
}

/// `clear_range` on a range with no keys is a no-op.
pub async fn clear_range_on_empty_range_is_noop<B: StorageBackend>(backend: &B) {
    let result = backend.clear_range(b"noop:a".to_vec()..b"noop:z".to_vec()).await;
    assert!(result.is_ok(), "clear_range on empty range should succeed: {result:?}");
}

/// Double delete is idempotent — second delete is a no-op.
pub async fn idempotent_delete<B: StorageBackend>(backend: &B) {
    backend.set(b"err:idem".to_vec(), b"v".to_vec()).await.expect("set");
    backend.delete(b"err:idem").await.expect("first delete");
    backend.delete(b"err:idem").await.expect("second delete should be noop");
    let val = backend.get(b"err:idem").await.expect("get");
    assert_eq!(val, None);
}

// ============================================================================
// Convenience runner — run all conformance tests against a single backend
// ============================================================================

/// Run the full conformance suite against the given backend.
///
/// This function exercises every conformance test in sequence. It is a
/// convenience for backend authors who want a one-line invocation:
///
/// ```no_run
/// use std::sync::Arc;
/// use inferadb_common_storage::conformance;
/// use inferadb_common_storage::MemoryBackend;
///
/// #[tokio::test]
/// async fn memory_backend_conformance() {
///     conformance::run_all(Arc::new(MemoryBackend::new())).await;
/// }
/// ```
///
/// For finer-grained control or parallel execution, call individual test
/// functions directly.
pub async fn run_all<B: StorageBackend + 'static>(backend: Arc<B>) {
    // CRUD
    crud_get_returns_none_for_missing_key(backend.as_ref()).await;
    crud_set_then_get_returns_value(backend.as_ref()).await;
    crud_set_overwrites_existing(backend.as_ref()).await;
    crud_delete_nonexistent_is_noop(backend.as_ref()).await;
    crud_delete_removes_key(backend.as_ref()).await;
    crud_keys_are_byte_distinct(backend.as_ref()).await;
    crud_empty_key_and_value(backend.as_ref()).await;
    crud_large_value_roundtrip(backend.as_ref()).await;

    // Range
    range_results_are_ordered(backend.as_ref()).await;
    range_exclusive_end(backend.as_ref()).await;
    range_inclusive_end(backend.as_ref()).await;
    range_empty_range_returns_empty(backend.as_ref()).await;
    range_clear_range_removes_keys(backend.as_ref()).await;

    // TTL
    ttl_key_expires(backend.as_ref()).await;
    ttl_zero_is_immediately_expired(backend.as_ref()).await;
    ttl_overwrite_clears_ttl(backend.as_ref()).await;
    ttl_expired_keys_excluded_from_range(backend.as_ref()).await;

    // Transaction
    tx_read_your_writes(backend.as_ref()).await;
    tx_reads_committed_data(backend.as_ref()).await;
    tx_commit_applies_all(backend.as_ref()).await;
    tx_drop_without_commit_is_noop(backend.as_ref()).await;
    tx_delete_then_get_returns_none(backend.as_ref()).await;
    tx_cas_conflict_rejects_commit(backend.as_ref()).await;

    // CAS
    cas_insert_if_absent(backend.as_ref()).await;
    cas_insert_if_absent_fails_when_key_exists(backend.as_ref()).await;
    cas_update_with_matching_value(backend.as_ref()).await;
    cas_update_with_mismatched_value(backend.as_ref()).await;

    // Concurrent
    concurrent_sets_to_different_keys(Arc::clone(&backend)).await;
    concurrent_reads_return_consistent_value(Arc::clone(&backend)).await;
    concurrent_cas_exactly_one_winner(Arc::clone(&backend)).await;

    // Error semantics
    health_check_returns_healthy(backend.as_ref()).await;
    get_deleted_key_returns_none_not_error(backend.as_ref()).await;
    clear_range_on_empty_range_is_noop(backend.as_ref()).await;
    idempotent_delete(backend.as_ref()).await;
}
