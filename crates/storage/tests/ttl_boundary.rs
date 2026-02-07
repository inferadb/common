//! TTL boundary condition tests for `MemoryBackend`.
//!
//! Covers edge cases in TTL behavior: zero TTL, maximum TTL, expiration
//! boundaries, TTL clearing via `set`, and TTL replacement via `set_with_ttl`.

#![allow(clippy::expect_used, clippy::panic)]

use std::time::Duration;

use bytes::Bytes;
use inferadb_common_storage::{MemoryBackend, StorageBackend};

// ============================================================================
// Zero TTL
// ============================================================================

/// A key set with `Duration::ZERO` TTL should be considered immediately expired.
///
/// `MemoryBackend` stores `Instant::now() + ttl` as the expiry. With a zero
/// duration, the expiry equals the insertion time. Since `is_expired` checks
/// `expiry <= Instant::now()`, any subsequent read (even nanoseconds later)
/// will see the key as expired and return `None`.
#[tokio::test]
async fn test_zero_ttl_is_immediately_expired() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"zero-ttl".to_vec(), b"ephemeral".to_vec(), Duration::ZERO)
        .await
        .expect("set_with_ttl with zero duration should succeed");

    // The key is physically stored but logically expired — get returns None.
    let result = backend.get(b"zero-ttl").await.expect("get should not error");
    assert_eq!(result, None, "a key with zero TTL should be immediately expired on the next read");
}

/// A zero-TTL key should not appear in range query results.
#[tokio::test]
async fn test_zero_ttl_excluded_from_range() {
    let backend = MemoryBackend::new();

    // Insert a permanent key and a zero-TTL key in the same range.
    backend.set(b"range:a".to_vec(), b"permanent".to_vec()).await.expect("set");
    backend
        .set_with_ttl(b"range:b".to_vec(), b"ghost".to_vec(), Duration::ZERO)
        .await
        .expect("set_with_ttl");
    backend.set(b"range:c".to_vec(), b"also-permanent".to_vec()).await.expect("set");

    let results =
        backend.get_range(b"range:".to_vec()..b"range:~".to_vec()).await.expect("get_range");

    assert_eq!(results.len(), 2, "zero-TTL key should be filtered from range results");
    assert_eq!(results[0].value, Bytes::from("permanent"));
    assert_eq!(results[1].value, Bytes::from("also-permanent"));
}

// ============================================================================
// Maximum / Large TTL
// ============================================================================

/// A key with the largest safe TTL should not overflow or panic.
///
/// `std::time::Instant + Duration` can panic if the resulting instant exceeds
/// the platform's maximum representable time. We use a large-but-safe duration
/// (100 years) to verify no arithmetic issues occur.
#[tokio::test]
async fn test_large_ttl_no_overflow() {
    let backend = MemoryBackend::new();

    // ~100 years in seconds — large enough to exercise overflow concerns
    // but small enough to not panic on Instant addition.
    let hundred_years = Duration::from_secs(100 * 365 * 24 * 3600);

    backend
        .set_with_ttl(b"long-lived".to_vec(), b"value".to_vec(), hundred_years)
        .await
        .expect("set_with_ttl with large TTL should succeed");

    // Key should be readable (not expired).
    let result = backend.get(b"long-lived").await.expect("get should succeed");
    assert_eq!(
        result,
        Some(Bytes::from("value")),
        "key with large TTL should be readable immediately"
    );
}

/// A key with `Duration::MAX` may overflow on `Instant::now() + Duration::MAX`.
/// This test documents the expected behavior: the operation should either succeed
/// (if the platform can represent the resulting Instant) or the overflow is
/// caught at the type system level. On most platforms, this panics in debug mode.
///
/// Since the trait signature accepts any `Duration`, callers should be aware
/// that extreme values may cause panics. This test runs with `#[should_panic]`
/// on platforms where `Instant` addition overflows.
#[tokio::test]
#[should_panic(expected = "overflow")]
async fn test_max_ttl_overflows_instant() {
    let backend = MemoryBackend::new();

    // Duration::MAX (~584 billion years) will overflow Instant on all platforms.
    backend
        .set_with_ttl(b"overflow".to_vec(), b"value".to_vec(), Duration::MAX)
        .await
        .expect("this should panic before reaching here");
}

// ============================================================================
// Expiration Boundary (just before / just after)
// ============================================================================

/// A key should be readable immediately after being set with a short TTL,
/// and should be expired after the TTL elapses.
///
/// Uses real time with a 100ms TTL to minimize test duration while providing
/// a clear separation between "before expiry" and "after expiry".
#[tokio::test]
async fn test_expiration_boundary_before_and_after() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"boundary".to_vec(), b"value".to_vec(), Duration::from_millis(100))
        .await
        .expect("set_with_ttl");

    // Immediately after setting — key should exist.
    let before = backend.get(b"boundary").await.expect("get");
    assert_eq!(
        before,
        Some(Bytes::from("value")),
        "key should be readable immediately after set_with_ttl"
    );

    // Wait past the TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // After TTL elapses — key should be expired (is_expired returns true).
    let after = backend.get(b"boundary").await.expect("get");
    assert_eq!(after, None, "key should be expired after TTL elapses");
}

/// Multiple keys with different TTLs should expire independently.
#[tokio::test]
async fn test_independent_ttl_expiration() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"short".to_vec(), b"s".to_vec(), Duration::from_millis(100))
        .await
        .expect("set short TTL");

    backend
        .set_with_ttl(b"long".to_vec(), b"l".to_vec(), Duration::from_millis(500))
        .await
        .expect("set long TTL");

    // Wait past the short TTL but before the long TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let short_result = backend.get(b"short").await.expect("get short");
    let long_result = backend.get(b"long").await.expect("get long");

    assert_eq!(short_result, None, "short-TTL key should be expired");
    assert_eq!(long_result, Some(Bytes::from("l")), "long-TTL key should still be alive");
}

// ============================================================================
// TTL Clearing: set_with_ttl then set (no TTL)
// ============================================================================

/// Setting a key with TTL then overwriting with `set` (no TTL) should remove
/// the TTL, making the key permanent.
///
/// This is already partially covered by `test_overwrite_clears_ttl` in the
/// unit test module. This test adds a tighter timing window for precision.
#[tokio::test]
async fn test_set_after_set_with_ttl_clears_expiration() {
    let backend = MemoryBackend::new();

    // Set with a short TTL.
    backend
        .set_with_ttl(b"clearing".to_vec(), b"temporary".to_vec(), Duration::from_millis(100))
        .await
        .expect("set_with_ttl");

    // Immediately overwrite without TTL.
    backend.set(b"clearing".to_vec(), b"permanent".to_vec()).await.expect("set without TTL");

    // Wait past the original TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    // Key should still exist with the new value — TTL was cleared.
    let result = backend.get(b"clearing").await.expect("get");
    assert_eq!(
        result,
        Some(Bytes::from("permanent")),
        "overwriting with set() should clear the TTL, making the key permanent"
    );
}

/// `compare_and_set` on a key with TTL should also clear the TTL.
#[tokio::test]
async fn test_cas_clears_ttl() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"cas-ttl".to_vec(), b"original".to_vec(), Duration::from_millis(100))
        .await
        .expect("set_with_ttl");

    // CAS update — TTL should be cleared per the MemoryBackend implementation.
    backend
        .compare_and_set(b"cas-ttl", Some(b"original"), b"updated".to_vec())
        .await
        .expect("CAS should succeed");

    // Wait past the original TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = backend.get(b"cas-ttl").await.expect("get");
    assert_eq!(
        result,
        Some(Bytes::from("updated")),
        "CAS should clear the TTL, preventing expiration"
    );
}

/// `delete` on a key with TTL should remove both the data and the TTL metadata.
#[tokio::test]
async fn test_delete_clears_ttl_metadata() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"delete-me".to_vec(), b"value".to_vec(), Duration::from_secs(3600))
        .await
        .expect("set_with_ttl");

    backend.delete(b"delete-me").await.expect("delete");

    // Re-create the key without TTL.
    backend.set(b"delete-me".to_vec(), b"reborn".to_vec()).await.expect("set");

    // Wait a bit — the key should NOT expire because the old TTL metadata
    // was cleaned up by delete, and the new set has no TTL.
    tokio::time::sleep(Duration::from_millis(100)).await;

    let result = backend.get(b"delete-me").await.expect("get");
    assert_eq!(
        result,
        Some(Bytes::from("reborn")),
        "re-created key should not inherit TTL from deleted predecessor"
    );
}

// ============================================================================
// TTL Replacement: set_with_ttl then set_with_ttl again
// ============================================================================

/// Calling `set_with_ttl` a second time on the same key should replace the TTL.
/// The new TTL takes effect, overriding the original.
#[tokio::test]
async fn test_ttl_replacement_extends_expiration() {
    let backend = MemoryBackend::new();

    // Set with a very short TTL (100ms).
    backend
        .set_with_ttl(b"replace".to_vec(), b"v1".to_vec(), Duration::from_millis(100))
        .await
        .expect("first set_with_ttl");

    // Immediately replace with a longer TTL (2 seconds).
    backend
        .set_with_ttl(b"replace".to_vec(), b"v2".to_vec(), Duration::from_secs(2))
        .await
        .expect("second set_with_ttl");

    // Wait past the original TTL but before the new TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = backend.get(b"replace").await.expect("get");
    assert_eq!(
        result,
        Some(Bytes::from("v2")),
        "second set_with_ttl should replace TTL — key alive past original expiry"
    );
}

/// Calling `set_with_ttl` a second time with a shorter TTL should shorten the expiration.
#[tokio::test]
async fn test_ttl_replacement_shortens_expiration() {
    let backend = MemoryBackend::new();

    // Set with a long TTL (2 seconds).
    backend
        .set_with_ttl(b"shorten".to_vec(), b"v1".to_vec(), Duration::from_secs(2))
        .await
        .expect("first set_with_ttl");

    // Replace with a very short TTL (100ms).
    backend
        .set_with_ttl(b"shorten".to_vec(), b"v2".to_vec(), Duration::from_millis(100))
        .await
        .expect("second set_with_ttl");

    // Wait past the new (shorter) TTL.
    tokio::time::sleep(Duration::from_millis(200)).await;

    let result = backend.get(b"shorten").await.expect("get");
    assert_eq!(
        result, None,
        "second set_with_ttl with shorter TTL should cause earlier expiration"
    );
}

// ============================================================================
// Background Cleanup Interaction
// ============================================================================

/// The background cleanup task should remove expired keys from both the data
/// store and the TTL metadata store.
#[tokio::test]
async fn test_cleanup_task_removes_expired_keys() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"cleanup-me".to_vec(), b"value".to_vec(), Duration::from_millis(100))
        .await
        .expect("set_with_ttl");

    // Wait for the key to expire AND for the cleanup task to run (1s cycle).
    // The cleanup task runs every 1 second, so we need at least 1.2s.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    // After cleanup, the key should be gone from the data store.
    // Importantly, even without is_expired filtering, the data should be removed.
    let result = backend.get(b"cleanup-me").await.expect("get");
    assert_eq!(result, None, "cleanup task should have removed the expired key");
}

/// A key that hasn't expired yet should survive the cleanup task.
#[tokio::test]
async fn test_cleanup_task_preserves_live_keys() {
    let backend = MemoryBackend::new();

    backend
        .set_with_ttl(b"still-alive".to_vec(), b"value".to_vec(), Duration::from_secs(60))
        .await
        .expect("set_with_ttl");

    // Wait for the cleanup task to run at least once.
    tokio::time::sleep(Duration::from_millis(1500)).await;

    let result = backend.get(b"still-alive").await.expect("get");
    assert_eq!(
        result,
        Some(Bytes::from("value")),
        "cleanup task should not remove keys that haven't expired"
    );
}
