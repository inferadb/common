//! Range query edge case tests for `MemoryBackend`.
//!
//! Covers off-by-one errors, degenerate ranges, boundary inclusion/exclusion,
//! unbounded ranges, single-element ranges, and large values in range results.

#![allow(clippy::expect_used, clippy::panic)]

use std::ops::Bound;

use bytes::Bytes;
use inferadb_common_storage::{
    MemoryBackend, StorageBackend, assert_kv_pair, assert_range_results,
};

/// Helper: populate backend with keys "a", "b", "c", "d", "e".
async fn populated_backend() -> MemoryBackend {
    let backend = MemoryBackend::new();
    for (key, val) in [
        (b"a".as_slice(), b"va".as_slice()),
        (b"b", b"vb"),
        (b"c", b"vc"),
        (b"d", b"vd"),
        (b"e", b"ve"),
    ] {
        backend.set(key.to_vec(), val.to_vec()).await.expect("set");
    }
    backend
}

// ============================================================================
// Empty range (start > end)
// ============================================================================

/// When start > end (exclusive), `BTreeMap::range` would panic.
/// `MemoryBackend` delegates directly to `BTreeMap::range`, so we document
/// the expected behavior: empty vec, not an error.
///
/// NOTE: `BTreeMap::range(start..end)` panics when `start > end`. This test
/// verifies the behavior with `start == end` (exclusive end), which is a
/// degenerate empty range that does NOT panic.
#[tokio::test]
async fn test_degenerate_exclusive_range_start_equals_end() {
    let backend = populated_backend().await;

    // start..end where start == end => empty range (exclusive end means nothing matches)
    let results = backend
        .get_range(b"c".to_vec()..b"c".to_vec())
        .await
        .expect("degenerate exclusive range should succeed");
    assert!(
        results.is_empty(),
        "start == end (exclusive) should return empty vec, got {} results",
        results.len()
    );
}

// ============================================================================
// Single key exact match
// ============================================================================

/// `start..=start` (inclusive both ends) should return exactly one key if it exists.
#[tokio::test]
async fn test_single_key_inclusive_range() {
    let backend = populated_backend().await;

    let results = backend
        .get_range(b"c".to_vec()..=b"c".to_vec())
        .await
        .expect("single key inclusive range should succeed");
    assert_range_results!(results, [("c", "vc")]);
}

/// `start..=start` for a key that does NOT exist should return empty.
#[tokio::test]
async fn test_single_key_inclusive_range_nonexistent() {
    let backend = populated_backend().await;

    let results = backend
        .get_range(b"z".to_vec()..=b"z".to_vec())
        .await
        .expect("range on nonexistent key should succeed");
    assert!(results.is_empty(), "nonexistent key should return empty vec");
}

// ============================================================================
// Unbounded start
// ============================================================================

/// `..end` (unbounded start, exclusive end) should return all keys before `end`.
#[tokio::test]
async fn test_unbounded_start_exclusive_end() {
    let backend = populated_backend().await;

    let results =
        backend.get_range(..b"c".to_vec()).await.expect("unbounded start range should succeed");
    assert_range_results!(results, [("a", "va"), ("b", "vb")]);
}

/// `..=end` (unbounded start, inclusive end) should return all keys up to and including `end`.
#[tokio::test]
async fn test_unbounded_start_inclusive_end() {
    let backend = populated_backend().await;

    let results = backend
        .get_range(..=b"c".to_vec())
        .await
        .expect("unbounded start inclusive end should succeed");
    assert_range_results!(results, [("a", "va"), ("b", "vb"), ("c", "vc")]);
}

// ============================================================================
// Unbounded end
// ============================================================================

/// `start..` (inclusive start, unbounded end) should return all keys from `start` onward.
#[tokio::test]
async fn test_unbounded_end_inclusive_start() {
    let backend = populated_backend().await;

    let results =
        backend.get_range(b"c".to_vec()..).await.expect("unbounded end range should succeed");
    assert_range_results!(results, [("c", "vc"), ("d", "vd"), ("e", "ve")]);
}

// ============================================================================
// Fully unbounded
// ============================================================================

/// `..` (unbounded both ends) should return ALL keys.
#[tokio::test]
async fn test_fully_unbounded_range() {
    let backend = populated_backend().await;

    let results = backend
        .get_range::<std::ops::RangeFull>(..)
        .await
        .expect("fully unbounded range should succeed");
    assert_eq!(results.len(), 5, "should return all 5 keys");
    assert_kv_pair!(results[0], "a", "va");
    assert_kv_pair!(results[4], "e", "ve");
}

/// Fully unbounded range on an empty backend should return empty vec.
#[tokio::test]
async fn test_fully_unbounded_empty_backend() {
    let backend = MemoryBackend::new();

    let results = backend
        .get_range::<std::ops::RangeFull>(..)
        .await
        .expect("unbounded range on empty backend should succeed");
    assert!(results.is_empty());
}

// ============================================================================
// Boundary inclusion/exclusion with tuple bounds
// ============================================================================

/// `Included(start)..Included(end)` — both boundaries included.
#[tokio::test]
async fn test_both_inclusive_bounds() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::Included(b"b".to_vec()), Bound::Included(b"d".to_vec())))
        .await
        .expect("both inclusive bounds should succeed");
    assert_range_results!(results, [("b", "vb"), ("c", "vc"), ("d", "vd")]);
}

/// `Excluded(start)..Excluded(end)` — both boundaries excluded.
#[tokio::test]
async fn test_both_excluded_bounds() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::Excluded(b"a".to_vec()), Bound::Excluded(b"e".to_vec())))
        .await
        .expect("both excluded bounds should succeed");
    assert_range_results!(results, [("b", "vb"), ("c", "vc"), ("d", "vd")]);
}

/// `Excluded(start)..Included(end)` — start excluded, end included.
#[tokio::test]
async fn test_excluded_start_included_end() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::Excluded(b"b".to_vec()), Bound::Included(b"d".to_vec())))
        .await
        .expect("excluded start, included end should succeed");
    assert_range_results!(results, [("c", "vc"), ("d", "vd")]);
}

/// `Included(start)..Excluded(end)` — start included, end excluded.
#[tokio::test]
async fn test_included_start_excluded_end() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::Included(b"b".to_vec()), Bound::Excluded(b"d".to_vec())))
        .await
        .expect("included start, excluded end should succeed");
    assert_range_results!(results, [("b", "vb"), ("c", "vc")]);
}

/// `Unbounded..Unbounded` via tuple bounds — should return everything.
#[tokio::test]
async fn test_unbounded_tuple_bounds() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::<Vec<u8>>::Unbounded, Bound::<Vec<u8>>::Unbounded))
        .await
        .expect("unbounded tuple bounds should succeed");
    assert_eq!(results.len(), 5, "should return all 5 keys");
}

/// `Excluded(start)..Unbounded` — excluded start, no end.
#[tokio::test]
async fn test_excluded_start_unbounded_end() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::Excluded(b"c".to_vec()), Bound::<Vec<u8>>::Unbounded))
        .await
        .expect("excluded start, unbounded end should succeed");
    assert_range_results!(results, [("d", "vd"), ("e", "ve")]);
}

/// `Unbounded..Excluded(end)` — no start, excluded end.
#[tokio::test]
async fn test_unbounded_start_excluded_end() {
    let backend = populated_backend().await;

    let results = backend
        .get_range((Bound::<Vec<u8>>::Unbounded, Bound::Excluded(b"c".to_vec())))
        .await
        .expect("unbounded start, excluded end should succeed");
    assert_range_results!(results, [("a", "va"), ("b", "vb")]);
}

// ============================================================================
// Keys at exact boundaries
// ============================================================================

/// Keys that exactly match the boundary values should be correctly included/excluded.
#[tokio::test]
async fn test_boundary_key_inclusion() {
    let backend = populated_backend().await;

    // Exclusive start at "b" — "b" should NOT be in the result
    let results = backend
        .get_range((Bound::Excluded(b"b".to_vec()), Bound::Excluded(b"d".to_vec())))
        .await
        .expect("boundary test should succeed");

    let keys: Vec<_> = results.iter().map(|kv| kv.key.clone()).collect();
    assert!(
        !keys.contains(&Bytes::from("b")),
        "excluded start boundary 'b' should not be in results"
    );
    assert!(
        !keys.contains(&Bytes::from("d")),
        "excluded end boundary 'd' should not be in results"
    );
    assert!(keys.contains(&Bytes::from("c")), "key 'c' between boundaries should be in results");
}

/// When the excluded boundary is a key that doesn't exist, the nearest keys
/// are still correctly included.
#[tokio::test]
async fn test_boundary_between_existing_keys() {
    let backend = populated_backend().await;

    // "ba" doesn't exist, but "b" should be included with Included start
    let results = backend
        .get_range(b"b".to_vec()..b"ba".to_vec())
        .await
        .expect("range with boundary between keys should succeed");
    assert_range_results!(results, [("b", "vb")]);
}

// ============================================================================
// Large values
// ============================================================================

/// Keys with large values (1 MB+) should be returned correctly in range results.
#[tokio::test]
async fn test_large_values_in_range() {
    let backend = MemoryBackend::new();

    let large_value = vec![0xABu8; 1024 * 1024]; // 1 MB
    backend.set(b"large:1".to_vec(), large_value.clone()).await.expect("set large value");
    backend.set(b"large:2".to_vec(), large_value.clone()).await.expect("set large value");
    backend.set(b"other:1".to_vec(), b"small".to_vec()).await.expect("set small value");

    let results = backend
        .get_range(b"large:".to_vec()..b"large:~".to_vec())
        .await
        .expect("range with large values should succeed");

    assert_eq!(results.len(), 2, "should return both large keys");
    assert_eq!(results[0].value.len(), 1024 * 1024, "value should be 1 MB");
    assert_eq!(results[1].value.len(), 1024 * 1024, "value should be 1 MB");
}

// ============================================================================
// Results are sorted
// ============================================================================

/// Verify that range results are always sorted by key, even when keys were
/// inserted in non-sorted order.
#[tokio::test]
async fn test_range_results_sorted() {
    let backend = MemoryBackend::new();

    // Insert in reverse order
    for key in [b"e", b"d", b"c", b"b", b"a"] {
        backend.set(key.to_vec(), b"v".to_vec()).await.expect("set");
    }

    let results =
        backend.get_range(b"a".to_vec()..=b"e".to_vec()).await.expect("range should succeed");

    for window in results.windows(2) {
        assert!(
            window[0].key < window[1].key,
            "results should be sorted: {:?} should come before {:?}",
            window[0].key,
            window[1].key
        );
    }
}

// ============================================================================
// Empty range on populated backend
// ============================================================================

/// A range that falls entirely between existing keys should return empty.
#[tokio::test]
async fn test_range_between_keys_returns_empty() {
    let backend = MemoryBackend::new();

    backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("set");
    backend.set(b"z".to_vec(), b"vz".to_vec()).await.expect("set");

    // Range "m".."n" — no keys exist in this range
    let results = backend
        .get_range(b"m".to_vec()..b"n".to_vec())
        .await
        .expect("range between keys should succeed");
    assert!(results.is_empty(), "no keys exist in [m, n)");
}

// ============================================================================
// clear_range edge cases
// ============================================================================

/// `clear_range` with fully unbounded range should delete all keys.
#[tokio::test]
async fn test_clear_range_fully_unbounded() {
    let backend = populated_backend().await;

    backend
        .clear_range::<std::ops::RangeFull>(..)
        .await
        .expect("fully unbounded clear_range should succeed");

    let results = backend
        .get_range::<std::ops::RangeFull>(..)
        .await
        .expect("range after clear should succeed");
    assert!(results.is_empty(), "all keys should be deleted");
}

/// `clear_range` with single-key inclusive range.
#[tokio::test]
async fn test_clear_range_single_key() {
    let backend = populated_backend().await;

    backend
        .clear_range(b"c".to_vec()..=b"c".to_vec())
        .await
        .expect("single key clear_range should succeed");

    assert_eq!(backend.get(b"c").await.expect("get"), None, "c should be deleted");
    assert_eq!(
        backend.get(b"b").await.expect("get"),
        Some(Bytes::from("vb")),
        "b should still exist"
    );
    assert_eq!(
        backend.get(b"d").await.expect("get"),
        Some(Bytes::from("vd")),
        "d should still exist"
    );
}
