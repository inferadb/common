//! Conformance test suite for `MemoryBackend`.
//!
//! Each test function corresponds to a single conformance check, providing
//! fine-grained failure reporting. The `run_all` test exercises the full
//! suite as a one-liner to verify no tests are accidentally omitted.

#![allow(clippy::expect_used, clippy::panic)]

use std::sync::Arc;

use inferadb_common_storage::{MemoryBackend, conformance};

// ============================================================================
// CRUD (8 tests)
// ============================================================================

#[tokio::test]
async fn crud_get_returns_none_for_missing_key() {
    conformance::crud_get_returns_none_for_missing_key(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_set_then_get_returns_value() {
    conformance::crud_set_then_get_returns_value(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_set_overwrites_existing() {
    conformance::crud_set_overwrites_existing(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_delete_nonexistent_is_noop() {
    conformance::crud_delete_nonexistent_is_noop(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_delete_removes_key() {
    conformance::crud_delete_removes_key(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_keys_are_byte_distinct() {
    conformance::crud_keys_are_byte_distinct(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_empty_key_and_value() {
    conformance::crud_empty_key_and_value(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn crud_large_value_roundtrip() {
    conformance::crud_large_value_roundtrip(&MemoryBackend::new()).await;
}

// ============================================================================
// Range (5 tests)
// ============================================================================

#[tokio::test]
async fn range_results_are_ordered() {
    conformance::range_results_are_ordered(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn range_exclusive_end() {
    conformance::range_exclusive_end(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn range_inclusive_end() {
    conformance::range_inclusive_end(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn range_empty_range_returns_empty() {
    conformance::range_empty_range_returns_empty(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn range_clear_range_removes_keys() {
    conformance::range_clear_range_removes_keys(&MemoryBackend::new()).await;
}

// ============================================================================
// TTL (4 tests)
// ============================================================================

#[tokio::test]
async fn ttl_key_expires() {
    conformance::ttl_key_expires(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn ttl_zero_is_immediately_expired() {
    conformance::ttl_zero_is_immediately_expired(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn ttl_overwrite_clears_ttl() {
    conformance::ttl_overwrite_clears_ttl(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn ttl_expired_keys_excluded_from_range() {
    conformance::ttl_expired_keys_excluded_from_range(&MemoryBackend::new()).await;
}

// ============================================================================
// Transaction (6 tests)
// ============================================================================

#[tokio::test]
async fn tx_read_your_writes() {
    conformance::tx_read_your_writes(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn tx_reads_committed_data() {
    conformance::tx_reads_committed_data(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn tx_commit_applies_all() {
    conformance::tx_commit_applies_all(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn tx_drop_without_commit_is_noop() {
    conformance::tx_drop_without_commit_is_noop(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn tx_delete_then_get_returns_none() {
    conformance::tx_delete_then_get_returns_none(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn tx_cas_conflict_rejects_commit() {
    conformance::tx_cas_conflict_rejects_commit(&MemoryBackend::new()).await;
}

// ============================================================================
// CAS (4 tests)
// ============================================================================

#[tokio::test]
async fn cas_insert_if_absent() {
    conformance::cas_insert_if_absent(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn cas_insert_if_absent_fails_when_key_exists() {
    conformance::cas_insert_if_absent_fails_when_key_exists(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn cas_update_with_matching_value() {
    conformance::cas_update_with_matching_value(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn cas_update_with_mismatched_value() {
    conformance::cas_update_with_mismatched_value(&MemoryBackend::new()).await;
}

// ============================================================================
// Concurrent (3 tests)
// ============================================================================

#[tokio::test]
async fn concurrent_sets_to_different_keys() {
    conformance::concurrent_sets_to_different_keys(Arc::new(MemoryBackend::new())).await;
}

#[tokio::test]
async fn concurrent_reads_return_consistent_value() {
    conformance::concurrent_reads_return_consistent_value(Arc::new(MemoryBackend::new())).await;
}

#[tokio::test]
async fn concurrent_cas_exactly_one_winner() {
    conformance::concurrent_cas_exactly_one_winner(Arc::new(MemoryBackend::new())).await;
}

// ============================================================================
// Error semantics (4 tests)
// ============================================================================

#[tokio::test]
async fn health_check_returns_healthy() {
    conformance::health_check_returns_healthy(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn get_deleted_key_returns_none_not_error() {
    conformance::get_deleted_key_returns_none_not_error(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn clear_range_on_empty_range_is_noop() {
    conformance::clear_range_on_empty_range_is_noop(&MemoryBackend::new()).await;
}

#[tokio::test]
async fn idempotent_delete() {
    conformance::idempotent_delete(&MemoryBackend::new()).await;
}

// ============================================================================
// Full suite convenience runner
// ============================================================================

/// Runs all conformance tests in sequence to verify completeness.
/// This catches the case where a new conformance test is added to the module
/// but not wired into the individual test functions above.
#[tokio::test]
async fn run_all_conformance_tests() {
    conformance::run_all(Arc::new(MemoryBackend::new())).await;
}

// ============================================================================
// BufferedBackend wrapper conformance (4 tests)
// ============================================================================

#[tokio::test]
async fn buffered_backend_conformance() {
    conformance::buffered_backend_conformance().await;
}

#[tokio::test]
async fn buffered_read_your_writes() {
    conformance::buffered_read_your_writes().await;
}

#[tokio::test]
async fn buffered_commit_atomicity() {
    conformance::buffered_commit_atomicity().await;
}

#[tokio::test]
async fn buffered_transaction_accumulation() {
    conformance::buffered_transaction_accumulation().await;
}

// ============================================================================
// CachedBackend wrapper conformance (3 tests)
// ============================================================================

#[tokio::test]
async fn cached_backend_conformance() {
    conformance::cached_backend_conformance().await;
}

#[tokio::test]
async fn cached_invalidation_on_write() {
    conformance::cached_invalidation_on_write().await;
}

#[tokio::test]
async fn cached_invalidation_on_delete() {
    conformance::cached_invalidation_on_delete().await;
}
