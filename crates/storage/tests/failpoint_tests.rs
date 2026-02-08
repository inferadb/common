#![allow(clippy::expect_used, clippy::panic)]
//! Integration tests for fail-point injection.
//!
//! These tests require the `failpoints` feature:
//! ```bash
//! cargo test -p inferadb-common-storage --features failpoints --test failpoint_tests
//! ```

use inferadb_common_storage::{
    HealthProbe, MemoryBackend, StorageBackend,
    batch::{BatchConfig, BatchWriter},
};

#[tokio::test]
async fn batch_commit_failpoint_returns_error() {
    let scenario = fail::FailScenario::setup();
    fail::cfg("batch-before-commit", "return").expect("failed to configure fail point");

    let backend = MemoryBackend::new();
    let config = BatchConfig::default();
    let mut writer = BatchWriter::new(backend, config);
    writer.set(b"key".to_vec(), b"value".to_vec());
    let result = writer.flush().await;

    assert!(result.has_failures(), "batch flush should fail when fail point is active",);

    scenario.teardown();
}

#[tokio::test]
async fn batch_commit_without_failpoint_succeeds() {
    let scenario = fail::FailScenario::setup();
    // No fail point configured — batch should succeed normally

    let backend = MemoryBackend::new();
    let config = BatchConfig::default();
    let mut writer = BatchWriter::new(backend, config);
    writer.set(b"key".to_vec(), b"value".to_vec());
    let result = writer.flush().await;

    assert!(result.is_success(), "batch flush should succeed without fail point",);

    scenario.teardown();
}

#[tokio::test]
async fn health_check_failpoint_returns_error() {
    let scenario = fail::FailScenario::setup();
    fail::cfg("health-check", "return").expect("failed to configure fail point");

    let backend = MemoryBackend::new();
    let result = backend.health_check(HealthProbe::Readiness).await;

    assert!(result.is_err(), "health check should fail when fail point is active");

    scenario.teardown();
}

#[tokio::test]
async fn health_check_without_failpoint_succeeds() {
    let scenario = fail::FailScenario::setup();
    // No fail point configured — health check should succeed normally

    let backend = MemoryBackend::new();
    let result = backend.health_check(HealthProbe::Readiness).await;

    assert!(result.is_ok(), "health check should succeed without fail point");

    scenario.teardown();
}
