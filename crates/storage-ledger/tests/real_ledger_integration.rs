//! Integration tests for the Ledger storage backend with a real Ledger cluster.
//!
//! These tests require a running Ledger server. They are skipped unless the
//! `RUN_LEDGER_INTEGRATION_TESTS` environment variable is set.
//!
//! # Running the tests
//!
//! ```bash
//! # Start a Ledger server (single-node mode)
//! INFERADB__LEDGER__BOOTSTRAP_EXPECT=1 \
//! INFERADB__LEDGER__LISTEN_ADDR=0.0.0.0:50051 \
//! INFERADB__LEDGER__DATA_DIR=/tmp/ledger-test \
//! ledger
//!
//! # Run tests
//! RUN_LEDGER_INTEGRATION_TESTS=1 \
//! LEDGER_ENDPOINT=http://localhost:50051 \
//! cargo test --test real_ledger_integration -- --test-threads=1
//! ```
//!
//! Or use Docker Compose:
//!
//! ```bash
//! cd docker && ./run-integration-tests.sh
//! ```

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::{
    env,
    ops::Bound,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use bytes::Bytes;
use inferadb_common_storage::{NamespaceId, StorageBackend, VaultId};
use inferadb_common_storage_ledger::{LedgerBackend, LedgerBackendConfig};
use inferadb_ledger_sdk::{ClientConfig, ServerSource};
use tokio::time::sleep;

// ============================================================================
// Test Configuration
// ============================================================================

/// Global counter for generating unique vault IDs per test.
/// This ensures test isolation without requiring database cleanup.
static VAULT_COUNTER: AtomicU64 = AtomicU64::new(1000);

/// Check if real Ledger integration tests should run.
fn should_run() -> bool {
    env::var("RUN_LEDGER_INTEGRATION_TESTS").is_ok()
}

/// Get the Ledger endpoint from environment, or default.
fn ledger_endpoint() -> String {
    env::var("LEDGER_ENDPOINT").unwrap_or_else(|_| "http://localhost:50051".to_string())
}

/// Get the namespace ID from environment, or default.
fn ledger_namespace_id() -> NamespaceId {
    NamespaceId::from(
        env::var("LEDGER_NAMESPACE_ID").ok().and_then(|s| s.parse().ok()).unwrap_or(1),
    )
}

/// Get a unique vault ID for test isolation.
fn unique_vault_id() -> VaultId {
    VaultId::from(VAULT_COUNTER.fetch_add(1, Ordering::SeqCst) as i64)
}

/// Creates a ClientConfig for testing.
fn test_client_config(client_id: &str) -> ClientConfig {
    ClientConfig::builder()
        .servers(ServerSource::from_static([ledger_endpoint()]))
        .client_id(client_id)
        .build()
        .expect("valid client config")
}

/// Creates a LedgerBackend for testing with a unique vault.
async fn create_test_backend() -> LedgerBackend {
    let config = LedgerBackendConfig::builder()
        .client(test_client_config(&format!("test-client-{}", unique_vault_id())))
        .namespace_id(ledger_namespace_id())
        .vault_id(unique_vault_id())
        .build();

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

/// Creates a LedgerBackend with a specific vault ID (for isolation tests).
async fn create_backend_with_vault(vault_id: VaultId) -> LedgerBackend {
    let config = LedgerBackendConfig::builder()
        .client(test_client_config(&format!("test-client-vault-{}", vault_id)))
        .namespace_id(ledger_namespace_id())
        .vault_id(vault_id)
        .build();

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

// ============================================================================
// Basic Operations Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_get_nonexistent_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;
    let result = backend.get(b"nonexistent-key-12345").await;

    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn test_real_ledger_set_and_get() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Set a value
    backend.set(b"test-key".to_vec(), b"test-value".to_vec()).await.expect("set should succeed");

    // Get it back
    let result = backend.get(b"test-key").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("test-value")));
}

#[tokio::test]
async fn test_real_ledger_overwrite() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Set initial value
    backend.set(b"overwrite-key".to_vec(), b"initial".to_vec()).await.expect("set should succeed");

    // Overwrite
    backend.set(b"overwrite-key".to_vec(), b"updated".to_vec()).await.expect("set should succeed");

    // Verify
    let result = backend.get(b"overwrite-key").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("updated")));
}

#[tokio::test]
async fn test_real_ledger_delete() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Set then delete
    backend.set(b"delete-key".to_vec(), b"value".to_vec()).await.expect("set should succeed");
    backend.delete(b"delete-key").await.expect("delete should succeed");

    // Verify
    let result = backend.get(b"delete-key").await.expect("get should succeed");
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_real_ledger_delete_nonexistent() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Deleting a nonexistent key should succeed
    let result = backend.delete(b"nonexistent-delete-key").await;
    assert!(result.is_ok());
}

// ============================================================================
// Binary Data Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_binary_keys() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Key with null bytes and high bytes
    let key = [0x00, 0x01, 0xFF, 0xFE, 0x00, 0xAB];
    let value = b"binary key works";

    backend.set(key.to_vec(), value.to_vec()).await.expect("set should succeed");

    let result = backend.get(&key).await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from_static(value)));
}

#[tokio::test]
async fn test_real_ledger_large_value() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // 1MB value
    let key = b"large-value-key";
    let value: Vec<u8> = (0..1_000_000).map(|i| (i % 256) as u8).collect();

    backend.set(key.to_vec(), value.clone()).await.expect("set should succeed");

    let result = backend.get(key).await.expect("get should succeed");
    assert_eq!(result.map(|b| b.len()), Some(1_000_000));
}

// ============================================================================
// Range Query Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_range_query() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Insert keys with common prefix
    for i in 1..=5 {
        backend
            .set(format!("range:item:{}", i).into_bytes(), format!("v{}", i).into_bytes())
            .await
            .expect("set should succeed");
    }

    // Insert a key outside the range
    backend.set(b"other:item:1".to_vec(), b"other".to_vec()).await.expect("set should succeed");

    // Range query
    let results = backend
        .get_range(b"range:item:".to_vec()..b"range:item:~".to_vec())
        .await
        .expect("range should succeed");

    assert_eq!(results.len(), 5, "should find 5 keys in range");
}

#[tokio::test]
async fn test_real_ledger_range_query_inclusive_bounds() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    backend.set(b"bound:a".to_vec(), b"va".to_vec()).await.unwrap();
    backend.set(b"bound:b".to_vec(), b"vb".to_vec()).await.unwrap();
    backend.set(b"bound:c".to_vec(), b"vc".to_vec()).await.unwrap();

    // Inclusive bounds
    let results = backend
        .get_range((Bound::Included(b"bound:a".to_vec()), Bound::Included(b"bound:b".to_vec())))
        .await
        .expect("range should succeed");

    assert_eq!(results.len(), 2, "should include a and b");
}

#[tokio::test]
async fn test_real_ledger_clear_range() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Insert keys
    backend.set(b"clear:1".to_vec(), b"v1".to_vec()).await.unwrap();
    backend.set(b"clear:2".to_vec(), b"v2".to_vec()).await.unwrap();
    backend.set(b"keep:1".to_vec(), b"keep".to_vec()).await.unwrap();

    // Clear the clear: prefix
    backend
        .clear_range(b"clear:".to_vec()..b"clear:~".to_vec())
        .await
        .expect("clear should succeed");

    // Verify cleared
    assert_eq!(backend.get(b"clear:1").await.unwrap(), None);
    assert_eq!(backend.get(b"clear:2").await.unwrap(), None);

    // keep: should remain
    assert_eq!(backend.get(b"keep:1").await.unwrap(), Some(Bytes::from("keep")));
}

// ============================================================================
// TTL Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_ttl() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Set with short TTL (2 seconds)
    backend
        .set_with_ttl(b"ttl-key".to_vec(), b"expires-soon".to_vec(), 2)
        .await
        .expect("set_with_ttl should succeed");

    // Should exist immediately
    let result = backend.get(b"ttl-key").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("expires-soon")));

    // Wait for expiration
    sleep(Duration::from_secs(3)).await;

    // Should be expired
    let result = backend.get(b"ttl-key").await.expect("get should succeed");
    assert_eq!(result, None, "key should have expired");
}

// ============================================================================
// Transaction Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_transaction_commit() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Start transaction
    let mut txn = backend.transaction().await.expect("transaction should succeed");

    // Buffer writes
    txn.set(b"txn:key1".to_vec(), b"value1".to_vec());
    txn.set(b"txn:key2".to_vec(), b"value2".to_vec());

    // Read-your-writes
    let val = txn.get(b"txn:key1").await.expect("txn get should succeed");
    assert_eq!(val, Some(Bytes::from("value1")));

    // Commit
    txn.commit().await.expect("commit should succeed");

    // Verify after commit
    assert_eq!(backend.get(b"txn:key1").await.unwrap(), Some(Bytes::from("value1")));
    assert_eq!(backend.get(b"txn:key2").await.unwrap(), Some(Bytes::from("value2")));
}

#[tokio::test]
async fn test_real_ledger_transaction_delete() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Pre-populate
    backend.set(b"txn-delete".to_vec(), b"will-delete".to_vec()).await.unwrap();

    // Delete in transaction
    let mut txn = backend.transaction().await.unwrap();
    txn.delete(b"txn-delete".to_vec());

    // Read-your-writes: should see None
    assert_eq!(txn.get(b"txn-delete").await.unwrap(), None);

    txn.commit().await.unwrap();

    // Verify deleted
    assert_eq!(backend.get(b"txn-delete").await.unwrap(), None);
}

#[tokio::test]
async fn test_real_ledger_transaction_set_delete_set() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    let mut txn = backend.transaction().await.unwrap();

    // Set, delete, set again
    txn.set(b"sds-key".to_vec(), b"first".to_vec());
    txn.delete(b"sds-key".to_vec());
    txn.set(b"sds-key".to_vec(), b"final".to_vec());

    assert_eq!(txn.get(b"sds-key").await.unwrap(), Some(Bytes::from("final")));

    txn.commit().await.unwrap();

    assert_eq!(backend.get(b"sds-key").await.unwrap(), Some(Bytes::from("final")));
}

#[tokio::test]
async fn test_real_ledger_empty_transaction() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Empty transaction should commit successfully
    let txn = backend.transaction().await.unwrap();
    let result = txn.commit().await;
    assert!(result.is_ok());
}

// ============================================================================
// Vault Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_vault_isolation() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let vault_a = unique_vault_id();
    let vault_b = unique_vault_id();

    let backend_a = create_backend_with_vault(vault_a).await;
    let backend_b = create_backend_with_vault(vault_b).await;

    // Write to vault A
    backend_a.set(b"shared-key".to_vec(), b"vault-a-value".to_vec()).await.unwrap();

    // Should NOT be visible in vault B
    assert_eq!(backend_b.get(b"shared-key").await.unwrap(), None);

    // Write to vault B
    backend_b.set(b"shared-key".to_vec(), b"vault-b-value".to_vec()).await.unwrap();

    // Each vault sees its own value
    assert_eq!(backend_a.get(b"shared-key").await.unwrap(), Some(Bytes::from("vault-a-value")));
    assert_eq!(backend_b.get(b"shared-key").await.unwrap(), Some(Bytes::from("vault-b-value")));
}

// ============================================================================
// Concurrent Write Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_concurrent_writes() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    // Each spawned task creates its own backend with unique vault for isolation
    // Spawn multiple concurrent writers
    let mut handles = Vec::new();
    for i in 0..10 {
        let backend_clone = create_test_backend().await;
        let key = format!("concurrent:key:{}", i);
        let value = format!("value:{}", i);

        handles.push(tokio::spawn(async move {
            backend_clone.set(key.into_bytes(), value.into_bytes()).await
        }));
    }

    // Wait for all writers
    for handle in handles {
        handle.await.expect("task should succeed").expect("write should succeed");
    }

    // All writes should have succeeded (each backend has its own vault)
}

#[tokio::test]
async fn test_real_ledger_concurrent_writes_same_key() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let base_vault = unique_vault_id();

    // Multiple writers to the same vault/key
    let mut handles = Vec::new();
    for i in 0..5 {
        let backend = create_backend_with_vault(base_vault).await;
        let value = format!("writer-{}", i);

        handles.push(tokio::spawn(async move {
            backend.set(b"contested-key".to_vec(), value.into_bytes()).await
        }));
    }

    // All writes should succeed (last writer wins)
    for handle in handles {
        handle.await.expect("task should succeed").expect("write should succeed");
    }

    // Verify the key has some value
    let backend = create_backend_with_vault(base_vault).await;
    let result = backend.get(b"contested-key").await.unwrap();
    assert!(result.is_some(), "key should have a value");
}

// ============================================================================
// Reconnection Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_reconnection_after_idle() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // First operation
    backend
        .set(b"reconnect:key".to_vec(), b"value1".to_vec())
        .await
        .expect("first set should succeed");

    // Simulate idle period (connection may be dropped)
    sleep(Duration::from_secs(5)).await;

    // Should reconnect automatically
    let result = backend.get(b"reconnect:key").await.expect("get after idle should succeed");

    assert_eq!(result, Some(Bytes::from("value1")));

    // Write after reconnection
    backend
        .set(b"reconnect:key".to_vec(), b"value2".to_vec())
        .await
        .expect("second set should succeed");

    let result = backend.get(b"reconnect:key").await.unwrap();
    assert_eq!(result, Some(Bytes::from("value2")));
}

// ============================================================================
// Health Check Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_health_check() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    let result = backend.health_check().await;
    assert!(result.is_ok(), "health check should succeed");
}

// ============================================================================
// Stress Tests
// ============================================================================

#[tokio::test]
async fn test_real_ledger_many_keys() {
    if !should_run() {
        eprintln!("Skipping real Ledger test (RUN_LEDGER_INTEGRATION_TESTS not set)");
        return;
    }

    let backend = create_test_backend().await;

    // Insert many keys
    let count = 100;
    for i in 0..count {
        backend
            .set(format!("many:key:{:05}", i).into_bytes(), format!("value:{}", i).into_bytes())
            .await
            .expect("set should succeed");
    }

    // Range query should find all
    let results = backend
        .get_range(b"many:key:".to_vec()..b"many:key:~".to_vec())
        .await
        .expect("range should succeed");

    assert_eq!(results.len(), count, "should find all {} keys", count);
}
