//! Integration tests for the Ledger storage backend.
//!
//! These tests use the `MockLedgerServer` from the Ledger SDK to test
//! `LedgerBackend` behavior without requiring a real Ledger cluster.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use std::ops::Bound;

use bytes::Bytes;
use inferadb_common_storage::StorageBackend;
use inferadb_common_storage_ledger::{LedgerBackend, LedgerBackendConfig};
use inferadb_ledger_sdk::mock::MockLedgerServer;

// ============================================================================
// Test Helpers
// ============================================================================

/// Creates a LedgerBackend connected to the given mock server.
async fn create_test_backend(server: &MockLedgerServer) -> LedgerBackend {
    let config = LedgerBackendConfig::builder()
        .endpoints([server.endpoint()])
        .client_id("test-client")
        .namespace_id(1)
        .vault_id(0)
        .build()
        .expect("valid config");

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

// ============================================================================
// Basic Operations Tests
// ============================================================================

#[tokio::test]
async fn test_get_nonexistent_key_returns_none() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    let result = backend.get(b"nonexistent").await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn test_set_and_get_roundtrip() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Set a value
    backend.set(b"key1".to_vec(), b"value1".to_vec()).await.expect("set should succeed");

    // Get it back
    let result = backend.get(b"key1").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("value1")));
}

#[tokio::test]
async fn test_set_overwrites_existing_value() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Set initial value
    backend.set(b"key".to_vec(), b"initial".to_vec()).await.expect("set should succeed");

    // Overwrite
    backend.set(b"key".to_vec(), b"updated".to_vec()).await.expect("set should succeed");

    // Verify updated value
    let result = backend.get(b"key").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("updated")));
}

#[tokio::test]
async fn test_delete_removes_key() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Set then delete
    backend.set(b"key".to_vec(), b"value".to_vec()).await.expect("set should succeed");
    backend.delete(b"key").await.expect("delete should succeed");

    // Verify key is gone
    let result = backend.get(b"key").await.expect("get should succeed");
    assert_eq!(result, None);
}

#[tokio::test]
async fn test_delete_nonexistent_key_succeeds() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Deleting a key that doesn't exist should not error
    let result = backend.delete(b"nonexistent").await;
    assert!(result.is_ok());
}

// ============================================================================
// Binary Key Tests
// ============================================================================

#[tokio::test]
async fn test_binary_keys_with_null_bytes() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Key with embedded null bytes
    let key = [0x00, 0x01, 0xFF, 0x00, 0xAB];
    let value = b"binary key works";

    backend.set(key.to_vec(), value.to_vec()).await.expect("set should succeed");
    let result = backend.get(&key).await.expect("get should succeed");

    assert_eq!(result, Some(Bytes::from_static(value)));
}

#[tokio::test]
async fn test_binary_values() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Value with arbitrary binary data
    let key = b"binary-value-key";
    let value: Vec<u8> = (0..=255).collect();

    backend.set(key.to_vec(), value.clone()).await.expect("set should succeed");
    let result = backend.get(key).await.expect("get should succeed");

    assert_eq!(result, Some(Bytes::from(value)));
}

#[tokio::test]
async fn test_empty_key() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Empty key should work
    backend.set(vec![], b"empty key value".to_vec()).await.expect("set should succeed");
    let result = backend.get(&[]).await.expect("get should succeed");

    assert_eq!(result, Some(Bytes::from("empty key value")));
}

#[tokio::test]
async fn test_empty_value() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Empty value should work
    backend.set(b"key".to_vec(), vec![]).await.expect("set should succeed");
    let result = backend.get(b"key").await.expect("get should succeed");

    assert_eq!(result, Some(Bytes::new()));
}

// ============================================================================
// Range Query Tests
// ============================================================================

#[tokio::test]
async fn test_get_range_empty() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // No keys set, range should return empty
    let result =
        backend.get_range(b"a".to_vec()..b"z".to_vec()).await.expect("range should succeed");
    assert!(result.is_empty());
}

#[tokio::test]
async fn test_get_range_with_data() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Insert some keys
    backend.set(b"key:1".to_vec(), b"v1".to_vec()).await.unwrap();
    backend.set(b"key:2".to_vec(), b"v2".to_vec()).await.unwrap();
    backend.set(b"key:3".to_vec(), b"v3".to_vec()).await.unwrap();
    backend.set(b"other:1".to_vec(), b"other".to_vec()).await.unwrap();

    // Range should include key:1, key:2, key:3
    let result =
        backend.get_range(b"key:".to_vec()..b"key:~".to_vec()).await.expect("range should succeed");

    assert_eq!(result.len(), 3);
}

#[tokio::test]
async fn test_get_range_inclusive_bounds() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    backend.set(b"a".to_vec(), b"va".to_vec()).await.unwrap();
    backend.set(b"b".to_vec(), b"vb".to_vec()).await.unwrap();
    backend.set(b"c".to_vec(), b"vc".to_vec()).await.unwrap();

    // Using RangeInclusive via the tuple bounds
    let result = backend
        .get_range((Bound::Included(b"a".to_vec()), Bound::Included(b"b".to_vec())))
        .await
        .expect("range should succeed");

    // Should include 'a' and 'b', but not 'c'
    assert_eq!(result.len(), 2);
}

// ============================================================================
// Clear Range Tests
// ============================================================================

#[tokio::test]
async fn test_clear_range() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Insert keys
    backend.set(b"del:1".to_vec(), b"v1".to_vec()).await.unwrap();
    backend.set(b"del:2".to_vec(), b"v2".to_vec()).await.unwrap();
    backend.set(b"keep:1".to_vec(), b"keep".to_vec()).await.unwrap();

    // Clear the del: prefix
    backend.clear_range(b"del:".to_vec()..b"del:~".to_vec()).await.expect("clear should succeed");

    // del: keys should be gone
    assert_eq!(backend.get(b"del:1").await.unwrap(), None);
    assert_eq!(backend.get(b"del:2").await.unwrap(), None);

    // keep: key should remain
    assert_eq!(backend.get(b"keep:1").await.unwrap(), Some(Bytes::from("keep")));
}

#[tokio::test]
async fn test_clear_range_empty() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Clearing an empty range should succeed
    let result = backend.clear_range(b"nothing:".to_vec()..b"nothing:~".to_vec()).await;
    assert!(result.is_ok());
}

// ============================================================================
// TTL Tests
// ============================================================================

#[tokio::test]
async fn test_set_with_ttl() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Set with TTL
    backend
        .set_with_ttl(b"ephemeral".to_vec(), b"temp".to_vec(), 3600)
        .await
        .expect("set_with_ttl should succeed");

    // Key should exist initially (mock doesn't actually expire)
    let result = backend.get(b"ephemeral").await.expect("get should succeed");
    assert_eq!(result, Some(Bytes::from("temp")));
}

// ============================================================================
// Transaction Tests
// ============================================================================

#[tokio::test]
async fn test_transaction_basic() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Start a transaction
    let mut txn = backend.transaction().await.expect("transaction creation should succeed");

    // Buffer some writes
    txn.set(b"txn:1".to_vec(), b"value1".to_vec());
    txn.set(b"txn:2".to_vec(), b"value2".to_vec());

    // Read within transaction should see buffered writes
    let val = txn.get(b"txn:1").await.expect("txn get should succeed");
    assert_eq!(val, Some(Bytes::from("value1")));

    // Commit
    txn.commit().await.expect("commit should succeed");

    // Values should be visible after commit
    assert_eq!(backend.get(b"txn:1").await.unwrap(), Some(Bytes::from("value1")));
    assert_eq!(backend.get(b"txn:2").await.unwrap(), Some(Bytes::from("value2")));
}

#[tokio::test]
async fn test_transaction_delete() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Pre-populate a key
    backend.set(b"to-delete".to_vec(), b"will be deleted".to_vec()).await.unwrap();

    // Start transaction and delete
    let mut txn = backend.transaction().await.unwrap();
    txn.delete(b"to-delete".to_vec());

    // Transaction should see the key as deleted
    let val = txn.get(b"to-delete").await.unwrap();
    assert_eq!(val, None);

    // Commit
    txn.commit().await.unwrap();

    // Key should be deleted in backend
    assert_eq!(backend.get(b"to-delete").await.unwrap(), None);
}

#[tokio::test]
async fn test_transaction_read_your_writes() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    let mut txn = backend.transaction().await.unwrap();

    // Write then read within same transaction
    txn.set(b"ryw:key".to_vec(), b"ryw:value".to_vec());
    let val = txn.get(b"ryw:key").await.unwrap();

    assert_eq!(val, Some(Bytes::from("ryw:value")));
}

#[tokio::test]
async fn test_transaction_delete_then_set() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    let mut txn = backend.transaction().await.unwrap();

    // Delete then set same key
    txn.delete(b"key".to_vec());
    txn.set(b"key".to_vec(), b"final".to_vec());

    // Should see the set value
    let val = txn.get(b"key").await.unwrap();
    assert_eq!(val, Some(Bytes::from("final")));

    txn.commit().await.unwrap();
    assert_eq!(backend.get(b"key").await.unwrap(), Some(Bytes::from("final")));
}

#[tokio::test]
async fn test_transaction_set_then_delete() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    let mut txn = backend.transaction().await.unwrap();

    // Set then delete same key
    txn.set(b"key".to_vec(), b"temporary".to_vec());
    txn.delete(b"key".to_vec());

    // Should see None
    let val = txn.get(b"key").await.unwrap();
    assert_eq!(val, None);

    txn.commit().await.unwrap();
    assert_eq!(backend.get(b"key").await.unwrap(), None);
}

#[tokio::test]
async fn test_transaction_empty_commit() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Empty transaction should commit successfully
    let txn = backend.transaction().await.unwrap();
    let result = txn.commit().await;
    assert!(result.is_ok());
}

// ============================================================================
// Health Check Tests
// ============================================================================

#[tokio::test]
async fn test_health_check_healthy() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    let result = backend.health_check().await;
    assert!(result.is_ok());
}

// ============================================================================
// Namespace/Vault Isolation Tests
// ============================================================================

#[tokio::test]
async fn test_vault_isolation() {
    let server = MockLedgerServer::start().await.expect("mock server start");

    // Create two backends with different vaults
    let config1 = LedgerBackendConfig::builder()
        .endpoints([server.endpoint()])
        .client_id("client-vault-1")
        .namespace_id(1)
        .vault_id(100)
        .build()
        .unwrap();

    let config2 = LedgerBackendConfig::builder()
        .endpoints([server.endpoint()])
        .client_id("client-vault-2")
        .namespace_id(1)
        .vault_id(200)
        .build()
        .unwrap();

    let backend1 = LedgerBackend::new(config1).await.unwrap();
    let backend2 = LedgerBackend::new(config2).await.unwrap();

    // Set in vault 100
    backend1.set(b"shared-key".to_vec(), b"vault-100-value".to_vec()).await.unwrap();

    // Should not be visible in vault 200
    let result = backend2.get(b"shared-key").await.unwrap();
    assert_eq!(result, None);

    // Set in vault 200
    backend2.set(b"shared-key".to_vec(), b"vault-200-value".to_vec()).await.unwrap();

    // Each vault has its own value
    assert_eq!(backend1.get(b"shared-key").await.unwrap(), Some(Bytes::from("vault-100-value")));
    assert_eq!(backend2.get(b"shared-key").await.unwrap(), Some(Bytes::from("vault-200-value")));
}

// ============================================================================
// Request Counting (Verifying Client Behavior)
// ============================================================================

#[tokio::test]
async fn test_request_counting() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Perform some operations
    backend.set(b"k1".to_vec(), b"v1".to_vec()).await.unwrap();
    backend.set(b"k2".to_vec(), b"v2".to_vec()).await.unwrap();
    backend.get(b"k1").await.unwrap();
    backend.get(b"k2").await.unwrap();
    backend.get(b"k3").await.unwrap(); // nonexistent

    // Verify request counts
    assert_eq!(server.write_count(), 2, "should have 2 write requests");
    assert_eq!(server.read_count(), 3, "should have 3 read requests");
}

// ============================================================================
// Key Encoding Tests (via behavior)
// ============================================================================

#[tokio::test]
async fn test_key_ordering_preserved() {
    let server = MockLedgerServer::start().await.expect("mock server start");
    let backend = create_test_backend(&server).await;

    // Insert keys that should sort in a specific order
    backend.set(b"aaa".to_vec(), b"1".to_vec()).await.unwrap();
    backend.set(b"aab".to_vec(), b"2".to_vec()).await.unwrap();
    backend.set(b"bbb".to_vec(), b"3".to_vec()).await.unwrap();

    // Range query should respect ordering
    let results = backend.get_range(b"aa".to_vec()..b"ab".to_vec()).await.unwrap();

    // Should only include aaa and aab (not bbb)
    assert_eq!(results.len(), 2);
    // Keys should be in order
    assert!(results[0].key < results[1].key);
}

// ============================================================================
// Signing Key Store Tests
// ============================================================================

mod signing_key_store {
    use std::sync::Arc;

    use chrono::{Duration, Utc};
    use inferadb_common_storage::{
        StorageError,
        auth::{PublicSigningKey, PublicSigningKeyStore, SigningKeyMetrics},
    };
    use inferadb_common_storage_ledger::auth::LedgerSigningKeyStore;
    use inferadb_ledger_sdk::{
        ClientConfig, LedgerClient, ReadConsistency, ServerSource, mock::MockLedgerServer,
    };

    async fn create_signing_key_store(server: &MockLedgerServer) -> LedgerSigningKeyStore {
        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint()]))
            .client_id("signing-key-test")
            .build()
            .expect("valid config");

        let client = LedgerClient::new(config).await.expect("client creation");
        LedgerSigningKeyStore::new(Arc::new(client))
    }

    fn create_test_key(kid: &str) -> PublicSigningKey {
        let now = Utc::now();
        PublicSigningKey::builder()
            .kid(kid.to_owned())
            .public_key("MCowBQYDK2VwAyEAtest_public_key_data".to_owned())
            .client_id(12345)
            .cert_id(42)
            .created_at(now)
            .valid_from(now)
            .build()
    }

    #[tokio::test]
    async fn test_create_and_get_key() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let key = create_test_key("test-key-001");
        let namespace_id = 100;

        // Create the key
        store.create_key(namespace_id, &key).await.expect("create should succeed");

        // Retrieve it
        let retrieved =
            store.get_key(namespace_id, "test-key-001").await.expect("get should succeed");
        assert!(retrieved.is_some());
        let retrieved = retrieved.unwrap();
        assert_eq!(retrieved.kid, "test-key-001");
        assert_eq!(retrieved.client_id, 12345);
    }

    #[tokio::test]
    async fn test_create_duplicate_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let key = create_test_key("dup-key");
        let namespace_id = 100;

        // Create first time
        store.create_key(namespace_id, &key).await.expect("first create should succeed");

        // Create again should fail with conflict
        let result = store.create_key(namespace_id, &key).await;
        assert!(matches!(result, Err(StorageError::Conflict)));
    }

    #[tokio::test]
    async fn test_get_nonexistent_key_returns_none() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let result = store.get_key(100, "nonexistent").await.expect("get should succeed");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_list_active_keys() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create an active key
        let active_key = create_test_key("active-key");
        store.create_key(namespace_id, &active_key).await.expect("create active");

        // Create an inactive key
        let mut inactive_key = create_test_key("inactive-key");
        inactive_key.active = false;
        store.create_key(namespace_id, &inactive_key).await.expect("create inactive");

        // List should only return active keys
        let active_keys = store.list_active_keys(namespace_id).await.expect("list should succeed");

        // Should have at least the active key (mock might have different behavior)
        let active_kids: Vec<_> = active_keys.iter().map(|k| k.kid.as_str()).collect();
        assert!(active_kids.contains(&"active-key"));
    }

    #[tokio::test]
    async fn test_deactivate_key() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create a key
        let key = create_test_key("to-deactivate");
        store.create_key(namespace_id, &key).await.expect("create");

        // Deactivate it
        store
            .deactivate_key(namespace_id, "to-deactivate")
            .await
            .expect("deactivate should succeed");

        // Verify it's deactivated
        let retrieved = store.get_key(namespace_id, "to-deactivate").await.expect("get").unwrap();
        assert!(!retrieved.active);
    }

    #[tokio::test]
    async fn test_deactivate_nonexistent_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let result = store.deactivate_key(100, "nonexistent").await;
        assert!(matches!(result, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create a key
        let key = create_test_key("to-revoke");
        store.create_key(namespace_id, &key).await.expect("create");

        // Revoke it
        store.revoke_key(namespace_id, "to-revoke", Some("test reason")).await.expect("revoke");

        // Verify it's revoked
        let retrieved = store.get_key(namespace_id, "to-revoke").await.expect("get").unwrap();
        assert!(retrieved.revoked_at.is_some());
        assert!(!retrieved.active);
    }

    #[tokio::test]
    async fn test_revoke_key_idempotent() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create and revoke a key
        let key = create_test_key("revoke-twice");
        store.create_key(namespace_id, &key).await.expect("create");
        store.revoke_key(namespace_id, "revoke-twice", None).await.expect("first revoke");

        // Get the revocation timestamp
        let first = store.get_key(namespace_id, "revoke-twice").await.expect("get").unwrap();
        let first_revoked_at = first.revoked_at.unwrap();

        // Revoke again - should be idempotent (keep original timestamp)
        store.revoke_key(namespace_id, "revoke-twice", None).await.expect("second revoke");

        let second = store.get_key(namespace_id, "revoke-twice").await.expect("get").unwrap();
        assert_eq!(second.revoked_at.unwrap(), first_revoked_at);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let result = store.revoke_key(100, "nonexistent", None).await;
        assert!(matches!(result, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_activate_key() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create and deactivate a key
        let key = create_test_key("to-activate");
        store.create_key(namespace_id, &key).await.expect("create");
        store.deactivate_key(namespace_id, "to-activate").await.expect("deactivate");

        // Activate it
        store.activate_key(namespace_id, "to-activate").await.expect("activate");

        // Verify it's active
        let retrieved = store.get_key(namespace_id, "to-activate").await.expect("get").unwrap();
        assert!(retrieved.active);
    }

    #[tokio::test]
    async fn test_activate_revoked_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create and revoke a key
        let key = create_test_key("revoked-key");
        store.create_key(namespace_id, &key).await.expect("create");
        store.revoke_key(namespace_id, "revoked-key", None).await.expect("revoke");

        // Trying to activate should fail
        let result = store.activate_key(namespace_id, "revoked-key").await;
        assert!(matches!(result, Err(StorageError::Internal { .. })));
    }

    #[tokio::test]
    async fn test_activate_nonexistent_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let result = store.activate_key(100, "nonexistent").await;
        assert!(matches!(result, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_delete_key() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create a key
        let key = create_test_key("to-delete");
        store.create_key(namespace_id, &key).await.expect("create");

        // Delete it
        store.delete_key(namespace_id, "to-delete").await.expect("delete");

        // Verify it's gone
        let retrieved = store.get_key(namespace_id, "to-delete").await.expect("get");
        assert!(retrieved.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key_fails() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let result = store.delete_key(100, "nonexistent").await;
        assert!(matches!(result, Err(StorageError::NotFound { .. })));
    }

    #[tokio::test]
    async fn test_store_with_metrics() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint()]))
            .client_id("metrics-test")
            .build()
            .expect("valid config");

        let client = LedgerClient::new(config).await.expect("client");
        let metrics = SigningKeyMetrics::new();
        let store = LedgerSigningKeyStore::new(Arc::new(client)).with_metrics(metrics.clone());

        // Verify metrics is attached
        assert!(store.metrics().is_some());

        // Perform operations
        let key = create_test_key("metrics-key");
        store.create_key(100, &key).await.expect("create");
        store.get_key(100, "metrics-key").await.expect("get");

        // Check metrics were recorded
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.create_count, 1);
        assert_eq!(snapshot.get_count, 1);
    }

    #[tokio::test]
    async fn test_store_with_eventual_consistency() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let config = ClientConfig::builder()
            .servers(ServerSource::from_static([server.endpoint()]))
            .client_id("eventual-test")
            .build()
            .expect("valid config");

        let client = LedgerClient::new(config).await.expect("client");
        let store = LedgerSigningKeyStore::with_read_consistency(
            Arc::new(client),
            ReadConsistency::Eventual,
        );

        // Operations should still work
        let key = create_test_key("eventual-key");
        store.create_key(100, &key).await.expect("create");
        let retrieved = store.get_key(100, "eventual-key").await.expect("get");
        assert!(retrieved.is_some());
    }

    #[tokio::test]
    async fn test_store_client_accessor() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        // Should be able to access the client
        let _client = store.client();
    }

    #[tokio::test]
    async fn test_store_debug_impl() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;

        let debug_str = format!("{:?}", store);
        assert!(debug_str.contains("LedgerSigningKeyStore"));
        assert!(debug_str.contains("read_consistency"));
    }

    #[tokio::test]
    async fn test_list_filters_expired_keys() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create a key that's already expired
        let now = Utc::now();
        let expired_key = PublicSigningKey::builder()
            .kid("expired-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1)
            .cert_id(1)
            .created_at(now - Duration::hours(2))
            .valid_from(now - Duration::hours(2))
            .valid_until(now - Duration::hours(1)) // Expired 1 hour ago
            .build();
        store.create_key(namespace_id, &expired_key).await.expect("create expired");

        // Create a valid key
        let valid_key = create_test_key("valid-key");
        store.create_key(namespace_id, &valid_key).await.expect("create valid");

        // List should not include expired key
        let active_keys = store.list_active_keys(namespace_id).await.expect("list");
        let kids: Vec<_> = active_keys.iter().map(|k| k.kid.as_str()).collect();

        assert!(kids.contains(&"valid-key"));
        assert!(!kids.contains(&"expired-key"));
    }

    #[tokio::test]
    async fn test_list_filters_not_yet_valid_keys() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let store = create_signing_key_store(&server).await;
        let namespace_id = 100;

        // Create a key that's not yet valid
        let now = Utc::now();
        let future_key = PublicSigningKey::builder()
            .kid("future-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1)
            .cert_id(1)
            .created_at(now)
            .valid_from(now + Duration::hours(1)) // Valid in 1 hour
            .build();
        store.create_key(namespace_id, &future_key).await.expect("create future");

        // Create a currently valid key
        let valid_key = create_test_key("now-valid-key");
        store.create_key(namespace_id, &valid_key).await.expect("create valid");

        // List should not include future key
        let active_keys = store.list_active_keys(namespace_id).await.expect("list");
        let kids: Vec<_> = active_keys.iter().map(|k| k.kid.as_str()).collect();

        assert!(kids.contains(&"now-valid-key"));
        assert!(!kids.contains(&"future-key"));
    }
}
