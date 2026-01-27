//! Storage trait for public signing key lifecycle operations.
//!
//! This module provides the [`PublicSigningKeyStore`] trait that abstracts
//! persistence operations for public signing keys. Implementations can use
//! different backends (Ledger for production, in-memory for testing).
//!
//! # Key Lifecycle
//!
//! ```text
//! ┌─────────────┐     ┌─────────────┐     ┌─────────────┐
//! │   Created   │────►│   Active    │────►│  Revoked    │
//! │ (valid_from │     │             │     │ (permanent) │
//! │  in future) │     │             │     │             │
//! └─────────────┘     └──────┬──────┘     └─────────────┘
//!                            │
//!                            ▼
//!                     ┌─────────────┐
//!                     │  Inactive   │
//!                     │(reversible) │
//!                     └─────────────┘
//! ```
//!
//! # Usage
//!
//! ```no_run
//! use async_trait::async_trait;
//! use inferadb_common_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
//! use inferadb_common_storage::StorageError;
//!
//! async fn store_key<S: PublicSigningKeyStore>(
//!     store: &S,
//!     namespace_id: i64,
//!     key: &PublicSigningKey,
//! ) -> Result<(), StorageError> {
//!     store.create_key(namespace_id, key).await
//! }
//! ```

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

use crate::auth::PublicSigningKey;
use crate::error::{StorageError, StorageResult};

/// Storage key prefix for signing keys within a namespace.
pub const SIGNING_KEY_PREFIX: &str = "signing-keys/";

/// Storage trait for public signing key lifecycle operations.
///
/// This trait abstracts the persistence layer for public signing keys,
/// allowing different implementations for production (Ledger) and
/// testing (in-memory).
///
/// # Namespace Mapping
///
/// All operations take a `namespace_id` parameter, which corresponds to
/// the organization ID (`namespace_id == org_id`). Keys are stored at
/// `signing-keys/{kid}` within each namespace.
///
/// # Method Naming
///
/// Methods follow the existing `*Store` trait pattern in the codebase
/// (e.g., `VaultStore::create_vault`, `get_vault`).
///
/// # Error Handling
///
/// Operations return [`StorageResult`] with appropriate [`StorageError`]
/// variants. Implementations should provide retry logic for transient
/// failures where appropriate.
#[async_trait]
pub trait PublicSigningKeyStore: Send + Sync {
    /// Stores a new public signing key.
    ///
    /// The key is stored at `signing-keys/{kid}` within the namespace.
    /// If a key with the same `kid` already exists, this operation fails.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID (`namespace_id == org_id`)
    /// * `key` - The public signing key to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - A key with the same `kid` already exists
    /// - The storage backend is unavailable
    /// - Serialization fails
    async fn create_key(&self, namespace_id: i64, key: &PublicSigningKey) -> StorageResult<()>;

    /// Retrieves a public signing key by ID.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `kid` - The key identifier to look up
    ///
    /// # Returns
    ///
    /// - `Ok(Some(key))` if the key exists
    /// - `Ok(None)` if the key doesn't exist
    /// - `Err(...)` on storage errors
    async fn get_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>>;

    /// Lists all active public signing keys for a namespace.
    ///
    /// A key is considered active if:
    /// - `active == true`
    /// - `revoked_at.is_none()`
    /// - `valid_from <= now`
    /// - `valid_until.is_none() || valid_until > now`
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    ///
    /// # Returns
    ///
    /// A vector of active keys (may be empty).
    async fn list_active_keys(&self, namespace_id: i64) -> StorageResult<Vec<PublicSigningKey>>;

    /// Marks a key as inactive (soft revocation).
    ///
    /// Inactive keys are not used for validation but the operation is
    /// reversible. Use [`revoke_key`](Self::revoke_key) for permanent
    /// revocation.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `kid` - The key identifier to deactivate
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the key doesn't exist.
    async fn deactivate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()>;

    /// Marks a key as revoked (hard revocation with timestamp).
    ///
    /// Revocation is permanent—once revoked, a key cannot be reactivated.
    /// The `revoked_at` timestamp is set to the current time.
    ///
    /// This operation is idempotent: revoking an already-revoked key
    /// succeeds without modifying the original `revoked_at` timestamp.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `kid` - The key identifier to revoke
    /// * `reason` - Optional reason for revocation (stored for audit)
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the key doesn't exist.
    async fn revoke_key(
        &self,
        namespace_id: i64,
        kid: &str,
        reason: Option<&str>,
    ) -> StorageResult<()>;

    /// Reactivates a previously deactivated key.
    ///
    /// This only works for keys that were deactivated (soft revocation).
    /// Keys that have been permanently revoked (with `revoked_at` set)
    /// cannot be reactivated.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `kid` - The key identifier to reactivate
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The key doesn't exist ([`StorageError::NotFound`])
    /// - The key has been permanently revoked ([`StorageError::Internal`])
    async fn activate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()>;

    /// Deletes a key from storage.
    ///
    /// This permanently removes the key from the storage backend.
    /// Use with caution—this operation cannot be undone.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `kid` - The key identifier to delete
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::NotFound`] if the key doesn't exist.
    async fn delete_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()>;
}

/// In-memory implementation of [`PublicSigningKeyStore`] for testing.
///
/// This implementation stores keys in a thread-safe hash map, suitable for
/// unit tests and development. It does not persist data between restarts.
///
/// # Thread Safety
///
/// Uses [`parking_lot::RwLock`] for efficient concurrent access with
/// reader-writer semantics.
///
/// # Example
///
/// ```
/// use chrono::Utc;
/// use inferadb_common_storage::auth::{
///     MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore,
/// };
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let store = MemorySigningKeyStore::new();
///     
///     let key = PublicSigningKey::builder()
///         .kid("test-key-1".to_owned())
///         .public_key("MCowBQYDK2VwAyEA...".to_owned())
///         .client_id(1)
///         .cert_id(1)
///         .build();
///     
///     store.create_key(1, &key).await?;
///     
///     let retrieved = store.get_key(1, "test-key-1").await?;
///     assert!(retrieved.is_some());
///     
///     Ok(())
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct MemorySigningKeyStore {
    /// Keys indexed by (namespace_id, kid).
    keys: Arc<RwLock<HashMap<(i64, String), PublicSigningKey>>>,
}

impl MemorySigningKeyStore {
    /// Creates a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a composite key for the hash map.
    fn make_key(namespace_id: i64, kid: &str) -> (i64, String) {
        (namespace_id, kid.to_string())
    }
}

#[async_trait]
impl PublicSigningKeyStore for MemorySigningKeyStore {
    async fn create_key(&self, namespace_id: i64, key: &PublicSigningKey) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, &key.kid);
        let mut keys = self.keys.write();

        if keys.contains_key(&map_key) {
            return Err(StorageError::internal(format!(
                "Key already exists: {}",
                key.kid
            )));
        }

        keys.insert(map_key, key.clone());
        Ok(())
    }

    async fn get_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>> {
        let map_key = Self::make_key(namespace_id, kid);
        let keys = self.keys.read();
        Ok(keys.get(&map_key).cloned())
    }

    async fn list_active_keys(&self, namespace_id: i64) -> StorageResult<Vec<PublicSigningKey>> {
        let keys = self.keys.read();
        let now = Utc::now();

        let active_keys: Vec<PublicSigningKey> = keys
            .iter()
            .filter(|((ns_id, _), _)| *ns_id == namespace_id)
            .map(|(_, key)| key)
            .filter(|key| {
                key.active
                    && key.revoked_at.is_none()
                    && now >= key.valid_from
                    && key.valid_until.is_none_or(|until| now <= until)
            })
            .cloned()
            .collect();

        Ok(active_keys)
    }

    async fn deactivate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys
            .get_mut(&map_key)
            .ok_or_else(|| StorageError::not_found(kid))?;

        key.active = false;
        Ok(())
    }

    async fn revoke_key(
        &self,
        namespace_id: i64,
        kid: &str,
        _reason: Option<&str>,
    ) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys
            .get_mut(&map_key)
            .ok_or_else(|| StorageError::not_found(kid))?;

        // Idempotent: only set revoked_at if not already revoked
        if key.revoked_at.is_none() {
            key.revoked_at = Some(Utc::now());
            key.active = false;
        }
        Ok(())
    }

    async fn activate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys
            .get_mut(&map_key)
            .ok_or_else(|| StorageError::not_found(kid))?;

        if key.revoked_at.is_some() {
            return Err(StorageError::internal(format!(
                "Cannot reactivate permanently revoked key: {}",
                kid
            )));
        }

        key.active = true;
        Ok(())
    }

    async fn delete_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        if keys.remove(&map_key).is_none() {
            return Err(StorageError::not_found(kid));
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use chrono::Duration;

    /// Creates a test key with the given kid.
    fn make_test_key(kid: &str) -> PublicSigningKey {
        PublicSigningKey::builder()
            .kid(kid.to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1)
            .cert_id(1)
            .build()
    }

    /// Creates a test key with specified validity window.
    fn make_test_key_with_validity(
        kid: &str,
        valid_from: chrono::DateTime<Utc>,
        valid_until: Option<chrono::DateTime<Utc>>,
    ) -> PublicSigningKey {
        PublicSigningKey::builder()
            .kid(kid.to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1)
            .cert_id(1)
            .valid_from(valid_from)
            .maybe_valid_until(valid_until)
            .build()
    }

    #[tokio::test]
    async fn test_create_and_get_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("key-1");
        let namespace_id = 100;

        // Create the key
        store
            .create_key(namespace_id, &key)
            .await
            .expect("create_key should succeed");

        // Retrieve it
        let retrieved = store
            .get_key(namespace_id, "key-1")
            .await
            .expect("get_key should succeed");

        assert!(retrieved.is_some());
        let retrieved = retrieved.expect("key should exist");
        assert_eq!(retrieved.kid, "key-1");
        assert!(retrieved.active);
    }

    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.get_key(100, "nonexistent").await;

        assert!(result.is_ok());
        assert!(result.expect("should not error").is_none());
    }

    #[tokio::test]
    async fn test_create_duplicate_key_fails() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("dup-key");
        let namespace_id = 100;

        store
            .create_key(namespace_id, &key)
            .await
            .expect("first create should succeed");

        let result = store.create_key(namespace_id, &key).await;

        assert!(result.is_err());
        let err = result.expect_err("duplicate should fail");
        assert!(matches!(err, StorageError::Internal { .. }));
    }

    #[tokio::test]
    async fn test_same_kid_different_namespaces() {
        let store = MemorySigningKeyStore::new();
        let key1 = make_test_key("shared-kid");
        let key2 = make_test_key("shared-kid");

        // Same kid in different namespaces should work
        store
            .create_key(100, &key1)
            .await
            .expect("create in ns 100");
        store
            .create_key(200, &key2)
            .await
            .expect("create in ns 200");

        let r1 = store.get_key(100, "shared-kid").await.expect("get ns 100");
        let r2 = store.get_key(200, "shared-kid").await.expect("get ns 200");

        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[tokio::test]
    async fn test_list_active_keys() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = 100;

        // Create several keys with different states
        let active_key = make_test_key("active");
        let inactive_key = {
            let mut k = make_test_key("inactive");
            k.active = false;
            k
        };
        let future_key =
            make_test_key_with_validity("future", Utc::now() + Duration::hours(1), None);
        let expired_key = make_test_key_with_validity(
            "expired",
            Utc::now() - Duration::hours(2),
            Some(Utc::now() - Duration::hours(1)),
        );

        store
            .create_key(namespace_id, &active_key)
            .await
            .expect("create active");
        store
            .create_key(namespace_id, &inactive_key)
            .await
            .expect("create inactive");
        store
            .create_key(namespace_id, &future_key)
            .await
            .expect("create future");
        store
            .create_key(namespace_id, &expired_key)
            .await
            .expect("create expired");

        // Only the active key should be listed
        let active_keys = store
            .list_active_keys(namespace_id)
            .await
            .expect("list_active_keys");

        assert_eq!(active_keys.len(), 1);
        assert_eq!(active_keys[0].kid, "active");
    }

    #[tokio::test]
    async fn test_list_active_keys_empty_namespace() {
        let store = MemorySigningKeyStore::new();

        let result = store.list_active_keys(999).await;

        assert!(result.is_ok());
        assert!(result.expect("should return empty vec").is_empty());
    }

    #[tokio::test]
    async fn test_deactivate_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-deactivate");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");

        store
            .deactivate_key(namespace_id, "to-deactivate")
            .await
            .expect("deactivate");

        let retrieved = store
            .get_key(namespace_id, "to-deactivate")
            .await
            .expect("get");
        assert!(!retrieved.expect("exists").active);
    }

    #[tokio::test]
    async fn test_deactivate_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.deactivate_key(100, "nonexistent").await;

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("should be NotFound"),
            StorageError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-revoke");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");

        store
            .revoke_key(namespace_id, "to-revoke", Some("compromised"))
            .await
            .expect("revoke");

        let retrieved = store.get_key(namespace_id, "to-revoke").await.expect("get");
        let retrieved = retrieved.expect("exists");

        assert!(!retrieved.active);
        assert!(retrieved.revoked_at.is_some());
    }

    #[tokio::test]
    async fn test_revoke_key_idempotent() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("revoke-twice");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");

        store
            .revoke_key(namespace_id, "revoke-twice", None)
            .await
            .expect("first revoke");

        // Get the timestamp from first revocation
        let first = store
            .get_key(namespace_id, "revoke-twice")
            .await
            .expect("get");
        let first_revoked_at = first.expect("exists").revoked_at;

        // Second revocation should succeed and not change timestamp
        store
            .revoke_key(namespace_id, "revoke-twice", None)
            .await
            .expect("second revoke");

        let second = store
            .get_key(namespace_id, "revoke-twice")
            .await
            .expect("get");
        let second_revoked_at = second.expect("exists").revoked_at;

        assert_eq!(first_revoked_at, second_revoked_at);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.revoke_key(100, "nonexistent", None).await;

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("should be NotFound"),
            StorageError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_activate_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-reactivate");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");
        store
            .deactivate_key(namespace_id, "to-reactivate")
            .await
            .expect("deactivate");

        // Verify it's inactive
        let inactive = store
            .get_key(namespace_id, "to-reactivate")
            .await
            .expect("get");
        assert!(!inactive.expect("exists").active);

        // Reactivate
        store
            .activate_key(namespace_id, "to-reactivate")
            .await
            .expect("activate");

        let reactivated = store
            .get_key(namespace_id, "to-reactivate")
            .await
            .expect("get");
        assert!(reactivated.expect("exists").active);
    }

    #[tokio::test]
    async fn test_activate_revoked_key_fails() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("permanently-revoked");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");
        store
            .revoke_key(namespace_id, "permanently-revoked", None)
            .await
            .expect("revoke");

        let result = store
            .activate_key(namespace_id, "permanently-revoked")
            .await;

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("should be Internal"),
            StorageError::Internal { .. }
        ));
    }

    #[tokio::test]
    async fn test_delete_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-delete");
        let namespace_id = 100;

        store.create_key(namespace_id, &key).await.expect("create");

        store
            .delete_key(namespace_id, "to-delete")
            .await
            .expect("delete");

        let result = store.get_key(namespace_id, "to-delete").await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.delete_key(100, "nonexistent").await;

        assert!(result.is_err());
        assert!(matches!(
            result.expect_err("should be NotFound"),
            StorageError::NotFound { .. }
        ));
    }

    #[tokio::test]
    async fn test_clone_store_shares_state() {
        let store = MemorySigningKeyStore::new();
        let cloned = store.clone();
        let key = make_test_key("shared");

        store
            .create_key(100, &key)
            .await
            .expect("create via original");

        let result = cloned.get_key(100, "shared").await.expect("get via clone");

        assert!(result.is_some());
    }
}
