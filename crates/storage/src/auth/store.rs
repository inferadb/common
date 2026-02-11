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
//! // Demonstrates the trait interface; requires a concrete store implementation.
//! use async_trait::async_trait;
//! use inferadb_common_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
//! use inferadb_common_storage::{NamespaceId, StorageError};
//!
//! async fn store_key<S: PublicSigningKeyStore>(
//!     store: &S,
//!     namespace_id: NamespaceId,
//!     key: &PublicSigningKey,
//! ) -> Result<(), StorageError> {
//!     store.create_key(namespace_id, key).await
//! }
//! ```

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;
use chrono::Utc;
use parking_lot::RwLock;

use crate::{
    auth::PublicSigningKey,
    error::{StorageError, StorageResult},
    types::NamespaceId,
};

/// Storage key prefix for signing keys within a namespace.
pub const SIGNING_KEY_PREFIX: &str = "signing-keys/";

/// Persistence layer for public signing key lifecycle operations.
///
/// Abstracts key storage so production (Ledger) and testing (in-memory)
/// can share the same interface.
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
    async fn create_key(
        &self,
        namespace_id: NamespaceId,
        key: &PublicSigningKey,
    ) -> StorageResult<()>;

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
        namespace_id: NamespaceId,
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
    async fn list_active_keys(
        &self,
        namespace_id: NamespaceId,
    ) -> StorageResult<Vec<PublicSigningKey>>;

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
    async fn deactivate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()>;

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
        namespace_id: NamespaceId,
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
    async fn activate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()>;

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
    async fn delete_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()>;

    /// Stores multiple public signing keys in bulk.
    ///
    /// Returns a `Vec<StorageResult<()>>` with one result per input key,
    /// in the same order as the input.
    ///
    /// The default implementation calls [`create_key`](Self::create_key)
    /// sequentially. Implementations may override this for efficiency
    /// (e.g., single lock acquisition for in-memory, batched writes for
    /// ledger backends).
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `keys` - The keys to store
    async fn create_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[PublicSigningKey],
    ) -> Vec<StorageResult<()>> {
        let mut results = Vec::with_capacity(keys.len());
        for key in keys {
            results.push(self.create_key(namespace_id, key).await);
        }
        results
    }

    /// Revokes multiple keys in bulk.
    ///
    /// Each entry is a `(kid, optional_reason)` pair. Returns a
    /// `Vec<StorageResult<()>>` with one result per input, in the
    /// same order.
    ///
    /// The default implementation calls [`revoke_key`](Self::revoke_key)
    /// sequentially. Implementations may override this for efficiency.
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `keys` - Pairs of `(kid, optional_reason)` to revoke
    async fn revoke_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[(&str, Option<&str>)],
    ) -> Vec<StorageResult<()>> {
        let mut results = Vec::with_capacity(keys.len());
        for &(kid, reason) in keys {
            results.push(self.revoke_key(namespace_id, kid, reason).await);
        }
        results
    }

    /// Atomically rotates a signing key: revokes the old key and stores
    /// the new key as a single logical operation.
    ///
    /// Either both the revocation and the creation succeed, or neither
    /// takes effect. This is the recommended way to perform key rotation
    /// because it prevents windows where neither old nor new key is valid.
    ///
    /// The default implementation performs the two operations sequentially
    /// and attempts to roll back on failure. Implementations may override
    /// this with a truly atomic mechanism (e.g., a single transaction).
    ///
    /// # Arguments
    ///
    /// * `namespace_id` - Organization namespace ID
    /// * `old_kid` - The key identifier to revoke
    /// * `new_key` - The new key to store
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - The old key doesn't exist ([`StorageError::NotFound`])
    /// - The new key's `kid` already exists
    /// - The storage backend is unavailable
    async fn rotate_key(
        &self,
        namespace_id: NamespaceId,
        old_kid: &str,
        new_key: &PublicSigningKey,
    ) -> StorageResult<()> {
        // Store the new key first — if this fails, nothing has changed
        self.create_key(namespace_id, new_key).await?;

        // Revoke the old key — if this fails, roll back the new key
        if let Err(e) = self.revoke_key(namespace_id, old_kid, Some("key rotation")).await {
            // Best-effort rollback: delete the newly created key
            let _rollback = self.delete_key(namespace_id, &new_key.kid).await;
            return Err(e);
        }

        Ok(())
    }
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
/// # Examples
///
/// ```
/// use chrono::Utc;
/// use inferadb_common_storage::auth::{
///     MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore,
/// };
/// use inferadb_common_storage::NamespaceId;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let store = MemorySigningKeyStore::new();
///     let ns = NamespaceId::from(1);
///     
///     let key = PublicSigningKey::builder()
///         .kid("test-key-1")
///         .public_key("MCowBQYDK2VwAyEA...".to_owned())
///         .client_id(1)
///         .cert_id(1)
///         .build();
///     
///     store.create_key(ns, &key).await?;
///     
///     let retrieved = store.get_key(ns, "test-key-1").await?;
///     assert!(retrieved.is_some());
///     
///     Ok(())
/// }
/// ```
#[derive(Debug, Default, Clone)]
pub struct MemorySigningKeyStore {
    /// Keys indexed by (namespace_id, kid).
    keys: Arc<RwLock<HashMap<(NamespaceId, String), PublicSigningKey>>>,
}

impl MemorySigningKeyStore {
    /// Creates a new empty in-memory store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Creates a composite key for the hash map.
    fn make_key(namespace_id: NamespaceId, kid: &str) -> (NamespaceId, String) {
        (namespace_id, kid.to_string())
    }
}

#[async_trait]
impl PublicSigningKeyStore for MemorySigningKeyStore {
    #[tracing::instrument(skip(self, key), fields(kid = %key.kid))]
    async fn create_key(
        &self,
        namespace_id: NamespaceId,
        key: &PublicSigningKey,
    ) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, &key.kid);
        let mut keys = self.keys.write();

        if keys.contains_key(&map_key) {
            return Err(StorageError::internal(format!("Key already exists: {}", key.kid)));
        }

        keys.insert(map_key, key.clone());
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn get_key(
        &self,
        namespace_id: NamespaceId,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>> {
        let map_key = Self::make_key(namespace_id, kid);
        let keys = self.keys.read();
        Ok(keys.get(&map_key).cloned())
    }

    #[tracing::instrument(skip(self))]
    async fn list_active_keys(
        &self,
        namespace_id: NamespaceId,
    ) -> StorageResult<Vec<PublicSigningKey>> {
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

    #[tracing::instrument(skip(self))]
    async fn deactivate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys.get_mut(&map_key).ok_or_else(|| StorageError::not_found(kid))?;

        key.active = false;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn revoke_key(
        &self,
        namespace_id: NamespaceId,
        kid: &str,
        reason: Option<&str>,
    ) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys.get_mut(&map_key).ok_or_else(|| StorageError::not_found(kid))?;

        // Idempotent: only set revoked_at if not already revoked
        if key.revoked_at.is_none() {
            key.revoked_at = Some(Utc::now());
            key.active = false;
            key.revocation_reason = reason.map(String::from);
        }
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn activate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        let key = keys.get_mut(&map_key).ok_or_else(|| StorageError::not_found(kid))?;

        if key.revoked_at.is_some() {
            return Err(StorageError::internal(format!(
                "Cannot reactivate permanently revoked key: {}",
                kid
            )));
        }

        key.active = true;
        Ok(())
    }

    #[tracing::instrument(skip(self))]
    async fn delete_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let map_key = Self::make_key(namespace_id, kid);
        let mut keys = self.keys.write();

        if keys.remove(&map_key).is_none() {
            return Err(StorageError::not_found(kid));
        }
        Ok(())
    }

    /// Optimized bulk create: single write-lock acquisition for all keys.
    #[tracing::instrument(skip(self, keys), fields(count = keys.len()))]
    async fn create_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[PublicSigningKey],
    ) -> Vec<StorageResult<()>> {
        let mut store_keys = self.keys.write();
        let mut results = Vec::with_capacity(keys.len());

        for key in keys {
            let map_key = Self::make_key(namespace_id, &key.kid);
            match store_keys.entry(map_key) {
                std::collections::hash_map::Entry::Occupied(_) => {
                    results.push(Err(StorageError::internal(format!(
                        "Key already exists: {}",
                        key.kid
                    ))));
                },
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(key.clone());
                    results.push(Ok(()));
                },
            }
        }

        results
    }

    /// Optimized bulk revoke: single write-lock acquisition for all keys.
    #[tracing::instrument(skip(self, keys), fields(count = keys.len()))]
    async fn revoke_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[(&str, Option<&str>)],
    ) -> Vec<StorageResult<()>> {
        let mut store_keys = self.keys.write();
        let mut results = Vec::with_capacity(keys.len());

        for &(kid, reason) in keys {
            let map_key = Self::make_key(namespace_id, kid);
            match store_keys.get_mut(&map_key) {
                Some(key) => {
                    if key.revoked_at.is_none() {
                        key.revoked_at = Some(Utc::now());
                        key.active = false;
                        key.revocation_reason = reason.map(String::from);
                    }
                    results.push(Ok(()));
                },
                None => results.push(Err(StorageError::not_found(kid))),
            }
        }

        results
    }

    /// Atomic rotate: both revoke and create happen under a single lock.
    #[tracing::instrument(skip(self, new_key))]
    async fn rotate_key(
        &self,
        namespace_id: NamespaceId,
        old_kid: &str,
        new_key: &PublicSigningKey,
    ) -> StorageResult<()> {
        let mut store_keys = self.keys.write();

        let old_map_key = Self::make_key(namespace_id, old_kid);
        let new_map_key = Self::make_key(namespace_id, &new_key.kid);

        // Validate both preconditions before mutating
        if !store_keys.contains_key(&old_map_key) {
            return Err(StorageError::not_found(old_kid));
        }
        if store_keys.contains_key(&new_map_key) {
            return Err(StorageError::internal(format!("Key already exists: {}", new_key.kid)));
        }

        // Revoke old key (idempotent)
        if let Some(old_entry) = store_keys.get_mut(&old_map_key)
            && old_entry.revoked_at.is_none()
        {
            old_entry.revoked_at = Some(Utc::now());
            old_entry.active = false;
            old_entry.revocation_reason = Some("key rotation".to_string());
        }

        // Store new key
        store_keys.insert(new_map_key, new_key.clone());

        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Duration;

    use super::*;
    use crate::assert_storage_error;

    /// Creates a test key with the given kid.
    fn make_test_key(kid: &str) -> PublicSigningKey {
        PublicSigningKey::builder()
            .kid(kid)
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
            .kid(kid)
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
        let namespace_id = NamespaceId::from(100);

        // Create the key
        store.create_key(namespace_id, &key).await.expect("create_key should succeed");

        // Retrieve it
        let retrieved = store.get_key(namespace_id, "key-1").await.expect("get_key should succeed");

        assert!(retrieved.is_some());
        let retrieved = retrieved.expect("key should exist");
        assert_eq!(retrieved.kid, "key-1");
        assert!(retrieved.active);
    }

    #[tokio::test]
    async fn test_get_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.get_key(NamespaceId::from(100), "nonexistent").await;

        assert!(result.is_ok());
        assert!(result.expect("should not error").is_none());
    }

    #[tokio::test]
    async fn test_create_duplicate_key_fails() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("dup-key");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("first create should succeed");

        let result = store.create_key(namespace_id, &key).await;

        assert_storage_error!(result, Internal);
    }

    #[tokio::test]
    async fn test_same_kid_different_namespaces() {
        let store = MemorySigningKeyStore::new();
        let key1 = make_test_key("shared-kid");
        let key2 = make_test_key("shared-kid");

        // Same kid in different namespaces should work
        store.create_key(NamespaceId::from(100), &key1).await.expect("create in ns 100");
        store.create_key(NamespaceId::from(200), &key2).await.expect("create in ns 200");

        let r1 = store.get_key(NamespaceId::from(100), "shared-kid").await.expect("get ns 100");
        let r2 = store.get_key(NamespaceId::from(200), "shared-kid").await.expect("get ns 200");

        assert!(r1.is_some());
        assert!(r2.is_some());
    }

    #[tokio::test]
    async fn test_list_active_keys() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

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

        store.create_key(namespace_id, &active_key).await.expect("create active");
        store.create_key(namespace_id, &inactive_key).await.expect("create inactive");
        store.create_key(namespace_id, &future_key).await.expect("create future");
        store.create_key(namespace_id, &expired_key).await.expect("create expired");

        // Only the active key should be listed
        let active_keys = store.list_active_keys(namespace_id).await.expect("list_active_keys");

        assert_eq!(active_keys.len(), 1);
        assert_eq!(active_keys[0].kid, "active");
    }

    #[tokio::test]
    async fn test_list_active_keys_empty_namespace() {
        let store = MemorySigningKeyStore::new();

        let result = store.list_active_keys(NamespaceId::from(999)).await;

        assert!(result.is_ok());
        assert!(result.expect("should return empty vec").is_empty());
    }

    #[tokio::test]
    async fn test_deactivate_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-deactivate");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.deactivate_key(namespace_id, "to-deactivate").await.expect("deactivate");

        let retrieved = store.get_key(namespace_id, "to-deactivate").await.expect("get");
        assert!(!retrieved.expect("exists").active);
    }

    #[tokio::test]
    async fn test_deactivate_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.deactivate_key(NamespaceId::from(100), "nonexistent").await;

        assert_storage_error!(result, NotFound);
    }

    #[tokio::test]
    async fn test_revoke_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-revoke");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.revoke_key(namespace_id, "to-revoke", Some("compromised")).await.expect("revoke");

        let retrieved = store.get_key(namespace_id, "to-revoke").await.expect("get");
        let retrieved = retrieved.expect("exists");

        assert!(!retrieved.active);
        assert!(retrieved.revoked_at.is_some());
        assert_eq!(retrieved.revocation_reason.as_deref(), Some("compromised"));
    }

    #[tokio::test]
    async fn test_revoke_key_idempotent() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("revoke-twice");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.revoke_key(namespace_id, "revoke-twice", None).await.expect("first revoke");

        // Get the timestamp from first revocation
        let first = store.get_key(namespace_id, "revoke-twice").await.expect("get");
        let first_revoked_at = first.expect("exists").revoked_at;

        // Second revocation should succeed and not change timestamp
        store.revoke_key(namespace_id, "revoke-twice", None).await.expect("second revoke");

        let second = store.get_key(namespace_id, "revoke-twice").await.expect("get");
        let second_revoked_at = second.expect("exists").revoked_at;

        assert_eq!(first_revoked_at, second_revoked_at);
    }

    #[tokio::test]
    async fn test_revoke_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.revoke_key(NamespaceId::from(100), "nonexistent", None).await;

        assert_storage_error!(result, NotFound);
    }

    #[tokio::test]
    async fn test_activate_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-reactivate");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");
        store.deactivate_key(namespace_id, "to-reactivate").await.expect("deactivate");

        // Verify it's inactive
        let inactive = store.get_key(namespace_id, "to-reactivate").await.expect("get");
        assert!(!inactive.expect("exists").active);

        // Reactivate
        store.activate_key(namespace_id, "to-reactivate").await.expect("activate");

        let reactivated = store.get_key(namespace_id, "to-reactivate").await.expect("get");
        assert!(reactivated.expect("exists").active);
    }

    #[tokio::test]
    async fn test_activate_revoked_key_fails() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("permanently-revoked");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");
        store.revoke_key(namespace_id, "permanently-revoked", None).await.expect("revoke");

        let result = store.activate_key(namespace_id, "permanently-revoked").await;

        assert_storage_error!(result, Internal);
    }

    #[tokio::test]
    async fn test_delete_key() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("to-delete");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.delete_key(namespace_id, "to-delete").await.expect("delete");

        let result = store.get_key(namespace_id, "to-delete").await.expect("get");
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_delete_nonexistent_key() {
        let store = MemorySigningKeyStore::new();

        let result = store.delete_key(NamespaceId::from(100), "nonexistent").await;

        assert_storage_error!(result, NotFound);
    }

    #[tokio::test]
    async fn test_activate_nonexistent_key_fails() {
        let store = MemorySigningKeyStore::new();

        let result = store.activate_key(NamespaceId::from(100), "nonexistent").await;

        assert_storage_error!(result, NotFound);
    }

    #[tokio::test]
    async fn test_clone_store_shares_state() {
        let store = MemorySigningKeyStore::new();
        let cloned = store.clone();
        let key = make_test_key("shared");

        store.create_key(NamespaceId::from(100), &key).await.expect("create via original");

        let result = cloned.get_key(NamespaceId::from(100), "shared").await.expect("get via clone");

        assert!(result.is_some());
    }

    #[tokio::test]
    async fn test_revoke_key_stores_reason() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("reason-test");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.revoke_key(namespace_id, "reason-test", Some("compromised")).await.expect("revoke");

        let retrieved = store.get_key(namespace_id, "reason-test").await.expect("get");
        let retrieved = retrieved.expect("exists");

        assert!(!retrieved.active);
        assert!(retrieved.revoked_at.is_some());
        assert_eq!(retrieved.revocation_reason.as_deref(), Some("compromised"));
    }

    #[tokio::test]
    async fn test_revoke_key_without_reason() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("no-reason");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        store.revoke_key(namespace_id, "no-reason", None).await.expect("revoke");

        let retrieved = store.get_key(namespace_id, "no-reason").await.expect("get");
        let retrieved = retrieved.expect("exists");

        assert!(!retrieved.active);
        assert!(retrieved.revoked_at.is_some());
        assert!(retrieved.revocation_reason.is_none());
    }

    #[tokio::test]
    async fn test_revoke_key_idempotent_preserves_reason() {
        let store = MemorySigningKeyStore::new();
        let key = make_test_key("idempotent-reason");
        let namespace_id = NamespaceId::from(100);

        store.create_key(namespace_id, &key).await.expect("create");

        // First revocation with a reason
        store
            .revoke_key(namespace_id, "idempotent-reason", Some("compromised"))
            .await
            .expect("first revoke");

        let first = store.get_key(namespace_id, "idempotent-reason").await.expect("get");
        let first = first.expect("exists");
        assert_eq!(first.revocation_reason.as_deref(), Some("compromised"));

        // Second revocation with a different reason — original should be preserved
        store
            .revoke_key(namespace_id, "idempotent-reason", Some("different reason"))
            .await
            .expect("second revoke");

        let second = store.get_key(namespace_id, "idempotent-reason").await.expect("get");
        let second = second.expect("exists");
        assert_eq!(second.revocation_reason.as_deref(), Some("compromised"));
    }

    // ── Bulk operation tests ────────────────────────────────────────

    #[tokio::test]
    async fn test_create_keys_bulk() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let keys: Vec<PublicSigningKey> =
            (0..10).map(|i| make_test_key(&format!("bulk-{i}"))).collect();

        let results = store.create_keys(namespace_id, &keys).await;

        assert_eq!(results.len(), 10);
        for result in &results {
            assert!(result.is_ok());
        }

        // Verify all keys are retrievable
        for i in 0..10 {
            let key = store.get_key(namespace_id, &format!("bulk-{i}")).await.expect("get");
            assert!(key.is_some());
        }
    }

    #[tokio::test]
    async fn test_create_keys_bulk_with_duplicate() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        // Pre-create one key
        let existing = make_test_key("bulk-dup-2");
        store.create_key(namespace_id, &existing).await.expect("pre-create");

        let keys: Vec<PublicSigningKey> =
            (0..5).map(|i| make_test_key(&format!("bulk-dup-{i}"))).collect();

        let results = store.create_keys(namespace_id, &keys).await;

        assert_eq!(results.len(), 5);
        // Index 2 should fail (already exists)
        assert!(results[0].is_ok());
        assert!(results[1].is_ok());
        assert!(results[2].is_err());
        assert!(results[3].is_ok());
        assert!(results[4].is_ok());
    }

    #[tokio::test]
    async fn test_create_keys_empty() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let results = store.create_keys(namespace_id, &[]).await;
        assert!(results.is_empty());
    }

    #[tokio::test]
    async fn test_revoke_keys_bulk() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        // Create 10 keys
        for i in 0..10 {
            let key = make_test_key(&format!("revoke-bulk-{i}"));
            store.create_key(namespace_id, &key).await.expect("create");
        }

        let keys_to_revoke: Vec<(&str, Option<&str>)> = vec![
            ("revoke-bulk-0", Some("rotation")),
            ("revoke-bulk-3", None),
            ("revoke-bulk-7", Some("compromised")),
        ];

        let results = store.revoke_keys(namespace_id, &keys_to_revoke).await;

        assert_eq!(results.len(), 3);
        for result in &results {
            assert!(result.is_ok());
        }

        // Verify revocations took effect
        let k0 = store.get_key(namespace_id, "revoke-bulk-0").await.expect("get").expect("exists");
        assert!(k0.revoked_at.is_some());
        assert_eq!(k0.revocation_reason.as_deref(), Some("rotation"));

        let k3 = store.get_key(namespace_id, "revoke-bulk-3").await.expect("get").expect("exists");
        assert!(k3.revoked_at.is_some());
        assert!(k3.revocation_reason.is_none());

        // Non-revoked key should still be active
        let k5 = store.get_key(namespace_id, "revoke-bulk-5").await.expect("get").expect("exists");
        assert!(k5.active);
        assert!(k5.revoked_at.is_none());
    }

    #[tokio::test]
    async fn test_revoke_keys_with_missing() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let key = make_test_key("exists");
        store.create_key(namespace_id, &key).await.expect("create");

        let keys_to_revoke: Vec<(&str, Option<&str>)> =
            vec![("exists", None), ("does-not-exist", None)];

        let mut results = store.revoke_keys(namespace_id, &keys_to_revoke).await;

        assert_eq!(results.len(), 2);
        assert!(results[0].is_ok());
        assert_storage_error!(results.remove(1), NotFound);
    }

    #[tokio::test]
    async fn test_rotate_key_success() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let old_key = make_test_key("old-key");
        store.create_key(namespace_id, &old_key).await.expect("create old");

        let new_key = make_test_key("new-key");
        store.rotate_key(namespace_id, "old-key", &new_key).await.expect("rotate");

        // Old key should be revoked
        let old =
            store.get_key(namespace_id, "old-key").await.expect("get old").expect("old exists");
        assert!(!old.active);
        assert!(old.revoked_at.is_some());
        assert_eq!(old.revocation_reason.as_deref(), Some("key rotation"));

        // New key should be active
        let new =
            store.get_key(namespace_id, "new-key").await.expect("get new").expect("new exists");
        assert!(new.active);
        assert!(new.revoked_at.is_none());
    }

    #[tokio::test]
    async fn test_rotate_key_old_not_found() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let new_key = make_test_key("new-key");
        let result = store.rotate_key(namespace_id, "nonexistent", &new_key).await;

        assert_storage_error!(result, NotFound);

        // New key should not have been created
        let check = store.get_key(namespace_id, "new-key").await.expect("get");
        assert!(check.is_none());
    }

    #[tokio::test]
    async fn test_rotate_key_new_already_exists() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        let old_key = make_test_key("old-key");
        let conflicting_new = make_test_key("conflicting");
        store.create_key(namespace_id, &old_key).await.expect("create old");
        store.create_key(namespace_id, &conflicting_new).await.expect("create conflict");

        let new_key = make_test_key("conflicting");
        let result = store.rotate_key(namespace_id, "old-key", &new_key).await;

        assert!(result.is_err());

        // Old key should NOT have been revoked (atomic rollback)
        let old =
            store.get_key(namespace_id, "old-key").await.expect("get old").expect("old exists");
        assert!(old.active);
        assert!(old.revoked_at.is_none());
    }

    #[tokio::test]
    async fn test_rotate_key_atomicity_on_failure() {
        let store = MemorySigningKeyStore::new();
        let namespace_id = NamespaceId::from(100);

        // Do not create old key — rotate should fail at the old-key-not-found step
        let new_key = make_test_key("new-key-atomic");
        let result = store.rotate_key(namespace_id, "missing-old", &new_key).await;

        assert!(result.is_err());

        // Neither old (doesn't exist) nor new key should exist
        let check = store.get_key(namespace_id, "new-key-atomic").await.expect("get");
        assert!(check.is_none());
    }
}
