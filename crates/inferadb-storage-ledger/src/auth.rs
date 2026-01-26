//! Ledger-backed implementation of public signing key storage.
//!
//! This module provides [`LedgerSigningKeyStore`], which implements the
//! [`PublicSigningKeyStore`] trait using the InferaDB Ledger as the backing
//! store.
//!
//! # Architecture
//!
//! The Ledger stores public signing keys directly in the organization's
//! namespace using the key format `signing-keys/{kid}`. This allows Engine
//! to validate tokens without requiring connectivity to Control.
//!
//! ```text
//! ┌─────────────┐       ┌─────────────────────┐       ┌─────────────┐
//! │   Control   │       │       Ledger        │       │   Engine    │
//! │             │──────►│                     │◄──────│             │
//! │ writes keys │       │  signing-keys/{kid} │       │ reads keys  │
//! └─────────────┘       └─────────────────────┘       └─────────────┘
//! ```
//!
//! # Namespace Mapping
//!
//! Keys are stored at the namespace level (no vault required), where
//! `namespace_id == org_id`. Each organization has its own isolated
//! namespace for signing keys.
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use chrono::Utc;
//! use inferadb_ledger_sdk::LedgerClient;
//! use inferadb_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
//! use inferadb_storage_ledger::auth::LedgerSigningKeyStore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Assume we have a configured LedgerClient
//! # let client: Arc<LedgerClient> = todo!();
//! let store = LedgerSigningKeyStore::new(client);
//!
//! let key = PublicSigningKey::builder()
//!     .kid("key-2024-001".to_owned())
//!     .public_key("MCowBQYDK2VwAyEA...".to_owned())
//!     .client_id(1001)
//!     .cert_id(42)
//!     .build();
//!
//! // Store the key in the org's namespace
//! store.create_key(100, &key).await?;
//!
//! // Retrieve it later
//! let retrieved = store.get_key(100, "key-2024-001").await?;
//! assert!(retrieved.is_some());
//! # Ok(())
//! # }
//! ```

use std::sync::Arc;
use std::time::Instant;

use async_trait::async_trait;
use chrono::Utc;
use inferadb_ledger_sdk::{LedgerClient, ListEntitiesOpts, Operation, ReadConsistency};
use inferadb_storage::{
    StorageError, StorageResult,
    auth::{
        PublicSigningKey, PublicSigningKeyStore, SIGNING_KEY_PREFIX, SigningKeyErrorKind,
        SigningKeyMetrics,
    },
};
use tonic::Code;

use crate::LedgerStorageError;

/// Ledger-backed implementation of [`PublicSigningKeyStore`].
///
/// This implementation stores public signing keys in the InferaDB Ledger,
/// providing a durable, cryptographically verifiable storage layer for
/// JWT validation.
///
/// # Thread Safety
///
/// `LedgerSigningKeyStore` is `Send + Sync` and can be safely shared across
/// threads. The underlying SDK client manages connection pooling internally.
///
/// # Read Consistency
///
/// By default, this implementation uses linearizable (strong) consistency
/// for reads to ensure Engine always sees the latest key state. This can
/// be configured via [`LedgerSigningKeyStore::with_read_consistency`].
///
/// # Metrics
///
/// Optionally collects operation metrics when configured via
/// [`LedgerSigningKeyStore::with_metrics`]. Metrics include operation counts,
/// latencies, and error rates.
///
/// # Error Handling
///
/// Operations convert Ledger SDK errors to [`StorageError`] variants:
/// - Connection failures → `StorageError::Connection`
/// - Key not found → `StorageError::NotFound`
/// - Duplicate key → `StorageError::Conflict`
/// - Serialization issues → `StorageError::Serialization`
#[derive(Clone)]
pub struct LedgerSigningKeyStore {
    client: Arc<LedgerClient>,
    read_consistency: ReadConsistency,
    metrics: Option<SigningKeyMetrics>,
}

impl std::fmt::Debug for LedgerSigningKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigningKeyStore")
            .field("read_consistency", &self.read_consistency)
            .finish_non_exhaustive()
    }
}

impl LedgerSigningKeyStore {
    /// Creates a new Ledger-backed signing key store.
    ///
    /// The store uses linearizable consistency by default to ensure
    /// Engine always sees the latest key state.
    #[must_use]
    pub fn new(client: Arc<LedgerClient>) -> Self {
        Self {
            client,
            read_consistency: ReadConsistency::Linearizable,
            metrics: None,
        }
    }

    /// Creates a store with the specified read consistency level.
    ///
    /// Use `ReadConsistency::Eventual` for read-heavy workloads where
    /// slight staleness is acceptable. Note that eventual consistency
    /// may delay key revocation propagation.
    #[must_use]
    pub fn with_read_consistency(client: Arc<LedgerClient>, consistency: ReadConsistency) -> Self {
        Self {
            client,
            read_consistency: consistency,
            metrics: None,
        }
    }

    /// Enables metrics collection for this store.
    ///
    /// The provided [`SigningKeyMetrics`] will record operation counts,
    /// latencies, and error rates. Metrics are thread-safe and can be
    /// shared across multiple store instances.
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use inferadb_ledger_sdk::LedgerClient;
    /// use inferadb_storage::auth::SigningKeyMetrics;
    /// use inferadb_storage_ledger::auth::LedgerSigningKeyStore;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client: Arc<LedgerClient> = todo!();
    /// let metrics = SigningKeyMetrics::new();
    /// let store = LedgerSigningKeyStore::new(client).with_metrics(metrics.clone());
    ///
    /// // Use store... metrics are automatically recorded
    /// # Ok(())
    /// # }
    /// ```
    #[must_use]
    pub fn with_metrics(mut self, metrics: SigningKeyMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Returns the metrics collector if configured.
    #[must_use]
    pub fn metrics(&self) -> Option<&SigningKeyMetrics> {
        self.metrics.as_ref()
    }

    /// Returns the underlying Ledger client.
    #[must_use]
    pub fn client(&self) -> &LedgerClient {
        &self.client
    }

    /// Constructs the storage key for a signing key.
    ///
    /// Keys are stored at `signing-keys/{kid}` within the namespace.
    fn storage_key(kid: &str) -> String {
        format!("{SIGNING_KEY_PREFIX}{kid}")
    }

    /// Reads a key from Ledger with the configured consistency.
    async fn do_read(
        &self,
        namespace_id: i64,
        key: &str,
    ) -> Result<Option<Vec<u8>>, LedgerStorageError> {
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => {
                self.client.read_consistent(namespace_id, None, key).await
            }
            ReadConsistency::Eventual => self.client.read(namespace_id, None, key).await,
        };

        result.map_err(LedgerStorageError::Sdk)
    }

    /// Deserializes a key from stored bytes.
    fn deserialize_key(bytes: &[u8]) -> StorageResult<PublicSigningKey> {
        serde_json::from_slice(bytes).map_err(|e| StorageError::serialization(e.to_string()))
    }

    /// Serializes a key to bytes for storage.
    fn serialize_key(key: &PublicSigningKey) -> StorageResult<Vec<u8>> {
        serde_json::to_vec(key).map_err(|e| StorageError::serialization(e.to_string()))
    }

    /// Records an error to metrics if configured.
    fn record_error(&self, kind: SigningKeyErrorKind) {
        if let Some(metrics) = &self.metrics {
            metrics.record_error(kind);
        }
    }

    /// Converts a storage error to a metrics error kind.
    fn error_to_kind(error: &StorageError) -> SigningKeyErrorKind {
        match error {
            StorageError::NotFound { .. } => SigningKeyErrorKind::NotFound,
            StorageError::Conflict { .. } => SigningKeyErrorKind::Conflict,
            StorageError::Connection { .. } => SigningKeyErrorKind::Connection,
            StorageError::Serialization { .. } => SigningKeyErrorKind::Serialization,
            _ => SigningKeyErrorKind::Other,
        }
    }
}

#[async_trait]
impl PublicSigningKeyStore for LedgerSigningKeyStore {
    async fn create_key(&self, namespace_id: i64, key: &PublicSigningKey) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(&key.kid);

        // Check if key already exists
        if let Some(_existing) = self.do_read(namespace_id, &storage_key).await? {
            self.record_error(SigningKeyErrorKind::Conflict);
            return Err(StorageError::conflict());
        }

        let value = Self::serialize_key(key)?;

        let result = self
            .client
            .write(
                namespace_id,
                None, // No vault - keys are namespace-level
                vec![Operation::set_entity(storage_key, value)],
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                // Handle race condition where another writer created the key
                if let inferadb_ledger_sdk::SdkError::Rpc { code, .. } = &e
                    && *code == Code::AlreadyExists
                {
                    return StorageError::conflict();
                }
                StorageError::from(LedgerStorageError::Sdk(e))
            });

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_create(start.elapsed());
        }

        result
    }

    async fn get_key(
        &self,
        namespace_id: i64,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = match self.do_read(namespace_id, &storage_key).await {
            Ok(Some(bytes)) => Self::deserialize_key(&bytes).map(Some),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        };

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_get(start.elapsed());
        }

        result
    }

    async fn list_active_keys(&self, namespace_id: i64) -> StorageResult<Vec<PublicSigningKey>> {
        let start = Instant::now();
        let opts = ListEntitiesOpts {
            key_prefix: SIGNING_KEY_PREFIX.to_string(),
            at_height: None,
            include_expired: false,
            limit: 1000, // Reasonable limit for signing keys per org
            page_token: None,
            consistency: self.read_consistency,
        };

        let result = self
            .client
            .list_entities(namespace_id, opts)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::Sdk(e)));

        let list_result = match result {
            Ok(result) => {
                let now = Utc::now();
                let mut active_keys = Vec::new();

                for entity in result.items {
                    match Self::deserialize_key(&entity.value) {
                        Ok(key) => {
                            // Check all active conditions
                            let is_active = key.active
                                && key.revoked_at.is_none()
                                && now >= key.valid_from
                                && key.valid_until.is_none_or(|until| now <= until);

                            if is_active {
                                active_keys.push(key);
                            }
                        }
                        Err(e) => {
                            tracing::warn!(
                                key = entity.key,
                                error = %e,
                                "Failed to deserialize signing key, skipping"
                            );
                        }
                    }
                }

                Ok(active_keys)
            }
            Err(e) => {
                self.record_error(Self::error_to_kind(&e));
                Err(e)
            }
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_list(start.elapsed());
        }

        list_result
    }

    async fn deactivate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = async {
            let bytes = self
                .do_read(namespace_id, &storage_key)
                .await?
                .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

            let mut key = Self::deserialize_key(&bytes)?;
            key.active = false;

            let value = Self::serialize_key(&key)?;

            self.client
                .write(
                    namespace_id,
                    None,
                    vec![Operation::set_entity(storage_key, value)],
                )
                .await
                .map(|_| ())
                .map_err(|e| StorageError::from(LedgerStorageError::Sdk(e)))
        }
        .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_deactivate(start.elapsed());
        }

        result
    }

    async fn revoke_key(
        &self,
        namespace_id: i64,
        kid: &str,
        _reason: Option<&str>,
    ) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = async {
            let bytes = self
                .do_read(namespace_id, &storage_key)
                .await?
                .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

            let mut key = Self::deserialize_key(&bytes)?;

            // Idempotent: if already revoked, keep original timestamp
            if key.revoked_at.is_none() {
                key.revoked_at = Some(Utc::now());
                key.active = false;
            }

            let value = Self::serialize_key(&key)?;

            self.client
                .write(
                    namespace_id,
                    None,
                    vec![Operation::set_entity(storage_key, value)],
                )
                .await
                .map(|_| ())
                .map_err(|e| StorageError::from(LedgerStorageError::Sdk(e)))
        }
        .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_revoke(start.elapsed());
        }

        result
    }

    async fn activate_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = async {
            let bytes = self
                .do_read(namespace_id, &storage_key)
                .await?
                .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

            let mut key = Self::deserialize_key(&bytes)?;

            // Cannot reactivate a revoked key
            if key.revoked_at.is_some() {
                return Err(StorageError::internal(format!(
                    "Cannot reactivate revoked key: {kid}"
                )));
            }

            key.active = true;

            let value = Self::serialize_key(&key)?;

            self.client
                .write(
                    namespace_id,
                    None,
                    vec![Operation::set_entity(storage_key, value)],
                )
                .await
                .map(|_| ())
                .map_err(|e| StorageError::from(LedgerStorageError::Sdk(e)))
        }
        .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_activate(start.elapsed());
        }

        result
    }

    async fn delete_key(&self, namespace_id: i64, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = async {
            // Check if key exists
            if self.do_read(namespace_id, &storage_key).await?.is_none() {
                return Err(StorageError::not_found(format!("Key not found: {kid}")));
            }

            self.client
                .write(
                    namespace_id,
                    None,
                    vec![Operation::delete_entity(storage_key)],
                )
                .await
                .map(|_| ())
                .map_err(|e| StorageError::from(LedgerStorageError::Sdk(e)))
        }
        .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_delete(start.elapsed());
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_key_format() {
        assert_eq!(
            LedgerSigningKeyStore::storage_key("key-abc123"),
            "signing-keys/key-abc123"
        );
    }

    #[test]
    fn test_serialization_round_trip() {
        let now = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("test-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(12345)
            .cert_id(42)
            .created_at(now)
            .valid_from(now)
            .build();

        let bytes = LedgerSigningKeyStore::serialize_key(&key).expect("serialize");
        let deserialized = LedgerSigningKeyStore::deserialize_key(&bytes).expect("deserialize");

        assert_eq!(key.kid, deserialized.kid);
        assert_eq!(key.public_key, deserialized.public_key);
        assert_eq!(key.client_id, deserialized.client_id);
        assert_eq!(key.cert_id, deserialized.cert_id);
        assert_eq!(key.active, deserialized.active);
    }

    #[test]
    fn test_error_to_kind_mapping() {
        assert_eq!(
            LedgerSigningKeyStore::error_to_kind(&StorageError::not_found("key")),
            SigningKeyErrorKind::NotFound
        );
        assert_eq!(
            LedgerSigningKeyStore::error_to_kind(&StorageError::conflict()),
            SigningKeyErrorKind::Conflict
        );
        assert_eq!(
            LedgerSigningKeyStore::error_to_kind(&StorageError::connection("err")),
            SigningKeyErrorKind::Connection
        );
        assert_eq!(
            LedgerSigningKeyStore::error_to_kind(&StorageError::serialization("err")),
            SigningKeyErrorKind::Serialization
        );
        assert_eq!(
            LedgerSigningKeyStore::error_to_kind(&StorageError::internal("err")),
            SigningKeyErrorKind::Other
        );
    }
}
