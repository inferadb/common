//! Ledger-backed implementation of public signing key storage.
//!
//! This module provides [`LedgerSigningKeyStore`](crate::auth::LedgerSigningKeyStore),
//! which implements the
//! [`PublicSigningKeyStore`](inferadb_common_storage::auth::PublicSigningKeyStore) trait using the
//! InferaDB Ledger as the backing store.
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
//! // Requires a running Ledger server.
//! use std::sync::Arc;
//! use chrono::Utc;
//! use inferadb_ledger_sdk::LedgerClient;
//! use inferadb_common_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
//! use inferadb_common_storage::NamespaceId;
//! use inferadb_common_storage_ledger::auth::LedgerSigningKeyStore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Assume we have a configured LedgerClient
//! # let client: Arc<LedgerClient> = todo!();
//! let store = LedgerSigningKeyStore::new(client);
//!
//! let key = PublicSigningKey::builder()
//!     .kid("key-2024-001")
//!     .public_key("MCowBQYDK2VwAyEA...".to_owned())
//!     .client_id(1001)
//!     .cert_id(42)
//!     .build();
//!
//! // Store the key in the org's namespace
//! let ns = NamespaceId::from(100);
//! store.create_key(ns, &key).await?;
//!
//! // Retrieve it later
//! let retrieved = store.get_key(ns, "key-2024-001").await?;
//! assert!(retrieved.is_some());
//! # Ok(())
//! # }
//! ```

use std::{collections::HashMap, future::Future, sync::Arc, time::Instant};

use async_trait::async_trait;
use chrono::Utc;
use inferadb_common_storage::{
    NamespaceId, StorageError, StorageResult,
    auth::{
        PublicSigningKey, PublicSigningKeyStore, SIGNING_KEY_PREFIX, SigningKeyErrorKind,
        SigningKeyMetrics,
    },
};
use inferadb_ledger_sdk::{
    LedgerClient, ListEntitiesOpts, Operation, ReadConsistency, SetCondition,
};
use tonic::Code;

use crate::{LedgerStorageError, config::CasRetryConfig};

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
/// # Concurrency
///
/// Write operations (`revoke_key`, `deactivate_key`, `activate_key`, `delete_key`)
/// use optimistic locking via compare-and-set (CAS). Each operation reads the
/// current value, modifies it, and writes back conditioned on the value being
/// unchanged. If a concurrent writer modified the key between the read and write,
/// the operation returns [`StorageError::Conflict`].
///
/// Callers should retry the full operation on `Conflict`. Since each operation
/// re-reads the current value, the retry naturally picks up the latest state.
///
/// # Error Handling
///
/// Operations convert Ledger SDK errors to [`StorageError`] variants:
/// - Connection failures → `StorageError::Connection`
/// - Key not found → `StorageError::NotFound`
/// - Duplicate key or CAS failure → `StorageError::Conflict`
/// - Serialization issues → `StorageError::Serialization`
#[derive(Clone)]
pub struct LedgerSigningKeyStore {
    client: Arc<LedgerClient>,
    read_consistency: ReadConsistency,
    metrics: Option<SigningKeyMetrics>,
    cas_retry_config: CasRetryConfig,
}

impl std::fmt::Debug for LedgerSigningKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigningKeyStore")
            .field("read_consistency", &self.read_consistency)
            .field("cas_retry_config", &self.cas_retry_config)
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
            cas_retry_config: CasRetryConfig::default(),
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
            cas_retry_config: CasRetryConfig::default(),
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
    /// // Requires a running Ledger server.
    /// use std::sync::Arc;
    /// use inferadb_ledger_sdk::LedgerClient;
    /// use inferadb_common_storage::auth::SigningKeyMetrics;
    /// use inferadb_common_storage_ledger::auth::LedgerSigningKeyStore;
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

    /// Configures the CAS retry policy for write operations.
    ///
    /// By default, CAS operations are retried up to 5 times on conflict.
    /// Use this to tune retry behavior for workloads with high or low
    /// write contention.
    #[must_use]
    pub fn with_cas_retry_config(mut self, config: CasRetryConfig) -> Self {
        self.cas_retry_config = config;
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
        namespace_id: NamespaceId,
        key: &str,
    ) -> Result<Option<Vec<u8>>, LedgerStorageError> {
        let ns: i64 = namespace_id.into();
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => self.client.read_consistent(ns, None, key).await,
            ReadConsistency::Eventual => self.client.read(ns, None, key).await,
        };

        result.map_err(LedgerStorageError::from)
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

    /// Performs a conditional write using optimistic locking.
    ///
    /// The write is conditioned on the current value matching `expected_value`.
    /// If the value has been modified since it was read (by a concurrent writer),
    /// this returns [`StorageError::Conflict`].
    ///
    /// Callers should retry the full read-modify-write cycle on conflict.
    async fn cas_write(
        &self,
        namespace_id: NamespaceId,
        storage_key: String,
        new_value: Vec<u8>,
        expected_value: Vec<u8>,
    ) -> StorageResult<()> {
        use inferadb_ledger_sdk::SdkError;

        match self
            .client
            .write(
                namespace_id.into(),
                None,
                vec![Operation::set_entity_if(
                    storage_key,
                    new_value,
                    SetCondition::ValueEquals(expected_value),
                )],
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::Rpc { code: Code::FailedPrecondition, .. }) => {
                Err(StorageError::conflict())
            },
            Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
        }
    }

    /// Performs a conditional delete using optimistic locking.
    ///
    /// Uses a two-operation atomic batch: a CAS precondition check
    /// (`set_entity_if` with the current value) followed by a `delete_entity`.
    /// If the value has been modified since it was read, the entire batch
    /// fails with [`StorageError::Conflict`].
    async fn cas_delete(
        &self,
        namespace_id: NamespaceId,
        storage_key: String,
        expected_value: Vec<u8>,
    ) -> StorageResult<()> {
        use inferadb_ledger_sdk::SdkError;

        match self
            .client
            .write(
                namespace_id.into(),
                None,
                vec![
                    // Precondition: value must match what we read
                    Operation::set_entity_if(
                        storage_key.clone(),
                        expected_value.clone(),
                        SetCondition::ValueEquals(expected_value),
                    ),
                    // Delete the entity (atomic with the precondition)
                    Operation::delete_entity(storage_key),
                ],
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::Rpc { code: Code::FailedPrecondition, .. }) => {
                Err(StorageError::conflict())
            },
            Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
        }
    }

    /// Retries a read-modify-write cycle on CAS conflict.
    ///
    /// The provided `operation` closure should perform the full cycle:
    /// read the current value, compute the mutation, and call
    /// [`cas_write`](Self::cas_write) or [`cas_delete`](Self::cas_delete).
    ///
    /// On [`StorageError::Conflict`], the closure is re-invoked (re-reading
    /// the current value) up to `cas_retry_config.max_retries` times.
    /// Jitter is applied between retries to reduce contention.
    ///
    /// Non-conflict errors are returned immediately without retry.
    async fn with_cas_retry<F, Fut>(&self, operation: F) -> StorageResult<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = StorageResult<()>>,
    {
        crate::retry::with_cas_retry(&self.cas_retry_config, operation).await
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
    #[tracing::instrument(skip(self, key), fields(kid = %key.kid))]
    async fn create_key(
        &self,
        namespace_id: NamespaceId,
        key: &PublicSigningKey,
    ) -> StorageResult<()> {
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
                namespace_id.into(),
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
                StorageError::from(LedgerStorageError::from(e))
            });

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_create(start.elapsed());
        }

        result
    }

    #[tracing::instrument(skip(self))]
    async fn get_key(
        &self,
        namespace_id: NamespaceId,
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

    #[tracing::instrument(skip(self))]
    async fn list_active_keys(
        &self,
        namespace_id: NamespaceId,
    ) -> StorageResult<Vec<PublicSigningKey>> {
        let start = Instant::now();
        let opts = ListEntitiesOpts {
            key_prefix: SIGNING_KEY_PREFIX.to_string(),
            at_height: None,
            include_expired: false,
            limit: 1000, // Reasonable limit for signing keys per org
            page_token: None,
            consistency: self.read_consistency,
            vault_id: None, // Signing keys are namespace-level, not vault-scoped
        };

        let result = self
            .client
            .list_entities(namespace_id.into(), opts)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)));

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
                        },
                        Err(e) => {
                            tracing::error!(
                                key = entity.key,
                                error = %e,
                                "Failed to deserialize signing key, skipping — \
                                 investigate possible schema migration or data corruption"
                            );
                            self.record_error(SigningKeyErrorKind::Serialization);
                        },
                    }
                }

                Ok(active_keys)
            },
            Err(e) => {
                self.record_error(Self::error_to_kind(&e));
                Err(e)
            },
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_list(start.elapsed());
        }

        list_result
    }

    #[tracing::instrument(skip(self))]
    async fn deactivate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
                let bytes = self
                    .do_read(namespace_id, &storage_key)
                    .await?
                    .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

                let mut key = Self::deserialize_key(&bytes)?;
                key.active = false;

                let value = Self::serialize_key(&key)?;

                self.cas_write(namespace_id, storage_key.clone(), value, bytes).await
            })
            .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_deactivate(start.elapsed());
        }

        result
    }

    #[tracing::instrument(skip(self))]
    async fn revoke_key(
        &self,
        namespace_id: NamespaceId,
        kid: &str,
        reason: Option<&str>,
    ) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);
        let reason_owned = reason.map(String::from);

        let result = self
            .with_cas_retry(|| {
                let sk = storage_key.clone();
                let reason_ref = reason_owned.clone();
                async move {
                    let bytes = self
                        .do_read(namespace_id, &sk)
                        .await?
                        .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

                    let mut key = Self::deserialize_key(&bytes)?;

                    // Idempotent: if already revoked, keep original timestamp
                    if key.revoked_at.is_none() {
                        key.revoked_at = Some(Utc::now());
                        key.active = false;
                        key.revocation_reason = reason_ref;
                    }

                    let value = Self::serialize_key(&key)?;

                    self.cas_write(namespace_id, sk, value, bytes).await
                }
            })
            .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_revoke(start.elapsed());
        }

        result
    }

    #[tracing::instrument(skip(self))]
    async fn activate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
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

                self.cas_write(namespace_id, storage_key.clone(), value, bytes).await
            })
            .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_activate(start.elapsed());
        }

        result
    }

    #[tracing::instrument(skip(self))]
    async fn delete_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
                let bytes = self
                    .do_read(namespace_id, &storage_key)
                    .await?
                    .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

                self.cas_delete(namespace_id, storage_key.clone(), bytes).await
            })
            .await;

        if let Err(ref e) = result {
            self.record_error(Self::error_to_kind(e));
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_delete(start.elapsed());
        }

        result
    }

    /// Optimized bulk create: batches all key writes into a single SDK `write()` call.
    ///
    /// Unlike the default sequential implementation, this issues one network
    /// round-trip regardless of how many keys are being stored. Individual
    /// serialization failures are reported per-key; the remaining keys are
    /// still submitted in the batch.
    #[tracing::instrument(skip(self, keys), fields(count = keys.len()))]
    async fn create_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[PublicSigningKey],
    ) -> Vec<StorageResult<()>> {
        if keys.is_empty() {
            return Vec::new();
        }

        let start = Instant::now();

        // Pre-serialize all keys, separating successes from failures.
        // Track which indices had serialization errors so we can report per-key.
        let mut operations = Vec::with_capacity(keys.len());
        let mut serialization_errors: Vec<(usize, StorageError)> = Vec::new();

        for (i, key) in keys.iter().enumerate() {
            match Self::serialize_key(key) {
                Ok(value) => {
                    let storage_key = Self::storage_key(&key.kid);
                    operations.push(Operation::set_entity(storage_key, value));
                },
                Err(e) => {
                    self.record_error(SigningKeyErrorKind::Serialization);
                    serialization_errors.push((i, e));
                },
            }
        }

        // Submit all valid operations in a single batch write
        let batch_failed = if operations.is_empty() {
            false
        } else {
            match self.client.write(namespace_id.into(), None, operations).await {
                Ok(_) => false,
                Err(e) => {
                    let storage_err = StorageError::from(LedgerStorageError::from(e));
                    self.record_error(Self::error_to_kind(&storage_err));
                    true
                },
            }
        };

        // Build per-key results: serialization errors go at their original indices,
        // remaining slots get the batch outcome.
        let mut ser_error_map: HashMap<usize, StorageError> =
            serialization_errors.into_iter().collect();

        let mut results = Vec::with_capacity(keys.len());
        for i in 0..keys.len() {
            if let Some(err) = ser_error_map.remove(&i) {
                results.push(Err(err));
            } else if batch_failed {
                results.push(Err(StorageError::internal("Batch key creation failed")));
            } else {
                results.push(Ok(()));
            }
        }

        if let Some(metrics) = &self.metrics {
            metrics.record_create(start.elapsed());
        }

        results
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_storage_key_format() {
        assert_eq!(LedgerSigningKeyStore::storage_key("key-abc123"), "signing-keys/key-abc123");
    }

    #[test]
    fn test_serialization_round_trip() {
        let now = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("test-key")
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
        assert!(deserialized.revocation_reason.is_none());
    }

    #[test]
    fn test_serialization_round_trip_with_revocation_reason() {
        let now = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("revoked-key")
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(12345)
            .cert_id(42)
            .created_at(now)
            .valid_from(now)
            .revoked_at(now)
            .revocation_reason("compromised")
            .active(false)
            .build();

        let bytes = LedgerSigningKeyStore::serialize_key(&key).expect("serialize");
        let deserialized = LedgerSigningKeyStore::deserialize_key(&bytes).expect("deserialize");

        assert_eq!(deserialized.revocation_reason.as_deref(), Some("compromised"));
        assert_eq!(deserialized.revoked_at, Some(now));
        assert!(!deserialized.active);
    }

    #[test]
    fn test_deserialization_backward_compatible_without_revocation_reason() {
        // Simulate JSON stored before revocation_reason field existed
        let legacy_json = r#"{
            "kid": "legacy-key",
            "public_key": "MCowBQYDK2VwAyEAtest",
            "client_id": 12345,
            "cert_id": 42,
            "created_at": "2024-01-15T10:30:00Z",
            "valid_from": "2024-01-15T10:30:00Z",
            "valid_until": null,
            "active": true,
            "revoked_at": null
        }"#;

        let deserialized = LedgerSigningKeyStore::deserialize_key(legacy_json.as_bytes())
            .expect("legacy JSON should deserialize");

        assert_eq!(deserialized.kid, "legacy-key");
        assert!(deserialized.revocation_reason.is_none());
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
