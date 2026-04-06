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
//! organization using the key format `signing-keys/{kid}`. This allows Engine
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
//! # Organization Scoping
//!
//! Keys are stored at the organization level (no vault required). Each
//! organization has its own isolated key space for signing keys.
//!
//! # Examples
//!
//! ```no_run
//! // Requires a running Ledger server.
//! use std::sync::Arc;
//! use chrono::Utc;
//! use inferadb_ledger_sdk::LedgerClient;
//! use inferadb_common_storage::auth::{PublicSigningKey, PublicSigningKeyStore};
//! use inferadb_common_storage::OrganizationSlug;
//! use inferadb_common_storage_ledger::auth::LedgerSigningKeyStore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Assume we have a configured LedgerClient
//! # let client: Arc<LedgerClient> = todo!();
//! let store = LedgerSigningKeyStore::new(client, inferadb_ledger_sdk::UserSlug::from(1));
//!
//! let key = PublicSigningKey::builder()
//!     .kid("key-2024-001")
//!     .public_key("MCowBQYDK2VwAyEA...".to_owned())
//!     .client_id(1001)
//!     .cert_id(42)
//!     .build();
//!
//! // Store the key in the org's organization
//! let org = OrganizationSlug::from(100);
//! store.create_key(org, &key).await?;
//!
//! // Retrieve it later
//! let retrieved = store.get_key(org, "key-2024-001").await?;
//! assert!(retrieved.is_some());
//! # Ok(())
//! # }
//! ```

use std::{future::Future, sync::Arc, time::Instant};

use async_trait::async_trait;
use chrono::Utc;
use inferadb_common_storage::{
    CasRetryConfig, OrganizationSlug, StorageError, StorageResult,
    auth::{
        PublicSigningKey, PublicSigningKeyStore, SIGNING_KEY_PREFIX, SigningKeyErrorKind,
        SigningKeyMetrics,
    },
};
use inferadb_ledger_sdk::{
    LedgerClient, ListEntitiesOpts, Operation, ReadConsistency, SetCondition, UserSlug,
};

use crate::LedgerStorageError;

/// Maximum number of signing keys returned per organization in a single list call.
///
/// If an organization exceeds this limit, the result is truncated and a warning
/// is logged. This guards against unbounded responses while covering the vast
/// majority of deployments. If you consistently hit this limit, consider
/// implementing pagination or archiving inactive keys.
const MAX_SIGNING_KEYS_PER_ORG: u32 = 1000;

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
/// Collects operation metrics when configured via
/// [`LedgerSigningKeyStore::with_metrics`]. Metrics include operation counts,
/// latencies, and error rates.
///
/// # Concurrency
///
/// Write operations ([`revoke_key`](PublicSigningKeyStore::revoke_key),
/// [`deactivate_key`](PublicSigningKeyStore::deactivate_key),
/// [`activate_key`](PublicSigningKeyStore::activate_key),
/// [`delete_key`](PublicSigningKeyStore::delete_key))
/// use optimistic locking via compare-and-set (CAS). Each operation reads the
/// current value, modifies it, and writes back conditioned on the value being
/// unchanged. CAS conflicts are retried internally (see
/// [`with_cas_retry_config`](Self::with_cas_retry_config) for tuning).
///
/// If all internal retries are exhausted, the operation returns
/// [`StorageError::CasRetriesExhausted`]. This typically indicates sustained
/// write contention that callers should handle (e.g., back off and retry at
/// a higher level).
///
/// # Error Handling
///
/// Operations convert Ledger SDK errors to [`StorageError`] variants:
/// - Connection failures → [`StorageError::Connection`]
/// - Key not found → [`StorageError::NotFound`]
/// - Duplicate key or CAS failure → [`StorageError::Conflict`]
/// - Serialization issues → [`StorageError::Serialization`]
#[derive(Clone)]
pub struct LedgerSigningKeyStore {
    /// SDK client for Ledger operations.
    client: Arc<LedgerClient>,
    /// Caller identity for audit trails.
    caller: UserSlug,
    /// Consistency level for key lookups.
    read_consistency: ReadConsistency,
    /// Optional metrics collector for key store operations.
    metrics: Option<SigningKeyMetrics>,
    /// CAS retry configuration for optimistic locking.
    cas_retry_config: CasRetryConfig,
    /// Optional cancellation token for cooperative shutdown.
    cancellation_token: Option<tokio_util::sync::CancellationToken>,
}

impl std::fmt::Debug for LedgerSigningKeyStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerSigningKeyStore")
            .field("caller", &self.caller)
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
    #[must_use = "constructing a store has no side effects"]
    pub fn new(client: Arc<LedgerClient>, caller: UserSlug) -> Self {
        Self {
            client,
            caller,
            read_consistency: ReadConsistency::Linearizable,
            metrics: None,
            cas_retry_config: CasRetryConfig::default(),
            cancellation_token: None,
        }
    }

    /// Creates a store with the specified read consistency level.
    ///
    /// Use `ReadConsistency::Eventual` for read-heavy workloads where
    /// slight staleness is acceptable. Note that eventual consistency
    /// may delay key revocation propagation.
    ///
    /// **Note:** This creates a new store instance with default CAS retry configuration.
    /// To customize both read consistency and CAS retries, call
    /// [`with_cas_retry_config`](Self::with_cas_retry_config) on the returned instance.
    #[must_use = "constructing a store has no side effects"]
    pub fn with_read_consistency(
        client: Arc<LedgerClient>,
        caller: UserSlug,
        consistency: ReadConsistency,
    ) -> Self {
        Self {
            client,
            caller,
            read_consistency: consistency,
            metrics: None,
            cas_retry_config: CasRetryConfig::default(),
            cancellation_token: None,
        }
    }

    /// Enables metrics collection for this store.
    ///
    /// The provided [`SigningKeyMetrics`] will record operation counts,
    /// latencies, and error rates. Metrics are thread-safe and can be
    /// shared across multiple store instances.
    ///
    /// # Examples
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
    /// let store = LedgerSigningKeyStore::new(client, inferadb_ledger_sdk::UserSlug::from(1)).with_metrics(metrics.clone());
    ///
    /// // Use store... metrics are automatically recorded
    /// # Ok(())
    /// # }
    /// ```
    #[must_use = "returns a modified store builder without side effects"]
    pub fn with_metrics(mut self, metrics: SigningKeyMetrics) -> Self {
        self.metrics = Some(metrics);
        self
    }

    /// Configures the CAS retry policy for write operations.
    ///
    /// By default, CAS operations are retried up to
    /// [`DEFAULT_MAX_CAS_RETRIES`](crate::DEFAULT_MAX_CAS_RETRIES) times on conflict.
    /// Use this to tune retry behavior for workloads with high or low
    /// write contention.
    #[must_use = "returns a modified store builder without side effects"]
    pub fn with_cas_retry_config(mut self, config: CasRetryConfig) -> Self {
        self.cas_retry_config = config;
        self
    }

    /// Configures a cancellation token for cooperative shutdown.
    ///
    /// When the token is cancelled, in-flight SDK operations are cancelled
    /// at the next retry boundary.
    #[must_use = "returns a modified store builder without side effects"]
    pub fn with_cancellation_token(mut self, token: tokio_util::sync::CancellationToken) -> Self {
        self.cancellation_token = Some(token);
        self
    }

    /// Returns the metrics collector if configured.
    #[must_use = "returns a reference without side effects"]
    pub fn metrics(&self) -> Option<&SigningKeyMetrics> {
        self.metrics.as_ref()
    }

    /// Returns the underlying Ledger client.
    #[must_use = "returns a reference without side effects"]
    pub fn client(&self) -> &LedgerClient {
        &self.client
    }

    /// Constructs the storage key for a signing key.
    ///
    /// Keys are stored at `signing-keys/{kid}` within the organization.
    fn storage_key(kid: &str) -> String {
        format!("{SIGNING_KEY_PREFIX}{kid}")
    }

    /// Reads a key from Ledger with the configured consistency and cancellation token.
    async fn do_read(
        &self,
        organization: OrganizationSlug,
        key: &str,
    ) -> Result<Option<Vec<u8>>, LedgerStorageError> {
        self.client
            .read(
                self.caller,
                organization,
                None,
                key,
                Some(self.read_consistency),
                self.cancellation_token.clone(),
            )
            .await
            .map_err(LedgerStorageError::from)
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
        organization: OrganizationSlug,
        storage_key: String,
        new_value: Vec<u8>,
        expected_value: Vec<u8>,
    ) -> StorageResult<()> {
        match self
            .client
            .set_entity(
                self.caller,
                organization,
                None,
                storage_key,
                new_value,
                None,
                Some(SetCondition::ValueEquals(expected_value)),
                self.cancellation_token.clone(),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.is_cas_conflict() => Err(StorageError::conflict()),
            Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
        }
    }

    /// Performs a conditional delete using optimistic locking.
    ///
    /// Uses a two-operation atomic batch: a CAS precondition check
    /// (`set_entity` with `SetCondition::ValueEquals`) followed by a `delete_entity`.
    /// If the value has been modified since it was read, the entire batch
    /// fails with [`StorageError::Conflict`].
    async fn cas_delete(
        &self,
        organization: OrganizationSlug,
        storage_key: String,
        expected_value: Vec<u8>,
    ) -> StorageResult<()> {
        match self
            .client
            .write(
                self.caller,
                organization,
                None,
                vec![
                    // Precondition: value must match what we read
                    Operation::set_entity(
                        storage_key.clone(),
                        expected_value.clone(),
                        None,
                        Some(SetCondition::ValueEquals(expected_value)),
                    ),
                    // Delete the entity (atomic with the precondition)
                    Operation::delete_entity(storage_key),
                ],
                self.cancellation_token.clone(),
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(e) if e.is_cas_conflict() => Err(StorageError::conflict()),
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
        inferadb_common_storage::with_cas_retry(&self.cas_retry_config, operation).await
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
    /// Stores a signing key in the Ledger atomically.
    ///
    /// Uses `SetCondition::NotExists` for a single atomic write that fails if
    /// the key already exists, eliminating the TOCTOU race of read-then-write.
    ///
    /// Returns [`StorageError::Conflict`] if a key with the same `kid` already exists.
    #[tracing::instrument(skip(self, key), fields(kid = %key.kid))]
    async fn create_key(
        &self,
        organization: OrganizationSlug,
        key: &PublicSigningKey,
    ) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(&key.kid);
        let value = Self::serialize_key(key)?;

        let result = self
            .client
            .set_entity(
                self.caller,
                organization,
                None,
                storage_key,
                value,
                None,
                Some(SetCondition::NotExists),
                self.cancellation_token.clone(),
            )
            .await
            .map(|_| ())
            .map_err(|e| {
                if e.is_cas_conflict() {
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

    /// Retrieves a signing key by ID from the Ledger.
    ///
    /// Returns `Ok(None)` if no key with the given `kid` exists.
    #[tracing::instrument(skip(self))]
    async fn get_key(
        &self,
        organization: OrganizationSlug,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = match self.do_read(organization, &storage_key).await {
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

    /// Retrieves multiple signing keys by ID using a single batch read.
    ///
    /// Uses the SDK's `batch_read` to fetch all keys in one RPC call,
    /// reducing round-trip latency compared to sequential `get_key` calls.
    #[tracing::instrument(skip(self, kids), fields(count = kids.len()))]
    async fn get_keys(
        &self,
        organization: OrganizationSlug,
        kids: &[&str],
    ) -> StorageResult<Vec<Option<PublicSigningKey>>> {
        let start = Instant::now();
        let storage_keys: Vec<String> = kids.iter().map(|kid| Self::storage_key(kid)).collect();

        let result = self
            .client
            .batch_read(
                self.caller,
                organization,
                None,
                storage_keys,
                Some(self.read_consistency),
                self.cancellation_token.clone(),
            )
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)));

        let batch_result = match result {
            Ok(entries) => {
                let mut keys = Vec::with_capacity(entries.len());
                for (_key, value) in entries {
                    match value {
                        Some(bytes) => match Self::deserialize_key(&bytes) {
                            Ok(key) => keys.push(Some(key)),
                            Err(e) => {
                                self.record_error(SigningKeyErrorKind::Serialization);
                                return Err(e);
                            },
                        },
                        None => keys.push(None),
                    }
                }
                Ok(keys)
            },
            Err(e) => {
                self.record_error(Self::error_to_kind(&e));
                Err(e)
            },
        };

        if let Some(metrics) = &self.metrics {
            metrics.record_get(start.elapsed());
        }

        batch_result
    }

    /// Lists all active signing keys in the organization.
    ///
    /// Returns up to `MAX_SIGNING_KEYS_PER_ORG` keys. If more keys exist, the
    /// result is silently truncated and a warning is logged. A key is considered
    /// active if it is not revoked, not expired, and its `valid_from` timestamp
    /// has passed.
    #[tracing::instrument(skip(self))]
    async fn list_active_keys(
        &self,
        organization: OrganizationSlug,
    ) -> StorageResult<Vec<PublicSigningKey>> {
        let start = Instant::now();
        let opts = ListEntitiesOpts {
            key_prefix: SIGNING_KEY_PREFIX.to_string(),
            at_height: None,
            include_expired: false,
            limit: MAX_SIGNING_KEYS_PER_ORG,
            page_token: None,
            consistency: self.read_consistency,
            vault: None, // Signing keys are organization-level, not vault-scoped
        };

        let result = self
            .client
            .list_entities(self.caller, organization, opts)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)));

        let list_result = match result {
            Ok(result) => {
                if result.has_next_page() {
                    tracing::warn!(
                        organization = %organization,
                        limit = MAX_SIGNING_KEYS_PER_ORG,
                        "signing key list truncated at {MAX_SIGNING_KEYS_PER_ORG} keys for org {organization}",
                    );
                }

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

    /// Deactivates a signing key using CAS for consistency.
    #[tracing::instrument(skip(self))]
    async fn deactivate_key(&self, organization: OrganizationSlug, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
                let bytes = self
                    .do_read(organization, &storage_key)
                    .await?
                    .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

                let mut key = Self::deserialize_key(&bytes)?;
                key.active = false;

                let value = Self::serialize_key(&key)?;

                self.cas_write(organization, storage_key.clone(), value, bytes).await
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

    /// Revokes a signing key with an optional reason, using CAS.
    #[tracing::instrument(skip(self))]
    async fn revoke_key(
        &self,
        organization: OrganizationSlug,
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
                        .do_read(organization, &sk)
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

                    self.cas_write(organization, sk, value, bytes).await
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

    /// Reactivates a previously deactivated signing key using CAS.
    #[tracing::instrument(skip(self))]
    async fn activate_key(&self, organization: OrganizationSlug, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
                let bytes = self
                    .do_read(organization, &storage_key)
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

                self.cas_write(organization, storage_key.clone(), value, bytes).await
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

    /// Permanently removes a signing key from the Ledger using CAS.
    #[tracing::instrument(skip(self))]
    async fn delete_key(&self, organization: OrganizationSlug, kid: &str) -> StorageResult<()> {
        let start = Instant::now();
        let storage_key = Self::storage_key(kid);

        let result = self
            .with_cas_retry(|| async {
                let bytes = self
                    .do_read(organization, &storage_key)
                    .await?
                    .ok_or_else(|| StorageError::not_found(format!("Key not found: {kid}")))?;

                self.cas_delete(organization, storage_key.clone(), bytes).await
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
