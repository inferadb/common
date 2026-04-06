//! Ledger-backed storage backend implementation.
//!
//! This module provides [`LedgerBackend`], which implements the
//! [`StorageBackend`](inferadb_common_storage::StorageBackend) trait using
//! the InferaDB Ledger SDK.

use std::{
    ops::{Bound, RangeBounds},
    sync::Arc,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    HealthMetadata, HealthProbe, HealthStatus, KeyValue, Metrics, OrganizationSlug, SizeLimits,
    StorageBackend, StorageError, StorageRange, StorageResult, Transaction, VaultSlug,
    validate_sizes,
};
use inferadb_ledger_sdk::{
    LedgerClient, ListEntitiesOpts, Operation, ReadConsistency, SetCondition, UserSlug,
};

use crate::{
    config::{LedgerBackendConfig, TimeoutConfig},
    error::{LedgerStorageError, Result},
    keys::{decode_key, encode_key},
    transaction::LedgerTransaction,
};

/// Returns the byte length of the longest common prefix of two strings.
///
/// Since keys are hex-encoded (single-byte UTF-8 characters), byte length equals
/// character count, making string slicing at `&s[..len]` safe.
fn common_prefix_len(a: &str, b: &str) -> usize {
    a.bytes().zip(b.bytes()).take_while(|(ca, cb)| ca == cb).count()
}

/// Ledger-backed implementation of [`StorageBackend`].
///
/// This backend uses the InferaDB Ledger SDK to provide durable, cryptographically
/// verifiable key-value storage. All operations target a Ledger organization
/// and optionally a vault for data isolation.
///
/// # Key Encoding
///
/// Keys are encoded as lowercase hexadecimal strings to:
/// - Preserve byte ordering for range scans
/// - Ensure compatibility with Ledger's string-based key format
/// - Support arbitrary binary keys
///
/// # Circuit Breaking
///
/// Circuit breaking is handled by the SDK at the transport layer. Configure it
/// on [`ClientConfig`](inferadb_ledger_sdk::ClientConfig) via
/// [`CircuitBreakerConfig`](inferadb_ledger_sdk::CircuitBreakerConfig).
///
/// # Thread Safety
///
/// `LedgerBackend` is `Send + Sync` and can be safely shared across threads.
/// The underlying SDK client manages connection pooling internally.
///
/// # Examples
///
/// ```no_run
/// // Requires a running Ledger server.
/// use inferadb_common_storage_ledger::{
///     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
/// };
/// use inferadb_common_storage::StorageBackend;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = ClientConfig::builder()
///         .servers(ServerSource::from_static(["http://localhost:50051"]))
///         .client_id("my-service")
///         .build()?;
///
///     let config = LedgerBackendConfig::builder()
///         .client(client)
///         .caller(1)
///         .organization(1)
///         .build()?;
///
///     let backend = LedgerBackend::new(config).await?;
///
///     // Basic operations
///     backend.set(b"key".to_vec(), b"value".to_vec()).await?;
///     let value = backend.get(b"key").await?;
///     assert_eq!(value, Some(bytes::Bytes::from("value")));
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct LedgerBackend {
    /// The underlying SDK client.
    client: Arc<LedgerClient>,

    /// Caller identity for audit trails.
    caller: UserSlug,

    /// Organization ID for all operations.
    organization: OrganizationSlug,

    /// Optional vault ID for scoped operations.
    vault: Option<VaultSlug>,

    /// Read consistency level.
    read_consistency: ReadConsistency,

    /// Number of entities fetched per page during range queries.
    page_size: u32,

    /// Maximum total results from a single range query.
    max_range_results: usize,

    /// Per-operation timeout configuration.
    timeout_config: TimeoutConfig,

    /// Optional key/value size limits.
    size_limits: Option<SizeLimits>,

    /// Metrics collector for per-organization operation tracking.
    metrics: Metrics,

    /// Optional cancellation token for graceful shutdown.
    cancellation_token: Option<tokio_util::sync::CancellationToken>,

    /// Cached string representation of the organization ID for metrics.
    org_str_cached: String,
}

impl std::fmt::Debug for LedgerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerBackend")
            .field("organization", &self.organization)
            .field("vault", &self.vault)
            .field("read_consistency", &self.read_consistency)
            .finish_non_exhaustive()
    }
}

impl LedgerBackend {
    /// Creates a new Ledger backend with the given configuration.
    ///
    /// This establishes a connection to the Ledger service and validates
    /// the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration is invalid
    /// - Unable to connect to Ledger
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // Requires a running Ledger server.
    /// use inferadb_common_storage_ledger::{
    ///     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
    /// };
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ClientConfig::builder()
    ///     .servers(ServerSource::from_static(["http://localhost:50051"]))
    ///     .client_id("my-service")
    ///     .build()?;
    ///
    /// let config = LedgerBackendConfig::builder()
    ///     .client(client)
    ///     .caller(1)
    ///     .organization(1)
    ///     .build()?;
    ///
    /// let backend = LedgerBackend::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: LedgerBackendConfig) -> Result<Self> {
        let caller = config.caller();
        let organization = config.organization();
        let vault = config.vault();
        let read_consistency = config.read_consistency();
        let page_size = config.page_size();
        let max_range_results = config.max_range_results();
        let timeout_config = config.timeout_config().clone();
        let size_limits = config.size_limits();
        let cancellation_token = config.cancellation_token().cloned();

        let client = LedgerClient::new(config.into_client_config())
            .await
            .map_err(LedgerStorageError::from)?;

        Ok(Self {
            client: Arc::new(client),
            caller,
            org_str_cached: organization.to_string(),
            organization,
            vault,
            read_consistency,
            page_size,
            max_range_results,
            timeout_config,
            size_limits,
            metrics: Metrics::new(),
            cancellation_token,
        })
    }

    /// Creates a backend from an existing SDK client with default settings.
    ///
    /// Uses default timeouts, pagination, and no size limits.
    /// For customization, use [`LedgerBackendConfig::builder`] with
    /// [`ClientConfig`](inferadb_ledger_sdk::ClientConfig) instead.
    #[must_use = "constructing a backend has no side effects"]
    pub fn from_client(
        client: Arc<LedgerClient>,
        caller: UserSlug,
        organization: OrganizationSlug,
        vault: Option<VaultSlug>,
        read_consistency: ReadConsistency,
    ) -> Self {
        use crate::config::{DEFAULT_MAX_RANGE_RESULTS, DEFAULT_PAGE_SIZE};
        Self {
            client,
            caller,
            org_str_cached: organization.to_string(),
            organization,
            vault,
            read_consistency,
            page_size: DEFAULT_PAGE_SIZE,
            max_range_results: DEFAULT_MAX_RANGE_RESULTS,
            timeout_config: TimeoutConfig::default(),
            size_limits: None,
            metrics: Metrics::new(),
            cancellation_token: None,
        }
    }

    /// Creates a backend connected to a single Ledger endpoint.
    ///
    /// This is a convenience constructor for simple deployments where a
    /// single Ledger server is used with default settings (linearizable
    /// reads, default pagination).
    ///
    /// For more control over the configuration, use
    /// [`LedgerBackendConfig::builder`] directly.
    ///
    /// # Arguments
    ///
    /// * `endpoint` — The Ledger server URL (e.g., `"http://localhost:50051"`)
    /// * `client_id` — Unique identifier for this client instance
    /// * `organization` — Organization scope for all keys
    /// * `vault` — Optional vault scope within the organization
    ///
    /// # Errors
    ///
    /// Returns an error if the client configuration is invalid or the
    /// connection cannot be established.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use inferadb_common_storage_ledger::LedgerBackend;
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// // Without vault
    /// let backend = LedgerBackend::from_endpoint(
    ///     "http://localhost:50051",
    ///     "my-service",
    ///     1u64,
    ///     1u64,
    ///     None::<u64>,
    /// ).await?;
    ///
    /// // With vault
    /// let backend = LedgerBackend::from_endpoint(
    ///     "http://localhost:50051",
    ///     "my-service",
    ///     1u64,
    ///     1u64,
    ///     Some(100u64),
    /// ).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn from_endpoint(
        endpoint: &str,
        client_id: &str,
        caller: impl Into<UserSlug>,
        organization: impl Into<OrganizationSlug>,
        vault: Option<impl Into<VaultSlug>>,
    ) -> Result<Self> {
        use inferadb_ledger_sdk::{ClientConfig, ServerSource};

        use crate::config::LedgerBackendConfig;

        let client_config = ClientConfig::builder()
            .servers(ServerSource::from_static([endpoint]))
            .client_id(client_id)
            .build()
            .map_err(LedgerStorageError::from)?;

        let config = LedgerBackendConfig::builder()
            .client(client_config)
            .caller(caller)
            .organization(organization)
            .maybe_vault(vault.map(Into::into))
            .build()
            .map_err(LedgerStorageError::from)?;

        Self::new(config).await
    }

    /// Returns the organization ID.
    #[must_use = "returns a value without side effects"]
    pub fn organization(&self) -> OrganizationSlug {
        self.organization
    }

    /// Returns the vault ID if configured.
    #[must_use = "returns a value without side effects"]
    pub fn vault(&self) -> Option<VaultSlug> {
        self.vault
    }

    /// Returns the underlying SDK client.
    #[must_use = "returns a value without side effects"]
    pub fn client(&self) -> &LedgerClient {
        &self.client
    }

    /// Returns an [`Arc`] handle to the underlying SDK client.
    ///
    /// Useful when passing the client to other components that require
    /// shared ownership, such as [`LedgerSigningKeyStore`](crate::auth::LedgerSigningKeyStore).
    #[must_use = "returns a value without side effects"]
    pub fn client_arc(&self) -> Arc<LedgerClient> {
        Arc::clone(&self.client)
    }

    /// Returns the configured page size for range queries.
    #[must_use = "returns a value without side effects"]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Returns the configured maximum number of results for range queries.
    #[must_use = "returns a value without side effects"]
    pub fn max_range_results(&self) -> usize {
        self.max_range_results
    }

    /// Returns `Ok(())` if no limits are configured or sizes are within bounds.
    ///
    /// Returns [`StorageError::SizeLimitExceeded`] if limits are exceeded.
    fn check_sizes(&self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        if let Some(ref limits) = self.size_limits {
            validate_sizes(key, value, limits)?;
        }
        Ok(())
    }

    /// Returns [`StorageError::ShuttingDown`] if shutdown has been signalled, `Ok(())` otherwise.
    fn check_cancelled(&self) -> StorageResult<()> {
        if let Some(ref token) = self.cancellation_token
            && token.is_cancelled()
        {
            return Err(StorageError::shutting_down());
        }
        Ok(())
    }

    /// Signals the backend to shut down.
    ///
    /// After calling this method, new operations return
    /// [`StorageError::ShuttingDown`] immediately. In-flight SDK operations
    /// are cancelled cooperatively at the next retry boundary.
    ///
    /// If the backend was constructed without a
    /// [`CancellationToken`](tokio_util::sync::CancellationToken), this method
    /// is a no-op. To enable shutdown support, provide a token via
    /// [`LedgerBackendConfig`].
    ///
    /// This method is idempotent — calling it multiple times has no additional
    /// effect.
    pub fn shutdown(&self) {
        if let Some(ref token) = self.cancellation_token {
            token.cancel();
        }
    }

    /// Returns `true` if the backend has been signalled to shut down.
    #[must_use = "returns a value without side effects"]
    pub fn is_shutting_down(&self) -> bool {
        self.cancellation_token.as_ref().is_some_and(|t| t.is_cancelled())
    }

    /// Returns a reference to the metrics collector.
    #[must_use = "returns a value without side effects"]
    pub fn storage_metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns the organization ID as a cached string for metric recording.
    fn org_str(&self) -> &str {
        &self.org_str_cached
    }

    /// Performs a read with the configured consistency level and cancellation token.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        self.client
            .read(
                self.caller,
                self.organization,
                self.vault,
                key,
                Some(self.read_consistency),
                self.cancellation_token.clone(),
            )
            .await
            .map_err(LedgerStorageError::from)
    }

    /// Computes the expiration timestamp by adding `ttl` to the current
    /// system time.
    ///
    /// Returns the number of seconds since the Unix epoch at which the key
    /// should expire. The `Duration` is converted to whole seconds at this
    /// boundary — sub-second precision is truncated since the Ledger SDK
    /// only supports second-granularity expiration.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the system clock is set before
    /// the Unix epoch.
    pub(crate) fn compute_expiration_timestamp(ttl: Duration) -> StorageResult<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + ttl.as_secs())
            .map_err(|_| {
                StorageError::internal(
                    "system clock is before the Unix epoch; cannot compute expiration timestamp",
                )
            })
    }

    /// Internal range query without metrics wrapping.
    ///
    /// Used by both `get_range` (via `ledger_op!`) and `clear_range` to avoid
    /// double-counting metrics when `clear_range` fetches keys to delete.
    async fn get_range_inner(&self, range: StorageRange) -> StorageResult<Vec<KeyValue>> {
        // Convert range bounds to hex-encoded strings
        let (start_key, start_inclusive) = match range.start_bound() {
            Bound::Included(k) => (Some(encode_key(k)), true),
            Bound::Excluded(k) => (Some(encode_key(k)), false),
            Bound::Unbounded => (None, true),
        };

        let (end_key, end_inclusive) = match range.end_bound() {
            Bound::Included(k) => (Some(encode_key(k)), true),
            Bound::Excluded(k) => (Some(encode_key(k)), false),
            Bound::Unbounded => (None, true),
        };

        // Longest common prefix of start and end minimizes server-side scanning.
        let prefix = match (&start_key, &end_key) {
            (Some(start), Some(end)) => {
                let len = common_prefix_len(start, end);
                start[..len].to_owned()
            },
            (Some(start), None) => start.clone(),
            (None, _) => String::new(),
        };

        // Paginate through results, bounded by list timeout.
        let list_timeout = self.timeout_config.list_timeout;
        tokio::time::timeout(list_timeout, async {
            let mut all_key_values = Vec::new();
            let mut page_token: Option<String> = None;

            loop {
                self.check_cancelled()?;

                let opts = ListEntitiesOpts {
                    key_prefix: prefix.clone(),
                    at_height: None,
                    include_expired: false,
                    limit: self.page_size,
                    page_token: page_token.take(),
                    consistency: self.read_consistency,
                    vault: self.vault,
                };

                let result = self
                    .client
                    .list_entities(self.caller, self.organization, opts)
                    .await
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

                if all_key_values.is_empty() {
                    all_key_values.reserve(result.items.len());
                }

                for entity in &result.items {
                    let after_start = match &start_key {
                        Some(start) if start_inclusive => &entity.key >= start,
                        Some(start) => &entity.key > start,
                        None => true,
                    };

                    let before_end = match &end_key {
                        Some(end) if end_inclusive => &entity.key <= end,
                        Some(end) => &entity.key < end,
                        None => true,
                    };

                    if after_start && before_end {
                        match decode_key(&entity.key) {
                            Ok(key) => {
                                all_key_values.push(KeyValue {
                                    key: Bytes::from(key),
                                    value: Bytes::from(entity.value.clone()),
                                });
                            },
                            Err(e) => {
                                tracing::warn!(key = entity.key, "Failed to decode key: {}", e);
                            },
                        }
                    }
                }

                if all_key_values.len() > self.max_range_results {
                    return Err(StorageError::range_limit_exceeded(
                        all_key_values.len(),
                        self.max_range_results,
                    ));
                }

                if result.has_next_page() {
                    page_token = result.next_page_token;
                } else {
                    break;
                }
            }

            all_key_values.sort_by(|a, b| a.key.cmp(&b.key));
            Ok(all_key_values)
        })
        .await
        .unwrap_or_else(|_| Err(StorageError::timeout()))
    }
}

impl inferadb_common_storage::MetricsCollector for LedgerBackend {
    fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

/// Wraps a [`LedgerBackend`] operation with standard prologue and epilogue:
///
/// **Prologue:** `check_cancelled`, optional `check_sizes`.
/// **Epilogue:** per-operation metric, error metric.
///
/// # Usage
///
/// ```text
/// ledger_op!(self, record_get_org, { async body })
/// ledger_op!(self, record_set_org, sizes(&key, &value), { async body })
/// ```
macro_rules! ledger_op {
    ($self:expr, $metric:ident,sizes($key:expr, $val:expr), $body:block) => {{
        $self.check_cancelled()?;
        $self.check_sizes($key, $val)?;
        let start = std::time::Instant::now();
        let result = $body;
        let org = $self.org_str();
        $self.metrics.$metric(start.elapsed(), org);
        if result.is_err() {
            $self.metrics.record_error_org(org);
        }
        result
    }};
    ($self:expr, $metric:ident, $body:block) => {{
        $self.check_cancelled()?;
        let start = std::time::Instant::now();
        let result = $body;
        let org = $self.org_str();
        $self.metrics.$metric(start.elapsed(), org);
        if result.is_err() {
            $self.metrics.record_error_org(org);
        }
        result
    }};
}

#[async_trait]
impl StorageBackend for LedgerBackend {
    /// Reads a value by key, respecting the configured read consistency level.
    #[tracing::instrument(skip(self, key), fields(key_len = key.len()))]
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        ledger_op!(self, record_get_org, {
            let encoded_key = encode_key(key);
            tokio::time::timeout(self.timeout_config.read_timeout, async {
                match self.do_read(&encoded_key).await {
                    Ok(Some(value)) => Ok(Some(Bytes::from(value))),
                    Ok(None) => Ok(None),
                    Err(e) => Err(StorageError::from(e)),
                }
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Stores a key-value pair in the Ledger.
    #[tracing::instrument(skip(self, key, value), fields(key_len = key.len(), value_len = value.len()))]
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        ledger_op!(self, record_set_org, sizes(&key, &value), {
            let encoded_key = encode_key(&key);
            tokio::time::timeout(self.timeout_config.write_timeout, async {
                self.client
                    .set_entity(
                        self.caller,
                        self.organization,
                        self.vault,
                        encoded_key,
                        value,
                        None,
                        None,
                        self.cancellation_token.clone(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Performs a compare-and-set operation.
    ///
    /// Conflict errors (`FailedPrecondition`) are **not** retried — they propagate
    /// immediately as [`StorageError::Conflict`].
    #[tracing::instrument(skip(self, key, expected, new_value), fields(key_len = key.len()))]
    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        ledger_op!(self, record_cas_org, sizes(key, &new_value), {
            let encoded_key = encode_key(key);
            let condition = SetCondition::from_expected(expected.map(|v| v.to_vec()));
            tokio::time::timeout(self.timeout_config.write_timeout, async {
                match self
                    .client
                    .set_entity(
                        self.caller,
                        self.organization,
                        self.vault,
                        encoded_key,
                        new_value,
                        None,
                        Some(condition),
                        self.cancellation_token.clone(),
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) if e.is_cas_conflict() => Err(StorageError::conflict()),
                    Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
                }
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Removes a key and its value from the Ledger.
    #[tracing::instrument(skip(self, key), fields(key_len = key.len()))]
    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        ledger_op!(self, record_delete_org, {
            let encoded_key = encode_key(key);
            tokio::time::timeout(self.timeout_config.write_timeout, async {
                self.client
                    .delete_entity(
                        self.caller,
                        self.organization,
                        self.vault,
                        encoded_key,
                        self.cancellation_token.clone(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Scans a key range with server-side pagination and prefix optimization.
    #[tracing::instrument(skip(self, range))]
    async fn get_range(&self, range: StorageRange) -> StorageResult<Vec<KeyValue>> {
        ledger_op!(self, record_get_range_org, { self.get_range_inner(range).await })
    }

    /// Deletes all keys in a range using a two-phase get-then-delete approach.
    #[tracing::instrument(skip(self, range))]
    async fn clear_range(&self, range: StorageRange) -> StorageResult<()> {
        ledger_op!(self, record_clear_range_org, {
            let keys_to_delete = self.get_range_inner(range).await?;

            if keys_to_delete.is_empty() {
                return Ok(());
            }

            let operations: Vec<_> = keys_to_delete
                .into_iter()
                .map(|kv| Operation::delete_entity(encode_key(&kv.key)))
                .collect();

            // Use list_timeout (not write_timeout) because the batch delete
            // size correlates with the preceding range scan, which also uses
            // list_timeout. A narrow write_timeout would fail for large ranges.
            tokio::time::timeout(self.timeout_config.list_timeout, async {
                self.client
                    .write(
                        self.caller,
                        self.organization,
                        self.vault,
                        operations,
                        self.cancellation_token.clone(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Stores a key-value pair with automatic expiration.
    ///
    /// Computes an absolute Unix timestamp by adding the `ttl` duration to the
    /// current system time. Sub-second precision in `ttl` is truncated.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the system clock is set before
    /// the Unix epoch, since a valid absolute timestamp cannot be computed.
    #[tracing::instrument(skip(self, key, value), fields(key_len = key.len(), value_len = value.len(), ttl_ms = ttl.as_millis() as u64))]
    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        ledger_op!(self, record_set_org, sizes(&key, &value), {
            let encoded_key = encode_key(&key);
            let expires_at = Self::compute_expiration_timestamp(ttl)?;
            tokio::time::timeout(self.timeout_config.write_timeout, async {
                self.client
                    .set_entity(
                        self.caller,
                        self.organization,
                        self.vault,
                        encoded_key,
                        value,
                        Some(expires_at),
                        None,
                        self.cancellation_token.clone(),
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Performs a compare-and-set operation with TTL.
    ///
    /// Combines CAS precondition checking with automatic key expiration.
    /// Conflict errors (`FailedPrecondition`) are **not** retried.
    #[tracing::instrument(skip(self, key, expected, new_value), fields(key_len = key.len(), ttl_ms = ttl.as_millis() as u64))]
    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        ledger_op!(self, record_cas_org, sizes(key, &new_value), {
            let encoded_key = encode_key(key);
            let expires_at = Self::compute_expiration_timestamp(ttl)?;
            let condition = SetCondition::from_expected(expected.map(|v| v.to_vec()));
            tokio::time::timeout(self.timeout_config.write_timeout, async {
                match self
                    .client
                    .set_entity(
                        self.caller,
                        self.organization,
                        self.vault,
                        encoded_key,
                        new_value,
                        Some(expires_at),
                        Some(condition),
                        self.cancellation_token.clone(),
                    )
                    .await
                {
                    Ok(_) => Ok(()),
                    Err(e) if e.is_cas_conflict() => Err(StorageError::conflict()),
                    Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
                }
            })
            .await
            .unwrap_or_else(|_| Err(StorageError::timeout()))
        })
    }

    /// Creates a new [`LedgerTransaction`] for buffered atomic writes.
    #[tracing::instrument(skip(self))]
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        ledger_op!(self, record_transaction_org, {
            let txn = LedgerTransaction::new(
                Arc::clone(&self.client),
                self.caller,
                self.organization,
                self.vault,
                self.read_consistency,
                self.cancellation_token.clone(),
            );
            Ok(Box::new(txn) as Box<dyn Transaction>)
        })
    }

    /// Checks backend connectivity.
    #[tracing::instrument(skip(self))]
    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        let start = std::time::Instant::now();

        match probe {
            HealthProbe::Liveness => {
                // Liveness: verify the async runtime is responsive.
                // No external I/O — a deadlocked runtime won't reach this point.
                let metadata = HealthMetadata::new(start.elapsed(), "ledger")
                    .with_detail("probe", "liveness".to_owned());
                Ok(HealthStatus::healthy(metadata))
            },
            HealthProbe::Readiness | HealthProbe::Startup => {
                // Readiness/Startup: probe the ledger connection.
                let result = tokio::time::timeout(self.timeout_config.read_timeout, async {
                    self.client
                        .health_check()
                        .await
                        .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;
                    Ok(())
                })
                .await
                .unwrap_or_else(|_| Err(StorageError::timeout()));

                let check_duration = start.elapsed();
                let metadata = HealthMetadata::new(check_duration, "ledger")
                    .with_detail("probe", probe.to_string())
                    .with_detail("connection_latency_ms", check_duration.as_millis().to_string());

                match result {
                    Ok(()) => Ok(HealthStatus::healthy(metadata)),
                    Err(e) => Err(e),
                }
            },
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::ascii(b"hello world" as &[u8])]
    #[case::binary(&[0x00, 0x01, 0xFF, 0xFE, 0x00])]
    #[case::empty(b"")]
    fn test_key_encoding_roundtrip(#[case] original: &[u8]) {
        let encoded = encode_key(original);
        let decoded = decode_key(&encoded).unwrap();
        assert_eq!(original, decoded.as_slice());
    }

    #[test]
    fn test_key_encoding_preserves_order() {
        let k1 = b"aaa";
        let k2 = b"aab";
        let k3 = b"bbb";

        let e1 = encode_key(k1);
        let e2 = encode_key(k2);
        let e3 = encode_key(k3);

        assert!(e1 < e2);
        assert!(e2 < e3);
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_key("invalid-hex-gg");
        assert!(result.is_err());
    }

    #[rstest]
    #[case::partial_match("abc", "abd", 2)]
    #[case::longer_prefix("hello", "help", 3)]
    #[case::no_match("abc", "xyz", 0)]
    #[case::identical("same", "same", 4)]
    #[case::empty_left("", "anything", 0)]
    #[case::empty_right("anything", "", 0)]
    #[case::both_empty("", "", 0)]
    #[case::slice_check("abcdef", "abcxyz", 3)]
    fn test_common_prefix_len(#[case] a: &str, #[case] b: &str, #[case] expected: usize) {
        assert_eq!(common_prefix_len(a, b), expected);
    }

    #[test]
    fn test_expiration_timestamp_is_in_the_future() {
        let ttl = Duration::from_secs(300);
        let before =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let expires_at = LedgerBackend::compute_expiration_timestamp(ttl).unwrap();

        let after =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let ttl_secs = ttl.as_secs();
        // The expiration timestamp must be at least `before + ttl_secs`
        // and at most `after + ttl_secs` (accounting for wall-clock drift
        // between the two SystemTime::now() calls).
        assert!(
            expires_at >= before + ttl_secs,
            "expiration {expires_at} should be >= {}",
            before + ttl_secs,
        );
        assert!(
            expires_at <= after + ttl_secs,
            "expiration {expires_at} should be <= {}",
            after + ttl_secs,
        );
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            /// The common prefix length must never exceed either string's length,
            /// and the prefix at that length must actually be shared.
            #[test]
            fn common_prefix_len_is_shared_prefix(
                a in "[a-f0-9]{0,64}",
                b in "[a-f0-9]{0,64}",
            ) {
                let len = common_prefix_len(&a, &b);
                prop_assert!(len <= a.len());
                prop_assert!(len <= b.len());
                prop_assert_eq!(&a[..len], &b[..len]);
            }

            /// The prefix must be maximal: if both strings have at least one more byte
            /// after the prefix, those bytes must differ.
            #[test]
            fn common_prefix_len_is_maximal(
                a in "[a-f0-9]{1,64}",
                b in "[a-f0-9]{1,64}",
            ) {
                let len = common_prefix_len(&a, &b);
                if len < a.len() && len < b.len() {
                    prop_assert_ne!(a.as_bytes()[len], b.as_bytes()[len]);
                }
            }

            /// Identical strings must have a common prefix equal to the full length.
            #[test]
            fn common_prefix_len_of_identical_strings(s in "[a-f0-9]{0,64}") {
                prop_assert_eq!(common_prefix_len(&s, &s), s.len());
            }

            /// common_prefix_len must be symmetric.
            #[test]
            fn common_prefix_len_is_symmetric(
                a in "[a-f0-9]{0,64}",
                b in "[a-f0-9]{0,64}",
            ) {
                prop_assert_eq!(common_prefix_len(&a, &b), common_prefix_len(&b, &a));
            }
        }
    }
}
