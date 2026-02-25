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
    StorageBackend, StorageError, StorageResult, Transaction, VaultSlug, validate_sizes,
};
use inferadb_ledger_sdk::{
    LedgerClient, ListEntitiesOpts, Operation, ReadConsistency, SetCondition,
};

use crate::{
    config::{LedgerBackendConfig, RetryConfig, TimeoutConfig},
    error::{LedgerStorageError, Result},
    keys::{decode_key, encode_key},
    retry::{with_retry, with_retry_timeout},
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

    /// Retry configuration for transient failures.
    retry_config: RetryConfig,

    /// Per-operation timeout configuration.
    timeout_config: TimeoutConfig,

    /// Optional key/value size limits.
    size_limits: Option<SizeLimits>,

    /// Optional circuit breaker for fail-fast during backend outages.
    circuit_breaker: Option<crate::circuit_breaker::CircuitBreaker>,

    /// Metrics collector for per-organization operation tracking.
    metrics: Metrics,

    /// Optional cancellation token for graceful shutdown.
    cancellation_token: Option<tokio_util::sync::CancellationToken>,
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
    ///     .organization(1)
    ///     .build()?;
    ///
    /// let backend = LedgerBackend::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: LedgerBackendConfig) -> Result<Self> {
        let organization = config.organization();
        let vault = config.vault();
        let read_consistency = config.read_consistency();
        let page_size = config.page_size();
        let max_range_results = config.max_range_results();
        let retry_config = config.retry_config().clone();
        let timeout_config = config.timeout_config().clone();
        let size_limits = config.size_limits();
        let circuit_breaker = config
            .circuit_breaker_config()
            .cloned()
            .map(crate::circuit_breaker::CircuitBreaker::new);
        let cancellation_token = config.cancellation_token().cloned();

        let client = LedgerClient::new(config.into_client_config())
            .await
            .map_err(LedgerStorageError::from)?;

        Ok(Self {
            client: Arc::new(client),
            organization,
            vault,
            read_consistency,
            page_size,
            max_range_results,
            retry_config,
            timeout_config,
            size_limits,
            circuit_breaker,
            metrics: Metrics::new(),
            cancellation_token,
        })
    }

    /// Creates a backend from an existing SDK client.
    ///
    /// This is useful when you want to share a client across multiple
    /// backend instances or when you need more control over client lifecycle.
    ///
    /// Uses default pagination settings ([`DEFAULT_PAGE_SIZE`] and
    /// [`DEFAULT_MAX_RANGE_RESULTS`]).
    ///
    /// [`DEFAULT_PAGE_SIZE`]: crate::config::DEFAULT_PAGE_SIZE
    /// [`DEFAULT_MAX_RANGE_RESULTS`]: crate::config::DEFAULT_MAX_RANGE_RESULTS
    #[must_use = "constructing a backend has no side effects"]
    pub fn from_client(
        client: Arc<LedgerClient>,
        organization: OrganizationSlug,
        vault: Option<VaultSlug>,
        read_consistency: ReadConsistency,
    ) -> Self {
        use crate::config::{DEFAULT_MAX_RANGE_RESULTS, DEFAULT_PAGE_SIZE};
        Self {
            client,
            organization,
            vault,
            read_consistency,
            page_size: DEFAULT_PAGE_SIZE,
            max_range_results: DEFAULT_MAX_RANGE_RESULTS,
            retry_config: RetryConfig::default(),
            timeout_config: TimeoutConfig::default(),
            size_limits: None,
            circuit_breaker: None,
            metrics: Metrics::new(),
            cancellation_token: None,
        }
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

    /// Returns the vault slug as `Option<u64>` for SDK calls that expect a raw value.
    fn vault_raw(&self) -> Option<u64> {
        self.vault.map(u64::from)
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

    /// Returns [`StorageError::CircuitOpen`] if the circuit breaker is open, `Ok(())` otherwise.
    fn check_circuit(&self) -> StorageResult<()> {
        if let Some(ref cb) = self.circuit_breaker
            && !cb.allow_request()
        {
            return Err(StorageError::circuit_open());
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
    /// [`StorageError::ShuttingDown`] immediately. In-flight operations that
    /// already passed the cancellation check are allowed to complete.
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

    /// Records a storage result with the circuit breaker.
    ///
    /// Only transient errors (connection, timeout) are recorded as failures.
    fn record_circuit_result<T>(&self, result: &StorageResult<T>) {
        if let Some(ref cb) = self.circuit_breaker {
            match result {
                Ok(_) => cb.record_success(),
                Err(e) if e.is_transient() => cb.record_failure(),
                Err(_) => {
                    // Non-transient errors (NotFound, Conflict, etc.) don't indicate
                    // backend health issues — don't affect circuit breaker state.
                },
            }
        }
    }

    /// Returns the circuit breaker metrics, if a circuit breaker is configured.
    #[must_use = "returns a value without side effects"]
    pub fn circuit_breaker_metrics(&self) -> Option<crate::circuit_breaker::CircuitBreakerMetrics> {
        self.circuit_breaker.as_ref().map(crate::circuit_breaker::CircuitBreaker::metrics)
    }

    /// Returns the current circuit breaker state, if a circuit breaker is configured.
    #[must_use = "returns a value without side effects"]
    pub fn circuit_breaker_state(&self) -> Option<crate::circuit_breaker::CircuitState> {
        self.circuit_breaker.as_ref().map(crate::circuit_breaker::CircuitBreaker::state)
    }

    /// Returns a reference to the metrics collector.
    #[must_use = "returns a value without side effects"]
    pub fn storage_metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// Returns the organization ID as a string for metric recording.
    fn org_str(&self) -> String {
        self.organization.to_string()
    }

    /// Performs a read with the configured consistency level.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => {
                self.client.read_consistent(self.organization, self.vault_raw(), key).await
            },
            ReadConsistency::Eventual => {
                self.client.read(self.organization, self.vault_raw(), key).await
            },
        };

        result.map_err(LedgerStorageError::from)
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
    fn compute_expiration_timestamp(ttl: Duration) -> StorageResult<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + ttl.as_secs())
            .map_err(|_| {
                StorageError::internal(
                    "system clock is before the Unix epoch; cannot compute expiration timestamp",
                )
            })
    }
}

impl inferadb_common_storage::MetricsCollector for LedgerBackend {
    fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

#[async_trait]
impl StorageBackend for LedgerBackend {
    /// Reads a value by key, respecting the configured read consistency level.
    #[tracing::instrument(skip(self, key), fields(key_len = key.len()))]
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        self.check_cancelled()?;
        self.check_circuit()?;
        let start = std::time::Instant::now();
        let encoded_key = encode_key(key);

        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.read_timeout,
            None,
            "get",
            || async {
                match self.do_read(&encoded_key).await {
                    Ok(Some(value)) => Ok(Some(Bytes::from(value))),
                    Ok(None) => Ok(None),
                    Err(e) => Err(StorageError::from(e)),
                }
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_get_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Stores a key-value pair in the Ledger.
    #[tracing::instrument(skip(self, key, value), fields(key_len = key.len(), value_len = value.len()))]
    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        self.check_cancelled()?;
        self.check_circuit()?;
        self.check_sizes(&key, &value)?;
        let start = std::time::Instant::now();
        let encoded_key = encode_key(&key);

        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.write_timeout,
            None,
            "set",
            || async {
                self.client
                    .write(
                        self.organization,
                        self.vault_raw(),
                        vec![Operation::set_entity(encoded_key.clone(), value.clone())],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_set_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Performs a compare-and-set operation, retrying on transient errors.
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
        self.check_cancelled()?;
        self.check_circuit()?;
        self.check_sizes(key, &new_value)?;
        let start = std::time::Instant::now();
        let encoded_key = encode_key(key);

        let condition = match expected {
            None => SetCondition::NotExists,
            Some(expected_value) => SetCondition::ValueEquals(expected_value.to_vec()),
        };

        use inferadb_ledger_sdk::SdkError;
        use tonic::Code;

        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.write_timeout,
            None,
            "compare_and_set",
            || async {
                match self
                    .client
                    .write(
                        self.organization,
                        self.vault_raw(),
                        vec![Operation::set_entity_if(
                            encoded_key.clone(),
                            new_value.clone(),
                            condition.clone(),
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
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_set_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Removes a key and its value from the Ledger.
    #[tracing::instrument(skip(self, key), fields(key_len = key.len()))]
    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.check_cancelled()?;
        self.check_circuit()?;
        let start = std::time::Instant::now();
        let encoded_key = encode_key(key);

        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.write_timeout,
            None,
            "delete",
            || async {
                self.client
                    .write(
                        self.organization,
                        self.vault_raw(),
                        vec![Operation::delete_entity(encoded_key.clone())],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_delete_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Scans a key range with server-side pagination and prefix optimization.
    #[tracing::instrument(skip(self, range))]
    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.check_cancelled()?;
        self.check_circuit()?;
        let start = std::time::Instant::now();

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

        // Find common prefix between start and end for efficient scanning.
        // For range queries, we use the longest common prefix of start and end
        // to minimize the number of entities returned by the server.
        //
        // Uses common_prefix_len to compute the prefix length without allocating,
        // then slices into one of the existing strings to build the prefix.
        let prefix = match (&start_key, &end_key) {
            (Some(start), Some(end)) => {
                let len = common_prefix_len(start, end);
                start[..len].to_owned()
            },
            (Some(start), None) => start.clone(),
            (None, Some(_)) => {
                // common_prefix_len("", end) is always 0, so prefix is empty
                String::new()
            },
            (None, None) => String::new(),
        };

        // Paginate through results using page_token, bounded by list timeout.
        let list_timeout = self.timeout_config.list_timeout;
        let result = tokio::time::timeout(list_timeout, async {
            let mut all_key_values = Vec::new();
            let mut page_token: Option<String> = None;

            loop {
                let current_page_token = page_token.take();
                let prefix_clone = prefix.clone();

                let result = with_retry(&self.retry_config, None, "get_range_page", || async {
                    let opts = ListEntitiesOpts {
                        key_prefix: prefix_clone.clone(),
                        at_height: None,
                        include_expired: false,
                        limit: self.page_size,
                        page_token: current_page_token.clone(),
                        consistency: self.read_consistency,
                        vault_slug: self.vault_raw(),
                    };

                    self.client
                        .list_entities(self.organization, opts)
                        .await
                        .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
                })
                .await?;

                // Pre-allocate on the first page to reduce reallocations
                if all_key_values.is_empty() {
                    all_key_values.reserve(result.items.len());
                }

                // Filter results to match exact range bounds
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
                                // Skip malformed keys
                            },
                        }
                    }
                }

                // Check safety bound before continuing to the next page
                if all_key_values.len() > self.max_range_results {
                    return Err(StorageError::internal(format!(
                        "range query exceeded safety limit of {} results (got {}); \
                         increase max_range_results in LedgerBackendConfig if this is expected",
                        self.max_range_results,
                        all_key_values.len(),
                    )));
                }

                // Continue to next page or break
                if result.has_next_page() {
                    page_token = result.next_page_token;
                } else {
                    break;
                }
            }

            // Sort by key to ensure consistent ordering
            all_key_values.sort_by(|a, b| a.key.cmp(&b.key));

            Ok(all_key_values)
        })
        .await
        .unwrap_or(Err(StorageError::timeout()));
        self.record_circuit_result(&result);
        self.metrics.record_get_range_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Deletes all keys in a range using a two-phase get-then-delete approach.
    #[tracing::instrument(skip(self, range))]
    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.check_cancelled()?;
        self.check_circuit()?;
        let start = std::time::Instant::now();

        // First, get all keys in the range (retried per-page internally)
        let keys_to_delete = self.get_range(range).await?;

        if keys_to_delete.is_empty() {
            return Ok(());
        }

        // Build delete operations
        let operations: Vec<_> = keys_to_delete
            .into_iter()
            .map(|kv| Operation::delete_entity(encode_key(&kv.key)))
            .collect();

        // Execute as batch delete with retry and timeout
        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.list_timeout,
            None,
            "clear_range",
            || async {
                self.client
                    .write(self.organization, self.vault_raw(), operations.clone())
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_clear_range_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Stores a key-value pair with automatic expiration.
    ///
    /// Computes an absolute Unix timestamp by adding the `ttl` duration to the
    /// current system time. The Ledger SDK's `set_entity_with_expiry`
    /// interprets this value as an absolute expiration timestamp in seconds
    /// since the Unix epoch. Sub-second precision in `ttl` is truncated.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the system clock is set before
    /// the Unix epoch, since a valid absolute timestamp cannot be computed.
    #[tracing::instrument(skip(self, key, value), fields(key_len = key.len(), value_len = value.len(), ttl_ms = ttl.as_millis() as u64))]
    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        self.check_cancelled()?;
        self.check_circuit()?;
        self.check_sizes(&key, &value)?;
        let start = std::time::Instant::now();
        let encoded_key = encode_key(&key);
        let expires_at = Self::compute_expiration_timestamp(ttl)?;

        let result = with_retry_timeout(
            &self.retry_config,
            self.timeout_config.write_timeout,
            None,
            "set_with_ttl",
            || async {
                self.client
                    .write(
                        self.organization,
                        self.vault_raw(),
                        vec![Operation::set_entity_with_expiry(
                            encoded_key.clone(),
                            value.clone(),
                            expires_at,
                        )],
                    )
                    .await
                    .map(|_| ())
                    .map_err(|e| StorageError::from(LedgerStorageError::from(e)))
            },
        )
        .await;
        self.record_circuit_result(&result);
        self.metrics.record_set_org(start.elapsed(), &self.org_str());
        if result.is_err() {
            self.metrics.record_error_org(&self.org_str());
        }
        result
    }

    /// Creates a new [`LedgerTransaction`] for buffered atomic writes.
    #[tracing::instrument(skip(self))]
    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        self.check_cancelled()?;
        self.check_circuit()?;
        let start = std::time::Instant::now();
        let txn = LedgerTransaction::new(
            Arc::clone(&self.client),
            self.organization,
            self.vault,
            self.read_consistency,
        );
        self.metrics.record_transaction_org(start.elapsed(), &self.org_str());
        Ok(Box::new(txn))
    }

    /// Checks backend connectivity, bypassing the circuit breaker.
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
                // Health checks bypass the circuit breaker — they are used to probe
                // backend health and should always attempt a real connection.
                let result = with_retry_timeout(
                    &self.retry_config,
                    self.timeout_config.read_timeout,
                    None,
                    "health_check",
                    || async {
                        self.client
                            .health_check()
                            .await
                            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;
                        Ok(())
                    },
                )
                .await;
                self.record_circuit_result(&result);

                let check_duration = start.elapsed();
                let mut metadata = HealthMetadata::new(check_duration, "ledger")
                    .with_detail("probe", probe.to_string())
                    .with_detail("connection_latency_ms", check_duration.as_millis().to_string());

                if let Some(cb_state) = self.circuit_breaker_state() {
                    metadata =
                        metadata.with_detail("circuit_breaker_state", format!("{cb_state:?}"));
                }

                match result {
                    Ok(()) => {
                        if let Some(crate::circuit_breaker::CircuitState::HalfOpen) =
                            self.circuit_breaker_state()
                        {
                            Ok(HealthStatus::degraded(metadata, "circuit breaker half-open"))
                        } else {
                            Ok(HealthStatus::healthy(metadata))
                        }
                    },
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
