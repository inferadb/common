//! Configuration for the Ledger storage backend.
//!
//! This module provides [`LedgerBackendConfig`] which configures the connection
//! to Ledger and determines how keys are scoped within the Ledger namespace.
//!
//! All configuration structs validate their fields at construction time via
//! fallible builders. Defaults always pass validation.

use std::time::Duration;

use inferadb_common_storage::{ConfigError, NamespaceId, SizeLimits, VaultId};
use inferadb_ledger_sdk::{ClientConfig, ReadConsistency};

/// Default number of entities fetched per page during range queries.
pub const DEFAULT_PAGE_SIZE: u32 = 10_000;

/// Default upper safety bound on the total number of results returned
/// by a single `get_range` call across all pages.
pub const DEFAULT_MAX_RANGE_RESULTS: usize = 100_000;

/// Default maximum number of retry attempts for transient failures.
pub const DEFAULT_MAX_RETRIES: u32 = 3;

/// Default initial backoff duration between retries.
pub const DEFAULT_INITIAL_BACKOFF: Duration = Duration::from_millis(100);

/// Default maximum backoff duration between retries.
pub const DEFAULT_MAX_BACKOFF: Duration = Duration::from_secs(5);

/// Default timeout for read operations (get, health_check).
pub const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Default timeout for write operations (set, delete, compare_and_set, set_with_ttl).
pub const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(10);

/// Default timeout for list operations (get_range, clear_range).
pub const DEFAULT_LIST_TIMEOUT: Duration = Duration::from_secs(30);

/// Retry policy for transient Ledger failures.
///
/// When a storage operation fails with a transient error (connection,
/// timeout, rate limiting), the operation is retried with exponential
/// backoff. Non-transient errors (conflict, serialization, not-found)
/// are returned immediately without retry.
///
/// # Backoff Strategy
///
/// Each retry doubles the backoff duration, starting from
/// `initial_backoff`, up to `max_backoff`. Random jitter (0–50% of
/// the computed delay) is added to prevent thundering-herd effects.
///
/// # Validation
///
/// - `initial_backoff` must be positive (`> Duration::ZERO`)
/// - `max_backoff` must be `>= initial_backoff`
///
/// Set `max_retries` to `0` to disable retries entirely.
///
/// # Example
///
/// ```
/// use std::time::Duration;
///
/// use inferadb_common_storage_ledger::RetryConfig;
///
/// let config = RetryConfig::builder()
///     .max_retries(5)
///     .initial_backoff(Duration::from_millis(200))
///     .max_backoff(Duration::from_secs(10))
///     .build()
///     .expect("valid config");
///
/// assert_eq!(config.max_retries(), 5);
/// ```
#[derive(Debug, Clone)]
pub struct RetryConfig {
    /// Maximum number of retry attempts. Set to `0` to disable retries.
    pub(crate) max_retries: u32,

    /// Initial backoff duration. Doubles with each subsequent attempt.
    pub(crate) initial_backoff: Duration,

    /// Upper bound on the backoff duration.
    pub(crate) max_backoff: Duration,
}

#[bon::bon]
impl RetryConfig {
    /// Creates a new retry configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if:
    /// - `initial_backoff` is zero
    /// - `max_backoff < initial_backoff`
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_MAX_RETRIES)] max_retries: u32,
        #[builder(default = DEFAULT_INITIAL_BACKOFF)] initial_backoff: Duration,
        #[builder(default = DEFAULT_MAX_BACKOFF)] max_backoff: Duration,
    ) -> Result<Self, ConfigError> {
        if initial_backoff.is_zero() {
            return Err(ConfigError::MustBePositive {
                field: "initial_backoff",
                value: format!("{initial_backoff:?}"),
            });
        }
        if max_backoff < initial_backoff {
            return Err(ConfigError::InvalidRelation {
                field_a: "initial_backoff",
                value_a: format!("{initial_backoff:?}"),
                field_b: "max_backoff",
                value_b: format!("{max_backoff:?}"),
            });
        }
        Ok(Self { max_retries, initial_backoff, max_backoff })
    }

    /// Returns the maximum number of retry attempts.
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns the initial backoff duration.
    #[must_use]
    pub fn initial_backoff(&self) -> Duration {
        self.initial_backoff
    }

    /// Returns the maximum backoff duration.
    #[must_use]
    pub fn max_backoff(&self) -> Duration {
        self.max_backoff
    }
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: DEFAULT_MAX_RETRIES,
            initial_backoff: DEFAULT_INITIAL_BACKOFF,
            max_backoff: DEFAULT_MAX_BACKOFF,
        }
    }
}

/// Default maximum number of CAS retry attempts on conflict.
pub const DEFAULT_MAX_CAS_RETRIES: u32 = 5;

/// Default base delay between CAS retry attempts.
///
/// Jitter (0–100% of the base delay) is added to each retry to reduce
/// contention among concurrent writers.
pub const DEFAULT_CAS_RETRY_BASE_DELAY: Duration = Duration::from_millis(50);

/// Retry policy for compare-and-set (CAS) conflicts.
///
/// CAS conflicts occur when a concurrent writer modifies the same key
/// between a read and a conditional write. Unlike transient errors
/// (handled by [`RetryConfig`]), CAS conflicts require re-reading the
/// current value before retrying — the entire read-modify-write cycle
/// must be repeated.
///
/// # Backoff Strategy
///
/// Each retry waits `base_delay + random(0..base_delay)`. The uniform
/// jitter reduces contention when multiple writers target the same key.
///
/// # Example
///
/// ```
/// use std::time::Duration;
///
/// use inferadb_common_storage_ledger::CasRetryConfig;
///
/// let config = CasRetryConfig::builder()
///     .max_retries(3)
///     .base_delay(Duration::from_millis(100))
///     .build();
///
/// assert_eq!(config.max_retries(), 3);
/// ```
#[derive(Debug, Clone)]
pub struct CasRetryConfig {
    /// Maximum number of CAS retry attempts. A value of `0` disables
    /// CAS retries, causing the first conflict to propagate immediately.
    pub(crate) max_retries: u32,

    /// Base delay between CAS retry attempts. Jitter is added on top.
    pub(crate) base_delay: Duration,
}

#[bon::bon]
impl CasRetryConfig {
    /// Creates a new CAS retry configuration.
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_MAX_CAS_RETRIES)] max_retries: u32,
        #[builder(default = DEFAULT_CAS_RETRY_BASE_DELAY)] base_delay: Duration,
    ) -> Self {
        Self { max_retries, base_delay }
    }

    /// Returns the maximum number of CAS retry attempts.
    #[must_use]
    pub fn max_retries(&self) -> u32 {
        self.max_retries
    }

    /// Returns the base delay between CAS retry attempts.
    #[must_use]
    pub fn base_delay(&self) -> Duration {
        self.base_delay
    }
}

impl Default for CasRetryConfig {
    fn default() -> Self {
        Self { max_retries: DEFAULT_MAX_CAS_RETRIES, base_delay: DEFAULT_CAS_RETRY_BASE_DELAY }
    }
}

/// Per-operation timeout configuration for Ledger storage operations.
///
/// Provides separate timeout durations for reads, writes, and list
/// operations, reflecting their different expected latency profiles.
/// The timeout bounds the total wall-clock time of an operation,
/// including all retry attempts.
///
/// # Validation
///
/// All three timeout durations must be positive (`> Duration::ZERO`).
///
/// # Example
///
/// ```
/// use std::time::Duration;
///
/// use inferadb_common_storage_ledger::TimeoutConfig;
///
/// let config = TimeoutConfig::builder()
///     .read_timeout(Duration::from_secs(3))
///     .write_timeout(Duration::from_secs(8))
///     .list_timeout(Duration::from_secs(20))
///     .build()
///     .expect("valid config");
///
/// assert_eq!(config.read_timeout(), Duration::from_secs(3));
/// ```
#[derive(Debug, Clone)]
pub struct TimeoutConfig {
    /// Timeout for read operations (`get`, `health_check`).
    pub(crate) read_timeout: Duration,

    /// Timeout for write operations (`set`, `delete`, `compare_and_set`,
    /// `set_with_ttl`).
    pub(crate) write_timeout: Duration,

    /// Timeout for list operations (`get_range`, `clear_range`).
    pub(crate) list_timeout: Duration,
}

#[bon::bon]
impl TimeoutConfig {
    /// Creates a new timeout configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if any timeout duration is zero.
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_READ_TIMEOUT)] read_timeout: Duration,
        #[builder(default = DEFAULT_WRITE_TIMEOUT)] write_timeout: Duration,
        #[builder(default = DEFAULT_LIST_TIMEOUT)] list_timeout: Duration,
    ) -> Result<Self, ConfigError> {
        if read_timeout.is_zero() {
            return Err(ConfigError::MustBePositive {
                field: "read_timeout",
                value: format!("{read_timeout:?}"),
            });
        }
        if write_timeout.is_zero() {
            return Err(ConfigError::MustBePositive {
                field: "write_timeout",
                value: format!("{write_timeout:?}"),
            });
        }
        if list_timeout.is_zero() {
            return Err(ConfigError::MustBePositive {
                field: "list_timeout",
                value: format!("{list_timeout:?}"),
            });
        }
        Ok(Self { read_timeout, write_timeout, list_timeout })
    }

    /// Returns the read operation timeout.
    #[must_use]
    pub fn read_timeout(&self) -> Duration {
        self.read_timeout
    }

    /// Returns the write operation timeout.
    #[must_use]
    pub fn write_timeout(&self) -> Duration {
        self.write_timeout
    }

    /// Returns the list operation timeout.
    #[must_use]
    pub fn list_timeout(&self) -> Duration {
        self.list_timeout
    }
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            read_timeout: DEFAULT_READ_TIMEOUT,
            write_timeout: DEFAULT_WRITE_TIMEOUT,
            list_timeout: DEFAULT_LIST_TIMEOUT,
        }
    }
}

/// Configuration for [`LedgerBackend`](crate::LedgerBackend).
///
/// This configuration determines how the backend connects to Ledger and
/// how keys are scoped within the Ledger namespace hierarchy.
///
/// # Key Scoping
///
/// Ledger uses a two-level hierarchy for data isolation:
///
/// - **Namespace**: Organization-level container (required)
/// - **Vault**: Optional blockchain chain within a namespace
///
/// If `vault_id` is `None`, keys are stored at the namespace level.
/// If `vault_id` is `Some(id)`, keys are scoped to that specific vault.
///
/// # Validation
///
/// - `page_size` must be `>= 1`
/// - `max_range_results` must be `>= 1`
///
/// # Example
///
/// ```no_run
/// // Requires a running Ledger server for the `ClientConfig` connection.
/// use inferadb_common_storage::VaultId;
/// use inferadb_common_storage_ledger::{ClientConfig, LedgerBackendConfig, ServerSource};
///
/// let client = ClientConfig::builder()
///     .servers(ServerSource::from_static(["http://localhost:50051"]))
///     .client_id("my-service-001")
///     .build()?;
///
/// let config = LedgerBackendConfig::builder()
///     .client(client)
///     .namespace_id(1)
///     .vault_id(VaultId::from(100))  // Optional
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct LedgerBackendConfig {
    /// SDK client configuration.
    pub(crate) client: ClientConfig,

    /// Namespace ID for data scoping.
    pub(crate) namespace_id: NamespaceId,

    /// Optional vault ID for finer-grained scoping.
    pub(crate) vault_id: Option<VaultId>,

    /// Read consistency level.
    pub(crate) read_consistency: ReadConsistency,

    /// Maximum number of entities per page when fetching range results.
    ///
    /// This controls the `limit` field sent to the Ledger SDK's
    /// `list_entities` call. Defaults to `10_000`.
    pub(crate) page_size: u32,

    /// Upper safety bound on total results returned by a single `get_range`
    /// call across all pages.
    ///
    /// If a range query accumulates more results than this limit, the
    /// operation returns [`StorageError::Internal`] rather than silently
    /// truncating. Defaults to `100_000`.
    pub(crate) max_range_results: usize,

    /// Retry configuration for transient failures.
    ///
    /// When set, transient errors (connection, timeout) trigger automatic
    /// retry with exponential backoff. Non-transient errors are returned
    /// immediately. Defaults to 3 retries with 100ms initial backoff.
    pub(crate) retry_config: RetryConfig,

    /// Per-operation timeout configuration.
    ///
    /// Bounds the total wall-clock time of each storage operation,
    /// including all retry attempts. Defaults to 5s reads, 10s writes,
    /// 30s list operations.
    pub(crate) timeout_config: TimeoutConfig,

    /// Optional key/value size limits.
    ///
    /// When set, write operations (`set`, `compare_and_set`, `set_with_ttl`)
    /// validate key and value sizes before sending to the ledger. This
    /// provides clear error messages instead of opaque downstream failures.
    pub(crate) size_limits: Option<SizeLimits>,

    /// Optional circuit breaker configuration.
    ///
    /// When set, a circuit breaker protects the backend from cascading
    /// failures by failing fast when the ledger is unreachable, and
    /// periodically probing to detect recovery.
    pub(crate) circuit_breaker_config: Option<crate::circuit_breaker::CircuitBreakerConfig>,
}

#[bon::bon]
impl LedgerBackendConfig {
    /// Creates a new configuration.
    ///
    /// # Arguments
    ///
    /// * `client` - SDK client configuration (servers, timeouts, TLS, etc.).
    /// * `namespace_id` - Namespace ID for key scoping.
    ///
    /// # Optional Fields
    ///
    /// * `vault_id` - Vault ID for finer-grained scoping within the namespace.
    /// * `read_consistency` - Read consistency level (default: Linearizable).
    /// * `page_size` - Number of entities per page for range queries (default: 10,000).
    /// * `max_range_results` - Safety cap on total range results (default: 100,000).
    /// * `timeout_config` - Per-operation timeouts (default: 5s read, 10s write, 30s list).
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `page_size` or `max_range_results` is zero.
    #[builder]
    pub fn new(
        client: ClientConfig,
        #[builder(into)] namespace_id: NamespaceId,
        vault_id: Option<VaultId>,
        #[builder(default = ReadConsistency::Linearizable)] read_consistency: ReadConsistency,
        #[builder(default = DEFAULT_PAGE_SIZE)] page_size: u32,
        #[builder(default = DEFAULT_MAX_RANGE_RESULTS)] max_range_results: usize,
        #[builder(default)] retry_config: RetryConfig,
        #[builder(default)] timeout_config: TimeoutConfig,
        size_limits: Option<SizeLimits>,
        circuit_breaker_config: Option<crate::circuit_breaker::CircuitBreakerConfig>,
    ) -> Result<Self, ConfigError> {
        if page_size == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "page_size",
                min: "1".into(),
                value: "0".into(),
            });
        }
        if max_range_results == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_range_results",
                min: "1".into(),
                value: "0".into(),
            });
        }
        Ok(Self {
            client,
            namespace_id,
            vault_id,
            read_consistency,
            page_size,
            max_range_results,
            retry_config,
            timeout_config,
            size_limits,
            circuit_breaker_config,
        })
    }

    /// Returns the SDK client configuration.
    #[must_use]
    pub fn client(&self) -> &ClientConfig {
        &self.client
    }

    /// Returns the namespace ID.
    #[must_use]
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    /// Returns the vault ID if configured.
    #[must_use]
    pub fn vault_id(&self) -> Option<VaultId> {
        self.vault_id
    }

    /// Returns the read consistency level.
    #[must_use]
    pub fn read_consistency(&self) -> ReadConsistency {
        self.read_consistency
    }

    /// Returns the page size for range queries.
    #[must_use]
    pub fn page_size(&self) -> u32 {
        self.page_size
    }

    /// Returns the maximum number of results a single range query may return.
    #[must_use]
    pub fn max_range_results(&self) -> usize {
        self.max_range_results
    }

    /// Returns the retry configuration.
    #[must_use]
    pub fn retry_config(&self) -> &RetryConfig {
        &self.retry_config
    }

    /// Returns the timeout configuration.
    #[must_use]
    pub fn timeout_config(&self) -> &TimeoutConfig {
        &self.timeout_config
    }

    /// Returns the configured size limits, if any.
    #[must_use]
    pub fn size_limits(&self) -> Option<SizeLimits> {
        self.size_limits
    }

    /// Returns the configured circuit breaker config, if any.
    #[must_use]
    pub fn circuit_breaker_config(&self) -> Option<&crate::circuit_breaker::CircuitBreakerConfig> {
        self.circuit_breaker_config.as_ref()
    }

    /// Returns the SDK client configuration for building a client.
    pub(crate) fn into_client_config(self) -> ClientConfig {
        self.client
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use inferadb_ledger_sdk::ServerSource;

    use super::*;

    fn test_client() -> ClientConfig {
        ClientConfig::builder()
            .servers(ServerSource::from_static(["http://localhost:50051"]))
            .client_id("test-client")
            .build()
            .unwrap()
    }

    // ── RetryConfig validation ──────────────────────────────────────

    #[test]
    fn retry_config_defaults_pass_validation() {
        let config = RetryConfig::builder().build().unwrap();
        assert_eq!(config.max_retries(), DEFAULT_MAX_RETRIES);
        assert_eq!(config.initial_backoff(), DEFAULT_INITIAL_BACKOFF);
        assert_eq!(config.max_backoff(), DEFAULT_MAX_BACKOFF);
    }

    #[test]
    fn retry_config_zero_initial_backoff_rejected() {
        let err = RetryConfig::builder().initial_backoff(Duration::ZERO).build().unwrap_err();
        assert!(err.to_string().contains("initial_backoff"), "error should name the field: {err}");
    }

    #[test]
    fn retry_config_max_backoff_below_initial_rejected() {
        let err = RetryConfig::builder()
            .initial_backoff(Duration::from_secs(5))
            .max_backoff(Duration::from_secs(1))
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("initial_backoff") && err.to_string().contains("max_backoff"),
            "error should name both fields: {err}"
        );
    }

    #[test]
    fn retry_config_zero_max_retries_allowed() {
        let config = RetryConfig::builder().max_retries(0).build().unwrap();
        assert_eq!(config.max_retries(), 0);
    }

    #[test]
    fn retry_config_equal_backoffs_allowed() {
        let config = RetryConfig::builder()
            .initial_backoff(Duration::from_secs(1))
            .max_backoff(Duration::from_secs(1))
            .build()
            .unwrap();
        assert_eq!(config.initial_backoff(), config.max_backoff());
    }

    // ── TimeoutConfig validation ────────────────────────────────────

    #[test]
    fn timeout_config_defaults_pass_validation() {
        let config = TimeoutConfig::builder().build().unwrap();
        assert_eq!(config.read_timeout(), DEFAULT_READ_TIMEOUT);
        assert_eq!(config.write_timeout(), DEFAULT_WRITE_TIMEOUT);
        assert_eq!(config.list_timeout(), DEFAULT_LIST_TIMEOUT);
    }

    #[test]
    fn timeout_config_zero_read_timeout_rejected() {
        let err = TimeoutConfig::builder().read_timeout(Duration::ZERO).build().unwrap_err();
        assert!(err.to_string().contains("read_timeout"), "error should name the field: {err}");
    }

    #[test]
    fn timeout_config_zero_write_timeout_rejected() {
        let err = TimeoutConfig::builder().write_timeout(Duration::ZERO).build().unwrap_err();
        assert!(err.to_string().contains("write_timeout"), "error should name the field: {err}");
    }

    #[test]
    fn timeout_config_zero_list_timeout_rejected() {
        let err = TimeoutConfig::builder().list_timeout(Duration::ZERO).build().unwrap_err();
        assert!(err.to_string().contains("list_timeout"), "error should name the field: {err}");
    }

    #[test]
    fn timeout_config_default_impl() {
        let tc = TimeoutConfig::default();
        assert_eq!(tc.read_timeout(), Duration::from_secs(5));
        assert_eq!(tc.write_timeout(), Duration::from_secs(10));
        assert_eq!(tc.list_timeout(), Duration::from_secs(30));
    }

    // ── LedgerBackendConfig validation ──────────────────────────────

    #[test]
    fn ledger_config_defaults_pass_validation() {
        let config =
            LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build().unwrap();

        assert_eq!(config.namespace_id(), NamespaceId::from(1));
        assert!(config.vault_id().is_none());
        assert_eq!(config.page_size(), DEFAULT_PAGE_SIZE);
        assert_eq!(config.max_range_results(), DEFAULT_MAX_RANGE_RESULTS);
    }

    #[test]
    fn ledger_config_with_vault() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .vault_id(VaultId::from(100))
            .build()
            .unwrap();

        assert_eq!(config.vault_id(), Some(VaultId::from(100)));
    }

    #[test]
    fn ledger_config_read_consistency_default_is_linearizable() {
        let config =
            LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build().unwrap();

        assert!(matches!(config.read_consistency(), ReadConsistency::Linearizable));
    }

    #[test]
    fn ledger_config_read_consistency_eventual() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .read_consistency(ReadConsistency::Eventual)
            .build()
            .unwrap();

        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn ledger_config_all_optional_fields() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .vault_id(VaultId::from(100))
            .read_consistency(ReadConsistency::Eventual)
            .build()
            .unwrap();

        assert_eq!(config.vault_id(), Some(VaultId::from(100)));
        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn ledger_config_client_accessor() {
        let config =
            LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build().unwrap();

        let _client = config.client();
    }

    #[test]
    fn ledger_config_pagination_defaults() {
        let config =
            LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build().unwrap();

        assert_eq!(config.page_size(), DEFAULT_PAGE_SIZE);
        assert_eq!(config.max_range_results(), DEFAULT_MAX_RANGE_RESULTS);
    }

    #[test]
    fn ledger_config_custom_pagination() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .page_size(500)
            .max_range_results(50_000)
            .build()
            .unwrap();

        assert_eq!(config.page_size(), 500);
        assert_eq!(config.max_range_results(), 50_000);
    }

    #[test]
    fn ledger_config_zero_page_size_rejected() {
        let err = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .page_size(0)
            .build()
            .unwrap_err();
        assert!(err.to_string().contains("page_size"), "error should name the field: {err}");
    }

    #[test]
    fn ledger_config_zero_max_range_results_rejected() {
        let err = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .max_range_results(0)
            .build()
            .unwrap_err();
        assert!(
            err.to_string().contains("max_range_results"),
            "error should name the field: {err}"
        );
    }

    #[test]
    fn ledger_config_timeout_defaults() {
        let config =
            LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build().unwrap();

        let tc = config.timeout_config();
        assert_eq!(tc.read_timeout(), DEFAULT_READ_TIMEOUT);
        assert_eq!(tc.write_timeout(), DEFAULT_WRITE_TIMEOUT);
        assert_eq!(tc.list_timeout(), DEFAULT_LIST_TIMEOUT);
    }

    #[test]
    fn ledger_config_custom_timeout() {
        let timeout = TimeoutConfig::builder()
            .read_timeout(Duration::from_secs(2))
            .write_timeout(Duration::from_secs(4))
            .list_timeout(Duration::from_secs(15))
            .build()
            .unwrap();

        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .timeout_config(timeout)
            .build()
            .unwrap();

        let tc = config.timeout_config();
        assert_eq!(tc.read_timeout(), Duration::from_secs(2));
        assert_eq!(tc.write_timeout(), Duration::from_secs(4));
        assert_eq!(tc.list_timeout(), Duration::from_secs(15));
    }
}
