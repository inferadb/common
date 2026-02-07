//! Configuration for the Ledger storage backend.
//!
//! This module provides [`LedgerBackendConfig`] which configures the connection
//! to Ledger and determines how keys are scoped within the Ledger namespace.

use std::time::Duration;

use inferadb_common_storage::{NamespaceId, VaultId};
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
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use inferadb_common_storage_ledger::RetryConfig;
///
/// let config = RetryConfig::builder()
///     .max_retries(5)
///     .initial_backoff(Duration::from_millis(200))
///     .max_backoff(Duration::from_secs(10))
///     .build();
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
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_MAX_RETRIES)] max_retries: u32,
        #[builder(default = DEFAULT_INITIAL_BACKOFF)] initial_backoff: Duration,
        #[builder(default = DEFAULT_MAX_BACKOFF)] max_backoff: Duration,
    ) -> Self {
        Self { max_retries, initial_backoff, max_backoff }
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

/// Per-operation timeout configuration for Ledger storage operations.
///
/// Provides separate timeout durations for reads, writes, and list
/// operations, reflecting their different expected latency profiles.
/// The timeout bounds the total wall-clock time of an operation,
/// including all retry attempts.
///
/// # Example
///
/// ```no_run
/// use std::time::Duration;
///
/// use inferadb_common_storage_ledger::TimeoutConfig;
///
/// let config = TimeoutConfig::builder()
///     .read_timeout(Duration::from_secs(3))
///     .write_timeout(Duration::from_secs(8))
///     .list_timeout(Duration::from_secs(20))
///     .build();
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
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_READ_TIMEOUT)] read_timeout: Duration,
        #[builder(default = DEFAULT_WRITE_TIMEOUT)] write_timeout: Duration,
        #[builder(default = DEFAULT_LIST_TIMEOUT)] list_timeout: Duration,
    ) -> Self {
        Self { read_timeout, write_timeout, list_timeout }
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
/// # Example
///
/// ```no_run
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
///     .build();
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
    ) -> Self {
        Self {
            client,
            namespace_id,
            vault_id,
            read_consistency,
            page_size,
            max_range_results,
            retry_config,
            timeout_config,
        }
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

    #[test]
    fn test_valid_config() {
        let config = LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build();

        assert_eq!(config.namespace_id(), NamespaceId::from(1));
        assert!(config.vault_id().is_none());
    }

    #[test]
    fn test_config_with_vault() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .vault_id(VaultId::from(100))
            .build();

        assert_eq!(config.vault_id(), Some(VaultId::from(100)));
    }

    #[test]
    fn test_read_consistency_default_is_linearizable() {
        let config = LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build();

        assert!(matches!(config.read_consistency(), ReadConsistency::Linearizable));
    }

    #[test]
    fn test_read_consistency_eventual() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .read_consistency(ReadConsistency::Eventual)
            .build();

        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn test_all_optional_fields() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .vault_id(VaultId::from(100))
            .read_consistency(ReadConsistency::Eventual)
            .build();

        assert_eq!(config.vault_id(), Some(VaultId::from(100)));
        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn test_client_accessor() {
        let config = LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build();

        // Verify we can access the client config
        let _client = config.client();
    }

    #[test]
    fn test_pagination_defaults() {
        let config = LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build();

        assert_eq!(config.page_size(), DEFAULT_PAGE_SIZE);
        assert_eq!(config.max_range_results(), DEFAULT_MAX_RANGE_RESULTS);
    }

    #[test]
    fn test_custom_pagination_config() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .page_size(500)
            .max_range_results(50_000)
            .build();

        assert_eq!(config.page_size(), 500);
        assert_eq!(config.max_range_results(), 50_000);
    }
}
