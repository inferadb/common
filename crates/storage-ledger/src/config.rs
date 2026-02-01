//! Configuration for the Ledger storage backend.
//!
//! This module provides [`LedgerBackendConfig`] which configures the connection
//! to Ledger and determines how keys are scoped within the Ledger namespace.

use std::time::Duration;

use inferadb_ledger_sdk::{ClientConfig, ReadConsistency, RetryPolicy, ServerSource, TlsConfig};
use serde::{Deserialize, Serialize};

use crate::error::{LedgerStorageError, Result};

/// Default request timeout (30 seconds).
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(30);

/// Default connection timeout (5 seconds).
const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

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
/// use inferadb_common_storage_ledger::LedgerBackendConfig;
///
/// let config = LedgerBackendConfig::builder()
///     .endpoints(vec!["http://localhost:50051"])
///     .client_id("my-service-001")
///     .namespace_id(1)
///     .vault_id(100)  // Optional
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LedgerBackendConfig {
    /// Server endpoint URLs.
    pub(crate) endpoints: Vec<String>,

    /// Unique client identifier for idempotency tracking.
    pub(crate) client_id: String,

    /// Namespace ID for data scoping.
    pub(crate) namespace_id: i64,

    /// Optional vault ID for finer-grained scoping.
    pub(crate) vault_id: Option<i64>,

    /// Request timeout.
    #[serde(with = "humantime_serde", default = "default_timeout")]
    pub(crate) timeout: Duration,

    /// Connection timeout.
    #[serde(with = "humantime_serde", default = "default_connect_timeout")]
    pub(crate) connect_timeout: Duration,

    /// Read consistency level.
    #[serde(default)]
    pub(crate) read_consistency: ReadConsistencyConfig,

    /// Retry policy.
    #[serde(default)]
    pub(crate) retry_policy: RetryPolicyConfig,

    /// Enable compression.
    #[serde(default)]
    pub(crate) compression: bool,

    /// TLS configuration.
    #[serde(skip)]
    pub(crate) tls: Option<TlsConfig>,
}

fn default_timeout() -> Duration {
    DEFAULT_TIMEOUT
}

fn default_connect_timeout() -> Duration {
    DEFAULT_CONNECT_TIMEOUT
}

/// Serializable read consistency configuration.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ReadConsistencyConfig {
    /// Read from any replica (may be stale, faster).
    Eventual,
    /// Read from leader (strong consistency, higher latency).
    #[default]
    Linearizable,
}

impl From<ReadConsistencyConfig> for ReadConsistency {
    fn from(config: ReadConsistencyConfig) -> Self {
        match config {
            ReadConsistencyConfig::Eventual => ReadConsistency::Eventual,
            ReadConsistencyConfig::Linearizable => ReadConsistency::Linearizable,
        }
    }
}

/// Serializable retry policy configuration.
#[derive(Debug, Clone, bon::Builder, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetryPolicyConfig {
    /// Maximum number of retry attempts.
    #[serde(default = "default_max_attempts")]
    #[builder(default = default_max_attempts())]
    pub max_attempts: u32,

    /// Initial backoff duration.
    #[serde(with = "humantime_serde", default = "default_initial_backoff")]
    #[builder(default = default_initial_backoff())]
    pub initial_backoff: Duration,

    /// Maximum backoff duration.
    #[serde(with = "humantime_serde", default = "default_max_backoff")]
    #[builder(default = default_max_backoff())]
    pub max_backoff: Duration,
}

fn default_max_attempts() -> u32 {
    3
}

fn default_initial_backoff() -> Duration {
    Duration::from_millis(100)
}

fn default_max_backoff() -> Duration {
    Duration::from_secs(10)
}

impl Default for RetryPolicyConfig {
    fn default() -> Self {
        Self {
            max_attempts: default_max_attempts(),
            initial_backoff: default_initial_backoff(),
            max_backoff: default_max_backoff(),
        }
    }
}

impl From<RetryPolicyConfig> for RetryPolicy {
    fn from(config: RetryPolicyConfig) -> Self {
        RetryPolicy::builder()
            .max_attempts(config.max_attempts)
            .initial_backoff(config.initial_backoff)
            .max_backoff(config.max_backoff)
            .build()
    }
}

#[bon::bon]
impl LedgerBackendConfig {
    /// Creates a new configuration, validating all required fields.
    ///
    /// # Arguments
    ///
    /// * `endpoints` - Server endpoint URLs. At least one must be provided.
    /// * `client_id` - Unique client identifier for idempotency tracking.
    /// * `namespace_id` - Namespace ID for key scoping.
    ///
    /// # Optional Fields
    ///
    /// * `vault_id` - Vault ID for finer-grained scoping within the namespace.
    /// * `timeout` - Request timeout (default: 30 seconds).
    /// * `connect_timeout` - Connection timeout (default: 5 seconds).
    /// * `read_consistency` - Read consistency level (default: Linearizable).
    /// * `retry_policy` - Retry policy (default: RetryPolicyConfig default).
    /// * `compression` - Enable gzip compression (default: false).
    /// * `tls` - TLS configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No endpoints provided or endpoints list is empty
    /// - Client ID is empty
    #[builder]
    pub fn new(
        #[builder(with = |iter: impl IntoIterator<Item = impl Into<String>>| {
            iter.into_iter().map(Into::into).collect()
        })]
        endpoints: Vec<String>,
        #[builder(into)] client_id: String,
        namespace_id: i64,
        vault_id: Option<i64>,
        #[builder(default = DEFAULT_TIMEOUT)] timeout: Duration,
        #[builder(default = DEFAULT_CONNECT_TIMEOUT)] connect_timeout: Duration,
        #[builder(default)] read_consistency: ReadConsistencyConfig,
        #[builder(default)] retry_policy: RetryPolicyConfig,
        #[builder(default)] compression: bool,
        tls: Option<TlsConfig>,
    ) -> Result<Self> {
        if endpoints.is_empty() {
            return Err(LedgerStorageError::Config("at least one endpoint is required".into()));
        }

        if client_id.is_empty() {
            return Err(LedgerStorageError::Config("client_id cannot be empty".into()));
        }

        Ok(Self {
            endpoints,
            client_id,
            namespace_id,
            vault_id,
            timeout,
            connect_timeout,
            read_consistency,
            retry_policy,
            compression,
            tls,
        })
    }

    /// Returns the configured endpoints.
    #[must_use]
    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Returns the client identifier.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// Returns the namespace ID.
    #[must_use]
    pub fn namespace_id(&self) -> i64 {
        self.namespace_id
    }

    /// Returns the vault ID if configured.
    #[must_use]
    pub fn vault_id(&self) -> Option<i64> {
        self.vault_id
    }

    /// Returns the request timeout.
    #[must_use]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns the connection timeout.
    #[must_use]
    pub fn connect_timeout(&self) -> Duration {
        self.connect_timeout
    }

    /// Returns the read consistency level.
    #[must_use]
    pub fn read_consistency(&self) -> ReadConsistency {
        self.read_consistency.clone().into()
    }

    /// Returns whether compression is enabled.
    #[must_use]
    pub fn compression(&self) -> bool {
        self.compression
    }

    /// Builds the SDK client configuration from this backend config.
    pub(crate) fn build_client_config(&self) -> Result<ClientConfig> {
        ClientConfig::builder()
            .servers(ServerSource::from_static(self.endpoints.clone()))
            .client_id(&self.client_id)
            .timeout(self.timeout)
            .connect_timeout(self.connect_timeout)
            .retry_policy(self.retry_policy.clone().into())
            .compression(self.compression)
            .maybe_tls(self.tls.clone())
            .build()
            .map_err(LedgerStorageError::from)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .build();

        assert!(config.is_ok());
        let config = config.unwrap();
        assert_eq!(config.endpoints(), &["http://localhost:50051"]);
        assert_eq!(config.client_id(), "test-client");
        assert_eq!(config.namespace_id(), 1);
        assert!(config.vault_id().is_none());
    }

    #[test]
    fn test_config_with_vault() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .vault_id(100)
            .build()
            .unwrap();

        assert_eq!(config.vault_id(), Some(100));
    }

    #[test]
    fn test_validation_empty_endpoints() {
        let result = LedgerBackendConfig::builder()
            .endpoints(Vec::<String>::new())
            .client_id("test-client")
            .namespace_id(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_validation_empty_client_id() {
        let result = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("")
            .namespace_id(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_custom_timeouts() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(config.timeout(), Duration::from_secs(60));
        assert_eq!(config.connect_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_read_consistency_default_is_linearizable() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .build()
            .unwrap();

        assert!(matches!(config.read_consistency(), ReadConsistency::Linearizable));
    }

    #[test]
    fn test_read_consistency_eventual() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .read_consistency(ReadConsistencyConfig::Eventual)
            .build()
            .unwrap();

        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn test_all_optional_fields() {
        let config = LedgerBackendConfig::builder()
            .endpoints(vec!["http://localhost:50051"])
            .client_id("test-client")
            .namespace_id(1)
            .vault_id(100)
            .timeout(Duration::from_secs(60))
            .connect_timeout(Duration::from_secs(10))
            .read_consistency(ReadConsistencyConfig::Eventual)
            .retry_policy(RetryPolicyConfig::default())
            .compression(true)
            .build()
            .unwrap();

        assert_eq!(config.vault_id(), Some(100));
        assert_eq!(config.timeout(), Duration::from_secs(60));
        assert!(config.compression());
    }

    #[test]
    fn test_retry_policy_builder_defaults_match_default_impl() {
        let built = RetryPolicyConfig::builder().build();
        let default = RetryPolicyConfig::default();

        assert_eq!(built.max_attempts, default.max_attempts);
        assert_eq!(built.initial_backoff, default.initial_backoff);
        assert_eq!(built.max_backoff, default.max_backoff);
    }

    #[test]
    fn test_retry_policy_builder_with_custom_values() {
        let config = RetryPolicyConfig::builder()
            .max_attempts(5)
            .initial_backoff(Duration::from_millis(200))
            .max_backoff(Duration::from_secs(30))
            .build();

        assert_eq!(config.max_attempts, 5);
        assert_eq!(config.initial_backoff, Duration::from_millis(200));
        assert_eq!(config.max_backoff, Duration::from_secs(30));
    }

    #[test]
    fn test_retry_policy_builder_partial_overrides() {
        let config = RetryPolicyConfig::builder().max_attempts(10).build();

        assert_eq!(config.max_attempts, 10);
        // Other fields should use defaults
        assert_eq!(config.initial_backoff, default_initial_backoff());
        assert_eq!(config.max_backoff, default_max_backoff());
    }

    #[test]
    fn test_config_deserialization_with_defaults() {
        // Test that default_timeout and default_connect_timeout are called
        let json = r#"{
            "endpoints": ["http://localhost:50051"],
            "client_id": "test",
            "namespace_id": 1
        }"#;

        let config: LedgerBackendConfig = serde_json::from_str(json).unwrap();

        // These should use the default_* functions
        assert_eq!(config.timeout, DEFAULT_TIMEOUT);
        assert_eq!(config.connect_timeout, DEFAULT_CONNECT_TIMEOUT);
    }
}
