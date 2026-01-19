//! Configuration for the Ledger storage backend.
//!
//! This module provides [`LedgerBackendConfig`] which configures the connection
//! to Ledger and determines how keys are scoped within the Ledger namespace.

use std::time::Duration;

use inferadb_ledger_sdk::{ClientConfig, ReadConsistency, RetryPolicy, TlsConfig};
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
/// use inferadb_storage_ledger::LedgerBackendConfig;
///
/// let config = LedgerBackendConfig::builder()
///     .with_endpoint("http://localhost:50051")
///     .with_client_id("my-service-001")
///     .with_namespace_id(1)
///     .with_vault_id(100)  // Optional
///     .build()?;
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone, Serialize, Deserialize)]
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryPolicyConfig {
    /// Maximum number of retry attempts.
    #[serde(default = "default_max_attempts")]
    pub max_attempts: u32,

    /// Initial backoff duration.
    #[serde(with = "humantime_serde", default = "default_initial_backoff")]
    pub initial_backoff: Duration,

    /// Maximum backoff duration.
    #[serde(with = "humantime_serde", default = "default_max_backoff")]
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
            .with_max_attempts(config.max_attempts)
            .with_initial_backoff(config.initial_backoff)
            .with_max_backoff(config.max_backoff)
            .build()
    }
}

impl LedgerBackendConfig {
    /// Creates a new configuration builder.
    #[must_use]
    pub fn builder() -> LedgerBackendConfigBuilder {
        LedgerBackendConfigBuilder::default()
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
        let mut builder = ClientConfig::builder()
            .with_endpoints(self.endpoints.clone())
            .with_client_id(&self.client_id)
            .with_timeout(self.timeout)
            .with_connect_timeout(self.connect_timeout)
            .with_retry_policy(self.retry_policy.clone().into())
            .with_compression(self.compression);

        if let Some(ref tls) = self.tls {
            builder = builder.with_tls(tls.clone());
        }

        builder.build().map_err(LedgerStorageError::from)
    }
}

/// Builder for [`LedgerBackendConfig`].
#[derive(Debug, Default)]
pub struct LedgerBackendConfigBuilder {
    endpoints: Vec<String>,
    client_id: Option<String>,
    namespace_id: Option<i64>,
    vault_id: Option<i64>,
    timeout: Option<Duration>,
    connect_timeout: Option<Duration>,
    read_consistency: ReadConsistencyConfig,
    retry_policy: RetryPolicyConfig,
    compression: bool,
    tls: Option<TlsConfig>,
}

impl LedgerBackendConfigBuilder {
    /// Sets the server endpoint URLs.
    ///
    /// At least one endpoint must be provided.
    #[must_use]
    pub fn with_endpoints<I, S>(mut self, endpoints: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.endpoints = endpoints.into_iter().map(Into::into).collect();
        self
    }

    /// Adds a single endpoint URL.
    #[must_use]
    pub fn with_endpoint<S: Into<String>>(mut self, endpoint: S) -> Self {
        self.endpoints.push(endpoint.into());
        self
    }

    /// Sets the client identifier for idempotency tracking.
    ///
    /// This must be unique per client instance to ensure correct
    /// duplicate detection.
    #[must_use]
    pub fn with_client_id<S: Into<String>>(mut self, client_id: S) -> Self {
        self.client_id = Some(client_id.into());
        self
    }

    /// Sets the namespace ID for key scoping.
    ///
    /// All keys will be stored within this namespace.
    #[must_use]
    pub fn with_namespace_id(mut self, namespace_id: i64) -> Self {
        self.namespace_id = Some(namespace_id);
        self
    }

    /// Sets the vault ID for key scoping.
    ///
    /// If set, keys will be scoped to this specific vault within the namespace.
    /// If not set, keys are stored at the namespace level.
    #[must_use]
    pub fn with_vault_id(mut self, vault_id: i64) -> Self {
        self.vault_id = Some(vault_id);
        self
    }

    /// Sets the request timeout.
    ///
    /// Default: 30 seconds.
    #[must_use]
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets the connection timeout.
    ///
    /// Default: 5 seconds.
    #[must_use]
    pub fn with_connect_timeout(mut self, timeout: Duration) -> Self {
        self.connect_timeout = Some(timeout);
        self
    }

    /// Sets the read consistency level.
    ///
    /// Default: Linearizable (strong consistency).
    #[must_use]
    pub fn with_read_consistency(mut self, consistency: ReadConsistency) -> Self {
        self.read_consistency = match consistency {
            ReadConsistency::Eventual => ReadConsistencyConfig::Eventual,
            ReadConsistency::Linearizable => ReadConsistencyConfig::Linearizable,
        };
        self
    }

    /// Sets the retry policy.
    #[must_use]
    pub fn with_retry_policy(mut self, policy: RetryPolicy) -> Self {
        self.retry_policy = RetryPolicyConfig {
            max_attempts: policy.max_attempts,
            initial_backoff: policy.initial_backoff,
            max_backoff: policy.max_backoff,
        };
        self
    }

    /// Enables gzip compression.
    #[must_use]
    pub fn with_compression(mut self, enabled: bool) -> Self {
        self.compression = enabled;
        self
    }

    /// Sets the TLS configuration.
    #[must_use]
    pub fn with_tls(mut self, tls: TlsConfig) -> Self {
        self.tls = Some(tls);
        self
    }

    /// Builds the configuration, validating all settings.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - No endpoints provided
    /// - Client ID is missing or empty
    /// - Namespace ID is not set
    pub fn build(self) -> Result<LedgerBackendConfig> {
        if self.endpoints.is_empty() {
            return Err(LedgerStorageError::Config(
                "at least one endpoint is required".into(),
            ));
        }

        let client_id = self
            .client_id
            .ok_or_else(|| LedgerStorageError::Config("client_id is required".into()))?;

        if client_id.is_empty() {
            return Err(LedgerStorageError::Config(
                "client_id cannot be empty".into(),
            ));
        }

        let namespace_id = self
            .namespace_id
            .ok_or_else(|| LedgerStorageError::Config("namespace_id is required".into()))?;

        Ok(LedgerBackendConfig {
            endpoints: self.endpoints,
            client_id,
            namespace_id,
            vault_id: self.vault_id,
            timeout: self.timeout.unwrap_or(DEFAULT_TIMEOUT),
            connect_timeout: self.connect_timeout.unwrap_or(DEFAULT_CONNECT_TIMEOUT),
            read_consistency: self.read_consistency,
            retry_policy: self.retry_policy,
            compression: self.compression,
            tls: self.tls,
        })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_config() {
        let config = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .with_namespace_id(1)
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
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .with_namespace_id(1)
            .with_vault_id(100)
            .build()
            .unwrap();

        assert_eq!(config.vault_id(), Some(100));
    }

    #[test]
    fn test_missing_endpoint() {
        let result = LedgerBackendConfig::builder()
            .with_client_id("test-client")
            .with_namespace_id(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_missing_client_id() {
        let result = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_namespace_id(1)
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_missing_namespace_id() {
        let result = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .build();

        assert!(result.is_err());
    }

    #[test]
    fn test_custom_timeouts() {
        let config = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .with_namespace_id(1)
            .with_timeout(Duration::from_secs(60))
            .with_connect_timeout(Duration::from_secs(10))
            .build()
            .unwrap();

        assert_eq!(config.timeout(), Duration::from_secs(60));
        assert_eq!(config.connect_timeout(), Duration::from_secs(10));
    }

    #[test]
    fn test_read_consistency_default_is_linearizable() {
        let config = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .with_namespace_id(1)
            .build()
            .unwrap();

        assert!(matches!(
            config.read_consistency(),
            ReadConsistency::Linearizable
        ));
    }

    #[test]
    fn test_read_consistency_eventual() {
        let config = LedgerBackendConfig::builder()
            .with_endpoint("http://localhost:50051")
            .with_client_id("test-client")
            .with_namespace_id(1)
            .with_read_consistency(ReadConsistency::Eventual)
            .build()
            .unwrap();

        assert!(matches!(
            config.read_consistency(),
            ReadConsistency::Eventual
        ));
    }
}
