//! Configuration for the Ledger storage backend.
//!
//! This module provides [`LedgerBackendConfig`] which configures the connection
//! to Ledger and determines how keys are scoped within the Ledger namespace.

use inferadb_ledger_sdk::{ClientConfig, ReadConsistency};

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
/// use inferadb_ledger_sdk::{ClientConfig, ServerSource};
///
/// let client = ClientConfig::builder()
///     .servers(ServerSource::from_static(["http://localhost:50051"]))
///     .client_id("my-service-001")
///     .build()?;
///
/// let config = LedgerBackendConfig::builder()
///     .client(client)
///     .namespace_id(1)
///     .vault_id(100)  // Optional
///     .build();
/// # Ok::<(), Box<dyn std::error::Error>>(())
/// ```
#[derive(Debug, Clone)]
pub struct LedgerBackendConfig {
    /// SDK client configuration.
    pub(crate) client: ClientConfig,

    /// Namespace ID for data scoping.
    pub(crate) namespace_id: i64,

    /// Optional vault ID for finer-grained scoping.
    pub(crate) vault_id: Option<i64>,

    /// Read consistency level.
    pub(crate) read_consistency: ReadConsistency,
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
    #[builder]
    pub fn new(
        client: ClientConfig,
        namespace_id: i64,
        vault_id: Option<i64>,
        #[builder(default = ReadConsistency::Linearizable)] read_consistency: ReadConsistency,
    ) -> Self {
        Self { client, namespace_id, vault_id, read_consistency }
    }

    /// Returns the SDK client configuration.
    #[must_use]
    pub fn client(&self) -> &ClientConfig {
        &self.client
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

    /// Returns the read consistency level.
    #[must_use]
    pub fn read_consistency(&self) -> ReadConsistency {
        self.read_consistency
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

        assert_eq!(config.namespace_id(), 1);
        assert!(config.vault_id().is_none());
    }

    #[test]
    fn test_config_with_vault() {
        let config = LedgerBackendConfig::builder()
            .client(test_client())
            .namespace_id(1)
            .vault_id(100)
            .build();

        assert_eq!(config.vault_id(), Some(100));
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
            .vault_id(100)
            .read_consistency(ReadConsistency::Eventual)
            .build();

        assert_eq!(config.vault_id(), Some(100));
        assert!(matches!(config.read_consistency(), ReadConsistency::Eventual));
    }

    #[test]
    fn test_client_accessor() {
        let config = LedgerBackendConfig::builder().client(test_client()).namespace_id(1).build();

        // Verify we can access the client config
        let _client = config.client();
    }
}
