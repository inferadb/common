//! Shared test utilities for Ledger backend testing.
//!
//! This module provides common helpers for creating mock Ledger servers,
//! client configurations, and backend instances. It is feature-gated
//! behind `testutil` to prevent leaking into production builds.
//!
//! # Usage
//!
//! In integration tests, enable the feature in `Cargo.toml`:
//!
//! ```toml
//! [dev-dependencies]
//! inferadb-common-storage-ledger = { path = "../storage-ledger", features = ["testutil"] }
//! ```
//!
//! Then import helpers:
//!
//! ```no_run
//! // Requires the `testutil` feature to be enabled.
//! use inferadb_common_storage_ledger::testutil::{test_client_config, create_test_backend};
//! ```

use inferadb_common_storage::VaultId;
use inferadb_ledger_sdk::{ClientConfig, ServerSource, mock::MockLedgerServer};

use crate::{backend::LedgerBackend, config::LedgerBackendConfig};

/// Create a [`ClientConfig`] pointing at the given mock server.
///
/// Uses `"test-client"` as the default client ID. If you need a specific
/// client ID (e.g., for multi-client tests), use [`test_client_config_with_id`].
pub fn test_client_config(server: &MockLedgerServer) -> ClientConfig {
    test_client_config_with_id(server, "test-client")
}

/// Create a [`ClientConfig`] with a specific client ID.
///
/// # Panics
///
/// Panics if the `ClientConfig` builder fails (should not happen with
/// valid mock server endpoints).
pub fn test_client_config_with_id(server: &MockLedgerServer, client_id: &str) -> ClientConfig {
    ClientConfig::builder()
        .servers(ServerSource::from_static([server.endpoint()]))
        .client_id(client_id)
        .build()
        .expect("valid client config")
}

/// Create a [`LedgerBackend`] connected to the given mock server.
///
/// Uses default configuration: namespace 1, vault 0, no pagination
/// overrides. For custom configuration, build the backend manually
/// using [`test_client_config`].
///
/// # Panics
///
/// Panics if backend creation fails.
pub async fn create_test_backend(server: &MockLedgerServer) -> LedgerBackend {
    let config = LedgerBackendConfig::builder()
        .client(test_client_config(server))
        .namespace_id(1)
        .vault_id(VaultId::from(0))
        .build();

    LedgerBackend::new(config).await.expect("backend creation should succeed")
}

/// Create a [`LedgerBackend`] with custom pagination settings.
///
/// Useful for testing pagination behavior with smaller page sizes.
///
/// # Panics
///
/// Panics if backend creation fails.
pub async fn create_paginated_backend(
    server: &MockLedgerServer,
    page_size: u32,
    max_range_results: usize,
) -> LedgerBackend {
    let config = LedgerBackendConfig::builder()
        .client(test_client_config(server))
        .namespace_id(1)
        .vault_id(VaultId::from(0))
        .page_size(page_size)
        .max_range_results(max_range_results)
        .build();

    LedgerBackend::new(config).await.expect("paginated backend creation should succeed")
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use inferadb_common_storage::StorageBackend;

    use super::*;

    #[tokio::test]
    async fn test_create_test_backend_is_functional() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let backend = create_test_backend(&server).await;
        // Smoke test: set and get a value
        backend.set(b"test-key".to_vec(), b"test-value".to_vec()).await.expect("set");
        let val = backend.get(b"test-key").await.expect("get");
        assert!(val.is_some());
    }

    #[tokio::test]
    async fn test_create_paginated_backend_has_custom_settings() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let backend = create_paginated_backend(&server, 5, 50).await;
        assert_eq!(backend.page_size(), 5);
        assert_eq!(backend.max_range_results(), 50);
    }

    #[tokio::test]
    async fn test_test_client_config_with_id() {
        let server = MockLedgerServer::start().await.expect("mock server");
        let config = test_client_config_with_id(&server, "custom-client");
        // Just verify it builds without panic
        let _ = config;
    }
}
