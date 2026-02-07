//! Ledger-backed implementation of `StorageBackend` for InferaDB.
//!
//! This crate provides [`LedgerBackend`], a production-grade storage backend that
//! implements the [`StorageBackend`](inferadb_common_storage::StorageBackend) trait using
//! InferaDB Ledger's blockchain database. This enables both Engine and Control
//! services to use Ledger as their storage layer through a unified interface.
//!
//! # Features
//!
//! - **Unified storage**: Single implementation serves both Engine and Control
//! - **Cryptographic verification**: All data backed by Merkle proofs
//! - **Automatic idempotency**: Built-in duplicate detection via SDK
//! - **Strong consistency**: Linearizable reads available
//! - **TTL support**: Automatic key expiration via Ledger's native TTL
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                     Repository Layer                        │
//! │  OrganizationRepository │ VaultRepository │ RelationshipRepo│
//! ├─────────────────────────────────────────────────────────────┤
//! │                   LedgerBackend                              │
//! │         (implements StorageBackend trait)                    │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Ledger SDK                                 │
//! │   LedgerClient │ SequenceTracker │ ConnectionPool           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Ledger Service                             │
//! │   Blockchain consensus │ Merkle trees │ Replication         │
//! └─────────────────────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! // Requires a running Ledger server.
//! use inferadb_common_storage_ledger::{
//!     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
//! };
//! use inferadb_common_storage::StorageBackend;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let client = ClientConfig::builder()
//!         .servers(ServerSource::from_static(["http://localhost:50051"]))
//!         .client_id("my-service")
//!         .build()?;
//!
//!     let config = LedgerBackendConfig::builder()
//!         .client(client)
//!         .namespace_id(1)
//!         .build();
//!
//!     let backend = LedgerBackend::new(config).await?;
//!
//!     // Use like any other StorageBackend
//!     backend.set(b"key".to_vec(), b"value".to_vec()).await?;
//!     let value = backend.get(b"key").await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Key Mapping
//!
//! The backend maps byte keys to Ledger's string-based entity keys using
//! hex encoding to preserve ordering:
//!
//! | StorageBackend | Ledger |
//! |----------------|--------|
//! | `get(key)` | `client.read_consistent(ns, vault, hex(key))` |
//! | `set(key, value)` | `client.write([SetEntity { key: hex(key), value }])` |
//! | `get_range(start..end)` | `client.list_entities(prefix)` + filter |
//!
//! # Consistency Model
//!
//! By default, this backend uses linearizable (strong) consistency for reads
//! to ensure correctness for authorization decisions. This can be configured
//! to use eventual consistency for read-heavy workloads where staleness is
//! acceptable.

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod backend;
mod config;
mod error;
mod keys;
mod retry;
mod transaction;

/// Authentication-related storage implementations.
pub mod auth;
/// Shared test utilities for Ledger backend testing.
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil;

pub use backend::LedgerBackend;
pub use config::{
    DEFAULT_INITIAL_BACKOFF, DEFAULT_LIST_TIMEOUT, DEFAULT_MAX_BACKOFF, DEFAULT_MAX_RANGE_RESULTS,
    DEFAULT_MAX_RETRIES, DEFAULT_PAGE_SIZE, DEFAULT_READ_TIMEOUT, DEFAULT_WRITE_TIMEOUT,
    LedgerBackendConfig, RetryConfig, TimeoutConfig,
};
pub use error::{LedgerStorageError, Result};
// Re-export SDK types needed to build LedgerBackendConfig
pub use inferadb_ledger_sdk::{ClientConfig, ReadConsistency, ServerSource};
pub use transaction::LedgerTransaction;
