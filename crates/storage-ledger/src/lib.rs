//! Ledger-backed implementation of [`StorageBackend`](inferadb_common_storage::StorageBackend) for
//! InferaDB.
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
//! │                   LedgerBackend                             │
//! │         (implements StorageBackend trait)                   │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Ledger SDK                                │
//! │   LedgerClient │ SequenceTracker │ ConnectionPool           │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Ledger Service                            │
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
//!         .organization(1)
//!         .build()?;
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
//! | StorageBackend          | Ledger                                                       |
//! | ----------------------- | ------------------------------------------------------------ |
//! | `get(key)`              | `read` with configured [`ReadConsistency`]                   |
//! | `set(key, value)`       | `write([Operation::set_entity(hex(key), value)])`            |
//! | `get_range(start..end)` | `list_entities(prefix)` + client-side filtering              |
//!
//! # Consistency Model
//!
//! By default, this backend uses linearizable (strong) consistency for reads
//! to ensure correctness for authorization decisions. This can be configured
//! to use eventual consistency for read-heavy workloads where staleness is
//! acceptable.
//!
//! # Circuit Breaking
//!
//! Circuit breaking is handled by the Ledger SDK at the transport layer.
//! Configure it via [`CircuitBreakerConfig`] on [`ClientConfig`]:
//!
//! ```no_run
//! use inferadb_common_storage_ledger::{
//!     CircuitBreakerConfig, ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ClientConfig::builder()
//!     .servers(ServerSource::from_static(["http://localhost:50051"]))
//!     .client_id("my-service")
//!     .circuit_breaker(CircuitBreakerConfig::builder().build())
//!     .build()?;
//!
//! let config = LedgerBackendConfig::builder()
//!     .client(client)
//!     .organization(1)
//!     .build()?;
//!
//! let backend = LedgerBackend::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! When the circuit is open, SDK operations return
//! [`SdkError::CircuitOpen`](inferadb_ledger_sdk::SdkError::CircuitOpen), which is mapped to
//! [`StorageError::Connection`](inferadb_common_storage::StorageError::Connection).
//!
//! # Distributed Tracing
//!
//! The backend supports [W3C Trace Context] propagation through to the
//! Ledger service. When enabled, every outgoing gRPC request includes
//! `traceparent` and `tracestate` headers, connecting storage operations to
//! the request's distributed trace.
//!
//! Enable trace propagation on the [`ClientConfig`]:
//!
//! ```no_run
//! use inferadb_common_storage_ledger::{
//!     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource, TraceConfig,
//! };
//!
//! # #[tokio::main]
//! # async fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let client = ClientConfig::builder()
//!     .servers(ServerSource::from_static(["http://localhost:50051"]))
//!     .client_id("my-service")
//!     .trace(TraceConfig::enabled())
//!     .build()?;
//!
//! let config = LedgerBackendConfig::builder()
//!     .client(client)
//!     .organization(1)
//!     .build()?;
//!
//! let backend = LedgerBackend::new(config).await?;
//! # Ok(())
//! # }
//! ```
//!
//! To see end-to-end traces (API → storage → ledger), pair this with a
//! `tracing-opentelemetry` subscriber that exports spans to your collector
//! (Jaeger, Grafana Tempo, Datadog, etc.). The SDK extracts the active
//! OpenTelemetry context from the current `tracing::Span` and propagates it
//! as W3C headers on every request.
//!
//! [W3C Trace Context]: https://www.w3.org/TR/trace-context/

#![deny(unsafe_code)]
#![warn(missing_docs)]

mod backend;
mod config;
mod error;
mod keys;
mod transaction;

/// Authentication-related storage implementations.
pub mod auth;
/// Test utilities for Ledger backend testing.
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil;

/// Ledger-backed storage backend.
pub use backend::LedgerBackend;
/// Configuration types and default constants for the Ledger backend.
pub use config::{
    DEFAULT_LIST_TIMEOUT, DEFAULT_MAX_RANGE_RESULTS, DEFAULT_PAGE_SIZE, DEFAULT_READ_TIMEOUT,
    DEFAULT_WRITE_TIMEOUT, LedgerBackendConfig, TimeoutConfig,
};
/// Ledger-specific error types and result alias.
pub use error::{LedgerStorageError, Result};
/// Configuration validation error type.
pub use inferadb_common_storage::ConfigError;
/// CAS retry configuration, re-exported from the base storage crate.
pub use inferadb_common_storage::{
    CasRetryConfig, DEFAULT_CAS_RETRY_BASE_DELAY, DEFAULT_MAX_CAS_RETRIES,
};
/// Re-exported SDK types needed to build [`LedgerBackendConfig`].
pub use inferadb_ledger_sdk::{
    CircuitBreakerConfig, ClientConfig, ReadConsistency, Region, ServerSource, TraceConfig,
};
/// Re-exported SDK token types for consumer convenience.
pub use inferadb_ledger_sdk::{PublicKeyInfo, TokenPair, ValidatedToken};
/// Ledger-backed transaction implementation.
pub use transaction::LedgerTransaction;
