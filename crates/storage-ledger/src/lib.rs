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
//!         .namespace_id(1)
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
//! | `get(key)`              | `read_consistent` or `read` depending on [`ReadConsistency`] |
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
//!     .namespace_id(1)
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
/// Circuit breaker for fail-fast during backend outages.
pub mod circuit_breaker;
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

/// Ledger-backed storage backend.
pub use backend::LedgerBackend;
/// Circuit breaker types for fail-fast during backend outages.
pub use circuit_breaker::{
    CircuitBreaker, CircuitBreakerConfig, CircuitBreakerMetrics, CircuitState,
    DEFAULT_FAILURE_THRESHOLD, DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD, DEFAULT_RECOVERY_TIMEOUT,
};
/// Configuration types and default constants for the Ledger backend.
pub use config::{
    CasRetryConfig, DEFAULT_CAS_RETRY_BASE_DELAY, DEFAULT_INITIAL_BACKOFF, DEFAULT_LIST_TIMEOUT,
    DEFAULT_MAX_BACKOFF, DEFAULT_MAX_CAS_RETRIES, DEFAULT_MAX_RANGE_RESULTS, DEFAULT_MAX_RETRIES,
    DEFAULT_PAGE_SIZE, DEFAULT_READ_TIMEOUT, DEFAULT_WRITE_TIMEOUT, LedgerBackendConfig,
    RetryConfig, TimeoutConfig,
};
/// Ledger-specific error types and result alias.
pub use error::{LedgerStorageError, Result};
/// Configuration validation error type.
pub use inferadb_common_storage::ConfigError;
/// Re-exported SDK types needed to build [`LedgerBackendConfig`].
pub use inferadb_ledger_sdk::{ClientConfig, ReadConsistency, ServerSource, TraceConfig};
/// Ledger-backed transaction implementation.
pub use transaction::LedgerTransaction;
