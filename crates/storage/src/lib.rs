//! Shared storage backend abstraction for InferaDB services.
//!
//! Provides the [`StorageBackend`] trait and related types that form
//! the foundation for all storage operations in InferaDB. Both the Engine and
//! Control services use this abstraction, enabling a unified storage layer.
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────────────────────────────────────────────────────┐
//! │                    Service Layer                            │
//! │         (Engine API handlers, Control API handlers)         │
//! ├─────────────────────────────────────────────────────────────┤
//! │                   Repository Layer                          │
//! │  RelationshipRepository │ OrganizationRepository │ etc.     │
//! │         (Domain logic, serialization, indexing)             │
//! ├─────────────────────────────────────────────────────────────┤
//! │                 inferadb-storage                            │
//! │              StorageBackend trait                           │
//! │  (get, set, delete, get_range, compare_and_set, transaction) │
//! ├──────────────┬───────────────────────────────────────────────┤
//! │ MemoryBackend│            LedgerBackend                      │
//! │   (testing)  │          (production)                         │
//! └──────────────┴───────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```no_run
//! use inferadb_common_storage::{MemoryBackend, StorageBackend};
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     // Create an in-memory backend for testing
//!     let backend = MemoryBackend::new();
//!
//!     // Store a value
//!     backend.set(b"user:123".to_vec(), b"Alice".to_vec()).await?;
//!
//!     // Retrieve it
//!     let value = backend.get(b"user:123").await?;
//!     assert_eq!(value.map(|b| b.to_vec()), Some(b"Alice".to_vec()));
//!
//!     // Use transactions for atomic operations
//!     let mut txn = backend.transaction().await?;
//!     txn.set(b"counter".to_vec(), b"1".to_vec());
//!     txn.set(b"updated".to_vec(), b"true".to_vec());
//!     txn.commit().await?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Compare-and-Set (CAS)
//!
//! [`StorageBackend::compare_and_set`] provides atomic conditional updates for
//! optimistic concurrency control. Pass `expected: None` for insert-if-absent
//! or `expected: Some(bytes)` for update-if-unchanged. See the
//! [`compare_and_set`](StorageBackend::compare_and_set) method documentation
//! for full semantics, TTL interaction, transaction behavior, and retry
//! patterns.
//!
//! # Available Backends
//!
//! | Backend | Use Case | Persistence |
//! |---------|----------|-------------|
//! | [`MemoryBackend`] | Testing, development | No |
//! | `LedgerBackend` (in `inferadb-storage-ledger`) | Production | Yes |
//!
//! # Implementing a Backend
//!
//! To implement a new storage backend:
//!
//! 1. Implement the [`StorageBackend`] trait
//! 2. Implement a corresponding [`Transaction`] type
//! 3. Map backend-specific errors to [`StorageError`]
//!
//! See the [`memory`] module source for a reference implementation.
//!
//! # Error Handling
//!
//! All operations return [`StorageResult<T>`], which wraps potential
//! [`StorageError`] variants. Backends should map their internal errors
//! to these standardized error types.
//!
//! # Feature Flags
//!
//! - **`testutil`**: Enables the `testutil` module with shared test helpers (key/value generators,
//!   backend factories, assertion macros). Enable this in `[dev-dependencies]` for integration
//!   tests.

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Authentication primitives: signing keys, key stores, and audit logging.
pub mod auth;
/// Core [`StorageBackend`] trait defining the key-value storage interface.
pub mod backend;
/// Batched write operations with automatic transaction splitting.
pub mod batch;
/// Conformance test suite for validating [`StorageBackend`] implementations.
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used, clippy::panic)]
pub mod conformance;
/// Error types, result aliases, and diagnostic helpers.
pub mod error;
/// Health check probes and status reporting.
pub mod health;
/// In-memory [`StorageBackend`] implementation for testing and development.
pub mod memory;
/// Operation metrics collection: counts, latencies, percentiles, and per-organization breakdowns.
pub mod metrics;
/// Token-bucket rate limiter wrapper for storage backends.
pub mod rate_limiter;
/// Key and value size limit validation.
pub mod size_limits;
/// Test utilities: key/value generators, backend factories, and assertion macros.
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil;
/// Transaction trait for atomic multi-operation commits.
pub mod transaction;
/// Common domain types: [`KeyValue`], [`OrganizationSlug`], [`VaultSlug`], and other ID newtypes.
pub mod types;

// Re-export primary types at crate root for convenience
pub use backend::StorageBackend;
pub use batch::{BatchConfig, BatchFlushStats, BatchOperation, BatchResult, BatchWriter};
pub use error::{BoxError, ConfigError, StorageError, StorageResult, TimeoutContext};
pub use health::{HealthMetadata, HealthProbe, HealthStatus};
pub use memory::MemoryBackend;
pub use metrics::{
    DEFAULT_MAX_TRACKED_ORGANIZATIONS, LatencyPercentiles, Metrics, MetricsCollector,
    MetricsSnapshot, OrganizationOperationSnapshot,
};
pub use rate_limiter::{
    OrganizationExtractor, RateLimitConfig, RateLimitMetricsSnapshot, RateLimitedBackend,
    TokenBucketLimiter,
};
pub use size_limits::{
    DEFAULT_MAX_KEY_SIZE, DEFAULT_MAX_VALUE_SIZE, SizeLimits, validate_key_size, validate_sizes,
};
pub use transaction::Transaction;
pub use types::{CertId, ClientId, KeyValue, OrganizationSlug, VaultSlug};
pub use zeroize::Zeroizing;
