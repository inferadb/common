//! Shared storage backend abstraction for InferaDB services.
//!
//! This crate provides the [`StorageBackend`] trait and related types that form
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
//! │    (get, set, delete, get_range, transaction)               │
//! ├──────────────┬───────────────────────────────────────────────┤
//! │ MemoryBackend│            LedgerBackend                      │
//! │   (testing)  │          (production)                         │
//! └──────────────┴───────────────────────────────────────────────┘
//! ```
//!
//! # Quick Start
//!
//! ```
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

pub mod auth;
pub mod backend;
pub mod batch;
pub mod error;
pub mod memory;
pub mod metrics;
pub mod size_limits;
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil;
pub mod transaction;
pub mod types;

// Re-export primary types at crate root for convenience
pub use backend::StorageBackend;
pub use batch::{BatchConfig, BatchFlushStats, BatchOperation, BatchWriter};
pub use error::{BoxError, ConfigError, StorageError, StorageResult};
pub use memory::MemoryBackend;
pub use metrics::{LatencyPercentiles, Metrics, MetricsCollector, MetricsSnapshot};
pub use size_limits::{
    DEFAULT_MAX_KEY_SIZE, DEFAULT_MAX_VALUE_SIZE, SizeLimits, validate_key_size, validate_sizes,
};
pub use transaction::Transaction;
pub use types::{CertId, ClientId, KeyValue, NamespaceId, VaultId};
pub use zeroize::Zeroizing;
