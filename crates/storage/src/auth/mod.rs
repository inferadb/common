//! Authentication types and storage for Ledger-based token validation.
//!
//! This module contains shared type definitions and storage traits for public
//! signing keys stored in the Ledger. These types are used by both Control
//! (to write keys) and Engine (to read and validate keys).
//!
//! # Architecture
//!
//! ```text
//! ┌─────────────┐       ┌─────────────┐       ┌─────────────┐
//! │   Control   │       │   Ledger    │       │   Engine    │
//! │             │──────►│  (source    │◄──────│             │
//! │ writes keys │       │   of truth) │       │ reads keys  │
//! └─────────────┘       └─────────────┘       └─────────────┘
//! ```
//!
//! # Key Storage
//!
//! Keys are stored as Ledger entities scoped to an organization:
//!
//! - **Organization**: `{organization_slug}`
//! - **Key prefix**: `signing-keys/`
//! - **Full path**: `signing-keys/{kid}`
//!
//! # Storage Trait
//!
//! The [`PublicSigningKeyStore`](crate::auth::PublicSigningKeyStore) trait provides the interface
//! for key lifecycle operations. Use [`MemorySigningKeyStore`](crate::auth::MemorySigningKeyStore)
//! for testing.
//!
//! # Examples
//!
//! ```no_run
//! use inferadb_common_storage::auth::{
//!     MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore,
//! };
//! use inferadb_common_storage::OrganizationSlug;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let store = MemorySigningKeyStore::new();
//! let org = OrganizationSlug::from(100);
//!
//! let key = PublicSigningKey::builder()
//!     .kid("key-abc123")
//!     .public_key("MCowBQYDK2VwAyEA...".to_owned())
//!     .client_id(1001)
//!     .cert_id(42)
//!     .build();
//!
//! store.create_key(org, &key).await?;
//!
//! let retrieved = store.get_key(org, "key-abc123").await?;
//! assert!(retrieved.is_some());
//! # Ok(())
//! # }
//! ```

pub mod audit;
pub mod audited_store;
mod metrics;
mod signing_key;
mod store;

pub use metrics::{SigningKeyErrorKind, SigningKeyMetrics, SigningKeyMetricsSnapshot};
pub use signing_key::PublicSigningKey;
pub use store::{MemorySigningKeyStore, PublicSigningKeyStore, SIGNING_KEY_PREFIX};
