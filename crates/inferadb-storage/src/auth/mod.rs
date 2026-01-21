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
//! Keys are stored as Ledger entities in the organization's namespace:
//!
//! - **Namespace**: `{namespace_id}` (where `namespace_id == org_id`)
//! - **Key prefix**: `signing-keys/`
//! - **Full path**: `signing-keys/{kid}`
//!
//! # Storage Trait
//!
//! The [`PublicSigningKeyStore`] trait provides the interface for key lifecycle
//! operations. Use [`MemorySigningKeyStore`] for testing.
//!
//! # Example
//!
//! ```no_run
//! use chrono::Utc;
//! use inferadb_storage::auth::{
//!     MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore,
//! };
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let store = MemorySigningKeyStore::new();
//!     
//!     let key = PublicSigningKey {
//!         kid: "key-abc123".to_string(),
//!         public_key: "MCowBQYDK2VwAyEA...".to_string(),
//!         client_id: 1001,
//!         cert_id: 42,
//!         created_at: Utc::now(),
//!         valid_from: Utc::now(),
//!         valid_until: None,
//!         active: true,
//!         revoked_at: None,
//!     };
//!     
//!     store.create_key(100, &key).await?;
//!     
//!     let retrieved = store.get_key(100, "key-abc123").await?;
//!     assert!(retrieved.is_some());
//!     
//!     Ok(())
//! }
//! ```

mod metrics;
mod signing_key;
mod store;

pub use metrics::{SigningKeyErrorKind, SigningKeyMetrics, SigningKeyMetricsSnapshot};
pub use signing_key::PublicSigningKey;
pub use store::{MemorySigningKeyStore, PublicSigningKeyStore, SIGNING_KEY_PREFIX};
