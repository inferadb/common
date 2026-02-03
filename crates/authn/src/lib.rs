//! # InferaDB Common Authentication
//!
//! Shared JWT authentication types and utilities for InferaDB services.
//!
//! This crate provides:
//! - **JWT validation**: Claims parsing, signature verification
//! - **Signing key cache**: Ledger-backed cache with TTL and fallback
//! - **Algorithm validation**: Security checks for JWT algorithms
//!
//! ## Features
//!
//! - Only asymmetric algorithms (EdDSA, RS256) are supported
//! - Symmetric algorithms (HS256, etc.) are explicitly rejected
//! - Graceful degradation during Ledger outages via fallback cache
//!
//! ## Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use inferadb_common_authn::{SigningKeyCache, jwt::verify_with_signing_key_cache};
//! use inferadb_common_storage::auth::MemorySigningKeyStore;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! // Setup signing key cache
//! let store = Arc::new(MemorySigningKeyStore::new());
//! let cache = SigningKeyCache::new(store, Duration::from_secs(300));
//!
//! // Verify a JWT using Ledger-backed keys
//! let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6Im9yZy0uLi4ifQ...";
//! let claims = verify_with_signing_key_cache(token, &cache).await?;
//!
//! println!("Verified for org: {}", claims.org_id.unwrap_or_default());
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

/// Authentication error types.
pub mod error;
/// JWT validation and claims.
pub mod jwt;
/// Ledger-backed signing key cache.
pub mod signing_key_cache;
/// Algorithm validation.
pub mod validation;

// Re-export key types for convenience
pub use error::{AuthError, Result};
pub use jwt::JwtClaims;
pub use signing_key_cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, SigningKeyCache};
pub use validation::{ACCEPTED_ALGORITHMS, FORBIDDEN_ALGORITHMS, validate_algorithm};
