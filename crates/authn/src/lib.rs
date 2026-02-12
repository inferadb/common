//! Shared JWT authentication types and utilities for InferaDB services.
//!
//! This crate provides:
//! - **JWT validation**: Claims parsing, signature verification
//! - **Signing key cache**: Ledger-backed cache with TTL and fallback
//! - **Algorithm validation**: Security checks for JWT algorithms
//!
//! # Features
//!
//! - Only EdDSA (Ed25519) is currently supported for JWT signatures
//! - Symmetric algorithms (HS256, etc.) are explicitly rejected
//! - Graceful degradation during Ledger outages via fallback cache
//!
//! # Key Material Zeroing
//!
//! This crate uses [`zeroize::Zeroizing`] wrappers to scrub sensitive data from
//! memory when it is no longer needed. The following code paths are protected:
//!
//! | Location | Material | Protection |
//! |---|---|---|
//! | [`PublicSigningKey`](inferadb_common_storage::auth::PublicSigningKey) | Base64url public key | `Zeroizing<String>` field |
//! | `to_decoding_key()` decoded bytes | Raw 32-byte public key | `Zeroizing<Vec<u8>>` |
//! | `to_decoding_key()` fixed-size copy | `[u8; 32]` stack array | `Zeroizing<[u8; 32]>` |
//! | `decode_jwt_claims()` payload | Decoded JWT claims JSON | `Zeroizing<Vec<u8>>` |
//! | Test helpers `generate_test_keypair()` | PKCS#8 DER private key | `Zeroizing<Vec<u8>>` |
//! | Test helpers `generate_test_keypair()` | Raw 32-byte private key | `Zeroizing<[u8; 32]>` |
//!
//! **Known gaps** (due to external types that do not implement `Zeroize`):
//!
//! - `jsonwebtoken::DecodingKey` — holds an internal copy of key bytes that cannot be zeroed. The
//!   decoded raw bytes are dropped before constructing the `DecodingKey` to minimize overlap.
//! - `jsonwebtoken::EncodingKey` — used only in test code for JWT signing. Cannot be wrapped in
//!   `Zeroizing` (external type).
//! - `ed25519_dalek::SigningKey` — used only in test code. The `SigningKey` type implements its own
//!   [`Zeroize`](zeroize::Zeroize) on drop.
//!
//! # Examples
//!
//! ```no_run
//! // Requires a `PublicSigningKeyStore` implementation and a valid JWT token.
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

/// Authentication error types and the crate-wide [`Result`](error::Result) alias.
pub mod error;
/// JWT decoding, claims parsing, and signature verification.
pub mod jwt;
/// JWT replay prevention via JTI (JWT ID) tracking.
pub mod replay;
/// Ledger-backed signing key cache with TTL and fallback tiers.
pub mod signing_key_cache;
/// Test utilities for authentication testing (requires the `testutil` feature).
#[cfg(any(test, feature = "testutil"))]
#[allow(clippy::expect_used)]
pub mod testutil;
/// Algorithm and key-ID validation for JWT headers.
pub mod validation;

/// Re-exported types, traits, constants, and functions for convenience.
pub use error::{AuthError, Result};
pub use jwt::{DEFAULT_MAX_IAT_AGE, JwtClaims};
pub use replay::{InMemoryReplayDetector, ReplayDetector};
pub use signing_key_cache::{
    DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL, DEFAULT_FALLBACK_CAPACITY,
    DEFAULT_FALLBACK_CRITICAL_THRESHOLD, DEFAULT_FALLBACK_TTL, DEFAULT_FALLBACK_WARN_THRESHOLD,
    SigningKeyCache,
};
pub use validation::{
    ACCEPTED_ALGORITHMS, FORBIDDEN_ALGORITHMS, MAX_KID_LENGTH, validate_algorithm, validate_kid,
};
