//! Storage error types and result alias.
//!
//! This module defines the error types that can occur during storage operations.
//! All storage backends must map their internal errors to these standardized error types.
//!
//! # Error Types
//!
//! - [`StorageError::NotFound`] - Key does not exist in the storage backend
//! - [`StorageError::Conflict`] - Transaction conflict due to concurrent modification
//! - [`StorageError::Connection`] - Network or connection-related failures
//! - [`StorageError::Serialization`] - Data encoding/decoding failures
//! - [`StorageError::Internal`] - Backend-specific internal errors
//! - [`StorageError::Timeout`] - Operation exceeded time limit
//!
//! # Example
//!
//! ```
//! use inferadb_common_storage::{StorageError, StorageResult};
//!
//! fn lookup(key: &str) -> StorageResult<Vec<u8>> {
//!     Err(StorageError::not_found(key))
//! }
//! ```

use std::sync::Arc;

use thiserror::Error;

/// A boxed error type for source chain tracking.
pub type BoxError = Arc<dyn std::error::Error + Send + Sync>;

/// Result type alias for storage operations.
///
/// All storage operations return this type, providing consistent error handling
/// across different backend implementations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Errors that can occur during storage operations.
///
/// This enum represents the canonical set of errors that any storage backend
/// can produce. Backend implementations should map their internal error types
/// to these variants.
///
/// Errors preserve their source chain via the `#[source]` attribute, enabling
/// debugging tools to display the full error context.
///
/// # Non-exhaustive
///
/// This enum is marked `#[non_exhaustive]` — new variants may be added in
/// future minor releases without a semver-breaking change. Downstream match
/// expressions must include a wildcard arm (`_ =>`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// The requested key was not found in the storage backend.
    ///
    /// This is a recoverable error indicating the key does not exist.
    #[error("Key not found: {key}")]
    NotFound {
        /// The key that was not found.
        key: String,
    },

    /// Transaction conflict due to optimistic locking failure.
    ///
    /// This error occurs when a transaction attempts to commit but another
    /// concurrent transaction has modified the same keys. The transaction
    /// should typically be retried.
    #[error("Transaction conflict")]
    Conflict,

    /// Connection or network error.
    ///
    /// This error indicates a failure to communicate with the storage backend,
    /// such as a network timeout, DNS failure, or connection refused.
    #[error("Connection error: {message}")]
    Connection {
        /// Description of the connection error.
        message: String,
        /// The underlying error that caused this connection failure.
        #[source]
        source: Option<BoxError>,
    },

    /// Serialization or deserialization error.
    ///
    /// This error occurs when data cannot be encoded for storage or decoded
    /// when retrieved. This typically indicates data corruption or schema
    /// incompatibility.
    #[error("Serialization error: {message}")]
    Serialization {
        /// Description of the serialization error.
        message: String,
        /// The underlying error that caused serialization to fail.
        #[source]
        source: Option<BoxError>,
    },

    /// Internal storage backend error.
    ///
    /// This is a catch-all for backend-specific errors that don't fit other
    /// categories.
    #[error("Internal error: {message}")]
    Internal {
        /// Description of the internal error.
        message: String,
        /// The underlying error that caused this internal failure.
        #[source]
        source: Option<BoxError>,
    },

    /// Operation timed out.
    ///
    /// The storage operation exceeded its configured time limit. This can occur
    /// during long-running queries, slow network conditions, or backend overload.
    #[error("Operation timeout")]
    Timeout,
}

impl StorageError {
    /// Creates a new `NotFound` error for the given key.
    #[must_use]
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into() }
    }

    /// Creates a new `Conflict` error.
    #[must_use]
    pub fn conflict() -> Self {
        Self::Conflict
    }

    /// Creates a new `Connection` error with the given message.
    #[must_use]
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection { message: message.into(), source: None }
    }

    /// Creates a new `Connection` error with a message and source error.
    #[must_use]
    pub fn connection_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Connection { message: message.into(), source: Some(Arc::new(source)) }
    }

    /// Creates a new `Serialization` error with the given message.
    #[must_use]
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization { message: message.into(), source: None }
    }

    /// Creates a new `Serialization` error with a message and source error.
    #[must_use]
    pub fn serialization_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Serialization { message: message.into(), source: Some(Arc::new(source)) }
    }

    /// Creates a new `Internal` error with the given message.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal { message: message.into(), source: None }
    }

    /// Creates a new `Internal` error with a message and source error.
    #[must_use]
    pub fn internal_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Internal { message: message.into(), source: Some(Arc::new(source)) }
    }

    /// Creates a new `Timeout` error.
    #[must_use]
    pub fn timeout() -> Self {
        Self::Timeout
    }
}
