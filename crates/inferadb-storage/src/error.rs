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
//! use inferadb_storage::{StorageError, StorageResult};
//!
//! fn lookup(key: &str) -> StorageResult<Vec<u8>> {
//!     Err(StorageError::NotFound(key.to_string()))
//! }
//! ```

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
#[derive(Debug, thiserror::Error)]
pub enum StorageError {
    /// The requested key was not found in the storage backend.
    ///
    /// This is a recoverable error indicating the key does not exist.
    /// The string parameter contains the key that was not found.
    #[error("Key not found: {0}")]
    NotFound(String),

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
    #[error("Connection error: {0}")]
    Connection(String),

    /// Serialization or deserialization error.
    ///
    /// This error occurs when data cannot be encoded for storage or decoded
    /// when retrieved. This typically indicates data corruption or schema
    /// incompatibility.
    #[error("Serialization error: {0}")]
    Serialization(String),

    /// Internal storage backend error.
    ///
    /// This is a catch-all for backend-specific errors that don't fit other
    /// categories. The string contains a description of the underlying error.
    #[error("Internal error: {0}")]
    Internal(String),

    /// Operation timed out.
    ///
    /// The storage operation exceeded its configured time limit. This can occur
    /// during long-running queries, slow network conditions, or backend overload.
    #[error("Operation timeout")]
    Timeout,
}
