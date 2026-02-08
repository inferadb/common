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
//! - [`StorageError::CasRetriesExhausted`] - CAS retries exhausted due to sustained contention
//! - [`ConfigError`] - Configuration value failed validation at construction time
//!
//! # Trace Context
//!
//! Each error variant carries an optional `span_id` captured from the active
//! [`tracing::Span`] at construction time. This enables end-to-end correlation
//! of errors with the request that produced them, bridging the gap between
//! error types and distributed tracing infrastructure.
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

use std::{fmt, sync::Arc};

use thiserror::Error;

/// A boxed error type for source chain tracking.
pub type BoxError = Arc<dyn std::error::Error + Send + Sync>;

/// Result type alias for storage operations.
///
/// All storage operations return this type, providing consistent error handling
/// across different backend implementations.
pub type StorageResult<T> = Result<T, StorageError>;

/// Error returned when a configuration value fails validation.
///
/// Each variant names the field that was invalid and the constraint it
/// violated, providing actionable feedback for operators constructing
/// configs.
///
/// # Non-exhaustive
///
/// New variants may be added in future minor releases.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ConfigError {
    /// A field that must be positive was set to zero or a zero-length duration.
    #[error("invalid {field}: must be positive (got {value})")]
    MustBePositive {
        /// The name of the configuration field.
        field: &'static str,
        /// A human-readable representation of the invalid value.
        value: String,
    },

    /// A minimum-bound constraint was violated.
    #[error("invalid {field}: must be >= {min} (got {value})")]
    BelowMinimum {
        /// The name of the configuration field.
        field: &'static str,
        /// The minimum allowed value (human-readable).
        min: String,
        /// The actual value provided (human-readable).
        value: String,
    },

    /// A relational constraint between two fields was violated.
    #[error("invalid config: {field_a} ({value_a}) must be <= {field_b} ({value_b})")]
    InvalidRelation {
        /// The field that should be the smaller value.
        field_a: &'static str,
        /// The actual value of field_a (human-readable).
        value_a: String,
        /// The field that should be the larger value.
        field_b: &'static str,
        /// The actual value of field_b (human-readable).
        value_b: String,
    },
}

/// Captures the span ID from the current tracing span, if any.
fn current_span_id() -> Option<tracing::span::Id> {
    tracing::Span::current().id()
}

/// Errors that can occur during storage operations.
///
/// This enum represents the canonical set of errors that any storage backend
/// can produce. Backend implementations should map their internal error types
/// to these variants.
///
/// Errors preserve their source chain via the `#[source]` attribute, enabling
/// debugging tools to display the full error context.
///
/// Each variant carries an optional `span_id` captured from the active
/// [`tracing::Span`] at error creation time. When present, the span ID is
/// included in the [`Display`] output for log correlation.
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
    NotFound {
        /// The key that was not found.
        key: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Transaction conflict due to optimistic locking failure.
    ///
    /// This error occurs when a transaction attempts to commit but another
    /// concurrent transaction has modified the same keys. The transaction
    /// should typically be retried.
    Conflict {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Connection or network error.
    ///
    /// This error indicates a failure to communicate with the storage backend,
    /// such as a network timeout, DNS failure, or connection refused.
    Connection {
        /// Description of the connection error.
        message: String,
        /// The underlying error that caused this connection failure.
        #[source]
        source: Option<BoxError>,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Serialization or deserialization error.
    ///
    /// This error occurs when data cannot be encoded for storage or decoded
    /// when retrieved. This typically indicates data corruption or schema
    /// incompatibility.
    Serialization {
        /// Description of the serialization error.
        message: String,
        /// The underlying error that caused serialization to fail.
        #[source]
        source: Option<BoxError>,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Internal storage backend error.
    ///
    /// This is a catch-all for backend-specific errors that don't fit other
    /// categories.
    Internal {
        /// Description of the internal error.
        message: String,
        /// The underlying error that caused this internal failure.
        #[source]
        source: Option<BoxError>,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Operation timed out.
    ///
    /// The storage operation exceeded its configured time limit. This can occur
    /// during long-running queries, slow network conditions, or backend overload.
    Timeout {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// CAS retry attempts exhausted.
    ///
    /// A compare-and-set operation was retried the maximum number of times
    /// but every attempt encountered a concurrent modification conflict.
    /// This indicates sustained write contention on the same key.
    CasRetriesExhausted {
        /// The number of CAS attempts that were made before giving up.
        attempts: u32,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },
}

/// Appends ` [span=<id>]` to a formatter when a span ID is present.
fn fmt_span_suffix(f: &mut fmt::Formatter<'_>, span_id: &Option<tracing::span::Id>) -> fmt::Result {
    if let Some(id) = span_id { write!(f, " [span={}]", id.into_u64()) } else { Ok(()) }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotFound { key, span_id } => {
                write!(f, "Key not found: {key}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Conflict { span_id } => {
                write!(f, "Transaction conflict")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Connection { message, span_id, .. } => {
                write!(f, "Connection error: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Serialization { message, span_id, .. } => {
                write!(f, "Serialization error: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Internal { message, span_id, .. } => {
                write!(f, "Internal error: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Timeout { span_id } => {
                write!(f, "Operation timeout")?;
                fmt_span_suffix(f, span_id)
            },
            Self::CasRetriesExhausted { attempts, span_id } => {
                write!(f, "CAS retries exhausted after {attempts} attempts")?;
                fmt_span_suffix(f, span_id)
            },
        }
    }
}

impl StorageError {
    /// Creates a new `NotFound` error for the given key.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn not_found(key: impl Into<String>) -> Self {
        Self::NotFound { key: key.into(), span_id: current_span_id() }
    }

    /// Creates a new `Conflict` error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn conflict() -> Self {
        Self::Conflict { span_id: current_span_id() }
    }

    /// Creates a new `Connection` error with the given message.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn connection(message: impl Into<String>) -> Self {
        Self::Connection { message: message.into(), source: None, span_id: current_span_id() }
    }

    /// Creates a new `Connection` error with a message and source error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn connection_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Connection {
            message: message.into(),
            source: Some(Arc::new(source)),
            span_id: current_span_id(),
        }
    }

    /// Creates a new `Serialization` error with the given message.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn serialization(message: impl Into<String>) -> Self {
        Self::Serialization { message: message.into(), source: None, span_id: current_span_id() }
    }

    /// Creates a new `Serialization` error with a message and source error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn serialization_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Serialization {
            message: message.into(),
            source: Some(Arc::new(source)),
            span_id: current_span_id(),
        }
    }

    /// Creates a new `Internal` error with the given message.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal { message: message.into(), source: None, span_id: current_span_id() }
    }

    /// Creates a new `Internal` error with a message and source error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn internal_with_source(
        message: impl Into<String>,
        source: impl std::error::Error + Send + Sync + 'static,
    ) -> Self {
        Self::Internal {
            message: message.into(),
            source: Some(Arc::new(source)),
            span_id: current_span_id(),
        }
    }

    /// Creates a new `Timeout` error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn timeout() -> Self {
        Self::Timeout { span_id: current_span_id() }
    }

    /// Creates a new `CasRetriesExhausted` error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn cas_retries_exhausted(attempts: u32) -> Self {
        Self::CasRetriesExhausted { attempts, span_id: current_span_id() }
    }

    /// Returns the tracing span ID captured when this error was created,
    /// if a tracing subscriber was active at that time.
    ///
    /// Use this to correlate errors with distributed traces in structured
    /// logging output.
    #[must_use]
    pub fn span_id(&self) -> Option<&tracing::span::Id> {
        match self {
            Self::NotFound { span_id, .. }
            | Self::Conflict { span_id, .. }
            | Self::Connection { span_id, .. }
            | Self::Serialization { span_id, .. }
            | Self::Internal { span_id, .. }
            | Self::Timeout { span_id, .. }
            | Self::CasRetriesExhausted { span_id, .. } => span_id.as_ref(),
        }
    }

    /// Returns `true` if this error is transient and the operation may
    /// succeed on retry.
    ///
    /// Transient errors indicate the storage backend is temporarily
    /// unavailable (network partition, timeout, rate limiting) but may
    /// recover. Non-transient errors (not found, conflict, serialization,
    /// internal logic errors) represent definitive failures that will not
    /// resolve by retrying the same operation.
    #[must_use]
    pub fn is_transient(&self) -> bool {
        matches!(self, Self::Connection { .. } | Self::Timeout { .. })
    }
}
