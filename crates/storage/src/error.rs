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

    /// The circuit breaker is open and rejecting requests.
    ///
    /// This error is returned when the backend's circuit breaker has
    /// detected sustained failures and is preventing further requests
    /// to avoid cascading failures. The caller should wait for the
    /// circuit breaker's recovery timeout before retrying.
    CircuitOpen {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Key or value exceeds the configured size limit.
    ///
    /// This error is returned when a write operation provides a key or
    /// value whose byte length exceeds the backend's configured
    /// [`SizeLimits`](crate::SizeLimits).
    SizeLimitExceeded {
        /// Whether the oversized payload was `"key"` or `"value"`.
        kind: &'static str,
        /// The actual size of the payload in bytes.
        actual: usize,
        /// The configured maximum size in bytes.
        limit: usize,
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
            Self::NotFound { span_id, .. } => {
                write!(f, "Key not found")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Conflict { span_id } => {
                write!(f, "Transaction conflict")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Connection { span_id, .. } => {
                write!(f, "Connection error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Serialization { span_id, .. } => {
                write!(f, "Serialization error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Internal { span_id, .. } => {
                write!(f, "Internal error")?;
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
            Self::CircuitOpen { span_id } => {
                write!(f, "Circuit breaker is open")?;
                fmt_span_suffix(f, span_id)
            },
            Self::SizeLimitExceeded { kind, actual, limit, span_id } => {
                write!(f, "Size limit exceeded: {kind} is {actual} bytes, limit is {limit} bytes")?;
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

    /// Creates a new `CircuitOpen` error.
    ///
    /// Captures the current tracing span ID for log correlation.
    #[must_use]
    pub fn circuit_open() -> Self {
        Self::CircuitOpen { span_id: current_span_id() }
    }

    /// Creates a new `SizeLimitExceeded` error.
    ///
    /// `kind` should be `"key"` or `"value"`. Captures the current tracing
    /// span ID for log correlation.
    #[must_use]
    pub fn size_limit_exceeded(kind: &'static str, actual: usize, limit: usize) -> Self {
        Self::SizeLimitExceeded { kind, actual, limit, span_id: current_span_id() }
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
            | Self::CasRetriesExhausted { span_id, .. }
            | Self::CircuitOpen { span_id, .. }
            | Self::SizeLimitExceeded { span_id, .. } => span_id.as_ref(),
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

    /// Returns a detailed diagnostic string for server-side logging.
    ///
    /// Unlike [`Display`], which produces generic messages safe for external
    /// consumers, this method includes internal details such as connection
    /// error messages, key names, and backend-specific context. **Never
    /// expose this output to external callers.**
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::NotFound { key, .. } => {
                format!("Key not found: {key}")
            },
            Self::Connection { message, .. } => {
                format!("Connection error: {message}")
            },
            Self::Serialization { message, .. } => {
                format!("Serialization error: {message}")
            },
            Self::Internal { message, .. } => {
                format!("Internal error: {message}")
            },
            // Variants with no additional private context — detail matches Display
            _ => self.to_string(),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use tracing_subscriber::{Registry, layer::SubscriberExt};

    use super::*;

    /// Installs a minimal tracing subscriber for the duration of the closure,
    /// ensuring `Span::current().id()` returns `Some`.
    fn with_subscriber<F: FnOnce()>(f: F) {
        let subscriber = Registry::default().with(tracing_subscriber::fmt::layer());
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn span_id_captured_when_subscriber_active() {
        with_subscriber(|| {
            let span = tracing::info_span!("test_span");
            let _guard = span.enter();

            let err = StorageError::not_found("key-1");
            assert!(err.span_id().is_some(), "span_id must be captured inside active span");
        });
    }

    #[test]
    fn span_id_none_without_subscriber() {
        // No subscriber → current_span_id() returns None
        let err = StorageError::not_found("key-2");
        assert!(err.span_id().is_none(), "span_id must be None without a subscriber");
    }

    #[test]
    fn display_includes_span_id_when_present() {
        with_subscriber(|| {
            let span = tracing::info_span!("display_test");
            let _guard = span.enter();

            let err = StorageError::timeout();
            let display = err.to_string();
            assert!(display.contains("[span="), "Display must include span suffix: {display}");
        });
    }

    #[test]
    fn display_excludes_span_id_when_absent() {
        let err = StorageError::timeout();
        let display = err.to_string();
        assert!(!display.contains("[span="), "Display must not include span suffix: {display}");
        assert_eq!(display, "Operation timeout");
    }

    #[test]
    fn each_constructor_captures_span() {
        with_subscriber(|| {
            let span = tracing::info_span!("constructor_test");
            let _guard = span.enter();

            assert!(StorageError::not_found("k").span_id().is_some());
            assert!(StorageError::conflict().span_id().is_some());
            assert!(StorageError::connection("msg").span_id().is_some());
            assert!(
                StorageError::connection_with_source("msg", StorageError::timeout())
                    .span_id()
                    .is_some()
            );
            assert!(StorageError::serialization("msg").span_id().is_some());
            assert!(
                StorageError::serialization_with_source("msg", StorageError::timeout())
                    .span_id()
                    .is_some()
            );
            assert!(StorageError::internal("msg").span_id().is_some());
            assert!(
                StorageError::internal_with_source("msg", StorageError::timeout())
                    .span_id()
                    .is_some()
            );
            assert!(StorageError::timeout().span_id().is_some());
            assert!(StorageError::cas_retries_exhausted(3).span_id().is_some());
            assert!(StorageError::circuit_open().span_id().is_some());
        });
    }

    #[test]
    fn display_is_generic_for_connection() {
        let err = StorageError::connection("tcp://ledger.internal:9200 connection refused");
        assert_eq!(err.to_string(), "Connection error");
    }

    #[test]
    fn display_is_generic_for_internal() {
        let err = StorageError::internal("Auth error: permission denied for user admin");
        assert_eq!(err.to_string(), "Internal error");
    }

    #[test]
    fn display_is_generic_for_serialization() {
        let err = StorageError::serialization("invalid key format at path /vault/secret");
        assert_eq!(err.to_string(), "Serialization error");
    }

    #[test]
    fn display_is_generic_for_not_found() {
        let err = StorageError::not_found("ns-123/vault-456/secret-key");
        assert_eq!(err.to_string(), "Key not found");
    }

    #[test]
    fn detail_preserves_internal_context() {
        let err = StorageError::connection("tcp://ledger.internal:9200 refused");
        assert_eq!(err.detail(), "Connection error: tcp://ledger.internal:9200 refused");

        let err = StorageError::not_found("ns-123/vault-456/key");
        assert_eq!(err.detail(), "Key not found: ns-123/vault-456/key");

        let err = StorageError::internal("Auth error: admin denied");
        assert_eq!(err.detail(), "Internal error: Auth error: admin denied");
    }

    #[test]
    fn display_never_contains_internal_details() {
        let cases = vec![
            (
                StorageError::connection("tcp://ledger.internal:9200 connection refused"),
                vec!["ledger.internal", "9200", "tcp://", "connection refused"],
            ),
            (
                StorageError::internal("Auth error: denied for user admin@org"),
                vec!["admin@org", "denied", "Auth error"],
            ),
            (
                StorageError::serialization("invalid format at /vault/secret"),
                vec!["/vault/secret", "invalid format"],
            ),
            (
                StorageError::not_found("ns-123/vault-456/secret-key"),
                vec!["ns-123", "vault-456", "secret-key"],
            ),
        ];

        for (err, forbidden_substrings) in cases {
            let display = err.to_string();
            for forbidden in forbidden_substrings {
                assert!(
                    !display.contains(forbidden),
                    "Display must not contain '{forbidden}', got: {display}",
                );
            }
        }
    }
}
