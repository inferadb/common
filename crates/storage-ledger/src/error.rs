//! Error types for the Ledger storage backend.
//!
//! This module provides error types that map between the Ledger SDK's errors
//! and the generic [`StorageError`](inferadb_common_storage::StorageError) type.
//!
//! Error chains are preserved through the conversion, enabling debugging tools
//! to display the full error context from SDK through to storage layer.
//!
//! Each variant carries an optional `span_id` captured from the active
//! [`tracing::Span`] at error creation time for end-to-end trace correlation.

use std::fmt;

use inferadb_common_storage::StorageError;
use inferadb_ledger_sdk::SdkError;
use thiserror::Error;
use tonic::Code;

/// Result type alias for Ledger storage operations.
pub type Result<T> = std::result::Result<T, LedgerStorageError>;

/// Captures the span ID from the current tracing span, if any.
fn current_span_id() -> Option<tracing::span::Id> {
    tracing::Span::current().id()
}

/// Errors specific to the Ledger storage backend.
///
/// This error type wraps SDK errors and provides additional context
/// for storage-layer failures. The error chain is preserved when
/// converting to [`StorageError`].
///
/// Each variant carries an optional `span_id` captured from the active
/// [`tracing::Span`] at error creation time. When present, the span ID
/// is included in the [`Display`] output for log correlation.
///
/// # Non-exhaustive
///
/// This enum is marked `#[non_exhaustive]` — new variants may be added in
/// future minor releases without a semver-breaking change. Downstream match
/// expressions must include a wildcard arm (`_ =>`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum LedgerStorageError {
    /// Error from the Ledger SDK.
    Sdk {
        /// The underlying SDK error.
        #[source]
        source: SdkError,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Configuration error.
    Config {
        /// Description of the configuration error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Key encoding error.
    KeyEncoding {
        /// Description of the encoding error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Transaction error.
    Transaction {
        /// Description of the transaction error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },
}

/// Appends ` [span=<id>]` to a formatter when a span ID is present.
fn fmt_span_suffix(f: &mut fmt::Formatter<'_>, span_id: &Option<tracing::span::Id>) -> fmt::Result {
    if let Some(id) = span_id { write!(f, " [span={}]", id.into_u64()) } else { Ok(()) }
}

impl fmt::Display for LedgerStorageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Sdk { span_id, .. } => {
                write!(f, "Ledger SDK error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Config { span_id, .. } => {
                write!(f, "Configuration error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyEncoding { span_id, .. } => {
                write!(f, "Key encoding error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::Transaction { span_id, .. } => {
                write!(f, "Transaction error")?;
                fmt_span_suffix(f, span_id)
            },
        }
    }
}

impl From<SdkError> for LedgerStorageError {
    fn from(source: SdkError) -> Self {
        Self::Sdk { source, span_id: current_span_id() }
    }
}

impl LedgerStorageError {
    /// Creates a new `Config` error.
    #[must_use]
    pub fn config(message: impl Into<String>) -> Self {
        Self::Config { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyEncoding` error.
    #[must_use]
    pub fn key_encoding(message: impl Into<String>) -> Self {
        Self::KeyEncoding { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `Transaction` error.
    #[must_use]
    pub fn transaction(message: impl Into<String>) -> Self {
        Self::Transaction { message: message.into(), span_id: current_span_id() }
    }

    /// Returns the tracing span ID captured when this error was created.
    #[must_use]
    pub fn span_id(&self) -> Option<&tracing::span::Id> {
        match self {
            Self::Sdk { span_id, .. }
            | Self::Config { span_id, .. }
            | Self::KeyEncoding { span_id, .. }
            | Self::Transaction { span_id, .. } => span_id.as_ref(),
        }
    }

    /// Returns a detailed diagnostic string for server-side logging.
    ///
    /// Unlike [`Display`], which produces generic messages safe for external
    /// consumers, this method includes the full SDK error message and other
    /// internal context. **Never expose this output to external callers.**
    #[must_use]
    pub fn detail(&self) -> String {
        match self {
            Self::Sdk { source, .. } => {
                format!("Ledger SDK error: {source}")
            },
            Self::Config { message, .. } => {
                format!("Configuration error: {message}")
            },
            Self::KeyEncoding { message, .. } => {
                format!("Key encoding error: {message}")
            },
            Self::Transaction { message, .. } => {
                format!("Transaction error: {message}")
            },
        }
    }
}

impl From<LedgerStorageError> for StorageError {
    fn from(err: LedgerStorageError) -> Self {
        match err {
            LedgerStorageError::Sdk { source, .. } => sdk_error_to_storage_error(source),
            LedgerStorageError::Config { message, .. } => {
                StorageError::internal(format!("Config: {message}"))
            },
            LedgerStorageError::KeyEncoding { message, .. } => StorageError::serialization(message),
            LedgerStorageError::Transaction { message, .. } => {
                StorageError::internal(format!("Transaction: {message}"))
            },
        }
    }
}

/// Converts an SDK error to a storage error, preserving the error chain.
///
/// This mapping is designed to preserve the semantic meaning of errors
/// while using the canonical [`StorageError`] variants. The original
/// SDK error is preserved as the source for debugging.
fn sdk_error_to_storage_error(err: SdkError) -> StorageError {
    match &err {
        // Connection and transport errors - preserve source chain
        SdkError::Connection { message, .. } => {
            StorageError::connection_with_source(message.clone(), err)
        },
        SdkError::Transport { .. } => StorageError::connection_with_source("Transport error", err),
        SdkError::Unavailable { message } => {
            StorageError::connection_with_source(message.clone(), err)
        },
        SdkError::StreamDisconnected { message } => {
            StorageError::connection_with_source(message.clone(), err)
        },

        // Timeout errors
        SdkError::Timeout { duration_ms } => {
            tracing::warn!(duration_ms = duration_ms, "Ledger operation timed out");
            StorageError::timeout()
        },

        // RPC errors - map based on gRPC status code
        SdkError::Rpc { code, message, .. } => match code {
            Code::NotFound => StorageError::not_found(message.clone()),
            Code::AlreadyExists => StorageError::conflict(),
            Code::Aborted | Code::FailedPrecondition => StorageError::conflict(),
            Code::InvalidArgument => StorageError::serialization_with_source(message.clone(), err),
            Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted => {
                StorageError::connection_with_source(message.clone(), err)
            },
            Code::PermissionDenied | Code::Unauthenticated => {
                StorageError::internal_with_source(format!("Auth error: {message}"), err)
            },
            Code::DataLoss => {
                StorageError::internal_with_source(format!("Data loss: {message}"), err)
            },
            _ => {
                StorageError::internal_with_source(format!("gRPC error ({code:?}): {message}"), err)
            },
        },

        // Retry exhausted - preserve the full context
        SdkError::RetryExhausted { attempts, last_error, .. } => {
            tracing::error!(attempts = attempts, "Retry exhausted: {}", last_error);
            StorageError::connection_with_source(
                format!("Retry exhausted after {attempts} attempts: {last_error}"),
                err,
            )
        },

        // Idempotency errors
        SdkError::AlreadyCommitted { tx_id, block_height } => {
            tracing::debug!(
                tx_id = tx_id,
                block_height = block_height,
                "Operation already committed"
            );
            StorageError::internal_with_source(
                format!("Unexpected: already committed tx={tx_id}"),
                err,
            )
        },

        SdkError::Idempotency { message, .. } => {
            StorageError::internal_with_source(format!("Idempotency error: {message}"), err)
        },

        // Configuration and validation errors
        SdkError::Config { message } => {
            StorageError::internal_with_source(format!("Config: {message}"), err)
        },
        SdkError::InvalidUrl { url, message } => {
            StorageError::internal_with_source(format!("Invalid URL '{url}': {message}"), err)
        },

        // Client shutdown
        SdkError::Shutdown => StorageError::connection_with_source("Client shutting down", err),

        // Proof verification - indicates data integrity issue
        SdkError::ProofVerification { reason } => {
            tracing::error!("Proof verification failed: {}", reason);
            StorageError::internal_with_source(format!("Proof verification failed: {reason}"), err)
        },

        // Rate limiting - connection-level retry
        SdkError::RateLimited { retry_after, .. } => {
            tracing::warn!(
                retry_after_ms = retry_after.as_millis() as u64,
                "Rate limited by Ledger"
            );
            StorageError::connection_with_source("Rate limited", err)
        },

        // Request cancelled by caller
        SdkError::Cancelled => StorageError::internal_with_source("Request cancelled", err),

        // Client-side validation error
        SdkError::Validation { message } => {
            StorageError::serialization_with_source(message.clone(), err)
        },

        // Circuit breaker open
        SdkError::CircuitOpen { endpoint, .. } => {
            tracing::warn!(endpoint = %endpoint, "Circuit breaker open");
            StorageError::connection_with_source(format!("Circuit open for {endpoint}"), err)
        },
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::error::Error;

    use snafu::Location;

    use super::*;

    #[test]
    fn test_connection_error_mapping() {
        let sdk_err = SdkError::Connection {
            message: "connection refused".into(),
            location: Location::default(),
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
        // Verify source chain is preserved
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_timeout_error_mapping() {
        let sdk_err = SdkError::Timeout { duration_ms: 30000 };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Timeout { .. }));
    }

    #[test]
    fn test_not_found_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::NotFound,
            message: "key not found".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::NotFound { .. }));
    }

    #[test]
    fn test_conflict_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::Aborted,
            message: "transaction conflict".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_already_exists_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::AlreadyExists,
            message: "key exists".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_invalid_argument_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::InvalidArgument,
            message: "invalid key format".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Serialization { .. }));
        // Verify source chain is preserved
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_config_error_mapping() {
        let err = LedgerStorageError::config("missing endpoint");
        let storage_err: StorageError = err.into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
    }

    #[test]
    fn test_key_encoding_error_mapping() {
        let err = LedgerStorageError::key_encoding("invalid hex");
        let storage_err: StorageError = err.into();

        assert!(matches!(storage_err, StorageError::Serialization { .. }));
    }

    #[test]
    fn test_transaction_error_mapping() {
        let err = LedgerStorageError::transaction("commit failed");
        let storage_err: StorageError = err.into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
    }

    #[test]
    fn test_unavailable_error_mapping() {
        let sdk_err = SdkError::Unavailable { message: "service down".into() };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_stream_disconnected_error_mapping() {
        let sdk_err = SdkError::StreamDisconnected { message: "stream closed".into() };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_retry_exhausted_error_mapping() {
        let sdk_err = SdkError::RetryExhausted {
            attempts: 3,
            last_error: "still down".into(),
            attempt_history: vec![],
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_already_committed_error_mapping() {
        let sdk_err = SdkError::AlreadyCommitted { tx_id: "tx-123".into(), block_height: 42 };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_idempotency_error_mapping() {
        let sdk_err = SdkError::Idempotency {
            message: "duplicate request".into(),
            conflict_key: None,
            original_tx_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_config_sdk_error_mapping() {
        let sdk_err = SdkError::Config { message: "invalid config".into() };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_invalid_url_error_mapping() {
        let sdk_err =
            SdkError::InvalidUrl { url: "not-a-url".into(), message: "parse error".into() };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_shutdown_error_mapping() {
        let sdk_err = SdkError::Shutdown;
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_proof_verification_error_mapping() {
        let sdk_err = SdkError::ProofVerification { reason: "hash mismatch" };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_failed_precondition_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::FailedPrecondition,
            message: "precondition failed".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_data_loss_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::DataLoss,
            message: "data corrupted".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_permission_denied_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::PermissionDenied,
            message: "access denied".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_unauthenticated_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::Unauthenticated,
            message: "not authed".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_unknown_rpc_code_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::Unknown,
            message: "unknown error".into(),
            request_id: None,
            trace_id: None,
        };
        let storage_err: StorageError = LedgerStorageError::from(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
        assert!(storage_err.source().is_some());
    }

    #[test]
    fn test_error_display_is_generic() {
        // Display should NOT contain the internal message
        let err = LedgerStorageError::config("missing endpoint https://ledger.internal:9200");
        assert_eq!(err.to_string(), "Configuration error");

        let err = LedgerStorageError::key_encoding("bad hex");
        assert_eq!(err.to_string(), "Key encoding error");

        let err = LedgerStorageError::transaction("commit failed at block 42");
        assert_eq!(err.to_string(), "Transaction error");
    }

    #[test]
    fn test_detail_preserves_internal_context() {
        let err = LedgerStorageError::config("missing endpoint https://ledger.internal:9200");
        assert_eq!(
            err.detail(),
            "Configuration error: missing endpoint https://ledger.internal:9200"
        );

        let err = LedgerStorageError::key_encoding("bad hex");
        assert_eq!(err.detail(), "Key encoding error: bad hex");

        let err = LedgerStorageError::transaction("commit failed at block 42");
        assert_eq!(err.detail(), "Transaction error: commit failed at block 42");
    }

    /// Installs a minimal tracing subscriber for the duration of the closure.
    fn with_subscriber<F: FnOnce()>(f: F) {
        use tracing_subscriber::layer::SubscriberExt;
        let subscriber =
            tracing_subscriber::Registry::default().with(tracing_subscriber::fmt::layer());
        tracing::subscriber::with_default(subscriber, f);
    }

    #[test]
    fn span_id_captured_in_ledger_errors() {
        with_subscriber(|| {
            let span = tracing::info_span!("ledger_test");
            let _guard = span.enter();

            let err = LedgerStorageError::config("bad");
            assert!(err.span_id().is_some(), "span_id must be captured");
        });
    }

    #[test]
    fn span_propagates_through_ledger_to_storage_conversion() {
        with_subscriber(|| {
            let span = tracing::info_span!("conversion_test");
            let _guard = span.enter();

            // Create a LedgerStorageError inside the span
            let ledger_err = LedgerStorageError::key_encoding("bad hex");
            assert!(ledger_err.span_id().is_some());

            // Convert to StorageError — the From impl calls a constructor
            // which captures the *current* span at conversion time
            let storage_err: StorageError = ledger_err.into();
            assert!(
                storage_err.span_id().is_some(),
                "StorageError must capture span_id during From conversion"
            );
        });
    }

    #[test]
    fn display_includes_span_for_ledger_error() {
        with_subscriber(|| {
            let span = tracing::info_span!("display_test");
            let _guard = span.enter();

            let err = LedgerStorageError::config("test");
            let display = err.to_string();
            assert!(display.contains("[span="), "Display must include span: {display}");
        });
    }
}
