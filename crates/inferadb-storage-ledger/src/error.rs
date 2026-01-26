//! Error types for the Ledger storage backend.
//!
//! This module provides error types that map between the Ledger SDK's errors
//! and the generic [`StorageError`](inferadb_storage::StorageError) type.

use inferadb_ledger_sdk::SdkError;
use inferadb_storage::StorageError;
use tonic::Code;

/// Result type alias for Ledger storage operations.
pub type Result<T> = std::result::Result<T, LedgerStorageError>;

/// Errors specific to the Ledger storage backend.
///
/// This error type wraps SDK errors and provides additional context
/// for storage-layer failures.
#[derive(Debug, thiserror::Error)]
pub enum LedgerStorageError {
    /// Error from the Ledger SDK.
    #[error("Ledger SDK error: {0}")]
    Sdk(#[from] SdkError),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Key encoding error.
    #[error("Key encoding error: {0}")]
    KeyEncoding(String),

    /// Transaction error.
    #[error("Transaction error: {0}")]
    Transaction(String),
}

impl From<LedgerStorageError> for StorageError {
    fn from(err: LedgerStorageError) -> Self {
        match err {
            LedgerStorageError::Sdk(sdk_err) => sdk_error_to_storage_error(sdk_err),
            LedgerStorageError::Config(msg) => StorageError::internal(format!("Config: {msg}")),
            LedgerStorageError::KeyEncoding(msg) => StorageError::serialization(msg),
            LedgerStorageError::Transaction(msg) => {
                StorageError::internal(format!("Transaction: {msg}"))
            }
        }
    }
}

/// Converts an SDK error to a storage error.
///
/// This mapping is designed to preserve the semantic meaning of errors
/// while using the canonical [`StorageError`] variants.
fn sdk_error_to_storage_error(err: SdkError) -> StorageError {
    match &err {
        // Connection and transport errors
        SdkError::Connection { message, .. } => StorageError::connection(message.clone()),
        SdkError::Transport { source, .. } => StorageError::connection(source.to_string()),
        SdkError::Unavailable { message } => StorageError::connection(message.clone()),
        SdkError::StreamDisconnected { message } => StorageError::connection(message.clone()),

        // Timeout errors
        SdkError::Timeout { duration_ms } => {
            // Log the timeout duration for debugging
            tracing::warn!(duration_ms = duration_ms, "Ledger operation timed out");
            StorageError::timeout()
        }

        // RPC errors - map based on gRPC status code
        SdkError::Rpc { code, message } => match code {
            Code::NotFound => StorageError::not_found(message.clone()),
            Code::AlreadyExists => StorageError::conflict(),
            Code::Aborted | Code::FailedPrecondition => StorageError::conflict(),
            Code::InvalidArgument => StorageError::serialization(message.clone()),
            Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted => {
                if err.is_retryable() {
                    // Retryable errors are typically transient
                    StorageError::connection(message.clone())
                } else {
                    StorageError::internal(message.clone())
                }
            }
            Code::PermissionDenied | Code::Unauthenticated => {
                StorageError::internal(format!("Auth error: {message}"))
            }
            Code::DataLoss => StorageError::internal(format!("Data loss: {message}")),
            _ => StorageError::internal(format!("gRPC error ({code:?}): {message}")),
        },

        // Retry exhausted
        SdkError::RetryExhausted {
            attempts,
            last_error,
        } => {
            tracing::error!(attempts = attempts, "Retry exhausted: {}", last_error);
            StorageError::connection(format!(
                "Retry exhausted after {attempts} attempts: {last_error}"
            ))
        }

        // Idempotency errors - these shouldn't normally surface to the storage layer
        SdkError::AlreadyCommitted {
            tx_id,
            block_height,
        } => {
            // This is actually success - the operation was already applied
            tracing::debug!(
                tx_id = tx_id,
                block_height = block_height,
                "Operation already committed"
            );
            // Return internal error as this shouldn't happen in normal flow
            StorageError::internal(format!("Unexpected: already committed tx={tx_id}"))
        }

        SdkError::SequenceGap {
            expected,
            server_has,
        } => StorageError::internal(format!(
            "Sequence gap: expected {expected}, server has {server_has}"
        )),

        SdkError::Idempotency { message } => {
            StorageError::internal(format!("Idempotency error: {message}"))
        }

        // Configuration and validation errors
        SdkError::Config { message } => StorageError::internal(format!("Config: {message}")),
        SdkError::InvalidUrl { url, message } => {
            StorageError::internal(format!("Invalid URL '{url}': {message}"))
        }

        // Client shutdown
        SdkError::Shutdown => StorageError::connection("Client shutting down"),

        // Proof verification - indicates data integrity issue
        SdkError::ProofVerification { reason } => {
            tracing::error!("Proof verification failed: {}", reason);
            StorageError::internal(format!("Proof verification failed: {reason}"))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use snafu::Location;

    #[test]
    fn test_connection_error_mapping() {
        let sdk_err = SdkError::Connection {
            message: "connection refused".into(),
            location: Location::default(),
        };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Connection { .. }));
    }

    #[test]
    fn test_timeout_error_mapping() {
        let sdk_err = SdkError::Timeout { duration_ms: 30000 };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Timeout { .. }));
    }

    #[test]
    fn test_not_found_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::NotFound,
            message: "key not found".into(),
        };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::NotFound { .. }));
    }

    #[test]
    fn test_conflict_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::Aborted,
            message: "transaction conflict".into(),
        };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_already_exists_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::AlreadyExists,
            message: "key exists".into(),
        };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Conflict { .. }));
    }

    #[test]
    fn test_invalid_argument_rpc_mapping() {
        let sdk_err = SdkError::Rpc {
            code: Code::InvalidArgument,
            message: "invalid key format".into(),
        };
        let storage_err: StorageError = LedgerStorageError::Sdk(sdk_err).into();

        assert!(matches!(storage_err, StorageError::Serialization { .. }));
    }

    #[test]
    fn test_config_error_mapping() {
        let err = LedgerStorageError::Config("missing endpoint".into());
        let storage_err: StorageError = err.into();

        assert!(matches!(storage_err, StorageError::Internal { .. }));
    }

    #[test]
    fn test_key_encoding_error_mapping() {
        let err = LedgerStorageError::KeyEncoding("invalid hex".into());
        let storage_err: StorageError = err.into();

        assert!(matches!(storage_err, StorageError::Serialization { .. }));
    }
}
