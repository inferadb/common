//! Authentication error types.
//!
//! This module defines errors that can occur during JWT authentication and
//! signing key validation.

use thiserror::Error;

/// Authentication and authorization errors.
///
/// # Non-exhaustive
///
/// This enum is marked `#[non_exhaustive]` — new variants may be added in
/// future minor releases without a semver-breaking change. Downstream match
/// expressions must include a wildcard arm (`_ =>`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Malformed JWT - cannot be decoded.
    #[error("Invalid token format: {0}")]
    InvalidTokenFormat(String),

    /// Token has expired.
    #[error("Token expired")]
    TokenExpired,

    /// Token not yet valid (nbf claim in future).
    #[error("Token not yet valid")]
    TokenNotYetValid,

    /// Signature verification failed.
    #[error("Invalid signature")]
    InvalidSignature,

    /// Unknown or invalid issuer.
    #[error("Invalid issuer: {0}")]
    InvalidIssuer(String),

    /// Audience doesn't match expected value.
    #[error("Invalid audience: {0}")]
    InvalidAudience(String),

    /// Required claim is missing.
    #[error("Missing claim: {0}")]
    MissingClaim(String),

    /// Scope validation failed.
    #[error("Invalid scope: {0}")]
    InvalidScope(String),

    /// Algorithm not in allowed list.
    #[error("Unsupported algorithm: {0}")]
    UnsupportedAlgorithm(String),

    /// JWKS-related errors.
    #[error("JWKS error: {0}")]
    JwksError(String),

    /// OIDC discovery failed.
    #[error("OIDC discovery failed: {0}")]
    OidcDiscoveryFailed(String),

    /// Token introspection failed.
    #[error("Introspection failed: {0}")]
    IntrospectionFailed(String),

    /// Invalid introspection response.
    #[error("Invalid introspection response: {0}")]
    InvalidIntrospectionResponse(String),

    /// Token is inactive (from introspection).
    #[error("Token is inactive")]
    TokenInactive,

    /// Required tenant_id claim missing from OAuth token.
    #[error("Missing tenant_id claim in OAuth token")]
    MissingTenantId,

    /// Token too old (issued at exceeds max age).
    #[error("Token too old")]
    TokenTooOld,

    // ========== Ledger-backed key validation errors ==========
    /// Signing key not found in Ledger.
    #[error("Signing key not found: {kid}")]
    KeyNotFound {
        /// Key ID that was not found.
        kid: String,
    },

    /// Signing key is inactive (soft-disabled).
    #[error("Signing key is inactive: {kid}")]
    KeyInactive {
        /// Key ID that is inactive.
        kid: String,
    },

    /// Signing key has been permanently revoked.
    #[error("Signing key revoked: {kid}")]
    KeyRevoked {
        /// Key ID that was revoked.
        kid: String,
    },

    /// Signing key is not yet valid (valid_from in future).
    #[error("Signing key not yet valid: {kid}")]
    KeyNotYetValid {
        /// Key ID that is not yet valid.
        kid: String,
    },

    /// Signing key has expired (valid_until in past).
    #[error("Signing key expired: {kid}")]
    KeyExpired {
        /// Key ID that expired.
        kid: String,
    },

    /// Invalid public key format.
    #[error("Invalid public key: {0}")]
    InvalidPublicKey(String),

    /// Storage backend error during key lookup.
    ///
    /// Wraps the original [`StorageError`] to preserve the full error source
    /// chain for debugging and structured logging.
    ///
    /// [`StorageError`]: inferadb_common_storage::StorageError
    #[error("Key storage error: {0}")]
    KeyStorageError(
        /// The underlying storage error that caused the key lookup to fail.
        #[source]
        inferadb_common_storage::StorageError,
    ),
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::InvalidToken => {
                AuthError::InvalidTokenFormat("Invalid JWT structure".into())
            },
            ErrorKind::InvalidSignature => AuthError::InvalidSignature,
            ErrorKind::ExpiredSignature => AuthError::TokenExpired,
            ErrorKind::ImmatureSignature => AuthError::TokenNotYetValid,
            ErrorKind::InvalidAudience => {
                AuthError::InvalidAudience("Audience validation failed".into())
            },
            ErrorKind::InvalidIssuer => AuthError::InvalidIssuer("Issuer validation failed".into()),
            ErrorKind::InvalidAlgorithm => {
                AuthError::UnsupportedAlgorithm("Algorithm not supported".into())
            },
            _ => AuthError::InvalidTokenFormat(format!("JWT error: {}", err)),
        }
    }
}

impl From<inferadb_common_storage::StorageError> for AuthError {
    fn from(err: inferadb_common_storage::StorageError) -> Self {
        AuthError::KeyStorageError(err)
    }
}

/// Result type alias for authentication operations.
pub type Result<T> = std::result::Result<T, AuthError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_error_display() {
        let err = AuthError::InvalidTokenFormat("test".into());
        assert_eq!(err.to_string(), "Invalid token format: test");

        let err = AuthError::TokenExpired;
        assert_eq!(err.to_string(), "Token expired");

        let err = AuthError::MissingClaim("tenant_id".into());
        assert_eq!(err.to_string(), "Missing claim: tenant_id");
    }

    #[test]
    fn test_error_from_jsonwebtoken() {
        let jwt_err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
        let auth_err: AuthError = jwt_err.into();

        assert!(matches!(auth_err, AuthError::TokenExpired));
    }

    #[test]
    fn test_oauth_error_variants() {
        let err = AuthError::OidcDiscoveryFailed("endpoint not found".into());
        assert_eq!(err.to_string(), "OIDC discovery failed: endpoint not found");

        let err = AuthError::IntrospectionFailed("connection refused".into());
        assert_eq!(err.to_string(), "Introspection failed: connection refused");

        let err = AuthError::InvalidIntrospectionResponse("malformed JSON".into());
        assert_eq!(err.to_string(), "Invalid introspection response: malformed JSON");

        let err = AuthError::TokenInactive;
        assert_eq!(err.to_string(), "Token is inactive");

        let err = AuthError::MissingTenantId;
        assert_eq!(err.to_string(), "Missing tenant_id claim in OAuth token");
    }

    #[test]
    fn test_key_error_variants() {
        let err = AuthError::KeyNotFound { kid: "key-123".into() };
        assert_eq!(err.to_string(), "Signing key not found: key-123");

        let err = AuthError::KeyInactive { kid: "key-456".into() };
        assert_eq!(err.to_string(), "Signing key is inactive: key-456");

        let err = AuthError::KeyRevoked { kid: "key-789".into() };
        assert_eq!(err.to_string(), "Signing key revoked: key-789");

        let err = AuthError::KeyNotYetValid { kid: "key-abc".into() };
        assert_eq!(err.to_string(), "Signing key not yet valid: key-abc");

        let err = AuthError::KeyExpired { kid: "key-def".into() };
        assert_eq!(err.to_string(), "Signing key expired: key-def");
    }

    #[test]
    fn test_key_storage_error_display() {
        let storage_err = inferadb_common_storage::StorageError::Connection {
            message: "connection refused".into(),
            source: None,
        };
        let err = AuthError::KeyStorageError(storage_err);
        assert_eq!(err.to_string(), "Key storage error: Connection error: connection refused");
    }

    #[test]
    fn test_key_storage_error_preserves_source_chain() {
        use std::error::Error;

        let storage_err = inferadb_common_storage::StorageError::Connection {
            message: "connection refused".into(),
            source: None,
        };
        let auth_err = AuthError::KeyStorageError(storage_err);

        // The source chain should expose the StorageError
        let source = auth_err.source();
        assert!(source.is_some(), "source chain must be preserved");

        let source = source.expect("source exists");
        assert_eq!(source.to_string(), "Connection error: connection refused");
    }

    #[test]
    fn test_key_storage_error_from_conversion() {
        let storage_err = inferadb_common_storage::StorageError::Timeout;
        let auth_err: AuthError = storage_err.into();
        assert!(matches!(auth_err, AuthError::KeyStorageError(_)));
        assert_eq!(auth_err.to_string(), "Key storage error: Operation timeout");
    }

    #[test]
    fn test_key_storage_error_nested_source_chain() {
        use std::{error::Error, sync::Arc};

        let inner_err: Arc<dyn std::error::Error + Send + Sync> =
            Arc::new(inferadb_common_storage::StorageError::Timeout);
        let storage_err = inferadb_common_storage::StorageError::Connection {
            message: "connection failed".into(),
            source: Some(inner_err),
        };
        let auth_err = AuthError::KeyStorageError(storage_err);

        // Level 1: AuthError → StorageError
        let level_1 = auth_err.source().expect("level 1 source");
        assert_eq!(level_1.to_string(), "Connection error: connection failed");

        // Level 2: StorageError → inner error
        let level_2 = level_1.source().expect("level 2 source");
        assert_eq!(level_2.to_string(), "Operation timeout");
    }
}
