//! Authentication error types.
//!
//! This module defines errors that can occur during JWT authentication and
//! signing key validation.
//!
//! # Trace Context
//!
//! Each error variant carries an optional `span_id` captured from the active
//! [`tracing::Span`] at construction time. This enables end-to-end correlation
//! of errors with the request that produced them, bridging the gap between
//! error types and distributed tracing infrastructure.

use std::fmt;

use thiserror::Error;

/// Captures the span ID from the current tracing span, if any.
fn current_span_id() -> Option<tracing::span::Id> {
    tracing::Span::current().id()
}

/// Appends ` [span=<id>]` to a formatter when a span ID is present.
fn fmt_span_suffix(f: &mut fmt::Formatter<'_>, span_id: &Option<tracing::span::Id>) -> fmt::Result {
    if let Some(id) = span_id { write!(f, " [span={}]", id.into_u64()) } else { Ok(()) }
}

/// Authentication and authorization errors.
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
pub enum AuthError {
    /// Malformed JWT - cannot be decoded.
    InvalidTokenFormat {
        /// Description of the token format error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token has expired.
    TokenExpired {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token not yet valid (nbf claim in future).
    TokenNotYetValid {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Signature verification failed.
    InvalidSignature {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Unknown or invalid issuer.
    InvalidIssuer {
        /// Description of the issuer error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Audience doesn't match expected value.
    InvalidAudience {
        /// Description of the audience error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Required claim is missing.
    MissingClaim {
        /// The name of the missing claim.
        claim: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Scope validation failed.
    InvalidScope {
        /// Description of the scope error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Algorithm not in allowed list.
    UnsupportedAlgorithm {
        /// Description of the algorithm error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// JWKS-related errors.
    JwksError {
        /// Description of the JWKS error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// OIDC discovery failed.
    OidcDiscoveryFailed {
        /// Description of the OIDC discovery error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token introspection failed.
    IntrospectionFailed {
        /// Description of the introspection error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Invalid introspection response.
    InvalidIntrospectionResponse {
        /// Description of the response error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token is inactive (from introspection).
    TokenInactive {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Required tenant_id claim missing from OAuth token.
    MissingTenantId {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token too old (issued at exceeds max age).
    TokenTooOld {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    // ========== Ledger-backed key validation errors ==========
    /// Signing key not found in Ledger.
    KeyNotFound {
        /// Key ID that was not found.
        kid: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Signing key is inactive (soft-disabled).
    KeyInactive {
        /// Key ID that is inactive.
        kid: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Signing key has been permanently revoked.
    KeyRevoked {
        /// Key ID that was revoked.
        kid: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Signing key is not yet valid (valid_from in future).
    KeyNotYetValid {
        /// Key ID that is not yet valid.
        kid: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Signing key has expired (valid_until in past).
    KeyExpired {
        /// Key ID that expired.
        kid: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Invalid public key format.
    InvalidPublicKey {
        /// Description of the public key error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Storage backend error during key lookup.
    ///
    /// Wraps the original [`StorageError`] to preserve the full error source
    /// chain for debugging and structured logging.
    ///
    /// [`StorageError`]: inferadb_common_storage::StorageError
    KeyStorageError {
        /// The underlying storage error that caused the key lookup to fail.
        #[source]
        source: inferadb_common_storage::StorageError,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    // ========== Replay prevention errors ==========
    /// JWT replay detected — a token with this JTI has already been presented.
    ///
    /// This error is only returned when a [`ReplayDetector`] is configured
    /// and the token's `jti` claim matches a previously-seen value.
    ///
    /// [`ReplayDetector`]: crate::replay::ReplayDetector
    TokenReplayed {
        /// The duplicate JTI value.
        jti: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token is missing a required `jti` claim.
    ///
    /// When a [`ReplayDetector`] is configured, every token must carry a
    /// `jti` claim to enable replay tracking. Tokens without it are rejected.
    ///
    /// [`ReplayDetector`]: crate::replay::ReplayDetector
    MissingJti {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenFormat { message, span_id } => {
                write!(f, "Invalid token format: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenExpired { span_id } => {
                write!(f, "Token expired")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenNotYetValid { span_id } => {
                write!(f, "Token not yet valid")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidSignature { span_id } => {
                write!(f, "Invalid signature")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidIssuer { message, span_id } => {
                write!(f, "Invalid issuer: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidAudience { message, span_id } => {
                write!(f, "Invalid audience: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingClaim { claim, span_id } => {
                write!(f, "Missing claim: {claim}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidScope { message, span_id } => {
                write!(f, "Invalid scope: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::UnsupportedAlgorithm { message, span_id } => {
                write!(f, "Unsupported algorithm: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::JwksError { message, span_id } => {
                write!(f, "JWKS error: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::OidcDiscoveryFailed { message, span_id } => {
                write!(f, "OIDC discovery failed: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::IntrospectionFailed { message, span_id } => {
                write!(f, "Introspection failed: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidIntrospectionResponse { message, span_id } => {
                write!(f, "Invalid introspection response: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenInactive { span_id } => {
                write!(f, "Token is inactive")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingTenantId { span_id } => {
                write!(f, "Missing tenant_id claim in OAuth token")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenTooOld { span_id } => {
                write!(f, "Token too old")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyNotFound { kid, span_id } => {
                write!(f, "Signing key not found: {kid}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyInactive { kid, span_id } => {
                write!(f, "Signing key is inactive: {kid}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyRevoked { kid, span_id } => {
                write!(f, "Signing key revoked: {kid}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyNotYetValid { kid, span_id } => {
                write!(f, "Signing key not yet valid: {kid}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyExpired { kid, span_id } => {
                write!(f, "Signing key expired: {kid}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidPublicKey { message, span_id } => {
                write!(f, "Invalid public key: {message}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyStorageError { source, span_id } => {
                write!(f, "Key storage error: {source}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenReplayed { jti, span_id } => {
                write!(f, "Token replayed: JTI '{jti}' has already been presented")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingJti { span_id } => {
                write!(f, "Missing jti claim: replay detection requires a jti claim")?;
                fmt_span_suffix(f, span_id)
            },
        }
    }
}

impl AuthError {
    /// Creates a new `InvalidTokenFormat` error.
    #[must_use]
    pub fn invalid_token_format(message: impl Into<String>) -> Self {
        Self::InvalidTokenFormat { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `TokenExpired` error.
    #[must_use]
    pub fn token_expired() -> Self {
        Self::TokenExpired { span_id: current_span_id() }
    }

    /// Creates a new `TokenNotYetValid` error.
    #[must_use]
    pub fn token_not_yet_valid() -> Self {
        Self::TokenNotYetValid { span_id: current_span_id() }
    }

    /// Creates a new `InvalidSignature` error.
    #[must_use]
    pub fn invalid_signature() -> Self {
        Self::InvalidSignature { span_id: current_span_id() }
    }

    /// Creates a new `InvalidIssuer` error.
    #[must_use]
    pub fn invalid_issuer(message: impl Into<String>) -> Self {
        Self::InvalidIssuer { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidAudience` error.
    #[must_use]
    pub fn invalid_audience(message: impl Into<String>) -> Self {
        Self::InvalidAudience { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `MissingClaim` error.
    #[must_use]
    pub fn missing_claim(claim: impl Into<String>) -> Self {
        Self::MissingClaim { claim: claim.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidScope` error.
    #[must_use]
    pub fn invalid_scope(message: impl Into<String>) -> Self {
        Self::InvalidScope { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `UnsupportedAlgorithm` error.
    #[must_use]
    pub fn unsupported_algorithm(message: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `JwksError` error.
    #[must_use]
    pub fn jwks_error(message: impl Into<String>) -> Self {
        Self::JwksError { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `OidcDiscoveryFailed` error.
    #[must_use]
    pub fn oidc_discovery_failed(message: impl Into<String>) -> Self {
        Self::OidcDiscoveryFailed { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `IntrospectionFailed` error.
    #[must_use]
    pub fn introspection_failed(message: impl Into<String>) -> Self {
        Self::IntrospectionFailed { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidIntrospectionResponse` error.
    #[must_use]
    pub fn invalid_introspection_response(message: impl Into<String>) -> Self {
        Self::InvalidIntrospectionResponse { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `TokenInactive` error.
    #[must_use]
    pub fn token_inactive() -> Self {
        Self::TokenInactive { span_id: current_span_id() }
    }

    /// Creates a new `MissingTenantId` error.
    #[must_use]
    pub fn missing_tenant_id() -> Self {
        Self::MissingTenantId { span_id: current_span_id() }
    }

    /// Creates a new `TokenTooOld` error.
    #[must_use]
    pub fn token_too_old() -> Self {
        Self::TokenTooOld { span_id: current_span_id() }
    }

    /// Creates a new `KeyNotFound` error.
    #[must_use]
    pub fn key_not_found(kid: impl Into<String>) -> Self {
        Self::KeyNotFound { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyInactive` error.
    #[must_use]
    pub fn key_inactive(kid: impl Into<String>) -> Self {
        Self::KeyInactive { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyRevoked` error.
    #[must_use]
    pub fn key_revoked(kid: impl Into<String>) -> Self {
        Self::KeyRevoked { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyNotYetValid` error.
    #[must_use]
    pub fn key_not_yet_valid(kid: impl Into<String>) -> Self {
        Self::KeyNotYetValid { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyExpired` error.
    #[must_use]
    pub fn key_expired(kid: impl Into<String>) -> Self {
        Self::KeyExpired { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidPublicKey` error.
    #[must_use]
    pub fn invalid_public_key(message: impl Into<String>) -> Self {
        Self::InvalidPublicKey { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyStorageError`.
    #[must_use]
    pub fn key_storage_error(source: inferadb_common_storage::StorageError) -> Self {
        Self::KeyStorageError { source, span_id: current_span_id() }
    }

    /// Creates a new `TokenReplayed` error.
    #[must_use]
    pub fn token_replayed(jti: impl Into<String>) -> Self {
        Self::TokenReplayed { jti: jti.into(), span_id: current_span_id() }
    }

    /// Creates a new `MissingJti` error.
    #[must_use]
    pub fn missing_jti() -> Self {
        Self::MissingJti { span_id: current_span_id() }
    }

    /// Returns the tracing span ID captured when this error was created,
    /// if a tracing subscriber was active at that time.
    #[must_use]
    pub fn span_id(&self) -> Option<&tracing::span::Id> {
        match self {
            Self::InvalidTokenFormat { span_id, .. }
            | Self::TokenExpired { span_id, .. }
            | Self::TokenNotYetValid { span_id, .. }
            | Self::InvalidSignature { span_id, .. }
            | Self::InvalidIssuer { span_id, .. }
            | Self::InvalidAudience { span_id, .. }
            | Self::MissingClaim { span_id, .. }
            | Self::InvalidScope { span_id, .. }
            | Self::UnsupportedAlgorithm { span_id, .. }
            | Self::JwksError { span_id, .. }
            | Self::OidcDiscoveryFailed { span_id, .. }
            | Self::IntrospectionFailed { span_id, .. }
            | Self::InvalidIntrospectionResponse { span_id, .. }
            | Self::TokenInactive { span_id, .. }
            | Self::MissingTenantId { span_id, .. }
            | Self::TokenTooOld { span_id, .. }
            | Self::KeyNotFound { span_id, .. }
            | Self::KeyInactive { span_id, .. }
            | Self::KeyRevoked { span_id, .. }
            | Self::KeyNotYetValid { span_id, .. }
            | Self::KeyExpired { span_id, .. }
            | Self::InvalidPublicKey { span_id, .. }
            | Self::KeyStorageError { span_id, .. }
            | Self::TokenReplayed { span_id, .. }
            | Self::MissingJti { span_id, .. } => span_id.as_ref(),
        }
    }
}

impl From<jsonwebtoken::errors::Error> for AuthError {
    fn from(err: jsonwebtoken::errors::Error) -> Self {
        use jsonwebtoken::errors::ErrorKind;

        match err.kind() {
            ErrorKind::InvalidToken => AuthError::invalid_token_format("Invalid JWT structure"),
            ErrorKind::InvalidSignature => AuthError::invalid_signature(),
            ErrorKind::ExpiredSignature => AuthError::token_expired(),
            ErrorKind::ImmatureSignature => AuthError::token_not_yet_valid(),
            ErrorKind::InvalidAudience => AuthError::invalid_audience("Audience validation failed"),
            ErrorKind::InvalidIssuer => AuthError::invalid_issuer("Issuer validation failed"),
            ErrorKind::InvalidAlgorithm => {
                AuthError::unsupported_algorithm("Algorithm not supported")
            },
            _ => AuthError::invalid_token_format(format!("JWT error: {}", err)),
        }
    }
}

impl From<inferadb_common_storage::StorageError> for AuthError {
    fn from(err: inferadb_common_storage::StorageError) -> Self {
        AuthError::key_storage_error(err)
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
        let err = AuthError::invalid_token_format("test");
        assert_eq!(err.to_string(), "Invalid token format: test");

        let err = AuthError::token_expired();
        assert_eq!(err.to_string(), "Token expired");

        let err = AuthError::missing_claim("tenant_id");
        assert_eq!(err.to_string(), "Missing claim: tenant_id");
    }

    #[test]
    fn test_error_from_jsonwebtoken() {
        let jwt_err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
        let auth_err: AuthError = jwt_err.into();

        assert!(matches!(auth_err, AuthError::TokenExpired { .. }));
    }

    #[test]
    fn test_oauth_error_variants() {
        let err = AuthError::oidc_discovery_failed("endpoint not found");
        assert_eq!(err.to_string(), "OIDC discovery failed: endpoint not found");

        let err = AuthError::introspection_failed("connection refused");
        assert_eq!(err.to_string(), "Introspection failed: connection refused");

        let err = AuthError::invalid_introspection_response("malformed JSON");
        assert_eq!(err.to_string(), "Invalid introspection response: malformed JSON");

        let err = AuthError::token_inactive();
        assert_eq!(err.to_string(), "Token is inactive");

        let err = AuthError::missing_tenant_id();
        assert_eq!(err.to_string(), "Missing tenant_id claim in OAuth token");
    }

    #[test]
    fn test_key_error_variants() {
        let err = AuthError::key_not_found("key-123");
        assert_eq!(err.to_string(), "Signing key not found: key-123");

        let err = AuthError::key_inactive("key-456");
        assert_eq!(err.to_string(), "Signing key is inactive: key-456");

        let err = AuthError::key_revoked("key-789");
        assert_eq!(err.to_string(), "Signing key revoked: key-789");

        let err = AuthError::key_not_yet_valid("key-abc");
        assert_eq!(err.to_string(), "Signing key not yet valid: key-abc");

        let err = AuthError::key_expired("key-def");
        assert_eq!(err.to_string(), "Signing key expired: key-def");
    }

    #[test]
    fn test_key_storage_error_display() {
        let storage_err = inferadb_common_storage::StorageError::connection("connection refused");
        let err = AuthError::key_storage_error(storage_err);
        assert_eq!(err.to_string(), "Key storage error: Connection error: connection refused");
    }

    #[test]
    fn test_key_storage_error_preserves_source_chain() {
        use std::error::Error;

        let storage_err = inferadb_common_storage::StorageError::connection("connection refused");
        let auth_err = AuthError::key_storage_error(storage_err);

        // The source chain should expose the StorageError
        let source = auth_err.source();
        assert!(source.is_some(), "source chain must be preserved");

        let source = source.expect("source exists");
        assert_eq!(source.to_string(), "Connection error: connection refused");
    }

    #[test]
    fn test_key_storage_error_from_conversion() {
        let storage_err = inferadb_common_storage::StorageError::timeout();
        let auth_err: AuthError = storage_err.into();
        assert!(matches!(auth_err, AuthError::KeyStorageError { .. }));
        assert_eq!(auth_err.to_string(), "Key storage error: Operation timeout");
    }

    #[test]
    fn test_key_storage_error_nested_source_chain() {
        use std::error::Error;

        let storage_err = inferadb_common_storage::StorageError::connection_with_source(
            "connection failed",
            inferadb_common_storage::StorageError::timeout(),
        );
        let auth_err = AuthError::key_storage_error(storage_err);

        // Level 1: AuthError → StorageError
        let level_1 = auth_err.source().expect("level 1 source");
        assert_eq!(level_1.to_string(), "Connection error: connection failed");

        // Level 2: StorageError → inner error
        let level_2 = level_1.source().expect("level 2 source");
        assert_eq!(level_2.to_string(), "Operation timeout");
    }

    #[test]
    fn test_replay_error_variants() {
        let err = AuthError::token_replayed("jti-abc-123");
        assert_eq!(err.to_string(), "Token replayed: JTI 'jti-abc-123' has already been presented");

        let err = AuthError::missing_jti();
        assert_eq!(err.to_string(), "Missing jti claim: replay detection requires a jti claim");
    }

    #[test]
    fn test_replay_error_debug_does_not_panic() {
        let err = AuthError::token_replayed("test-jti");
        let _ = format!("{:?}", err);

        let err = AuthError::missing_jti();
        let _ = format!("{:?}", err);
    }
}
