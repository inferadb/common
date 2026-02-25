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
/// included in the [`Display`](std::fmt::Display) output for log correlation.
///
/// # Non-exhaustive
///
/// This enum is marked `#[non_exhaustive]` — new variants may be added in
/// future minor releases without a semver-breaking change. Downstream match
/// expressions must include a wildcard arm (`_ =>`).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AuthError {
    /// Malformed JWT that cannot be decoded.
    InvalidTokenFormat {
        /// Description of the token format error.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token has expired (`exp` claim in the past).
    TokenExpired {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token is not yet valid (`nbf` claim is in the future).
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

    /// Audience does not match expected value.
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

    /// JWKS fetch or parsing failed.
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

    /// Required tenant identifier (`org` claim) missing from JWT.
    MissingTenantId {
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },

    /// Token too old (`iat` claim exceeds maximum allowed age).
    TokenTooOld {
        /// The `iat` timestamp from the token (seconds since epoch).
        iat_timestamp: u64,
        /// The maximum allowed age in seconds.
        max_age_secs: u64,
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
        /// Key ID that has expired.
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
    /// This is the **only conditionally transient** variant: [`is_transient()`](Self::is_transient)
    /// delegates to
    /// [`StorageError::is_transient()`](inferadb_common_storage::StorageError::is_transient),
    /// returning `true` for connection failures, timeouts, and rate limiting.
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

    // ========== Input validation errors ==========
    /// JWT `kid` header parameter failed validation.
    ///
    /// The `kid` (Key ID) value extracted from the JWT header does not
    /// conform to the expected format. Valid `kid` values must be 1–256
    /// characters long and contain only `[a-zA-Z0-9._-]`.
    InvalidKid {
        /// Description of the constraint that was violated.
        message: String,
        /// Span ID captured at error creation for trace correlation.
        span_id: Option<tracing::span::Id>,
    },
}

impl fmt::Display for AuthError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidTokenFormat { span_id, .. } => {
                write!(f, "Invalid token format")?;
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
            Self::InvalidIssuer { span_id, .. } => {
                write!(f, "Invalid issuer")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidAudience { span_id, .. } => {
                write!(f, "Invalid audience")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingClaim { claim, span_id } => {
                write!(f, "Missing required claim: {claim}")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidScope { span_id, .. } => {
                write!(f, "Invalid scope")?;
                fmt_span_suffix(f, span_id)
            },
            Self::UnsupportedAlgorithm { span_id, .. } => {
                write!(f, "Unsupported algorithm")?;
                fmt_span_suffix(f, span_id)
            },
            Self::JwksError { span_id, .. } => {
                write!(f, "JWKS error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::OidcDiscoveryFailed { span_id, .. } => {
                write!(f, "OIDC discovery failed")?;
                fmt_span_suffix(f, span_id)
            },
            Self::IntrospectionFailed { span_id, .. } => {
                write!(f, "Token introspection failed")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidIntrospectionResponse { span_id, .. } => {
                write!(f, "Invalid introspection response")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenInactive { span_id } => {
                write!(f, "Token is inactive")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingTenantId { span_id } => {
                write!(f, "Missing required tenant identifier")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenTooOld { span_id, .. } => {
                write!(f, "Token too old")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyNotFound { span_id, .. } => {
                write!(f, "Signing key not found")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyInactive { span_id, .. } => {
                write!(f, "Signing key is inactive")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyRevoked { span_id, .. } => {
                write!(f, "Signing key has been revoked")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyNotYetValid { span_id, .. } => {
                write!(f, "Signing key is not yet valid")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyExpired { span_id, .. } => {
                write!(f, "Signing key has expired")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidPublicKey { span_id, .. } => {
                write!(f, "Invalid public key")?;
                fmt_span_suffix(f, span_id)
            },
            Self::KeyStorageError { span_id, .. } => {
                write!(f, "Key storage error")?;
                fmt_span_suffix(f, span_id)
            },
            Self::TokenReplayed { span_id, .. } => {
                write!(f, "Token has already been presented")?;
                fmt_span_suffix(f, span_id)
            },
            Self::MissingJti { span_id } => {
                write!(f, "Missing jti claim: replay detection requires a jti claim")?;
                fmt_span_suffix(f, span_id)
            },
            Self::InvalidKid { span_id, .. } => {
                write!(f, "Invalid kid")?;
                fmt_span_suffix(f, span_id)
            },
        }
    }
}

impl AuthError {
    /// Creates a new `InvalidTokenFormat` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_token_format(message: impl Into<String>) -> Self {
        Self::InvalidTokenFormat { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `TokenExpired` error.
    #[must_use = "error values must be used or propagated"]
    pub fn token_expired() -> Self {
        Self::TokenExpired { span_id: current_span_id() }
    }

    /// Creates a new `TokenNotYetValid` error.
    #[must_use = "error values must be used or propagated"]
    pub fn token_not_yet_valid() -> Self {
        Self::TokenNotYetValid { span_id: current_span_id() }
    }

    /// Creates a new `InvalidSignature` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_signature() -> Self {
        Self::InvalidSignature { span_id: current_span_id() }
    }

    /// Creates a new `InvalidIssuer` error.
    ///
    /// The `message` is preserved for [`detail()`](Self::detail) but redacted
    /// from [`Display`](std::fmt::Display) to avoid leaking server configuration.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_issuer(message: impl Into<String>) -> Self {
        let message = message.into();
        tracing::debug!(detail = %message, "Invalid issuer");
        Self::InvalidIssuer { message, span_id: current_span_id() }
    }

    /// Creates a new `InvalidAudience` error.
    ///
    /// The `message` is preserved for [`detail()`](Self::detail) but redacted
    /// from [`Display`](std::fmt::Display) to avoid leaking expected audience configuration.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_audience(message: impl Into<String>) -> Self {
        let message = message.into();
        tracing::debug!(detail = %message, "Invalid audience");
        Self::InvalidAudience { message, span_id: current_span_id() }
    }

    /// Creates a new `MissingClaim` error.
    #[must_use = "error values must be used or propagated"]
    pub fn missing_claim(claim: impl Into<String>) -> Self {
        Self::MissingClaim { claim: claim.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidScope` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_scope(message: impl Into<String>) -> Self {
        Self::InvalidScope { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `UnsupportedAlgorithm` error.
    #[must_use = "error values must be used or propagated"]
    pub fn unsupported_algorithm(message: impl Into<String>) -> Self {
        Self::UnsupportedAlgorithm { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `JwksError` error.
    #[must_use = "error values must be used or propagated"]
    pub fn jwks_error(message: impl Into<String>) -> Self {
        Self::JwksError { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `OidcDiscoveryFailed` error.
    #[must_use = "error values must be used or propagated"]
    pub fn oidc_discovery_failed(message: impl Into<String>) -> Self {
        Self::OidcDiscoveryFailed { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `IntrospectionFailed` error.
    #[must_use = "error values must be used or propagated"]
    pub fn introspection_failed(message: impl Into<String>) -> Self {
        Self::IntrospectionFailed { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidIntrospectionResponse` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_introspection_response(message: impl Into<String>) -> Self {
        Self::InvalidIntrospectionResponse { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `TokenInactive` error.
    #[must_use = "error values must be used or propagated"]
    pub fn token_inactive() -> Self {
        Self::TokenInactive { span_id: current_span_id() }
    }

    /// Creates a new `MissingTenantId` error.
    #[must_use = "error values must be used or propagated"]
    pub fn missing_tenant_id() -> Self {
        Self::MissingTenantId { span_id: current_span_id() }
    }

    /// Creates a new `TokenTooOld` error.
    ///
    /// # Arguments
    ///
    /// * `iat_timestamp` — The `iat` value from the token (seconds since epoch)
    /// * `max_age_secs` — The maximum allowed age in seconds
    #[must_use = "error values must be used or propagated"]
    pub fn token_too_old(iat_timestamp: u64, max_age_secs: u64) -> Self {
        Self::TokenTooOld { iat_timestamp, max_age_secs, span_id: current_span_id() }
    }

    /// Creates a new `KeyNotFound` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_not_found(kid: impl Into<String>) -> Self {
        Self::KeyNotFound { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyInactive` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_inactive(kid: impl Into<String>) -> Self {
        Self::KeyInactive { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyRevoked` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_revoked(kid: impl Into<String>) -> Self {
        Self::KeyRevoked { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyNotYetValid` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_not_yet_valid(kid: impl Into<String>) -> Self {
        Self::KeyNotYetValid { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyExpired` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_expired(kid: impl Into<String>) -> Self {
        Self::KeyExpired { kid: kid.into(), span_id: current_span_id() }
    }

    /// Creates a new `InvalidPublicKey` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_public_key(message: impl Into<String>) -> Self {
        Self::InvalidPublicKey { message: message.into(), span_id: current_span_id() }
    }

    /// Creates a new `KeyStorageError` error.
    #[must_use = "error values must be used or propagated"]
    pub fn key_storage_error(source: inferadb_common_storage::StorageError) -> Self {
        Self::KeyStorageError { source, span_id: current_span_id() }
    }

    /// Creates a new `TokenReplayed` error.
    #[must_use = "error values must be used or propagated"]
    pub fn token_replayed(jti: impl Into<String>) -> Self {
        Self::TokenReplayed { jti: jti.into(), span_id: current_span_id() }
    }

    /// Creates a new `MissingJti` error.
    #[must_use = "error values must be used or propagated"]
    pub fn missing_jti() -> Self {
        Self::MissingJti { span_id: current_span_id() }
    }

    /// Creates a new `InvalidKid` error.
    #[must_use = "error values must be used or propagated"]
    pub fn invalid_kid(message: impl Into<String>) -> Self {
        Self::InvalidKid { message: message.into(), span_id: current_span_id() }
    }

    /// Returns the tracing span ID captured when this error was created,
    /// if a tracing subscriber was active at that time.
    #[must_use = "discarding the span ID loses trace correlation context"]
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
            | Self::MissingJti { span_id, .. }
            | Self::InvalidKid { span_id, .. } => span_id.as_ref(),
        }
    }

    /// Returns a detailed diagnostic string for server-side logging.
    ///
    /// Unlike [`Display`](std::fmt::Display), which produces generic messages safe for API
    /// responses, this method returns the full internal context including
    /// expected values, key IDs, and backend error details. **Never expose
    /// this output to external callers.**
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use inferadb_common_authn::error::AuthError;
    ///
    /// let err = AuthError::invalid_audience("expected 'api.example.com', got 'evil.com'");
    /// // Display (safe for API responses): "Invalid audience"
    /// // detail (server-side only): "Invalid audience: expected 'api.example.com', got 'evil.com'"
    /// tracing::debug!(detail = err.detail(), "auth error");
    /// ```
    #[must_use = "discarding the detail string loses diagnostic context"]
    pub fn detail(&self) -> String {
        match self {
            Self::InvalidTokenFormat { message, .. } => {
                format!("Invalid token format: {message}")
            },
            Self::InvalidIssuer { message, .. } => {
                format!("Invalid issuer: {message}")
            },
            Self::InvalidAudience { message, .. } => {
                format!("Invalid audience: {message}")
            },
            Self::MissingClaim { claim, .. } => {
                format!("Missing required claim: {claim}")
            },
            Self::InvalidScope { message, .. } => {
                format!("Invalid scope: {message}")
            },
            Self::UnsupportedAlgorithm { message, .. } => {
                format!("Unsupported algorithm: {message}")
            },
            Self::JwksError { message, .. } => {
                format!("JWKS error: {message}")
            },
            Self::OidcDiscoveryFailed { message, .. } => {
                format!("OIDC discovery failed: {message}")
            },
            Self::IntrospectionFailed { message, .. } => {
                format!("Token introspection failed: {message}")
            },
            Self::InvalidIntrospectionResponse { message, .. } => {
                format!("Invalid introspection response: {message}")
            },
            Self::KeyNotFound { kid, .. } => {
                format!("Signing key not found: kid={kid}")
            },
            Self::KeyInactive { kid, .. } => {
                format!("Signing key is inactive: kid={kid}")
            },
            Self::KeyRevoked { kid, .. } => {
                format!("Signing key has been revoked: kid={kid}")
            },
            Self::KeyNotYetValid { kid, .. } => {
                format!("Signing key is not yet valid: kid={kid}")
            },
            Self::KeyExpired { kid, .. } => {
                format!("Signing key has expired: kid={kid}")
            },
            Self::InvalidPublicKey { message, .. } => {
                format!("Invalid public key: {message}")
            },
            Self::KeyStorageError { source, .. } => {
                format!("Key storage error: {source}")
            },
            Self::TokenReplayed { jti, .. } => {
                format!("Token replayed: jti={jti}")
            },
            Self::InvalidKid { message, .. } => {
                format!("Invalid kid: {message}")
            },
            Self::TokenTooOld { iat_timestamp, max_age_secs, .. } => {
                format!("Token too old: iat={iat_timestamp}, max_age={max_age_secs}s")
            },
            // Variants with no additional context — detail matches Display
            _ => self.to_string(),
        }
    }

    /// Returns `true` if this error is transient and the operation may
    /// succeed on retry.
    ///
    /// # Transient variants
    ///
    /// - [`KeyStorageError`](Self::KeyStorageError) — delegates to
    ///   [`StorageError::is_transient()`](inferadb_common_storage::StorageError::is_transient).
    ///   Transient when the underlying storage error is a connection failure, timeout, or rate
    ///   limit. Permanent when the storage error is a conflict, serialization error, or internal
    ///   logic error.
    ///
    /// # Permanent variants
    ///
    /// All authentication and validation failures are permanent:
    ///
    /// - **Token errors** (`InvalidTokenFormat`, `TokenExpired`, `TokenNotYetValid`,
    ///   `InvalidSignature`, `TokenTooOld`, `TokenInactive`, `TokenReplayed`, `MissingJti`) — the
    ///   token itself is invalid; retrying the same token won't fix it.
    /// - **Claim errors** (`InvalidIssuer`, `InvalidAudience`, `MissingClaim`, `InvalidScope`,
    ///   `MissingTenantId`) — the token's claims don't match the server's requirements.
    /// - **Algorithm errors** (`UnsupportedAlgorithm`) — the token uses a disallowed algorithm.
    /// - **Key errors** (`KeyNotFound`, `KeyInactive`, `KeyRevoked`, `KeyNotYetValid`,
    ///   `KeyExpired`, `InvalidPublicKey`, `InvalidKid`) — the signing key is in a definitive state
    ///   that won't change on retry.
    /// - **Protocol errors** (`JwksError`, `OidcDiscoveryFailed`, `IntrospectionFailed`,
    ///   `InvalidIntrospectionResponse`) — while these may involve network calls, the errors
    ///   typically indicate configuration or protocol issues rather than transient failures.
    ///   Callers needing retry for JWKS/OIDC fetches should implement retry at the HTTP transport
    ///   layer.
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use inferadb_common_authn::error::AuthError;
    /// use inferadb_common_storage::StorageError;
    ///
    /// let transient_err = AuthError::key_storage_error(StorageError::connection("network down"));
    /// assert!(transient_err.is_transient());
    ///
    /// let permanent_err = AuthError::token_expired();
    /// assert!(!permanent_err.is_transient());
    /// ```
    #[must_use = "use the return value to decide retry behavior"]
    pub fn is_transient(&self) -> bool {
        match self {
            Self::KeyStorageError { source, .. } => source.is_transient(),
            _ => false,
        }
    }
}

/// Converts a [`jsonwebtoken::errors::Error`] into the corresponding [`AuthError`] variant.
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

/// Converts a [`StorageError`](inferadb_common_storage::StorageError) into
/// [`AuthError::KeyStorageError`].
impl From<inferadb_common_storage::StorageError> for AuthError {
    fn from(err: inferadb_common_storage::StorageError) -> Self {
        AuthError::key_storage_error(err)
    }
}

/// Result type alias for authentication operations.
///
/// Shorthand for `std::result::Result<T, `[`AuthError`]`>`.
pub type Result<T> = std::result::Result<T, AuthError>;

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use rstest::rstest;

    use super::*;

    #[rstest]
    #[case::invalid_token_format(
        AuthError::invalid_token_format("JWT missing segment 3"),
        "Invalid token format"
    )]
    #[case::token_expired(AuthError::token_expired(), "Token expired")]
    #[case::missing_claim(
        AuthError::missing_claim("tenant_id"),
        "Missing required claim: tenant_id"
    )]
    #[case::oidc_discovery(
        AuthError::oidc_discovery_failed("endpoint not found"),
        "OIDC discovery failed"
    )]
    #[case::introspection(
        AuthError::introspection_failed("connection refused"),
        "Token introspection failed"
    )]
    #[case::invalid_introspection(
        AuthError::invalid_introspection_response("malformed JSON"),
        "Invalid introspection response"
    )]
    #[case::token_inactive(AuthError::token_inactive(), "Token is inactive")]
    #[case::missing_tenant_id(AuthError::missing_tenant_id(), "Missing required tenant identifier")]
    #[case::key_not_found(AuthError::key_not_found("key-123"), "Signing key not found")]
    #[case::key_inactive(AuthError::key_inactive("key-456"), "Signing key is inactive")]
    #[case::key_revoked(AuthError::key_revoked("key-789"), "Signing key has been revoked")]
    #[case::key_not_yet_valid(
        AuthError::key_not_yet_valid("key-abc"),
        "Signing key is not yet valid"
    )]
    #[case::key_expired(AuthError::key_expired("key-def"), "Signing key has expired")]
    #[case::key_storage(
        AuthError::key_storage_error(inferadb_common_storage::StorageError::connection(
            "connection refused"
        )),
        "Key storage error"
    )]
    fn test_display_is_generic(#[case] err: AuthError, #[case] expected: &str) {
        assert_eq!(err.to_string(), expected);
    }

    #[rstest]
    #[case::invalid_token_format(
        AuthError::invalid_token_format("JWT missing segment 3"),
        "Invalid token format: JWT missing segment 3"
    )]
    #[case::invalid_audience(
        AuthError::invalid_audience("expected 'api.example.com', got 'evil.com'"),
        "Invalid audience: expected 'api.example.com', got 'evil.com'"
    )]
    #[case::invalid_issuer(
        AuthError::invalid_issuer("expected 'auth.internal', got 'attacker.com'"),
        "Invalid issuer: expected 'auth.internal', got 'attacker.com'"
    )]
    #[case::key_not_found(
        AuthError::key_not_found("key-123"),
        "Signing key not found: kid=key-123"
    )]
    #[case::key_revoked(
        AuthError::key_revoked("key-789"),
        "Signing key has been revoked: kid=key-789"
    )]
    fn test_detail_preserves_internal_context(#[case] err: AuthError, #[case] expected: &str) {
        assert_eq!(err.detail(), expected);
    }

    #[test]
    fn test_error_from_jsonwebtoken() {
        let jwt_err =
            jsonwebtoken::errors::Error::from(jsonwebtoken::errors::ErrorKind::ExpiredSignature);
        let auth_err: AuthError = jwt_err.into();

        assert!(matches!(auth_err, AuthError::TokenExpired { .. }));
    }

    #[test]
    fn test_key_storage_error_detail_includes_source() {
        let storage_err = inferadb_common_storage::StorageError::connection("connection refused");
        let err = AuthError::key_storage_error(storage_err);
        assert_eq!(err.detail(), "Key storage error: Connection error");
    }

    #[test]
    fn test_key_storage_error_preserves_source_chain() {
        use std::error::Error;

        let storage_err = inferadb_common_storage::StorageError::connection("connection refused");
        let auth_err = AuthError::key_storage_error(storage_err);

        // The source chain should expose the StorageError
        let source = auth_err.source();
        assert!(source.is_some(), "source chain must be preserved");

        // Source Display is also sanitized
        let source = source.expect("source exists");
        assert_eq!(source.to_string(), "Connection error");
    }

    #[test]
    fn test_key_storage_error_from_conversion() {
        let storage_err = inferadb_common_storage::StorageError::timeout();
        let auth_err: AuthError = storage_err.into();
        assert!(matches!(auth_err, AuthError::KeyStorageError { .. }));
        assert_eq!(auth_err.to_string(), "Key storage error");
    }

    #[test]
    fn test_key_storage_error_nested_source_chain() {
        use std::error::Error;

        let storage_err = inferadb_common_storage::StorageError::connection_with_source(
            "connection failed",
            inferadb_common_storage::StorageError::timeout(),
        );
        let auth_err = AuthError::key_storage_error(storage_err);

        // Level 1: AuthError → StorageError (sanitized Display)
        let level_1 = auth_err.source().expect("level 1 source");
        assert_eq!(level_1.to_string(), "Connection error");

        // Level 2: StorageError → inner error
        let level_2 = level_1.source().expect("level 2 source");
        assert_eq!(level_2.to_string(), "Operation timeout");
    }

    #[test]
    fn test_replay_error_display_is_generic() {
        let err = AuthError::token_replayed("jti-abc-123");
        // Display should NOT contain the actual JTI
        assert_eq!(err.to_string(), "Token has already been presented");

        let err = AuthError::missing_jti();
        assert_eq!(err.to_string(), "Missing jti claim: replay detection requires a jti claim");
    }

    #[test]
    fn test_replay_error_detail_includes_jti() {
        let err = AuthError::token_replayed("jti-abc-123");
        assert_eq!(err.detail(), "Token replayed: jti=jti-abc-123");
    }

    #[test]
    fn test_replay_error_debug_does_not_panic() {
        let err = AuthError::token_replayed("test-jti");
        let _ = format!("{:?}", err);

        let err = AuthError::missing_jti();
        let _ = format!("{:?}", err);
    }

    #[test]
    fn test_display_never_contains_internal_details() {
        // Security test: verify Display output doesn't contain internal values
        let cases = vec![
            (
                AuthError::invalid_audience("expected 'api.example.com', got 'evil.com'"),
                vec!["api.example.com", "evil.com", "expected"],
            ),
            (
                AuthError::invalid_issuer("expected 'auth.internal'"),
                vec!["auth.internal", "expected"],
            ),
            (AuthError::unsupported_algorithm("Algorithm 'HS256' is not allowed"), vec!["HS256"]),
            (AuthError::key_not_found("org-12345.key-v2"), vec!["org-12345", "key-v2"]),
            (
                AuthError::key_storage_error(inferadb_common_storage::StorageError::connection(
                    "tcp://ledger.internal:9200 connection refused",
                )),
                vec!["ledger.internal", "9200", "tcp://"],
            ),
            (AuthError::token_replayed("550e8400-e29b-41d4-a716-446655440000"), vec!["550e8400"]),
            (
                AuthError::invalid_kid("kid contains invalid char '/' at position 5"),
                vec!["/", "position"],
            ),
        ];

        for (err, forbidden_substrings) in cases {
            let display = err.to_string();
            for forbidden in forbidden_substrings {
                assert!(
                    !display.contains(forbidden),
                    "Display of {:?} must not contain '{forbidden}', got: {display}",
                    std::mem::discriminant(&err),
                );
            }
        }
    }

    #[rstest]
    #[case::connection(inferadb_common_storage::StorageError::connection("network down"), true)]
    #[case::timeout(inferadb_common_storage::StorageError::timeout(), true)]
    #[case::rate_limit(
        inferadb_common_storage::StorageError::rate_limit_exceeded(
            std::time::Duration::from_millis(100)
        ),
        true
    )]
    #[case::not_found(inferadb_common_storage::StorageError::not_found("missing"), false)]
    #[case::conflict(inferadb_common_storage::StorageError::conflict(), false)]
    fn test_is_transient_key_storage_error_delegates(
        #[case] storage_err: inferadb_common_storage::StorageError,
        #[case] expected: bool,
    ) {
        let err = AuthError::key_storage_error(storage_err);
        assert_eq!(
            err.is_transient(),
            expected,
            "KeyStorageError delegation should{} be transient",
            if expected { "" } else { " NOT" },
        );
    }

    #[rstest]
    #[case::invalid_token_format(AuthError::invalid_token_format("bad"))]
    #[case::token_expired(AuthError::token_expired())]
    #[case::token_not_yet_valid(AuthError::token_not_yet_valid())]
    #[case::invalid_signature(AuthError::invalid_signature())]
    #[case::invalid_issuer(AuthError::invalid_issuer("wrong issuer"))]
    #[case::invalid_audience(AuthError::invalid_audience("wrong audience"))]
    #[case::missing_claim(AuthError::missing_claim("aud"))]
    #[case::invalid_scope(AuthError::invalid_scope("read"))]
    #[case::unsupported_algorithm(AuthError::unsupported_algorithm("HS256"))]
    #[case::jwks_error(AuthError::jwks_error("fetch failed"))]
    #[case::oidc_discovery_failed(AuthError::oidc_discovery_failed("timeout"))]
    #[case::introspection_failed(AuthError::introspection_failed("error"))]
    #[case::invalid_introspection_response(AuthError::invalid_introspection_response("bad json"))]
    #[case::token_inactive(AuthError::token_inactive())]
    #[case::missing_tenant_id(AuthError::missing_tenant_id())]
    #[case::token_too_old(AuthError::token_too_old(1_000_000, 86400))]
    #[case::key_not_found(AuthError::key_not_found("kid-1"))]
    #[case::key_inactive(AuthError::key_inactive("kid-1"))]
    #[case::key_revoked(AuthError::key_revoked("kid-1"))]
    #[case::key_not_yet_valid(AuthError::key_not_yet_valid("kid-1"))]
    #[case::key_expired(AuthError::key_expired("kid-1"))]
    #[case::invalid_public_key(AuthError::invalid_public_key("bad pem"))]
    #[case::token_replayed(AuthError::token_replayed("jti-123"))]
    #[case::missing_jti(AuthError::missing_jti())]
    #[case::invalid_kid(AuthError::invalid_kid("invalid char '/' at position 0"))]
    fn test_permanent_variant_not_transient(#[case] err: AuthError) {
        assert!(!err.is_transient(), "{:?} should NOT be transient", std::mem::discriminant(&err),);
    }
}
