//! JWT validation utilities.
//!
//! This module provides security checks for JWT fields, ensuring only
//! approved algorithms and well-formed identifiers are accepted.
//!
//! # Security
//!
//! These validators implement security best practices:
//! - Strict algorithm checks to prevent algorithm substitution attacks
//! - Only asymmetric algorithms (EdDSA, RS256) are allowed
//! - Symmetric algorithms and "none" are always rejected

use crate::error::AuthError;

/// Forbidden JWT algorithms that are never accepted for security reasons.
///
/// These algorithms are blocked because:
/// - `none`: No signature verification (trivially bypassable)
/// - `HS256`, `HS384`, `HS512`: Symmetric algorithms (shared secret vulnerability)
///
/// Only EdDSA (Ed25519) is currently supported.
pub const FORBIDDEN_ALGORITHMS: &[&str] = &["none", "HS256", "HS384", "HS512"];

/// Accepted JWT algorithms.
///
/// Currently only EdDSA (Ed25519) is supported end-to-end. The verification
/// pipeline in [`crate::jwt::verify_with_signing_key_cache`] only handles
/// EdDSA keys from the Ledger-backed signing key store.
///
/// **To add RS256 support in the future:**
/// 1. Add RS256 back to this list
/// 2. Store RSA public keys in the signing key store (currently EdDSA only)
/// 3. Extend [`crate::jwt::verify_with_signing_key_cache`] to select the correct `Algorithm`
///    variant based on the key type
/// 4. Add integration tests for RS256 end-to-end verification
///
/// Per RFC 8725 Section 3.1, validators must reject algorithms they do not
/// fully implement — listing RS256 here without verification support would
/// produce confusing errors at the signature verification stage.
pub const ACCEPTED_ALGORITHMS: &[&str] = &["EdDSA"];

/// Validate JWT algorithm against security policies.
///
/// This function enforces strict algorithm security per RFC 8725:
/// - ALWAYS rejects symmetric algorithms (HS256, HS384, HS512)
/// - ALWAYS rejects "none" algorithm
/// - Only accepts EdDSA (Ed25519)
///
/// # Arguments
///
/// * `alg` - The algorithm from the JWT header
///
/// # Errors
///
/// Returns [`AuthError::UnsupportedAlgorithm`] if:
/// - Algorithm is symmetric (HS256, HS384, HS512)
/// - Algorithm is "none"
/// - Algorithm is not in [`ACCEPTED_ALGORITHMS`]
///
/// # Examples
///
/// ```
/// use inferadb_common_authn::validation::validate_algorithm;
///
/// // EdDSA is accepted
/// let result = validate_algorithm("EdDSA");
/// assert!(result.is_ok());
///
/// // RS256 is not currently supported
/// let result = validate_algorithm("RS256");
/// assert!(result.is_err());
///
/// // Symmetric algorithm rejected
/// let result = validate_algorithm("HS256");
/// assert!(result.is_err());
/// ```
pub fn validate_algorithm(alg: &str) -> Result<(), AuthError> {
    // Check against forbidden algorithms
    if FORBIDDEN_ALGORITHMS.contains(&alg) {
        return Err(AuthError::unsupported_algorithm(format!(
            "Algorithm '{}' is not allowed for security reasons",
            alg
        )));
    }

    // Check if in accepted list
    if !ACCEPTED_ALGORITHMS.contains(&alg) {
        return Err(AuthError::unsupported_algorithm(format!(
            "Algorithm '{}' is not in accepted list (only EdDSA is supported)",
            alg
        )));
    }

    Ok(())
}

/// Maximum allowed length for a JWT `kid` header parameter.
pub const MAX_KID_LENGTH: usize = 256;

/// Validate the JWT `kid` (Key ID) header parameter.
///
/// The `kid` is used as a cache key and storage lookup key. Validating it
/// at JWT parsing time — before any cache or storage interaction — prevents
/// cache pollution, storage errors, and unexpected behavior from adversarial
/// or malformed values.
///
/// # Constraints
///
/// - Non-empty (at least 1 character)
/// - At most [`MAX_KID_LENGTH`] characters (256)
/// - Only ASCII alphanumeric characters, hyphens, underscores, and dots: `[a-zA-Z0-9._-]`
///
/// # Errors
///
/// Returns [`AuthError::InvalidKid`] describing which constraint was violated.
///
/// # Examples
///
/// ```
/// use inferadb_common_authn::validation::validate_kid;
///
/// // Valid kid values
/// assert!(validate_kid("org-abc-123").is_ok());
/// assert!(validate_kid("my_key.v2").is_ok());
///
/// // Empty kid rejected
/// assert!(validate_kid("").is_err());
///
/// // Path traversal rejected
/// assert!(validate_kid("../etc/passwd").is_err());
/// ```
pub fn validate_kid(kid: &str) -> Result<(), AuthError> {
    if kid.is_empty() {
        return Err(AuthError::invalid_kid("kid must not be empty"));
    }

    if kid.len() > MAX_KID_LENGTH {
        return Err(AuthError::invalid_kid(format!(
            "kid exceeds maximum length of {} (got {})",
            MAX_KID_LENGTH,
            kid.len()
        )));
    }

    if let Some(pos) =
        kid.find(|c: char| !(c.is_ascii_alphanumeric() || c == '.' || c == '_' || c == '-'))
    {
        return Err(AuthError::invalid_kid(format!(
            "kid contains invalid character '{}' at position {} (allowed: a-zA-Z0-9._-)",
            kid.as_bytes()[pos] as char,
            pos
        )));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_algorithm_eddsa_accepted() {
        assert!(validate_algorithm("EdDSA").is_ok());
    }

    #[test]
    fn test_validate_algorithm_rs256_rejected() {
        // RS256 is not currently supported end-to-end — only EdDSA has full
        // verification pipeline support. RS256 should produce a clear error
        // rather than passing validation and failing at signature verification.
        let result = validate_algorithm("RS256");
        assert!(
            matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("not in accepted list"))
        );
    }

    #[test]
    fn test_validate_algorithm_symmetric_rejected() {
        assert!(validate_algorithm("HS256").is_err());
        assert!(validate_algorithm("HS384").is_err());
        assert!(validate_algorithm("HS512").is_err());
    }

    #[test]
    fn test_validate_algorithm_none_rejected() {
        let result = validate_algorithm("none");
        assert!(
            matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("not allowed for security reasons"))
        );
    }

    #[test]
    fn test_validate_algorithm_not_in_list() {
        // ES256 is not in ACCEPTED_ALGORITHMS
        let result = validate_algorithm("ES256");
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm { .. })));
    }

    #[test]
    fn test_forbidden_algorithms_each_rejected_with_security_message() {
        // Each forbidden algorithm must be rejected before checking the
        // accepted list, with a message indicating security reasons.
        for alg in FORBIDDEN_ALGORITHMS {
            let result = validate_algorithm(alg);
            assert!(
                matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("not allowed for security reasons")),
                "Expected security rejection for forbidden algorithm '{alg}'"
            );
        }
    }

    #[test]
    fn test_forbidden_algorithms_constant() {
        assert_eq!(FORBIDDEN_ALGORITHMS.len(), 4);
        assert!(FORBIDDEN_ALGORITHMS.contains(&"none"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS256"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS384"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS512"));
    }

    #[test]
    fn test_accepted_algorithms_constant() {
        assert_eq!(ACCEPTED_ALGORITHMS.len(), 1);
        assert!(ACCEPTED_ALGORITHMS.contains(&"EdDSA"));
        // RS256 intentionally excluded — see ACCEPTED_ALGORITHMS doc comment
        assert!(!ACCEPTED_ALGORITHMS.contains(&"RS256"));
    }

    // ========== validate_kid tests ==========

    #[test]
    fn test_validate_kid_valid_alphanumeric() {
        assert!(validate_kid("abc123").is_ok());
    }

    #[test]
    fn test_validate_kid_valid_with_hyphens_underscores_dots() {
        assert!(validate_kid("org-abc_123.v2").is_ok());
    }

    #[test]
    fn test_validate_kid_valid_single_char() {
        assert!(validate_kid("k").is_ok());
    }

    #[test]
    fn test_validate_kid_valid_at_max_length() {
        let kid = "a".repeat(MAX_KID_LENGTH);
        assert!(validate_kid(&kid).is_ok());
    }

    #[test]
    fn test_validate_kid_empty_rejected() {
        let result = validate_kid("");
        assert!(
            matches!(result, Err(AuthError::InvalidKid { message: ref msg, .. }) if msg.contains("must not be empty")),
            "Expected empty kid rejection, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_kid_oversized_rejected() {
        let kid = "a".repeat(MAX_KID_LENGTH + 1);
        let result = validate_kid(&kid);
        assert!(
            matches!(result, Err(AuthError::InvalidKid { message: ref msg, .. }) if msg.contains("exceeds maximum length")),
            "Expected oversized kid rejection, got: {result:?}"
        );
    }

    #[test]
    fn test_validate_kid_path_traversal_rejected() {
        let result = validate_kid("../etc/passwd");
        assert!(
            matches!(result, Err(AuthError::InvalidKid { message: ref msg, .. }) if msg.contains("invalid character '/'"))
        );
    }

    #[test]
    fn test_validate_kid_null_bytes_rejected() {
        let result = validate_kid("key\0id");
        assert!(matches!(result, Err(AuthError::InvalidKid { .. })));
    }

    #[test]
    fn test_validate_kid_spaces_rejected() {
        let result = validate_kid("key id");
        assert!(
            matches!(result, Err(AuthError::InvalidKid { message: ref msg, .. }) if msg.contains("invalid character ' '"))
        );
    }

    #[test]
    fn test_validate_kid_colon_rejected() {
        let result = validate_kid("ns:kid");
        assert!(matches!(result, Err(AuthError::InvalidKid { .. })));
    }

    #[test]
    fn test_validate_kid_unicode_rejected() {
        let result = validate_kid("kid-\u{00e9}");
        assert!(matches!(result, Err(AuthError::InvalidKid { .. })));
    }
}
