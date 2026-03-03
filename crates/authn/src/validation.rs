//! Algorithm and key-ID validation for JWT headers.
//!
//! This module provides security checks for JWT fields, ensuring only
//! approved algorithms and well-formed identifiers are accepted.
//!
//! # Security
//!
//! These validators implement security best practices:
//! - Strict algorithm checks to prevent algorithm substitution attacks
//! - Only EdDSA (Ed25519) is accepted
//! - Symmetric algorithms and "none" are always rejected

use jsonwebtoken::Algorithm;

use crate::error::AuthError;

/// Validates the JWT algorithm against security policies.
///
/// Enforces strict algorithm security per RFC 8725:
/// - Rejects symmetric algorithms (HS256, HS384, HS512)
/// - Accepts only EdDSA (Ed25519)
/// - Rejects all other algorithms
///
/// Matches directly on the [`Algorithm`] enum to avoid relying on
/// `Debug` formatting, which is not semver-stable.
///
/// # Arguments
///
/// * `alg` — The algorithm variant from the decoded JWT header
///
/// # Errors
///
/// Returns [`AuthError::UnsupportedAlgorithm`] if:
/// - Algorithm is symmetric (HS256, HS384, HS512) — rejected with a security-specific message
/// - Algorithm is anything other than EdDSA
///
/// # Examples
///
/// ```no_run
/// use inferadb_common_authn::validation::validate_algorithm;
/// use jsonwebtoken::Algorithm;
///
/// // EdDSA is accepted
/// let result = validate_algorithm(Algorithm::EdDSA);
/// assert!(result.is_ok());
///
/// // RS256 is not currently supported
/// let result = validate_algorithm(Algorithm::RS256);
/// assert!(result.is_err());
///
/// // Symmetric algorithm rejected
/// let result = validate_algorithm(Algorithm::HS256);
/// assert!(result.is_err());
/// ```
pub fn validate_algorithm(alg: Algorithm) -> Result<(), AuthError> {
    match alg {
        Algorithm::EdDSA => Ok(()),
        Algorithm::HS256 | Algorithm::HS384 | Algorithm::HS512 => {
            Err(AuthError::unsupported_algorithm(
                "symmetric algorithms are not allowed for security reasons",
            ))
        },
        other => {
            Err(AuthError::unsupported_algorithm(format!("{other:?}: only EdDSA is accepted")))
        },
    }
}

/// Maximum allowed length for a JWT `kid` header parameter.
///
/// Prevents cache key bloat and storage abuse from adversarial inputs.
pub const MAX_KID_LENGTH: usize = 256;

/// Validates the JWT `kid` (Key ID) header parameter.
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
/// ```no_run
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
    use crate::assert_auth_error;

    #[test]
    fn test_validate_algorithm_eddsa_accepted() {
        assert!(validate_algorithm(Algorithm::EdDSA).is_ok());
    }

    #[test]
    fn test_validate_algorithm_rs256_rejected() {
        // RS256 is not currently supported end-to-end — only EdDSA has full
        // verification pipeline support. RS256 should produce a clear error
        // rather than passing validation and failing at signature verification.
        let result = validate_algorithm(Algorithm::RS256);
        assert!(
            matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("only EdDSA is accepted"))
        );
    }

    #[test]
    fn test_validate_algorithm_symmetric_rejected_with_security_message() {
        for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
            let result = validate_algorithm(alg);
            assert!(
                matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("not allowed for security reasons")),
                "Expected security rejection for symmetric algorithm '{alg:?}'"
            );
        }
    }

    #[test]
    fn test_validate_algorithm_not_in_list() {
        // ES256 is not accepted
        let result = validate_algorithm(Algorithm::ES256);
        assert_auth_error!(result, UnsupportedAlgorithm);
    }

    #[test]
    fn test_validate_algorithm_rs384_rejected() {
        let result = validate_algorithm(Algorithm::RS384);
        assert!(
            matches!(result, Err(AuthError::UnsupportedAlgorithm { message: ref msg, .. }) if msg.contains("only EdDSA is accepted"))
        );
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
        assert_auth_error!(result, InvalidKid);
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
        let result = validate_kid("org:kid");
        assert_auth_error!(result, InvalidKid);
    }

    #[test]
    fn test_validate_kid_unicode_rejected() {
        let result = validate_kid("kid-\u{00e9}");
        assert_auth_error!(result, InvalidKid);
    }
}
