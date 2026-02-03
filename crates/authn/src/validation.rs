//! JWT algorithm validation.
//!
//! This module provides security checks for JWT algorithms, ensuring only
//! approved asymmetric algorithms are accepted.
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
/// Only asymmetric algorithms (EdDSA, RS256) are allowed.
pub const FORBIDDEN_ALGORITHMS: &[&str] = &["none", "HS256", "HS384", "HS512"];

/// Accepted JWT algorithms.
///
/// These are the only algorithms accepted:
/// - `EdDSA`: Ed25519 signatures (recommended, fastest, most secure)
/// - `RS256`: RSA-SHA256 signatures (legacy support)
///
/// This list is intentionally not configurable to ensure consistent security
/// across all deployments. The management API uses EdDSA exclusively.
pub const ACCEPTED_ALGORITHMS: &[&str] = &["EdDSA", "RS256"];

/// Validate JWT algorithm against security policies.
///
/// This function enforces strict algorithm security:
/// - ALWAYS rejects symmetric algorithms (HS256, HS384, HS512)
/// - ALWAYS rejects "none" algorithm
/// - Only accepts EdDSA and RS256
///
/// # Arguments
///
/// * `alg` - The algorithm from the JWT header
///
/// # Errors
///
/// Returns an error if:
/// - Algorithm is symmetric (HS256, HS384, HS512)
/// - Algorithm is "none"
/// - Algorithm is not EdDSA or RS256
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
/// // RS256 is accepted
/// let result = validate_algorithm("RS256");
/// assert!(result.is_ok());
///
/// // Symmetric algorithm rejected
/// let result = validate_algorithm("HS256");
/// assert!(result.is_err());
/// ```
pub fn validate_algorithm(alg: &str) -> Result<(), AuthError> {
    // Check against forbidden algorithms
    if FORBIDDEN_ALGORITHMS.contains(&alg) {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not allowed for security reasons",
            alg
        )));
    }

    // Check if in accepted list
    if !ACCEPTED_ALGORITHMS.contains(&alg) {
        return Err(AuthError::UnsupportedAlgorithm(format!(
            "Algorithm '{}' is not in accepted list (only EdDSA and RS256 are supported)",
            alg
        )));
    }

    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_algorithm_asymmetric() {
        assert!(validate_algorithm("EdDSA").is_ok());
        assert!(validate_algorithm("RS256").is_ok());
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
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_validate_algorithm_not_in_list() {
        // ES256 is not in ACCEPTED_ALGORITHMS
        let result = validate_algorithm("ES256");
        assert!(matches!(result, Err(AuthError::UnsupportedAlgorithm(_))));
    }

    #[test]
    fn test_forbidden_algorithms_constant() {
        // Verify the FORBIDDEN_ALGORITHMS constant is correctly defined
        assert_eq!(FORBIDDEN_ALGORITHMS.len(), 4);
        assert!(FORBIDDEN_ALGORITHMS.contains(&"none"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS256"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS384"));
        assert!(FORBIDDEN_ALGORITHMS.contains(&"HS512"));
    }

    #[test]
    fn test_accepted_algorithms_constant() {
        // Verify the ACCEPTED_ALGORITHMS constant is correctly defined
        assert_eq!(ACCEPTED_ALGORITHMS.len(), 2);
        assert!(ACCEPTED_ALGORITHMS.contains(&"EdDSA"));
        assert!(ACCEPTED_ALGORITHMS.contains(&"RS256"));
    }
}
