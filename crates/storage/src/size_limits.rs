//! Key and value size validation for storage backends.
//!
//! Provides configurable size limits to prevent abuse and catch oversized
//! payloads before they reach downstream storage systems. Backends can accept
//! an optional [`SizeLimits`] at construction time and call [`validate_sizes`]
//! on every write path.
//!
//! # Defaults
//!
//! | Limit | Default |
//! |-------|---------|
//! | `max_key_size` | 512 bytes |
//! | `max_value_size` | 524 288 bytes (512 KiB) |

use crate::StorageError;

/// Default maximum key size in bytes (512 B).
pub const DEFAULT_MAX_KEY_SIZE: usize = 512;

/// Default maximum value size in bytes (512 KiB).
pub const DEFAULT_MAX_VALUE_SIZE: usize = 512 * 1024;

/// Configurable size limits for keys and values.
///
/// Both limits must be at least 1. Use [`SizeLimits::default`] for the
/// standard limits, or construct with custom values.
///
/// # Example
///
/// ```no_run
/// use inferadb_common_storage::SizeLimits;
///
/// let limits = SizeLimits::new(256, 1024 * 1024);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SizeLimits {
    max_key_size: usize,
    max_value_size: usize,
}

impl SizeLimits {
    /// Creates size limits with the given bounds.
    ///
    /// Both values must be at least 1.
    ///
    /// # Panics
    ///
    /// Panics if either limit is zero.
    #[must_use]
    pub fn new(max_key_size: usize, max_value_size: usize) -> Self {
        assert!(max_key_size >= 1, "max_key_size must be >= 1");
        assert!(max_value_size >= 1, "max_value_size must be >= 1");
        Self { max_key_size, max_value_size }
    }

    /// Returns the maximum allowed key size in bytes.
    #[must_use]
    pub fn max_key_size(&self) -> usize {
        self.max_key_size
    }

    /// Returns the maximum allowed value size in bytes.
    #[must_use]
    pub fn max_value_size(&self) -> usize {
        self.max_value_size
    }
}

impl Default for SizeLimits {
    fn default() -> Self {
        Self { max_key_size: DEFAULT_MAX_KEY_SIZE, max_value_size: DEFAULT_MAX_VALUE_SIZE }
    }
}

/// Validates key and value sizes against the given limits.
///
/// Returns `Ok(())` when both sizes are within bounds, or
/// `Err(StorageError::SizeLimitExceeded)` identifying which limit was
/// violated.
pub fn validate_sizes(
    key: &[u8],
    value: &[u8],
    limits: &SizeLimits,
) -> Result<(), StorageError> {
    if key.len() > limits.max_key_size {
        return Err(StorageError::size_limit_exceeded(
            "key",
            key.len(),
            limits.max_key_size,
        ));
    }
    if value.len() > limits.max_value_size {
        return Err(StorageError::size_limit_exceeded(
            "value",
            value.len(),
            limits.max_value_size,
        ));
    }
    Ok(())
}

/// Validates key size only (for operations where the value is not available,
/// e.g. delete or get operations that want key-length protection).
pub fn validate_key_size(key: &[u8], limits: &SizeLimits) -> Result<(), StorageError> {
    if key.len() > limits.max_key_size {
        return Err(StorageError::size_limit_exceeded(
            "key",
            key.len(),
            limits.max_key_size,
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_limits() {
        let limits = SizeLimits::default();
        assert_eq!(limits.max_key_size(), DEFAULT_MAX_KEY_SIZE);
        assert_eq!(limits.max_value_size(), DEFAULT_MAX_VALUE_SIZE);
    }

    #[test]
    fn custom_limits() {
        let limits = SizeLimits::new(64, 1024);
        assert_eq!(limits.max_key_size(), 64);
        assert_eq!(limits.max_value_size(), 1024);
    }

    #[test]
    #[should_panic(expected = "max_key_size must be >= 1")]
    fn zero_key_size_panics() {
        SizeLimits::new(0, 1024);
    }

    #[test]
    #[should_panic(expected = "max_value_size must be >= 1")]
    fn zero_value_size_panics() {
        SizeLimits::new(1, 0);
    }

    #[test]
    fn validate_within_limits() {
        let limits = SizeLimits::new(10, 20);
        let key = vec![0u8; 10];
        let value = vec![0u8; 20];
        assert!(validate_sizes(&key, &value, &limits).is_ok());
    }

    #[test]
    fn validate_key_exceeds_limit() {
        let limits = SizeLimits::new(10, 20);
        let key = vec![0u8; 11];
        let value = vec![0u8; 5];
        let err = validate_sizes(&key, &value, &limits).unwrap_err();
        assert!(matches!(
            err,
            StorageError::SizeLimitExceeded { kind, actual: 11, limit: 10, .. }
            if kind == "key"
        ));
    }

    #[test]
    fn validate_value_exceeds_limit() {
        let limits = SizeLimits::new(10, 20);
        let key = vec![0u8; 5];
        let value = vec![0u8; 21];
        let err = validate_sizes(&key, &value, &limits).unwrap_err();
        assert!(matches!(
            err,
            StorageError::SizeLimitExceeded { kind, actual: 21, limit: 20, .. }
            if kind == "value"
        ));
    }

    #[test]
    fn validate_key_size_only() {
        let limits = SizeLimits::new(10, 20);
        assert!(validate_key_size(&vec![0u8; 10], &limits).is_ok());
        assert!(validate_key_size(&vec![0u8; 11], &limits).is_err());
    }

    #[test]
    fn validate_at_exact_limit() {
        let limits = SizeLimits::new(5, 10);
        assert!(validate_sizes(&vec![0u8; 5], &vec![0u8; 10], &limits).is_ok());
    }

    #[test]
    fn validate_one_byte_over_limit() {
        let limits = SizeLimits::new(5, 10);
        assert!(validate_sizes(&vec![0u8; 6], &vec![0u8; 10], &limits).is_err());
        assert!(validate_sizes(&vec![0u8; 5], &vec![0u8; 11], &limits).is_err());
    }
}
