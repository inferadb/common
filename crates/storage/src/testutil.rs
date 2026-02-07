//! Shared test utilities for storage backend testing.
//!
//! This module provides common helpers for creating test backends, generating
//! test data, and asserting on [`StorageResult`] values. It is feature-gated
//! behind `testutil` to prevent leaking into production builds.
//!
//! # Usage
//!
//! In integration tests, enable the feature in `Cargo.toml`:
//!
//! ```toml
//! [dev-dependencies]
//! inferadb-common-storage = { path = "../storage", features = ["testutil"] }
//! ```
//!
//! Then import helpers:
//!
//! ```no_run
//! // Requires the `testutil` feature to be enabled.
//! use inferadb_common_storage::testutil::{make_key, make_value, populated_backend};
//! ```

use crate::{
    StorageBackend,
    error::{StorageError, StorageResult},
    memory::MemoryBackend,
};

/// Create a deterministic test key from a prefix and index.
///
/// Produces keys like `"prefix:000042"` (zero-padded to 6 digits) encoded
/// as UTF-8 bytes. The zero-padding ensures lexicographic ordering matches
/// numeric ordering, which is important for range query tests.
#[must_use]
pub fn make_key(prefix: &str, idx: usize) -> Vec<u8> {
    format!("{prefix}:{idx:06}").into_bytes()
}

/// Create a test value of the given size filled with `0xAB` bytes.
///
/// Useful for benchmarks and tests that need values of specific sizes
/// without caring about the content.
#[must_use]
pub fn make_value(size: usize) -> Vec<u8> {
    vec![0xAB; size]
}

/// Create a test value tagged with a task ID and sequence number.
///
/// Produces values like `"task3-val042"` encoded as UTF-8 bytes.
/// Useful for concurrent tests where you need to identify which task
/// wrote which value.
#[must_use]
pub fn make_tagged_value(task: usize, seq: usize) -> Vec<u8> {
    format!("task{task}-val{seq}").into_bytes()
}

/// Create a [`MemoryBackend`] pre-populated with `count` keys.
///
/// Keys are formatted as `"{prefix}:{idx:06}"` with values of `value_size`
/// bytes each. The backend is ready for immediate use in tests.
///
/// # Panics
///
/// Panics if any `set` operation fails (should not happen with `MemoryBackend`).
pub async fn populated_backend(prefix: &str, count: usize, value_size: usize) -> MemoryBackend {
    let backend = MemoryBackend::new();
    let value = make_value(value_size);
    for i in 0..count {
        backend.set(make_key(prefix, i), value.clone()).await.expect("populate set failed");
    }
    backend
}

/// Assert that a [`StorageResult`] is a [`StorageError::Conflict`].
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::assert_conflict;
/// use inferadb_common_storage::error::{StorageError, StorageResult};
///
/// let result: StorageResult<()> = Err(StorageError::Conflict);
/// assert_conflict!(result);
/// ```
#[macro_export]
macro_rules! assert_conflict {
    ($result:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::Conflict)),
            "expected StorageError::Conflict, got: {:?}",
            $result,
        );
    };
    ($result:expr, $msg:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::Conflict)),
            "{}: expected StorageError::Conflict, got: {:?}",
            $msg,
            $result,
        );
    };
}

/// Assert that a [`StorageResult`] is a [`StorageError::NotFound`].
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::assert_not_found;
/// use inferadb_common_storage::error::{StorageError, StorageResult};
///
/// let result: StorageResult<()> = Err(StorageError::NotFound { key: "missing".into() });
/// assert_not_found!(result);
/// ```
#[macro_export]
macro_rules! assert_not_found {
    ($result:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::NotFound { .. })),
            "expected StorageError::NotFound, got: {:?}",
            $result,
        );
    };
    ($result:expr, $msg:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::NotFound { .. })),
            "{}: expected StorageError::NotFound, got: {:?}",
            $msg,
            $result,
        );
    };
}

/// Assert that a [`StorageResult`] is `Ok`.
///
/// Returns the inner value on success, panics with a descriptive message
/// on failure.
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::assert_storage_ok;
/// use inferadb_common_storage::error::StorageResult;
///
/// let result: StorageResult<i32> = Ok(42);
/// let value = assert_storage_ok!(result);
/// assert_eq!(value, 42);
/// ```
#[macro_export]
macro_rules! assert_storage_ok {
    ($result:expr) => {
        match $result {
            Ok(val) => val,
            Err(e) => panic!("expected Ok, got StorageError: {e:?}"),
        }
    };
    ($result:expr, $msg:expr) => {
        match $result {
            Ok(val) => val,
            Err(e) => panic!("{}: expected Ok, got StorageError: {e:?}", $msg),
        }
    };
}

/// Assert that a [`StorageResult`] contains a [`StorageError::Timeout`].
#[macro_export]
macro_rules! assert_timeout {
    ($result:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::Timeout)),
            "expected StorageError::Timeout, got: {:?}",
            $result,
        );
    };
}

/// Helper to verify that a result is an error of a specific variant.
///
/// This is a convenience for tests that need to match on error variants
/// without importing the error type directly.
pub fn is_conflict<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::Conflict))
}

/// Helper to verify that a result is a `NotFound` error.
pub fn is_not_found<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::NotFound { .. }))
}

/// Helper to verify that a result is a `Timeout` error.
pub fn is_timeout<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::Timeout))
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_make_key_format() {
        let key = make_key("test", 42);
        assert_eq!(key, b"test:000042");
    }

    #[test]
    fn test_make_key_ordering() {
        let k1 = make_key("k", 1);
        let k2 = make_key("k", 10);
        let k3 = make_key("k", 100);
        assert!(k1 < k2);
        assert!(k2 < k3);
    }

    #[test]
    fn test_make_value_size() {
        assert_eq!(make_value(0).len(), 0);
        assert_eq!(make_value(64).len(), 64);
        assert!(make_value(1024).iter().all(|&b| b == 0xAB));
    }

    #[test]
    fn test_make_tagged_value() {
        let val = make_tagged_value(3, 42);
        assert_eq!(val, b"task3-val42");
    }

    #[tokio::test]
    async fn test_populated_backend() {
        let backend = populated_backend("item", 5, 16).await;
        for i in 0..5 {
            let key = make_key("item", i);
            let val = backend.get(&key).await.expect("get");
            assert!(val.is_some(), "key {i} should exist");
            assert_eq!(val.expect("present").len(), 16);
        }
    }

    #[test]
    fn test_assert_conflict_macro() {
        let result: StorageResult<()> = Err(StorageError::Conflict);
        assert_conflict!(result);
    }

    #[test]
    fn test_assert_not_found_macro() {
        let result: StorageResult<()> = Err(StorageError::NotFound { key: "missing".into() });
        assert_not_found!(result);
    }

    #[test]
    fn test_assert_storage_ok_macro() {
        let result: StorageResult<i32> = Ok(42);
        let val = assert_storage_ok!(result);
        assert_eq!(val, 42);
    }

    #[test]
    fn test_is_conflict() {
        assert!(is_conflict::<()>(&Err(StorageError::Conflict)));
        assert!(!is_conflict::<()>(&Ok(())));
    }

    #[test]
    fn test_is_not_found() {
        assert!(is_not_found::<()>(&Err(StorageError::NotFound { key: "x".into() })));
        assert!(!is_not_found::<()>(&Ok(())));
    }
}
