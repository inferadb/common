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

use std::{
    ops::RangeBounds,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    StorageBackend,
    error::{StorageError, StorageResult},
    health::{HealthProbe, HealthStatus},
    memory::MemoryBackend,
    transaction::Transaction,
    types::KeyValue,
};

/// Creates a deterministic test key from a prefix and index.
///
/// Produces keys like `"prefix:000042"` (zero-padded to 6 digits) encoded
/// as UTF-8 bytes. The zero-padding ensures lexicographic ordering matches
/// numeric ordering, which is important for range query tests.
#[must_use]
pub fn make_key(prefix: &str, idx: usize) -> Vec<u8> {
    format!("{prefix}:{idx:06}").into_bytes()
}

/// Creates a test value of the given size filled with `0xAB` bytes.
///
/// Useful for benchmarks and tests that need values of specific sizes
/// without caring about the content.
#[must_use]
pub fn make_value(size: usize) -> Vec<u8> {
    vec![0xAB; size]
}

/// Creates a test value tagged with a task ID and sequence number.
///
/// Produces values like `"task3-val042"` encoded as UTF-8 bytes.
/// Useful for concurrent tests where you need to identify which task
/// wrote which value.
#[must_use]
pub fn make_tagged_value(task: usize, seq: usize) -> Vec<u8> {
    format!("task{task}-val{seq}").into_bytes()
}

/// Creates a [`MemoryBackend`] pre-populated with `count` keys.
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
/// use inferadb_common_storage::assert_conflict;
/// use inferadb_common_storage::error::{StorageError, StorageResult};
///
/// let result: StorageResult<()> = Err(StorageError::conflict());
/// assert_conflict!(result);
/// ```
#[macro_export]
macro_rules! assert_conflict {
    ($result:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::Conflict { .. })),
            "expected StorageError::Conflict, got: {:?}",
            $result,
        );
    };
    ($result:expr, $msg:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::Conflict { .. })),
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
/// use inferadb_common_storage::assert_not_found;
/// use inferadb_common_storage::error::{StorageError, StorageResult};
///
/// let result: StorageResult<()> = Err(StorageError::not_found("missing"));
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
/// use inferadb_common_storage::assert_storage_ok;
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
            matches!($result, Err($crate::error::StorageError::Timeout { .. })),
            "expected StorageError::Timeout, got: {:?}",
            $result,
        );
    };
}

/// Returns `true` if the result is `Err(StorageError::Conflict { .. })`.
pub fn is_conflict<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::Conflict { .. }))
}

/// Returns `true` if the result is `Err(StorageError::NotFound { .. })`.
pub fn is_not_found<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::NotFound { .. }))
}

/// Returns `true` if the result is `Err(StorageError::Timeout { .. })`.
pub fn is_timeout<T>(result: &StorageResult<T>) -> bool {
    matches!(result, Err(StorageError::Timeout { .. }))
}

/// Assert that a [`StorageResult`] is an `Err` matching the given [`StorageError`] variant.
///
/// This is a generic version of the per-variant assertion macros. It works with
/// any `StorageError` variant, including struct variants with fields.
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::assert_storage_error;
/// use inferadb_common_storage::error::{StorageError, StorageResult};
///
/// let result: StorageResult<()> = Err(StorageError::connection("down"));
/// assert_storage_error!(result, Connection);
/// ```
#[macro_export]
macro_rules! assert_storage_error {
    ($result:expr, $variant:ident) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::$variant { .. })),
            "expected StorageError::{}, got: {:?}",
            stringify!($variant),
            $result,
        );
    };
    ($result:expr, $variant:ident, $msg:expr) => {
        assert!(
            matches!($result, Err($crate::error::StorageError::$variant { .. })),
            "{}: expected StorageError::{}, got: {:?}",
            $msg,
            stringify!($variant),
            $result,
        );
    };
}

/// Assert that a [`KeyValue`] pair matches the expected key and value.
///
/// Accepts either `&[u8]` slices or `&str` for the expected key and value.
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::assert_kv_pair;
/// use inferadb_common_storage::types::KeyValue;
/// use bytes::Bytes;
///
/// let kv = KeyValue { key: Bytes::from("user"), value: Bytes::from("alice") };
/// assert_kv_pair!(kv, "user", "alice");
/// ```
#[macro_export]
macro_rules! assert_kv_pair {
    ($kv:expr, $expected_key:expr, $expected_value:expr) => {
        assert_eq!(
            $kv.key,
            bytes::Bytes::from($expected_key),
            "key mismatch: expected {:?}, got {:?}",
            $expected_key,
            $kv.key,
        );
        assert_eq!(
            $kv.value,
            bytes::Bytes::from($expected_value),
            "value mismatch at key {:?}: expected {:?}, got {:?}",
            $kv.key,
            $expected_value,
            $kv.value,
        );
    };
}

/// Assert that a slice of [`KeyValue`] pairs matches the expected key-value pairs.
///
/// Each expected pair is specified as `(key, value)` where both are convertible
/// to [`Bytes`](bytes::Bytes). Asserts the length matches first, then checks
/// each pair in order.
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::assert_range_results;
/// use inferadb_common_storage::types::KeyValue;
/// use bytes::Bytes;
///
/// let results = vec![
///     KeyValue { key: Bytes::from("a"), value: Bytes::from("va") },
///     KeyValue { key: Bytes::from("b"), value: Bytes::from("vb") },
/// ];
/// assert_range_results!(results, [("a", "va"), ("b", "vb")]);
/// ```
#[macro_export]
macro_rules! assert_range_results {
    ($results:expr, [$(($key:expr, $value:expr)),* $(,)?]) => {{
        let expected: &[(&str, &str)] = &[$(($key, $value)),*];
        assert_eq!(
            $results.len(),
            expected.len(),
            "range result count mismatch: expected {}, got {}",
            expected.len(),
            $results.len(),
        );
        for (i, (ek, ev)) in expected.iter().enumerate() {
            assert_eq!(
                $results[i].key,
                bytes::Bytes::from(*ek),
                "key mismatch at index {i}: expected {:?}, got {:?}",
                ek,
                $results[i].key,
            );
            assert_eq!(
                $results[i].value,
                bytes::Bytes::from(*ev),
                "value mismatch at index {i} (key {:?}): expected {:?}, got {:?}",
                $results[i].key,
                ev,
                $results[i].value,
            );
        }
    }};
}

// ============================================================================
// FailingBackend
// ============================================================================

/// Identifies a [`StorageBackend`] method for targeted failure injection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Operation {
    /// [`StorageBackend::get`]
    Get,
    /// [`StorageBackend::set`]
    Set,
    /// [`StorageBackend::set_with_ttl`]
    SetWithTtl,
    /// [`StorageBackend::compare_and_set`]
    CompareAndSet,
    /// [`StorageBackend::delete`]
    Delete,
    /// [`StorageBackend::get_range`]
    GetRange,
    /// [`StorageBackend::clear_range`]
    ClearRange,
    /// [`StorageBackend::transaction`]
    Transaction,
    /// [`StorageBackend::health_check`]
    HealthCheck,
}

/// Factory that produces a [`StorageError`] on each invocation.
///
/// Use the provided constructors ([`error_factory_connection`],
/// [`error_factory_timeout`], etc.) or supply a custom closure.
pub type ErrorFactory = Arc<dyn Fn() -> StorageError + Send + Sync>;

/// Returns a factory that produces [`StorageError::Connection`] errors.
#[must_use]
pub fn error_factory_connection(detail: &str) -> ErrorFactory {
    let detail = detail.to_owned();
    Arc::new(move || StorageError::connection(&detail))
}

/// Returns a factory that produces [`StorageError::Timeout`] errors.
#[must_use]
pub fn error_factory_timeout() -> ErrorFactory {
    Arc::new(StorageError::timeout)
}

/// Returns a factory that produces [`StorageError::Internal`] errors.
#[must_use]
pub fn error_factory_internal(detail: &str) -> ErrorFactory {
    let detail = detail.to_owned();
    Arc::new(move || StorageError::internal(detail.clone()))
}

/// Configures when and how a [`FailingBackend`] injects failures.
///
/// # Examples
///
/// Fail all `set` and `delete` operations immediately:
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::{
///     FailureConfig, Operation, error_factory_connection,
/// };
///
/// let config = FailureConfig::new(error_factory_connection("injected"))
///     .with_operations(vec![Operation::Set, Operation::Delete]);
/// ```
///
/// Fail after 3 successful operations:
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::{
///     FailureConfig, error_factory_timeout,
/// };
///
/// let config = FailureConfig::new(error_factory_timeout())
///     .with_fail_after(3);
/// ```
pub struct FailureConfig {
    /// Factory that produces the injected error.
    error_factory: ErrorFactory,

    /// Restrict failures to these operations. Empty = fail all operations.
    operations: Vec<Operation>,

    /// Succeed this many targeted operations before starting to fail.
    /// `0` means fail immediately.
    fail_after: usize,
}

impl FailureConfig {
    /// Create a config that fails all operations immediately with the given
    /// error factory.
    #[must_use]
    pub fn new(error_factory: ErrorFactory) -> Self {
        Self { error_factory, operations: Vec::new(), fail_after: 0 }
    }

    /// Restrict failures to the listed operations. Unlisted operations always
    /// delegate to the inner backend.
    #[must_use]
    pub fn with_operations(mut self, operations: Vec<Operation>) -> Self {
        self.operations = operations;
        self
    }

    /// Allow `n` targeted operations to succeed before failures begin.
    #[must_use]
    pub fn with_fail_after(mut self, n: usize) -> Self {
        self.fail_after = n;
        self
    }
}

/// [`StorageBackend`] wrapper that injects configurable failures.
///
/// `FailingBackend` wraps any backend and injects errors according to the
/// [`FailureConfig`]. Untargeted operations delegate directly to the inner
/// backend, so you can combine it with [`MemoryBackend`] for self-contained
/// failure-injection tests.
///
/// The failure counter is shared via [`Arc`], making it safe to clone and use
/// across concurrent tasks.
///
/// # Examples
///
/// ```no_run
/// // Requires the `testutil` feature to be enabled.
/// use inferadb_common_storage::testutil::{
///     FailingBackend, FailureConfig, error_factory_connection,
/// };
/// use inferadb_common_storage::{MemoryBackend, StorageBackend};
///
/// # #[tokio::main]
/// # async fn main() {
/// let config = FailureConfig::new(error_factory_connection("boom"));
/// let backend = FailingBackend::wrap(MemoryBackend::new(), config);
///
/// // All operations fail immediately.
/// assert!(backend.get(b"key").await.is_err());
/// # }
/// ```
pub struct FailingBackend<B> {
    inner: B,
    error_factory: ErrorFactory,
    operations: Vec<Operation>,
    /// Number of targeted operations that have succeeded so far.
    counter: Arc<AtomicUsize>,
    /// Number of targeted operations that must succeed before failures begin.
    fail_after: usize,
}

impl<B: Clone> Clone for FailingBackend<B> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            error_factory: Arc::clone(&self.error_factory),
            operations: self.operations.clone(),
            counter: Arc::clone(&self.counter),
            fail_after: self.fail_after,
        }
    }
}

impl<B> FailingBackend<B> {
    /// Wrap the given backend with the provided failure configuration.
    pub fn wrap(inner: B, config: FailureConfig) -> Self {
        Self {
            inner,
            error_factory: config.error_factory,
            operations: config.operations,
            counter: Arc::new(AtomicUsize::new(0)),
            fail_after: config.fail_after,
        }
    }

    /// Returns the number of targeted operations that have succeeded.
    #[must_use]
    pub fn succeeded_count(&self) -> usize {
        self.counter.load(Ordering::Relaxed)
    }

    /// Resets the operation counter to zero.
    pub fn reset(&self) {
        self.counter.store(0, Ordering::Relaxed);
    }

    /// Returns `true` if `op` is targeted for failure.
    fn is_targeted(&self, op: Operation) -> bool {
        self.operations.is_empty() || self.operations.contains(&op)
    }

    /// Check whether this targeted operation should fail.
    ///
    /// Returns `Err` with the injected error when the failure threshold is
    /// reached, or `Ok(())` if the operation should proceed normally.
    fn check_failure(&self, op: Operation) -> StorageResult<()> {
        if !self.is_targeted(op) {
            return Ok(());
        }

        let prev = self.counter.fetch_add(1, Ordering::Relaxed);
        if prev >= self.fail_after { Err((self.error_factory)()) } else { Ok(()) }
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for FailingBackend<B> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        self.check_failure(Operation::Get)?;
        self.inner.get(key).await
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        self.check_failure(Operation::Set)?;
        self.inner.set(key, value).await
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        self.check_failure(Operation::SetWithTtl)?;
        self.inner.set_with_ttl(key, value, ttl).await
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        self.check_failure(Operation::CompareAndSet)?;
        self.inner.compare_and_set(key, expected, new_value).await
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.check_failure(Operation::Delete)?;
        self.inner.delete(key).await
    }

    async fn get_range<R: RangeBounds<Vec<u8>> + Send>(
        &self,
        range: R,
    ) -> StorageResult<Vec<KeyValue>> {
        self.check_failure(Operation::GetRange)?;
        self.inner.get_range(range).await
    }

    async fn clear_range<R: RangeBounds<Vec<u8>> + Send>(&self, range: R) -> StorageResult<()> {
        self.check_failure(Operation::ClearRange)?;
        self.inner.clear_range(range).await
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        self.check_failure(Operation::Transaction)?;
        self.inner.transaction().await
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.check_failure(Operation::HealthCheck)?;
        self.inner.health_check(probe).await
    }
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
        let result: StorageResult<()> = Err(StorageError::conflict());
        assert_conflict!(result);
    }

    #[test]
    fn test_assert_not_found_macro() {
        let result: StorageResult<()> = Err(StorageError::not_found("missing"));
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
        assert!(is_conflict::<()>(&Err(StorageError::conflict())));
        assert!(!is_conflict::<()>(&Ok(())));
    }

    #[test]
    fn test_is_not_found() {
        assert!(is_not_found::<()>(&Err(StorageError::not_found("x"))));
        assert!(!is_not_found::<()>(&Ok(())));
    }

    #[test]
    fn test_assert_storage_error_conflict() {
        let result: StorageResult<()> = Err(StorageError::conflict());
        assert_storage_error!(result, Conflict);
    }

    #[test]
    fn test_assert_storage_error_not_found() {
        let result: StorageResult<()> = Err(StorageError::not_found("x"));
        assert_storage_error!(result, NotFound);
    }

    #[test]
    fn test_assert_storage_error_connection() {
        let result: StorageResult<()> = Err(StorageError::connection("down"));
        assert_storage_error!(result, Connection);
    }

    #[test]
    fn test_assert_storage_error_timeout() {
        let result: StorageResult<()> = Err(StorageError::timeout());
        assert_storage_error!(result, Timeout);
    }

    #[test]
    fn test_assert_storage_error_with_message() {
        let result: StorageResult<()> = Err(StorageError::conflict());
        assert_storage_error!(result, Conflict, "CAS should fail");
    }

    #[test]
    fn test_assert_kv_pair_macro() {
        use bytes::Bytes;

        use crate::types::KeyValue;

        let kv = KeyValue { key: Bytes::from("user"), value: Bytes::from("alice") };
        assert_kv_pair!(kv, "user", "alice");
    }

    #[test]
    fn test_assert_range_results_macro() {
        use bytes::Bytes;

        use crate::types::KeyValue;

        let results = [
            KeyValue { key: Bytes::from("a"), value: Bytes::from("va") },
            KeyValue { key: Bytes::from("b"), value: Bytes::from("vb") },
        ];
        assert_range_results!(results, [("a", "va"), ("b", "vb")]);
    }

    #[test]
    fn test_assert_range_results_empty() {
        let results: Vec<crate::types::KeyValue> = vec![];
        assert_range_results!(results, []);
    }

    #[test]
    fn test_assert_range_results_single() {
        use bytes::Bytes;

        use crate::types::KeyValue;

        let results = [KeyValue { key: Bytes::from("x"), value: Bytes::from("vx") }];
        assert_range_results!(results, [("x", "vx")]);
    }

    // ── FailingBackend tests ───────────────────────────────────────

    fn failing_backend(config: FailureConfig) -> FailingBackend<MemoryBackend> {
        FailingBackend::wrap(MemoryBackend::new(), config)
    }

    #[tokio::test]
    async fn test_failing_backend_fails_all_immediately() {
        let backend = failing_backend(FailureConfig::new(error_factory_connection("down")));

        assert!(backend.get(b"k").await.is_err());
        assert!(backend.set(b"k".to_vec(), b"v".to_vec()).await.is_err());
        assert!(backend.delete(b"k").await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_get_only() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::Get]);
        let backend = failing_backend(config);

        // set is NOT targeted — should succeed.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set should work");

        // get IS targeted — should fail.
        let result = backend.get(b"k").await;
        assert!(matches!(result, Err(StorageError::Connection { .. })));
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_set_only() {
        let config =
            FailureConfig::new(error_factory_timeout()).with_operations(vec![Operation::Set]);
        let backend = failing_backend(config);

        // set IS targeted — should fail.
        let result = backend.set(b"k".to_vec(), b"v".to_vec()).await;
        assert!(matches!(result, Err(StorageError::Timeout { .. })));

        // get is NOT targeted — should succeed.
        let result = backend.get(b"k").await.expect("get should work");
        assert_eq!(result, None);
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_delete_only() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::Delete]);
        let backend = failing_backend(config);

        // set works.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set should work");

        // delete fails.
        assert!(backend.delete(b"k").await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_compare_and_set() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::CompareAndSet]);
        let backend = failing_backend(config);

        // set works.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set");

        // CAS fails.
        assert!(backend.compare_and_set(b"k", Some(b"v"), b"v2".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_get_range() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::GetRange]);
        let backend = failing_backend(config);

        backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("set");

        // get_range fails.
        assert!(backend.get_range(b"a".to_vec()..b"z".to_vec()).await.is_err());

        // get works (not targeted).
        assert!(backend.get(b"a").await.is_ok());
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_clear_range() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::ClearRange]);
        let backend = failing_backend(config);

        assert!(backend.clear_range(b"a".to_vec()..b"z".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_transaction() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::Transaction]);
        let backend = failing_backend(config);

        assert!(backend.transaction().await.is_err());

        // Other ops work.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set");
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_health_check() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::HealthCheck]);
        let backend = failing_backend(config);

        assert!(backend.health_check(HealthProbe::Readiness).await.is_err());

        // Other ops work.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set");
    }

    #[tokio::test]
    async fn test_failing_backend_targeted_set_with_ttl() {
        let config = FailureConfig::new(error_factory_connection("down"))
            .with_operations(vec![Operation::SetWithTtl]);
        let backend = failing_backend(config);

        assert!(
            backend
                .set_with_ttl(b"k".to_vec(), b"v".to_vec(), Duration::from_secs(60))
                .await
                .is_err()
        );

        // Regular set works.
        backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set");
    }

    #[tokio::test]
    async fn test_failing_backend_fail_after_n() {
        let config = FailureConfig::new(error_factory_connection("down")).with_fail_after(3);
        let backend = failing_backend(config);

        // First 3 operations succeed.
        backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("op 1");
        backend.set(b"b".to_vec(), b"vb".to_vec()).await.expect("op 2");
        backend.set(b"c".to_vec(), b"vc".to_vec()).await.expect("op 3");

        assert_eq!(backend.succeeded_count(), 3);

        // Fourth fails.
        assert!(backend.set(b"d".to_vec(), b"vd".to_vec()).await.is_err());

        // Subsequent operations also fail.
        assert!(backend.get(b"a").await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_fail_after_targeted() {
        let config = FailureConfig::new(error_factory_timeout())
            .with_operations(vec![Operation::Get])
            .with_fail_after(2);
        let backend = failing_backend(config);

        // Sets don't count (not targeted).
        backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("set");
        backend.set(b"b".to_vec(), b"vb".to_vec()).await.expect("set");

        // First two gets succeed.
        backend.get(b"a").await.expect("get 1");
        backend.get(b"b").await.expect("get 2");
        assert_eq!(backend.succeeded_count(), 2);

        // Third get fails.
        assert!(backend.get(b"a").await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_reset() {
        let config = FailureConfig::new(error_factory_connection("down")).with_fail_after(1);
        let backend = failing_backend(config);

        // First succeeds, second fails.
        backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("op 1");
        assert!(backend.set(b"b".to_vec(), b"vb".to_vec()).await.is_err());

        // Reset counter.
        backend.reset();
        assert_eq!(backend.succeeded_count(), 0);

        // First succeeds again.
        backend.set(b"c".to_vec(), b"vc".to_vec()).await.expect("op after reset");
        assert!(backend.set(b"d".to_vec(), b"vd".to_vec()).await.is_err());
    }

    #[tokio::test]
    async fn test_failing_backend_custom_error() {
        let config = FailureConfig::new(error_factory_internal("injected fault"));
        let backend = failing_backend(config);

        let err = backend.get(b"k").await.expect_err("should fail");
        assert!(matches!(err, StorageError::Internal { .. }));
        assert!(err.detail().contains("injected fault"));
    }

    #[tokio::test]
    async fn test_failing_backend_clone_shares_counter() {
        let config = FailureConfig::new(error_factory_connection("down")).with_fail_after(2);
        let backend = failing_backend(config);

        let clone = backend.clone();

        // One operation on original.
        backend.set(b"a".to_vec(), b"va".to_vec()).await.expect("op 1 on original");
        // One on clone — shares the counter.
        clone.set(b"b".to_vec(), b"vb".to_vec()).await.expect("op 2 on clone");

        // Third operation on either should fail.
        assert!(backend.set(b"c".to_vec(), b"vc".to_vec()).await.is_err());
        assert!(clone.set(b"d".to_vec(), b"vd".to_vec()).await.is_err());
    }
}
