//! Instrumented wrapper that records per-operation timing and error metrics.
//!
//! [`InstrumentedBackend`] wraps any [`StorageBackend`] and records latency,
//! error counts, conflict counts, TTL operations, and health checks via the
//! crate's [`Metrics`] infrastructure.
//!
//! # Examples
//!
//! ```no_run
//! use inferadb_common_storage::{MemoryBackend, MetricsCollector, StorageBackend};
//! use inferadb_common_storage::instrumented::InstrumentedBackend;
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MemoryBackend::new();
//! let instrumented = InstrumentedBackend::new(backend);
//!
//! instrumented.set(b"key".to_vec(), b"value".to_vec()).await?;
//! let snap = instrumented.metrics().snapshot();
//! assert_eq!(snap.set_count, 1);
//! # Ok(())
//! # }
//! ```

use std::time::Duration;

use async_trait::async_trait;
use bytes::Bytes;

use crate::{
    StorageBackend, StorageError, StorageRange,
    error::StorageResult,
    health::{HealthProbe, HealthStatus},
    metrics::{Metrics, MetricsCollector},
    transaction::Transaction,
    types::KeyValue,
};

/// [`StorageBackend`] wrapper that records per-operation timing and error
/// metrics.
///
/// Every method delegates to the inner backend and records:
/// - **Latency**: Operation duration via the appropriate `record_*` method
/// - **Errors**: General error count on any failure
/// - **Conflicts**: Conflict count on CAS failures
/// - **TTL ops**: TTL operation count for `set_with_ttl` and `compare_and_set_with_ttl`
/// - **Health checks**: Health check count (no timing)
pub struct InstrumentedBackend<B> {
    inner: B,
    metrics: Metrics,
}

impl<B: std::fmt::Debug> std::fmt::Debug for InstrumentedBackend<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InstrumentedBackend").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl<B: Clone> Clone for InstrumentedBackend<B> {
    fn clone(&self) -> Self {
        Self { inner: self.inner.clone(), metrics: Metrics::new() }
    }
}

impl<B: StorageBackend> InstrumentedBackend<B> {
    /// Wraps a backend with fresh metrics.
    #[must_use = "constructing an instrumented backend has no side effects"]
    pub fn new(inner: B) -> Self {
        Self { inner, metrics: Metrics::new() }
    }

    /// Wraps a backend with the provided metrics instance.
    #[must_use = "constructing an instrumented backend has no side effects"]
    pub fn with_metrics(inner: B, metrics: Metrics) -> Self {
        Self { inner, metrics }
    }

    /// Returns a reference to the inner backend.
    #[must_use = "returns a reference without side effects"]
    pub fn inner(&self) -> &B {
        &self.inner
    }

    fn record_error(&self, err: &StorageError) {
        self.metrics.record_error();
        if matches!(err, StorageError::Conflict { .. }) {
            self.metrics.record_conflict();
        }
    }
}

impl<B: StorageBackend> MetricsCollector for InstrumentedBackend<B> {
    fn metrics(&self) -> &Metrics {
        &self.metrics
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for InstrumentedBackend<B> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let start = std::time::Instant::now();
        let result = self.inner.get(key).await;
        self.metrics.record_get(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.set(key, value).await;
        self.metrics.record_set(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.compare_and_set(key, expected, new_value).await;
        self.metrics.record_cas(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.delete(key).await;
        self.metrics.record_delete(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn get_range(&self, range: StorageRange) -> StorageResult<Vec<KeyValue>> {
        let start = std::time::Instant::now();
        let result = self.inner.get_range(range).await;
        self.metrics.record_get_range(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn clear_range(&self, range: StorageRange) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.clear_range(range).await;
        self.metrics.record_clear_range(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.set_with_ttl(key, value, ttl).await;
        self.metrics.record_set(start.elapsed());
        self.metrics.record_ttl_operation();
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        let start = std::time::Instant::now();
        let result = self.inner.compare_and_set_with_ttl(key, expected, new_value, ttl).await;
        self.metrics.record_cas(start.elapsed());
        self.metrics.record_ttl_operation();
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        let start = std::time::Instant::now();
        let result = self.inner.transaction().await;
        self.metrics.record_transaction(start.elapsed());
        if let Err(ref e) = result {
            self.record_error(e);
        }
        result
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.metrics.record_health_check();
        self.inner.health_check(probe).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::{MemoryBackend, to_storage_range};

    #[tokio::test]
    async fn set_increments_set_count() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        backend.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.set_count, 1);
    }

    #[tokio::test]
    async fn get_increments_get_count() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        let _ = backend.get(b"key").await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.get_count, 1);
    }

    #[tokio::test]
    async fn records_delete_metrics() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        backend.set(b"key".to_vec(), b"val".to_vec()).await.unwrap();
        backend.delete(b"key").await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.delete_count, 1);
    }

    #[tokio::test]
    async fn get_range_increments_get_range_count() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        let _ = backend.get_range(to_storage_range(b"a".to_vec()..b"z".to_vec())).await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.get_range_count, 1);
    }

    #[tokio::test]
    async fn clear_range_increments_clear_range_count() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        backend.clear_range(to_storage_range(b"a".to_vec()..b"z".to_vec())).await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.clear_range_count, 1);
    }

    #[tokio::test]
    async fn records_ttl_operations() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        backend
            .set_with_ttl(b"ttl-key".to_vec(), b"val".to_vec(), Duration::from_secs(60))
            .await
            .unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.ttl_operations, 1);
        assert_eq!(snap.set_count, 1);
    }

    #[tokio::test]
    async fn records_conflict_on_cas_failure() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        // Set a value, then CAS with wrong expected
        backend.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        let result = backend.compare_and_set(b"key", Some(b"wrong"), b"v2".to_vec()).await;
        assert!(result.is_err());

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.cas_count, 1, "CAS operations must be counted separately from SET");
        assert_eq!(snap.set_count, 1, "only the initial set() should count as SET");
        assert_eq!(snap.conflict_count, 1);
        assert_eq!(snap.error_count, 1);
    }

    #[tokio::test]
    async fn records_transaction_metrics() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        let mut txn = backend.transaction().await.unwrap();
        txn.set(b"key".to_vec(), b"val".to_vec());
        txn.commit().await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.transaction_count, 1);
    }

    #[tokio::test]
    async fn records_health_check() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        let status = backend.health_check(HealthProbe::Readiness).await.unwrap();
        assert!(status.is_healthy());

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.health_check_count, 1);
    }

    #[tokio::test]
    async fn inner_accessor_returns_wrapped_backend() {
        let memory = MemoryBackend::new();
        let backend = InstrumentedBackend::new(memory);

        // Inner should work like a normal backend
        backend.inner().set(b"direct".to_vec(), b"val".to_vec()).await.unwrap();
        let val = backend.inner().get(b"direct").await.unwrap();
        assert_eq!(val, Some(Bytes::from("val")));
    }

    #[tokio::test]
    async fn with_metrics_uses_provided_instance() {
        let metrics = Metrics::new();
        let backend = InstrumentedBackend::with_metrics(MemoryBackend::new(), metrics);

        backend.set(b"key".to_vec(), b"val".to_vec()).await.unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.set_count, 1);
    }

    #[tokio::test]
    async fn compare_and_set_with_ttl_records_cas_and_ttl() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());

        backend
            .compare_and_set_with_ttl(b"key", None, b"val".to_vec(), Duration::from_secs(60))
            .await
            .unwrap();

        let snap = backend.metrics().snapshot();
        assert_eq!(snap.cas_count, 1);
        assert_eq!(snap.ttl_operations, 1);
    }

    #[tokio::test]
    async fn clone_creates_fresh_metrics() {
        let backend = InstrumentedBackend::new(MemoryBackend::new());
        backend.set(b"key".to_vec(), b"val".to_vec()).await.unwrap();

        let cloned = backend.clone();

        let original_snap = backend.metrics().snapshot();
        let cloned_snap = cloned.metrics().snapshot();
        assert_eq!(original_snap.set_count, 1);
        assert_eq!(cloned_snap.set_count, 0);
    }
}
