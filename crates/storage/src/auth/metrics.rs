//! Metrics collection for signing key storage operations.
//!
//! Provides observability into signing key lifecycle operations including
//! counts, latencies, percentiles, and error rates.
//!
//! # Examples
//!
//! ```
//! use std::time::Duration;
//! use inferadb_common_storage::auth::{SigningKeyErrorKind, SigningKeyMetrics};
//!
//! let metrics = SigningKeyMetrics::new();
//!
//! // Record a successful get operation
//! metrics.record_get(Duration::from_micros(150));
//!
//! // Record an error
//! metrics.record_error(SigningKeyErrorKind::NotFound);
//!
//! // Get a snapshot with percentiles
//! let snapshot = metrics.snapshot();
//! assert_eq!(snapshot.get_count, 1);
//! assert_eq!(snapshot.get_percentiles.p50, 150);
//! ```

use std::{
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use crate::metrics::{LatencyHistogram, LatencyPercentiles};

/// Default histogram window size for signing key metrics.
const DEFAULT_HISTOGRAM_WINDOW_SIZE: usize = 1024;

/// Error categories for signing key operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SigningKeyErrorKind {
    /// Key not found in storage.
    NotFound,
    /// Key already exists (conflict on create).
    Conflict,
    /// Connection or network error.
    Connection,
    /// Serialization/deserialization error.
    Serialization,
    /// Key state validation error (inactive, revoked, expired).
    InvalidState,
    /// Other/unknown error.
    Other,
}

/// Snapshot of signing key metrics at a point in time.
#[derive(Debug, Clone, Default, bon::Builder)]
pub struct SigningKeyMetricsSnapshot {
    // Operation counts
    /// Total create_key operations.
    #[builder(default)]
    pub create_count: u64,
    /// Total get_key operations.
    #[builder(default)]
    pub get_count: u64,
    /// Total list_active_keys operations.
    #[builder(default)]
    pub list_count: u64,
    /// Total deactivate_key operations.
    #[builder(default)]
    pub deactivate_count: u64,
    /// Total revoke_key operations.
    #[builder(default)]
    pub revoke_count: u64,
    /// Total activate_key operations.
    #[builder(default)]
    pub activate_count: u64,
    /// Total delete_key operations.
    #[builder(default)]
    pub delete_count: u64,

    // Latencies (cumulative microseconds)
    /// Total latency for create operations in microseconds.
    #[builder(default)]
    pub create_latency_us: u64,
    /// Total latency for get operations in microseconds.
    #[builder(default)]
    pub get_latency_us: u64,
    /// Total latency for list operations in microseconds.
    #[builder(default)]
    pub list_latency_us: u64,
    /// Total latency for deactivate operations in microseconds.
    #[builder(default)]
    pub deactivate_latency_us: u64,
    /// Total latency for revoke operations in microseconds.
    #[builder(default)]
    pub revoke_latency_us: u64,
    /// Total latency for activate operations in microseconds.
    #[builder(default)]
    pub activate_latency_us: u64,
    /// Total latency for delete operations in microseconds.
    #[builder(default)]
    pub delete_latency_us: u64,

    // Latency percentiles (p50/p95/p99)
    /// Create latency percentiles in microseconds.
    #[builder(default)]
    pub create_percentiles: LatencyPercentiles,
    /// Get latency percentiles in microseconds.
    #[builder(default)]
    pub get_percentiles: LatencyPercentiles,
    /// List latency percentiles in microseconds.
    #[builder(default)]
    pub list_percentiles: LatencyPercentiles,
    /// Deactivate latency percentiles in microseconds.
    #[builder(default)]
    pub deactivate_percentiles: LatencyPercentiles,
    /// Revoke latency percentiles in microseconds.
    #[builder(default)]
    pub revoke_percentiles: LatencyPercentiles,
    /// Activate latency percentiles in microseconds.
    #[builder(default)]
    pub activate_percentiles: LatencyPercentiles,
    /// Delete latency percentiles in microseconds.
    #[builder(default)]
    pub delete_percentiles: LatencyPercentiles,

    // Error counts by category
    /// Not found errors.
    #[builder(default)]
    pub error_not_found: u64,
    /// Conflict errors.
    #[builder(default)]
    pub error_conflict: u64,
    /// Connection errors.
    #[builder(default)]
    pub error_connection: u64,
    /// Serialization errors.
    #[builder(default)]
    pub error_serialization: u64,
    /// Invalid state errors.
    #[builder(default)]
    pub error_invalid_state: u64,
    /// Other errors.
    #[builder(default)]
    pub error_other: u64,

    // L3 fallback cache metrics
    /// Current number of entries in the L3 fallback cache.
    #[builder(default)]
    pub fallback_entry_count: u64,
    /// Maximum capacity of the L3 fallback cache.
    #[builder(default)]
    pub fallback_capacity: u64,
    /// Fill percentage of the L3 fallback cache (0.0–100.0).
    #[builder(default)]
    pub fallback_fill_pct: f64,

    // Background refresh metrics
    /// Number of completed background refresh cycles.
    #[builder(default)]
    pub refresh_count: u64,
    /// Total number of keys refreshed across all cycles.
    #[builder(default)]
    pub refresh_keys_total: u64,
    /// Total number of refresh errors across all cycles.
    #[builder(default)]
    pub refresh_errors_total: u64,
    /// Cumulative refresh latency in microseconds across all cycles.
    #[builder(default)]
    pub refresh_latency_us: u64,
}

impl SigningKeyMetricsSnapshot {
    /// Returns the total number of operations.
    #[must_use]
    pub fn total_operations(&self) -> u64 {
        self.create_count
            + self.get_count
            + self.list_count
            + self.deactivate_count
            + self.revoke_count
            + self.activate_count
            + self.delete_count
    }

    /// Returns the total number of errors.
    #[must_use]
    pub fn total_errors(&self) -> u64 {
        self.error_not_found
            + self.error_conflict
            + self.error_connection
            + self.error_serialization
            + self.error_invalid_state
            + self.error_other
    }

    /// Returns the error rate as a fraction (0.0 to 1.0).
    #[must_use]
    pub fn error_rate(&self) -> f64 {
        let total = self.total_operations();
        if total == 0 { 0.0 } else { self.total_errors() as f64 / total as f64 }
    }

    /// Returns the average get latency in microseconds.
    #[must_use]
    pub fn avg_get_latency_us(&self) -> f64 {
        if self.get_count == 0 { 0.0 } else { self.get_latency_us as f64 / self.get_count as f64 }
    }

    /// Returns the average create latency in microseconds.
    #[must_use]
    pub fn avg_create_latency_us(&self) -> f64 {
        if self.create_count == 0 {
            0.0
        } else {
            self.create_latency_us as f64 / self.create_count as f64
        }
    }

    /// Returns the average list latency in microseconds.
    #[must_use]
    pub fn avg_list_latency_us(&self) -> f64 {
        if self.list_count == 0 {
            0.0
        } else {
            self.list_latency_us as f64 / self.list_count as f64
        }
    }

    /// Returns the count of serialization/deserialization errors.
    ///
    /// Non-zero values may indicate keys in storage that could not be parsed,
    /// possibly due to schema migration or data corruption. Operators should
    /// alert on this counter and investigate the affected keys.
    ///
    /// This is a convenience alias for `error_serialization`.
    #[must_use]
    pub fn deserialization_errors(&self) -> u64 {
        self.error_serialization
    }
}

/// Inner storage for atomic counters and histograms.
struct SigningKeyMetricsInner {
    // Operation counts
    create_count: AtomicU64,
    get_count: AtomicU64,
    list_count: AtomicU64,
    deactivate_count: AtomicU64,
    revoke_count: AtomicU64,
    activate_count: AtomicU64,
    delete_count: AtomicU64,

    // Latencies (cumulative microseconds)
    create_latency_us: AtomicU64,
    get_latency_us: AtomicU64,
    list_latency_us: AtomicU64,
    deactivate_latency_us: AtomicU64,
    revoke_latency_us: AtomicU64,
    activate_latency_us: AtomicU64,
    delete_latency_us: AtomicU64,

    // Latency histograms for percentile computation
    create_histogram: LatencyHistogram,
    get_histogram: LatencyHistogram,
    list_histogram: LatencyHistogram,
    deactivate_histogram: LatencyHistogram,
    revoke_histogram: LatencyHistogram,
    activate_histogram: LatencyHistogram,
    delete_histogram: LatencyHistogram,

    // Error counts
    error_not_found: AtomicU64,
    error_conflict: AtomicU64,
    error_connection: AtomicU64,
    error_serialization: AtomicU64,
    error_invalid_state: AtomicU64,
    error_other: AtomicU64,
}

/// Metrics collector for signing key storage operations.
///
/// Thread-safe metrics collection using atomic counters. Designed to be
/// shared across threads via cloning (uses `Arc` internally).
///
/// # Examples
///
/// ```
/// use std::time::{Duration, Instant};
/// use inferadb_common_storage::auth::{SigningKeyMetrics, SigningKeyErrorKind};
///
/// let metrics = SigningKeyMetrics::new();
///
/// // Record operation with timing
/// let start = Instant::now();
/// // ... perform get_key operation ...
/// metrics.record_get(start.elapsed());
///
/// // Record an error
/// metrics.record_error(SigningKeyErrorKind::NotFound);
///
/// // Take a snapshot with percentiles
/// let snapshot = metrics.snapshot();
/// assert_eq!(snapshot.get_count, 1);
/// assert_eq!(snapshot.error_not_found, 1);
/// ```
#[derive(Clone)]
pub struct SigningKeyMetrics {
    inner: Arc<SigningKeyMetricsInner>,
}

impl SigningKeyMetrics {
    /// Creates a new metrics collector.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Arc::new(SigningKeyMetricsInner {
                create_count: AtomicU64::new(0),
                get_count: AtomicU64::new(0),
                list_count: AtomicU64::new(0),
                deactivate_count: AtomicU64::new(0),
                revoke_count: AtomicU64::new(0),
                activate_count: AtomicU64::new(0),
                delete_count: AtomicU64::new(0),
                create_latency_us: AtomicU64::new(0),
                get_latency_us: AtomicU64::new(0),
                list_latency_us: AtomicU64::new(0),
                deactivate_latency_us: AtomicU64::new(0),
                revoke_latency_us: AtomicU64::new(0),
                activate_latency_us: AtomicU64::new(0),
                delete_latency_us: AtomicU64::new(0),
                create_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                get_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                list_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                deactivate_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                revoke_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                activate_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                delete_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
                error_not_found: AtomicU64::new(0),
                error_conflict: AtomicU64::new(0),
                error_connection: AtomicU64::new(0),
                error_serialization: AtomicU64::new(0),
                error_invalid_state: AtomicU64::new(0),
                error_other: AtomicU64::new(0),
            }),
        }
    }

    /// Records a create_key operation.
    pub fn record_create(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.create_count.fetch_add(1, Ordering::Relaxed);
        self.inner.create_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.create_histogram.record(us);
    }

    /// Records a get_key operation.
    pub fn record_get(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.get_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.get_histogram.record(us);
    }

    /// Records a list_active_keys operation.
    pub fn record_list(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.list_count.fetch_add(1, Ordering::Relaxed);
        self.inner.list_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.list_histogram.record(us);
    }

    /// Records a deactivate_key operation.
    pub fn record_deactivate(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.deactivate_count.fetch_add(1, Ordering::Relaxed);
        self.inner.deactivate_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.deactivate_histogram.record(us);
    }

    /// Records a revoke_key operation.
    pub fn record_revoke(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.revoke_count.fetch_add(1, Ordering::Relaxed);
        self.inner.revoke_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.revoke_histogram.record(us);
    }

    /// Records an activate_key operation.
    pub fn record_activate(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.activate_count.fetch_add(1, Ordering::Relaxed);
        self.inner.activate_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.activate_histogram.record(us);
    }

    /// Records a delete_key operation.
    pub fn record_delete(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.delete_count.fetch_add(1, Ordering::Relaxed);
        self.inner.delete_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.delete_histogram.record(us);
    }

    /// Records an error by category.
    pub fn record_error(&self, kind: SigningKeyErrorKind) {
        match kind {
            SigningKeyErrorKind::NotFound => {
                self.inner.error_not_found.fetch_add(1, Ordering::Relaxed);
            },
            SigningKeyErrorKind::Conflict => {
                self.inner.error_conflict.fetch_add(1, Ordering::Relaxed);
            },
            SigningKeyErrorKind::Connection => {
                self.inner.error_connection.fetch_add(1, Ordering::Relaxed);
            },
            SigningKeyErrorKind::Serialization => {
                self.inner.error_serialization.fetch_add(1, Ordering::Relaxed);
            },
            SigningKeyErrorKind::InvalidState => {
                self.inner.error_invalid_state.fetch_add(1, Ordering::Relaxed);
            },
            SigningKeyErrorKind::Other => {
                self.inner.error_other.fetch_add(1, Ordering::Relaxed);
            },
        }
    }

    /// Returns a snapshot of current metrics including percentiles.
    #[must_use]
    pub fn snapshot(&self) -> SigningKeyMetricsSnapshot {
        SigningKeyMetricsSnapshot {
            create_count: self.inner.create_count.load(Ordering::Relaxed),
            get_count: self.inner.get_count.load(Ordering::Relaxed),
            list_count: self.inner.list_count.load(Ordering::Relaxed),
            deactivate_count: self.inner.deactivate_count.load(Ordering::Relaxed),
            revoke_count: self.inner.revoke_count.load(Ordering::Relaxed),
            activate_count: self.inner.activate_count.load(Ordering::Relaxed),
            delete_count: self.inner.delete_count.load(Ordering::Relaxed),
            create_latency_us: self.inner.create_latency_us.load(Ordering::Relaxed),
            get_latency_us: self.inner.get_latency_us.load(Ordering::Relaxed),
            list_latency_us: self.inner.list_latency_us.load(Ordering::Relaxed),
            deactivate_latency_us: self.inner.deactivate_latency_us.load(Ordering::Relaxed),
            revoke_latency_us: self.inner.revoke_latency_us.load(Ordering::Relaxed),
            activate_latency_us: self.inner.activate_latency_us.load(Ordering::Relaxed),
            delete_latency_us: self.inner.delete_latency_us.load(Ordering::Relaxed),
            create_percentiles: self.inner.create_histogram.percentiles(),
            get_percentiles: self.inner.get_histogram.percentiles(),
            list_percentiles: self.inner.list_histogram.percentiles(),
            deactivate_percentiles: self.inner.deactivate_histogram.percentiles(),
            revoke_percentiles: self.inner.revoke_histogram.percentiles(),
            activate_percentiles: self.inner.activate_histogram.percentiles(),
            delete_percentiles: self.inner.delete_histogram.percentiles(),
            error_not_found: self.inner.error_not_found.load(Ordering::Relaxed),
            error_conflict: self.inner.error_conflict.load(Ordering::Relaxed),
            error_connection: self.inner.error_connection.load(Ordering::Relaxed),
            error_serialization: self.inner.error_serialization.load(Ordering::Relaxed),
            error_invalid_state: self.inner.error_invalid_state.load(Ordering::Relaxed),
            error_other: self.inner.error_other.load(Ordering::Relaxed),
            ..Default::default()
        }
    }

    /// Resets all metrics to zero.
    pub fn reset(&self) {
        self.inner.create_count.store(0, Ordering::Relaxed);
        self.inner.get_count.store(0, Ordering::Relaxed);
        self.inner.list_count.store(0, Ordering::Relaxed);
        self.inner.deactivate_count.store(0, Ordering::Relaxed);
        self.inner.revoke_count.store(0, Ordering::Relaxed);
        self.inner.activate_count.store(0, Ordering::Relaxed);
        self.inner.delete_count.store(0, Ordering::Relaxed);
        self.inner.create_latency_us.store(0, Ordering::Relaxed);
        self.inner.get_latency_us.store(0, Ordering::Relaxed);
        self.inner.list_latency_us.store(0, Ordering::Relaxed);
        self.inner.deactivate_latency_us.store(0, Ordering::Relaxed);
        self.inner.revoke_latency_us.store(0, Ordering::Relaxed);
        self.inner.activate_latency_us.store(0, Ordering::Relaxed);
        self.inner.delete_latency_us.store(0, Ordering::Relaxed);
        self.inner.create_histogram.reset();
        self.inner.get_histogram.reset();
        self.inner.list_histogram.reset();
        self.inner.deactivate_histogram.reset();
        self.inner.revoke_histogram.reset();
        self.inner.activate_histogram.reset();
        self.inner.delete_histogram.reset();
        self.inner.error_not_found.store(0, Ordering::Relaxed);
        self.inner.error_conflict.store(0, Ordering::Relaxed);
        self.inner.error_connection.store(0, Ordering::Relaxed);
        self.inner.error_serialization.store(0, Ordering::Relaxed);
        self.inner.error_invalid_state.store(0, Ordering::Relaxed);
        self.inner.error_other.store(0, Ordering::Relaxed);
    }

    /// Logs current metrics at INFO level.
    pub fn log_metrics(&self) {
        let snapshot = self.snapshot();
        tracing::info!(
            create_count = snapshot.create_count,
            get_count = snapshot.get_count,
            list_count = snapshot.list_count,
            deactivate_count = snapshot.deactivate_count,
            revoke_count = snapshot.revoke_count,
            activate_count = snapshot.activate_count,
            delete_count = snapshot.delete_count,
            total_operations = snapshot.total_operations(),
            total_errors = snapshot.total_errors(),
            error_rate = format!("{:.2}%", snapshot.error_rate() * 100.0),
            avg_get_latency_us = format!("{:.1}", snapshot.avg_get_latency_us()),
            avg_create_latency_us = format!("{:.1}", snapshot.avg_create_latency_us()),
            get_p50 = snapshot.get_percentiles.p50,
            get_p95 = snapshot.get_percentiles.p95,
            get_p99 = snapshot.get_percentiles.p99,
            create_p99 = snapshot.create_percentiles.p99,
            "signing_key_metrics"
        );
    }
}

impl Default for SigningKeyMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SigningKeyMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKeyMetrics").field("snapshot", &self.snapshot()).finish()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_new_metrics_are_zero() {
        let metrics = SigningKeyMetrics::new();
        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.total_operations(), 0);
        assert_eq!(snapshot.total_errors(), 0);
    }

    #[test]
    fn test_record_operations() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_create(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(50));
        metrics.record_get(Duration::from_micros(150));
        metrics.record_list(Duration::from_micros(200));
        metrics.record_deactivate(Duration::from_micros(75));
        metrics.record_revoke(Duration::from_micros(80));
        metrics.record_activate(Duration::from_micros(60));
        metrics.record_delete(Duration::from_micros(90));

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.create_count, 1);
        assert_eq!(snapshot.get_count, 2);
        assert_eq!(snapshot.list_count, 1);
        assert_eq!(snapshot.deactivate_count, 1);
        assert_eq!(snapshot.revoke_count, 1);
        assert_eq!(snapshot.activate_count, 1);
        assert_eq!(snapshot.delete_count, 1);
        assert_eq!(snapshot.total_operations(), 8);

        assert_eq!(snapshot.create_latency_us, 100);
        assert_eq!(snapshot.get_latency_us, 200); // 50 + 150
        assert_eq!(snapshot.list_latency_us, 200);
    }

    #[test]
    fn test_record_errors() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_error(SigningKeyErrorKind::NotFound);
        metrics.record_error(SigningKeyErrorKind::NotFound);
        metrics.record_error(SigningKeyErrorKind::Conflict);
        metrics.record_error(SigningKeyErrorKind::Connection);
        metrics.record_error(SigningKeyErrorKind::Serialization);
        metrics.record_error(SigningKeyErrorKind::InvalidState);
        metrics.record_error(SigningKeyErrorKind::Other);

        let snapshot = metrics.snapshot();

        assert_eq!(snapshot.error_not_found, 2);
        assert_eq!(snapshot.error_conflict, 1);
        assert_eq!(snapshot.error_connection, 1);
        assert_eq!(snapshot.error_serialization, 1);
        assert_eq!(snapshot.error_invalid_state, 1);
        assert_eq!(snapshot.error_other, 1);
        assert_eq!(snapshot.total_errors(), 7);
    }

    #[test]
    fn test_error_rate() {
        let metrics = SigningKeyMetrics::new();

        // No operations = 0% error rate
        assert!((metrics.snapshot().error_rate() - 0.0).abs() < f64::EPSILON);

        // 10 operations, 2 errors = 20% error rate
        for _ in 0..10 {
            metrics.record_get(Duration::from_micros(10));
        }
        metrics.record_error(SigningKeyErrorKind::NotFound);
        metrics.record_error(SigningKeyErrorKind::Connection);

        let snapshot = metrics.snapshot();
        assert!((snapshot.error_rate() - 0.2).abs() < f64::EPSILON);
    }

    #[test]
    fn test_average_latency() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(200));
        metrics.record_get(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert!((snapshot.avg_get_latency_us() - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_reset() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_create(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(50));
        metrics.record_error(SigningKeyErrorKind::NotFound);

        assert!(metrics.snapshot().total_operations() > 0);
        assert!(metrics.snapshot().total_errors() > 0);

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_operations(), 0);
        assert_eq!(snapshot.total_errors(), 0);
        assert_eq!(snapshot.create_latency_us, 0);
        assert_eq!(snapshot.get_latency_us, 0);
    }

    #[test]
    fn test_clone_shares_state() {
        let metrics1 = SigningKeyMetrics::new();
        let metrics2 = metrics1.clone();

        metrics1.record_get(Duration::from_micros(100));
        metrics2.record_get(Duration::from_micros(200));

        // Both clones should see 2 get operations
        assert_eq!(metrics1.snapshot().get_count, 2);
        assert_eq!(metrics2.snapshot().get_count, 2);
    }

    #[test]
    fn test_debug_impl() {
        let metrics = SigningKeyMetrics::new();
        metrics.record_get(Duration::from_micros(100));

        let debug_str = format!("{metrics:?}");
        assert!(debug_str.contains("SigningKeyMetrics"));
        assert!(debug_str.contains("snapshot"));
    }

    #[test]
    fn test_default_impl() {
        let metrics = SigningKeyMetrics::default();
        assert_eq!(metrics.snapshot().total_operations(), 0);
    }

    #[test]
    fn test_snapshot_avg_methods_with_zero_count() {
        let snapshot = SigningKeyMetricsSnapshot::default();

        // Should return 0.0 for zero counts, not NaN or panic
        assert!((snapshot.avg_get_latency_us() - 0.0).abs() < f64::EPSILON);
        assert!((snapshot.avg_create_latency_us() - 0.0).abs() < f64::EPSILON);
        assert!((snapshot.avg_list_latency_us() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_metrics_snapshot_builder_defaults() {
        // Builder with no fields should produce all zeros (matching Default)
        let built = SigningKeyMetricsSnapshot::builder().build();
        let default = SigningKeyMetricsSnapshot::default();

        assert_eq!(built.create_count, default.create_count);
        assert_eq!(built.get_count, default.get_count);
        assert_eq!(built.list_count, default.list_count);
        assert_eq!(built.error_not_found, default.error_not_found);
        assert_eq!(built.total_operations(), 0);
        assert_eq!(built.total_errors(), 0);
    }

    #[test]
    fn test_metrics_snapshot_builder_partial() {
        // Builder should allow setting only some fields
        let snapshot = SigningKeyMetricsSnapshot::builder().get_count(5).error_not_found(1).build();

        assert_eq!(snapshot.get_count, 5);
        assert_eq!(snapshot.error_not_found, 1);
        assert_eq!(snapshot.total_operations(), 5);
        assert_eq!(snapshot.total_errors(), 1);
        // Other fields should be 0
        assert_eq!(snapshot.create_count, 0);
        assert_eq!(snapshot.list_count, 0);
    }

    #[test]
    fn test_metrics_snapshot_builder_all_fields() {
        let snapshot = SigningKeyMetricsSnapshot::builder()
            // Operation counts
            .create_count(1)
            .get_count(2)
            .list_count(3)
            .deactivate_count(4)
            .revoke_count(5)
            .activate_count(6)
            .delete_count(7)
            // Latencies
            .create_latency_us(100)
            .get_latency_us(200)
            .list_latency_us(300)
            .deactivate_latency_us(400)
            .revoke_latency_us(500)
            .activate_latency_us(600)
            .delete_latency_us(700)
            // Errors
            .error_not_found(10)
            .error_conflict(11)
            .error_connection(12)
            .error_serialization(13)
            .error_invalid_state(14)
            .error_other(15)
            .build();

        assert_eq!(snapshot.total_operations(), 1 + 2 + 3 + 4 + 5 + 6 + 7);
        assert_eq!(snapshot.total_errors(), 10 + 11 + 12 + 13 + 14 + 15);
    }

    #[test]
    fn test_metrics_snapshot_builder_for_comparison() {
        // Real use case: compare actual metrics with expected
        let metrics = SigningKeyMetrics::new();
        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(200));
        metrics.record_error(SigningKeyErrorKind::NotFound);

        let actual = metrics.snapshot();

        // Build expected snapshot for comparison
        let expected = SigningKeyMetricsSnapshot::builder()
            .get_count(2)
            .get_latency_us(300)
            .error_not_found(1)
            .build();

        assert_eq!(actual.get_count, expected.get_count);
        assert_eq!(actual.get_latency_us, expected.get_latency_us);
        assert_eq!(actual.error_not_found, expected.error_not_found);
    }

    #[test]
    fn test_log_metrics() {
        let metrics = SigningKeyMetrics::new();

        // Record some operations
        metrics.record_get(Duration::from_micros(100));
        metrics.record_create(Duration::from_micros(200));
        metrics.record_list(Duration::from_micros(300));
        metrics.record_error(SigningKeyErrorKind::NotFound);

        // Should not panic
        metrics.log_metrics();
    }

    #[test]
    fn test_avg_create_latency() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_create(Duration::from_micros(100));
        metrics.record_create(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert!((snapshot.avg_create_latency_us() - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_avg_list_latency() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_list(Duration::from_micros(100));
        metrics.record_list(Duration::from_micros(200));
        metrics.record_list(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert!((snapshot.avg_list_latency_us() - 200.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_deserialization_errors_accessor() {
        let metrics = SigningKeyMetrics::new();

        // No errors initially
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.deserialization_errors(), 0);

        // Record serialization errors (which covers deserialization)
        metrics.record_error(SigningKeyErrorKind::Serialization);
        metrics.record_error(SigningKeyErrorKind::Serialization);
        metrics.record_error(SigningKeyErrorKind::NotFound); // Different kind

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.deserialization_errors(), 2, "only serialization errors should count");
        assert_eq!(snapshot.error_serialization, 2);
    }

    // ── Percentile tests ──────────────────────────────────────────────

    #[test]
    fn test_snapshot_includes_percentiles() {
        let metrics = SigningKeyMetrics::new();

        for v in 1..=100 {
            metrics.record_get(Duration::from_micros(v));
        }

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 100);
        assert_eq!(snapshot.get_percentiles.p50, 50);
        assert_eq!(snapshot.get_percentiles.p95, 95);
        assert_eq!(snapshot.get_percentiles.p99, 99);
    }

    #[test]
    fn test_snapshot_percentiles_all_operation_types() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_create(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(200));
        metrics.record_list(Duration::from_micros(300));
        metrics.record_deactivate(Duration::from_micros(400));
        metrics.record_revoke(Duration::from_micros(500));
        metrics.record_activate(Duration::from_micros(600));
        metrics.record_delete(Duration::from_micros(700));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.create_percentiles.p50, 100);
        assert_eq!(snapshot.get_percentiles.p50, 200);
        assert_eq!(snapshot.list_percentiles.p50, 300);
        assert_eq!(snapshot.deactivate_percentiles.p50, 400);
        assert_eq!(snapshot.revoke_percentiles.p50, 500);
        assert_eq!(snapshot.activate_percentiles.p50, 600);
        assert_eq!(snapshot.delete_percentiles.p50, 700);
    }

    #[test]
    fn test_reset_clears_percentiles() {
        let metrics = SigningKeyMetrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.create_percentiles, LatencyPercentiles::default());
    }

    #[test]
    fn test_default_snapshot_percentiles_are_zero() {
        let snapshot = SigningKeyMetricsSnapshot::default();
        assert_eq!(snapshot.get_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.create_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.list_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.deactivate_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.revoke_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.activate_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.delete_percentiles, LatencyPercentiles::default());
    }

    #[test]
    fn test_percentile_accuracy_within_1_percent() {
        let metrics = SigningKeyMetrics::new();
        for v in 1..=1000 {
            metrics.record_get(Duration::from_micros(v));
        }
        let p = metrics.snapshot().get_percentiles;
        assert!((p.p50 as i64 - 500).unsigned_abs() <= 10, "p50={}", p.p50);
        assert!((p.p95 as i64 - 950).unsigned_abs() <= 10, "p95={}", p.p95);
        assert!((p.p99 as i64 - 990).unsigned_abs() <= 10, "p99={}", p.p99);
    }
}
