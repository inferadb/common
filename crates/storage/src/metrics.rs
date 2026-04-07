//! Storage metrics collection and monitoring
//!
//! This module provides comprehensive metrics for storage backends including:
//!
//! - Operation counts (get, set, delete, range queries, transactions)
//! - Operation latencies (cumulative microseconds and p50/p95/p99 percentiles)
//! - Error and conflict rates
//!
//! # Memory Ordering Strategy
//!
//! All atomic operations use `Ordering::Relaxed`. This is intentional:
//!
//! - **Correctness**: Each counter is independent and monotonically increasing. `Relaxed`
//!   guarantees atomicity of individual operations (no torn reads/writes), which is sufficient for
//!   `fetch_add` on a single counter.
//! - **Snapshot consistency**: `snapshot()` reads multiple counters sequentially. With `Relaxed`,
//!   counters may appear slightly inconsistent relative to each other (e.g., `error_count` might
//!   reflect an increment before the corresponding `get_count` is visible). This is acceptable for
//!   telemetry — dashboards and alerting operate on time-aggregated data where sub-microsecond
//!   ordering is irrelevant.
//! - **Why not `Acquire`/`Release`?** Upgrading to `Acquire` loads and `Release` stores would add
//!   memory barrier overhead (significant on ARM/aarch64) but would **not** provide multi-counter
//!   transactional consistency. True point-in-time snapshots across 20 counters would require a
//!   mutex, which defeats the purpose of lock-free metrics on the hot path.
//! - **`reset()` uses `Relaxed`** because it is called infrequently (e.g., between reporting
//!   intervals) and approximate zeroing is acceptable — a concurrent increment racing with reset
//!   may be lost, which is fine for periodic telemetry.
//!
//! # Percentile Tracking
//!
//! Latency percentiles (p50, p95, p99) are computed from a bounded sliding window of recent
//! samples. Each operation type maintains its own `LatencyHistogram` — a set of sharded circular
//! buffers totaling 1024 latency values (in microseconds). Recording selects a shard by hashing
//! the current thread ID, reducing [`parking_lot::Mutex`] contention by ~8x under high
//! concurrency. Each lock is held only for the duration of a single push (O(1)).
//!
//! Percentiles are computed at snapshot time by merging all shards and sorting. This keeps the
//! recording hot path fast (sub-microsecond) while deferring the O(n log n) sort to the
//! infrequent snapshot path.
//!
//! # Usage
//!
//! ```no_run
//! use std::time::Duration;
//! use inferadb_common_storage::metrics::Metrics;
//!
//! let metrics = Metrics::new();
//!
//! // Record operations
//! metrics.record_get(Duration::from_micros(100));
//! metrics.record_set(Duration::from_micros(200));
//!
//! // Get a snapshot with percentiles
//! let snapshot = metrics.snapshot();
//! assert_eq!(snapshot.get_count, 1);
//! assert_eq!(snapshot.avg_get_latency_us(), 100.0);
//! assert_eq!(snapshot.get_percentiles.p50, 100);
//! ```

use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use parking_lot::Mutex;
use tracing::warn;

/// Default number of latency samples retained per operation type.
const DEFAULT_HISTOGRAM_WINDOW_SIZE: usize = 1024;

/// Number of shards in `LatencyHistogram` to reduce lock contention on the recording hot path.
const NUM_HISTOGRAM_SHARDS: usize = 8;

// ── LatencyPercentiles ──────────────────────────────────────────────────

/// Latency percentiles for a single operation type, in microseconds.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LatencyPercentiles {
    /// 50th percentile (median) latency in microseconds.
    pub p50: u64,
    /// 95th percentile latency in microseconds.
    pub p95: u64,
    /// 99th percentile latency in microseconds.
    pub p99: u64,
}

// ── Organization Metrics ───────────────────────────────────────────────────

/// Default maximum number of tracked organizations before overflow goes to the `"_other"` bucket.
///
/// 100 is chosen to cover typical multi-tenant deployments without excessive memory overhead
/// (each organization adds ~104 bytes of counter state).
pub const DEFAULT_MAX_TRACKED_ORGANIZATIONS: usize = 100;

/// Sentinel organization name for operations that exceed the cardinality bound.
///
/// The leading underscore prevents collisions with user-defined organizations.
const OTHER_BUCKET: &str = "_other";

/// Per-organization operation counters.
///
/// Tracks the same operation types as the global metrics but without histograms
/// to keep per-organization memory footprint low.
#[derive(Debug, Clone, Default)]
struct OrganizationCounters {
    get_count: u64,
    set_count: u64,
    cas_count: u64,
    delete_count: u64,
    get_range_count: u64,
    clear_range_count: u64,
    transaction_count: u64,
    get_latency_us: u64,
    set_latency_us: u64,
    cas_latency_us: u64,
    delete_latency_us: u64,
    get_range_latency_us: u64,
    clear_range_latency_us: u64,
    transaction_latency_us: u64,
    error_count: u64,
}

// Note: OrganizationCounters is a pure data holder — snapshot() converts
// it to OrganizationOperationSnapshot which provides the public API.

/// Per-organization metrics snapshot, suitable for serialization and dashboard display.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OrganizationOperationSnapshot {
    /// The organization identifier.
    pub organization: String,
    /// Total GET operations for this organization.
    pub get_count: u64,
    /// Total SET operations for this organization.
    pub set_count: u64,
    /// Total CAS (compare-and-set) operations for this organization.
    pub cas_count: u64,
    /// Total DELETE operations for this organization.
    pub delete_count: u64,
    /// Total GET_RANGE operations for this organization.
    pub get_range_count: u64,
    /// Total CLEAR_RANGE operations for this organization.
    pub clear_range_count: u64,
    /// Total TRANSACTION operations for this organization.
    pub transaction_count: u64,
    /// Total GET latency in microseconds for this organization.
    pub get_latency_us: u64,
    /// Total SET latency in microseconds for this organization.
    pub set_latency_us: u64,
    /// Total CAS latency in microseconds for this organization.
    pub cas_latency_us: u64,
    /// Total DELETE latency in microseconds for this organization.
    pub delete_latency_us: u64,
    /// Total GET_RANGE latency in microseconds for this organization.
    pub get_range_latency_us: u64,
    /// Total CLEAR_RANGE latency in microseconds for this organization.
    pub clear_range_latency_us: u64,
    /// Total TRANSACTION latency in microseconds for this organization.
    pub transaction_latency_us: u64,
    /// Total errors for this organization.
    pub error_count: u64,
}

impl OrganizationOperationSnapshot {
    /// Returns the total operations across all types for this organization.
    #[must_use = "returns a computed total without side effects"]
    pub fn total_operations(&self) -> u64 {
        self.get_count
            + self.set_count
            + self.cas_count
            + self.delete_count
            + self.get_range_count
            + self.clear_range_count
            + self.transaction_count
    }

    /// Returns the error rate for this organization (errors / total operations).
    #[must_use = "returns a computed rate without side effects"]
    pub fn error_rate(&self) -> f64 {
        let total = self.total_operations();
        if total == 0 {
            return 0.0;
        }
        self.error_count as f64 / total as f64
    }
}

/// Bounded-cardinality tracker for per-organization metrics.
///
/// Tracks up to `max_organizations` distinct organizations. Operations for organizations
/// beyond the limit are aggregated into the `"_other"` overflow bucket.
struct OrganizationTracker {
    counters: HashMap<String, OrganizationCounters>,
    max_organizations: usize,
}

impl OrganizationTracker {
    fn new(max_organizations: usize) -> Self {
        Self { counters: HashMap::new(), max_organizations }
    }

    /// Returns counters for the given organization, creating them if needed, respecting the
    /// cardinality bound.
    fn get_or_insert(&mut self, organization: &str) -> &mut OrganizationCounters {
        // Determine the effective key: the organization itself if within cardinality
        // limit, or the overflow bucket otherwise.
        let effective_key = if self.counters.contains_key(organization) {
            organization.to_owned()
        } else {
            let tracked = self.counters.keys().filter(|k| k.as_str() != OTHER_BUCKET).count();
            if tracked < self.max_organizations {
                organization.to_owned()
            } else {
                OTHER_BUCKET.to_owned()
            }
        };
        self.counters.entry(effective_key).or_default()
    }

    fn snapshot(&self) -> Vec<OrganizationOperationSnapshot> {
        let mut entries: Vec<OrganizationOperationSnapshot> = self
            .counters
            .iter()
            .map(|(ns, c)| OrganizationOperationSnapshot {
                organization: ns.clone(),
                get_count: c.get_count,
                set_count: c.set_count,
                cas_count: c.cas_count,
                delete_count: c.delete_count,
                get_range_count: c.get_range_count,
                clear_range_count: c.clear_range_count,
                transaction_count: c.transaction_count,
                get_latency_us: c.get_latency_us,
                set_latency_us: c.set_latency_us,
                cas_latency_us: c.cas_latency_us,
                delete_latency_us: c.delete_latency_us,
                get_range_latency_us: c.get_range_latency_us,
                clear_range_latency_us: c.clear_range_latency_us,
                transaction_latency_us: c.transaction_latency_us,
                error_count: c.error_count,
            })
            .collect();
        // Sort by total operations descending for dashboard-friendly output
        entries.sort_by_key(|e| std::cmp::Reverse(e.total_operations()));
        entries
    }

    fn reset(&mut self) {
        self.counters.clear();
    }
}

// ── LatencyHistogram ────────────────────────────────────────────────────

/// A sharded circular buffer of latency samples for streaming percentile computation.
///
/// Records the most recent `capacity` latency values (in microseconds) across
/// [`NUM_HISTOGRAM_SHARDS`] independent shards. Each shard holds `capacity / NUM_HISTOGRAM_SHARDS`
/// samples (rounded up, minimum 1). Recording selects a shard by hashing the current thread ID,
/// reducing mutex contention by ~8x under high concurrency. Percentiles are computed on demand
/// by merging all shards, sorting, and applying the nearest-rank method.
pub(crate) struct LatencyHistogram {
    shards: Vec<Mutex<HistogramInner>>,
}

struct HistogramInner {
    /// Circular buffer of latency samples.
    buf: Vec<u64>,
    /// Next write position in the circular buffer.
    pos: usize,
    /// Maximum number of samples to retain.
    capacity: usize,
}

/// Returns a shard index for the current thread, cached in thread-local storage.
fn thread_shard_index() -> usize {
    thread_local! {
        static SHARD: usize = {
            use std::hash::{Hash, Hasher};
            let mut hasher = std::collections::hash_map::DefaultHasher::new();
            std::thread::current().id().hash(&mut hasher);
            hasher.finish() as usize % NUM_HISTOGRAM_SHARDS
        };
    }
    SHARD.with(|s| *s)
}

impl LatencyHistogram {
    /// Creates a new histogram with the given total window size, distributed across shards.
    pub(crate) fn new(capacity: usize) -> Self {
        let per_shard = (capacity / NUM_HISTOGRAM_SHARDS).max(1);
        let shards = (0..NUM_HISTOGRAM_SHARDS)
            .map(|_| {
                Mutex::new(HistogramInner {
                    buf: Vec::with_capacity(per_shard),
                    pos: 0,
                    capacity: per_shard,
                })
            })
            .collect();
        Self { shards }
    }

    /// Records a latency sample in microseconds.
    ///
    /// Selects a shard based on the calling thread's ID to minimize contention.
    pub(crate) fn record(&self, value_us: u64) {
        let shard_idx = thread_shard_index();
        let mut inner = self.shards[shard_idx].lock();
        let pos = inner.pos;
        if inner.buf.len() < inner.capacity {
            inner.buf.push(value_us);
        } else {
            inner.buf[pos] = value_us;
        }
        inner.pos = (pos + 1) % inner.capacity;
    }

    /// Computes p50, p95, p99 percentiles from the current buffer contents.
    ///
    /// Merges samples from all shards, then sorts and computes percentiles.
    /// Returns `LatencyPercentiles::default()` (all zeros) if no samples have been recorded.
    pub(crate) fn percentiles(&self) -> LatencyPercentiles {
        let mut all_samples = Vec::new();
        for shard in &self.shards {
            let inner = shard.lock();
            all_samples.extend_from_slice(&inner.buf);
        }
        if all_samples.is_empty() {
            return LatencyPercentiles::default();
        }
        all_samples.sort_unstable();
        let len = all_samples.len();
        LatencyPercentiles {
            p50: all_samples[percentile_index(len, 50)],
            p95: all_samples[percentile_index(len, 95)],
            p99: all_samples[percentile_index(len, 99)],
        }
    }

    /// Resets the histogram, discarding all samples from all shards.
    pub(crate) fn reset(&self) {
        for shard in &self.shards {
            let mut inner = shard.lock();
            inner.buf.clear();
            inner.pos = 0;
        }
    }
}

/// Computes the index for a given percentile in a sorted array of `len` elements.
///
/// Uses nearest-rank method: `index = ceil(percentile/100 * len) - 1`, clamped to valid range.
fn percentile_index(len: usize, percentile: u32) -> usize {
    if len == 0 {
        return 0;
    }
    let rank = (u64::from(percentile) * len as u64).div_ceil(100) as usize;
    rank.saturating_sub(1).min(len - 1)
}

// ── MetricsSnapshot ─────────────────────────────────────────────────────

/// Point-in-time snapshot of all storage metrics for export and inspection.
#[derive(Debug, Clone, Default, bon::Builder)]
pub struct MetricsSnapshot {
    /// Total GET operations.
    #[builder(default)]
    pub get_count: u64,
    /// Total SET operations.
    #[builder(default)]
    pub set_count: u64,
    /// Total DELETE operations.
    #[builder(default)]
    pub delete_count: u64,
    /// Total GET_RANGE operations.
    #[builder(default)]
    pub get_range_count: u64,
    /// Total CLEAR_RANGE operations.
    #[builder(default)]
    pub clear_range_count: u64,
    /// Total TRANSACTION operations.
    #[builder(default)]
    pub transaction_count: u64,
    /// Total CAS (compare-and-set) operations.
    #[builder(default)]
    pub cas_count: u64,

    /// Total GET latency in microseconds.
    #[builder(default)]
    pub get_latency_us: u64,
    /// Total SET latency in microseconds.
    #[builder(default)]
    pub set_latency_us: u64,
    /// Total DELETE latency in microseconds.
    #[builder(default)]
    pub delete_latency_us: u64,
    /// Total GET_RANGE latency in microseconds.
    #[builder(default)]
    pub get_range_latency_us: u64,
    /// Total CLEAR_RANGE latency in microseconds.
    #[builder(default)]
    pub clear_range_latency_us: u64,
    /// Total TRANSACTION latency in microseconds.
    #[builder(default)]
    pub transaction_latency_us: u64,
    /// Total CAS latency in microseconds.
    #[builder(default)]
    pub cas_latency_us: u64,

    /// GET latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub get_percentiles: LatencyPercentiles,
    /// SET latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub set_percentiles: LatencyPercentiles,
    /// DELETE latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub delete_percentiles: LatencyPercentiles,
    /// GET_RANGE latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub get_range_percentiles: LatencyPercentiles,
    /// CLEAR_RANGE latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub clear_range_percentiles: LatencyPercentiles,
    /// TRANSACTION latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub transaction_percentiles: LatencyPercentiles,
    /// CAS latency percentiles (p50/p95/p99) in microseconds.
    #[builder(default)]
    pub cas_percentiles: LatencyPercentiles,

    /// Total errors.
    #[builder(default)]
    pub error_count: u64,
    /// Transaction and CAS conflicts.
    #[builder(default)]
    pub conflict_count: u64,

    /// TTL operations count.
    #[builder(default)]
    pub ttl_operations: u64,
    /// Health check count.
    #[builder(default)]
    pub health_check_count: u64,

    /// Per-organization metrics breakdowns for the top-N most active organizations.
    ///
    /// Sorted by total operations descending. Organizations beyond the configured
    /// cardinality limit are aggregated into the `"_other"` bucket.
    #[builder(default)]
    pub organization_metrics: Vec<OrganizationOperationSnapshot>,
}

impl MetricsSnapshot {
    /// Returns the average GET latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_get_latency_us(&self) -> f64 {
        if self.get_count == 0 { 0.0 } else { self.get_latency_us as f64 / self.get_count as f64 }
    }

    /// Returns the average SET latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_set_latency_us(&self) -> f64 {
        if self.set_count == 0 { 0.0 } else { self.set_latency_us as f64 / self.set_count as f64 }
    }

    /// Returns the average DELETE latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_delete_latency_us(&self) -> f64 {
        if self.delete_count == 0 {
            0.0
        } else {
            self.delete_latency_us as f64 / self.delete_count as f64
        }
    }

    /// Returns the average GET_RANGE latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_get_range_latency_us(&self) -> f64 {
        if self.get_range_count == 0 {
            0.0
        } else {
            self.get_range_latency_us as f64 / self.get_range_count as f64
        }
    }

    /// Returns the average CLEAR_RANGE latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_clear_range_latency_us(&self) -> f64 {
        if self.clear_range_count == 0 {
            0.0
        } else {
            self.clear_range_latency_us as f64 / self.clear_range_count as f64
        }
    }

    /// Returns the average TRANSACTION latency in microseconds.
    #[must_use = "returns a computed average without side effects"]
    pub fn avg_transaction_latency_us(&self) -> f64 {
        if self.transaction_count == 0 {
            0.0
        } else {
            self.transaction_latency_us as f64 / self.transaction_count as f64
        }
    }

    /// Returns the error rate (0.0 - 1.0).
    #[must_use = "returns a computed rate without side effects"]
    pub fn error_rate(&self) -> f64 {
        let total_ops = self.total_operations();
        if total_ops == 0 { 0.0 } else { self.error_count as f64 / total_ops as f64 }
    }

    /// Returns the conflict rate (0.0 - 1.0).
    #[must_use = "returns a computed rate without side effects"]
    pub fn conflict_rate(&self) -> f64 {
        let denominator = self.cas_count + self.transaction_count;
        if denominator == 0 { 0.0 } else { self.conflict_count as f64 / denominator as f64 }
    }

    /// Returns the total operation count.
    #[must_use = "returns a computed total without side effects"]
    pub fn total_operations(&self) -> u64 {
        self.get_count
            + self.set_count
            + self.delete_count
            + self.get_range_count
            + self.clear_range_count
            + self.transaction_count
            + self.cas_count
    }
}

// ── Metrics / MetricsInner ──────────────────────────────────────────────

/// Collects operation counts, latencies, error rates, and cache statistics for a storage backend.
#[derive(Clone)]
pub struct Metrics {
    inner: Arc<MetricsInner>,
}

// All fields use `Ordering::Relaxed` — see module-level docs for rationale.
struct MetricsInner {
    // Operation counts
    get_count: AtomicU64,
    set_count: AtomicU64,
    delete_count: AtomicU64,
    get_range_count: AtomicU64,
    clear_range_count: AtomicU64,
    transaction_count: AtomicU64,
    cas_count: AtomicU64,

    // Latencies (cumulative microseconds)
    get_latency_us: AtomicU64,
    set_latency_us: AtomicU64,
    delete_latency_us: AtomicU64,
    get_range_latency_us: AtomicU64,
    clear_range_latency_us: AtomicU64,
    transaction_latency_us: AtomicU64,
    cas_latency_us: AtomicU64,

    // Latency histograms for percentile computation
    get_histogram: LatencyHistogram,
    set_histogram: LatencyHistogram,
    delete_histogram: LatencyHistogram,
    get_range_histogram: LatencyHistogram,
    clear_range_histogram: LatencyHistogram,
    transaction_histogram: LatencyHistogram,
    cas_histogram: LatencyHistogram,

    // Errors
    error_count: AtomicU64,
    conflict_count: AtomicU64,

    // Other
    ttl_operations: AtomicU64,
    health_check_count: AtomicU64,

    // Organization-level tracking
    organization_tracker: Mutex<OrganizationTracker>,
}

impl Metrics {
    /// Creates a new metrics collector.
    #[must_use = "constructing a metrics collector has no side effects"]
    pub fn new() -> Self {
        Self { inner: Self::new_inner(DEFAULT_MAX_TRACKED_ORGANIZATIONS) }
    }

    /// Creates a new metrics collector with a custom organization cardinality limit.
    ///
    /// `max_tracked_organizations` controls how many distinct organizations are tracked
    /// individually. Operations for organizations beyond this limit are aggregated
    /// into the `"_other"` overflow bucket.
    #[must_use = "constructing a metrics collector has no side effects"]
    pub fn with_max_organizations(max_tracked_organizations: usize) -> Self {
        Self { inner: Self::new_inner(max_tracked_organizations) }
    }

    fn new_inner(max_organizations: usize) -> Arc<MetricsInner> {
        Arc::new(MetricsInner {
            get_count: AtomicU64::new(0),
            set_count: AtomicU64::new(0),
            delete_count: AtomicU64::new(0),
            get_range_count: AtomicU64::new(0),
            clear_range_count: AtomicU64::new(0),
            transaction_count: AtomicU64::new(0),
            cas_count: AtomicU64::new(0),
            get_latency_us: AtomicU64::new(0),
            set_latency_us: AtomicU64::new(0),
            delete_latency_us: AtomicU64::new(0),
            get_range_latency_us: AtomicU64::new(0),
            clear_range_latency_us: AtomicU64::new(0),
            transaction_latency_us: AtomicU64::new(0),
            cas_latency_us: AtomicU64::new(0),
            get_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            set_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            delete_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            get_range_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            clear_range_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            transaction_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            cas_histogram: LatencyHistogram::new(DEFAULT_HISTOGRAM_WINDOW_SIZE),
            error_count: AtomicU64::new(0),
            conflict_count: AtomicU64::new(0),
            ttl_operations: AtomicU64::new(0),
            health_check_count: AtomicU64::new(0),
            organization_tracker: Mutex::new(OrganizationTracker::new(max_organizations)),
        })
    }

    /// Records a GET operation.
    pub fn record_get(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.get_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.get_histogram.record(us);
    }

    /// Records a SET operation.
    pub fn record_set(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.set_count.fetch_add(1, Ordering::Relaxed);
        self.inner.set_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.set_histogram.record(us);
    }

    /// Records a DELETE operation.
    pub fn record_delete(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.delete_count.fetch_add(1, Ordering::Relaxed);
        self.inner.delete_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.delete_histogram.record(us);
    }

    /// Records a GET_RANGE operation.
    pub fn record_get_range(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.get_range_count.fetch_add(1, Ordering::Relaxed);
        self.inner.get_range_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.get_range_histogram.record(us);
    }

    /// Records a CLEAR_RANGE operation.
    pub fn record_clear_range(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.clear_range_count.fetch_add(1, Ordering::Relaxed);
        self.inner.clear_range_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.clear_range_histogram.record(us);
    }

    /// Records a TRANSACTION operation.
    pub fn record_transaction(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.transaction_count.fetch_add(1, Ordering::Relaxed);
        self.inner.transaction_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.transaction_histogram.record(us);
    }

    /// Records a CAS (compare-and-set) operation.
    pub fn record_cas(&self, duration: Duration) {
        let us = duration.as_micros() as u64;
        self.inner.cas_count.fetch_add(1, Ordering::Relaxed);
        self.inner.cas_latency_us.fetch_add(us, Ordering::Relaxed);
        self.inner.cas_histogram.record(us);
    }

    /// Records a general error.
    pub fn record_error(&self) {
        self.inner.error_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a transaction conflict.
    pub fn record_conflict(&self) {
        self.inner.conflict_count.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a TTL operation.
    pub fn record_ttl_operation(&self) {
        self.inner.ttl_operations.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a health check.
    pub fn record_health_check(&self) {
        self.inner.health_check_count.fetch_add(1, Ordering::Relaxed);
    }

    // ── Organization-aware recording methods ───────────────────────────────
    //
    // These methods record both the global metric AND the per-organization
    // breakdown. Pass `organization` to attribute the operation to a specific
    // tenant/organization for multi-tenant observability.

    /// Records a GET operation attributed to an organization.
    pub fn record_get_org(&self, duration: Duration, organization: &str) {
        self.record_get(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.get_count += 1;
        c.get_latency_us += us;
    }

    /// Records a SET operation attributed to an organization.
    pub fn record_set_org(&self, duration: Duration, organization: &str) {
        self.record_set(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.set_count += 1;
        c.set_latency_us += us;
    }

    /// Records a CAS (compare-and-set) operation attributed to an organization.
    pub fn record_cas_org(&self, duration: Duration, organization: &str) {
        self.record_cas(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.cas_count += 1;
        c.cas_latency_us += us;
    }

    /// Records a DELETE operation attributed to an organization.
    pub fn record_delete_org(&self, duration: Duration, organization: &str) {
        self.record_delete(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.delete_count += 1;
        c.delete_latency_us += us;
    }

    /// Records a GET_RANGE operation attributed to an organization.
    pub fn record_get_range_org(&self, duration: Duration, organization: &str) {
        self.record_get_range(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.get_range_count += 1;
        c.get_range_latency_us += us;
    }

    /// Records a CLEAR_RANGE operation attributed to an organization.
    pub fn record_clear_range_org(&self, duration: Duration, organization: &str) {
        self.record_clear_range(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.clear_range_count += 1;
        c.clear_range_latency_us += us;
    }

    /// Records a TRANSACTION operation attributed to an organization.
    pub fn record_transaction_org(&self, duration: Duration, organization: &str) {
        self.record_transaction(duration);
        let us = duration.as_micros() as u64;
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.transaction_count += 1;
        c.transaction_latency_us += us;
    }

    /// Records an error attributed to an organization.
    pub fn record_error_org(&self, organization: &str) {
        self.record_error();
        let mut tracker = self.inner.organization_tracker.lock();
        let c = tracker.get_or_insert(organization);
        c.error_count += 1;
    }

    /// Returns a snapshot of current metrics.
    ///
    /// Reads all counters using `Relaxed` ordering. The snapshot is approximately
    /// consistent — individual counter values are accurate, but counters may
    /// reflect different points in time relative to each other. See the module-level
    /// documentation for the full ordering rationale.
    ///
    /// Percentiles are computed from the sliding window of recent latency samples
    /// for each operation type.
    #[must_use = "returns a point-in-time snapshot without side effects"]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            get_count: self.inner.get_count.load(Ordering::Relaxed),
            set_count: self.inner.set_count.load(Ordering::Relaxed),
            delete_count: self.inner.delete_count.load(Ordering::Relaxed),
            get_range_count: self.inner.get_range_count.load(Ordering::Relaxed),
            clear_range_count: self.inner.clear_range_count.load(Ordering::Relaxed),
            transaction_count: self.inner.transaction_count.load(Ordering::Relaxed),
            cas_count: self.inner.cas_count.load(Ordering::Relaxed),
            get_latency_us: self.inner.get_latency_us.load(Ordering::Relaxed),
            set_latency_us: self.inner.set_latency_us.load(Ordering::Relaxed),
            delete_latency_us: self.inner.delete_latency_us.load(Ordering::Relaxed),
            get_range_latency_us: self.inner.get_range_latency_us.load(Ordering::Relaxed),
            clear_range_latency_us: self.inner.clear_range_latency_us.load(Ordering::Relaxed),
            transaction_latency_us: self.inner.transaction_latency_us.load(Ordering::Relaxed),
            cas_latency_us: self.inner.cas_latency_us.load(Ordering::Relaxed),
            get_percentiles: self.inner.get_histogram.percentiles(),
            set_percentiles: self.inner.set_histogram.percentiles(),
            delete_percentiles: self.inner.delete_histogram.percentiles(),
            get_range_percentiles: self.inner.get_range_histogram.percentiles(),
            clear_range_percentiles: self.inner.clear_range_histogram.percentiles(),
            transaction_percentiles: self.inner.transaction_histogram.percentiles(),
            cas_percentiles: self.inner.cas_histogram.percentiles(),
            error_count: self.inner.error_count.load(Ordering::Relaxed),
            conflict_count: self.inner.conflict_count.load(Ordering::Relaxed),
            ttl_operations: self.inner.ttl_operations.load(Ordering::Relaxed),
            health_check_count: self.inner.health_check_count.load(Ordering::Relaxed),
            organization_metrics: self.inner.organization_tracker.lock().snapshot(),
        }
    }

    /// Resets all metrics to zero.
    pub fn reset(&self) {
        self.inner.get_count.store(0, Ordering::Relaxed);
        self.inner.set_count.store(0, Ordering::Relaxed);
        self.inner.delete_count.store(0, Ordering::Relaxed);
        self.inner.get_range_count.store(0, Ordering::Relaxed);
        self.inner.clear_range_count.store(0, Ordering::Relaxed);
        self.inner.transaction_count.store(0, Ordering::Relaxed);
        self.inner.cas_count.store(0, Ordering::Relaxed);
        self.inner.get_latency_us.store(0, Ordering::Relaxed);
        self.inner.set_latency_us.store(0, Ordering::Relaxed);
        self.inner.delete_latency_us.store(0, Ordering::Relaxed);
        self.inner.get_range_latency_us.store(0, Ordering::Relaxed);
        self.inner.clear_range_latency_us.store(0, Ordering::Relaxed);
        self.inner.transaction_latency_us.store(0, Ordering::Relaxed);
        self.inner.cas_latency_us.store(0, Ordering::Relaxed);
        self.inner.get_histogram.reset();
        self.inner.set_histogram.reset();
        self.inner.delete_histogram.reset();
        self.inner.get_range_histogram.reset();
        self.inner.clear_range_histogram.reset();
        self.inner.transaction_histogram.reset();
        self.inner.cas_histogram.reset();
        self.inner.error_count.store(0, Ordering::Relaxed);
        self.inner.conflict_count.store(0, Ordering::Relaxed);
        self.inner.ttl_operations.store(0, Ordering::Relaxed);
        self.inner.health_check_count.store(0, Ordering::Relaxed);
        self.inner.organization_tracker.lock().reset();
    }

    /// Logs current metrics at INFO level, with WARN-level alerts when the
    /// error rate exceeds 5% or the conflict rate exceeds 10%.
    pub fn log_metrics(&self) {
        let snapshot = self.snapshot();

        if snapshot.total_operations() == 0 {
            return;
        }

        tracing::info!(
            get_count = snapshot.get_count,
            set_count = snapshot.set_count,
            delete_count = snapshot.delete_count,
            get_range_count = snapshot.get_range_count,
            clear_range_count = snapshot.clear_range_count,
            transaction_count = snapshot.transaction_count,
            avg_get_latency_us = snapshot.avg_get_latency_us(),
            avg_set_latency_us = snapshot.avg_set_latency_us(),
            avg_delete_latency_us = snapshot.avg_delete_latency_us(),
            avg_clear_range_latency_us = snapshot.avg_clear_range_latency_us(),
            avg_transaction_latency_us = snapshot.avg_transaction_latency_us(),
            get_p50 = snapshot.get_percentiles.p50,
            get_p95 = snapshot.get_percentiles.p95,
            get_p99 = snapshot.get_percentiles.p99,
            set_p99 = snapshot.set_percentiles.p99,
            error_count = snapshot.error_count,
            error_rate = snapshot.error_rate(),
            conflict_count = snapshot.conflict_count,
            conflict_rate = snapshot.conflict_rate(),
            "Storage metrics snapshot"
        );

        // Warn if error rate is high
        if snapshot.error_rate() > 0.05 {
            warn!(
                error_rate = snapshot.error_rate(),
                error_count = snapshot.error_count,
                total_ops = snapshot.total_operations(),
                "High storage error rate detected"
            );
        }

        // Warn if conflict rate is high
        if snapshot.conflict_rate() > 0.10 {
            warn!(
                conflict_rate = snapshot.conflict_rate(),
                conflict_count = snapshot.conflict_count,
                transaction_count = snapshot.transaction_count,
                "High transaction/CAS conflict rate detected"
            );
        }

        // Log per-organization breakdown (top 5 by total operations)
        for entry in snapshot.organization_metrics.iter().take(5) {
            tracing::info!(
                organization = %entry.organization,
                total_ops = entry.total_operations(),
                get_count = entry.get_count,
                set_count = entry.set_count,
                error_count = entry.error_count,
                error_rate = entry.error_rate(),
                "Organization metrics"
            );
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        Self::new()
    }
}

/// Exposes the [`Metrics`] instance for a storage backend.
pub trait MetricsCollector {
    /// Returns a reference to the backend's metrics collector.
    fn metrics(&self) -> &Metrics;
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    // ── LatencyHistogram unit tests ─────────────────────────────────────

    #[test]
    fn test_histogram_empty_percentiles() {
        let h = LatencyHistogram::new(16);
        let p = h.percentiles();
        assert_eq!(p, LatencyPercentiles::default());
    }

    #[test]
    fn test_histogram_single_sample() {
        let h = LatencyHistogram::new(16);
        h.record(42);
        let p = h.percentiles();
        assert_eq!(p.p50, 42);
        assert_eq!(p.p95, 42);
        assert_eq!(p.p99, 42);
    }

    #[test]
    fn test_histogram_known_distribution() {
        let h = LatencyHistogram::new(1024);
        // Record values 1..=100
        for v in 1..=100 {
            h.record(v);
        }
        let p = h.percentiles();
        assert_eq!(p.p50, 50);
        assert_eq!(p.p95, 95);
        assert_eq!(p.p99, 99);
    }

    #[test]
    fn test_histogram_circular_eviction() {
        // Use capacity 80 so each of the 8 shards gets 10 slots.
        // Single-threaded: all records land in one shard (capacity 10).
        let h = LatencyHistogram::new(80);
        // Write 20 values — only the last 10 should remain in the shard
        for v in 1..=20 {
            h.record(v);
        }
        let p = h.percentiles();
        // Buffer contains [11..=20], so p50 ≈ 15, p99 = 20
        assert_eq!(p.p50, 15);
        assert_eq!(p.p99, 20);
    }

    #[test]
    fn test_histogram_reset() {
        let h = LatencyHistogram::new(16);
        h.record(100);
        h.record(200);
        h.reset();
        let p = h.percentiles();
        assert_eq!(p, LatencyPercentiles::default());
    }

    #[test]
    fn test_percentile_accuracy_within_1_percent() {
        // Use capacity 8000 so each shard holds 1000 — enough for all samples on one thread.
        let h = LatencyHistogram::new(8000);
        for v in 1..=1000 {
            h.record(v);
        }
        let p = h.percentiles();
        // For a uniform distribution 1..=1000:
        //   Exact p50 = 500, p95 = 950, p99 = 990
        // Allow 1% error (10 for p50/p95, 10 for p99)
        assert!((p.p50 as i64 - 500).unsigned_abs() <= 10, "p50={}", p.p50);
        assert!((p.p95 as i64 - 950).unsigned_abs() <= 10, "p95={}", p.p95);
        assert!((p.p99 as i64 - 990).unsigned_abs() <= 10, "p99={}", p.p99);
    }

    #[test]
    fn test_histogram_sharding_reduces_contention() {
        use std::sync::Arc;

        // Each shard holds 1000 samples. 4 threads x 1000 = 4000 total.
        // Even if all threads hash to the same shard, 1000 samples survive.
        let h = Arc::new(LatencyHistogram::new(NUM_HISTOGRAM_SHARDS * 1000));
        let mut handles = Vec::new();
        for t in 0..4 {
            let h = Arc::clone(&h);
            handles.push(std::thread::spawn(move || {
                let base = u64::try_from(t * 1000).expect("thread index fits u64");
                for i in 1..=1000 {
                    h.record(base + i);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("thread panicked");
        }

        let p = h.percentiles();
        // Samples span 1..=4000 but shard collisions may evict some.
        // Verify non-trivial data was collected and percentiles are ordered.
        assert!(p.p50 > 0, "p50 should be non-zero");
        assert!(p.p95 >= p.p50, "p95 should be >= p50");
        assert!(p.p99 >= p.p95, "p99 should be >= p95");
        // p99 must come from the upper range of recorded values
        assert!(p.p99 >= 1000, "p99={} should be >= 1000", p.p99);
    }

    // ── Percentile index ────────────────────────────────────────────────

    #[test]
    fn test_percentile_index_edge_cases() {
        assert_eq!(percentile_index(0, 50), 0);
        assert_eq!(percentile_index(1, 50), 0);
        assert_eq!(percentile_index(1, 99), 0);
        assert_eq!(percentile_index(100, 50), 49);
        assert_eq!(percentile_index(100, 95), 94);
        assert_eq!(percentile_index(100, 99), 98);
    }

    // ── MetricsSnapshot percentile integration ──────────────────────────

    #[test]
    fn test_snapshot_includes_percentiles() {
        let metrics = Metrics::new();

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
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_delete(Duration::from_micros(300));
        metrics.record_get_range(Duration::from_micros(400));
        metrics.record_clear_range(Duration::from_micros(500));
        metrics.record_transaction(Duration::from_micros(600));
        metrics.record_cas(Duration::from_micros(700));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_percentiles.p50, 100);
        assert_eq!(snapshot.set_percentiles.p50, 200);
        assert_eq!(snapshot.delete_percentiles.p50, 300);
        assert_eq!(snapshot.get_range_percentiles.p50, 400);
        assert_eq!(snapshot.clear_range_percentiles.p50, 500);
        assert_eq!(snapshot.transaction_percentiles.p50, 600);
        assert_eq!(snapshot.cas_percentiles.p50, 700);
    }

    #[test]
    fn test_reset_clears_percentiles() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_percentiles, LatencyPercentiles::default());
    }

    #[test]
    fn test_default_snapshot_percentiles_are_zero() {
        let snapshot = MetricsSnapshot::default();
        assert_eq!(snapshot.get_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.set_percentiles, LatencyPercentiles::default());
        assert_eq!(snapshot.delete_percentiles, LatencyPercentiles::default());
    }

    // ── Existing tests (unchanged) ──────────────────────────────────────

    #[test]
    fn test_metrics_recording() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_delete(Duration::from_micros(150));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 1);
        assert_eq!(snapshot.set_count, 1);
        assert_eq!(snapshot.delete_count, 1);
        assert_eq!(snapshot.get_latency_us, 100);
        assert_eq!(snapshot.set_latency_us, 200);
        assert_eq!(snapshot.delete_latency_us, 150);
    }

    #[test]
    fn test_average_latency() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(200));
        metrics.record_get(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 3);
        assert_eq!(snapshot.avg_get_latency_us(), 200.0);
    }

    #[test]
    fn test_error_rate() {
        let metrics = Metrics::new();

        // Record 4 operations total
        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(100));
        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(100));
        // Record 1 error
        metrics.record_error();

        // Error rate = errors / total_ops = 1/4 = 0.25
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.error_rate(), 0.25);
    }

    #[test]
    fn test_conflict_rate_transaction_only() {
        let metrics = Metrics::new();

        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_conflict();

        // denominator = cas_count(0) + transaction_count(4) = 4
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conflict_rate(), 0.25);
    }

    #[test]
    fn test_conflict_rate_cas_and_transaction() {
        let metrics = Metrics::new();

        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_cas(Duration::from_micros(500));
        metrics.record_cas(Duration::from_micros(500));
        metrics.record_conflict();

        // denominator = cas_count(2) + transaction_count(2) = 4
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.conflict_rate(), 0.25);
    }

    #[test]
    fn test_record_cas() {
        let metrics = Metrics::new();

        metrics.record_cas(Duration::from_micros(300));
        metrics.record_cas(Duration::from_micros(500));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.cas_count, 2);
        assert_eq!(snapshot.cas_latency_us, 800);
        // CAS operations are counted separately from SET
        assert_eq!(snapshot.set_count, 0);
    }

    #[test]
    fn test_metrics_reset() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_error();

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 0);
        assert_eq!(snapshot.set_count, 0);
        assert_eq!(snapshot.error_count, 0);
    }

    #[test]
    fn test_record_get_range() {
        let metrics = Metrics::new();

        metrics.record_get_range(Duration::from_micros(500));
        metrics.record_get_range(Duration::from_micros(300));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_range_count, 2);
        assert_eq!(snapshot.get_range_latency_us, 800);
        assert_eq!(snapshot.avg_get_range_latency_us(), 400.0);
    }

    #[test]
    fn test_record_clear_range() {
        let metrics = Metrics::new();

        metrics.record_clear_range(Duration::from_micros(600));
        metrics.record_clear_range(Duration::from_micros(400));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.clear_range_count, 2);
        assert_eq!(snapshot.clear_range_latency_us, 1000);
        // Latency no longer leaks into get_range bucket
        assert_eq!(snapshot.get_range_latency_us, 0);
    }

    #[test]
    fn test_record_transaction_latency() {
        let metrics = Metrics::new();

        metrics.record_transaction(Duration::from_micros(1000));
        metrics.record_transaction(Duration::from_micros(2000));
        metrics.record_transaction(Duration::from_micros(3000));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.transaction_count, 3);
        assert_eq!(snapshot.transaction_latency_us, 6000);
        assert_eq!(snapshot.avg_transaction_latency_us(), 2000.0);
    }

    #[test]
    fn test_record_ttl_operation() {
        let metrics = Metrics::new();

        metrics.record_ttl_operation();
        metrics.record_ttl_operation();
        metrics.record_ttl_operation();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.ttl_operations, 3);
    }

    #[test]
    fn test_record_health_check() {
        let metrics = Metrics::new();

        metrics.record_health_check();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.health_check_count, 1);
    }

    #[test]
    fn test_avg_delete_latency() {
        let metrics = Metrics::new();

        metrics.record_delete(Duration::from_micros(100));
        metrics.record_delete(Duration::from_micros(200));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.avg_delete_latency_us(), 150.0);
    }

    #[test]
    fn test_total_operations() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(100));
        metrics.record_delete(Duration::from_micros(100));
        metrics.record_get_range(Duration::from_micros(100));
        metrics.record_clear_range(Duration::from_micros(100));
        metrics.record_transaction(Duration::from_micros(100));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.total_operations(), 6);
    }

    #[test]
    fn test_zero_count_averages_return_zero() {
        let snapshot = MetricsSnapshot::default();

        assert_eq!(snapshot.avg_get_latency_us(), 0.0);
        assert_eq!(snapshot.avg_set_latency_us(), 0.0);
        assert_eq!(snapshot.avg_delete_latency_us(), 0.0);
        assert_eq!(snapshot.avg_get_range_latency_us(), 0.0);
        assert_eq!(snapshot.avg_transaction_latency_us(), 0.0);
        assert_eq!(snapshot.error_rate(), 0.0);
        assert_eq!(snapshot.conflict_rate(), 0.0);
    }

    #[test]
    fn test_log_metrics_no_ops() {
        // When there are no operations, log_metrics should return early
        let metrics = Metrics::new();
        metrics.log_metrics(); // Should not panic
    }

    #[test]
    fn test_log_metrics_with_ops() {
        let metrics = Metrics::new();

        metrics.record_get(Duration::from_micros(100));
        metrics.record_set(Duration::from_micros(200));
        metrics.record_delete(Duration::from_micros(150));
        metrics.record_transaction(Duration::from_micros(1000));

        // Should log without panic
        metrics.log_metrics();
    }

    #[test]
    fn test_log_metrics_high_error_rate() {
        let metrics = Metrics::new();

        // Create 10 operations with 2 errors = 20% error rate (above 5% threshold)
        for _ in 0..10 {
            metrics.record_get(Duration::from_micros(100));
        }
        metrics.record_error();
        metrics.record_error();

        // Should log warning for high error rate
        metrics.log_metrics();
    }

    #[test]
    fn test_log_metrics_high_conflict_rate() {
        let metrics = Metrics::new();

        // Create 5 transactions with 1 conflict = 20% conflict rate (above 10% threshold)
        for _ in 0..5 {
            metrics.record_transaction(Duration::from_micros(1000));
        }
        metrics.record_conflict();

        // Should log warning for high conflict rate
        metrics.log_metrics();
    }

    #[test]
    fn test_metrics_clone() {
        let metrics = Metrics::new();
        metrics.record_get(Duration::from_micros(100));

        let cloned = metrics.clone();
        // Both share the same inner state
        cloned.record_get(Duration::from_micros(100));

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 2);
    }

    #[test]
    fn test_metrics_default() {
        let metrics = Metrics::default();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.get_count, 0);
        assert_eq!(snapshot.total_operations(), 0);
    }

    #[test]
    fn test_metrics_snapshot_builder() {
        let snapshot = MetricsSnapshot::builder().get_count(10).set_count(5).error_count(2).build();

        assert_eq!(snapshot.get_count, 10);
        assert_eq!(snapshot.set_count, 5);
        assert_eq!(snapshot.error_count, 2);
    }

    #[test]
    fn test_avg_clear_range_latency() {
        let metrics = Metrics::new();

        metrics.record_clear_range(Duration::from_micros(300));
        metrics.record_clear_range(Duration::from_micros(500));

        let snapshot = metrics.snapshot();
        assert!((snapshot.avg_clear_range_latency_us() - 400.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_avg_clear_range_latency_zero_count() {
        let snapshot = MetricsSnapshot::default();
        assert!((snapshot.avg_clear_range_latency_us() - 0.0).abs() < f64::EPSILON);
    }

    #[test]
    fn test_clear_range_metrics_isolation() {
        let metrics = Metrics::new();

        // Record both get_range and clear_range
        metrics.record_get_range(Duration::from_micros(100));
        metrics.record_clear_range(Duration::from_micros(500));

        let snapshot = metrics.snapshot();
        // Each operation's latency is tracked independently
        assert_eq!(snapshot.get_range_latency_us, 100);
        assert_eq!(snapshot.clear_range_latency_us, 500);
        assert_eq!(snapshot.get_range_count, 1);
        assert_eq!(snapshot.clear_range_count, 1);
    }

    #[test]
    fn test_clear_range_metrics_reset() {
        let metrics = Metrics::new();

        metrics.record_clear_range(Duration::from_micros(500));

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.clear_range_count, 0);
        assert_eq!(snapshot.clear_range_latency_us, 0);
    }

    // ── Organization-level metrics tests ───────────────────────────────────

    #[test]
    fn test_organization_metrics_single_organization() {
        let metrics = Metrics::new();
        metrics.record_get_org(Duration::from_micros(100), "org-1");
        metrics.record_set_org(Duration::from_micros(200), "org-1");
        metrics.record_delete_org(Duration::from_micros(50), "org-1");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.organization_metrics.len(), 1);

        let entry = &snapshot.organization_metrics[0];
        assert_eq!(entry.organization, "org-1");
        assert_eq!(entry.get_count, 1);
        assert_eq!(entry.set_count, 1);
        assert_eq!(entry.delete_count, 1);
        assert_eq!(entry.get_latency_us, 100);
        assert_eq!(entry.set_latency_us, 200);
        assert_eq!(entry.delete_latency_us, 50);
        assert_eq!(entry.total_operations(), 3);
    }

    #[test]
    fn test_organization_metrics_multiple_organizations() {
        let metrics = Metrics::new();
        metrics.record_get_org(Duration::from_micros(100), "org-a");
        metrics.record_get_org(Duration::from_micros(100), "org-a");
        metrics.record_get_org(Duration::from_micros(100), "org-a");
        metrics.record_set_org(Duration::from_micros(200), "org-b");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.organization_metrics.len(), 2);

        // Sorted by total ops descending
        assert_eq!(snapshot.organization_metrics[0].organization, "org-a");
        assert_eq!(snapshot.organization_metrics[0].get_count, 3);
        assert_eq!(snapshot.organization_metrics[1].organization, "org-b");
        assert_eq!(snapshot.organization_metrics[1].set_count, 1);

        // Global metrics also updated
        assert_eq!(snapshot.get_count, 3);
        assert_eq!(snapshot.set_count, 1);
    }

    #[test]
    fn test_organization_metrics_cardinality_bound() {
        let metrics = Metrics::with_max_organizations(3);

        // Fill up the 3 tracked slots
        metrics.record_get_org(Duration::from_micros(10), "org-1");
        metrics.record_get_org(Duration::from_micros(20), "org-2");
        metrics.record_get_org(Duration::from_micros(30), "org-3");

        // Overflow goes to _other
        metrics.record_get_org(Duration::from_micros(40), "org-4");
        metrics.record_get_org(Duration::from_micros(50), "org-5");

        let snapshot = metrics.snapshot();
        // 3 tracked + 1 _other = 4
        assert_eq!(snapshot.organization_metrics.len(), 4);

        let other = snapshot
            .organization_metrics
            .iter()
            .find(|entry| entry.organization == "_other")
            .expect("_other bucket should exist");
        assert_eq!(other.get_count, 2);
        assert_eq!(other.get_latency_us, 90); // 40 + 50

        // Global still has all 5
        assert_eq!(snapshot.get_count, 5);
    }

    #[test]
    fn test_organization_metrics_existing_ns_not_counted_against_limit() {
        let metrics = Metrics::with_max_organizations(2);

        metrics.record_get_org(Duration::from_micros(10), "org-1");
        metrics.record_get_org(Duration::from_micros(20), "org-2");
        // Re-recording to existing org should NOT overflow
        metrics.record_get_org(Duration::from_micros(30), "org-1");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.organization_metrics.len(), 2);

        let ns1 = snapshot
            .organization_metrics
            .iter()
            .find(|entry| entry.organization == "org-1")
            .expect("org-1 should exist");
        assert_eq!(ns1.get_count, 2);
    }

    #[test]
    fn test_organization_metrics_all_operation_types() {
        let metrics = Metrics::new();
        let org = "tenant-42";

        metrics.record_get_org(Duration::from_micros(10), org);
        metrics.record_set_org(Duration::from_micros(20), org);
        metrics.record_delete_org(Duration::from_micros(30), org);
        metrics.record_get_range_org(Duration::from_micros(40), org);
        metrics.record_clear_range_org(Duration::from_micros(50), org);
        metrics.record_transaction_org(Duration::from_micros(60), org);
        metrics.record_error_org(org);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.organization_metrics.len(), 1);
        let entry = &snapshot.organization_metrics[0];
        assert_eq!(entry.organization, "tenant-42");
        assert_eq!(entry.get_count, 1);
        assert_eq!(entry.set_count, 1);
        assert_eq!(entry.delete_count, 1);
        assert_eq!(entry.get_range_count, 1);
        assert_eq!(entry.clear_range_count, 1);
        assert_eq!(entry.transaction_count, 1);
        assert_eq!(entry.error_count, 1);
        assert_eq!(entry.total_operations(), 6);
        assert!(entry.error_rate() > 0.16);
    }

    #[test]
    fn test_organization_metrics_reset_clears_all() {
        let metrics = Metrics::new();
        metrics.record_get_org(Duration::from_micros(100), "org-1");
        metrics.record_set_org(Duration::from_micros(200), "org-2");

        metrics.reset();

        let snapshot = metrics.snapshot();
        assert!(snapshot.organization_metrics.is_empty());
    }

    #[test]
    fn test_organization_metrics_sorted_by_total_operations() {
        let metrics = Metrics::new();

        // org-b has 1 op, org-a has 3 ops
        metrics.record_get_org(Duration::from_micros(10), "org-b");
        metrics.record_get_org(Duration::from_micros(10), "org-a");
        metrics.record_set_org(Duration::from_micros(10), "org-a");
        metrics.record_delete_org(Duration::from_micros(10), "org-a");

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.organization_metrics[0].organization, "org-a");
        assert_eq!(snapshot.organization_metrics[0].total_operations(), 3);
        assert_eq!(snapshot.organization_metrics[1].organization, "org-b");
        assert_eq!(snapshot.organization_metrics[1].total_operations(), 1);
    }

    #[test]
    fn test_organization_operation_snapshot_error_rate() {
        let snap = OrganizationOperationSnapshot {
            organization: "test".into(),
            get_count: 8,
            set_count: 2,
            error_count: 3,
            ..Default::default()
        };
        assert!((snap.error_rate() - 0.3).abs() < f64::EPSILON);

        // Zero ops = zero rate
        let empty = OrganizationOperationSnapshot::default();
        assert!((empty.error_rate()).abs() < f64::EPSILON);
    }

    #[test]
    fn test_organization_metrics_default_snapshot_is_empty() {
        let metrics = Metrics::new();
        let snapshot = metrics.snapshot();
        assert!(snapshot.organization_metrics.is_empty());
    }
}
