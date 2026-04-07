//! Rate limiting for storage backends.
//!
//! Provides a [`TokenBucketLimiter`] implementation
//! that protects backends from overload. The [`RateLimitedBackend`] wrapper
//! applies rate limiting transparently before delegating to the inner backend.
//!
//! # Per-Organization Limiting
//!
//! In multi-tenant deployments, [`RateLimitedBackend`] supports per-organization
//! rate limits via a configurable [`OrganizationExtractor`]. Each organization gets
//! its own token bucket, preventing noisy-neighbor issues.
//!
//! # Examples
//!
//! ```no_run
//! use std::time::Duration;
//! use inferadb_common_storage::{MemoryBackend, StorageBackend};
//! use inferadb_common_storage::rate_limiter::{
//!     RateLimitConfig, RateLimitedBackend, TokenBucketLimiter,
//! };
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let backend = MemoryBackend::new();
//! let config = RateLimitConfig::new(100, 20)?;
//! let limiter = TokenBucketLimiter::new(config);
//! let limited = RateLimitedBackend::new(backend, limiter);
//!
//! // Operations are rate-limited transparently
//! limited.set(b"key".to_vec(), b"value".to_vec()).await?;
//! # Ok(())
//! # }
//! ```

use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;
use tracing::warn;

use crate::{
    StorageBackend, StorageRange,
    error::{StorageError, StorageResult},
    health::{HealthProbe, HealthStatus},
    metrics::{Metrics, MetricsCollector},
    transaction::Transaction,
    types::KeyValue,
};

/// Default maximum number of per-organization buckets before new organizations
/// are rejected with a warning log. Prevents unbounded memory growth in
/// multi-tenant deployments with high organization cardinality.
pub const DEFAULT_MAX_ORGANIZATION_BUCKETS: usize = 10_000;

/// Number of shards for per-organization bucket storage.
/// Reduces cross-organization mutex contention under high concurrency.
const NUM_SHARDS: usize = 64;

/// Default idle timeout for organization buckets (10 minutes).
const DEFAULT_ORG_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Interval between periodic stale-bucket cleanup sweeps (60 seconds).
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);

/// Default maximum number of distinct organizations tracked in per-org metrics.
/// Organizations beyond this limit are aggregated under the `_other` key.
const DEFAULT_PER_ORG_METRICS_MAX: usize = 1000;

/// Configuration for a token-bucket rate limiter.
///
/// The bucket refills at `rate` tokens per second with a maximum burst
/// capacity of `burst`. When the bucket is empty, requests are rejected
/// with [`StorageError::RateLimitExceeded`] including a `retry_after`
/// hint.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Sustained rate in tokens per second.
    rate: u64,
    /// Maximum burst size (bucket capacity).
    burst: u64,
}

impl RateLimitConfig {
    /// Creates a new rate limit configuration.
    ///
    /// # Arguments
    ///
    /// * `rate` — Sustained tokens per second (must be >= 1)
    /// * `burst` — Maximum burst capacity (must be >= 1)
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BelowMinimum`](crate::ConfigError::BelowMinimum) if `rate` or `burst`
    /// is zero.
    pub fn new(rate: u64, burst: u64) -> Result<Self, crate::ConfigError> {
        if rate == 0 {
            return Err(crate::ConfigError::BelowMinimum {
                field: "rate",
                min: "1".into(),
                value: "0".into(),
            });
        }
        if burst == 0 {
            return Err(crate::ConfigError::BelowMinimum {
                field: "burst",
                min: "1".into(),
                value: "0".into(),
            });
        }
        Ok(Self { rate, burst })
    }

    /// Returns the sustained rate in tokens per second.
    #[must_use = "returns the configured rate without side effects"]
    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the maximum burst capacity.
    #[must_use = "returns the configured burst without side effects"]
    pub fn burst(&self) -> u64 {
        self.burst
    }
}

/// Internal state for a single token bucket.
#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
    last_accessed: Instant,
    config: RateLimitConfig,
}

impl BucketState {
    fn new(config: RateLimitConfig) -> Self {
        let now = Instant::now();
        Self { tokens: config.burst as f64, last_refill: now, last_accessed: now, config }
    }

    /// Attempts to consume one token, refilling first. Returns `Ok(())` on
    /// success or `Err(retry_after)` if the bucket is empty.
    fn try_acquire(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * self.config.rate as f64;
        self.tokens = (self.tokens + refill).min(self.config.burst as f64);
        self.last_refill = now;
        self.last_accessed = now;

        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            Ok(())
        } else {
            // Time until one token is available
            let deficit = 1.0 - self.tokens;
            let wait_secs = deficit / self.config.rate as f64;
            Err(Duration::from_secs_f64(wait_secs))
        }
    }
}

/// Extracts an organization identifier from a storage key.
///
/// Implementations determine how keys map to organizations for per-tenant
/// rate limiting. When no extractor is set, all operations share a
/// single global bucket.
pub trait OrganizationExtractor: Send + Sync {
    /// Returns the organization for the given key, or `None` for the
    /// global/default bucket.
    fn extract(&self, key: &[u8]) -> Option<String>;
}

/// Token-bucket rate limiter with optional per-organization buckets.
///
/// Thread-safe via internal [`parking_lot::Mutex`]. Supports both a global
/// bucket and optional per-organization buckets sharded across [`NUM_SHARDS`]
/// independent locks to reduce cross-organization contention.
pub struct TokenBucketLimiter {
    global: Mutex<BucketState>,
    organization_shards: Vec<Mutex<HashMap<String, BucketState>>>,
    organization_config: Option<HashMap<String, RateLimitConfig>>,
    default_config: RateLimitConfig,
    extractor: Option<Arc<dyn OrganizationExtractor>>,
    metrics: RateLimitMetrics,
    max_organization_buckets: usize,
    org_idle_timeout: Option<Duration>,
    last_cleanup: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for TokenBucketLimiter {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenBucketLimiter")
            .field("default_config", &self.default_config)
            .field("has_extractor", &self.extractor.is_some())
            .finish_non_exhaustive()
    }
}

/// Metrics tracked by the rate limiter.
#[derive(Debug)]
struct RateLimitMetrics {
    allowed: std::sync::atomic::AtomicU64,
    rejected: std::sync::atomic::AtomicU64,
    per_org_allowed: Mutex<HashMap<String, u64>>,
    per_org_rejected: Mutex<HashMap<String, u64>>,
    per_org_max: usize,
}

impl RateLimitMetrics {
    fn new() -> Self {
        Self {
            allowed: std::sync::atomic::AtomicU64::new(0),
            rejected: std::sync::atomic::AtomicU64::new(0),
            per_org_allowed: Mutex::new(HashMap::new()),
            per_org_rejected: Mutex::new(HashMap::new()),
            per_org_max: DEFAULT_PER_ORG_METRICS_MAX,
        }
    }

    fn record_allowed(&self, org: Option<&str>) {
        self.allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(org) = org {
            let mut map = self.per_org_allowed.lock();
            if let Some(count) = map.get_mut(org) {
                *count += 1;
            } else if map.len() < self.per_org_max {
                map.insert(org.to_owned(), 1);
            } else {
                *map.entry("_other".to_owned()).or_insert(0) += 1;
            }
        }
    }

    fn record_rejected(&self, org: Option<&str>) {
        self.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if let Some(org) = org {
            let mut map = self.per_org_rejected.lock();
            if let Some(count) = map.get_mut(org) {
                *count += 1;
            } else if map.len() < self.per_org_max {
                map.insert(org.to_owned(), 1);
            } else {
                *map.entry("_other".to_owned()).or_insert(0) += 1;
            }
        }
    }
}

/// Snapshot of rate limiter metrics.
#[derive(Debug, Clone, Default)]
pub struct RateLimitMetricsSnapshot {
    /// Total requests that were allowed through.
    pub allowed: u64,
    /// Total requests that were rejected.
    pub rejected: u64,
    /// Per-organization allowed counts.
    pub per_org_allowed: HashMap<String, u64>,
    /// Per-organization rejected counts.
    pub per_org_rejected: HashMap<String, u64>,
}

/// Computes a shard index for the given organization name using the
/// djb2 hash algorithm. Deterministic and dependency-free.
fn shard_index(org: &str) -> usize {
    let mut hash: u64 = 5381;
    for byte in org.as_bytes() {
        hash = hash.wrapping_mul(33).wrapping_add(u64::from(*byte));
    }
    (hash as usize) % NUM_SHARDS
}

/// Returns the current time as milliseconds since `UNIX_EPOCH`.
fn epoch_millis_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

impl TokenBucketLimiter {
    /// Creates a new limiter with the given global configuration.
    #[must_use = "constructing a limiter has no side effects"]
    pub fn new(config: RateLimitConfig) -> Self {
        let shards: Vec<Mutex<HashMap<String, BucketState>>> =
            (0..NUM_SHARDS).map(|_| Mutex::new(HashMap::new())).collect();

        Self {
            global: Mutex::new(BucketState::new(config)),
            organization_shards: shards,
            organization_config: None,
            default_config: config,
            extractor: None,
            metrics: RateLimitMetrics::new(),
            max_organization_buckets: DEFAULT_MAX_ORGANIZATION_BUCKETS,
            org_idle_timeout: None,
            last_cleanup: std::sync::atomic::AtomicU64::new(epoch_millis_now()),
        }
    }

    /// Sets an organization extractor for per-tenant rate limiting.
    ///
    /// When set, each organization gets its own token bucket. Operations
    /// on unrecognized organizations use the global bucket.
    #[must_use = "returns the modified limiter for chaining"]
    pub fn with_organization_extractor(
        mut self,
        extractor: Arc<dyn OrganizationExtractor>,
    ) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Sets per-organization rate limit overrides.
    ///
    /// Organizations not in this map use `default_config`.
    #[must_use = "returns the modified limiter for chaining"]
    pub fn with_organization_configs(mut self, configs: HashMap<String, RateLimitConfig>) -> Self {
        self.organization_config = Some(configs);
        self
    }

    /// Sets the maximum number of per-organization buckets.
    ///
    /// When the limit is reached, new organizations fall back to the global
    /// bucket and a warning is logged. Defaults to
    /// [`DEFAULT_MAX_ORGANIZATION_BUCKETS`].
    #[must_use = "returns the modified limiter for chaining"]
    pub fn with_max_organization_buckets(mut self, max: usize) -> Self {
        self.max_organization_buckets = max;
        self
    }

    /// Sets the idle timeout for organization buckets.
    ///
    /// Buckets not accessed within this duration are evicted during
    /// periodic cleanup. Defaults to [`DEFAULT_ORG_IDLE_TIMEOUT`] when
    /// enabled. Pass `None` to disable eviction entirely.
    #[must_use = "returns the modified limiter for chaining"]
    pub fn with_org_idle_timeout(mut self, timeout: Duration) -> Self {
        self.org_idle_timeout = Some(timeout);
        self
    }

    /// Sets the maximum number of distinct organizations tracked in
    /// per-org metrics. Organizations beyond this limit are aggregated
    /// under the `_other` key. Defaults to [`DEFAULT_PER_ORG_METRICS_MAX`].
    #[must_use = "returns the modified limiter for chaining"]
    pub fn with_per_org_metrics_max(mut self, max: usize) -> Self {
        self.metrics.per_org_max = max;
        self
    }

    /// Checks the rate limit for the given key.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::RateLimitExceeded`] with a `retry_after` hint if the
    /// bucket is empty.
    pub fn check(&self, key: &[u8]) -> StorageResult<()> {
        // Per-organization limiting if extractor is configured
        if let Some(extractor) = &self.extractor
            && let Some(org) = extractor.extract(key)
        {
            return self.check_organization(&org);
        }

        // Fall through to global bucket
        self.check_global()
    }

    fn check_global(&self) -> StorageResult<()> {
        let mut bucket = self.global.lock();
        match bucket.try_acquire() {
            Ok(()) => {
                self.metrics.record_allowed(None);
                Ok(())
            },
            Err(retry_after) => {
                self.metrics.record_rejected(None);
                Err(StorageError::rate_limit_exceeded(retry_after))
            },
        }
    }

    fn check_organization(&self, org: &str) -> StorageResult<()> {
        let config = self
            .organization_config
            .as_ref()
            .and_then(|m| m.get(org).copied())
            .unwrap_or(self.default_config);

        let shard_idx = shard_index(org);
        let mut shard = self.organization_shards[shard_idx].lock();

        // Periodic cleanup of stale buckets in this shard
        self.maybe_cleanup_shard(&mut shard);

        // Count total orgs across all shards for the cardinality limit.
        // If the org already has a bucket in this shard, skip the check.
        if !shard.contains_key(org) {
            let total_orgs: usize = shard.len() + self.count_orgs_in_other_shards(shard_idx);
            if total_orgs >= self.max_organization_buckets {
                warn!(
                    organization = org,
                    bucket_count = total_orgs,
                    max = self.max_organization_buckets,
                    "organization bucket limit reached, falling back to global bucket"
                );
                drop(shard);
                return self.check_global();
            }
        }

        let bucket = shard.entry(org.to_owned()).or_insert_with(|| BucketState::new(config));

        match bucket.try_acquire() {
            Ok(()) => {
                self.metrics.record_allowed(Some(org));
                Ok(())
            },
            Err(retry_after) => {
                self.metrics.record_rejected(Some(org));
                Err(StorageError::rate_limit_exceeded(retry_after))
            },
        }
    }

    /// Counts organizations in all shards except the one at `exclude_idx`.
    fn count_orgs_in_other_shards(&self, exclude_idx: usize) -> usize {
        self.organization_shards
            .iter()
            .enumerate()
            .filter(|(i, _)| *i != exclude_idx)
            .map(|(_, s)| s.lock().len())
            .sum()
    }

    /// Runs stale-bucket cleanup on the given shard if enough time has passed
    /// since the last cleanup.
    fn maybe_cleanup_shard(&self, shard: &mut HashMap<String, BucketState>) {
        let timeout = match self.org_idle_timeout {
            Some(t) => t,
            None => DEFAULT_ORG_IDLE_TIMEOUT,
        };

        let now_millis = epoch_millis_now();
        let last = self.last_cleanup.load(std::sync::atomic::Ordering::Relaxed);
        if now_millis.saturating_sub(last) < CLEANUP_INTERVAL.as_millis() as u64 {
            return;
        }

        // Try to claim the cleanup. If another thread beat us, skip.
        if self
            .last_cleanup
            .compare_exchange(
                last,
                now_millis,
                std::sync::atomic::Ordering::Release,
                std::sync::atomic::Ordering::Relaxed,
            )
            .is_err()
        {
            return;
        }

        let now = Instant::now();
        shard.retain(|_, bucket| now.duration_since(bucket.last_accessed) < timeout);
    }

    /// Removes organization buckets that have not been accessed within `max_idle`.
    ///
    /// Iterates all shards and evicts stale entries. Callers can invoke this
    /// directly for deterministic cleanup in tests; in production the
    /// periodic check inside [`check_organization`](Self::check_organization) handles eviction.
    pub fn evict_stale(&self, max_idle: Duration) {
        let now = Instant::now();
        for shard_mutex in &self.organization_shards {
            let mut shard = shard_mutex.lock();
            shard.retain(|_, bucket| now.duration_since(bucket.last_accessed) < max_idle);
        }
    }

    /// Returns the total number of organization buckets across all shards.
    #[must_use = "returns a count without side effects"]
    pub fn organization_count(&self) -> usize {
        self.organization_shards.iter().map(|s| s.lock().len()).sum()
    }

    /// Returns a snapshot of the rate limiter metrics.
    #[must_use = "returns a point-in-time snapshot without side effects"]
    pub fn metrics_snapshot(&self) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            allowed: self.metrics.allowed.load(std::sync::atomic::Ordering::Relaxed),
            rejected: self.metrics.rejected.load(std::sync::atomic::Ordering::Relaxed),
            per_org_allowed: self.metrics.per_org_allowed.lock().clone(),
            per_org_rejected: self.metrics.per_org_rejected.lock().clone(),
        }
    }

    /// Returns the shard index for a given organization name.
    /// Exposed for testing shard distribution.
    #[cfg(test)]
    fn shard_index_for(org: &str) -> usize {
        shard_index(org)
    }
}

/// [`StorageBackend`] wrapper that applies rate limiting before
/// delegating to the inner backend.
///
/// Read operations (`get`, `get_range`) and write operations (`set`,
/// `delete`, `compare_and_set`, `clear_range`, `set_with_ttl`) all
/// consume one token per call. Transactions and health checks are
/// exempt from rate limiting.
pub struct RateLimitedBackend<B> {
    inner: B,
    limiter: Arc<TokenBucketLimiter>,
}

impl<B: std::fmt::Debug> std::fmt::Debug for RateLimitedBackend<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RateLimitedBackend")
            .field("inner", &self.inner)
            .field("limiter", &self.limiter)
            .finish()
    }
}

impl<B: StorageBackend> RateLimitedBackend<B> {
    /// Wraps a backend with the given rate limiter.
    ///
    /// The limiter is wrapped in an [`Arc`] internally, so multiple
    /// backends can share a single limiter.
    #[must_use = "constructing a rate-limited backend has no side effects"]
    pub fn new(inner: B, limiter: TokenBucketLimiter) -> Self {
        Self { inner, limiter: Arc::new(limiter) }
    }

    /// Returns a reference to the inner backend.
    #[must_use = "returns a reference without side effects"]
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Returns the rate limiter.
    #[must_use = "returns a reference without side effects"]
    pub fn limiter(&self) -> &TokenBucketLimiter {
        &self.limiter
    }
}

#[async_trait]
impl<B: StorageBackend> StorageBackend for RateLimitedBackend<B> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        self.limiter.check(key)?;
        self.inner.get(key).await
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        self.limiter.check(&key)?;
        self.inner.set(key, value).await
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        self.limiter.check(key)?;
        self.inner.compare_and_set(key, expected, new_value).await
    }

    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        self.limiter.check(key)?;
        self.inner.compare_and_set_with_ttl(key, expected, new_value, ttl).await
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.limiter.check(key)?;
        self.inner.delete(key).await
    }

    async fn get_range(&self, range: StorageRange) -> StorageResult<Vec<KeyValue>> {
        // Range operations use global bucket (no single key to extract organization from)
        self.limiter.check_global()?;
        self.inner.get_range(range).await
    }

    async fn clear_range(&self, range: StorageRange) -> StorageResult<()> {
        self.limiter.check_global()?;
        self.inner.clear_range(range).await
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        self.limiter.check(&key)?;
        self.inner.set_with_ttl(key, value, ttl).await
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        // Transactions are exempt from rate limiting. Operations within a
        // transaction are not individually metered.
        self.inner.transaction().await
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        // Health checks are always exempt from rate limiting
        self.inner.health_check(probe).await
    }
}

impl<B: MetricsCollector> MetricsCollector for RateLimitedBackend<B> {
    fn metrics(&self) -> &Metrics {
        self.inner.metrics()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::ops::Bound;

    use super::*;
    use crate::{MemoryBackend, assert_storage_error, to_storage_range};

    #[test]
    fn test_rate_limit_config_new_stores_values() {
        let config = RateLimitConfig::new(100, 20).unwrap();
        assert_eq!(config.rate(), 100);
        assert_eq!(config.burst(), 20);
    }

    #[test]
    fn test_rate_limit_config_new_zero_rate_returns_error() {
        let err = RateLimitConfig::new(0, 10).unwrap_err();
        assert!(err.to_string().contains("rate"), "error should name the field: {err}");
    }

    #[test]
    fn test_rate_limit_config_new_zero_burst_returns_error() {
        let err = RateLimitConfig::new(10, 0).unwrap_err();
        assert!(err.to_string().contains("burst"), "error should name the field: {err}");
    }

    #[test]
    fn test_bucket_try_acquire_within_burst_succeeds() {
        let config = RateLimitConfig::new(10, 5).unwrap();
        let mut bucket = BucketState::new(config);
        // Should allow up to burst capacity
        for _ in 0..5 {
            assert!(bucket.try_acquire().is_ok());
        }
        // 6th should fail
        assert!(bucket.try_acquire().is_err());
    }

    #[test]
    fn test_bucket_try_acquire_exhausted_returns_positive_retry_after() {
        let config = RateLimitConfig::new(10, 1).unwrap();
        let mut bucket = BucketState::new(config);
        // Consume the single token
        assert!(bucket.try_acquire().is_ok());
        // Next attempt should give a positive retry_after
        let retry = bucket.try_acquire().unwrap_err();
        assert!(retry.as_nanos() > 0);
    }

    #[test]
    fn test_limiter_check_within_burst_succeeds() {
        let config = RateLimitConfig::new(1000, 5).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        for _ in 0..5 {
            assert!(limiter.check(b"key").is_ok());
        }
        // Should be rejected
        assert_storage_error!(limiter.check(b"key"), RateLimitExceeded);
    }

    #[test]
    fn test_rate_limit_exceeded_error_is_transient() {
        let err = StorageError::rate_limit_exceeded(Duration::from_millis(100));
        assert!(err.is_transient());
    }

    #[test]
    fn test_metrics_snapshot_tracks_allowed_and_rejected() {
        let config = RateLimitConfig::new(1000, 2).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        // 2 allowed
        let _ = limiter.check(b"a");
        let _ = limiter.check(b"b");
        // 1 rejected
        let _ = limiter.check(b"c");

        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.allowed, 2);
        assert_eq!(snap.rejected, 1);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_set_get_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("value")));
    }

    #[tokio::test]
    async fn test_rate_limited_backend_set_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 2).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Use up burst
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        limited.set(b"b".to_vec(), b"v".to_vec()).await.unwrap();

        // Third should fail
        assert_storage_error!(limited.set(b"c".to_vec(), b"v".to_vec()).await, RateLimitExceeded);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_health_check_bypasses_rate_limit() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Exhaust the limiter
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        // Health check should still succeed and return a HealthStatus
        let status = limited.health_check(HealthProbe::Readiness).await.unwrap();
        assert!(status.is_healthy());
    }

    #[tokio::test]
    async fn test_rate_limited_backend_transaction_bypasses_rate_limit() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Exhaust the limiter
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        // Transaction creation should still succeed
        let txn = limited.transaction().await;
        assert!(txn.is_ok());
    }

    /// Test organization-based rate limiting with a simple prefix extractor.
    struct PrefixExtractor;

    impl OrganizationExtractor for PrefixExtractor {
        fn extract(&self, key: &[u8]) -> Option<String> {
            // Extract organization as the part before the first ':'
            let key_str = std::str::from_utf8(key).ok()?;
            key_str.split(':').next().map(String::from)
        }
    }

    #[test]
    fn test_limiter_per_organization_independent_buckets() {
        let config = RateLimitConfig::new(1000, 2).unwrap();
        let limiter =
            TokenBucketLimiter::new(config).with_organization_extractor(Arc::new(PrefixExtractor));

        // Organization "ns1" gets 2 tokens
        assert!(limiter.check(b"ns1:key1").is_ok());
        assert!(limiter.check(b"ns1:key2").is_ok());
        assert!(limiter.check(b"ns1:key3").is_err()); // exhausted

        // Organization "ns2" is independent — still has 2 tokens
        assert!(limiter.check(b"ns2:key1").is_ok());
        assert!(limiter.check(b"ns2:key2").is_ok());
        assert!(limiter.check(b"ns2:key3").is_err());
    }

    #[test]
    fn test_limiter_per_organization_config_override_burst() {
        let default_config = RateLimitConfig::new(1000, 2).unwrap();
        let premium_config = RateLimitConfig::new(1000, 5).unwrap();

        let mut overrides = HashMap::new();
        overrides.insert("premium".to_owned(), premium_config);

        let limiter = TokenBucketLimiter::new(default_config)
            .with_organization_extractor(Arc::new(PrefixExtractor))
            .with_organization_configs(overrides);

        // "basic" organization gets default (2 burst)
        assert!(limiter.check(b"basic:k1").is_ok());
        assert!(limiter.check(b"basic:k2").is_ok());
        assert!(limiter.check(b"basic:k3").is_err());

        // "premium" organization gets override (5 burst)
        for i in 0..5 {
            assert!(
                limiter.check(format!("premium:k{i}").as_bytes()).is_ok(),
                "premium request {i} should succeed"
            );
        }
        assert!(limiter.check(b"premium:k5").is_err());
    }

    #[test]
    fn test_bucket_try_acquire_refills_after_elapsed_time() {
        let config = RateLimitConfig::new(1000, 1).unwrap();
        let mut bucket = BucketState::new(config);

        // Consume the token
        assert!(bucket.try_acquire().is_ok());
        assert!(bucket.try_acquire().is_err());

        // Simulate time passing by backdating last_refill
        bucket.last_refill -= Duration::from_millis(2);

        // Should have refilled ~2 tokens, capped at burst=1
        assert!(bucket.try_acquire().is_ok());
    }

    #[test]
    fn test_rate_limit_exceeded_display_includes_retry_after_ms() {
        let err = StorageError::rate_limit_exceeded(Duration::from_millis(150));
        let display = err.to_string();
        assert!(display.contains("150"), "display should contain retry_after ms: {display}");
        assert!(display.contains("Rate limit exceeded"), "display: {display}");
    }

    #[test]
    fn test_limiter_organization_bucket_limit_exceeded_falls_back_to_global() {
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config)
            .with_organization_extractor(Arc::new(PrefixExtractor))
            .with_max_organization_buckets(2);

        // Fill up two organization buckets
        assert!(limiter.check(b"org1:k1").is_ok());
        assert!(limiter.check(b"org2:k1").is_ok());

        // Third org exceeds the bucket limit -- falls back to the global bucket
        // and still succeeds (global bucket has capacity)
        assert!(limiter.check(b"org3:k1").is_ok());

        // Verify no third org bucket was created
        let total_orgs: usize = limiter.organization_count();
        assert_eq!(total_orgs, 2, "should not exceed max_organization_buckets");
    }

    #[test]
    fn test_limiter_debug_shows_has_extractor_field() {
        let config = RateLimitConfig::new(100, 20).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let debug = format!("{limiter:?}");
        assert!(debug.contains("has_extractor: false"), "debug output: {debug}");

        let limiter_with =
            TokenBucketLimiter::new(config).with_organization_extractor(Arc::new(PrefixExtractor));
        let debug_with = format!("{limiter_with:?}");
        assert!(debug_with.contains("has_extractor: true"), "debug output: {debug_with}");
    }

    #[tokio::test]
    async fn test_rate_limited_backend_inner_and_limiter_accessors() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(100, 20).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);
        let _inner: &MemoryBackend = limited.inner();
        let limiter_ref = limited.limiter();
        let snap = limiter_ref.metrics_snapshot();
        assert_eq!(snap.allowed, 0);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_delete_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
        limited.delete(b"key").await.unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_rate_limited_backend_compare_and_set_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.compare_and_set(b"key", None, b"v1".to_vec()).await.unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("v1")));
    }

    #[tokio::test]
    async fn test_rate_limited_backend_compare_and_set_with_ttl_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited
            .compare_and_set_with_ttl(b"key", None, b"v1".to_vec(), Duration::from_secs(60))
            .await
            .unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("v1")));
    }

    #[tokio::test]
    async fn test_rate_limited_backend_set_with_ttl_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited
            .set_with_ttl(b"key".to_vec(), b"value".to_vec(), Duration::from_secs(60))
            .await
            .unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("value")));
    }

    #[tokio::test]
    async fn test_rate_limited_backend_get_range_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        limited.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        limited.set(b"c".to_vec(), b"3".to_vec()).await.unwrap();

        let range = (Bound::Included(b"a".to_vec()), Bound::Excluded(b"d".to_vec()));
        let results = limited.get_range(range).await.unwrap();
        assert_eq!(results.len(), 3);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_clear_range_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        limited.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();

        let range = (Bound::Included(b"a".to_vec()), Bound::Excluded(b"c".to_vec()));
        limited.clear_range(range).await.unwrap();

        let val = limited.get(b"a").await.unwrap();
        assert!(val.is_none());
    }

    #[tokio::test]
    async fn test_rate_limited_backend_delete_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        assert_storage_error!(limited.delete(b"a").await, RateLimitExceeded);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_get_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        assert_storage_error!(limited.get(b"a").await, RateLimitExceeded);
    }

    #[tokio::test]
    async fn test_rate_limited_backend_cas_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        assert_storage_error!(
            limited.compare_and_set(b"a", Some(b"v"), b"v2".to_vec()).await,
            RateLimitExceeded
        );
    }

    #[tokio::test]
    async fn test_rate_limited_backend_cas_with_ttl_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        assert_storage_error!(
            limited
                .compare_and_set_with_ttl(b"a", Some(b"v"), b"v2".to_vec(), Duration::from_secs(60))
                .await,
            RateLimitExceeded
        );
    }

    #[tokio::test]
    async fn test_rate_limited_backend_set_with_ttl_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        assert_storage_error!(
            limited.set_with_ttl(b"b".to_vec(), b"v".to_vec(), Duration::from_secs(60)).await,
            RateLimitExceeded
        );
    }

    #[tokio::test]
    async fn test_rate_limited_backend_get_range_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        assert_storage_error!(
            limited.get_range(to_storage_range(b"a".to_vec()..b"z".to_vec())).await,
            RateLimitExceeded
        );
    }

    #[tokio::test]
    async fn test_rate_limited_backend_clear_range_exhausted_returns_rate_limit_exceeded() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1).unwrap();
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        assert_storage_error!(
            limited.clear_range(to_storage_range(b"a".to_vec()..b"z".to_vec())).await,
            RateLimitExceeded
        );
    }

    #[test]
    fn test_limiter_per_organization_rejection_tracks_metrics() {
        let config = RateLimitConfig::new(1000, 1).unwrap();
        let limiter =
            TokenBucketLimiter::new(config).with_organization_extractor(Arc::new(PrefixExtractor));

        assert!(limiter.check(b"org1:k1").is_ok());
        assert!(limiter.check(b"org1:k2").is_err());

        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.allowed, 1);
        assert_eq!(snap.rejected, 1);
    }

    #[test]
    fn test_limiter_extractor_returning_none_uses_global_bucket() {
        struct NeverExtractor;
        impl OrganizationExtractor for NeverExtractor {
            fn extract(&self, _key: &[u8]) -> Option<String> {
                None
            }
        }

        let config = RateLimitConfig::new(1000, 2).unwrap();
        let limiter =
            TokenBucketLimiter::new(config).with_organization_extractor(Arc::new(NeverExtractor));

        assert!(limiter.check(b"anything").is_ok());
        assert!(limiter.check(b"anything_else").is_ok());
        assert!(limiter.check(b"third").is_err());

        let total_orgs = limiter.organization_count();
        assert_eq!(total_orgs, 0);
    }

    // --- New tests ---

    #[test]
    fn test_shard_distribution_spreads_organizations() {
        let orgs = ["alpha", "beta", "gamma", "delta", "epsilon", "zeta"];
        let mut shard_indices: Vec<usize> =
            orgs.iter().map(|o| TokenBucketLimiter::shard_index_for(o)).collect();
        shard_indices.sort_unstable();
        shard_indices.dedup();
        assert!(
            shard_indices.len() >= 2,
            "expected at least 2 distinct shards from {} orgs, got {:?}",
            orgs.len(),
            shard_indices
        );
    }

    #[test]
    fn test_org_bucket_eviction_removes_stale_entries() {
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config)
            .with_organization_extractor(Arc::new(PrefixExtractor))
            .with_org_idle_timeout(Duration::from_secs(60));

        // Create some org buckets
        assert!(limiter.check(b"org1:k").is_ok());
        assert!(limiter.check(b"org2:k").is_ok());
        assert!(limiter.check(b"org3:k").is_ok());
        assert_eq!(limiter.organization_count(), 3);

        // Backdate last_accessed on org1 and org2 to simulate staleness
        for shard_mutex in &limiter.organization_shards {
            let mut shard = shard_mutex.lock();
            for (name, bucket) in shard.iter_mut() {
                if name == "org1" || name == "org2" {
                    bucket.last_accessed -= Duration::from_secs(120);
                }
            }
        }

        // Evict with a 60s window — org1 and org2 should be removed
        limiter.evict_stale(Duration::from_secs(60));
        assert_eq!(limiter.organization_count(), 1);

        // org3 should still be present
        let mut found_org3 = false;
        for shard_mutex in &limiter.organization_shards {
            let shard = shard_mutex.lock();
            if shard.contains_key("org3") {
                found_org3 = true;
            }
        }
        assert!(found_org3, "org3 should survive eviction");
    }

    #[test]
    fn test_per_org_metrics_track_allowed_and_rejected() {
        let config = RateLimitConfig::new(1000, 2).unwrap();
        let limiter =
            TokenBucketLimiter::new(config).with_organization_extractor(Arc::new(PrefixExtractor));

        // org_a: 2 allowed, 1 rejected
        assert!(limiter.check(b"org_a:k1").is_ok());
        assert!(limiter.check(b"org_a:k2").is_ok());
        assert!(limiter.check(b"org_a:k3").is_err());

        // org_b: 1 allowed
        assert!(limiter.check(b"org_b:k1").is_ok());

        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.per_org_allowed.get("org_a"), Some(&2));
        assert_eq!(snap.per_org_rejected.get("org_a"), Some(&1));
        assert_eq!(snap.per_org_allowed.get("org_b"), Some(&1));
        assert_eq!(snap.per_org_rejected.get("org_b"), None);
    }

    #[test]
    fn test_per_org_metrics_overflow_uses_other_bucket() {
        let config = RateLimitConfig::new(1000, 100).unwrap();
        let limiter = TokenBucketLimiter::new(config)
            .with_organization_extractor(Arc::new(PrefixExtractor))
            .with_per_org_metrics_max(3);

        // Fill up 3 distinct org metric slots
        assert!(limiter.check(b"a:k").is_ok());
        assert!(limiter.check(b"b:k").is_ok());
        assert!(limiter.check(b"c:k").is_ok());

        // 4th org should overflow to "_other"
        assert!(limiter.check(b"d:k").is_ok());
        assert!(limiter.check(b"e:k").is_ok());

        let snap = limiter.metrics_snapshot();
        assert_eq!(snap.per_org_allowed.get("a"), Some(&1));
        assert_eq!(snap.per_org_allowed.get("b"), Some(&1));
        assert_eq!(snap.per_org_allowed.get("c"), Some(&1));
        assert_eq!(snap.per_org_allowed.get("_other"), Some(&2));
        assert_eq!(snap.per_org_allowed.get("d"), None, "d should not have its own slot");
        assert_eq!(snap.per_org_allowed.get("e"), None, "e should not have its own slot");
    }
}
