//! Rate limiting for storage backends.
//!
//! Provides a [`RateLimiter`] trait and [`TokenBucketLimiter`] implementation
//! that protect backends from overload. The [`RateLimitedBackend`] wrapper
//! applies rate limiting transparently before delegating to the inner backend.
//!
//! # Per-Namespace Limiting
//!
//! In multi-tenant deployments, [`RateLimitedBackend`] supports per-namespace
//! rate limits via a configurable [`NamespaceExtractor`]. Each namespace gets
//! its own token bucket, preventing noisy-neighbor issues.
//!
//! # Example
//!
//! ```no_run
//! use std::time::Duration;
//! use inferadb_common_storage::{MemoryBackend, StorageBackend};
//! use inferadb_common_storage::rate_limiter::{
//!     RateLimitConfig, RateLimitedBackend, TokenBucketLimiter,
//! };
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let backend = MemoryBackend::new();
//! let config = RateLimitConfig::new(100, 20);
//! let limiter = TokenBucketLimiter::new(config);
//! let limited = RateLimitedBackend::new(backend, limiter);
//!
//! // Operations are rate-limited transparently
//! limited.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
//! # });
//! ```

use std::{
    collections::HashMap,
    ops::RangeBounds,
    sync::Arc,
    time::{Duration, Instant},
};

use async_trait::async_trait;
use bytes::Bytes;
use parking_lot::Mutex;

use crate::{
    StorageBackend,
    error::{StorageError, StorageResult},
    health::{HealthProbe, HealthStatus},
    metrics::{Metrics, MetricsCollector},
    transaction::Transaction,
    types::KeyValue,
};

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
    /// * `rate` - Sustained tokens per second (must be >= 1)
    /// * `burst` - Maximum burst capacity (must be >= 1)
    ///
    /// # Panics
    ///
    /// Panics if `rate` or `burst` is zero.
    #[must_use]
    pub fn new(rate: u64, burst: u64) -> Self {
        assert!(rate >= 1, "rate must be at least 1");
        assert!(burst >= 1, "burst must be at least 1");
        Self { rate, burst }
    }

    /// Returns the sustained rate in tokens per second.
    #[must_use]
    pub fn rate(&self) -> u64 {
        self.rate
    }

    /// Returns the maximum burst capacity.
    #[must_use]
    pub fn burst(&self) -> u64 {
        self.burst
    }
}

/// Internal state for a single token bucket.
#[derive(Debug)]
struct BucketState {
    tokens: f64,
    last_refill: Instant,
    config: RateLimitConfig,
}

impl BucketState {
    fn new(config: RateLimitConfig) -> Self {
        Self { tokens: config.burst as f64, last_refill: Instant::now(), config }
    }

    /// Attempts to consume one token, refilling first. Returns `Ok(())` on
    /// success or `Err(retry_after)` if the bucket is empty.
    fn try_acquire(&mut self) -> Result<(), Duration> {
        let now = Instant::now();
        let elapsed = now.duration_since(self.last_refill);
        let refill = elapsed.as_secs_f64() * self.config.rate as f64;
        self.tokens = (self.tokens + refill).min(self.config.burst as f64);
        self.last_refill = now;

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

/// Extracts a namespace identifier from a storage key.
///
/// Implementations determine how keys map to namespaces for per-tenant
/// rate limiting. When no extractor is set, all operations share a
/// single global bucket.
pub trait NamespaceExtractor: Send + Sync {
    /// Returns the namespace for the given key, or `None` for the
    /// global/default bucket.
    fn extract(&self, key: &[u8]) -> Option<String>;
}

/// A rate limiter using the token bucket algorithm.
///
/// Thread-safe via internal `parking_lot::Mutex`. Supports both a global
/// bucket and optional per-namespace buckets.
pub struct TokenBucketLimiter {
    global: Mutex<BucketState>,
    namespaces: Mutex<HashMap<String, BucketState>>,
    namespace_config: Option<HashMap<String, RateLimitConfig>>,
    default_config: RateLimitConfig,
    extractor: Option<Arc<dyn NamespaceExtractor>>,
    metrics: RateLimitMetrics,
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
}

impl RateLimitMetrics {
    fn new() -> Self {
        Self {
            allowed: std::sync::atomic::AtomicU64::new(0),
            rejected: std::sync::atomic::AtomicU64::new(0),
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
}

impl TokenBucketLimiter {
    /// Creates a new limiter with the given global configuration.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            global: Mutex::new(BucketState::new(config)),
            namespaces: Mutex::new(HashMap::new()),
            namespace_config: None,
            default_config: config,
            extractor: None,
            metrics: RateLimitMetrics::new(),
        }
    }

    /// Sets a namespace extractor for per-tenant rate limiting.
    ///
    /// When set, each namespace gets its own token bucket. Operations
    /// on unrecognized namespaces use the global bucket.
    #[must_use]
    pub fn with_namespace_extractor(mut self, extractor: Arc<dyn NamespaceExtractor>) -> Self {
        self.extractor = Some(extractor);
        self
    }

    /// Sets per-namespace rate limit overrides.
    ///
    /// Namespaces not in this map use `default_config`.
    #[must_use]
    pub fn with_namespace_configs(mut self, configs: HashMap<String, RateLimitConfig>) -> Self {
        self.namespace_config = Some(configs);
        self
    }

    /// Checks the rate limit, returning `Ok(())` if allowed or
    /// `Err(StorageError::RateLimitExceeded)` if rejected.
    pub fn check(&self, key: &[u8]) -> StorageResult<()> {
        // Per-namespace limiting if extractor is configured
        if let Some(extractor) = &self.extractor
            && let Some(ns) = extractor.extract(key)
        {
            return self.check_namespace(&ns);
        }

        // Fall through to global bucket
        self.check_global()
    }

    fn check_global(&self) -> StorageResult<()> {
        let mut bucket = self.global.lock();
        match bucket.try_acquire() {
            Ok(()) => {
                self.metrics.allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            },
            Err(retry_after) => {
                self.metrics.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(StorageError::rate_limit_exceeded(retry_after))
            },
        }
    }

    fn check_namespace(&self, ns: &str) -> StorageResult<()> {
        let config = self
            .namespace_config
            .as_ref()
            .and_then(|m| m.get(ns).copied())
            .unwrap_or(self.default_config);

        let mut namespaces = self.namespaces.lock();
        let bucket = namespaces.entry(ns.to_owned()).or_insert_with(|| BucketState::new(config));

        match bucket.try_acquire() {
            Ok(()) => {
                self.metrics.allowed.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(())
            },
            Err(retry_after) => {
                self.metrics.rejected.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Err(StorageError::rate_limit_exceeded(retry_after))
            },
        }
    }

    /// Returns a snapshot of the rate limiter metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> RateLimitMetricsSnapshot {
        RateLimitMetricsSnapshot {
            allowed: self.metrics.allowed.load(std::sync::atomic::Ordering::Relaxed),
            rejected: self.metrics.rejected.load(std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// A [`StorageBackend`] wrapper that applies rate limiting before
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
    pub fn new(inner: B, limiter: TokenBucketLimiter) -> Self {
        Self { inner, limiter: Arc::new(limiter) }
    }

    /// Returns a reference to the inner backend.
    #[must_use]
    pub fn inner(&self) -> &B {
        &self.inner
    }

    /// Returns the rate limiter.
    #[must_use]
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

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        self.limiter.check(key)?;
        self.inner.delete(key).await
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        // Range operations use global bucket (no single key to extract namespace from)
        self.limiter.check_global()?;
        self.inner.get_range(range).await
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.limiter.check_global()?;
        self.inner.clear_range(range).await
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        self.limiter.check(&key)?;
        self.inner.set_with_ttl(key, value, ttl).await
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        // Transactions are exempt — individual ops within will be rate-limited
        // at commit time by the inner backend, not through this wrapper.
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
    use super::*;
    use crate::{MemoryBackend, assert_storage_error};

    #[test]
    fn config_creation() {
        let config = RateLimitConfig::new(100, 20);
        assert_eq!(config.rate(), 100);
        assert_eq!(config.burst(), 20);
    }

    #[test]
    #[should_panic(expected = "rate must be at least 1")]
    fn config_rejects_zero_rate() {
        let _ = RateLimitConfig::new(0, 10);
    }

    #[test]
    #[should_panic(expected = "burst must be at least 1")]
    fn config_rejects_zero_burst() {
        let _ = RateLimitConfig::new(10, 0);
    }

    #[test]
    fn bucket_allows_within_burst() {
        let config = RateLimitConfig::new(10, 5);
        let mut bucket = BucketState::new(config);
        // Should allow up to burst capacity
        for _ in 0..5 {
            assert!(bucket.try_acquire().is_ok());
        }
        // 6th should fail
        assert!(bucket.try_acquire().is_err());
    }

    #[test]
    fn bucket_retry_after_is_positive() {
        let config = RateLimitConfig::new(10, 1);
        let mut bucket = BucketState::new(config);
        // Consume the single token
        assert!(bucket.try_acquire().is_ok());
        // Next attempt should give a positive retry_after
        let retry = bucket.try_acquire().unwrap_err();
        assert!(retry.as_nanos() > 0);
    }

    #[test]
    fn limiter_allows_within_limit() {
        let config = RateLimitConfig::new(1000, 5);
        let limiter = TokenBucketLimiter::new(config);
        for _ in 0..5 {
            assert!(limiter.check(b"key").is_ok());
        }
        // Should be rejected
        assert_storage_error!(limiter.check(b"key"), RateLimitExceeded);
    }

    #[test]
    fn rate_limit_exceeded_is_transient() {
        let err = StorageError::rate_limit_exceeded(Duration::from_millis(100));
        assert!(err.is_transient());
    }

    #[test]
    fn metrics_track_allowed_and_rejected() {
        let config = RateLimitConfig::new(1000, 2);
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
    async fn rate_limited_backend_passes_through() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1000, 100);
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        limited.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();
        let val = limited.get(b"key").await.unwrap();
        assert_eq!(val, Some(Bytes::from("value")));
    }

    #[tokio::test]
    async fn rate_limited_backend_rejects_when_exhausted() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 2);
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Use up burst
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();
        limited.set(b"b".to_vec(), b"v".to_vec()).await.unwrap();

        // Third should fail
        assert_storage_error!(limited.set(b"c".to_vec(), b"v".to_vec()).await, RateLimitExceeded);
    }

    #[tokio::test]
    async fn health_check_bypasses_rate_limit() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1);
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Exhaust the limiter
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        // Health check should still succeed and return a HealthStatus
        let status = limited.health_check(HealthProbe::Readiness).await.unwrap();
        assert!(status.is_healthy());
    }

    #[tokio::test]
    async fn transaction_bypasses_rate_limit() {
        let backend = MemoryBackend::new();
        let config = RateLimitConfig::new(1, 1);
        let limiter = TokenBucketLimiter::new(config);
        let limited = RateLimitedBackend::new(backend, limiter);

        // Exhaust the limiter
        limited.set(b"a".to_vec(), b"v".to_vec()).await.unwrap();

        // Transaction creation should still succeed
        let txn = limited.transaction().await;
        assert!(txn.is_ok());
    }

    /// Test namespace-based rate limiting with a simple prefix extractor.
    struct PrefixExtractor;

    impl NamespaceExtractor for PrefixExtractor {
        fn extract(&self, key: &[u8]) -> Option<String> {
            // Extract namespace as the part before the first ':'
            let key_str = std::str::from_utf8(key).ok()?;
            key_str.split(':').next().map(String::from)
        }
    }

    #[test]
    fn per_namespace_rate_limiting() {
        let config = RateLimitConfig::new(1000, 2);
        let limiter =
            TokenBucketLimiter::new(config).with_namespace_extractor(Arc::new(PrefixExtractor));

        // Namespace "ns1" gets 2 tokens
        assert!(limiter.check(b"ns1:key1").is_ok());
        assert!(limiter.check(b"ns1:key2").is_ok());
        assert!(limiter.check(b"ns1:key3").is_err()); // exhausted

        // Namespace "ns2" is independent — still has 2 tokens
        assert!(limiter.check(b"ns2:key1").is_ok());
        assert!(limiter.check(b"ns2:key2").is_ok());
        assert!(limiter.check(b"ns2:key3").is_err());
    }

    #[test]
    fn per_namespace_config_override() {
        let default_config = RateLimitConfig::new(1000, 2);
        let premium_config = RateLimitConfig::new(1000, 5);

        let mut overrides = HashMap::new();
        overrides.insert("premium".to_owned(), premium_config);

        let limiter = TokenBucketLimiter::new(default_config)
            .with_namespace_extractor(Arc::new(PrefixExtractor))
            .with_namespace_configs(overrides);

        // "basic" namespace gets default (2 burst)
        assert!(limiter.check(b"basic:k1").is_ok());
        assert!(limiter.check(b"basic:k2").is_ok());
        assert!(limiter.check(b"basic:k3").is_err());

        // "premium" namespace gets override (5 burst)
        for i in 0..5 {
            assert!(
                limiter.check(format!("premium:k{i}").as_bytes()).is_ok(),
                "premium request {i} should succeed"
            );
        }
        assert!(limiter.check(b"premium:k5").is_err());
    }

    #[test]
    fn bucket_refills_over_time() {
        let config = RateLimitConfig::new(1000, 1);
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
    fn display_includes_retry_after() {
        let err = StorageError::rate_limit_exceeded(Duration::from_millis(150));
        let display = err.to_string();
        assert!(display.contains("150"), "display should contain retry_after ms: {display}");
        assert!(display.contains("Rate limit exceeded"), "display: {display}");
    }
}
