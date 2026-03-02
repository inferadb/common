//! Read-through cache wrapper for storage backends.
//!
//! [`CachedBackend`] wraps any [`StorageBackend`] and adds a read-through
//! cache using [`moka`]. On reads, the cache is checked first; on writes,
//! the corresponding cache entry is invalidated before the write is delegated.
//!
//! # Design
//!
//! - **Cache-aside pattern**: `get` checks cache → miss → fetch from inner → populate cache. Both
//!   present and absent keys are cached (`Option<Bytes>`).
//! - **Pre-invalidation**: writes invalidate the cache entry *before* delegating to the inner
//!   backend, preventing stale reads during concurrent access.
//! - **Range bypass**: `get_range` bypasses the cache entirely.
//! - **Transaction pass-through**: transactions go directly to the inner backend for atomicity.
//!
//! # Usage
//!
//! ```no_run
//! # use std::time::Duration;
//! # use inferadb_common_storage::{CachedBackend, CacheConfig, MemoryBackend, StorageBackend};
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let inner = MemoryBackend::new();
//! let config = CacheConfig::builder()
//!     .max_entries(10_000)
//!     .ttl(Duration::from_secs(60))
//!     .build()?;
//! let cached = CachedBackend::new(inner, config);
//!
//! cached.set(b"key".to_vec(), b"value".to_vec()).await?;
//! let _ = cached.get(b"key").await?; // populates cache
//! let _ = cached.get(b"key").await?; // served from cache
//! # Ok(())
//! # }
//! ```

use std::{ops::RangeBounds, time::Duration};

use async_trait::async_trait;
use bytes::Bytes;
use moka::future::Cache;
use tracing::trace;

use crate::{
    ConfigError, StorageBackend,
    error::StorageResult,
    health::{HealthProbe, HealthStatus},
    transaction::Transaction,
    types::KeyValue,
};

// ───────────────────────────────────────────────────────────────────────────
// CacheConfig
// ───────────────────────────────────────────────────────────────────────────

/// Default maximum number of cache entries.
const DEFAULT_MAX_ENTRIES: u64 = 10_000;

/// Default cache TTL.
const DEFAULT_TTL: Duration = Duration::from_secs(60);

/// Minimum allowed cache TTL.
const MIN_TTL: Duration = Duration::from_secs(1);

/// Configuration for the read-through cache.
///
/// # Validation
///
/// - `max_entries` must be >= 1
/// - `ttl` must be >= 1 second
///
/// Use [`CacheConfig::disabled()`] to create a backend with caching turned off.
///
/// # Examples
///
/// ```no_run
/// # use std::time::Duration;
/// # use inferadb_common_storage::CacheConfig;
/// let config = CacheConfig::builder()
///     .max_entries(5_000)
///     .ttl(Duration::from_secs(120))
///     .build()
///     .expect("valid config");
/// ```
#[derive(Clone)]
pub struct CacheConfig {
    max_entries: u64,
    ttl: Duration,
    enabled: bool,
}

impl CacheConfig {
    /// Creates a validated cache configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if `max_entries` is 0 or `ttl` is less than 1 second.
    pub fn builder() -> CacheConfigBuilder {
        CacheConfigBuilder { max_entries: DEFAULT_MAX_ENTRIES, ttl: DEFAULT_TTL }
    }

    /// Creates a disabled cache configuration.
    ///
    /// The resulting [`CachedBackend`] will pass all operations directly to the
    /// inner backend with no caching overhead.
    pub fn disabled() -> Self {
        Self { max_entries: 0, ttl: Duration::ZERO, enabled: false }
    }

    /// Returns the maximum number of cache entries.
    pub fn max_entries(&self) -> u64 {
        self.max_entries
    }

    /// Returns the cache TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Returns whether caching is enabled.
    pub fn enabled(&self) -> bool {
        self.enabled
    }
}

/// Builder for [`CacheConfig`].
pub struct CacheConfigBuilder {
    max_entries: u64,
    ttl: Duration,
}

impl CacheConfigBuilder {
    /// Sets the maximum number of entries in the cache.
    pub fn max_entries(mut self, max_entries: u64) -> Self {
        self.max_entries = max_entries;
        self
    }

    /// Sets the TTL for cache entries.
    pub fn ttl(mut self, ttl: Duration) -> Self {
        self.ttl = ttl;
        self
    }

    /// Builds the [`CacheConfig`], validating all fields.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`] if:
    /// - `max_entries` is 0
    /// - `ttl` is less than 1 second
    pub fn build(self) -> Result<CacheConfig, ConfigError> {
        if self.max_entries == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_entries",
                value: self.max_entries.to_string(),
                min: "1".to_owned(),
            });
        }
        if self.ttl < MIN_TTL {
            return Err(ConfigError::BelowMinimum {
                field: "ttl",
                value: format!("{}ms", self.ttl.as_millis()),
                min: "1s".to_owned(),
            });
        }
        Ok(CacheConfig { max_entries: self.max_entries, ttl: self.ttl, enabled: true })
    }
}

// ───────────────────────────────────────────────────────────────────────────
// CachedBackend
// ───────────────────────────────────────────────────────────────────────────

/// A read-through caching wrapper around any [`StorageBackend`].
///
/// Caches both present and absent keys to prevent repeated backend lookups.
/// Write operations invalidate the cache before delegating.
#[derive(Clone)]
pub struct CachedBackend<S: StorageBackend> {
    inner: S,
    cache: Option<Cache<Vec<u8>, Option<Bytes>>>,
    config: CacheConfig,
}

impl<S: StorageBackend + Clone> CachedBackend<S> {
    /// Creates a new cached backend.
    ///
    /// If `config` was created with [`CacheConfig::disabled()`], no cache is
    /// allocated and all operations pass through directly.
    pub fn new(inner: S, config: CacheConfig) -> Self {
        let cache = if config.enabled {
            Some(Cache::builder().max_capacity(config.max_entries).time_to_live(config.ttl).build())
        } else {
            None
        };
        Self { inner, cache, config }
    }

    /// Returns a reference to the inner backend.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    /// Returns cache statistics: `(current_entries, max_entries)`.
    pub fn cache_stats(&self) -> (u64, u64) {
        let count = self.cache.as_ref().map_or(0, |c| c.entry_count());
        (count, self.config.max_entries)
    }

    /// Invalidates all cache entries.
    pub fn clear_cache(&self) {
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
        }
    }
}

#[async_trait]
impl<S: StorageBackend + Clone> StorageBackend for CachedBackend<S> {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        if let Some(cache) = &self.cache {
            if let Some(cached_value) = cache.get(key).await {
                trace!(key_len = key.len(), "cache hit");
                return Ok(cached_value);
            }

            let result = self.inner.get(key).await?;
            cache.insert(key.to_vec(), result.clone()).await;
            trace!(key_len = key.len(), "cache miss, populated");
            return Ok(result);
        }

        self.inner.get(key).await
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        if let Some(cache) = &self.cache {
            cache.invalidate(&key).await;
        }
        self.inner.set(key, value).await
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        if let Some(cache) = &self.cache {
            cache.invalidate(key).await;
        }
        self.inner.delete(key).await
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        self.inner.get_range(range).await
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        if let Some(cache) = &self.cache {
            cache.invalidate_all();
        }
        self.inner.clear_range(range).await
    }

    async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()> {
        if let Some(cache) = &self.cache {
            cache.invalidate(&key).await;
        }
        self.inner.set_with_ttl(key, value, ttl).await
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        self.inner.transaction().await
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        if let Some(cache) = &self.cache {
            cache.invalidate(key).await;
        }
        self.inner.compare_and_set(key, expected, new_value).await
    }

    async fn compare_and_set_with_ttl(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
        ttl: Duration,
    ) -> StorageResult<()> {
        if let Some(cache) = &self.cache {
            cache.invalidate(key).await;
        }
        self.inner.compare_and_set_with_ttl(key, expected, new_value, ttl).await
    }

    async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus> {
        self.inner.health_check(probe).await
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::MemoryBackend;

    fn test_config() -> CacheConfig {
        CacheConfig::builder().max_entries(100).ttl(Duration::from_secs(60)).build().unwrap()
    }

    #[tokio::test]
    async fn cache_hit_on_second_read() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner.clone(), test_config());

        cached.set(b"key".to_vec(), b"value".to_vec()).await.unwrap();

        // First read populates cache
        let v1 = cached.get(b"key").await.unwrap();
        assert_eq!(v1, Some(Bytes::from("value")));

        // Mutate inner directly — cached read should still return old value
        inner.set(b"key".to_vec(), b"changed".to_vec()).await.unwrap();
        let v2 = cached.get(b"key").await.unwrap();
        assert_eq!(v2, Some(Bytes::from("value")), "should serve from cache");
    }

    #[tokio::test]
    async fn miss_caching_prevents_repeated_lookups() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner.clone(), test_config());

        // First read caches None
        let v = cached.get(b"absent").await.unwrap();
        assert_eq!(v, None);

        // Even if we sneak data into inner, cache returns None
        inner.set(b"absent".to_vec(), b"surprise".to_vec()).await.unwrap();
        let v = cached.get(b"absent").await.unwrap();
        assert_eq!(v, None, "absent key should be cached as None");
    }

    #[tokio::test]
    async fn set_invalidates_cache() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner, test_config());

        cached.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        cached.get(b"key").await.unwrap(); // populate cache

        cached.set(b"key".to_vec(), b"v2".to_vec()).await.unwrap();
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v2")));
    }

    #[tokio::test]
    async fn delete_invalidates_cache() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner, test_config());

        cached.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        cached.get(b"key").await.unwrap(); // populate cache

        cached.delete(b"key").await.unwrap();
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, None);
    }

    #[tokio::test]
    async fn compare_and_set_invalidates_cache() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner, test_config());

        cached.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        cached.get(b"key").await.unwrap(); // populate cache

        cached.compare_and_set(b"key", Some(b"v1"), b"v2".to_vec()).await.unwrap();
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v2")));
    }

    #[tokio::test]
    async fn clear_range_invalidates_all() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner.clone(), test_config());

        cached.set(b"a".to_vec(), b"1".to_vec()).await.unwrap();
        cached.set(b"b".to_vec(), b"2".to_vec()).await.unwrap();
        // Populate cache
        cached.get(b"a").await.unwrap();
        cached.get(b"b").await.unwrap();

        cached.clear_range(b"a".to_vec()..b"c".to_vec()).await.unwrap();

        // After clear_range, the cache should have been invalidated.
        // Mutate inner directly to verify cache no longer serves stale data.
        inner.set(b"a".to_vec(), b"fresh".to_vec()).await.unwrap();
        let v = cached.get(b"a").await.unwrap();
        assert_eq!(v, Some(Bytes::from("fresh")), "clear_range should invalidate cache");
    }

    #[tokio::test]
    async fn transaction_bypasses_cache() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner.clone(), test_config());

        cached.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        cached.get(b"key").await.unwrap(); // populate cache

        // Transaction writes directly to inner
        let mut txn = cached.transaction().await.unwrap();
        txn.set(b"key".to_vec(), b"v2".to_vec());
        txn.commit().await.unwrap();

        // Cache still has v1 — transactions bypass the cache
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v1")), "cache should still have old value");

        // Direct inner read shows v2
        let v = inner.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v2")));
    }

    #[tokio::test]
    async fn disabled_cache_passes_through() {
        let inner = MemoryBackend::new();
        let cached = CachedBackend::new(inner.clone(), CacheConfig::disabled());

        cached.set(b"key".to_vec(), b"v1".to_vec()).await.unwrap();
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v1")));

        // Mutate inner directly — should be visible immediately (no cache)
        inner.set(b"key".to_vec(), b"v2".to_vec()).await.unwrap();
        let v = cached.get(b"key").await.unwrap();
        assert_eq!(v, Some(Bytes::from("v2")));
    }

    #[tokio::test]
    async fn config_validation() {
        // Zero entries
        let result = CacheConfig::builder().max_entries(0).build();
        assert!(result.is_err());

        // TTL too short
        let result = CacheConfig::builder().ttl(Duration::from_millis(500)).build();
        assert!(result.is_err());

        // Valid
        let result = CacheConfig::builder().max_entries(1).ttl(Duration::from_secs(1)).build();
        assert!(result.is_ok());
    }
}
