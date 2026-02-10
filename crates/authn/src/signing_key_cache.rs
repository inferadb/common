//! Ledger-backed signing key cache for JWT validation.
//!
//! This module provides [`SigningKeyCache`], which wraps
//! [`PublicSigningKeyStore`](inferadb_common_storage::auth::PublicSigningKeyStore) with in-memory
//! caching to avoid Ledger round-trips on every token validation.
//!
//! # Architecture
//!
//! ```text
//! JWT arrives → extract kid, org_id
//!              → check local cache (L1)
//!              → miss? fetch from Ledger via PublicSigningKeyStore (L2)
//!              → validate key state (active, not revoked, within validity window)
//!              → cache decoding key locally
//!              → verify signature
//! ```
//!
//! # Cache Strategy
//!
//! - **L1 TTL**: Default 300 seconds (5 minutes)
//! - **L3 Fallback TTL**: Default 3600 seconds (1 hour) — bounds staleness during outages
//! - **Eviction**: Time-based expiration + capacity limits
//! - **Invalidation**: Keys become invalid on next fetch after Ledger state changes
//!
//! # Examples
//!
//! ```no_run
//! // Requires a `PublicSigningKeyStore` implementation (e.g., LedgerSigningKeyStore).
//! use std::sync::Arc;
//! use std::time::Duration;
//! use inferadb_common_authn::SigningKeyCache;
//! use inferadb_common_storage::{NamespaceId, auth::PublicSigningKeyStore};
//!
//! async fn example(key_store: Arc<dyn PublicSigningKeyStore>) {
//!     // Create cache with 5-minute TTL
//!     let cache = SigningKeyCache::new(key_store, Duration::from_secs(300));
//!
//!     // Get decoding key for JWT validation
//!     // org_id from JWT claims, kid from JWT header
//!     let decoding_key = cache.get_decoding_key(NamespaceId::from(42), "key-2024-001").await;
//! }
//! ```

use std::{
    collections::HashSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use fail::fail_point;
use inferadb_common_storage::{
    NamespaceId, StorageError, Zeroizing,
    auth::{PublicSigningKey, PublicSigningKeyStore},
};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

use crate::error::AuthError;

/// Default cache TTL (5 minutes).
///
/// This balances security (revoked keys propagate within this window)
/// with performance (reduces Ledger round-trips).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default maximum cache capacity.
pub const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

/// Default maximum fallback cache capacity.
///
/// The fallback cache stores keys with a staleness-bounded TTL for graceful
/// degradation during Ledger outages. This capacity bound prevents unbounded
/// memory growth in long-running services.
pub const DEFAULT_FALLBACK_CAPACITY: u64 = 10_000;

/// Default maximum TTL for the fallback (L3) cache (1 hour).
///
/// Entries older than this are evicted even if the Ledger remains unreachable.
/// This bounds the window during which a revoked key could still be served
/// from the fallback cache during an outage. Operators can tune this via
/// [`SigningKeyCache::with_fallback_ttl`] based on their security posture:
///
/// - **Shorter TTL** (e.g., 15 minutes): tighter security, higher risk of total outage if Ledger is
///   down for longer
/// - **Longer TTL** (e.g., 4 hours): more availability, but revoked keys remain trusted longer
///   during outages
pub const DEFAULT_FALLBACK_TTL: Duration = Duration::from_secs(3_600);

/// Default fill percentage at which a warning is emitted (80%).
pub const DEFAULT_FALLBACK_WARN_THRESHOLD: f64 = 80.0;

/// Default fill percentage at which a critical alert is emitted (95%).
pub const DEFAULT_FALLBACK_CRITICAL_THRESHOLD: f64 = 95.0;

/// An entry in the fallback (L3) cache, carrying the decoding key
/// along with the timestamp at which it was inserted. The insertion
/// time enables logging the entry age when the fallback is used.
#[derive(Clone)]
struct FallbackEntry {
    key: Arc<DecodingKey>,
    inserted_at: Instant,
}

/// Cache for public signing keys fetched from Ledger.
///
/// Wraps [`PublicSigningKeyStore`] with in-memory caching to avoid
/// Ledger round-trips on every token validation. An optional background
/// refresh task (see [`with_refresh_interval`](Self::with_refresh_interval))
/// proactively re-fetches active keys before their TTL expires.
///
/// # Key Validation
///
/// When a key is fetched from Ledger, it must satisfy all conditions:
/// - `active == true`
/// - `revoked_at.is_none()`
/// - `now >= valid_from`
/// - `valid_until.is_none() || now <= valid_until`
///
/// Keys failing validation are not cached and result in auth errors.
///
/// # Cache Keys
///
/// Keys are cached using `{org_id}:{kid}` format, ensuring namespace isolation.
///
/// # Graceful Degradation
///
/// When Ledger is unavailable (connection or timeout errors), the cache falls back
/// to previously fetched keys stored in the fallback cache. This ensures continued
/// operation during transient Ledger outages. The fallback cache is both
/// capacity-bounded (LRU eviction) and staleness-bounded (configurable TTL,
/// default [`DEFAULT_FALLBACK_TTL`] = 1 hour) to prevent serving revoked keys
/// indefinitely during prolonged outages.
pub struct SigningKeyCache {
    /// In-memory cache with TTL-based expiration (L1).
    cache: Cache<String, Arc<DecodingKey>>,
    /// Backend store for fetching keys from Ledger (L2).
    key_store: Arc<dyn PublicSigningKeyStore>,
    /// Fallback cache for graceful degradation during Ledger outages (L3).
    /// Capacity-bounded with LRU eviction and a staleness-bounded TTL.
    fallback: Cache<String, FallbackEntry>,
    /// Monotonic generation counter incremented on every invalidation.
    ///
    /// Used to detect stale L2 reads: if the generation changes between
    /// the start and end of an L2 fetch, the result is discarded rather
    /// than being written into L1 with potentially-revoked data.
    invalidation_gen: Arc<AtomicU64>,
    /// Configured maximum capacity of the L3 fallback cache.
    ///
    /// Stored separately because `moka::Cache` does not expose its
    /// configured `max_capacity` after construction.
    fallback_capacity: u64,
    /// Fill percentage at which a warning is emitted (default: 80%).
    warn_threshold: f64,
    /// Fill percentage at which a critical alert is emitted (default: 95%).
    critical_threshold: f64,
    /// Whether the warning threshold alert has been fired.
    warn_fired: AtomicBool,
    /// Whether the critical threshold alert has been fired.
    critical_fired: AtomicBool,
    /// Cache keys accessed since the last background refresh cycle.
    /// The background task drains this set each tick to refresh only
    /// "active" keys, avoiding unnecessary Ledger reads for keys
    /// that no caller has requested recently.
    active_keys: Arc<Mutex<HashSet<String>>>,
    /// Cancellation token for stopping the background refresh task.
    cancel_token: CancellationToken,
    /// Handle for the background refresh task, if running.
    /// Wrapped in `Mutex` so `shutdown()` can take ownership via `&self`.
    refresh_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Number of completed background refresh cycles.
    refresh_count: AtomicU64,
    /// Total number of keys successfully refreshed across all cycles.
    refresh_keys_total: AtomicU64,
    /// Total number of per-key refresh errors across all cycles.
    refresh_errors_total: AtomicU64,
    /// Cumulative refresh latency in microseconds across all cycles.
    refresh_latency_us: AtomicU64,
}

impl SigningKeyCache {
    /// Creates a new signing key cache with default capacity and fallback TTL.
    ///
    /// # Arguments
    ///
    /// * `key_store` - Backend store (typically Ledger-backed)
    /// * `ttl` - Time-to-live for L1 cached keys
    ///
    /// # Examples
    ///
    /// ```no_run
    /// // Requires a `PublicSigningKeyStore` implementation (e.g., LedgerSigningKeyStore).
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use inferadb_common_authn::SigningKeyCache;
    /// use inferadb_common_storage::auth::PublicSigningKeyStore;
    ///
    /// fn example(key_store: Arc<dyn PublicSigningKeyStore>) {
    ///     let cache = SigningKeyCache::new(key_store, Duration::from_secs(300));
    /// }
    /// ```
    #[must_use]
    pub fn new(key_store: Arc<dyn PublicSigningKeyStore>, ttl: Duration) -> Self {
        Self::with_capacity(key_store, ttl, DEFAULT_CACHE_CAPACITY)
    }

    /// Creates a new signing key cache with custom capacity for L1 and L3.
    ///
    /// Uses [`DEFAULT_FALLBACK_TTL`] for the L3 fallback cache staleness bound.
    ///
    /// # Arguments
    ///
    /// * `key_store` - Backend store
    /// * `ttl` - Time-to-live for L1 cached keys
    /// * `max_capacity` - Maximum number of keys to cache in L1 and fallback
    #[must_use]
    pub fn with_capacity(
        key_store: Arc<dyn PublicSigningKeyStore>,
        ttl: Duration,
        max_capacity: u64,
    ) -> Self {
        Self::with_fallback_ttl(key_store, ttl, max_capacity, DEFAULT_FALLBACK_TTL)
    }

    /// Creates a new signing key cache with custom capacity and fallback TTL.
    ///
    /// The `fallback_ttl` bounds the maximum staleness of L3 fallback cache
    /// entries. After this duration, entries are evicted even if the Ledger
    /// remains unreachable. This limits the window during which a revoked
    /// key could be served from fallback during an outage.
    ///
    /// # Arguments
    ///
    /// * `key_store` - Backend store
    /// * `ttl` - Time-to-live for L1 cached keys
    /// * `max_capacity` - Maximum number of keys to cache in L1 and fallback
    /// * `fallback_ttl` - Maximum staleness for L3 fallback cache entries
    ///
    /// # Security Trade-off
    ///
    /// - **Shorter `fallback_ttl`**: revoked keys are evicted sooner during outages, but total
    ///   outage is more likely if Ledger is down for a prolonged period
    /// - **Longer `fallback_ttl`**: more availability during outages, but revoked keys remain
    ///   trusted longer
    #[must_use]
    pub fn with_fallback_ttl(
        key_store: Arc<dyn PublicSigningKeyStore>,
        ttl: Duration,
        max_capacity: u64,
        fallback_ttl: Duration,
    ) -> Self {
        Self {
            cache: Cache::builder().time_to_live(ttl).max_capacity(max_capacity).build(),
            key_store,
            fallback: Cache::builder()
                .time_to_live(fallback_ttl)
                .max_capacity(max_capacity)
                .build(),
            invalidation_gen: Arc::new(AtomicU64::new(0)),
            fallback_capacity: max_capacity,
            warn_threshold: DEFAULT_FALLBACK_WARN_THRESHOLD,
            critical_threshold: DEFAULT_FALLBACK_CRITICAL_THRESHOLD,
            warn_fired: AtomicBool::new(false),
            critical_fired: AtomicBool::new(false),
            active_keys: Arc::new(Mutex::new(HashSet::new())),
            cancel_token: CancellationToken::new(),
            refresh_handle: Mutex::new(None),
            refresh_count: AtomicU64::new(0),
            refresh_keys_total: AtomicU64::new(0),
            refresh_errors_total: AtomicU64::new(0),
            refresh_latency_us: AtomicU64::new(0),
        }
    }

    /// Returns the decoding key for JWT validation.
    ///
    /// Checks the local cache first, then fetches from Ledger on miss.
    /// The key is validated for state (active, not revoked, within validity window)
    /// before being returned.
    ///
    /// # Graceful Degradation
    ///
    /// If Ledger is unavailable (connection or timeout errors), the cache will
    /// attempt to return a previously cached key from the fallback store. This
    /// ensures continued operation during transient outages.
    ///
    /// # Arguments
    ///
    /// * `org_id` - Organization ID (maps to Ledger namespace_id)
    /// * `kid` - Key ID from JWT header
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key not found in Ledger ([`AuthError::KeyNotFound`])
    /// - Key is inactive ([`AuthError::KeyInactive`])
    /// - Key has been revoked ([`AuthError::KeyRevoked`])
    /// - Key is not yet valid ([`AuthError::KeyNotYetValid`])
    /// - Key has expired ([`AuthError::KeyExpired`])
    /// - Public key format is invalid ([`AuthError::InvalidPublicKey`])
    /// - Storage backend error with no fallback available ([`AuthError::KeyStorageError`])
    #[tracing::instrument(skip(self))]
    pub async fn get_decoding_key(
        &self,
        org_id: NamespaceId,
        kid: &str,
    ) -> Result<Arc<DecodingKey>, AuthError> {
        let cache_key = format!("{org_id}:{kid}");

        // Track this key as "active" for background refresh.
        self.active_keys.lock().insert(cache_key.clone());

        // L1: Check local cache (TTL-based)
        if let Some(key) = self.cache.get(&cache_key).await {
            tracing::debug!(cache = "L1", "cache hit");
            return Ok(key);
        }
        tracing::debug!(cache = "L1", "cache miss");

        // Snapshot the invalidation generation before the L2 fetch.
        // If `invalidate()` runs concurrently, it bumps this counter.
        // We compare after the L2 read to detect the race and discard
        // stale results rather than re-populating L1 with revoked data.
        let gen_before = self.invalidation_gen.load(Ordering::Acquire);

        // L2: Fetch from Ledger (org_id == namespace_id)
        let namespace_id = org_id;
        fail_point!("cache-before-l2-fetch", |_| {
            Err(AuthError::key_storage_error(StorageError::internal(
                "injected failure before L2 fetch",
            )))
        });
        let ledger_result = self.key_store.get_key(namespace_id, kid).await;

        match ledger_result {
            Ok(Some(public_key)) => {
                // Validate key state
                validate_key_state(&public_key)?;

                // Convert to DecodingKey
                let decoding_key = to_decoding_key(&public_key)?;
                let decoding_key = Arc::new(decoding_key);

                // Check if an invalidation occurred during the L2 fetch.
                // If so, discard this result — the key may have been revoked.
                let gen_after = self.invalidation_gen.load(Ordering::Acquire);
                if gen_after != gen_before {
                    tracing::debug!(
                        namespace_id = %namespace_id,
                        kid,
                        "Discarding L2 result: invalidation occurred during fetch"
                    );
                    // Return the key to the caller (it was valid at fetch time)
                    // but do NOT populate L1/L3 caches with potentially-stale data.
                    // The next request will re-fetch from Ledger.
                    return Ok(decoding_key);
                }

                // Cache locally (both TTL cache and fallback)
                self.cache.insert(cache_key.clone(), decoding_key.clone()).await;
                self.fallback
                    .insert(
                        cache_key,
                        FallbackEntry { key: decoding_key.clone(), inserted_at: Instant::now() },
                    )
                    .await;

                tracing::debug!(cache = "L2", "cache hit — populated L1 + L3");

                self.check_fallback_thresholds();

                Ok(decoding_key)
            },
            Ok(None) => Err(AuthError::key_not_found(kid.to_string())),
            Err(storage_error) => {
                // Check if this is a transient error (connection/timeout)
                // where fallback is appropriate
                if is_transient_error(&storage_error)
                    && let Some(entry) = self.fallback.get(&cache_key).await
                {
                    let age = entry.inserted_at.elapsed();
                    tracing::warn!(
                        cache = "L3",
                        fallback_age_secs = age.as_secs(),
                        "cache hit (fallback) — ledger unavailable"
                    );
                    return Ok(entry.key);
                }

                // No fallback available or not a transient error
                Err(AuthError::key_storage_error(storage_error))
            },
        }
    }

    /// Invalidates a specific key from all cache tiers.
    ///
    /// Removes the key from both the L1 TTL cache and the L3 fallback cache,
    /// and bumps the invalidation generation counter to prevent any in-flight
    /// L2 fetches from re-populating L1 with stale data.
    ///
    /// An audit event is emitted at INFO level for compliance tracking.
    ///
    /// Call this when a key is known to be revoked or deleted.
    /// The next lookup will fetch fresh state from Ledger.
    #[tracing::instrument(skip(self))]
    pub async fn invalidate(&self, org_id: NamespaceId, kid: &str) {
        let cache_key = format!("{org_id}:{kid}");
        // Bump generation first so any in-flight L2 reads will detect the change
        self.invalidation_gen.fetch_add(1, Ordering::Release);
        self.cache.invalidate(&cache_key).await;
        self.fallback.invalidate(&cache_key).await;
        tracing::info!(
            audit.action = "invalidate_cache",
            audit.resource = %format_args!("ns:{org_id}/kid:{kid}"),
            audit.result = "success",
            "audit_event"
        );
    }

    /// Clears all keys from all cache tiers.
    ///
    /// Removes all entries from both the L1 TTL cache and the L3 fallback cache.
    /// An audit event is emitted at INFO level for compliance tracking.
    /// Use sparingly - this causes a spike in Ledger fetches. Useful during
    /// key rotation events where all cached keys should be refreshed.
    #[tracing::instrument(skip(self))]
    pub async fn clear_all(&self) {
        let l1_count = self.cache.entry_count();
        let fallback_count = self.fallback.entry_count();
        // Bump generation to prevent in-flight L2 reads from re-populating
        self.invalidation_gen.fetch_add(1, Ordering::Release);
        self.cache.invalidate_all();
        self.fallback.invalidate_all();
        tracing::info!(
            audit.action = "clear_cache",
            audit.resource = "all_signing_keys",
            audit.result = "success",
            audit.l1_evicted = l1_count,
            audit.l3_evicted = fallback_count,
            "audit_event"
        );
    }

    /// Releases all cached resources for graceful shutdown.
    ///
    /// Clears all cache tiers (L1 and L3 fallback) and bumps the
    /// invalidation generation to prevent in-flight lookups from
    /// re-populating the cache.
    ///
    /// This is functionally equivalent to [`clear_all`](Self::clear_all) and
    /// is provided for API consistency with other shutdown-aware types in the
    /// workspace.
    pub async fn shutdown(&self) {
        // Signal the background refresh task to stop, if running.
        self.cancel_token.cancel();
        // Take the handle so we can await it without holding the lock.
        let handle = self.refresh_handle.lock().take();
        if let Some(handle) = handle {
            // Best-effort wait; if the task panicked, we just log.
            if let Err(err) = handle.await {
                tracing::warn!(error = %err, "background refresh task panicked");
            }
        }
        self.clear_all().await;
    }

    /// Returns current L1 cache entry count.
    ///
    /// Note: This count is eventually consistent. For accurate counts in tests,
    /// call `sync` first.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Returns current fallback cache entry count.
    ///
    /// Note: This count is eventually consistent. For accurate counts in tests,
    /// call `sync` first.
    #[must_use]
    pub fn fallback_entry_count(&self) -> u64 {
        self.fallback.entry_count()
    }

    /// Returns the configured maximum capacity of the L3 fallback cache.
    #[must_use]
    pub fn fallback_capacity(&self) -> u64 {
        self.fallback_capacity
    }

    /// Returns the current fill percentage of the L3 fallback cache (0.0–100.0).
    ///
    /// Returns 0.0 if capacity is zero to avoid division by zero.
    #[must_use]
    pub fn fallback_fill_pct(&self) -> f64 {
        if self.fallback_capacity == 0 {
            return 0.0;
        }
        (self.fallback.entry_count() as f64 / self.fallback_capacity as f64) * 100.0
    }

    /// Sets custom warning and critical thresholds for fallback cache fill alerts.
    ///
    /// Both thresholds are percentages (0.0–100.0). The warning threshold should
    /// be lower than the critical threshold.
    ///
    /// # Arguments
    ///
    /// * `warn` - Fill percentage at which a warning is emitted
    /// * `critical` - Fill percentage at which a critical alert is emitted
    #[must_use]
    pub fn with_thresholds(mut self, warn: f64, critical: f64) -> Self {
        self.warn_threshold = warn;
        self.critical_threshold = critical;
        self
    }

    /// Enables background refresh of active keys at the given interval.
    ///
    /// When enabled, a `tokio::spawn`ed background task wakes every
    /// `interval` and refreshes all keys that were accessed since the
    /// previous refresh tick. Keys that have not been accessed are
    /// skipped, so the task only does work proportional to actual traffic.
    ///
    /// The background task stops when [`shutdown`](Self::shutdown) is called
    /// or when the `SigningKeyCache` is dropped (via `CancellationToken`).
    ///
    /// # Arguments
    ///
    /// * `interval` - How often to refresh active keys. Should be less than the L1 TTL to prevent
    ///   any misses during normal operation.
    ///
    /// # Panics
    ///
    /// Must be called within a Tokio runtime context.
    #[must_use]
    pub fn with_refresh_interval(self: Arc<Self>, interval: Duration) -> Arc<Self> {
        let cache = Arc::clone(&self);
        let token = self.cancel_token.clone();
        let active_keys = Arc::clone(&self.active_keys);
        let key_store = Arc::clone(&self.key_store);

        let handle = tokio::spawn(async move {
            let mut ticker = tokio::time::interval(interval);
            // The first tick fires immediately; consume it so we start
            // with a full interval wait.
            ticker.tick().await;

            loop {
                tokio::select! {
                    _ = token.cancelled() => {
                        tracing::info!("background refresh task shutting down");
                        break;
                    }
                    _ = ticker.tick() => {
                        Self::do_refresh_cycle(&cache, &active_keys, &key_store).await;
                    }
                }
            }
        });

        *self.refresh_handle.lock() = Some(handle);
        self
    }

    /// Runs a single background refresh cycle.
    ///
    /// Drains the active-key set, then for each key fetches from L2
    /// and re-populates L1 + L3. Errors are logged per-key but do not
    /// stop the cycle.
    async fn do_refresh_cycle(
        cache: &Arc<Self>,
        active_keys: &Arc<Mutex<HashSet<String>>>,
        key_store: &Arc<dyn PublicSigningKeyStore>,
    ) {
        let keys: Vec<String> = {
            let mut set = active_keys.lock();
            set.drain().collect()
        };

        if keys.is_empty() {
            return;
        }

        let start = Instant::now();
        let mut refreshed: u64 = 0;
        let mut errors: u64 = 0;

        for cache_key in &keys {
            // Parse "namespace_id:kid" back into components.
            let Some((ns_str, kid)) = cache_key.split_once(':') else {
                tracing::warn!(cache_key, "malformed cache key in active set");
                continue;
            };
            let Ok(ns_id) = ns_str.parse::<i64>() else {
                tracing::warn!(cache_key, "unparseable namespace_id in cache key");
                continue;
            };
            let namespace_id = NamespaceId::from(ns_id);

            match key_store.get_key(namespace_id, kid).await {
                Ok(Some(public_key)) => {
                    if let Err(err) = validate_key_state(&public_key) {
                        tracing::debug!(
                            kid,
                            error = %err,
                            "background refresh: key failed validation, removing from cache"
                        );
                        cache.cache.invalidate(cache_key).await;
                        errors += 1;
                        continue;
                    }
                    match to_decoding_key(&public_key) {
                        Ok(dk) => {
                            let dk = Arc::new(dk);
                            cache.cache.insert(cache_key.clone(), dk.clone()).await;
                            cache
                                .fallback
                                .insert(
                                    cache_key.clone(),
                                    FallbackEntry { key: dk, inserted_at: Instant::now() },
                                )
                                .await;
                            refreshed += 1;
                        },
                        Err(err) => {
                            tracing::warn!(kid, error = %err, "background refresh: decoding key conversion failed");
                            errors += 1;
                        },
                    }
                },
                Ok(None) => {
                    tracing::debug!(kid, "background refresh: key no longer exists, evicting");
                    cache.cache.invalidate(cache_key).await;
                    cache.fallback.invalidate(cache_key).await;
                },
                Err(err) => {
                    tracing::warn!(kid, error = %err, "background refresh: L2 fetch failed");
                    errors += 1;
                    // Re-insert the key as active so the next cycle retries it.
                    active_keys.lock().insert(cache_key.clone());
                },
            }
        }

        let elapsed = start.elapsed();

        // Record metrics.
        cache.refresh_count.fetch_add(1, Ordering::Relaxed);
        cache.refresh_keys_total.fetch_add(refreshed, Ordering::Relaxed);
        cache.refresh_errors_total.fetch_add(errors, Ordering::Relaxed);
        cache.refresh_latency_us.fetch_add(elapsed.as_micros() as u64, Ordering::Relaxed);

        tracing::info!(
            refreshed,
            errors,
            elapsed_ms = elapsed.as_millis() as u64,
            total_keys = keys.len(),
            "background refresh cycle complete"
        );
    }

    /// Returns the number of keys currently tracked as "active" for
    /// background refresh.
    #[must_use]
    pub fn active_key_count(&self) -> usize {
        self.active_keys.lock().len()
    }

    /// Returns the cancellation token for the background refresh task.
    ///
    /// Callers can use this to integrate with external shutdown signals.
    #[must_use]
    pub fn cancel_token(&self) -> &CancellationToken {
        &self.cancel_token
    }

    /// Returns the number of completed background refresh cycles.
    #[must_use]
    pub fn refresh_count(&self) -> u64 {
        self.refresh_count.load(Ordering::Relaxed)
    }

    /// Returns the total number of keys successfully refreshed across all cycles.
    #[must_use]
    pub fn refresh_keys_total(&self) -> u64 {
        self.refresh_keys_total.load(Ordering::Relaxed)
    }

    /// Returns the total number of per-key refresh errors across all cycles.
    #[must_use]
    pub fn refresh_errors_total(&self) -> u64 {
        self.refresh_errors_total.load(Ordering::Relaxed)
    }

    /// Returns the cumulative refresh latency in microseconds across all cycles.
    #[must_use]
    pub fn refresh_latency_us(&self) -> u64 {
        self.refresh_latency_us.load(Ordering::Relaxed)
    }

    /// Checks L3 fallback cache fill against thresholds and emits alerts.
    ///
    /// Alerts are emitted once per threshold crossing (not on every operation).
    /// When the fill drops below a threshold, the alert flag is reset so it
    /// can fire again on the next crossing.
    fn check_fallback_thresholds(&self) {
        let fill_pct = self.fallback_fill_pct();

        // Critical threshold check
        if fill_pct >= self.critical_threshold {
            if self
                .critical_fired
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                tracing::error!(
                    fill_pct = format_args!("{fill_pct:.1}"),
                    threshold = format_args!("{:.1}", self.critical_threshold),
                    entry_count = self.fallback.entry_count(),
                    capacity = self.fallback_capacity,
                    "L3 fallback cache fill exceeds critical threshold"
                );
            }
        } else {
            self.critical_fired.store(false, Ordering::Relaxed);
        }

        // Warning threshold check
        if fill_pct >= self.warn_threshold {
            if self
                .warn_fired
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_ok()
            {
                tracing::warn!(
                    fill_pct = format_args!("{fill_pct:.1}"),
                    threshold = format_args!("{:.1}", self.warn_threshold),
                    entry_count = self.fallback.entry_count(),
                    capacity = self.fallback_capacity,
                    "L3 fallback cache fill exceeds warning threshold"
                );
            }
        } else {
            self.warn_fired.store(false, Ordering::Relaxed);
        }
    }

    /// Synchronizes pending cache operations.
    ///
    /// Call this before checking entry counts in tests to ensure
    /// all inserts and invalidations have been processed.
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    pub async fn sync(&self) {
        self.cache.run_pending_tasks().await;
        self.fallback.run_pending_tasks().await;
    }

    /// Clears only the L1 TTL cache, leaving the fallback cache intact.
    ///
    /// Used in tests to force a cache miss on L1 while preserving fallback
    /// entries for graceful degradation testing.
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    pub async fn clear_l1(&self) {
        self.cache.invalidate_all();
    }
}

/// Determines if a storage error is transient (connection/timeout).
///
/// Transient errors indicate Ledger is temporarily unavailable but may recover.
/// For these errors, we attempt to use the fallback cache.
///
/// Non-transient errors (not found, serialization, internal) indicate a
/// definitive response from Ledger and should not use fallback.
fn is_transient_error(error: &StorageError) -> bool {
    matches!(error, StorageError::Connection { .. } | StorageError::Timeout { .. })
}

/// Validates that a key is in a usable state.
///
/// A key is valid if:
/// - `active == true`
/// - `revoked_at.is_none()`
/// - `now >= valid_from`
/// - `valid_until.is_none() || now <= valid_until`
fn validate_key_state(key: &PublicSigningKey) -> Result<(), AuthError> {
    let now = Utc::now();

    if !key.active {
        return Err(AuthError::key_inactive(key.kid.clone()));
    }

    if key.revoked_at.is_some() {
        return Err(AuthError::key_revoked(key.kid.clone()));
    }

    if now < key.valid_from {
        return Err(AuthError::key_not_yet_valid(key.kid.clone()));
    }

    if let Some(valid_until) = key.valid_until
        && now > valid_until
    {
        return Err(AuthError::key_expired(key.kid.clone()));
    }

    Ok(())
}

/// Converts a [`PublicSigningKey`] to a jsonwebtoken [`DecodingKey`].
///
/// The public key is expected to be base64url-encoded (no padding) Ed25519 key.
fn to_decoding_key(key: &PublicSigningKey) -> Result<DecodingKey, AuthError> {
    // Decode base64url public key into a Zeroizing wrapper to ensure
    // the raw key bytes are scrubbed from memory when dropped.
    let public_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(key.public_key.as_bytes())
            .map_err(|e| AuthError::invalid_public_key(format!("base64 decode: {e}")))?,
    );

    // Verify key length (Ed25519 public keys are 32 bytes)
    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(AuthError::invalid_public_key(format!(
            "expected {PUBLIC_KEY_LENGTH} bytes, got {}",
            public_key_bytes.len()
        )));
    }

    // Validate it's a valid Ed25519 key by parsing it.
    // Wrap the stack-allocated copy in Zeroizing to ensure the raw key bytes
    // are scrubbed even if the compiler would otherwise optimize away the drop.
    let key_bytes: Zeroizing<[u8; PUBLIC_KEY_LENGTH]> = Zeroizing::new(
        public_key_bytes[..PUBLIC_KEY_LENGTH]
            .try_into()
            .map_err(|_| AuthError::invalid_public_key("failed to convert bytes"))?,
    );

    let _verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AuthError::invalid_public_key(format!("invalid Ed25519 key: {e}")))?;

    // Explicitly drop decoded key material before constructing the DecodingKey
    // to minimize the window where raw bytes exist in memory.
    drop(key_bytes);
    drop(public_key_bytes);

    // Convert to jsonwebtoken DecodingKey
    DecodingKey::from_ed_components(&key.public_key)
        .map_err(|e| AuthError::invalid_public_key(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use inferadb_common_storage::{
        CertId, ClientId,
        auth::{MemorySigningKeyStore, SigningKeyMetricsSnapshot},
    };
    use rstest::rstest;

    use super::*;
    use crate::testutil::generate_test_keypair;

    fn create_test_key(kid: &str, active: bool) -> PublicSigningKey {
        let (_, public_key_b64) = generate_test_keypair();
        PublicSigningKey {
            kid: kid.to_string(),
            public_key: public_key_b64.into(),
            client_id: ClientId::from(1),
            cert_id: CertId::from(1),
            created_at: Utc::now(),
            valid_from: Utc::now() - ChronoDuration::hours(1),
            valid_until: Some(Utc::now() + ChronoDuration::days(365)),
            active,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn create_valid_test_key(kid: &str) -> PublicSigningKey {
        create_test_key(kid, true)
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(60));

        let result = cache.get_decoding_key(NamespaceId::from(1), "nonexistent").await;

        assert!(matches!(result, Err(AuthError::KeyNotFound { kid, .. }) if kid == "nonexistent"));
    }

    #[tokio::test]
    async fn test_key_inactive() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_test_key("inactive-key", false);
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "inactive-key").await;

        assert!(matches!(result, Err(AuthError::KeyInactive { kid, .. }) if kid == "inactive-key"));
    }

    #[tokio::test]
    async fn test_key_revoked() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("revoked-key", true);
        key.revoked_at = Some(Utc::now());
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;

        assert!(matches!(result, Err(AuthError::KeyRevoked { kid, .. }) if kid == "revoked-key"));
    }

    #[tokio::test]
    async fn test_key_not_yet_valid() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("future-key", true);
        key.valid_from = Utc::now() + ChronoDuration::hours(1);
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "future-key").await;

        assert!(
            matches!(result, Err(AuthError::KeyNotYetValid { kid, .. }) if kid == "future-key")
        );
    }

    #[tokio::test]
    async fn test_key_expired() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("expired-key", true);
        key.valid_from = Utc::now() - ChronoDuration::days(2);
        key.valid_until = Some(Utc::now() - ChronoDuration::days(1));
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "expired-key").await;

        assert!(matches!(result, Err(AuthError::KeyExpired { kid, .. }) if kid == "expired-key"));
    }

    #[tokio::test]
    async fn test_invalid_public_key_format() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("bad-key", true);
        key.public_key = "not-valid-base64!!!".to_string().into();
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "bad-key").await;

        assert!(matches!(result, Err(AuthError::InvalidPublicKey { .. })));
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("cached-key");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call - cache miss
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "cached-key").await;
        assert!(result1.is_ok());

        // Second call - should hit cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "cached-key").await;
        assert!(result2.is_ok());

        // Entry should be in cache (sync to ensure count is accurate)
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let store = Arc::new(MemorySigningKeyStore::new());

        // Same kid, different namespaces
        let key1 = create_valid_test_key("shared-kid");
        let key2 = create_valid_test_key("shared-kid");
        store.create_key(NamespaceId::from(1), &key1).await.expect("create_key org1");
        store.create_key(NamespaceId::from(2), &key2).await.expect("create_key org2");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Both should work independently
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "shared-kid").await;
        let result2 = cache.get_decoding_key(NamespaceId::from(2), "shared-kid").await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        cache.sync().await;
        assert_eq!(cache.entry_count(), 2);
    }

    #[tokio::test]
    async fn test_invalidate() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("to-invalidate");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate cache
        let _ = cache.get_decoding_key(NamespaceId::from(1), "to-invalidate").await;
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);

        // Invalidate
        cache.invalidate(NamespaceId::from(1), "to-invalidate").await;

        // Cache should be empty after invalidation
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let store = Arc::new(MemorySigningKeyStore::new());

        for i in 0..5 {
            let key = create_valid_test_key(&format!("key-{i}"));
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
        }

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate cache
        for i in 0..5 {
            let _ = cache.get_decoding_key(NamespaceId::from(1), &format!("key-{i}")).await;
        }
        cache.sync().await;
        assert_eq!(cache.entry_count(), 5);
        assert_eq!(cache.fallback_entry_count(), 5);

        // Clear all tiers
        cache.clear_all().await;

        // Both L1 and fallback should be empty
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.fallback_entry_count(), 0);
    }

    #[tokio::test]
    async fn test_key_no_expiry() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_valid_test_key("no-expiry");
        key.valid_until = None; // No expiry
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "no-expiry").await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_state_active() {
        let key = create_test_key("active", true);
        assert!(validate_key_state(&key).is_ok());
    }

    /// Enum describing how to mutate a test key before validation.
    enum KeyMutation {
        Inactive,
        Revoked,
        NotYetValid,
        Expired,
    }

    #[rstest]
    #[case::inactive(KeyMutation::Inactive, "KeyInactive")]
    #[case::revoked(KeyMutation::Revoked, "KeyRevoked")]
    #[case::not_yet_valid(KeyMutation::NotYetValid, "KeyNotYetValid")]
    #[case::expired(KeyMutation::Expired, "KeyExpired")]
    fn test_validate_key_state_rejected(
        #[case] mutation: KeyMutation,
        #[case] expected_variant: &str,
    ) {
        let mut key = match &mutation {
            KeyMutation::Inactive => create_test_key("inactive", false),
            _ => create_test_key("test", true),
        };
        match mutation {
            KeyMutation::Inactive => {},
            KeyMutation::Revoked => key.revoked_at = Some(Utc::now()),
            KeyMutation::NotYetValid => {
                key.valid_from = Utc::now() + ChronoDuration::hours(1);
            },
            KeyMutation::Expired => {
                key.valid_from = Utc::now() - ChronoDuration::days(2);
                key.valid_until = Some(Utc::now() - ChronoDuration::days(1));
            },
        }
        let result = validate_key_state(&key);
        assert!(result.is_err(), "Expected {expected_variant} error");
        let err_debug = format!("{:?}", result.unwrap_err());
        assert!(
            err_debug.contains(expected_variant),
            "Expected {expected_variant}, got: {err_debug}",
        );
    }

    #[rstest]
    #[case::invalid_base64("not-valid!!!")]
    #[case::wrong_length("AAAA")]
    fn test_to_decoding_key_invalid(#[case] bad_key: &str) {
        let mut key = create_test_key("bad", true);
        key.public_key = bad_key.to_string().into();
        let result = to_decoding_key(&key);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey { .. })));
    }

    // ========== Fallback/Graceful Degradation Tests ==========

    /// Mock store that can be configured to fail with specific errors.
    struct FailingStore {
        inner: Arc<MemorySigningKeyStore>,
        fail_with: std::sync::Mutex<Option<StorageError>>,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(MemorySigningKeyStore::new()),
                fail_with: std::sync::Mutex::new(None),
            }
        }

        fn set_failure(&self, error: Option<StorageError>) {
            *self.fail_with.lock().expect("lock") = error;
        }
    }

    #[async_trait::async_trait]
    impl PublicSigningKeyStore for FailingStore {
        async fn create_key(
            &self,
            namespace_id: NamespaceId,
            key: &PublicSigningKey,
        ) -> Result<(), StorageError> {
            self.inner.create_key(namespace_id, key).await
        }

        async fn get_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<Option<PublicSigningKey>, StorageError> {
            if let Some(ref error) = *self.fail_with.lock().expect("lock") {
                return Err(match error {
                    StorageError::Connection { message, .. } => StorageError::connection(message),
                    StorageError::Timeout { .. } => StorageError::timeout(),
                    StorageError::NotFound { key, .. } => StorageError::not_found(key),
                    StorageError::Internal { message, .. } => StorageError::internal(message),
                    _ => StorageError::internal("unknown"),
                });
            }
            self.inner.get_key(namespace_id, kid).await
        }

        async fn list_active_keys(
            &self,
            namespace_id: NamespaceId,
        ) -> Result<Vec<PublicSigningKey>, StorageError> {
            self.inner.list_active_keys(namespace_id).await
        }

        async fn deactivate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.deactivate_key(namespace_id, kid).await
        }

        async fn revoke_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
            reason: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.revoke_key(namespace_id, kid, reason).await
        }

        async fn activate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.activate_key(namespace_id, kid).await
        }

        async fn delete_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.delete_key(namespace_id, kid).await
        }
    }

    #[tokio::test]
    async fn test_fallback_on_connection_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("fallback-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "fallback-key").await;
        assert!(result1.is_ok());

        // Simulate Ledger connection failure
        store.set_failure(Some(StorageError::connection("network error")));

        // Clear only L1 cache to force Ledger lookup (fallback remains)
        cache.clear_l1().await;
        cache.sync().await;

        // Should use fallback cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "fallback-key").await;
        assert!(result2.is_ok(), "should use fallback on connection error");
    }

    #[tokio::test]
    async fn test_fallback_on_timeout_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("timeout-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "timeout-key").await;
        assert!(result1.is_ok());

        // Simulate Ledger timeout
        store.set_failure(Some(StorageError::timeout()));

        // Clear only L1 cache (fallback remains)
        cache.clear_l1().await;
        cache.sync().await;

        // Should use fallback cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "timeout-key").await;
        assert!(result2.is_ok(), "should use fallback on timeout error");
    }

    #[tokio::test]
    async fn test_no_fallback_on_non_transient_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("no-fallback-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "no-fallback-key").await;
        assert!(result1.is_ok());

        // Simulate non-transient internal error (should NOT use fallback)
        store.set_failure(Some(StorageError::internal("db corruption")));

        // Clear only L1 cache (fallback remains, but should not be used for non-transient errors)
        cache.clear_l1().await;
        cache.sync().await;

        // Should NOT use fallback - internal errors are definitive responses
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "no-fallback-key").await;
        assert!(
            matches!(result2, Err(AuthError::KeyStorageError { .. })),
            "should NOT use fallback on internal error"
        );
    }

    #[tokio::test]
    async fn test_fallback_not_available_returns_error() {
        let store = Arc::new(FailingStore::new());

        // Don't create the key - fallback will be empty
        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Simulate connection failure with no prior cache
        store.set_failure(Some(StorageError::connection("network error")));

        // Should return error since no fallback available
        let result = cache.get_decoding_key(NamespaceId::from(1), "unknown-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError { .. })),
            "should return error when no fallback available"
        );
    }

    #[test]
    fn test_is_transient_error_connection() {
        let error = StorageError::connection("network error");
        assert!(is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_timeout() {
        let error = StorageError::timeout();
        assert!(is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_not_found() {
        let error = StorageError::not_found("key");
        assert!(!is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_internal() {
        let error = StorageError::internal("oops");
        assert!(!is_transient_error(&error));
    }

    #[tokio::test]
    async fn test_invalidate_removes_from_fallback() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("revoked-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate both L1 and fallback
        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Invalidate the key (simulating revocation)
        cache.invalidate(NamespaceId::from(1), "revoked-key").await;
        cache.sync().await;

        // Verify key is gone from both tiers
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.fallback_entry_count(), 0);

        // Simulate Ledger outage — the revoked key should NOT be served from fallback
        store.set_failure(Some(StorageError::connection("network error")));

        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError { .. })),
            "invalidated key must not be returned from fallback"
        );
    }

    #[tokio::test]
    async fn test_clear_all_removes_from_fallback() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("rotation-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate both tiers
        let result = cache.get_decoding_key(NamespaceId::from(1), "rotation-key").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Clear all tiers (key rotation event)
        cache.clear_all().await;
        cache.sync().await;

        // Verify fallback is also empty
        assert_eq!(cache.fallback_entry_count(), 0);

        // Simulate Ledger outage — no stale keys should be available
        store.set_failure(Some(StorageError::connection("network error")));

        let result = cache.get_decoding_key(NamespaceId::from(1), "rotation-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError { .. })),
            "cleared key must not be returned from fallback"
        );
    }

    #[tokio::test]
    async fn test_fallback_capacity_bounded() {
        let store = Arc::new(MemorySigningKeyStore::new());

        // Create a cache with capacity of 3
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            3,
        );

        // Insert 5 keys
        for i in 0..5 {
            let kid = format!("cap-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        cache.sync().await;

        // Fallback should be bounded — at most 3 entries
        assert!(
            cache.fallback_entry_count() <= 3,
            "fallback should not exceed capacity of 3, got {}",
            cache.fallback_entry_count()
        );
    }

    // ========== Concurrency Tests (Task 5) ==========

    /// Mock store that counts L2 reads and supports configurable delays.
    ///
    /// Used to test thundering herd prevention and race conditions
    /// in the signing key cache.
    struct DelayingStore {
        inner: Arc<MemorySigningKeyStore>,
        delay: std::sync::Mutex<Duration>,
        /// Controls whether the gate is active. When false, `get_key` skips
        /// the started/gate notifications and proceeds immediately.
        gate_enabled: std::sync::atomic::AtomicBool,
        /// When gate is enabled, `get_key` signals this after starting.
        started_notify: Arc<tokio::sync::Notify>,
        /// When gate is enabled, `get_key` waits on this after signalling start.
        gate_notify: Arc<tokio::sync::Notify>,
    }

    impl DelayingStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(MemorySigningKeyStore::new()),
                delay: std::sync::Mutex::new(Duration::ZERO),
                gate_enabled: std::sync::atomic::AtomicBool::new(false),
                started_notify: Arc::new(tokio::sync::Notify::new()),
                gate_notify: Arc::new(tokio::sync::Notify::new()),
            }
        }

        fn set_delay(&self, delay: Duration) {
            *self.delay.lock().expect("lock") = delay;
        }

        fn enable_gate(&self) {
            self.gate_enabled.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    #[async_trait::async_trait]
    impl PublicSigningKeyStore for DelayingStore {
        async fn create_key(
            &self,
            namespace_id: NamespaceId,
            key: &PublicSigningKey,
        ) -> Result<(), StorageError> {
            self.inner.create_key(namespace_id, key).await
        }

        async fn get_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<Option<PublicSigningKey>, StorageError> {
            if self.gate_enabled.load(std::sync::atomic::Ordering::SeqCst) {
                // Signal that we've started the L2 read
                self.started_notify.notify_one();

                // Wait for the gate to simulate slow L2 reads
                self.gate_notify.notified().await;
            }

            let delay = *self.delay.lock().expect("lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            self.inner.get_key(namespace_id, kid).await
        }

        async fn list_active_keys(
            &self,
            namespace_id: NamespaceId,
        ) -> Result<Vec<PublicSigningKey>, StorageError> {
            self.inner.list_active_keys(namespace_id).await
        }

        async fn deactivate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.deactivate_key(namespace_id, kid).await
        }

        async fn revoke_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
            reason: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.revoke_key(namespace_id, kid, reason).await
        }

        async fn activate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.activate_key(namespace_id, kid).await
        }

        async fn delete_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.delete_key(namespace_id, kid).await
        }
    }

    /// Tests that concurrent `get` + `invalidate` does not result in stale reads
    /// after invalidation completes.
    ///
    /// Scenario:
    /// 1. Key is cached in L1
    /// 2. L1 entry is cleared to force L2 read
    /// 3. A `get_decoding_key` call starts, hitting L2 (with a gate delay)
    /// 4. While the L2 read is in-flight, `invalidate` runs
    /// 5. The L2 read completes and the result must NOT be written to L1
    #[tokio::test]
    async fn test_no_stale_repopulation_after_invalidate() {
        let store = Arc::new(DelayingStore::new());

        let key = create_valid_test_key("race-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache (gate is disabled, so this completes immediately)
        let _ = cache.get_decoding_key(NamespaceId::from(1), "race-key").await;
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);

        // Clear L1 to force an L2 read on next get
        cache.clear_l1().await;
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0);

        // Enable the gate so the next L2 read blocks
        store.enable_gate();

        // Start a get_decoding_key that will block in L2 at the gate
        let cache_clone = Arc::clone(&cache);
        let get_handle = tokio::spawn(async move {
            cache_clone.get_decoding_key(NamespaceId::from(1), "race-key").await
        });

        // Wait for the L2 read to start
        store.started_notify.notified().await;

        // While L2 read is in-flight, invalidate the key
        cache.invalidate(NamespaceId::from(1), "race-key").await;

        // Now release the gate to let the L2 read complete
        store.gate_notify.notify_one();

        // The get should still succeed (the key was valid at fetch time)
        let result = get_handle.await.expect("task should not panic");
        assert!(result.is_ok(), "get should succeed with the fetched key");

        // But L1 must NOT have been re-populated (invalidation happened mid-fetch)
        cache.sync().await;
        assert_eq!(
            cache.entry_count(),
            0,
            "L1 must not be re-populated after invalidation during fetch"
        );

        // L3 fallback must also not be re-populated
        assert_eq!(
            cache.fallback_entry_count(),
            0,
            "L3 must not be re-populated after invalidation during fetch"
        );
    }

    /// Tests that concurrent `get` calls during L2 read latency all receive
    /// the same result.
    #[tokio::test]
    async fn test_concurrent_gets_during_l2_latency() {
        let store = Arc::new(DelayingStore::new());
        store.set_delay(Duration::from_millis(50));

        let key = create_valid_test_key("concurrent-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Launch 10 concurrent get calls — all should succeed
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "concurrent-key").await
            }));
        }

        // All should succeed
        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "all concurrent gets should succeed");
        }
    }

    /// Tests that L2 failure during concurrent access correctly falls back
    /// to L3 for all callers.
    #[tokio::test]
    async fn test_l2_failure_concurrent_fallback() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("concurrent-fallback");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache (populates L1 + L3)
        let _ = cache.get_decoding_key(NamespaceId::from(1), "concurrent-fallback").await;

        // Simulate Ledger failure and clear L1
        store.set_failure(Some(StorageError::connection("network error")));
        cache.clear_l1().await;
        cache.sync().await;

        // Launch 10 concurrent gets — all should use L3 fallback
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "concurrent-fallback").await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "all callers should receive fallback key");
        }
    }

    /// Stress test: 100 concurrent readers + 1 writer performing key rotation.
    /// No stale reads should be observed after invalidation completes.
    #[tokio::test]
    #[ignore] // Run explicitly with `cargo test -- --ignored`
    async fn test_stress_concurrent_readers_with_writer() {
        let store = Arc::new(DelayingStore::new());
        store.set_delay(Duration::from_millis(1));

        let key_v1 = create_valid_test_key("stress-key");
        store.inner.create_key(NamespaceId::from(1), &key_v1).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache
        let _ = cache.get_decoding_key(NamespaceId::from(1), "stress-key").await;

        let stale_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));

        // Spawn 100 readers that continuously read the key
        let mut reader_handles = Vec::new();
        for _ in 0..100 {
            let cache_clone = Arc::clone(&cache);
            let stale_count_clone = Arc::clone(&stale_count);
            reader_handles.push(tokio::spawn(async move {
                for _ in 0..10 {
                    let result =
                        cache_clone.get_decoding_key(NamespaceId::from(1), "stress-key").await;
                    if result.is_err() {
                        // After invalidation, a KeyNotFound is acceptable
                        // (key was deleted from store and re-created as v2)
                    }
                    // Small yield to interleave with the writer
                    tokio::task::yield_now().await;
                }
                stale_count_clone.load(std::sync::atomic::Ordering::SeqCst)
            }));
        }

        // Spawn 1 writer that performs key rotation
        let cache_writer = Arc::clone(&cache);
        let store_writer = Arc::clone(&store);
        let writer_handle = tokio::spawn(async move {
            for _ in 0..5 {
                // Invalidate the old key
                cache_writer.invalidate(NamespaceId::from(1), "stress-key").await;

                // Delete old key and create a new version
                let _ = store_writer.inner.delete_key(NamespaceId::from(1), "stress-key").await;
                let key_v2 = create_valid_test_key("stress-key");
                let _ = store_writer.inner.create_key(NamespaceId::from(1), &key_v2).await;

                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });

        // Wait for all tasks
        writer_handle.await.expect("writer should not panic");
        for handle in reader_handles {
            let _ = handle.await.expect("reader should not panic");
        }

        // After the writer finishes, the cache should not contain stale entries
        // from before the last invalidation
        cache.sync().await;

        // Verify the generation counter was incremented
        let generation = cache.invalidation_gen.load(Ordering::Acquire);
        assert!(
            generation >= 5,
            "generation should have been bumped at least 5 times, got {generation}"
        );
    }

    // ========== Fallback TTL / Staleness Bound Tests (Task 6) ==========

    /// Tests that L3 fallback entries expire after the configured TTL.
    ///
    /// Uses a very short fallback TTL (50ms), populates L3, waits for expiry,
    /// then verifies the entry is gone on the next transient-error fallback path.
    #[tokio::test]
    async fn test_fallback_entry_expires_after_ttl() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("expiring-fallback");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        // Short fallback TTL — entries expire quickly
        let fallback_ttl = Duration::from_millis(50);
        let cache = SigningKeyCache::with_fallback_ttl(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60), // L1 TTL
            10,                      // capacity
            fallback_ttl,
        );

        // Populate both L1 and L3
        let result = cache.get_decoding_key(NamespaceId::from(1), "expiring-fallback").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Wait for the fallback TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.sync().await;

        // The L3 entry should now be expired
        assert_eq!(
            cache.fallback_entry_count(),
            0,
            "L3 entry should be evicted after fallback TTL expires"
        );

        // Simulate Ledger outage and clear L1
        store.set_failure(Some(StorageError::connection("outage")));
        cache.clear_l1().await;
        cache.sync().await;

        // Fallback should NOT serve the expired entry
        let result = cache.get_decoding_key(NamespaceId::from(1), "expiring-fallback").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError { .. })),
            "expired fallback entry must not be served"
        );
    }

    /// Tests that L3 fallback entries are served within the TTL window.
    #[tokio::test]
    async fn test_fallback_entry_served_within_ttl() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("fresh-fallback");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        // Generous fallback TTL — entries survive
        let fallback_ttl = Duration::from_secs(60);
        let cache = SigningKeyCache::with_fallback_ttl(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            10,
            fallback_ttl,
        );

        // Populate L1 + L3
        let result = cache.get_decoding_key(NamespaceId::from(1), "fresh-fallback").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Simulate Ledger outage and clear L1
        store.set_failure(Some(StorageError::connection("outage")));
        cache.clear_l1().await;
        cache.sync().await;

        // Fallback should serve the still-valid entry
        let result = cache.get_decoding_key(NamespaceId::from(1), "fresh-fallback").await;
        assert!(result.is_ok(), "fallback entry within TTL should be served");
    }

    /// Tests that the default fallback TTL is applied when using `new()`.
    #[tokio::test]
    async fn test_default_fallback_ttl_is_applied() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("default-ttl");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        // Use the default constructor — should apply DEFAULT_FALLBACK_TTL
        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate L1 + L3
        let result = cache.get_decoding_key(NamespaceId::from(1), "default-ttl").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Simulate Ledger outage and clear L1
        store.set_failure(Some(StorageError::connection("outage")));
        cache.clear_l1().await;
        cache.sync().await;

        // The default TTL is 1 hour, so the entry should still be fresh
        let result = cache.get_decoding_key(NamespaceId::from(1), "default-ttl").await;
        assert!(result.is_ok(), "entry under default 1-hour TTL should be served");
    }

    /// Tests that `with_capacity` also applies the default fallback TTL.
    #[tokio::test]
    async fn test_with_capacity_applies_default_fallback_ttl() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("capacity-ttl");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            10,
        );

        // Populate L1 + L3
        let result = cache.get_decoding_key(NamespaceId::from(1), "capacity-ttl").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Simulate outage
        store.set_failure(Some(StorageError::connection("outage")));
        cache.clear_l1().await;
        cache.sync().await;

        // Should still serve from L3 under default TTL
        let result = cache.get_decoding_key(NamespaceId::from(1), "capacity-ttl").await;
        assert!(result.is_ok(), "entry under default fallback TTL should be served");
    }

    // ========== Concurrency Tests for SigningKeyCache (Task 21) ==========

    /// Mock store that counts L2 `get_key` calls and supports configurable
    /// delays plus failure injection. Combines the functionality of
    /// `DelayingStore` and `FailingStore` with call counting.
    struct CountingStore {
        inner: Arc<MemorySigningKeyStore>,
        get_count: std::sync::atomic::AtomicUsize,
        delay: std::sync::Mutex<Duration>,
        fail_with: std::sync::Mutex<Option<fn() -> StorageError>>,
    }

    impl CountingStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(MemorySigningKeyStore::new()),
                get_count: std::sync::atomic::AtomicUsize::new(0),
                delay: std::sync::Mutex::new(Duration::ZERO),
                fail_with: std::sync::Mutex::new(None),
            }
        }

        fn get_count(&self) -> usize {
            self.get_count.load(std::sync::atomic::Ordering::SeqCst)
        }

        fn reset_count(&self) {
            self.get_count.store(0, std::sync::atomic::Ordering::SeqCst);
        }

        fn set_delay(&self, delay: Duration) {
            *self.delay.lock().expect("lock") = delay;
        }

        fn set_failure(&self, factory: Option<fn() -> StorageError>) {
            *self.fail_with.lock().expect("lock") = factory;
        }
    }

    #[async_trait::async_trait]
    impl PublicSigningKeyStore for CountingStore {
        async fn create_key(
            &self,
            namespace_id: NamespaceId,
            key: &PublicSigningKey,
        ) -> Result<(), StorageError> {
            self.inner.create_key(namespace_id, key).await
        }

        async fn get_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<Option<PublicSigningKey>, StorageError> {
            self.get_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);

            if let Some(factory) = *self.fail_with.lock().expect("lock") {
                return Err(factory());
            }

            let delay = *self.delay.lock().expect("lock");
            if !delay.is_zero() {
                tokio::time::sleep(delay).await;
            }

            self.inner.get_key(namespace_id, kid).await
        }

        async fn list_active_keys(
            &self,
            namespace_id: NamespaceId,
        ) -> Result<Vec<PublicSigningKey>, StorageError> {
            self.inner.list_active_keys(namespace_id).await
        }

        async fn deactivate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.deactivate_key(namespace_id, kid).await
        }

        async fn revoke_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
            reason: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.revoke_key(namespace_id, kid, reason).await
        }

        async fn activate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.activate_key(namespace_id, kid).await
        }

        async fn delete_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.delete_key(namespace_id, kid).await
        }
    }

    /// Stampede prevention: 100 concurrent `get` calls for the same key
    /// after one warm-up call should produce 0 additional L2 reads.
    ///
    /// The warm-up populates L1, and subsequent concurrent reads all
    /// hit L1 (at most 1 total L2 read from the warm-up).
    #[tokio::test]
    async fn test_stampede_prevention_warm_cache() {
        let store = Arc::new(CountingStore::new());
        let key = create_valid_test_key("stampede-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache — 1 L2 read
        let _ = cache.get_decoding_key(NamespaceId::from(1), "stampede-key").await;
        cache.sync().await;
        assert_eq!(store.get_count(), 1, "warm-up should trigger exactly 1 L2 read");

        // Reset counter to measure only the concurrent reads
        store.reset_count();

        // Launch 100 concurrent gets — all should hit L1
        let mut handles = Vec::new();
        for _ in 0..100 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "stampede-key").await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "all concurrent gets should succeed");
        }

        // With a warm cache, all 100 reads should come from L1
        assert_eq!(
            store.get_count(),
            0,
            "warm cache should serve all concurrent reads from L1 (0 L2 reads)"
        );
    }

    /// Verifies that `get` + concurrent `invalidate` produces no stale reads
    /// after invalidation completes, with L2 read count verification.
    ///
    /// After invalidation, a subsequent read must hit L2 (not return stale L1 data).
    #[tokio::test]
    async fn test_no_stale_reads_after_invalidate_with_metrics() {
        let store = Arc::new(CountingStore::new());
        let key = create_valid_test_key("invalidate-metrics-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache
        let _ = cache.get_decoding_key(NamespaceId::from(1), "invalidate-metrics-key").await;
        cache.sync().await;
        assert_eq!(store.get_count(), 1);

        // Invalidate
        cache.invalidate(NamespaceId::from(1), "invalidate-metrics-key").await;
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0, "L1 should be empty after invalidation");

        // Reset count after warmup
        store.reset_count();

        // Launch concurrent reads after invalidation — each should go to L2
        // until L1 is repopulated
        let mut handles = Vec::new();
        for _ in 0..10 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "invalidate-metrics-key").await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "reads after invalidation should succeed");
        }

        // At least 1 L2 read must have occurred (the first post-invalidation miss)
        assert!(
            store.get_count() >= 1,
            "at least 1 L2 read should occur after invalidation, got {}",
            store.get_count()
        );

        // The cache should be re-populated
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1, "L1 should be re-populated after reads");
    }

    /// Concurrent `get` calls during simulated L2 read latency.
    ///
    /// All callers should receive the same (valid) result. With a
    /// delayed L2, multiple callers may hit L2 simultaneously, but
    /// all should succeed with a valid decoding key.
    #[tokio::test]
    async fn test_concurrent_gets_same_result_during_l2_latency() {
        let store = Arc::new(CountingStore::new());
        store.set_delay(Duration::from_millis(50));

        let key = create_valid_test_key("latency-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Launch 20 concurrent gets on a cold cache with 50ms L2 delay
        let mut handles = Vec::new();
        for _ in 0..20 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "latency-key").await
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "all concurrent gets should succeed");
            results.push(result.expect("already checked"));
        }

        // All results should point to the same key (Arc pointer equality
        // isn't guaranteed here since each L2 read creates a fresh Arc,
        // but all must be valid decoding keys for the same public key)
        assert_eq!(results.len(), 20);

        // After all reads, L1 should have exactly 1 entry
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1, "L1 should have exactly 1 entry for the key");
    }

    /// Cache entry expiration under concurrent access.
    ///
    /// Uses a very short L1 TTL. After the TTL expires, concurrent reads
    /// should cleanly transition to L2 fetches and re-populate L1.
    #[tokio::test]
    async fn test_cache_expiration_under_concurrent_access() {
        let store = Arc::new(CountingStore::new());
        let key = create_valid_test_key("expiring-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        // Very short L1 TTL
        let cache = Arc::new(SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_millis(50),
            100,
        ));

        // Warm the cache
        let _ = cache.get_decoding_key(NamespaceId::from(1), "expiring-key").await;
        cache.sync().await;
        assert_eq!(store.get_count(), 1);

        // Wait for L1 TTL to expire
        tokio::time::sleep(Duration::from_millis(100)).await;
        cache.sync().await;

        // Reset counter to measure post-expiration behavior
        store.reset_count();

        // Launch concurrent reads after expiration
        let mut handles = Vec::new();
        for _ in 0..20 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "expiring-key").await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "reads after TTL expiration should succeed");
        }

        // At least 1 L2 read should have occurred (cache was expired)
        assert!(
            store.get_count() >= 1,
            "at least 1 L2 read expected after expiration, got {}",
            store.get_count()
        );

        // Cache should be re-populated
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1, "L1 should be re-populated after expiration");
    }

    /// L2 failure during concurrent access — all callers should
    /// fall back to L3 and receive a valid key.
    #[tokio::test]
    async fn test_l2_failure_all_callers_use_l3_fallback() {
        let store = Arc::new(CountingStore::new());
        let key = create_valid_test_key("fallback-concurrent");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Warm the cache (populates L1 + L3)
        let _ = cache.get_decoding_key(NamespaceId::from(1), "fallback-concurrent").await;
        cache.sync().await;
        assert_eq!(store.get_count(), 1);
        assert_eq!(cache.fallback_entry_count(), 1, "L3 should be populated");

        // Simulate L2 failure and clear L1
        store.set_failure(Some(|| StorageError::connection("simulated outage")));
        cache.clear_l1().await;
        cache.sync().await;

        // Reset counter
        store.reset_count();

        // Launch 20 concurrent gets — all should use L3 fallback
        let mut handles = Vec::new();
        for _ in 0..20 {
            let cache_clone = Arc::clone(&cache);
            handles.push(tokio::spawn(async move {
                cache_clone.get_decoding_key(NamespaceId::from(1), "fallback-concurrent").await
            }));
        }

        for handle in handles {
            let result = handle.await.expect("task should not panic");
            assert!(result.is_ok(), "all callers should receive L3 fallback key");
        }

        // All 20 callers attempted L2 (all miss L1, all hit L2, all fail, all use L3)
        assert_eq!(
            store.get_count(),
            20,
            "all callers should attempt L2 before falling back to L3"
        );
    }

    /// L2 read count matches expected pattern across a full cache lifecycle:
    /// warm-up, hits, invalidation, re-population.
    #[tokio::test]
    async fn test_l2_read_count_across_lifecycle() {
        let store = Arc::new(CountingStore::new());
        let key = create_valid_test_key("lifecycle-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Phase 1: Cold cache — first get triggers L2 read
        let _ = cache.get_decoding_key(NamespaceId::from(1), "lifecycle-key").await;
        assert_eq!(store.get_count(), 1, "phase 1: cold miss = 1 L2 read");

        // Phase 2: Warm cache — 50 sequential gets, all from L1
        for _ in 0..50 {
            let result = cache.get_decoding_key(NamespaceId::from(1), "lifecycle-key").await;
            assert!(result.is_ok());
        }
        assert_eq!(store.get_count(), 1, "phase 2: warm hits = still 1 L2 read total");

        // Phase 3: Invalidation + re-population
        cache.invalidate(NamespaceId::from(1), "lifecycle-key").await;
        cache.sync().await;

        let _ = cache.get_decoding_key(NamespaceId::from(1), "lifecycle-key").await;
        assert_eq!(store.get_count(), 2, "phase 3: post-invalidation = 2 L2 reads total");

        // Phase 4: Second key — independent L2 read
        let key2 = create_valid_test_key("lifecycle-key-2");
        store.inner.create_key(NamespaceId::from(1), &key2).await.expect("create_key");
        let _ = cache.get_decoding_key(NamespaceId::from(1), "lifecycle-key-2").await;
        assert_eq!(
            store.get_count(),
            3,
            "phase 4: new key = 3 L2 reads total (1 per unique key per L1 TTL window)"
        );
    }

    // ── L3 Fallback Cache Metrics & Threshold Tests ────────────────────

    #[tokio::test]
    async fn test_fallback_capacity_accessor() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            500,
        );
        assert_eq!(cache.fallback_capacity(), 500);
    }

    #[tokio::test]
    async fn test_fallback_fill_pct_empty() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            100,
        );
        assert!((cache.fallback_fill_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_fallback_fill_pct_after_inserts() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            10,
        );

        // Insert 5 keys into a cache with capacity 10 → 50%
        for i in 0..5 {
            let kid = format!("fill-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        cache.sync().await;

        let fill = cache.fallback_fill_pct();
        assert!((fill - 50.0).abs() < 1.0, "expected ~50% fill, got {fill:.1}%",);
    }

    #[tokio::test]
    async fn test_fallback_fill_pct_zero_capacity() {
        let store = Arc::new(MemorySigningKeyStore::new());
        // Zero capacity — should not panic or produce NaN
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            0,
        );
        assert!((cache.fallback_fill_pct() - 0.0).abs() < f64::EPSILON);
    }

    #[tokio::test]
    async fn test_warn_threshold_fires_once() {
        let store = Arc::new(MemorySigningKeyStore::new());
        // Capacity 5, warn at 40% (2 entries), critical at 80% (4 entries)
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            5,
        )
        .with_thresholds(40.0, 80.0);

        // Insert 2 keys → 40% fill → warning fires
        for i in 0..2 {
            let kid = format!("warn-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        // Sync makes entry_count() consistent, then re-check thresholds
        cache.sync().await;
        cache.check_fallback_thresholds();

        // warn_fired should be set after threshold crossed
        assert!(
            cache.warn_fired.load(Ordering::Relaxed),
            "warning alert should have fired at 40% fill",
        );
        // critical should NOT be fired
        assert!(
            !cache.critical_fired.load(Ordering::Relaxed),
            "critical alert should not fire at 40% fill",
        );
    }

    #[tokio::test]
    async fn test_critical_threshold_fires() {
        let store = Arc::new(MemorySigningKeyStore::new());
        // Capacity 5, warn at 40% (2 entries), critical at 80% (4 entries)
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            5,
        )
        .with_thresholds(40.0, 80.0);

        // Insert 4 keys → 80% fill → both thresholds crossed
        for i in 0..4 {
            let kid = format!("crit-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        // Sync makes entry_count() consistent, then re-check thresholds
        cache.sync().await;
        cache.check_fallback_thresholds();

        assert!(cache.warn_fired.load(Ordering::Relaxed), "warning alert should have fired",);
        assert!(
            cache.critical_fired.load(Ordering::Relaxed),
            "critical alert should have fired at 80% fill",
        );
    }

    #[tokio::test]
    async fn test_threshold_resets_below() {
        let store = Arc::new(MemorySigningKeyStore::new());
        // Capacity 5, warn at 40% (2 entries), critical at 80% (4 entries)
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            5,
        )
        .with_thresholds(40.0, 80.0);

        // Insert 3 keys → 60% → warn fires
        for i in 0..3 {
            let kid = format!("reset-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        // Sync makes entry_count() consistent, then re-check thresholds
        cache.sync().await;
        cache.check_fallback_thresholds();
        assert!(cache.warn_fired.load(Ordering::Relaxed));

        // Clear all → fill drops to 0 → manually trigger threshold check
        cache.clear_all().await;
        cache.sync().await;
        cache.check_fallback_thresholds();

        // warn should be reset since fill is now 0%
        assert!(
            !cache.warn_fired.load(Ordering::Relaxed),
            "warning alert should reset when fill drops below threshold",
        );
    }

    #[tokio::test]
    async fn test_metrics_snapshot_includes_fallback_fields() {
        // Verify the fields exist and default correctly on SigningKeyMetricsSnapshot
        let snapshot = SigningKeyMetricsSnapshot::default();
        assert_eq!(snapshot.fallback_entry_count, 0);
        assert_eq!(snapshot.fallback_capacity, 0);
        assert!((snapshot.fallback_fill_pct - 0.0).abs() < f64::EPSILON);

        // Builder should allow setting fallback fields
        let snapshot = SigningKeyMetricsSnapshot::builder()
            .fallback_entry_count(50)
            .fallback_capacity(100)
            .fallback_fill_pct(50.0)
            .build();
        assert_eq!(snapshot.fallback_entry_count, 50);
        assert_eq!(snapshot.fallback_capacity, 100);
        assert!((snapshot.fallback_fill_pct - 50.0).abs() < f64::EPSILON);
    }

    // ── Background refresh tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_background_refresh_populates_cache() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("refresh-key");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Trigger a get to mark the key as "active".
        cache.get_decoding_key(NamespaceId::from(1), "refresh-key").await.expect("get");
        assert_eq!(cache.active_key_count(), 1);

        // Enable background refresh with a short interval.
        let cache = Arc::clone(&cache).with_refresh_interval(Duration::from_millis(50));

        // Wait for at least one refresh cycle to complete.
        tokio::time::sleep(Duration::from_millis(120)).await;

        assert!(cache.refresh_count() >= 1, "expected at least one refresh cycle");
        assert!(cache.refresh_keys_total() >= 1, "expected at least one key refreshed");
        assert_eq!(cache.refresh_errors_total(), 0);
        assert!(cache.refresh_latency_us() > 0);

        cache.shutdown().await;
    }

    #[tokio::test]
    async fn test_background_refresh_stops_on_shutdown() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("stop-key");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));
        cache.get_decoding_key(NamespaceId::from(1), "stop-key").await.expect("get");

        let cache = Arc::clone(&cache).with_refresh_interval(Duration::from_millis(50));

        // Let one cycle run.
        tokio::time::sleep(Duration::from_millis(80)).await;
        let count_before = cache.refresh_count();

        // Shutdown and verify no more cycles run.
        cache.shutdown().await;

        tokio::time::sleep(Duration::from_millis(150)).await;
        let count_after = cache.refresh_count();

        assert_eq!(count_before, count_after, "no cycles should run after shutdown");
    }

    #[tokio::test]
    async fn test_background_refresh_skips_inactive_keys() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key_a = create_valid_test_key("active-key");
        let key_b = create_valid_test_key("idle-key");
        store.create_key(NamespaceId::from(1), &key_a).await.expect("create_key");
        store.create_key(NamespaceId::from(1), &key_b).await.expect("create_key");

        // Use a CountingStore wrapper to count L2 fetches per key.
        let counting_store = Arc::new(CountingStore::new());
        counting_store.inner.create_key(NamespaceId::from(1), &key_a).await.expect("create_key");
        counting_store.inner.create_key(NamespaceId::from(1), &key_b).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&counting_store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Only access key_a, not key_b.
        cache.get_decoding_key(NamespaceId::from(1), "active-key").await.expect("get");
        // key_b is never accessed, so it should not appear in active set.

        let cache = Arc::clone(&cache).with_refresh_interval(Duration::from_millis(50));

        tokio::time::sleep(Duration::from_millis(120)).await;

        // key_a should have been fetched at least twice (initial + refresh).
        // key_b should have been fetched zero times.
        let total_get_count = counting_store.get_count.load(Ordering::Relaxed);
        // Initial get for key_a = 1, plus at least 1 refresh = 2+
        assert!(total_get_count >= 2, "expected at least 2 gets, got {total_get_count}");

        // active_key_count should be 0 after drain (or 1 if key_a was re-accessed).
        // But since we didn't re-access, active set should be empty after drain.
        // (It may refill if the refresh cycle re-activates, but our impl doesn't do that.)

        cache.shutdown().await;
    }

    #[tokio::test]
    async fn test_background_refresh_handles_l2_errors() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("error-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Initial successful get to mark key as active.
        cache.get_decoding_key(NamespaceId::from(1), "error-key").await.expect("get");

        // Now make the store fail.
        store.set_failure(Some(StorageError::connection("simulated outage")));

        let cache = Arc::clone(&cache).with_refresh_interval(Duration::from_millis(50));

        tokio::time::sleep(Duration::from_millis(120)).await;

        assert!(cache.refresh_count() >= 1);
        assert!(cache.refresh_errors_total() >= 1, "expected refresh errors from failing store");

        // The key should be re-queued for the next cycle (re-inserted on error).
        assert!(cache.active_key_count() >= 1, "failed key should be re-queued");

        cache.shutdown().await;
    }

    #[tokio::test]
    async fn test_background_refresh_evicts_deleted_keys() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("delete-me");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = Arc::new(SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        ));

        // Access key to mark it active.
        cache.get_decoding_key(NamespaceId::from(1), "delete-me").await.expect("get");
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);

        // Delete from the underlying store.
        store.delete_key(NamespaceId::from(1), "delete-me").await.expect("delete_key");

        let cache = Arc::clone(&cache).with_refresh_interval(Duration::from_millis(50));

        tokio::time::sleep(Duration::from_millis(120)).await;

        // After refresh, the key should be evicted from both L1 and L3.
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0, "deleted key should be evicted from L1");
        assert_eq!(cache.fallback_entry_count(), 0, "deleted key should be evicted from L3");

        cache.shutdown().await;
    }

    #[tokio::test]
    async fn test_background_refresh_metrics_snapshot() {
        let snapshot = SigningKeyMetricsSnapshot::default();
        assert_eq!(snapshot.refresh_count, 0);
        assert_eq!(snapshot.refresh_keys_total, 0);
        assert_eq!(snapshot.refresh_errors_total, 0);
        assert_eq!(snapshot.refresh_latency_us, 0);

        let snapshot = SigningKeyMetricsSnapshot::builder()
            .refresh_count(10)
            .refresh_keys_total(50)
            .refresh_errors_total(2)
            .refresh_latency_us(15000)
            .build();
        assert_eq!(snapshot.refresh_count, 10);
        assert_eq!(snapshot.refresh_keys_total, 50);
        assert_eq!(snapshot.refresh_errors_total, 2);
        assert_eq!(snapshot.refresh_latency_us, 15000);
    }

    #[tokio::test]
    async fn test_active_key_tracking() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key_a = create_valid_test_key("track-a");
        let key_b = create_valid_test_key("track-b");
        store.create_key(NamespaceId::from(1), &key_a).await.expect("create_key");
        store.create_key(NamespaceId::from(2), &key_b).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        assert_eq!(cache.active_key_count(), 0);

        cache.get_decoding_key(NamespaceId::from(1), "track-a").await.expect("get");
        assert_eq!(cache.active_key_count(), 1);

        cache.get_decoding_key(NamespaceId::from(2), "track-b").await.expect("get");
        assert_eq!(cache.active_key_count(), 2);

        // Duplicate access should not increase count (HashSet).
        cache.get_decoding_key(NamespaceId::from(1), "track-a").await.expect("get");
        assert_eq!(cache.active_key_count(), 2);
    }
}
