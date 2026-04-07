//! Distributed fixed-window rate limiter backed by [`StorageBackend`].
//!
//! [`AppRateLimiter`] enforces rate limits using storage-backed counters with
//! atomic compare-and-set (CAS) operations to prevent race conditions. Counters
//! are stored with TTL for automatic cleanup when the window expires.
//!
//! # Key format
//!
//! Rate limit counters are stored as:
//! `rate_limit:{category}:{identifier}:{window_start}`
//!
//! Counter values are stored as big-endian `u64` bytes for compact, parse-free
//! encoding.
//!
//! # Comparison with `RateLimitedBackend`
//!
//! This crate provides **distributed** fixed-window rate limiting for
//! application-level concerns (login attempts, API quotas). The
//! [`RateLimitedBackend`](inferadb_common_storage::RateLimitedBackend) in
//! `inferadb-common-storage` provides **in-process** token-bucket rate limiting
//! for protecting a single storage backend from overload.
//!
//! | Aspect | `AppRateLimiter` | `RateLimitedBackend` |
//! |--------|------------------|----------------------|
//! | Scope | Distributed (shared across nodes) | In-process (single node) |
//! | Algorithm | Fixed window | Token bucket |
//! | Backing | Any `StorageBackend` | In-memory (`parking_lot::Mutex`) |
//! | Granularity | Per category + identifier | Per operation (global / per-org) |
//! | Use case | API quotas, login throttling | Backend overload protection |
//! | Latency | Storage round-trip per check | Sub-microsecond (mutex only) |
//!
//! Use `AppRateLimiter` when limits must be enforced consistently across
//! multiple application instances. Use `RateLimitedBackend` when protecting a
//! single backend instance from excessive local load.
//!
//! # Examples
//!
//! ```no_run
//! use inferadb_common_storage::MemoryBackend;
//! use inferadb_common_ratelimit::{AppRateLimiter, RateLimitPolicy, RateLimitOutcome};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = MemoryBackend::new();
//! let limiter = AppRateLimiter::new(storage);
//!
//! let policy = RateLimitPolicy::per_hour(100)?;
//! let outcome = limiter.check("login_ip", "192.168.1.1", &policy).await?;
//! match outcome {
//!     RateLimitOutcome::Allowed { remaining, .. } => {
//!         println!("allowed, {remaining} remaining");
//!     }
//!     RateLimitOutcome::Limited { retry_after_secs } => {
//!         println!("rate limited, retry after {retry_after_secs}s");
//!     }
//!     _ => {}
//! }
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use inferadb_common_storage::{ConfigError, StorageBackend, StorageError, StorageResult};

/// Maximum number of CAS retry attempts before returning
/// [`StorageError::CasRetriesExhausted`].
const MAX_CAS_RETRIES: u32 = 10;

/// Base delay between CAS retries to reduce contention storms.
const CAS_RETRY_BASE_DELAY: Duration = Duration::from_millis(1);

/// Rate limit window duration.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum RateLimitWindow {
    /// Per hour (3600 seconds).
    Hour,
    /// Per day (86400 seconds).
    Day,
    /// Custom window duration.
    Custom(Duration),
}

impl RateLimitWindow {
    /// Returns the window duration in seconds.
    #[must_use]
    pub fn seconds(&self) -> u64 {
        match self {
            Self::Hour => 3600,
            Self::Day => 86400,
            Self::Custom(d) => d.as_secs(),
        }
    }

    /// Returns the window start timestamp for the given time.
    fn window_start(&self, now: SystemTime) -> u64 {
        let timestamp = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        let window_seconds = self.seconds();
        if window_seconds == 0 {
            return timestamp;
        }
        (timestamp / window_seconds) * window_seconds
    }

    /// Returns seconds until the current window expires (minimum 1).
    fn seconds_until_reset(&self, now: SystemTime) -> u64 {
        let window_start = self.window_start(now);
        let window_seconds = self.seconds();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        (window_start + window_seconds).saturating_sub(now_secs).max(1)
    }
}

/// Rate limit policy defining the maximum requests allowed within a window.
#[derive(Debug, Clone)]
pub struct RateLimitPolicy {
    /// Maximum number of requests in the window.
    pub max_requests: u32,
    /// Time window.
    pub window: RateLimitWindow,
}

impl RateLimitPolicy {
    /// Creates a new rate limit policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BelowMinimum`] if `max_requests` is zero or if
    /// a custom window duration is less than 1 second.
    pub fn new(max_requests: u32, window: RateLimitWindow) -> Result<Self, ConfigError> {
        if max_requests == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "max_requests",
                min: "1".into(),
                value: "0".into(),
            });
        }
        if window.seconds() == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "window_seconds",
                min: "1".into(),
                value: "0".into(),
            });
        }
        Ok(Self { max_requests, window })
    }

    /// Creates an hourly rate limit policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BelowMinimum`] if `max_requests` is zero.
    pub fn per_hour(max_requests: u32) -> Result<Self, ConfigError> {
        Self::new(max_requests, RateLimitWindow::Hour)
    }

    /// Creates a daily rate limit policy.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BelowMinimum`] if `max_requests` is zero.
    pub fn per_day(max_requests: u32) -> Result<Self, ConfigError> {
        Self::new(max_requests, RateLimitWindow::Day)
    }

    /// Creates a rate limit policy with a custom window duration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError::BelowMinimum`] if `max_requests` is zero.
    pub fn custom(max_requests: u32, window: Duration) -> Result<Self, ConfigError> {
        Self::new(max_requests, RateLimitWindow::Custom(window))
    }
}

/// Outcome of a rate limit check.
///
/// Returned by [`AppRateLimiter::check`]. Contains the allow/deny decision and
/// metadata useful for response headers (`X-RateLimit-Remaining`,
/// `Retry-After`).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RateLimitOutcome {
    /// The request is allowed.
    Allowed {
        /// Remaining requests in the current window.
        remaining: u64,
        /// Seconds until the window resets.
        reset_after_secs: u64,
    },
    /// The request is denied due to rate limiting.
    Limited {
        /// Seconds until the window resets and the caller may retry.
        retry_after_secs: u64,
    },
}

/// Flattened rate limit response for HTTP middleware.
///
/// Unlike [`RateLimitOutcome`], this struct always carries all fields regardless
/// of whether the request was allowed, making it straightforward to populate
/// `X-RateLimit-*` and `Retry-After` response headers.
///
/// Returned by [`AppRateLimiter::check_response`].
#[derive(Debug, Clone)]
pub struct RateLimitResponse {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window (0 when denied).
    pub remaining: u64,
    /// Seconds until the window resets.
    pub reset_after_secs: u64,
}

impl From<RateLimitOutcome> for RateLimitResponse {
    fn from(outcome: RateLimitOutcome) -> Self {
        match outcome {
            RateLimitOutcome::Allowed { remaining, reset_after_secs } => {
                Self { allowed: true, remaining, reset_after_secs }
            },
            RateLimitOutcome::Limited { retry_after_secs } => {
                Self { allowed: false, remaining: 0, reset_after_secs: retry_after_secs }
            },
        }
    }
}

/// Distributed fixed-window rate limiter backed by a [`StorageBackend`].
///
/// Uses storage-backed counters with atomic CAS operations and TTL for
/// automatic cleanup. Each counter key includes the category, identifier, and
/// window start timestamp for proper isolation and rotation.
///
/// # Examples
///
/// ```no_run
/// use inferadb_common_storage::MemoryBackend;
/// use inferadb_common_ratelimit::{AppRateLimiter, RateLimitPolicy, RateLimitOutcome};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let limiter = AppRateLimiter::new(MemoryBackend::new());
///
/// let policy = RateLimitPolicy::per_hour(100)?;
/// let outcome = limiter.check("login_ip", "192.168.1.1", &policy).await?;
/// if let RateLimitOutcome::Allowed { remaining, .. } = outcome {
///     println!("{remaining} requests remaining");
/// }
/// # Ok(())
/// # }
/// ```
pub struct AppRateLimiter<S> {
    storage: S,
}

impl<S: StorageBackend> AppRateLimiter<S> {
    /// Creates a new rate limiter using the given storage backend.
    #[must_use]
    pub fn new(storage: S) -> Self {
        Self { storage }
    }

    /// Returns a reference to the underlying storage backend.
    #[must_use]
    pub fn storage(&self) -> &S {
        &self.storage
    }

    /// Generates the storage key for a rate limit counter.
    fn counter_key(category: &str, identifier: &str, window_start: u64) -> Vec<u8> {
        format!("rate_limit:{category}:{identifier}:{window_start}").into_bytes()
    }

    /// Parses a counter value from big-endian u64 bytes.
    fn parse_counter(bytes: &[u8]) -> StorageResult<u64> {
        let arr: [u8; 8] = bytes.try_into().map_err(|_| {
            StorageError::internal(format!(
                "invalid rate limit counter: expected 8 bytes, got {}",
                bytes.len()
            ))
        })?;
        Ok(u64::from_be_bytes(arr))
    }

    /// Encodes a counter value as big-endian u64 bytes.
    fn encode_counter(value: u64) -> Vec<u8> {
        value.to_be_bytes().to_vec()
    }

    /// Checks whether a request is allowed under the given rate limit policy.
    ///
    /// Uses a CAS (compare-and-set) retry loop to atomically increment the
    /// counter, preventing race conditions under concurrent access. Returns a
    /// [`RateLimitOutcome`] with the decision and metadata (remaining count,
    /// reset time).
    ///
    /// # Arguments
    ///
    /// * `category` - Rate limit category (e.g., `"login_ip"`, `"api_key"`)
    /// * `identifier` - Unique identifier within the category (e.g., IP address)
    /// * `policy` - The rate limit policy to enforce
    ///
    /// # Errors
    ///
    /// - [`StorageError::CasRetriesExhausted`] if the CAS loop fails after `MAX_CAS_RETRIES`
    ///   attempts due to sustained contention.
    /// - Other [`StorageError`] variants on backend failures.
    pub async fn check(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimitPolicy,
    ) -> StorageResult<RateLimitOutcome> {
        let now = SystemTime::now();
        let window_start = policy.window.window_start(now);
        let key = Self::counter_key(category, identifier, window_start);
        let reset_after_secs = policy.window.seconds_until_reset(now);
        let ttl = Duration::from_secs(reset_after_secs);
        let max_requests = u64::from(policy.max_requests);

        for attempt in 1..=MAX_CAS_RETRIES {
            let current = self.storage.get(&key).await?;

            let current_count = match &current {
                Some(bytes) => Self::parse_counter(bytes)?,
                None => 0,
            };

            if current_count >= max_requests {
                return Ok(RateLimitOutcome::Limited { retry_after_secs: reset_after_secs });
            }

            let new_count = current_count + 1;
            let new_value = Self::encode_counter(new_count);
            let expected = current.as_deref();

            match self.storage.compare_and_set_with_ttl(&key, expected, new_value, ttl).await {
                Ok(()) => {
                    let remaining = max_requests - new_count;
                    return Ok(RateLimitOutcome::Allowed { remaining, reset_after_secs });
                },
                Err(StorageError::Conflict { .. }) => {
                    if attempt == MAX_CAS_RETRIES {
                        return Err(StorageError::cas_retries_exhausted(MAX_CAS_RETRIES));
                    }
                    // Sleep with jitter to reduce contention storms on hot keys.
                    // Deterministic jitter based on attempt number and current time
                    // avoids pulling in `rand` for a simple backoff.
                    let base_delay_us = CAS_RETRY_BASE_DELAY.as_micros() as u64;
                    let now_us = SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_micros() as u64;
                    let jitter_us =
                        (u64::from(attempt) * 137 + now_us % 1000) % (base_delay_us + 1);
                    tokio::time::sleep(Duration::from_micros(base_delay_us + jitter_us)).await;
                },
                Err(e) => return Err(e),
            }
        }

        // Unreachable: the loop either returns or continues
        Err(StorageError::cas_retries_exhausted(MAX_CAS_RETRIES))
    }

    /// Checks a rate limit and returns a flat [`RateLimitResponse`].
    ///
    /// This is a convenience wrapper around [`check`](Self::check) that returns
    /// a struct with all fields always present, suitable for populating HTTP
    /// rate limit headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`,
    /// `Retry-After`).
    ///
    /// # Errors
    ///
    /// Same as [`check`](Self::check).
    pub async fn check_response(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimitPolicy,
    ) -> StorageResult<RateLimitResponse> {
        self.check(category, identifier, policy).await.map(RateLimitResponse::from)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

    use inferadb_common_storage::MemoryBackend;

    use super::*;

    #[test]
    fn window_hour_seconds() {
        assert_eq!(RateLimitWindow::Hour.seconds(), 3600);
    }

    #[test]
    fn window_day_seconds() {
        assert_eq!(RateLimitWindow::Day.seconds(), 86400);
    }

    #[test]
    fn window_custom_seconds() {
        let window = RateLimitWindow::Custom(Duration::from_secs(300));
        assert_eq!(window.seconds(), 300);
    }

    #[test]
    fn window_start_rounds_down_to_boundary() {
        let window = RateLimitWindow::Hour;
        // 2024-01-01 00:00:00 UTC = 1704067200, + 30 minutes
        let time = UNIX_EPOCH + Duration::from_secs(1_704_067_200 + 1800);
        let start = window.window_start(time);
        assert_eq!(start, 1_704_067_200);
    }

    #[test]
    fn seconds_until_reset_within_window() {
        let window = RateLimitWindow::Hour;
        // 30 minutes into an hour window => 1800 seconds until reset
        let time = UNIX_EPOCH + Duration::from_secs(1_704_067_200 + 1800);
        let until = window.seconds_until_reset(time);
        assert_eq!(until, 1800);
    }

    #[test]
    fn policy_per_hour_sets_max_requests_and_window() {
        let policy = RateLimitPolicy::per_hour(100).unwrap();

        assert_eq!(policy.max_requests, 100);
        assert_eq!(policy.window.seconds(), 3600);
    }

    #[test]
    fn policy_per_day_sets_max_requests_and_window() {
        let policy = RateLimitPolicy::per_day(5).unwrap();

        assert_eq!(policy.max_requests, 5);
        assert_eq!(policy.window.seconds(), 86400);
    }

    #[test]
    fn policy_custom_sets_max_requests_and_window() {
        let policy = RateLimitPolicy::custom(50, Duration::from_secs(300)).unwrap();

        assert_eq!(policy.max_requests, 50);
        assert_eq!(policy.window.seconds(), 300);
    }

    #[test]
    fn policy_rejects_zero_max_requests() {
        // All constructors delegate to `new`, so testing one covers all paths.
        let err = RateLimitPolicy::new(0, RateLimitWindow::Hour).unwrap_err();
        assert!(matches!(err, ConfigError::BelowMinimum { field: "max_requests", .. }));
    }

    #[test]
    fn policy_rejects_zero_window_duration() {
        let err = RateLimitPolicy::custom(10, Duration::from_secs(0)).unwrap_err();
        assert!(matches!(err, ConfigError::BelowMinimum { field: "window_seconds", .. }));
    }

    #[test]
    fn policy_rejects_subsecond_window_duration() {
        let err = RateLimitPolicy::custom(10, Duration::from_millis(500)).unwrap_err();
        assert!(matches!(err, ConfigError::BelowMinimum { field: "window_seconds", .. }));
    }

    #[test]
    fn seconds_until_reset_never_returns_zero() {
        // At exact window boundary, should return full window duration, not 0
        let window = RateLimitWindow::Custom(Duration::from_secs(10));
        // now_secs = 100, which is an exact multiple of 10
        let time = UNIX_EPOCH + Duration::from_secs(100);
        let until = window.seconds_until_reset(time);
        assert_eq!(until, 10);
    }

    #[test]
    fn counter_encoding_round_trip() {
        for value in [0u64, 1, 42, 255, 1000, u64::MAX] {
            let encoded = AppRateLimiter::<MemoryBackend>::encode_counter(value);
            assert_eq!(encoded.len(), 8);
            let decoded = AppRateLimiter::<MemoryBackend>::parse_counter(&encoded).unwrap();
            assert_eq!(decoded, value);
        }
    }

    #[test]
    fn counter_parse_rejects_wrong_length() {
        let err = AppRateLimiter::<MemoryBackend>::parse_counter(&[0u8; 4]).unwrap_err();
        assert!(matches!(err, StorageError::Internal { .. }));
    }

    #[tokio::test]
    async fn allows_requests_under_limit() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(5).unwrap();

        for i in 0..5 {
            let outcome = limiter.check("test", "user1", &policy).await.unwrap();
            let is_allowed = matches!(outcome, RateLimitOutcome::Allowed { .. });
            assert!(is_allowed, "request {i} should be allowed");
        }
    }

    #[tokio::test]
    async fn blocks_requests_over_limit() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(3).unwrap();

        for _ in 0..3 {
            let outcome = limiter.check("test", "user1", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }

        let outcome = limiter.check("test", "user1", &policy).await.unwrap();
        assert!(matches!(outcome, RateLimitOutcome::Limited { .. }));
    }

    #[tokio::test]
    async fn remaining_decreases_each_check() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(5).unwrap();

        for expected_remaining in (0..5).rev() {
            let outcome = limiter.check("test", "user1", &policy).await.unwrap();
            match outcome {
                RateLimitOutcome::Allowed { remaining, .. } => {
                    assert_eq!(remaining, expected_remaining);
                },
                RateLimitOutcome::Limited { .. } => {
                    panic!("should not be limited yet");
                },
            }
        }
    }

    #[tokio::test]
    async fn outcome_includes_reset_after() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(10).unwrap();

        let outcome = limiter.check("test", "user1", &policy).await.unwrap();
        match outcome {
            RateLimitOutcome::Allowed { reset_after_secs, .. } => {
                assert!(reset_after_secs > 0);
                assert!(reset_after_secs <= 3600);
            },
            RateLimitOutcome::Limited { .. } => {
                panic!("should be allowed");
            },
        }
    }

    #[tokio::test]
    async fn limited_outcome_includes_retry_after() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(1).unwrap();

        // Exhaust the limit
        let _ = limiter.check("test", "user1", &policy).await.unwrap();

        let outcome = limiter.check("test", "user1", &policy).await.unwrap();
        match outcome {
            RateLimitOutcome::Limited { retry_after_secs } => {
                assert!(retry_after_secs > 0);
                assert!(retry_after_secs <= 3600);
            },
            RateLimitOutcome::Allowed { .. } => {
                panic!("should be limited");
            },
        }
    }

    #[tokio::test]
    async fn isolates_identifiers() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(2).unwrap();

        // Exhaust user1
        for _ in 0..2 {
            let outcome = limiter.check("test", "user1", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }
        let outcome = limiter.check("test", "user1", &policy).await.unwrap();
        assert!(matches!(outcome, RateLimitOutcome::Limited { .. }));

        // user2 is unaffected
        for _ in 0..2 {
            let outcome = limiter.check("test", "user2", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }
    }

    #[tokio::test]
    async fn isolates_categories() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(2).unwrap();

        // Exhaust cat1
        for _ in 0..2 {
            let outcome = limiter.check("cat1", "user1", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }
        let outcome = limiter.check("cat1", "user1", &policy).await.unwrap();
        assert!(matches!(outcome, RateLimitOutcome::Limited { .. }));

        // Different category is unaffected
        for _ in 0..2 {
            let outcome = limiter.check("cat2", "user1", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }
    }

    #[tokio::test]
    async fn concurrent_cas_retries() {
        // Spawn many concurrent tasks all checking the same key to exercise the
        // CAS retry loop. With MemoryBackend (which serializes via a RwLock),
        // CAS conflicts are less likely, but the correctness invariant holds:
        // total allowed count must equal max_requests.
        let limiter = Arc::new(AppRateLimiter::new(MemoryBackend::new()));
        let policy = RateLimitPolicy::per_hour(10).unwrap();
        let num_tasks: usize = 50;

        let mut handles = Vec::with_capacity(num_tasks);
        for _ in 0..num_tasks {
            let l = Arc::clone(&limiter);
            let p = policy.clone();
            handles.push(tokio::spawn(async move { l.check("concurrent", "user1", &p).await }));
        }

        let mut allowed_count = 0u64;
        let mut limited_count = 0u64;
        for handle in handles {
            let outcome = handle.await.unwrap().unwrap();
            match outcome {
                RateLimitOutcome::Allowed { .. } => allowed_count += 1,
                RateLimitOutcome::Limited { .. } => limited_count += 1,
            }
        }

        // Exactly max_requests should be allowed
        assert_eq!(allowed_count, 10);
        assert_eq!(limited_count, (num_tasks as u64) - 10);
    }

    #[tokio::test]
    async fn check_with_custom_window_enforces_limit() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::custom(3, Duration::from_secs(60)).unwrap();

        for _ in 0..3 {
            let outcome = limiter.check("test", "user1", &policy).await.unwrap();
            assert!(matches!(outcome, RateLimitOutcome::Allowed { .. }));
        }

        let outcome = limiter.check("test", "user1", &policy).await.unwrap();
        assert!(matches!(outcome, RateLimitOutcome::Limited { .. }));
    }

    #[tokio::test]
    async fn check_response_allowed_returns_flat_response() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(5).unwrap();

        let response = limiter.check_response("test", "user1", &policy).await.unwrap();

        assert!(response.allowed);
        assert_eq!(response.remaining, 4);
        assert!(response.reset_after_secs > 0);
        assert!(response.reset_after_secs <= 3600);
    }

    #[tokio::test]
    async fn check_response_limited_returns_zero_remaining() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(1).unwrap();

        let _ = limiter.check_response("test", "user1", &policy).await.unwrap();
        let response = limiter.check_response("test", "user1", &policy).await.unwrap();

        assert!(!response.allowed);
        assert_eq!(response.remaining, 0);
        assert!(response.reset_after_secs > 0);
    }

    #[test]
    fn rate_limit_response_from_allowed_outcome() {
        let outcome = RateLimitOutcome::Allowed { remaining: 42, reset_after_secs: 1800 };

        let response = RateLimitResponse::from(outcome);

        assert!(response.allowed);
        assert_eq!(response.remaining, 42);
        assert_eq!(response.reset_after_secs, 1800);
    }

    #[test]
    fn rate_limit_response_from_limited_outcome() {
        let outcome = RateLimitOutcome::Limited { retry_after_secs: 600 };

        let response = RateLimitResponse::from(outcome);

        assert!(!response.allowed);
        assert_eq!(response.remaining, 0);
        assert_eq!(response.reset_after_secs, 600);
    }

    #[tokio::test]
    async fn storage_accessor_returns_backend_reference() {
        let backend = MemoryBackend::new();
        let limiter = AppRateLimiter::new(backend);

        let _storage: &MemoryBackend = limiter.storage();
    }

    #[test]
    fn counter_key_includes_category_identifier_and_window() {
        let key =
            AppRateLimiter::<MemoryBackend>::counter_key("login_ip", "192.168.1.1", 1704067200);

        let key_str = String::from_utf8(key).unwrap();
        assert_eq!(key_str, "rate_limit:login_ip:192.168.1.1:1704067200");
    }

    #[test]
    fn counter_parse_rejects_empty_bytes() {
        let err = AppRateLimiter::<MemoryBackend>::parse_counter(&[]).unwrap_err();

        assert!(matches!(err, StorageError::Internal { .. }));
    }

    #[tokio::test]
    async fn cas_retry_delay_does_not_prevent_success() {
        // Verify that a limiter with a small limit still correctly allows exactly
        // `max_requests` under moderate concurrency, confirming the inter-retry
        // delay does not break the CAS retry logic.
        let limiter = Arc::new(AppRateLimiter::new(MemoryBackend::new()));
        let policy = RateLimitPolicy::per_hour(5).unwrap();
        let num_tasks: usize = 20;

        let mut handles = Vec::with_capacity(num_tasks);
        for _ in 0..num_tasks {
            let l = Arc::clone(&limiter);
            let p = policy.clone();
            handles.push(tokio::spawn(async move { l.check("cas_delay", "user1", &p).await }));
        }

        let mut allowed_count = 0u64;
        let mut limited_count = 0u64;
        for handle in handles {
            let outcome = handle.await.unwrap().unwrap();
            match outcome {
                RateLimitOutcome::Allowed { .. } => allowed_count += 1,
                RateLimitOutcome::Limited { .. } => limited_count += 1,
            }
        }

        assert_eq!(allowed_count, 5);
        assert_eq!(limited_count, (num_tasks as u64) - 5);
    }
}
