//! Distributed fixed-window rate limiter using [`StorageBackend`].
//!
//! [`AppRateLimiter`] provides a generic, storage-backed rate limiter that
//! works with any [`StorageBackend`] implementation. Counters are stored with
//! TTL for automatic cleanup.
//!
//! # Key Format
//!
//! Rate limit counters are stored as:
//! `rate_limit:{category}:{identifier}:{window_start}`
//!
//! # Examples
//!
//! ```no_run
//! use inferadb_common_storage::MemoryBackend;
//! use inferadb_common_ratelimit::{AppRateLimiter, RateLimitPolicy};
//!
//! # async fn example() -> Result<(), Box<dyn std::error::Error>> {
//! let storage = MemoryBackend::new();
//! let limiter = AppRateLimiter::new(storage);
//!
//! let policy = RateLimitPolicy::per_hour(100);
//! let allowed = limiter.check("login_ip", "192.168.1.1", &policy).await?;
//! # Ok(())
//! # }
//! ```

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use inferadb_common_storage::{StorageBackend, StorageError, StorageResult};

/// Rate limit window duration.
#[derive(Debug, Clone, Copy)]
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

    /// Returns seconds until the current window expires.
    fn seconds_until_reset(&self, now: SystemTime) -> u64 {
        let window_start = self.window_start(now);
        let window_seconds = self.seconds();
        let now_secs = now.duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
        window_start + window_seconds - now_secs
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
    #[must_use]
    pub fn new(max_requests: u32, window: RateLimitWindow) -> Self {
        Self { max_requests, window }
    }

    /// Creates an hourly rate limit policy.
    #[must_use]
    pub fn per_hour(max_requests: u32) -> Self {
        Self::new(max_requests, RateLimitWindow::Hour)
    }

    /// Creates a daily rate limit policy.
    #[must_use]
    pub fn per_day(max_requests: u32) -> Self {
        Self::new(max_requests, RateLimitWindow::Day)
    }

    /// Creates a rate limit policy with a custom window duration.
    #[must_use]
    pub fn custom(max_requests: u32, window: Duration) -> Self {
        Self::new(max_requests, RateLimitWindow::Custom(window))
    }
}

/// Rate limit check outcome with metadata.
///
/// Contains the allow/deny decision and metadata useful for response headers
/// (e.g. `X-RateLimit-Remaining`, `Retry-After`).
#[derive(Debug, Clone)]
pub struct RateLimitOutcome {
    /// Whether the request is allowed.
    pub allowed: bool,
    /// Remaining requests in the current window.
    pub remaining: u32,
    /// Seconds until the window resets.
    pub reset_after: u64,
}

/// Distributed fixed-window rate limiter backed by a [`StorageBackend`].
///
/// Uses storage-backed counters with TTL for automatic cleanup. Each
/// counter key includes the category, identifier, and window start
/// timestamp for proper isolation and rotation.
///
/// # Examples
///
/// ```no_run
/// use inferadb_common_storage::MemoryBackend;
/// use inferadb_common_ratelimit::{AppRateLimiter, RateLimitPolicy};
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// let limiter = AppRateLimiter::new(MemoryBackend::new());
///
/// let policy = RateLimitPolicy::per_hour(100);
/// let outcome = limiter.check_with_metadata("login_ip", "192.168.1.1", &policy).await?;
/// if outcome.allowed {
///     // process request
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

    /// Parses the counter value from stored bytes.
    fn parse_counter(bytes: &[u8]) -> StorageResult<u32> {
        let count_str = std::str::from_utf8(bytes).map_err(|e| {
            StorageError::internal(format!("invalid rate limit counter encoding: {e}"))
        })?;
        count_str
            .parse::<u32>()
            .map_err(|e| StorageError::internal(format!("invalid rate limit counter value: {e}")))
    }

    /// Checks whether a request is allowed under the given rate limit policy.
    ///
    /// Returns `Ok(true)` if the request is allowed, `Ok(false)` if the rate
    /// limit has been exceeded.
    ///
    /// # Arguments
    ///
    /// * `category` - Rate limit category (e.g., `"login_ip"`, `"api_key"`)
    /// * `identifier` - Unique identifier within the category (e.g., IP address)
    /// * `policy` - The rate limit policy to enforce
    pub async fn check(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimitPolicy,
    ) -> StorageResult<bool> {
        let now = SystemTime::now();
        let window_start = policy.window.window_start(now);
        let key = Self::counter_key(category, identifier, window_start);

        let current_count = match self.storage.get(&key).await? {
            Some(bytes) => Self::parse_counter(&bytes)?,
            None => 0,
        };

        if current_count >= policy.max_requests {
            return Ok(false);
        }

        let new_count = current_count + 1;
        let ttl = Duration::from_secs(policy.window.seconds());

        self.storage.set_with_ttl(key, new_count.to_string().into_bytes(), ttl).await?;

        Ok(true)
    }

    /// Returns the number of requests remaining in the current window.
    pub async fn remaining(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimitPolicy,
    ) -> StorageResult<u32> {
        let now = SystemTime::now();
        let window_start = policy.window.window_start(now);
        let key = Self::counter_key(category, identifier, window_start);

        let current_count = match self.storage.get(&key).await? {
            Some(bytes) => Self::parse_counter(&bytes)?,
            None => 0,
        };

        Ok(policy.max_requests.saturating_sub(current_count))
    }

    /// Returns seconds until the rate limit window resets.
    #[must_use]
    pub fn reset_after(&self, policy: &RateLimitPolicy) -> u64 {
        policy.window.seconds_until_reset(SystemTime::now())
    }

    /// Checks the rate limit and returns a detailed outcome with metadata.
    ///
    /// This is a convenience method that returns both the allow/deny decision
    /// and metadata useful for response headers (`X-RateLimit-Remaining`,
    /// `Retry-After`).
    pub async fn check_with_metadata(
        &self,
        category: &str,
        identifier: &str,
        policy: &RateLimitPolicy,
    ) -> StorageResult<RateLimitOutcome> {
        let allowed = self.check(category, identifier, policy).await?;
        let remaining =
            if allowed { self.remaining(category, identifier, policy).await? } else { 0 };
        let reset_after = self.reset_after(policy);

        Ok(RateLimitOutcome { allowed, remaining, reset_after })
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
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
    fn policy_constructors() {
        let hourly = RateLimitPolicy::per_hour(100);
        assert_eq!(hourly.max_requests, 100);
        assert_eq!(hourly.window.seconds(), 3600);

        let daily = RateLimitPolicy::per_day(5);
        assert_eq!(daily.max_requests, 5);
        assert_eq!(daily.window.seconds(), 86400);

        let custom = RateLimitPolicy::custom(50, Duration::from_secs(300));
        assert_eq!(custom.max_requests, 50);
        assert_eq!(custom.window.seconds(), 300);
    }

    #[tokio::test]
    async fn allows_requests_under_limit() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(5);

        for _ in 0..5 {
            assert!(limiter.check("test", "user1", &policy).await.unwrap());
        }
    }

    #[tokio::test]
    async fn blocks_requests_over_limit() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(3);

        for _ in 0..3 {
            assert!(limiter.check("test", "user1", &policy).await.unwrap());
        }

        assert!(!limiter.check("test", "user1", &policy).await.unwrap());
    }

    #[tokio::test]
    async fn isolates_identifiers() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(2);

        assert!(limiter.check("test", "user1", &policy).await.unwrap());
        assert!(limiter.check("test", "user1", &policy).await.unwrap());
        assert!(!limiter.check("test", "user1", &policy).await.unwrap());

        // user2 is unaffected
        assert!(limiter.check("test", "user2", &policy).await.unwrap());
        assert!(limiter.check("test", "user2", &policy).await.unwrap());
    }

    #[tokio::test]
    async fn isolates_categories() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(2);

        assert!(limiter.check("cat1", "user1", &policy).await.unwrap());
        assert!(limiter.check("cat1", "user1", &policy).await.unwrap());
        assert!(!limiter.check("cat1", "user1", &policy).await.unwrap());

        // Different category is unaffected
        assert!(limiter.check("cat2", "user1", &policy).await.unwrap());
        assert!(limiter.check("cat2", "user1", &policy).await.unwrap());
    }

    #[tokio::test]
    async fn remaining_count_decreases() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(5);

        assert_eq!(limiter.remaining("test", "user1", &policy).await.unwrap(), 5);

        limiter.check("test", "user1", &policy).await.unwrap();
        assert_eq!(limiter.remaining("test", "user1", &policy).await.unwrap(), 4);

        limiter.check("test", "user1", &policy).await.unwrap();
        assert_eq!(limiter.remaining("test", "user1", &policy).await.unwrap(), 3);
    }

    #[tokio::test]
    async fn check_with_metadata_returns_full_outcome() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(3);

        let outcome = limiter.check_with_metadata("test", "user1", &policy).await.unwrap();
        assert!(outcome.allowed);
        assert_eq!(outcome.remaining, 2);
        assert!(outcome.reset_after > 0);
        assert!(outcome.reset_after <= 3600);

        let outcome = limiter.check_with_metadata("test", "user1", &policy).await.unwrap();
        assert!(outcome.allowed);
        assert_eq!(outcome.remaining, 1);

        let outcome = limiter.check_with_metadata("test", "user1", &policy).await.unwrap();
        assert!(outcome.allowed);
        assert_eq!(outcome.remaining, 0);

        // Over limit
        let outcome = limiter.check_with_metadata("test", "user1", &policy).await.unwrap();
        assert!(!outcome.allowed);
        assert_eq!(outcome.remaining, 0);
    }

    #[tokio::test]
    async fn reset_after_is_within_window() {
        let limiter = AppRateLimiter::new(MemoryBackend::new());
        let policy = RateLimitPolicy::per_hour(10);

        let reset = limiter.reset_after(&policy);
        assert!(reset > 0);
        assert!(reset <= 3600);
    }
}
