//! JWT replay prevention via JTI (JWT ID) tracking.
//!
//! When enabled, the replay detector maintains a set of recently-seen JTI values.
//! Tokens presented more than once within their validity window are rejected,
//! preventing replay attacks where a captured JWT is reused by an attacker.
//!
//! # Usage
//!
//! ```no_run
//! use std::time::Duration;
//! use inferadb_common_authn::replay::InMemoryReplayDetector;
//!
//! // Create a replay detector bounded to 10_000 tracked JTIs
//! let detector = InMemoryReplayDetector::new(10_000);
//! ```
//!
//! # Design
//!
//! - **Opt-in**: Replay detection is not required. Pass a `ReplayDetector` to
//!   [`crate::jwt::verify_with_replay_detection`] to enable it.
//! - **Per-entry expiry**: Each JTI entry expires when the token itself expires, bounding memory
//!   usage automatically.
//! - **Capacity-bounded**: The in-memory implementation uses LRU eviction as a safety net beyond
//!   per-entry TTL.

use std::time::{Duration, Instant};

use async_trait::async_trait;
use moka::{future::Cache, policy::EvictionPolicy};

use crate::error::AuthError;

/// Trait for JWT replay detection.
///
/// Implementations track seen JTI values and reject duplicates.
/// The detector is responsible for automatically cleaning up expired entries.
#[async_trait]
pub trait ReplayDetector: Send + Sync {
    /// Check whether a JTI has been seen before and mark it as seen.
    ///
    /// # Arguments
    ///
    /// * `jti` — The JWT ID claim value
    /// * `expires_in` — Duration until the token expires (used for entry TTL)
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenReplayed`] if the JTI was already recorded.
    async fn check_and_mark(&self, jti: &str, expires_in: Duration) -> Result<(), AuthError>;
}

/// Per-entry expiry policy that stores the remaining lifetime at insertion time.
struct JtiExpiry;

impl moka::Expiry<String, Instant> for JtiExpiry {
    fn expire_after_create(
        &self,
        _key: &String,
        value: &Instant,
        created_at: Instant,
    ) -> Option<Duration> {
        // `value` holds the absolute expiration instant.
        // Return remaining duration, or zero if already past.
        Some(value.saturating_duration_since(created_at))
    }
}

/// In-memory replay detector backed by a [`moka::future::Cache`].
///
/// Each JTI is stored with a per-entry TTL matching the token's remaining
/// lifetime, ensuring automatic cleanup. The cache is also capacity-bounded
/// with LRU eviction as a safety net.
///
/// # Thread Safety
///
/// `InMemoryReplayDetector` is `Send + Sync` and safe for concurrent use
/// from multiple async tasks.
pub struct InMemoryReplayDetector {
    /// Cache mapping JTI → expiration instant.
    seen: Cache<String, Instant>,
}

impl InMemoryReplayDetector {
    /// Create a new replay detector with the given maximum capacity.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` — Maximum number of JTI entries tracked simultaneously. When capacity is
    ///   exceeded, the least-recently-used entry is evicted.
    pub fn new(max_capacity: u64) -> Self {
        let seen = Cache::builder()
            .max_capacity(max_capacity)
            .eviction_policy(EvictionPolicy::lru())
            .expire_after(JtiExpiry)
            .build();
        Self { seen }
    }
}

#[async_trait]
impl ReplayDetector for InMemoryReplayDetector {
    async fn check_and_mark(&self, jti: &str, expires_in: Duration) -> Result<(), AuthError> {
        let key = jti.to_owned();
        let expiration = Instant::now() + expires_in;

        // Try to insert; if the key already exists, this is a replay.
        let existed = self.seen.contains_key(&key);
        if existed {
            return Err(AuthError::token_replayed(jti));
        }

        self.seen.insert(key, expiration).await;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_first_presentation_accepted() {
        let detector = InMemoryReplayDetector::new(100);
        let result = detector.check_and_mark("jti-001", Duration::from_secs(60)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_second_presentation_rejected() {
        let detector = InMemoryReplayDetector::new(100);
        detector.check_and_mark("jti-002", Duration::from_secs(60)).await.unwrap();

        let result = detector.check_and_mark("jti-002", Duration::from_secs(60)).await;
        assert!(result.is_err());
        assert!(
            matches!(&result.unwrap_err(), AuthError::TokenReplayed { jti, .. } if jti == "jti-002")
        );
    }

    #[tokio::test]
    async fn test_different_jtis_accepted() {
        let detector = InMemoryReplayDetector::new(100);
        detector.check_and_mark("jti-a", Duration::from_secs(60)).await.unwrap();
        let result = detector.check_and_mark("jti-b", Duration::from_secs(60)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_jti_cleanup_after_expiration() {
        let detector = InMemoryReplayDetector::new(100);
        // Insert with very short TTL
        detector.check_and_mark("jti-expire", Duration::from_millis(50)).await.unwrap();

        // Wait for expiration
        tokio::time::sleep(Duration::from_millis(100)).await;
        // Run pending maintenance tasks
        detector.seen.run_pending_tasks().await;

        // Should be accepted again after expiration
        let result = detector.check_and_mark("jti-expire", Duration::from_millis(5000)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_capacity_eviction() {
        // Create a detector with capacity 2
        let detector = InMemoryReplayDetector::new(2);

        detector.check_and_mark("jti-1", Duration::from_secs(300)).await.unwrap();
        detector.check_and_mark("jti-2", Duration::from_secs(300)).await.unwrap();
        detector.check_and_mark("jti-3", Duration::from_secs(300)).await.unwrap();

        // Run pending tasks to trigger eviction
        detector.seen.run_pending_tasks().await;

        // jti-1 should have been evicted (LRU)
        let result = detector.check_and_mark("jti-1", Duration::from_secs(300)).await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_zero_duration_entry() {
        let detector = InMemoryReplayDetector::new(100);
        // A token with zero remaining lifetime — should still be tracked briefly
        let result = detector.check_and_mark("jti-zero", Duration::ZERO).await;
        assert!(result.is_ok());
    }
}
