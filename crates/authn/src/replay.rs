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

/// Detects and rejects replayed JWTs via JTI tracking.
///
/// Implementations track seen JTI values and reject duplicates,
/// automatically cleaning up expired entries.
#[async_trait]
pub trait ReplayDetector: Send + Sync {
    /// Checks whether a JTI has been seen before and marks it as seen.
    ///
    /// Implementations must ensure this check-and-mark operation is atomic.
    ///
    /// # Arguments
    ///
    /// * `jti` — The JWT ID claim value
    /// * `expires_in` — Duration until the token expires. Used to set entry TTL; entries may be
    ///   evicted before this duration if capacity limits are reached.
    ///
    /// # Errors
    ///
    /// Returns [`AuthError::TokenReplayed`] if the JTI was already recorded.
    async fn check_and_mark(&self, jti: &str, expires_in: Duration) -> Result<(), AuthError>;
}

/// Per-entry expiry policy that computes remaining lifetime from the stored expiration instant.
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

/// In-memory replay detector with per-entry TTL and LRU eviction.
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
    /// Creates a new replay detector with the given maximum capacity.
    ///
    /// # Arguments
    ///
    /// * `max_capacity` — Maximum number of JTI entries tracked simultaneously. When capacity is
    ///   exceeded, the least-recently-used entry is evicted.
    #[must_use = "constructing a replay detector has no side effects"]
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
        let expiration = Instant::now() + expires_in;

        // Atomic check-and-insert: `or_insert_with` ensures that concurrent
        // callers with the same JTI coalesce — only one future evaluates, and
        // subsequent callers see `is_fresh() == false`.
        let entry = self.seen.entry(jti.to_owned()).or_insert_with(async { expiration }).await;

        if entry.is_fresh() { Ok(()) } else { Err(AuthError::token_replayed(jti)) }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::Arc;

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

        // With zero TTL the entry expires immediately, so moka may evict it
        // before the next call. We only guarantee the first presentation succeeds;
        // whether a zero-TTL entry survives long enough to reject a replay is
        // implementation-dependent and not something callers should rely on.
    }

    #[tokio::test]
    async fn test_concurrent_replay_exactly_one_succeeds() {
        let detector = Arc::new(InMemoryReplayDetector::new(100));
        let task_count = 20;
        let mut handles = Vec::with_capacity(task_count);

        for _ in 0..task_count {
            let det = Arc::clone(&detector);
            handles.push(tokio::spawn(async move {
                det.check_and_mark("racy-jti", Duration::from_secs(60)).await
            }));
        }

        let mut ok_count = 0usize;
        let mut replayed_count = 0usize;
        for handle in handles {
            match handle.await.unwrap() {
                Ok(()) => ok_count += 1,
                Err(AuthError::TokenReplayed { .. }) => replayed_count += 1,
                Err(other) => panic!("unexpected error variant: {other}"),
            }
        }

        assert_eq!(ok_count, 1, "exactly one task should succeed");
        assert_eq!(replayed_count, task_count - 1, "all others should be rejected as replays");
    }
}
