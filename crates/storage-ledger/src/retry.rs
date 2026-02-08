//! Retry logic for transient storage failures.
//!
//! This module provides [`with_retry`], a utility that wraps an async
//! operation with automatic retry on transient errors (connection failures,
//! timeouts). Non-transient errors (conflict, serialization, not-found)
//! are returned immediately without retry.
//!
//! # Backoff Strategy
//!
//! Retries use exponential backoff with jitter:
//! - Base delay doubles with each attempt: `initial_backoff * 2^attempt`
//! - Delay is capped at `max_backoff`
//! - Random jitter of 0–50% of the computed delay is added to prevent thundering-herd effects
//!   across multiple clients

use std::{future::Future, sync::Arc, time::Duration};

use fail::fail_point;
use inferadb_common_storage::{Metrics, StorageError, StorageResult, TimeoutContext};
use parking_lot::Mutex;
use rand::Rng;

use crate::config::{CasRetryConfig, RetryConfig};

/// Tracks retry state for timeout context reporting.
///
/// Shared between `with_retry_tracked` and `with_retry_timeout` via `Arc<Mutex<...>>`.
/// When a timeout cancels the retry loop, the timeout handler reads this state
/// to produce a [`TimeoutContext`] with details about what the retry loop was doing.
#[derive(Debug, Default)]
struct RetryState {
    /// Number of attempts that completed (returned a result, whether success or error).
    attempts_completed: u32,
    /// Whether the retry loop is currently sleeping (backoff) vs executing an operation.
    during_backoff: bool,
    /// The detail string of the last error returned by the backend.
    /// Stored as a string because `StorageError` is not `Clone`.
    last_error_detail: Option<String>,
}

/// Executes `operation` with automatic retry on transient errors.
///
/// Returns the result of the first successful call, or the last error
/// if all retry attempts are exhausted.
///
/// # Retry Eligibility
///
/// Only errors where [`StorageError::is_transient`] returns `true` are
/// retried. All other errors are propagated immediately.
///
/// # Metrics
///
/// When `metrics` is provided, each retry attempt increments the
/// `retry_count` counter, and exhausted retries increment
/// `retry_exhausted_count`.
#[tracing::instrument(skip(config, metrics, operation), fields(max_retries = config.max_retries))]
pub(crate) async fn with_retry<F, Fut, T>(
    config: &RetryConfig,
    metrics: Option<&Metrics>,
    operation_name: &str,
    mut operation: F,
) -> StorageResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StorageResult<T>>,
{
    let mut last_error: Option<StorageError> = None;

    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(value) => {
                if attempt > 0 {
                    tracing::debug!(
                        operation = operation_name,
                        attempt = attempt + 1,
                        "operation succeeded after retry",
                    );
                }
                return Ok(value);
            },
            Err(err) if err.is_transient() && attempt < config.max_retries => {
                if let Some(m) = metrics {
                    m.record_retry();
                }
                let delay = compute_backoff(config, attempt);
                tracing::debug!(
                    operation = operation_name,
                    attempt = attempt + 1,
                    max_attempts = config.max_retries + 1,
                    delay_ms = delay.as_millis() as u64,
                    error = %err,
                    "transient error, retrying after backoff",
                );
                fail_point!("retry-before-sleep");
                tokio::time::sleep(delay).await;
                last_error = Some(err);
            },
            Err(err) => {
                // Non-transient error on any attempt, or transient on last attempt
                if attempt > 0
                    && err.is_transient()
                    && let Some(m) = metrics
                {
                    m.record_retry_exhausted();
                }
                return Err(err);
            },
        }
    }

    // All retries exhausted — return the last transient error
    if let Some(m) = metrics {
        m.record_retry_exhausted();
    }
    Err(last_error
        .unwrap_or_else(|| StorageError::internal("retry loop completed without result or error")))
}

/// Like [`with_retry`] but also updates a shared `RetryState` so that
/// `with_retry_timeout` can produce informative timeout errors.
#[tracing::instrument(skip(config, metrics, operation, state), fields(max_retries = config.max_retries))]
async fn with_retry_tracked<F, Fut, T>(
    config: &RetryConfig,
    metrics: Option<&Metrics>,
    operation_name: &str,
    mut operation: F,
    state: Arc<Mutex<RetryState>>,
) -> StorageResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StorageResult<T>>,
{
    let mut last_error: Option<StorageError> = None;

    for attempt in 0..=config.max_retries {
        // Mark: entering backend call (not in backoff)
        state.lock().during_backoff = false;

        match operation().await {
            Ok(value) => {
                if attempt > 0 {
                    tracing::debug!(
                        operation = operation_name,
                        attempt = attempt + 1,
                        "operation succeeded after retry",
                    );
                }
                return Ok(value);
            },
            Err(err) if err.is_transient() && attempt < config.max_retries => {
                if let Some(m) = metrics {
                    m.record_retry();
                }
                let delay = compute_backoff(config, attempt);
                tracing::debug!(
                    operation = operation_name,
                    attempt = attempt + 1,
                    max_attempts = config.max_retries + 1,
                    delay_ms = delay.as_millis() as u64,
                    error = %err,
                    "transient error, retrying after backoff",
                );

                // Update shared state before sleeping
                {
                    let mut s = state.lock();
                    s.attempts_completed = attempt + 1;
                    s.during_backoff = true;
                    s.last_error_detail = Some(err.detail());
                }

                last_error = Some(err);
                tokio::time::sleep(delay).await;
            },
            Err(err) => {
                // Non-transient error on any attempt, or transient on last attempt
                {
                    let mut s = state.lock();
                    s.attempts_completed = attempt + 1;
                    s.last_error_detail = Some(err.detail());
                }
                if attempt > 0
                    && err.is_transient()
                    && let Some(m) = metrics
                {
                    m.record_retry_exhausted();
                }
                return Err(err);
            },
        }
    }

    // All retries exhausted — return the last transient error
    if let Some(m) = metrics {
        m.record_retry_exhausted();
    }
    Err(last_error
        .unwrap_or_else(|| StorageError::internal("retry loop completed without result or error")))
}

/// Executes `operation` with retry **and** an overall timeout.
///
/// This wraps [`with_retry`] with `tokio::time::timeout`, bounding the
/// total wall-clock time of the operation including all retry attempts
/// and backoff sleeps.
///
/// When the timeout fires, the resulting `StorageError::Timeout` includes
/// a [`TimeoutContext`] that captures the retry state at the moment of
/// cancellation — how many attempts completed, whether the timeout hit
/// during a backoff sleep or a backend call, and the last backend error.
/// This helps operators distinguish configuration issues (timeout too
/// short for retry config) from backend slowness.
#[tracing::instrument(skip(config, metrics, operation), fields(timeout_ms = timeout.as_millis() as u64, max_retries = config.max_retries))]
pub(crate) async fn with_retry_timeout<F, Fut, T>(
    config: &RetryConfig,
    timeout: Duration,
    metrics: Option<&Metrics>,
    operation_name: &str,
    operation: F,
) -> StorageResult<T>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StorageResult<T>>,
{
    let state = Arc::new(Mutex::new(RetryState::default()));
    let state_clone = Arc::clone(&state);

    match tokio::time::timeout(
        timeout,
        with_retry_tracked(config, metrics, operation_name, operation, state_clone),
    )
    .await
    {
        Ok(result) => result,
        Err(_elapsed) => {
            // Timeout fired — read the retry state to build context
            let s = state.lock();
            let last_error = s
                .last_error_detail
                .as_ref()
                .map(|detail| Box::new(StorageError::internal(detail.clone())));
            let context = TimeoutContext {
                attempts_completed: s.attempts_completed,
                during_backoff: s.during_backoff,
                last_error,
            };
            Err(StorageError::timeout_with_context(context))
        },
    }
}

/// Retries a read-modify-write cycle on CAS conflict.
///
/// The provided `operation` closure should perform the full cycle:
/// read the current value, compute the mutation, and write back with
/// a CAS condition. On [`StorageError::Conflict`], the closure is
/// re-invoked up to `config.max_retries` times with jitter between
/// attempts to reduce contention.
///
/// Non-conflict errors are returned immediately without retry.
///
/// Returns [`StorageError::CasRetriesExhausted`] when all attempts
/// encounter conflicts.
#[tracing::instrument(skip(config, operation), fields(max_retries = config.max_retries))]
pub(crate) async fn with_cas_retry<F, Fut>(
    config: &CasRetryConfig,
    mut operation: F,
) -> StorageResult<()>
where
    F: FnMut() -> Fut,
    Fut: Future<Output = StorageResult<()>>,
{
    for attempt in 0..=config.max_retries {
        match operation().await {
            Ok(()) => return Ok(()),
            Err(StorageError::Conflict { .. }) if attempt < config.max_retries => {
                let jitter = if config.base_delay.as_millis() > 0 {
                    let range = config.base_delay.as_millis() as u64;
                    Duration::from_millis(rand::rng().random_range(0..=range))
                } else {
                    Duration::ZERO
                };
                let delay = config.base_delay + jitter;
                tracing::debug!(
                    attempt = attempt + 1,
                    max_attempts = config.max_retries + 1,
                    delay_ms = delay.as_millis() as u64,
                    "CAS conflict, retrying after jitter",
                );
                fail_point!("cas-retry-before-sleep");
                tokio::time::sleep(delay).await;
            },
            Err(StorageError::Conflict { .. }) => {
                return Err(StorageError::cas_retries_exhausted(config.max_retries + 1));
            },
            Err(e) => return Err(e),
        }
    }

    Err(StorageError::cas_retries_exhausted(config.max_retries + 1))
}

/// Computes the backoff duration for the given attempt number.
///
/// Uses exponential backoff with jitter:
/// `min(initial_backoff * 2^attempt, max_backoff) + random(0..50% of delay)`
fn compute_backoff(config: &RetryConfig, attempt: u32) -> Duration {
    let base = config.initial_backoff.saturating_mul(1u32.checked_shl(attempt).unwrap_or(u32::MAX));
    let capped = base.min(config.max_backoff);

    // Add jitter: 0–50% of the computed delay
    let jitter_range = capped.as_millis() as u64 / 2;
    if jitter_range > 0 {
        let jitter = rand::rng().random_range(0..=jitter_range);
        capped + Duration::from_millis(jitter)
    } else {
        capped
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn test_compute_backoff_exponential() {
        let config = RetryConfig::builder()
            .max_retries(5)
            .initial_backoff(Duration::from_millis(100))
            .max_backoff(Duration::from_secs(10))
            .build()
            .unwrap();

        // Attempt 0: base = 100ms
        let d0 = compute_backoff(&config, 0);
        assert!(d0 >= Duration::from_millis(100));
        assert!(d0 <= Duration::from_millis(150)); // 100 + up to 50% jitter

        // Attempt 1: base = 200ms
        let d1 = compute_backoff(&config, 1);
        assert!(d1 >= Duration::from_millis(200));
        assert!(d1 <= Duration::from_millis(300));

        // Attempt 2: base = 400ms
        let d2 = compute_backoff(&config, 2);
        assert!(d2 >= Duration::from_millis(400));
        assert!(d2 <= Duration::from_millis(600));
    }

    #[test]
    fn test_compute_backoff_capped_at_max() {
        let config = RetryConfig::builder()
            .max_retries(10)
            .initial_backoff(Duration::from_secs(1))
            .max_backoff(Duration::from_secs(5))
            .build()
            .unwrap();

        // Attempt 5: base = 32s, should be capped at 5s
        let d = compute_backoff(&config, 5);
        assert!(d >= Duration::from_secs(5));
        assert!(d <= Duration::from_millis(7500)); // 5s + up to 50% jitter
    }

    #[test]
    fn test_compute_backoff_zero_initial() {
        // Construct directly to bypass validation — zero initial_backoff is
        // rejected by the builder but compute_backoff should still handle it
        // gracefully (returns ZERO).
        let config = RetryConfig {
            max_retries: 3,
            initial_backoff: Duration::ZERO,
            max_backoff: Duration::from_secs(5),
        };

        let d = compute_backoff(&config, 0);
        assert_eq!(d, Duration::ZERO);
    }

    #[tokio::test]
    async fn test_retry_succeeds_first_attempt() {
        let config = RetryConfig::default();
        let call_count = AtomicU32::new(0);

        let result = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Ok::<_, StorageError>(42) }
        })
        .await;

        assert_eq!(result.ok(), Some(42));
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_retry_succeeds_after_transient_failure() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(10))
            .build()
            .unwrap();
        let call_count = AtomicU32::new(0);

        let result =
            with_retry(&config, None, "test_op", || {
                let attempt = call_count.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt < 2 { Err(StorageError::connection("temporary")) } else { Ok(42) }
                }
            })
            .await;

        assert_eq!(result.ok(), Some(42));
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 2 failures + 1 success
    }

    #[tokio::test]
    async fn test_retry_non_transient_error_not_retried() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_backoff(Duration::from_millis(1))
            .build()
            .unwrap();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::conflict()) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Conflict { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 1); // No retries
    }

    #[tokio::test]
    async fn test_retry_exhausted_returns_last_error() {
        let config = RetryConfig::builder()
            .max_retries(2)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(5))
            .build()
            .unwrap();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::timeout()) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Timeout { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn test_retry_disabled_with_zero_max_retries() {
        let config = RetryConfig::builder()
            .max_retries(0)
            .initial_backoff(Duration::from_millis(1))
            .build()
            .unwrap();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::connection("fail")) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Connection { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 1); // No retries
    }

    #[tokio::test]
    async fn test_retry_timeout_then_connection_returns_connection() {
        let config = RetryConfig::builder()
            .max_retries(2)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(5))
            .build()
            .unwrap();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            let attempt = call_count.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt == 0 {
                    Err(StorageError::timeout())
                } else {
                    Err(StorageError::connection("network down"))
                }
            }
        })
        .await;

        // Last error should be returned
        assert!(matches!(result, Err(StorageError::Connection { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 3);
    }

    #[tokio::test]
    async fn test_retry_records_metrics() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(5))
            .build()
            .unwrap();
        let metrics = Metrics::new();
        let call_count = AtomicU32::new(0);

        let result =
            with_retry(&config, Some(&metrics), "test_op", || {
                let attempt = call_count.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt < 2 { Err(StorageError::connection("temporary")) } else { Ok(42) }
                }
            })
            .await;

        assert_eq!(result.ok(), Some(42));
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.retry_count, 2); // 2 retry attempts before success
        assert_eq!(snapshot.retry_exhausted_count, 0); // did not exhaust
    }

    #[tokio::test]
    async fn test_retry_exhausted_records_metrics() {
        let config = RetryConfig::builder()
            .max_retries(2)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(5))
            .build()
            .unwrap();
        let metrics = Metrics::new();

        let result: StorageResult<i32> = with_retry(&config, Some(&metrics), "test_op", || async {
            Err(StorageError::timeout())
        })
        .await;

        assert!(matches!(result, Err(StorageError::Timeout { .. })));
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.retry_count, 2); // 2 retry attempts
        assert_eq!(snapshot.retry_exhausted_count, 1); // exhausted
    }

    #[tokio::test]
    async fn test_timeout_triggers_on_slow_operation() {
        let config = RetryConfig::builder()
            .max_retries(0)
            .initial_backoff(Duration::from_millis(1))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(42)
            })
            .await;

        assert!(matches!(result, Err(StorageError::Timeout { .. })));
    }

    #[tokio::test]
    async fn test_timeout_allows_fast_operation() {
        let config = RetryConfig::default();

        let result =
            with_retry_timeout(&config, Duration::from_secs(5), None, "test_op", || async {
                Ok::<_, StorageError>(42)
            })
            .await;

        assert_eq!(result.ok(), Some(42));
    }

    #[tokio::test]
    async fn test_timeout_bounds_retries() {
        // Retries with backoff would take longer than the timeout,
        // so the timeout should fire before retries exhaust.
        let config = RetryConfig::builder()
            .max_retries(100)
            .initial_backoff(Duration::from_secs(1))
            .max_backoff(Duration::from_secs(5))
            .build()
            .unwrap();

        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(100), None, "test_op", || {
                call_count.fetch_add(1, Ordering::Relaxed);
                async { Err(StorageError::timeout()) }
            })
            .await;

        assert!(matches!(result, Err(StorageError::Timeout { .. })));
        // Should not have exhausted all 100 retries — timeout should fire first
        let calls = call_count.load(Ordering::Relaxed);
        assert!(calls < 100, "expected timeout to fire before all retries, got {calls} calls");
    }

    // ── CAS retry tests ──────────────────────────────────────

    #[tokio::test]
    async fn test_cas_retry_succeeds_first_attempt() {
        let config = CasRetryConfig::default();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Ok(()) }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_cas_retry_succeeds_after_conflict() {
        let config =
            CasRetryConfig::builder().max_retries(3).base_delay(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            let attempt = call_count.fetch_add(1, Ordering::Relaxed);
            async move { if attempt < 2 { Err(StorageError::conflict()) } else { Ok(()) } }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 2 conflicts + 1 success
    }

    #[tokio::test]
    async fn test_cas_retry_exhausted_returns_cas_retries_exhausted() {
        let config =
            CasRetryConfig::builder().max_retries(2).base_delay(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::conflict()) }
        })
        .await;

        assert!(
            matches!(result, Err(StorageError::CasRetriesExhausted { attempts: 3, .. })),
            "expected CasRetriesExhausted with 3 attempts, got: {result:?}",
        );
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn test_cas_retry_non_conflict_error_not_retried() {
        let config =
            CasRetryConfig::builder().max_retries(5).base_delay(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::not_found("missing")) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::NotFound { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 1); // No retries
    }

    #[tokio::test]
    async fn test_cas_retry_disabled_with_zero_max_retries() {
        let config =
            CasRetryConfig::builder().max_retries(0).base_delay(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::conflict()) }
        })
        .await;

        assert!(
            matches!(result, Err(StorageError::CasRetriesExhausted { attempts: 1, .. })),
            "expected CasRetriesExhausted with 1 attempt, got: {result:?}",
        );
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_cas_retry_transient_error_not_retried() {
        // CAS retry should NOT retry transient errors — only Conflict.
        let config =
            CasRetryConfig::builder().max_retries(5).base_delay(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::connection("network down")) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Connection { .. })));
        assert_eq!(call_count.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn test_cas_retry_zero_base_delay() {
        let config = CasRetryConfig::builder().max_retries(2).base_delay(Duration::ZERO).build();
        let call_count = AtomicU32::new(0);

        let result = with_cas_retry(&config, || {
            let attempt = call_count.fetch_add(1, Ordering::Relaxed);
            async move { if attempt < 1 { Err(StorageError::conflict()) } else { Ok(()) } }
        })
        .await;

        assert!(result.is_ok());
        assert_eq!(call_count.load(Ordering::Relaxed), 2);
    }

    #[tokio::test]
    async fn test_timeout_during_first_attempt_has_context() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_backoff(Duration::from_millis(10))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(42)
            })
            .await;

        let err = result.unwrap_err();
        match &err {
            StorageError::Timeout { context: Some(ctx), .. } => {
                assert_eq!(ctx.attempts_completed, 0, "no attempt should have completed");
                assert!(!ctx.during_backoff, "should not be during backoff on first attempt");
                assert!(ctx.last_error.is_none(), "no prior error on first attempt");
            },
            other => panic!("expected Timeout with context, got: {other:?}"),
        }
        // Verify Display includes context
        let display = err.to_string();
        assert!(
            display.contains("timeout during backend operation on attempt 1"),
            "unexpected display: {display}"
        );
    }

    #[tokio::test]
    async fn test_timeout_during_backoff_sleep_has_context() {
        // Fast-failing operation + long backoff → timeout fires during sleep
        let config = RetryConfig::builder()
            .max_retries(100)
            .initial_backoff(Duration::from_secs(60))
            .max_backoff(Duration::from_secs(60))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                Err(StorageError::connection("test failure"))
            })
            .await;

        let err = result.unwrap_err();
        match &err {
            StorageError::Timeout { context: Some(ctx), .. } => {
                assert!(ctx.attempts_completed >= 1, "at least one attempt should complete");
                assert!(ctx.during_backoff, "should be during backoff when timeout fires");
                assert!(ctx.last_error.is_some(), "should have last error from the failed attempt");
            },
            other => panic!("expected Timeout with context, got: {other:?}"),
        }
        let display = err.to_string();
        assert!(display.contains("timeout during retry backoff"), "unexpected display: {display}");
    }

    #[tokio::test]
    async fn test_timeout_during_nth_retry_attempt_has_context() {
        // First attempt fails fast, second attempt hangs → timeout during backend op
        let call_count = AtomicU32::new(0);

        let config = RetryConfig::builder()
            .max_retries(10)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(1))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(100), None, "test_op", || {
                let attempt = call_count.fetch_add(1, Ordering::Relaxed);
                async move {
                    if attempt < 1 {
                        // First attempt: fail fast with transient error
                        Err(StorageError::connection("transient"))
                    } else {
                        // Second attempt: hang
                        tokio::time::sleep(Duration::from_secs(60)).await;
                        Ok(42)
                    }
                }
            })
            .await;

        let err = result.unwrap_err();
        match &err {
            StorageError::Timeout { context: Some(ctx), .. } => {
                assert_eq!(ctx.attempts_completed, 1, "first attempt completed before timeout");
                assert!(!ctx.during_backoff, "should be during backend op, not backoff");
                assert!(ctx.last_error.is_some(), "should have last error from first attempt");
            },
            other => panic!("expected Timeout with context, got: {other:?}"),
        }
        let display = err.to_string();
        assert!(
            display.contains("timeout during backend operation on attempt 2"),
            "unexpected display: {display}"
        );
    }

    #[tokio::test]
    async fn test_timeout_detail_includes_retry_context() {
        let config = RetryConfig::builder()
            .max_retries(100)
            .initial_backoff(Duration::from_secs(60))
            .max_backoff(Duration::from_secs(60))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                Err(StorageError::connection("ledger unreachable"))
            })
            .await;

        let err = result.unwrap_err();
        let detail = err.detail();
        assert!(
            detail.contains("during_backoff=true"),
            "detail should include during_backoff: {detail}"
        );
        assert!(
            detail.contains("attempts_completed="),
            "detail should include attempts_completed: {detail}"
        );
        assert!(detail.contains("last_error="), "detail should include last_error: {detail}");
    }

    #[tokio::test]
    async fn test_timeout_without_retries_has_context() {
        // max_retries=0 means just one attempt, no retries
        let config = RetryConfig::builder()
            .max_retries(0)
            .initial_backoff(Duration::from_millis(1))
            .build()
            .unwrap();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(42)
            })
            .await;

        let err = result.unwrap_err();
        match &err {
            StorageError::Timeout { context: Some(ctx), .. } => {
                assert_eq!(ctx.attempts_completed, 0);
                assert!(!ctx.during_backoff);
                assert!(ctx.last_error.is_none());
            },
            other => panic!("expected Timeout with context, got: {other:?}"),
        }
    }
}
