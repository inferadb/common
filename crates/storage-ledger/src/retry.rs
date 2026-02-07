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

use std::{future::Future, time::Duration};

use inferadb_common_storage::{Metrics, StorageError, StorageResult};
use rand::Rng;

use crate::config::RetryConfig;

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

/// Executes `operation` with retry **and** an overall timeout.
///
/// This wraps [`with_retry`] with `tokio::time::timeout`, bounding the
/// total wall-clock time of the operation including all retry attempts
/// and backoff sleeps.
///
/// Returns `StorageError::Timeout` if the deadline is exceeded.
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
    tokio::time::timeout(timeout, with_retry(config, metrics, operation_name, operation))
        .await
        .unwrap_or(Err(StorageError::Timeout))
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
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

    #[test]
    fn test_compute_backoff_exponential() {
        let config = RetryConfig::builder()
            .max_retries(5)
            .initial_backoff(Duration::from_millis(100))
            .max_backoff(Duration::from_secs(10))
            .build();

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
            .build();

        // Attempt 5: base = 32s, should be capped at 5s
        let d = compute_backoff(&config, 5);
        assert!(d >= Duration::from_secs(5));
        assert!(d <= Duration::from_millis(7500)); // 5s + up to 50% jitter
    }

    #[test]
    fn test_compute_backoff_zero_initial() {
        let config = RetryConfig::builder()
            .max_retries(3)
            .initial_backoff(Duration::ZERO)
            .max_backoff(Duration::from_secs(5))
            .build();

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
            .build();
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
        let config =
            RetryConfig::builder().max_retries(3).initial_backoff(Duration::from_millis(1)).build();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::Conflict) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Conflict)));
        assert_eq!(call_count.load(Ordering::Relaxed), 1); // No retries
    }

    #[tokio::test]
    async fn test_retry_exhausted_returns_last_error() {
        let config = RetryConfig::builder()
            .max_retries(2)
            .initial_backoff(Duration::from_millis(1))
            .max_backoff(Duration::from_millis(5))
            .build();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            call_count.fetch_add(1, Ordering::Relaxed);
            async { Err(StorageError::Timeout) }
        })
        .await;

        assert!(matches!(result, Err(StorageError::Timeout)));
        assert_eq!(call_count.load(Ordering::Relaxed), 3); // 1 initial + 2 retries
    }

    #[tokio::test]
    async fn test_retry_disabled_with_zero_max_retries() {
        let config =
            RetryConfig::builder().max_retries(0).initial_backoff(Duration::from_millis(1)).build();
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
            .build();
        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> = with_retry(&config, None, "test_op", || {
            let attempt = call_count.fetch_add(1, Ordering::Relaxed);
            async move {
                if attempt == 0 {
                    Err(StorageError::Timeout)
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
            .build();
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
            .build();
        let metrics = Metrics::new();

        let result: StorageResult<i32> =
            with_retry(&config, Some(&metrics), "test_op", || async { Err(StorageError::Timeout) })
                .await;

        assert!(matches!(result, Err(StorageError::Timeout)));
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.retry_count, 2); // 2 retry attempts
        assert_eq!(snapshot.retry_exhausted_count, 1); // exhausted
    }

    #[tokio::test]
    async fn test_timeout_triggers_on_slow_operation() {
        let config =
            RetryConfig::builder().max_retries(0).initial_backoff(Duration::from_millis(1)).build();

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(50), None, "test_op", || async {
                tokio::time::sleep(Duration::from_secs(10)).await;
                Ok(42)
            })
            .await;

        assert!(matches!(result, Err(StorageError::Timeout)));
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
            .build();

        let call_count = AtomicU32::new(0);

        let result: StorageResult<i32> =
            with_retry_timeout(&config, Duration::from_millis(100), None, "test_op", || {
                call_count.fetch_add(1, Ordering::Relaxed);
                async { Err(StorageError::Timeout) }
            })
            .await;

        assert!(matches!(result, Err(StorageError::Timeout)));
        // Should not have exhausted all 100 retries — timeout should fire first
        let calls = call_count.load(Ordering::Relaxed);
        assert!(calls < 100, "expected timeout to fire before all retries, got {calls} calls");
    }
}
