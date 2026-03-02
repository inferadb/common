//! Retry logic for CAS (compare-and-set) conflict resolution.
//!
//! This module provides [`with_cas_retry`], a utility that retries a
//! read-modify-write cycle when the write fails due to a CAS conflict.
//! Transient errors (connection failures, timeouts) are delegated to
//! the SDK's built-in retry logic and are not retried here.

use std::{future::Future, time::Duration};

use fail::fail_point;
use inferadb_common_storage::{StorageError, StorageResult};
use rand::RngExt;

use crate::config::CasRetryConfig;

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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use super::*;

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
}
