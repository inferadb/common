//! Health check types for storage backends.
//!
//! This module provides the [`HealthStatus`] enum and [`HealthMetadata`] struct
//! returned by [`StorageBackend::health_check`](crate::StorageBackend::health_check).
//! These types allow backends to report granular health information beyond a
//! simple healthy/unhealthy binary signal.
//!
//! # Probe Types
//!
//! Kubernetes (and similar orchestrators) distinguish three health signals:
//!
//! - **Liveness** — process is alive and not deadlocked. Failure triggers a container restart.
//! - **Readiness** — backend can serve traffic. Failure removes the pod from the load balancer.
//! - **Startup** — initial warm-up is complete. Failure prevents traffic until ready.
//!
//! See [`HealthProbe`] for the enum passed to
//! [`StorageBackend::health_check`](crate::StorageBackend::health_check).
//!
//! # Health States
//!
//! - **Healthy**: The backend is fully operational.
//! - **Degraded**: The backend can serve traffic but with reduced capability (e.g., circuit breaker
//!   half-open, fallback cache in use, elevated latency).
//! - **Unhealthy**: The backend cannot serve traffic reliably.
//!
//! # Mapping to HTTP / Kubernetes
//!
//! | `HealthProbe`  | `HealthStatus` | HTTP Status | Kubernetes Probe   |
//! |----------------|----------------|-------------|--------------------|
//! | `Liveness`     | `Healthy`      | 200 OK      | liveness: pass     |
//! | `Readiness`    | `Healthy`      | 200 OK      | readiness: pass    |
//! | `Readiness`    | `Degraded`     | 200 OK      | readiness: pass    |
//! | `Readiness`    | `Unhealthy`    | 503         | readiness: fail    |
//! | `Startup`      | `Healthy`      | 200 OK      | startup: pass      |

use std::{collections::HashMap, fmt, time::Duration};

/// The type of health probe to perform.
///
/// Different probe types have different failure semantics:
///
/// - **`Liveness`** — checks that the process is alive and the async runtime is responsive. A
///   failure triggers a container restart. Expected to succeed unless the process is deadlocked or
///   critically resource-exhausted.
///
/// - **`Readiness`** — checks that the backend can serve traffic. This is the original
///   `health_check` behavior: verifying connectivity to the underlying store, cache health, etc. A
///   failure removes the pod from the load balancer but does not restart it.
///
/// - **`Startup`** — checks that initial warm-up is complete (first connection established, initial
///   caches populated). A failure tells the orchestrator to keep waiting before sending traffic.
///   Once startup succeeds, the readiness probe takes over.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum HealthProbe {
    /// Process is alive and not deadlocked.
    Liveness,
    /// Backend can serve traffic (connection healthy, caches warm).
    Readiness,
    /// Initial warm-up is complete (first connection established).
    Startup,
}

impl fmt::Display for HealthProbe {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Liveness => write!(f, "liveness"),
            Self::Readiness => write!(f, "readiness"),
            Self::Startup => write!(f, "startup"),
        }
    }
}

/// Health status returned by [`StorageBackend::health_check`](crate::StorageBackend::health_check).
///
/// Each variant carries [`HealthMetadata`] with timing and backend-specific details.
///
/// # Examples
///
/// ```no_run
/// use inferadb_common_storage::health::{HealthStatus, HealthMetadata};
/// use std::time::Duration;
///
/// let status = HealthStatus::healthy(HealthMetadata::new(
///     Duration::from_millis(2),
///     "memory",
/// ));
/// assert!(status.is_healthy());
/// ```
#[derive(Debug, Clone)]
pub enum HealthStatus {
    /// Backend is fully operational.
    Healthy(HealthMetadata),
    /// Backend is operational but with reduced capability.
    ///
    /// The `String` describes the degradation reason (e.g., "circuit breaker half-open",
    /// "elevated latency", "fallback cache active").
    Degraded(HealthMetadata, String),
    /// Backend cannot serve traffic reliably.
    ///
    /// The `String` describes the failure reason.
    Unhealthy(HealthMetadata, String),
}

impl HealthStatus {
    /// Creates a `Healthy` status.
    #[must_use = "creating a status has no side effects"]
    pub fn healthy(metadata: HealthMetadata) -> Self {
        Self::Healthy(metadata)
    }

    /// Creates a `Degraded` status with a reason.
    #[must_use = "creating a status has no side effects"]
    pub fn degraded(metadata: HealthMetadata, reason: impl Into<String>) -> Self {
        Self::Degraded(metadata, reason.into())
    }

    /// Creates an `Unhealthy` status with a reason.
    #[must_use = "creating a status has no side effects"]
    pub fn unhealthy(metadata: HealthMetadata, reason: impl Into<String>) -> Self {
        Self::Unhealthy(metadata, reason.into())
    }

    /// Returns `true` if the backend is fully healthy.
    #[must_use = "health status predicates should be checked"]
    pub fn is_healthy(&self) -> bool {
        matches!(self, Self::Healthy(_))
    }

    /// Returns `true` if the backend is degraded.
    #[must_use = "health status predicates should be checked"]
    pub fn is_degraded(&self) -> bool {
        matches!(self, Self::Degraded(..))
    }

    /// Returns `true` if the backend is unhealthy.
    #[must_use = "health status predicates should be checked"]
    pub fn is_unhealthy(&self) -> bool {
        matches!(self, Self::Unhealthy(..))
    }

    /// Returns the metadata associated with this health status.
    #[must_use = "returns metadata by reference without side effects"]
    pub fn metadata(&self) -> &HealthMetadata {
        match self {
            Self::Healthy(m) | Self::Degraded(m, _) | Self::Unhealthy(m, _) => m,
        }
    }

    /// Returns the degradation or failure reason, if any.
    #[must_use = "returns the reason without side effects"]
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Healthy(_) => None,
            Self::Degraded(_, reason) | Self::Unhealthy(_, reason) => Some(reason),
        }
    }
}

impl std::fmt::Display for HealthStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Healthy(m) => write!(f, "healthy ({}ms)", m.check_duration.as_millis()),
            Self::Degraded(m, reason) => {
                write!(f, "degraded: {} ({}ms)", reason, m.check_duration.as_millis())
            },
            Self::Unhealthy(m, reason) => {
                write!(f, "unhealthy: {} ({}ms)", reason, m.check_duration.as_millis())
            },
        }
    }
}

/// Metadata about a health check result.
///
/// Contains timing information, backend identification, and an extensible
/// key-value map for backend-specific details (e.g., circuit breaker state,
/// cache statistics, connection pool info).
#[derive(Debug, Clone)]
pub struct HealthMetadata {
    /// How long the health check itself took.
    pub check_duration: Duration,
    /// Identifier for the backend type (e.g., "memory", "ledger", "rate_limited").
    pub backend: String,
    /// Backend-specific details.
    ///
    /// Common keys include:
    /// - `entry_count`: Number of entries in the store
    /// - `circuit_breaker_state`: Current circuit breaker state
    /// - `connection_latency_ms`: Latency of the backend connection check
    pub details: HashMap<String, String>,
}

impl HealthMetadata {
    /// Creates a new `HealthMetadata` with the given check duration and backend name.
    #[must_use = "constructing metadata has no side effects"]
    pub fn new(check_duration: Duration, backend: impl Into<String>) -> Self {
        Self { check_duration, backend: backend.into(), details: HashMap::new() }
    }

    /// Adds a detail entry, returning `self` for chaining.
    #[must_use = "returns the modified metadata for chaining"]
    pub fn with_detail(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.details.insert(key.into(), value.into());
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_healthy_status() {
        let meta = HealthMetadata::new(Duration::from_millis(5), "memory");
        let status = HealthStatus::healthy(meta);

        assert!(status.is_healthy());
        assert!(!status.is_degraded());
        assert!(!status.is_unhealthy());
        assert!(status.reason().is_none());
        assert_eq!(status.metadata().backend, "memory");
        assert_eq!(status.metadata().check_duration, Duration::from_millis(5));
    }

    #[test]
    fn test_degraded_status() {
        let meta = HealthMetadata::new(Duration::from_millis(50), "ledger");
        let status = HealthStatus::degraded(meta, "circuit breaker half-open");

        assert!(!status.is_healthy());
        assert!(status.is_degraded());
        assert!(!status.is_unhealthy());
        assert_eq!(status.reason(), Some("circuit breaker half-open"));
        assert_eq!(status.metadata().backend, "ledger");
    }

    #[test]
    fn test_unhealthy_status() {
        let meta = HealthMetadata::new(Duration::from_millis(1000), "ledger");
        let status = HealthStatus::unhealthy(meta, "connection refused");

        assert!(!status.is_healthy());
        assert!(!status.is_degraded());
        assert!(status.is_unhealthy());
        assert_eq!(status.reason(), Some("connection refused"));
    }

    #[test]
    fn test_metadata_with_details() {
        let meta = HealthMetadata::new(Duration::from_millis(3), "memory")
            .with_detail("entry_count", "42")
            .with_detail("memory_bytes", "8192");

        assert_eq!(meta.details.len(), 2);
        assert_eq!(meta.details.get("entry_count"), Some(&"42".to_owned()));
        assert_eq!(meta.details.get("memory_bytes"), Some(&"8192".to_owned()));
    }

    #[test]
    fn test_display_healthy() {
        let meta = HealthMetadata::new(Duration::from_millis(2), "memory");
        let status = HealthStatus::healthy(meta);
        assert_eq!(status.to_string(), "healthy (2ms)");
    }

    #[test]
    fn test_display_degraded() {
        let meta = HealthMetadata::new(Duration::from_millis(50), "ledger");
        let status = HealthStatus::degraded(meta, "elevated latency");
        assert_eq!(status.to_string(), "degraded: elevated latency (50ms)");
    }

    #[test]
    fn test_display_unhealthy() {
        let meta = HealthMetadata::new(Duration::from_secs(5), "ledger");
        let status = HealthStatus::unhealthy(meta, "timeout");
        assert_eq!(status.to_string(), "unhealthy: timeout (5000ms)");
    }

    #[test]
    fn test_health_probe_display() {
        assert_eq!(HealthProbe::Liveness.to_string(), "liveness");
        assert_eq!(HealthProbe::Readiness.to_string(), "readiness");
        assert_eq!(HealthProbe::Startup.to_string(), "startup");
    }

    #[test]
    fn test_health_probe_equality() {
        assert_eq!(HealthProbe::Liveness, HealthProbe::Liveness);
        assert_ne!(HealthProbe::Liveness, HealthProbe::Readiness);
        assert_ne!(HealthProbe::Readiness, HealthProbe::Startup);
    }

    #[test]
    fn test_health_probe_clone_copy() {
        let probe = HealthProbe::Readiness;
        let cloned = probe;
        assert_eq!(probe, cloned);
    }
}
