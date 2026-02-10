//! Circuit breaker for protecting against cascading failures.
//!
//! When the ledger backend is unreachable, every operation goes through the full
//! retry-with-timeout cycle before failing. The circuit breaker pattern detects
//! sustained failures and fails fast, periodically probing to detect recovery.
//!
//! # State Machine
//!
//! ```text
//! ┌────────┐  failure_threshold  ┌──────┐  recovery_timeout  ┌──────────┐
//! │ Closed │ ──────exceeded────→ │ Open │ ────elapsed─────→  │ HalfOpen │
//! └────────┘                     └──────┘ ←──probe fails──── └──────────┘
//!      ↑                                                          │
//!      └──────────────── success_threshold met ───────────────────┘
//! ```

use std::time::{Duration, Instant};

use parking_lot::Mutex;

/// Default number of consecutive failures before opening the circuit.
pub const DEFAULT_FAILURE_THRESHOLD: u32 = 5;

/// Default duration the circuit stays open before transitioning to half-open.
pub const DEFAULT_RECOVERY_TIMEOUT: Duration = Duration::from_secs(30);

/// Default number of successful probe requests required to close the circuit
/// from the half-open state.
pub const DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD: u32 = 2;

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation — all requests pass through.
    Closed,
    /// Requests are rejected immediately. The `Instant` indicates when the
    /// circuit should transition to [`HalfOpen`](CircuitState::HalfOpen).
    Open {
        /// When the circuit should transition to half-open.
        until: Instant,
    },
    /// A limited number of probe requests are allowed through to test
    /// whether the backend has recovered.
    HalfOpen,
}

impl std::fmt::Display for CircuitState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Closed => write!(f, "closed"),
            Self::Open { .. } => write!(f, "open"),
            Self::HalfOpen => write!(f, "half_open"),
        }
    }
}

/// Configuration for the circuit breaker.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before opening the circuit.
    failure_threshold: u32,
    /// How long the circuit stays open before transitioning to half-open.
    recovery_timeout: Duration,
    /// Number of successful probes required in half-open to close the circuit.
    half_open_success_threshold: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: DEFAULT_FAILURE_THRESHOLD,
            recovery_timeout: DEFAULT_RECOVERY_TIMEOUT,
            half_open_success_threshold: DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD,
        }
    }
}

#[bon::bon]
impl CircuitBreakerConfig {
    /// Creates a new circuit breaker configuration.
    ///
    /// # Errors
    ///
    /// Returns [`ConfigError`](inferadb_common_storage::ConfigError) if:
    /// - `failure_threshold` is zero
    /// - `recovery_timeout` is zero
    /// - `half_open_success_threshold` is zero
    #[builder]
    pub fn new(
        #[builder(default = DEFAULT_FAILURE_THRESHOLD)] failure_threshold: u32,
        #[builder(default = DEFAULT_RECOVERY_TIMEOUT)] recovery_timeout: Duration,
        #[builder(default = DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD)] half_open_success_threshold: u32,
    ) -> Result<Self, inferadb_common_storage::ConfigError> {
        use inferadb_common_storage::ConfigError;

        if failure_threshold == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "failure_threshold",
                min: "1".into(),
                value: "0".into(),
            });
        }
        if recovery_timeout.is_zero() {
            return Err(ConfigError::MustBePositive {
                field: "recovery_timeout",
                value: "0s".into(),
            });
        }
        if half_open_success_threshold == 0 {
            return Err(ConfigError::BelowMinimum {
                field: "half_open_success_threshold",
                min: "1".into(),
                value: "0".into(),
            });
        }
        Ok(Self { failure_threshold, recovery_timeout, half_open_success_threshold })
    }

    /// Returns the failure threshold.
    #[must_use]
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Returns the recovery timeout.
    #[must_use]
    pub fn recovery_timeout(&self) -> Duration {
        self.recovery_timeout
    }

    /// Returns the half-open success threshold.
    #[must_use]
    pub fn half_open_success_threshold(&self) -> u32 {
        self.half_open_success_threshold
    }
}

/// Internal mutable state protected by a mutex.
#[derive(Debug)]
struct Inner {
    state: CircuitState,
    consecutive_failures: u32,
    consecutive_half_open_successes: u32,
    config: CircuitBreakerConfig,

    // Metrics counters
    state_transitions: u64,
    fast_fail_count: u64,
    recovery_attempts: u64,
}

/// Thread-safe circuit breaker.
///
/// All state is behind a `parking_lot::Mutex` with very short critical
/// sections (no I/O under the lock). The breaker is `Clone` via `Arc`.
#[derive(Debug, Clone)]
pub struct CircuitBreaker {
    inner: std::sync::Arc<Mutex<Inner>>,
}

/// A snapshot of circuit breaker metrics.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CircuitBreakerMetrics {
    /// Current circuit state.
    pub state: CircuitState,
    /// Total number of state transitions since creation.
    pub state_transitions: u64,
    /// Total number of requests rejected due to open circuit.
    pub fast_fail_count: u64,
    /// Total number of half-open probe requests.
    pub recovery_attempts: u64,
    /// Current consecutive failure count.
    pub consecutive_failures: u32,
}

impl CircuitBreaker {
    /// Creates a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            inner: std::sync::Arc::new(Mutex::new(Inner {
                state: CircuitState::Closed,
                consecutive_failures: 0,
                consecutive_half_open_successes: 0,
                config,
                state_transitions: 0,
                fast_fail_count: 0,
                recovery_attempts: 0,
            })),
        }
    }

    /// Checks whether the circuit allows a request through.
    ///
    /// Returns `true` if the request should proceed. Returns `false` if
    /// the circuit is open and the request should be rejected immediately.
    ///
    /// In the half-open state, requests are allowed through as probes.
    pub fn allow_request(&self) -> bool {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => true,
            CircuitState::Open { until } => {
                if Instant::now() >= until {
                    // Recovery timeout elapsed — transition to half-open
                    inner.state = CircuitState::HalfOpen;
                    inner.consecutive_half_open_successes = 0;
                    inner.state_transitions += 1;
                    inner.recovery_attempts += 1;
                    tracing::info!(
                        previous_state = "open",
                        new_state = "half_open",
                        "circuit breaker transitioning to half-open for probe requests",
                    );
                    true
                } else {
                    inner.fast_fail_count += 1;
                    false
                }
            },
            CircuitState::HalfOpen => {
                inner.recovery_attempts += 1;
                true
            },
        }
    }

    /// Records a successful operation, potentially closing the circuit.
    pub fn record_success(&self) {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => {
                // Reset consecutive failures on any success
                inner.consecutive_failures = 0;
            },
            CircuitState::HalfOpen => {
                inner.consecutive_half_open_successes += 1;
                if inner.consecutive_half_open_successes >= inner.config.half_open_success_threshold
                {
                    inner.state = CircuitState::Closed;
                    inner.consecutive_failures = 0;
                    inner.consecutive_half_open_successes = 0;
                    inner.state_transitions += 1;
                    tracing::info!(
                        previous_state = "half_open",
                        new_state = "closed",
                        "circuit breaker closed after successful probes",
                    );
                }
            },
            CircuitState::Open { .. } => {
                // Should not happen (no requests allowed in open state),
                // but handle gracefully by ignoring.
            },
        }
    }

    /// Records a failed operation, potentially opening the circuit.
    ///
    /// Only transient failures should be recorded. Permanent errors (e.g.
    /// not found, conflict) do not indicate backend health issues.
    pub fn record_failure(&self) {
        let mut inner = self.inner.lock();
        match inner.state {
            CircuitState::Closed => {
                inner.consecutive_failures += 1;
                if inner.consecutive_failures >= inner.config.failure_threshold {
                    let until = Instant::now() + inner.config.recovery_timeout;
                    inner.state = CircuitState::Open { until };
                    inner.state_transitions += 1;
                    tracing::warn!(
                        consecutive_failures = inner.consecutive_failures,
                        recovery_timeout_secs = inner.config.recovery_timeout.as_secs(),
                        "circuit breaker opened after consecutive transient failures",
                    );
                }
            },
            CircuitState::HalfOpen => {
                // Probe failed — re-open the circuit
                let until = Instant::now() + inner.config.recovery_timeout;
                inner.state = CircuitState::Open { until };
                inner.consecutive_half_open_successes = 0;
                inner.state_transitions += 1;
                tracing::warn!(
                    previous_state = "half_open",
                    new_state = "open",
                    recovery_timeout_secs = inner.config.recovery_timeout.as_secs(),
                    "circuit breaker re-opened after probe failure",
                );
            },
            CircuitState::Open { .. } => {
                // Already open — no state change needed.
            },
        }
    }

    /// Returns the current state of the circuit breaker.
    #[must_use]
    pub fn state(&self) -> CircuitState {
        let inner = self.inner.lock();
        // Check if open circuit has expired (read-only peek doesn't transition)
        match inner.state {
            CircuitState::Open { until } if Instant::now() >= until => CircuitState::HalfOpen,
            other => other,
        }
    }

    /// Returns a snapshot of circuit breaker metrics.
    #[must_use]
    pub fn metrics(&self) -> CircuitBreakerMetrics {
        let inner = self.inner.lock();
        CircuitBreakerMetrics {
            state: match inner.state {
                CircuitState::Open { until } if Instant::now() >= until => CircuitState::HalfOpen,
                other => other,
            },
            state_transitions: inner.state_transitions,
            fast_fail_count: inner.fast_fail_count,
            recovery_attempts: inner.recovery_attempts,
            consecutive_failures: inner.consecutive_failures,
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::time::Duration;

    use rstest::rstest;

    use super::*;

    fn test_config(
        failure_threshold: u32,
        recovery_timeout: Duration,
        half_open_success_threshold: u32,
    ) -> CircuitBreakerConfig {
        CircuitBreakerConfig { failure_threshold, recovery_timeout, half_open_success_threshold }
    }

    #[test]
    fn starts_closed() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig::default());
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());
    }

    #[test]
    fn opens_after_threshold_failures() {
        let cb = CircuitBreaker::new(test_config(3, Duration::from_secs(30), 2));

        cb.record_failure();
        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Closed);
        assert!(cb.allow_request());

        cb.record_failure(); // 3rd failure hits threshold
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        assert!(!cb.allow_request());
    }

    #[test]
    fn success_resets_failure_count() {
        let cb = CircuitBreaker::new(test_config(3, Duration::from_secs(30), 2));

        cb.record_failure();
        cb.record_failure();
        cb.record_success(); // Reset

        cb.record_failure();
        cb.record_failure();
        // Still closed — success reset the count
        assert_eq!(cb.state(), CircuitState::Closed);
    }

    #[test]
    fn transitions_to_half_open_after_recovery_timeout() {
        let cb = CircuitBreaker::new(test_config(1, Duration::from_millis(10), 1));

        cb.record_failure(); // Opens circuit
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
        assert!(!cb.allow_request());

        // Wait for recovery timeout
        std::thread::sleep(Duration::from_millis(15));

        // Next allow_request should transition to half-open
        assert!(cb.allow_request());
        assert_eq!(cb.state(), CircuitState::HalfOpen);
    }

    #[test]
    fn half_open_closes_after_success_threshold() {
        let cb = CircuitBreaker::new(test_config(1, Duration::from_millis(10), 2));

        cb.record_failure(); // Open
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.allow_request()); // Transition to half-open

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::HalfOpen); // Still half-open (need 2)

        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed); // Now closed
    }

    #[test]
    fn half_open_reopens_on_failure() {
        let cb = CircuitBreaker::new(test_config(1, Duration::from_millis(10), 2));

        cb.record_failure(); // Open
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.allow_request()); // Half-open

        cb.record_failure(); // Probe failed — re-open
        assert!(matches!(cb.state(), CircuitState::Open { .. }));
    }

    #[test]
    fn metrics_tracking() {
        let cb = CircuitBreaker::new(test_config(2, Duration::from_millis(10), 1));

        // Two failures → open
        cb.record_failure();
        cb.record_failure();

        // Fast-fail requests while open
        assert!(!cb.allow_request());
        assert!(!cb.allow_request());

        let m = cb.metrics();
        assert!(matches!(m.state, CircuitState::Open { .. }));
        assert_eq!(m.state_transitions, 1); // closed → open
        assert_eq!(m.fast_fail_count, 2);
        assert_eq!(m.consecutive_failures, 2);
    }

    #[test]
    fn full_lifecycle() {
        let cb = CircuitBreaker::new(test_config(2, Duration::from_millis(10), 1));

        // Phase 1: Normal operation
        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        // Phase 2: Failures open the circuit
        cb.record_failure();
        cb.record_failure();
        assert!(matches!(cb.state(), CircuitState::Open { .. }));

        // Phase 3: Wait and probe
        std::thread::sleep(Duration::from_millis(15));
        assert!(cb.allow_request()); // Half-open

        // Phase 4: Probe succeeds → close
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);

        let m = cb.metrics();
        // closed→open (1), open→half_open (1), half_open→closed (1)
        assert_eq!(m.state_transitions, 3);
    }

    #[test]
    fn config_defaults_pass_validation() {
        let config = CircuitBreakerConfig::builder().build().unwrap();
        assert_eq!(config.failure_threshold(), DEFAULT_FAILURE_THRESHOLD);
        assert_eq!(config.recovery_timeout(), DEFAULT_RECOVERY_TIMEOUT);
        assert_eq!(config.half_open_success_threshold(), DEFAULT_HALF_OPEN_SUCCESS_THRESHOLD);
    }

    #[rstest]
    #[case::zero_failure_threshold("failure_threshold")]
    #[case::zero_recovery_timeout("recovery_timeout")]
    #[case::zero_half_open_success_threshold("half_open_success_threshold")]
    fn config_zero_field_rejected(#[case] field: &str) {
        let result = match field {
            "failure_threshold" => CircuitBreakerConfig::builder().failure_threshold(0).build(),
            "recovery_timeout" => {
                CircuitBreakerConfig::builder().recovery_timeout(Duration::ZERO).build()
            },
            "half_open_success_threshold" => {
                CircuitBreakerConfig::builder().half_open_success_threshold(0).build()
            },
            _ => unreachable!(),
        };
        assert!(result.is_err(), "{field} = 0 should be rejected");
    }

    #[test]
    fn display_for_circuit_state() {
        assert_eq!(CircuitState::Closed.to_string(), "closed");
        assert_eq!(
            CircuitState::Open { until: Instant::now() + Duration::from_secs(1) }.to_string(),
            "open"
        );
        assert_eq!(CircuitState::HalfOpen.to_string(), "half_open");
    }
}
