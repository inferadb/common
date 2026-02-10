//! Audit logging for signing key management operations.
//!
//! Provides a structured audit trail for all key lifecycle operations.
//! Enterprise compliance standards (SOC 2, ISO 27001) require logging
//! who performed an action, what was affected, when it happened, and
//! whether it succeeded.
//!
//! # Architecture
//!
//! The [`AuditLogger`] trait enables different audit backends:
//!
//! - [`TracingAuditLogger`]: Emits structured `tracing` events at a dedicated audit level (INFO),
//!   suitable for log aggregation and SIEM integration.
//! - Custom implementations can write to databases, external audit services, etc.
//!
//! # Usage
//!
//! ```no_run
//! use inferadb_common_storage::auth::audit::{
//!     AuditAction, AuditEvent, AuditResult, TracingAuditLogger, AuditLogger,
//! };
//!
//! # tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap().block_on(async {
//! let logger = TracingAuditLogger;
//! let event = AuditEvent::builder()
//!     .actor("admin@example.com")
//!     .action(AuditAction::StoreKey)
//!     .resource("ns:100/kid:key-abc123")
//!     .result(AuditResult::Success)
//!     .build();
//! logger.log(&event).await;
//! # });
//! ```

use std::{collections::HashMap, fmt};

use async_trait::async_trait;
use chrono::{DateTime, Utc};

/// Action performed on a signing key resource.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditAction {
    /// A new signing key was stored.
    StoreKey,
    /// A signing key was revoked.
    RevokeKey,
    /// A signing key was rotated (old revoked, new stored).
    RotateKey,
    /// A signing key was accessed (read from store).
    AccessKey,
    /// A signing key cache entry was invalidated.
    InvalidateCache,
    /// All cache entries were cleared.
    ClearCache,
    /// A signing key was deactivated (soft revocation).
    DeactivateKey,
    /// A signing key was reactivated.
    ActivateKey,
    /// A signing key was permanently deleted.
    DeleteKey,
    /// Multiple signing keys were stored in bulk.
    BulkStoreKeys,
    /// Multiple signing keys were revoked in bulk.
    BulkRevokeKeys,
}

impl fmt::Display for AuditAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StoreKey => write!(f, "store_key"),
            Self::RevokeKey => write!(f, "revoke_key"),
            Self::RotateKey => write!(f, "rotate_key"),
            Self::AccessKey => write!(f, "access_key"),
            Self::InvalidateCache => write!(f, "invalidate_cache"),
            Self::ClearCache => write!(f, "clear_cache"),
            Self::DeactivateKey => write!(f, "deactivate_key"),
            Self::ActivateKey => write!(f, "activate_key"),
            Self::DeleteKey => write!(f, "delete_key"),
            Self::BulkStoreKeys => write!(f, "bulk_store_keys"),
            Self::BulkRevokeKeys => write!(f, "bulk_revoke_keys"),
        }
    }
}

/// Outcome of an audited operation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditResult {
    /// Operation completed successfully.
    Success,
    /// Operation failed with the given reason.
    Failure(String),
}

impl fmt::Display for AuditResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Success => write!(f, "success"),
            Self::Failure(reason) => write!(f, "failure: {reason}"),
        }
    }
}

/// Structured audit event for key management operations.
///
/// Each event captures who performed an action, what was affected,
/// when it happened, and whether it succeeded.
#[derive(Debug, Clone, bon::Builder)]
pub struct AuditEvent {
    /// When the event occurred (defaults to now).
    #[builder(default = Utc::now())]
    pub timestamp: DateTime<Utc>,
    /// Identity of the actor performing the operation.
    #[builder(into)]
    pub actor: String,
    /// The action that was performed.
    pub action: AuditAction,
    /// Resource identifier (e.g., "ns:100/kid:key-abc123").
    #[builder(into)]
    pub resource: String,
    /// Outcome of the operation.
    pub result: AuditResult,
    /// Additional context (e.g., revocation reason, key count).
    #[builder(default)]
    pub metadata: HashMap<String, String>,
}

/// Trait for audit log backends.
///
/// Implementations should be durable and tamper-evident where possible.
/// The trait is intentionally simple — a single `log` method — to
/// accommodate backends ranging from structured logging to external
/// audit services.
#[async_trait]
pub trait AuditLogger: Send + Sync {
    /// Records an audit event.
    ///
    /// Implementations should not fail silently — log delivery failures
    /// should be surfaced through the observability stack.
    async fn log(&self, event: &AuditEvent);
}

#[async_trait]
impl<L: AuditLogger> AuditLogger for std::sync::Arc<L> {
    async fn log(&self, event: &AuditEvent) {
        (**self).log(event).await;
    }
}

/// Audit logger that emits structured `tracing` events.
///
/// Events are emitted at `INFO` level with structured fields, making
/// them easy to filter and forward to SIEM systems via
/// `tracing-subscriber` layers.
///
/// Field mapping:
/// - `audit.timestamp` — ISO 8601 timestamp
/// - `audit.actor` — who performed the action
/// - `audit.action` — the operation (e.g., "store_key")
/// - `audit.resource` — what was affected
/// - `audit.result` — "success" or "failure: ..."
/// - `audit.metadata.*` — additional context
#[derive(Debug, Clone, Copy)]
pub struct TracingAuditLogger;

#[async_trait]
impl AuditLogger for TracingAuditLogger {
    async fn log(&self, event: &AuditEvent) {
        let metadata_str = if event.metadata.is_empty() {
            String::new()
        } else {
            event.metadata.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join(", ")
        };

        tracing::info!(
            audit.timestamp = %event.timestamp.to_rfc3339(),
            audit.actor = %event.actor,
            audit.action = %event.action,
            audit.resource = %event.resource,
            audit.result = %event.result,
            audit.metadata = %metadata_str,
            "audit_event"
        );
    }
}

/// No-op audit logger for testing and environments where audit is not needed.
#[derive(Debug, Clone, Copy)]
pub struct NoopAuditLogger;

#[async_trait]
impl AuditLogger for NoopAuditLogger {
    async fn log(&self, _event: &AuditEvent) {}
}

/// Constructs a resource identifier string from namespace and kid.
pub fn key_resource(namespace_id: impl fmt::Display, kid: &str) -> String {
    format!("ns:{namespace_id}/kid:{kid}")
}

#[cfg(test)]
mod tests {
    use tracing_subscriber::layer::SubscriberExt;

    use super::*;

    #[test]
    fn test_audit_action_display() {
        assert_eq!(AuditAction::StoreKey.to_string(), "store_key");
        assert_eq!(AuditAction::RevokeKey.to_string(), "revoke_key");
        assert_eq!(AuditAction::RotateKey.to_string(), "rotate_key");
        assert_eq!(AuditAction::AccessKey.to_string(), "access_key");
        assert_eq!(AuditAction::InvalidateCache.to_string(), "invalidate_cache");
        assert_eq!(AuditAction::ClearCache.to_string(), "clear_cache");
        assert_eq!(AuditAction::DeactivateKey.to_string(), "deactivate_key");
        assert_eq!(AuditAction::ActivateKey.to_string(), "activate_key");
        assert_eq!(AuditAction::DeleteKey.to_string(), "delete_key");
        assert_eq!(AuditAction::BulkStoreKeys.to_string(), "bulk_store_keys");
        assert_eq!(AuditAction::BulkRevokeKeys.to_string(), "bulk_revoke_keys");
    }

    #[test]
    fn test_audit_result_display() {
        assert_eq!(AuditResult::Success.to_string(), "success");
        assert_eq!(
            AuditResult::Failure("connection lost".to_owned()).to_string(),
            "failure: connection lost"
        );
    }

    #[test]
    fn test_audit_event_builder_defaults() {
        let event = AuditEvent::builder()
            .actor("test-user")
            .action(AuditAction::StoreKey)
            .resource("ns:1/kid:abc")
            .result(AuditResult::Success)
            .build();

        assert_eq!(event.actor, "test-user");
        assert_eq!(event.action, AuditAction::StoreKey);
        assert_eq!(event.resource, "ns:1/kid:abc");
        assert_eq!(event.result, AuditResult::Success);
        assert!(event.metadata.is_empty());
        // Timestamp should be approximately now
        let diff = Utc::now() - event.timestamp;
        assert!(diff.num_seconds() < 2);
    }

    #[test]
    fn test_audit_event_builder_with_metadata() {
        let mut metadata = HashMap::new();
        metadata.insert("reason".to_owned(), "key compromise".to_owned());
        metadata.insert("key_count".to_owned(), "3".to_owned());

        let event = AuditEvent::builder()
            .actor("admin@org.com")
            .action(AuditAction::BulkRevokeKeys)
            .resource("ns:42")
            .result(AuditResult::Success)
            .metadata(metadata)
            .build();

        assert_eq!(event.metadata.len(), 2);
        assert_eq!(event.metadata.get("reason").map(String::as_str), Some("key compromise"));
    }

    #[test]
    fn test_key_resource_helper() {
        assert_eq!(key_resource(100, "key-abc"), "ns:100/kid:key-abc");
        assert_eq!(key_resource(42, "my.key-v2"), "ns:42/kid:my.key-v2");
    }

    #[tokio::test]
    async fn test_tracing_audit_logger_emits_event() {
        // Set up a tracing subscriber that captures events
        let subscriber = tracing_subscriber::registry()
            .with(tracing_subscriber::fmt::layer().with_test_writer());

        let _guard = tracing::subscriber::set_default(subscriber);

        let logger = TracingAuditLogger;
        let event = AuditEvent::builder()
            .actor("test")
            .action(AuditAction::AccessKey)
            .resource("ns:1/kid:k1")
            .result(AuditResult::Success)
            .build();

        logger.log(&event).await;
        // If we get here without panic, the logger works
    }

    #[tokio::test]
    async fn test_noop_audit_logger() {
        let logger = NoopAuditLogger;
        let event = AuditEvent::builder()
            .actor("test")
            .action(AuditAction::DeleteKey)
            .resource("ns:1/kid:k1")
            .result(AuditResult::Failure("not found".to_owned()))
            .build();

        // Should complete without error
        logger.log(&event).await;
    }

    #[tokio::test]
    async fn test_audit_event_for_each_operation_type() {
        let logger = TracingAuditLogger;

        let actions = [
            AuditAction::StoreKey,
            AuditAction::RevokeKey,
            AuditAction::RotateKey,
            AuditAction::AccessKey,
            AuditAction::InvalidateCache,
            AuditAction::ClearCache,
            AuditAction::DeactivateKey,
            AuditAction::ActivateKey,
            AuditAction::DeleteKey,
            AuditAction::BulkStoreKeys,
            AuditAction::BulkRevokeKeys,
        ];

        for action in actions {
            let event = AuditEvent::builder()
                .actor("test")
                .action(action)
                .resource("ns:1/kid:k1")
                .result(AuditResult::Success)
                .build();
            logger.log(&event).await;
        }
    }

    #[test]
    fn test_audit_event_fields_are_correct() {
        let ts = Utc::now();
        let mut metadata = HashMap::new();
        metadata.insert("key".to_owned(), "value".to_owned());

        let event = AuditEvent::builder()
            .timestamp(ts)
            .actor("actor")
            .action(AuditAction::StoreKey)
            .resource("resource")
            .result(AuditResult::Success)
            .metadata(metadata.clone())
            .build();

        assert_eq!(event.timestamp, ts);
        assert_eq!(event.actor, "actor");
        assert_eq!(event.action, AuditAction::StoreKey);
        assert_eq!(event.resource, "resource");
        assert_eq!(event.result, AuditResult::Success);
        assert_eq!(event.metadata, metadata);
    }
}
