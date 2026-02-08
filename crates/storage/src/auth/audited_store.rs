//! Audit-logging decorator for [`PublicSigningKeyStore`] implementations.
//!
//! Wraps any key store to emit structured [`AuditEvent`]s for every
//! mutation and access operation, without modifying the underlying store.

use std::{collections::HashMap, sync::Arc};

use async_trait::async_trait;

use super::{
    audit::{AuditAction, AuditEvent, AuditLogger, AuditResult, key_resource},
    signing_key::PublicSigningKey,
    store::PublicSigningKeyStore,
};
use crate::{error::StorageResult, types::NamespaceId};

/// Decorator that adds audit logging to any [`PublicSigningKeyStore`].
///
/// Every key management operation is logged as an [`AuditEvent`] via the
/// configured [`AuditLogger`]. The audit event includes the actor, action,
/// resource identifier, and whether the operation succeeded or failed.
///
/// # Usage
///
/// ```no_run
/// use inferadb_common_storage::auth::audited_store::AuditedKeyStore;
/// use inferadb_common_storage::auth::audit::TracingAuditLogger;
/// use inferadb_common_storage::auth::MemorySigningKeyStore;
///
/// let store = MemorySigningKeyStore::new();
/// let audited = AuditedKeyStore::new(store, TracingAuditLogger, "system");
/// ```
pub struct AuditedKeyStore<S, L> {
    inner: S,
    logger: L,
    actor: Arc<str>,
}

impl<S, L> AuditedKeyStore<S, L>
where
    S: PublicSigningKeyStore,
    L: AuditLogger,
{
    /// Creates a new audited key store wrapping the given store and logger.
    pub fn new(inner: S, logger: L, actor: impl Into<Arc<str>>) -> Self {
        Self { inner, logger, actor: actor.into() }
    }

    /// Returns a reference to the inner store.
    pub fn inner(&self) -> &S {
        &self.inner
    }

    async fn emit(
        &self,
        action: AuditAction,
        resource: String,
        result: &AuditResult,
        metadata: HashMap<String, String>,
    ) {
        let event = AuditEvent::builder()
            .actor(self.actor.to_string())
            .action(action)
            .resource(resource)
            .result(result.clone())
            .metadata(metadata)
            .build();
        self.logger.log(&event).await;
    }

    fn result_from<T>(res: &StorageResult<T>) -> AuditResult {
        match res {
            Ok(_) => AuditResult::Success,
            Err(e) => AuditResult::Failure(e.to_string()),
        }
    }
}

#[async_trait]
impl<S, L> PublicSigningKeyStore for AuditedKeyStore<S, L>
where
    S: PublicSigningKeyStore,
    L: AuditLogger,
{
    async fn create_key(
        &self,
        namespace_id: NamespaceId,
        key: &PublicSigningKey,
    ) -> StorageResult<()> {
        let res = self.inner.create_key(namespace_id, key).await;
        let audit_result = Self::result_from(&res);
        self.emit(
            AuditAction::StoreKey,
            key_resource(namespace_id, &key.kid),
            &audit_result,
            HashMap::new(),
        )
        .await;
        res
    }

    async fn get_key(
        &self,
        namespace_id: NamespaceId,
        kid: &str,
    ) -> StorageResult<Option<PublicSigningKey>> {
        let res = self.inner.get_key(namespace_id, kid).await;
        let audit_result = Self::result_from(&res);
        let mut metadata = HashMap::new();
        if let Ok(ref opt) = res {
            metadata.insert(
                "found".to_owned(),
                if opt.is_some() { "true" } else { "false" }.to_owned(),
            );
        }
        self.emit(AuditAction::AccessKey, key_resource(namespace_id, kid), &audit_result, metadata)
            .await;
        res
    }

    async fn list_active_keys(
        &self,
        namespace_id: NamespaceId,
    ) -> StorageResult<Vec<PublicSigningKey>> {
        // list_active_keys is a read operation; not individually audited
        // per the PRD's focus on mutations and access patterns.
        self.inner.list_active_keys(namespace_id).await
    }

    async fn deactivate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let res = self.inner.deactivate_key(namespace_id, kid).await;
        let audit_result = Self::result_from(&res);
        self.emit(
            AuditAction::DeactivateKey,
            key_resource(namespace_id, kid),
            &audit_result,
            HashMap::new(),
        )
        .await;
        res
    }

    async fn revoke_key(
        &self,
        namespace_id: NamespaceId,
        kid: &str,
        reason: Option<&str>,
    ) -> StorageResult<()> {
        let res = self.inner.revoke_key(namespace_id, kid, reason).await;
        let audit_result = Self::result_from(&res);
        let mut metadata = HashMap::new();
        if let Some(r) = reason {
            metadata.insert("reason".to_owned(), r.to_owned());
        }
        self.emit(AuditAction::RevokeKey, key_resource(namespace_id, kid), &audit_result, metadata)
            .await;
        res
    }

    async fn activate_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let res = self.inner.activate_key(namespace_id, kid).await;
        let audit_result = Self::result_from(&res);
        self.emit(
            AuditAction::ActivateKey,
            key_resource(namespace_id, kid),
            &audit_result,
            HashMap::new(),
        )
        .await;
        res
    }

    async fn delete_key(&self, namespace_id: NamespaceId, kid: &str) -> StorageResult<()> {
        let res = self.inner.delete_key(namespace_id, kid).await;
        let audit_result = Self::result_from(&res);
        self.emit(
            AuditAction::DeleteKey,
            key_resource(namespace_id, kid),
            &audit_result,
            HashMap::new(),
        )
        .await;
        res
    }

    async fn create_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[PublicSigningKey],
    ) -> Vec<StorageResult<()>> {
        let results = self.inner.create_keys(namespace_id, keys).await;
        let succeeded = results.iter().filter(|r| r.is_ok()).count();
        let failed = results.len() - succeeded;
        let audit_result = if failed == 0 {
            AuditResult::Success
        } else {
            AuditResult::Failure(format!("{failed} of {} keys failed", results.len()))
        };
        let mut metadata = HashMap::new();
        metadata.insert("key_count".to_owned(), keys.len().to_string());
        metadata.insert("succeeded".to_owned(), succeeded.to_string());
        metadata.insert("failed".to_owned(), failed.to_string());
        self.emit(
            AuditAction::BulkStoreKeys,
            format!("ns:{namespace_id}"),
            &audit_result,
            metadata,
        )
        .await;
        results
    }

    async fn revoke_keys(
        &self,
        namespace_id: NamespaceId,
        keys: &[(&str, Option<&str>)],
    ) -> Vec<StorageResult<()>> {
        let results = self.inner.revoke_keys(namespace_id, keys).await;
        let succeeded = results.iter().filter(|r| r.is_ok()).count();
        let failed = results.len() - succeeded;
        let audit_result = if failed == 0 {
            AuditResult::Success
        } else {
            AuditResult::Failure(format!("{failed} of {} keys failed", results.len()))
        };
        let mut metadata = HashMap::new();
        metadata.insert("key_count".to_owned(), keys.len().to_string());
        metadata.insert("succeeded".to_owned(), succeeded.to_string());
        metadata.insert("failed".to_owned(), failed.to_string());
        self.emit(
            AuditAction::BulkRevokeKeys,
            format!("ns:{namespace_id}"),
            &audit_result,
            metadata,
        )
        .await;
        results
    }

    async fn rotate_key(
        &self,
        namespace_id: NamespaceId,
        old_kid: &str,
        new_key: &PublicSigningKey,
    ) -> StorageResult<()> {
        let res = self.inner.rotate_key(namespace_id, old_kid, new_key).await;
        let audit_result = Self::result_from(&res);
        let mut metadata = HashMap::new();
        metadata.insert("old_kid".to_owned(), old_kid.to_owned());
        metadata.insert("new_kid".to_owned(), new_key.kid.clone());
        self.emit(
            AuditAction::RotateKey,
            key_resource(namespace_id, old_kid),
            &audit_result,
            metadata,
        )
        .await;
        res
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::expect_used)]

    use parking_lot::Mutex;

    use super::*;
    use crate::auth::{
        MemorySigningKeyStore,
        audit::{AuditAction, AuditEvent},
    };

    /// Test audit logger that records events for assertions.
    struct RecordingLogger {
        events: Mutex<Vec<AuditEvent>>,
    }

    impl RecordingLogger {
        fn new() -> Self {
            Self { events: Mutex::new(Vec::new()) }
        }

        fn events(&self) -> Vec<AuditEvent> {
            self.events.lock().clone()
        }

        fn last_event(&self) -> AuditEvent {
            self.events.lock().last().expect("no events recorded").clone()
        }
    }

    #[async_trait]
    impl AuditLogger for RecordingLogger {
        async fn log(&self, event: &AuditEvent) {
            self.events.lock().push(event.clone());
        }
    }

    fn make_test_key(kid: &str) -> PublicSigningKey {
        PublicSigningKey::builder()
            .kid(kid.to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1)
            .cert_id(1)
            .build()
    }

    #[tokio::test]
    async fn test_create_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let store = AuditedKeyStore::new(MemorySigningKeyStore::new(), logger.clone(), "admin");
        let ns = NamespaceId::from(1);
        let key = make_test_key("k1");

        let res = store.create_key(ns, &key).await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::StoreKey);
        assert_eq!(event.resource, "ns:1/kid:k1");
        assert_eq!(event.actor, "admin");
        assert_eq!(event.result, AuditResult::Success);
    }

    #[tokio::test]
    async fn test_get_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "reader");
        let res = store.get_key(ns, "k1").await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::AccessKey);
        assert_eq!(event.metadata.get("found").map(String::as_str), Some("true"));
    }

    #[tokio::test]
    async fn test_get_missing_key_emits_audit_with_found_false() {
        let logger = Arc::new(RecordingLogger::new());
        let store = AuditedKeyStore::new(MemorySigningKeyStore::new(), logger.clone(), "reader");
        let ns = NamespaceId::from(1);

        let res = store.get_key(ns, "missing").await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::AccessKey);
        assert_eq!(event.metadata.get("found").map(String::as_str), Some("false"));
    }

    #[tokio::test]
    async fn test_revoke_key_emits_audit_with_reason() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let res = store.revoke_key(ns, "k1", Some("key compromise")).await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::RevokeKey);
        assert_eq!(event.metadata.get("reason").map(String::as_str), Some("key compromise"));
    }

    #[tokio::test]
    async fn test_deactivate_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let res = store.deactivate_key(ns, "k1").await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::DeactivateKey);
        assert_eq!(event.result, AuditResult::Success);
    }

    #[tokio::test]
    async fn test_activate_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");
        inner.deactivate_key(ns, "k1").await.expect("deactivate");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let res = store.activate_key(ns, "k1").await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::ActivateKey);
    }

    #[tokio::test]
    async fn test_delete_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let res = store.delete_key(ns, "k1").await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::DeleteKey);
        assert_eq!(event.resource, "ns:1/kid:k1");
    }

    #[tokio::test]
    async fn test_rotate_key_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("old")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let new_key = make_test_key("new");
        let res = store.rotate_key(ns, "old", &new_key).await;
        assert!(res.is_ok());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::RotateKey);
        assert_eq!(event.metadata.get("old_kid").map(String::as_str), Some("old"));
        assert_eq!(event.metadata.get("new_kid").map(String::as_str), Some("new"));
    }

    #[tokio::test]
    async fn test_bulk_create_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let store = AuditedKeyStore::new(MemorySigningKeyStore::new(), logger.clone(), "admin");
        let ns = NamespaceId::from(1);
        let keys = vec![make_test_key("k1"), make_test_key("k2"), make_test_key("k3")];

        let results = store.create_keys(ns, &keys).await;
        assert!(results.iter().all(|r| r.is_ok()));

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::BulkStoreKeys);
        assert_eq!(event.metadata.get("key_count").map(String::as_str), Some("3"));
        assert_eq!(event.metadata.get("succeeded").map(String::as_str), Some("3"));
        assert_eq!(event.metadata.get("failed").map(String::as_str), Some("0"));
    }

    #[tokio::test]
    async fn test_bulk_revoke_emits_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");
        inner.create_key(ns, &make_test_key("k2")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");
        let keys = vec![("k1", None), ("k2", Some("expired"))];
        let results = store.revoke_keys(ns, &keys).await;
        assert!(results.iter().all(|r| r.is_ok()));

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::BulkRevokeKeys);
        assert_eq!(event.metadata.get("key_count").map(String::as_str), Some("2"));
    }

    #[tokio::test]
    async fn test_failed_operation_emits_failure_audit() {
        let logger = Arc::new(RecordingLogger::new());
        let store = AuditedKeyStore::new(MemorySigningKeyStore::new(), logger.clone(), "admin");
        let ns = NamespaceId::from(1);

        // Try to delete a key that doesn't exist
        let res = store.delete_key(ns, "nonexistent").await;
        assert!(res.is_err());

        let event = logger.last_event();
        assert_eq!(event.action, AuditAction::DeleteKey);
        let is_failure = matches!(event.result, AuditResult::Failure(_));
        assert!(is_failure, "expected Failure result");
    }

    #[tokio::test]
    async fn test_all_operations_emit_correct_action_types() {
        let logger = Arc::new(RecordingLogger::new());
        let inner = MemorySigningKeyStore::new();
        let ns = NamespaceId::from(1);

        // Set up state
        inner.create_key(ns, &make_test_key("k1")).await.expect("create");
        inner.create_key(ns, &make_test_key("k2")).await.expect("create");

        let store = AuditedKeyStore::new(inner, logger.clone(), "admin");

        // Perform each operation
        let _ = store.get_key(ns, "k1").await;
        let _ = store.deactivate_key(ns, "k1").await;
        let _ = store.activate_key(ns, "k1").await;
        let _ = store.revoke_key(ns, "k2", None).await;
        let _ = store.delete_key(ns, "k2").await;

        let events = logger.events();
        assert_eq!(events.len(), 5);
        assert_eq!(events[0].action, AuditAction::AccessKey);
        assert_eq!(events[1].action, AuditAction::DeactivateKey);
        assert_eq!(events[2].action, AuditAction::ActivateKey);
        assert_eq!(events[3].action, AuditAction::RevokeKey);
        assert_eq!(events[4].action, AuditAction::DeleteKey);
    }
}
