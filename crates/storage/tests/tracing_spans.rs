//! Integration test verifying that `#[instrument]` annotations produce
//! the expected span hierarchy on `MemoryBackend` operations.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};

use inferadb_common_storage::{HealthProbe, MemoryBackend, StorageBackend};
use tracing::Subscriber;
use tracing_subscriber::{layer::SubscriberExt, registry::LookupSpan};

// ---------------------------------------------------------------------------
// Collecting layer — records span names as they are entered
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct SpanCollector {
    spans: Arc<Mutex<Vec<String>>>,
}

impl<S> tracing_subscriber::Layer<S> for SpanCollector
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        _attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if let Some(span) = ctx.span(id) {
            self.spans.lock().expect("lock poisoned").push(span.name().to_owned());
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn memory_backend_set_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    backend.set(b"key-1".to_vec(), b"value-1".to_vec()).await.expect("set should succeed");

    let recorded = spans.lock().expect("lock poisoned");
    assert!(recorded.iter().any(|s| s == "set"), "expected a 'set' span, got: {recorded:?}");
}

#[tokio::test]
async fn memory_backend_get_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    let _ = backend.get(b"missing").await;

    let recorded = spans.lock().expect("lock poisoned");
    assert!(recorded.iter().any(|s| s == "get"), "expected a 'get' span, got: {recorded:?}");
}

#[tokio::test]
async fn memory_backend_delete_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    backend.delete(b"key").await.expect("delete should succeed");

    let recorded = spans.lock().expect("lock poisoned");
    assert!(recorded.iter().any(|s| s == "delete"), "expected a 'delete' span, got: {recorded:?}");
}

#[tokio::test]
async fn memory_backend_transaction_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    let _ = backend.transaction().await;

    let recorded = spans.lock().expect("lock poisoned");
    assert!(
        recorded.iter().any(|s| s == "transaction"),
        "expected a 'transaction' span, got: {recorded:?}"
    );
}

#[tokio::test]
async fn memory_backend_health_check_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    let _ = backend.health_check(HealthProbe::Readiness).await;

    let recorded = spans.lock().expect("lock poisoned");
    assert!(
        recorded.iter().any(|s| s == "health_check"),
        "expected a 'health_check' span, got: {recorded:?}"
    );
}

#[tokio::test]
async fn memory_backend_get_range_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    let _ = backend.get_range(b"a".to_vec()..b"z".to_vec()).await;

    let recorded = spans.lock().expect("lock poisoned");
    assert!(
        recorded.iter().any(|s| s == "get_range"),
        "expected a 'get_range' span, got: {recorded:?}"
    );
}

#[tokio::test]
async fn memory_backend_clear_range_creates_span() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();
    backend.clear_range(b"a".to_vec()..b"z".to_vec()).await.expect("clear_range should succeed");

    let recorded = spans.lock().expect("lock poisoned");
    assert!(
        recorded.iter().any(|s| s == "clear_range"),
        "expected a 'clear_range' span, got: {recorded:?}"
    );
}

#[tokio::test]
async fn all_crud_operations_produce_distinct_spans() {
    let collector = SpanCollector::default();
    let spans = Arc::clone(&collector.spans);

    let subscriber = tracing_subscriber::registry().with(collector);
    let _guard = tracing::subscriber::set_default(subscriber);

    let backend = MemoryBackend::new();

    // Exercise all basic CRUD operations
    backend.set(b"k".to_vec(), b"v".to_vec()).await.expect("set");
    let _ = backend.get(b"k").await;
    backend.delete(b"k").await.expect("delete");
    let _ = backend.get_range(b"a".to_vec()..b"z".to_vec()).await;
    backend.clear_range(b"a".to_vec()..b"z".to_vec()).await.expect("clear_range");
    let _ = backend.transaction().await;
    let _ = backend.health_check(HealthProbe::Readiness).await;

    let recorded = spans.lock().expect("lock poisoned");
    let expected =
        ["set", "get", "delete", "get_range", "clear_range", "transaction", "health_check"];

    for name in &expected {
        assert!(
            recorded.iter().any(|s| s == name),
            "missing span '{name}', recorded: {recorded:?}"
        );
    }
}
