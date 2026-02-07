#![allow(clippy::expect_used)]

use std::time::Duration;

use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use inferadb_common_storage::{MemoryBackend, StorageBackend};
use tokio::runtime::Runtime;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn rt() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("failed to create tokio runtime")
}

fn make_key(prefix: &[u8], idx: usize) -> Vec<u8> {
    let mut key = prefix.to_vec();
    key.extend_from_slice(format!("{idx:08}").as_bytes());
    key
}

fn make_value(size: usize) -> Vec<u8> {
    vec![0xAB; size]
}

/// Creates a backend pre-populated with `count` keys of the form
/// `prefix{00000000..count}`, each with a value of `value_size` bytes.
fn populated_backend(
    rt: &Runtime,
    prefix: &[u8],
    count: usize,
    value_size: usize,
) -> MemoryBackend {
    let backend = rt.block_on(async { MemoryBackend::new() });
    let value = make_value(value_size);
    rt.block_on(async {
        for i in 0..count {
            backend.set(make_key(prefix, i), value.clone()).await.expect("populate set failed");
        }
    });
    backend
}

// ---------------------------------------------------------------------------
// 1. get_operations
// ---------------------------------------------------------------------------

fn get_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_operations");
    let rt = rt();

    // -- existing key (varying value sizes) --
    for &value_size in &[64, 1024, 65_536] {
        let backend = populated_backend(&rt, b"get:", 1, value_size);
        let key = make_key(b"get:", 0);
        group.throughput(Throughput::Bytes(value_size as u64));
        group.bench_with_input(
            BenchmarkId::new("existing_key", value_size),
            &value_size,
            |b, _| {
                b.to_async(&rt).iter(|| {
                    let be = backend.clone();
                    let k = key.clone();
                    async move {
                        be.get(&k).await.expect("get failed");
                    }
                });
            },
        );
    }

    // -- missing key --
    {
        let backend = populated_backend(&rt, b"get:", 1, 64);
        group.bench_function("missing_key", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                async move {
                    let result = be.get(b"nonexistent").await.expect("get failed");
                    assert!(result.is_none());
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 2. set_operations
// ---------------------------------------------------------------------------

fn set_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("set_operations");
    let rt = rt();

    // -- new key (varying value sizes) --
    for &value_size in &[64, 1024, 65_536] {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.throughput(Throughput::Bytes(value_size as u64));
        group.bench_with_input(BenchmarkId::new("new_key", value_size), &value_size, |b, &vs| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let k = make_key(b"set:", idx);
                let v = make_value(vs);
                async move {
                    be.set(k, v).await.expect("set failed");
                }
            });
        });
    }

    // -- overwrite existing key --
    {
        let backend = populated_backend(&rt, b"overwrite:", 1, 1024);
        let key = make_key(b"overwrite:", 0);
        let value = make_value(1024);

        group.bench_function("overwrite_existing", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let k = key.clone();
                let v = value.clone();
                async move {
                    be.set(k, v).await.expect("set failed");
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 3. delete_operations
// ---------------------------------------------------------------------------

fn delete_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("delete_operations");
    let rt = rt();

    // -- delete existing key --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_function("existing_key", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let k = make_key(b"del:", idx);
                async move {
                    // Populate then delete in one iteration to measure the delete path.
                    // The set cost is included, but it establishes the key exists.
                    be.set(k.clone(), make_value(64)).await.expect("set failed");
                    be.delete(&k).await.expect("delete failed");
                }
            });
        });
    }

    // -- delete missing key (no-op) --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });

        group.bench_function("missing_key", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                async move {
                    be.delete(b"nonexistent").await.expect("delete failed");
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 4. get_range_operations
// ---------------------------------------------------------------------------

fn get_range_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("get_range_operations");
    let rt = rt();

    for &count in &[10, 100, 1000] {
        let backend = populated_backend(&rt, b"range:", count, 256);
        let start = make_key(b"range:", 0);
        let end = make_key(b"range:", count);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("scan", count), &count, |b, _| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let s = start.clone();
                let e = end.clone();
                async move {
                    let results = be.get_range(s..e).await.expect("get_range failed");
                    assert!(!results.is_empty());
                }
            });
        });
    }

    // -- prefix scan (all keys share a prefix) --
    {
        let backend = populated_backend(&rt, b"pfx:", 500, 128);

        group.bench_function("prefix_scan_500", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let s = b"pfx:".to_vec();
                let e = b"pfx:\xff".to_vec();
                async move {
                    let results = be.get_range(s..e).await.expect("get_range failed");
                    assert_eq!(results.len(), 500);
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 5. clear_range_operations
// ---------------------------------------------------------------------------

fn clear_range_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("clear_range_operations");
    let rt = rt();

    for &count in &[10, 100, 1000] {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let value = make_value(128);

        group.throughput(Throughput::Elements(count as u64));
        group.bench_with_input(BenchmarkId::new("clear", count), &count, |b, &cnt| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let v = value.clone();
                async move {
                    // Populate keys for this iteration
                    for i in 0..cnt {
                        be.set(make_key(b"clear:", i), v.clone()).await.expect("set failed");
                    }
                    // Measure the clear
                    let start = make_key(b"clear:", 0);
                    let end = make_key(b"clear:", cnt);
                    be.clear_range(start..end).await.expect("clear_range failed");
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 6. transaction_operations
// ---------------------------------------------------------------------------

fn transaction_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_operations");
    let rt = rt();

    // -- single operation commit --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_function("single_op_commit", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let mut txn = be.transaction().await.expect("txn failed");
                    txn.set(make_key(b"txn:", idx), make_value(64));
                    txn.commit().await.expect("commit failed");
                }
            });
        });
    }

    // -- multi-operation commit (10 ops) --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_function("multi_op_commit_10", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let base = counter.fetch_add(10, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let mut txn = be.transaction().await.expect("txn failed");
                    for i in 0..10 {
                        txn.set(make_key(b"txn10:", base + i), make_value(64));
                    }
                    txn.commit().await.expect("commit failed");
                }
            });
        });
    }

    // -- multi-operation commit (100 ops) --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_function("multi_op_commit_100", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let base = counter.fetch_add(100, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let mut txn = be.transaction().await.expect("txn failed");
                    for i in 0..100 {
                        txn.set(make_key(b"txn100:", base + i), make_value(64));
                    }
                    txn.commit().await.expect("commit failed");
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 7. concurrent_operations
// ---------------------------------------------------------------------------

fn concurrent_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("concurrent_operations");
    // Use a multi-thread runtime for actual concurrency
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("failed to create multi-thread runtime");

    // -- parallel reads --
    for &num_tasks in &[4u64, 16, 64] {
        let backend = populated_backend(&rt, b"conc:", 1000, 256);

        group.throughput(Throughput::Elements(num_tasks));
        group.bench_with_input(
            BenchmarkId::new("parallel_reads", num_tasks),
            &num_tasks,
            |b, &n| {
                b.to_async(&rt).iter(|| {
                    let be = backend.clone();
                    async move {
                        let mut set = tokio::task::JoinSet::new();
                        for i in 0..n {
                            let be = be.clone();
                            set.spawn(async move {
                                let key = make_key(b"conc:", (i as usize) % 1000);
                                be.get(&key).await.expect("get failed");
                            });
                        }
                        while set.join_next().await.is_some() {}
                    }
                });
            },
        );
    }

    // -- parallel writes --
    for &num_tasks in &[4u64, 16, 64] {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.throughput(Throughput::Elements(num_tasks));
        group.bench_with_input(
            BenchmarkId::new("parallel_writes", num_tasks),
            &num_tasks,
            |b, &n| {
                b.to_async(&rt).iter(|| {
                    let be = backend.clone();
                    let base = counter.fetch_add(n as usize, std::sync::atomic::Ordering::Relaxed);
                    async move {
                        let mut set = tokio::task::JoinSet::new();
                        for i in 0..n {
                            let be = be.clone();
                            set.spawn(async move {
                                be.set(make_key(b"pw:", base + i as usize), make_value(128))
                                    .await
                                    .expect("set failed");
                            });
                        }
                        while set.join_next().await.is_some() {}
                    }
                });
            },
        );
    }

    // -- mixed read-write workload --
    {
        let backend = populated_backend(&rt, b"mix:", 1000, 256);
        let counter = std::sync::atomic::AtomicUsize::new(0);

        group.bench_function("mixed_read_write_16", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let base = counter.fetch_add(8, std::sync::atomic::Ordering::Relaxed);
                async move {
                    let mut set = tokio::task::JoinSet::new();
                    // 8 readers
                    for i in 0..8u64 {
                        let be = be.clone();
                        set.spawn(async move {
                            let key = make_key(b"mix:", (i as usize) % 1000);
                            be.get(&key).await.expect("get failed");
                        });
                    }
                    // 8 writers
                    for i in 0..8u64 {
                        let be = be.clone();
                        set.spawn(async move {
                            be.set(make_key(b"mix:", base + i as usize), make_value(128))
                                .await
                                .expect("set failed");
                        });
                    }
                    while set.join_next().await.is_some() {}
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 8. ttl_operations
// ---------------------------------------------------------------------------

fn ttl_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("ttl_operations");
    let rt = rt();

    // -- set_with_ttl (varying value sizes) --
    for &value_size in &[64, 1024, 65_536] {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = std::sync::atomic::AtomicUsize::new(0);
        let ttl = Duration::from_secs(300);

        group.throughput(Throughput::Bytes(value_size as u64));
        group.bench_with_input(
            BenchmarkId::new("set_with_ttl", value_size),
            &value_size,
            |b, &vs| {
                b.to_async(&rt).iter(|| {
                    let be = backend.clone();
                    let idx = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let k = make_key(b"ttl:", idx);
                    let v = make_value(vs);
                    async move {
                        be.set_with_ttl(k, v, ttl).await.expect("set_with_ttl failed");
                    }
                });
            },
        );
    }

    // -- get key with TTL metadata --
    {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let key = b"ttl:read".to_vec();
        rt.block_on(async {
            backend
                .set_with_ttl(key.clone(), make_value(256), Duration::from_secs(3600))
                .await
                .expect("populate failed");
        });

        group.bench_function("get_with_ttl_metadata", |b| {
            b.to_async(&rt).iter(|| {
                let be = backend.clone();
                let k = key.clone();
                async move {
                    be.get(&k).await.expect("get failed");
                }
            });
        });
    }

    group.finish();
}

// ---------------------------------------------------------------------------
// 9. health_check
// ---------------------------------------------------------------------------

fn health_check(c: &mut Criterion) {
    let mut group = c.benchmark_group("health_check");
    let rt = rt();

    let backend = rt.block_on(async { MemoryBackend::new() });
    group.bench_function("health_check", |b| {
        b.to_async(&rt).iter(|| {
            let be = backend.clone();
            async move {
                be.health_check().await.expect("health check failed");
            }
        });
    });

    group.finish();
}

// ---------------------------------------------------------------------------
// Group registration
// ---------------------------------------------------------------------------

criterion_group!(
    benches,
    get_operations,
    set_operations,
    delete_operations,
    get_range_operations,
    clear_range_operations,
    transaction_operations,
    concurrent_operations,
    ttl_operations,
    health_check,
);
criterion_main!(benches);
