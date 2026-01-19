// Allow passing unit to black_box - this is intentional in benchmarks to prevent
// the compiler from optimizing away the call.
#![allow(clippy::unit_arg)]

//! Performance benchmarks for StorageBackend implementations.
//!
//! This benchmark suite measures the performance of core storage operations
//! (get, set, delete, get_range, transactions) across different backends.
//!
//! # Running Benchmarks
//!
//! ```bash
//! # Run all storage benchmarks
//! cargo bench -p inferadb-storage
//!
//! # Run specific benchmark group
//! cargo bench -p inferadb-storage -- get_operations
//!
//! # Save baseline for comparison
//! cargo bench -p inferadb-storage -- --save-baseline main
//!
//! # Compare against baseline
//! cargo bench -p inferadb-storage -- --baseline main
//! ```
//!
//! # Benchmark Groups
//!
//! - `get_operations`: Single key lookups (existing key, missing key)
//! - `set_operations`: Single key writes (new key, overwrite)
//! - `get_range_operations`: Range scans with varying result sizes
//! - `transaction_operations`: Transaction commit with multiple operations
//! - `concurrent_operations`: Parallel read/write workloads

use std::hint::black_box;
use std::sync::atomic::{AtomicUsize, Ordering};

use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use inferadb_storage::{MemoryBackend, StorageBackend};
use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

/// Generate a deterministic key for benchmarking.
fn make_key(prefix: &str, index: usize) -> Vec<u8> {
    format!("{}:{:08}", prefix, index).into_bytes()
}

/// Generate random value data of specified size.
fn make_value(size: usize, seed: u64) -> Vec<u8> {
    let mut rng = StdRng::seed_from_u64(seed);
    (0..size).map(|_| rng.gen()).collect()
}

/// Setup backend with N keys pre-populated.
async fn setup_backend_with_data(num_keys: usize, value_size: usize) -> MemoryBackend {
    let backend = MemoryBackend::new();
    for i in 0..num_keys {
        let key = make_key("bench", i);
        let value = make_value(value_size, i as u64);
        backend.set(key, value).await.unwrap();
    }
    backend
}

// =============================================================================
// GET Operation Benchmarks
// =============================================================================

fn bench_get_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("get_operations");

    // Benchmark: get existing key (hot path)
    group.bench_function("get_existing_key", |b| {
        let backend = rt.block_on(setup_backend_with_data(1000, 256));
        let key = make_key("bench", 500);

        b.to_async(&rt).iter(|| {
            let b = backend.clone();
            let k = key.clone();
            async move { black_box(b.get(&k).await.unwrap()) }
        });
    });

    // Benchmark: get missing key (cold path)
    group.bench_function("get_missing_key", |b| {
        let backend = rt.block_on(setup_backend_with_data(1000, 256));
        let key = make_key("missing", 0);

        b.to_async(&rt).iter(|| {
            let b = backend.clone();
            let k = key.clone();
            async move { black_box(b.get(&k).await.unwrap()) }
        });
    });

    // Benchmark: get with varying key sizes
    for key_size in [16, 64, 256, 1024] {
        group.bench_with_input(
            BenchmarkId::new("get_key_size", key_size),
            &key_size,
            |b, &size| {
                let backend = rt.block_on(async {
                    let backend = MemoryBackend::new();
                    let key = vec![b'k'; size];
                    let value = make_value(256, 0);
                    backend.set(key, value).await.unwrap();
                    backend
                });
                let key = vec![b'k'; size];

                b.to_async(&rt).iter(|| {
                    let bk = backend.clone();
                    let k = key.clone();
                    async move { black_box(bk.get(&k).await.unwrap()) }
                });
            },
        );
    }

    // Benchmark: get with varying value sizes
    for value_size in [64, 256, 1024, 4096, 16384] {
        group.bench_with_input(
            BenchmarkId::new("get_value_size", value_size),
            &value_size,
            |b, &size| {
                let backend = rt.block_on(async {
                    let backend = MemoryBackend::new();
                    let key = make_key("bench", 0);
                    let value = make_value(size, 0);
                    backend.set(key, value).await.unwrap();
                    backend
                });
                let key = make_key("bench", 0);

                b.to_async(&rt).iter(|| {
                    let bk = backend.clone();
                    let k = key.clone();
                    async move { black_box(bk.get(&k).await.unwrap()) }
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// SET Operation Benchmarks
// =============================================================================

fn bench_set_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("set_operations");

    // Benchmark: set new key
    group.bench_function("set_new_key", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = AtomicUsize::new(0);
        let value = make_value(256, 0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let key = make_key("new", counter.fetch_add(1, Ordering::SeqCst));
            let v = value.clone();
            async move { black_box(bk.set(key, v).await.unwrap()) }
        });
    });

    // Benchmark: overwrite existing key
    group.bench_function("set_overwrite", |b| {
        let backend = rt.block_on(setup_backend_with_data(1, 256));
        let key = make_key("bench", 0);
        let value = make_value(256, 1);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let k = key.clone();
            let v = value.clone();
            async move { black_box(bk.set(k, v).await.unwrap()) }
        });
    });

    // Benchmark: set with varying value sizes
    for value_size in [64, 256, 1024, 4096, 16384] {
        group.throughput(Throughput::Bytes(value_size as u64));
        group.bench_with_input(
            BenchmarkId::new("set_value_size", value_size),
            &value_size,
            |b, &size| {
                let backend = rt.block_on(async { MemoryBackend::new() });
                let counter = AtomicUsize::new(0);
                let value = make_value(size, 0);

                b.to_async(&rt).iter(|| {
                    let bk = backend.clone();
                    let key = make_key("size", counter.fetch_add(1, Ordering::SeqCst));
                    let v = value.clone();
                    async move { black_box(bk.set(key, v).await.unwrap()) }
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// DELETE Operation Benchmarks
// =============================================================================

fn bench_delete_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("delete_operations");

    // Benchmark: delete existing key
    group.bench_function("delete_existing_key", |b| {
        b.to_async(&rt).iter_custom(|iters| async move {
            // Setup: create keys to delete
            let backend = MemoryBackend::new();
            for i in 0..iters {
                let key = make_key("del", i as usize);
                let value = make_value(256, i);
                backend.set(key, value).await.unwrap();
            }

            // Measure: delete all keys
            let start = std::time::Instant::now();
            for i in 0..iters {
                let key = make_key("del", i as usize);
                backend.delete(&key).await.unwrap();
            }
            start.elapsed()
        });
    });

    // Benchmark: delete missing key (no-op)
    group.bench_function("delete_missing_key", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let key = make_key("missing", 0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let k = key.clone();
            async move { black_box(bk.delete(&k).await.unwrap()) }
        });
    });

    group.finish();
}

// =============================================================================
// GET_RANGE Operation Benchmarks
// =============================================================================

fn bench_get_range_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("get_range_operations");

    // Benchmark: range scan with varying result sizes
    for result_size in [10, 100, 500, 1000] {
        group.throughput(Throughput::Elements(result_size as u64));
        group.bench_with_input(
            BenchmarkId::new("range_scan_results", result_size),
            &result_size,
            |b, &size| {
                let backend = rt.block_on(setup_backend_with_data(size, 256));
                let start = make_key("bench", 0);
                let end = make_key("bench", size);

                b.to_async(&rt).iter(|| {
                    let bk = backend.clone();
                    let s = start.clone();
                    let e = end.clone();
                    async move { black_box(bk.get_range(s..e).await.unwrap()) }
                });
            },
        );
    }

    // Benchmark: prefix scan (common pattern)
    group.bench_function("prefix_scan_100", |b| {
        let backend = rt.block_on(async {
            let backend = MemoryBackend::new();
            // Insert 100 keys with same prefix
            for i in 0..100 {
                let key = format!("prefix:entity:{:04}", i).into_bytes();
                let value = make_value(256, i as u64);
                backend.set(key, value).await.unwrap();
            }
            // Insert 100 keys with different prefix (noise)
            for i in 0..100 {
                let key = format!("other:entity:{:04}", i).into_bytes();
                let value = make_value(256, i as u64);
                backend.set(key, value).await.unwrap();
            }
            backend
        });

        let start = b"prefix:entity:".to_vec();
        let end = b"prefix:entity:~".to_vec(); // ~ is 0x7E, sorts after alphanumerics

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let s = start.clone();
            let e = end.clone();
            async move { black_box(bk.get_range(s..e).await.unwrap()) }
        });
    });

    // Benchmark: empty range scan
    group.bench_function("range_scan_empty", |b| {
        let backend = rt.block_on(setup_backend_with_data(1000, 256));
        let start = b"zzz:".to_vec();
        let end = b"zzz:~".to_vec();

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let s = start.clone();
            let e = end.clone();
            async move { black_box(bk.get_range(s..e).await.unwrap()) }
        });
    });

    group.finish();
}

// =============================================================================
// CLEAR_RANGE Operation Benchmarks
// =============================================================================

fn bench_clear_range_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("clear_range_operations");

    // Benchmark: clear range with varying sizes
    for range_size in [10, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("clear_range_size", range_size),
            &range_size,
            |b, &size| {
                b.to_async(&rt).iter_custom(|iters| async move {
                    let mut total = std::time::Duration::ZERO;

                    for _ in 0..iters {
                        // Setup: create keys to clear
                        let backend = MemoryBackend::new();
                        for i in 0..size {
                            let key = make_key("clear", i);
                            let value = make_value(256, i as u64);
                            backend.set(key, value).await.unwrap();
                        }

                        let start = make_key("clear", 0);
                        let end = make_key("clear", size);

                        // Measure: clear range
                        let now = std::time::Instant::now();
                        backend.clear_range(start..end).await.unwrap();
                        total += now.elapsed();
                    }

                    total
                });
            },
        );
    }

    group.finish();
}

// =============================================================================
// Transaction Benchmarks
// =============================================================================

fn bench_transaction_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("transaction_operations");

    // Benchmark: transaction with single set
    group.bench_function("txn_single_set", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = AtomicUsize::new(0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let key = make_key("txn", counter.fetch_add(1, Ordering::SeqCst));
            let value = make_value(256, 0);
            async move {
                let mut txn = bk.transaction().await.unwrap();
                txn.set(key, value);
                black_box(txn.commit().await.unwrap())
            }
        });
    });

    // Benchmark: transaction with multiple operations
    for ops_count in [5, 10, 50, 100] {
        group.bench_with_input(
            BenchmarkId::new("txn_ops_count", ops_count),
            &ops_count,
            |b, &count| {
                let backend = rt.block_on(async { MemoryBackend::new() });
                let batch_counter = AtomicUsize::new(0);

                b.to_async(&rt).iter(|| {
                    let bk = backend.clone();
                    let batch = batch_counter.fetch_add(1, Ordering::SeqCst);
                    async move {
                        let mut txn = bk.transaction().await.unwrap();
                        for i in 0..count {
                            let key = format!("batch{}:key:{}", batch, i).into_bytes();
                            let value = make_value(256, i as u64);
                            txn.set(key, value);
                        }
                        black_box(txn.commit().await.unwrap())
                    }
                });
            },
        );
    }

    // Benchmark: transaction with mixed read-write
    group.bench_function("txn_read_write_mix", |b| {
        let backend = rt.block_on(setup_backend_with_data(100, 256));
        let counter = AtomicUsize::new(0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let cnt = counter.fetch_add(1, Ordering::SeqCst);
            async move {
                let mut txn = bk.transaction().await.unwrap();

                // Read existing keys
                for i in 0..5 {
                    let key = make_key("bench", i * 10);
                    let _ = txn.get(&key).await.unwrap();
                }

                // Write new keys
                for i in 0..5 {
                    let key = format!("txn:new:{}:{}", cnt, i).into_bytes();
                    let value = make_value(256, i as u64);
                    txn.set(key, value);
                }

                // Delete some keys (by marking for deletion)
                for i in 95..100 {
                    let key = make_key("bench", i);
                    txn.delete(key);
                }

                black_box(txn.commit().await.unwrap())
            }
        });
    });

    // Benchmark: read-your-writes within transaction
    group.bench_function("txn_read_your_writes", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            async move {
                let mut txn = bk.transaction().await.unwrap();

                // Write a key
                txn.set(b"key1".to_vec(), b"value1".to_vec());

                // Read it back (should see uncommitted write)
                let value = txn.get(b"key1").await.unwrap();
                black_box(value);

                // Write another key based on read
                txn.set(b"key2".to_vec(), b"value2".to_vec());

                black_box(txn.commit().await.unwrap())
            }
        });
    });

    // Benchmark: empty transaction (no-op)
    group.bench_function("txn_empty_commit", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            async move {
                let txn = bk.transaction().await.unwrap();
                black_box(txn.commit().await.unwrap())
            }
        });
    });

    group.finish();
}

// =============================================================================
// Concurrent Operation Benchmarks
// =============================================================================

fn bench_concurrent_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("concurrent_operations");

    // Reduce sample size for concurrent tests (they're slower)
    group.sample_size(50);

    // Benchmark: parallel reads
    group.bench_function("parallel_reads_10", |b| {
        let backend = rt.block_on(setup_backend_with_data(1000, 256));

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            async move {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let b = bk.clone();
                        let key = make_key("bench", i * 100);
                        tokio::spawn(async move { b.get(&key).await.unwrap() })
                    })
                    .collect();

                for handle in handles {
                    black_box(handle.await.unwrap());
                }
            }
        });
    });

    // Benchmark: parallel writes (different keys)
    group.bench_function("parallel_writes_10", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let batch_counter = AtomicUsize::new(0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let batch = batch_counter.fetch_add(1, Ordering::SeqCst);
            async move {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let b = bk.clone();
                        let key = format!("par:{}:{}", batch, i).into_bytes();
                        let value = make_value(256, i as u64);
                        tokio::spawn(async move { b.set(key, value).await.unwrap() })
                    })
                    .collect();

                for handle in handles {
                    black_box(handle.await.unwrap());
                }
            }
        });
    });

    // Benchmark: mixed read-write workload (80% reads, 20% writes)
    group.bench_function("mixed_workload_80_20", |b| {
        let backend = rt.block_on(setup_backend_with_data(1000, 256));
        let batch_counter = AtomicUsize::new(0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let batch = batch_counter.fetch_add(1, Ordering::SeqCst);
            async move {
                let handles: Vec<_> = (0..10)
                    .map(|i| {
                        let b = bk.clone();
                        if i < 8 {
                            // 80% reads
                            let key = make_key("bench", i * 100);
                            tokio::spawn(async move {
                                black_box(b.get(&key).await.unwrap());
                            })
                        } else {
                            // 20% writes
                            let key = format!("write:{}:{}", batch, i).into_bytes();
                            let value = make_value(256, i as u64);
                            tokio::spawn(async move {
                                black_box(b.set(key, value).await.unwrap());
                            })
                        }
                    })
                    .collect();

                for handle in handles {
                    handle.await.unwrap();
                }
            }
        });
    });

    group.finish();
}

// =============================================================================
// Health Check Benchmark
// =============================================================================

fn bench_health_check(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("health_check");

    group.bench_function("health_check", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            async move { black_box(bk.health_check().await.unwrap()) }
        });
    });

    group.finish();
}

// =============================================================================
// TTL Operation Benchmarks
// =============================================================================

fn bench_ttl_operations(c: &mut Criterion) {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let mut group = c.benchmark_group("ttl_operations");

    // Benchmark: set with TTL
    group.bench_function("set_with_ttl", |b| {
        let backend = rt.block_on(async { MemoryBackend::new() });
        let counter = AtomicUsize::new(0);
        let value = make_value(256, 0);

        b.to_async(&rt).iter(|| {
            let bk = backend.clone();
            let key = make_key("ttl", counter.fetch_add(1, Ordering::SeqCst));
            let v = value.clone();
            async move { black_box(bk.set_with_ttl(key, v, 3600).await.unwrap()) }
        });
    });

    group.finish();
}

// =============================================================================
// Benchmark Groups
// =============================================================================

criterion_group!(
    benches,
    bench_get_operations,
    bench_set_operations,
    bench_delete_operations,
    bench_get_range_operations,
    bench_clear_range_operations,
    bench_transaction_operations,
    bench_concurrent_operations,
    bench_health_check,
    bench_ttl_operations,
);

criterion_main!(benches);
