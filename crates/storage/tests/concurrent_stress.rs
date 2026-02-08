//! Concurrent access stress tests for `MemoryBackend`.
//!
//! These tests exercise the storage backend under realistic multi-threaded
//! workloads to detect data races, deadlocks, and lost updates. They are
//! gated behind the `stress_tests` cfg flag for CI runtime control:
//!
//! ```bash
//! cargo test -p inferadb-common-storage --test concurrent_stress -- --ignored
//! ```

#![allow(clippy::expect_used, clippy::panic)]

use std::{collections::HashSet, time::Duration};

use bytes::Bytes;
use inferadb_common_storage::{MemoryBackend, StorageBackend, error::StorageError};
use tokio::task::JoinSet;

/// Number of concurrent tasks for most tests.
const CONCURRENCY: usize = 16;

/// Number of CAS rounds for the exactly-one-winner test.
const CAS_ROUNDS: usize = 50;

/// Number of operations each task performs in mixed workload tests.
const OPS_PER_TASK: usize = 100;

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

fn make_key(prefix: &str, i: usize) -> Vec<u8> {
    format!("{prefix}:{i:06}").into_bytes()
}

fn make_value(task: usize, i: usize) -> Vec<u8> {
    format!("task{task}-val{i}").into_bytes()
}

// ---------------------------------------------------------------------------
// Test: Parallel writers to the same key (last writer wins)
// ---------------------------------------------------------------------------

/// Spawns `CONCURRENCY` tasks that each write to the same key `OPS_PER_TASK`
/// times. After all tasks complete, the key must hold a valid value written by
/// one of the tasks — no corruption, no partial writes.
#[tokio::test]
#[ignore] // Run with --ignored or RUSTFLAGS='--cfg stress_tests'
async fn parallel_writers_same_key() {
    let backend = MemoryBackend::new();
    let key = b"shared-key".to_vec();

    let mut set = JoinSet::new();
    for task_id in 0..CONCURRENCY {
        let backend = backend.clone();
        let key = key.clone();
        set.spawn(async move {
            for i in 0..OPS_PER_TASK {
                let value = make_value(task_id, i);
                backend.set(key.clone(), value).await.expect("set should succeed");
            }
            task_id
        });
    }

    // Await all tasks — no panics or deadlocks.
    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }

    // The key must exist and hold a well-formed value from some task.
    let value = backend.get(&key).await.expect("get should succeed").expect("key should exist");
    let s = String::from_utf8(value.to_vec()).expect("value should be valid utf-8");
    assert!(s.starts_with("task"), "value should be from one of the writer tasks, got: {s}");
}

// ---------------------------------------------------------------------------
// Test: Parallel CAS — exactly one winner per round
// ---------------------------------------------------------------------------

/// Runs `CAS_ROUNDS` rounds of CAS contention. In each round, the key holds a
/// known value and `CONCURRENCY` tasks race to CAS it. Exactly one task must
/// succeed; all others must receive `StorageError::Conflict`.
#[tokio::test]
#[ignore]
async fn cas_exactly_one_winner_per_round() {
    let backend = MemoryBackend::new();
    let key = b"cas-key".to_vec();

    for round in 0..CAS_ROUNDS {
        let current_value = format!("round-{round}").into_bytes();
        backend.set(key.clone(), current_value.clone()).await.expect("setup set should succeed");

        let new_value_fn = |task_id: usize| format!("round-{round}-winner-{task_id}").into_bytes();

        let mut set = JoinSet::new();
        for task_id in 0..CONCURRENCY {
            let backend = backend.clone();
            let key = key.clone();
            let expected = current_value.clone();
            let new_val = new_value_fn(task_id);
            set.spawn(async move { backend.compare_and_set(&key, Some(&expected), new_val).await });
        }

        let mut successes = 0usize;
        let mut conflicts = 0usize;
        while let Some(result) = set.join_next().await {
            match result.expect("task should not panic") {
                Ok(()) => successes += 1,
                Err(StorageError::Conflict { .. }) => conflicts += 1,
                Err(e) => panic!("unexpected error in CAS round {round}: {e}"),
            }
        }

        assert_eq!(successes, 1, "round {round}: exactly one CAS should succeed, got {successes}");
        assert_eq!(conflicts, CONCURRENCY - 1, "round {round}: all other CAS should conflict");
    }
}

// ---------------------------------------------------------------------------
// Test: CAS insert-if-absent — exactly one winner
// ---------------------------------------------------------------------------

/// Multiple tasks race to insert a key that does not yet exist using
/// `compare_and_set(key, None, value)`. Exactly one should win.
#[tokio::test]
#[ignore]
async fn cas_insert_if_absent_one_winner() {
    let backend = MemoryBackend::new();

    for round in 0..CAS_ROUNDS {
        let key = format!("insert-race-{round}").into_bytes();

        let mut set = JoinSet::new();
        for task_id in 0..CONCURRENCY {
            let backend = backend.clone();
            let key = key.clone();
            let value = format!("creator-{task_id}").into_bytes();
            set.spawn(async move { backend.compare_and_set(&key, None, value).await });
        }

        let mut successes = 0usize;
        let mut conflicts = 0usize;
        while let Some(result) = set.join_next().await {
            match result.expect("task should not panic") {
                Ok(()) => successes += 1,
                Err(StorageError::Conflict { .. }) => conflicts += 1,
                Err(e) => panic!("unexpected error in insert round {round}: {e}"),
            }
        }

        assert_eq!(successes, 1, "round {round}: exactly one insert should succeed");
        assert_eq!(conflicts, CONCURRENCY - 1);
    }
}

// ---------------------------------------------------------------------------
// Test: Mixed read-write workload
// ---------------------------------------------------------------------------

/// Spawns `CONCURRENCY` tasks that perform a mix of gets, sets, deletes, and
/// range scans concurrently on overlapping key spaces. Verifies no panics,
/// deadlocks, or data corruption.
#[tokio::test]
#[ignore]
async fn mixed_read_write_workload() {
    let backend = MemoryBackend::new();

    // Pre-populate some keys for range scans and reads to find.
    for i in 0..100 {
        backend
            .set(make_key("pre", i), make_value(0, i))
            .await
            .expect("pre-populate should succeed");
    }

    let mut set = JoinSet::new();
    for task_id in 0..CONCURRENCY {
        let backend = backend.clone();
        set.spawn(async move {
            for i in 0..OPS_PER_TASK {
                match i % 5 {
                    // Read an existing key
                    0 => {
                        let _ = backend.get(&make_key("pre", i % 100)).await;
                    },
                    // Write a new key
                    1 => {
                        let _ = backend
                            .set(make_key("task", task_id * 1000 + i), make_value(task_id, i))
                            .await;
                    },
                    // Delete a key (may or may not exist)
                    2 => {
                        let _ = backend.delete(&make_key("task", task_id * 1000 + i)).await;
                    },
                    // Range scan
                    3 => {
                        let start = make_key("pre", 0);
                        let end = make_key("pre", 10);
                        let _ = backend.get_range(start..end).await;
                    },
                    // Set with TTL
                    _ => {
                        let _ = backend
                            .set_with_ttl(
                                make_key("ttl", task_id * 1000 + i),
                                make_value(task_id, i),
                                Duration::from_secs(60),
                            )
                            .await;
                    },
                }
            }
            task_id
        });
    }

    // All tasks must complete without panic or deadlock.
    let mut completed = HashSet::new();
    while let Some(result) = set.join_next().await {
        let task_id = result.expect("task should not panic");
        completed.insert(task_id);
    }
    assert_eq!(completed.len(), CONCURRENCY, "all tasks should complete");
}

// ---------------------------------------------------------------------------
// Test: Concurrent range scans during writes
// ---------------------------------------------------------------------------

/// Writers continuously insert keys while readers perform range scans. Verifies
/// that range scan results are always internally consistent: keys are sorted
/// and each key's value is well-formed.
#[tokio::test]
#[ignore]
async fn concurrent_range_scans_during_writes() {
    let backend = MemoryBackend::new();
    let writers = 8;
    let readers = 8;

    let mut set = JoinSet::new();

    // Writer tasks
    for task_id in 0..writers {
        let backend = backend.clone();
        set.spawn(async move {
            for i in 0..OPS_PER_TASK {
                let key = format!("scan-key:{:06}", task_id * OPS_PER_TASK + i).into_bytes();
                let value = format!("v-{task_id}-{i}").into_bytes();
                backend.set(key, value).await.expect("write should succeed");
            }
        });
    }

    // Reader tasks performing range scans
    for _ in 0..readers {
        let backend = backend.clone();
        set.spawn(async move {
            for _ in 0..OPS_PER_TASK {
                let start = b"scan-key:".to_vec();
                let end = b"scan-key:\xff".to_vec();
                let results =
                    backend.get_range(start..end).await.expect("range scan should succeed");

                // Results must be sorted by key.
                for window in results.windows(2) {
                    assert!(window[0].key <= window[1].key, "range results should be sorted");
                }

                // Every value must be well-formed.
                for kv in &results {
                    let v =
                        String::from_utf8(kv.value.to_vec()).expect("value should be valid utf-8");
                    assert!(v.starts_with("v-"), "value should have expected prefix");
                }
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }
}

// ---------------------------------------------------------------------------
// Test: TTL expiration concurrent with reads and writes
// ---------------------------------------------------------------------------

/// Tasks set keys with short TTLs while other tasks continuously read them.
/// Verifies that reads either return the value or `None` (after expiration),
/// never an error or corrupted data.
#[tokio::test]
#[ignore]
async fn ttl_expiration_concurrent_with_reads() {
    let backend = MemoryBackend::new();
    let key_count = 50;

    // Writer tasks set keys with very short TTLs.
    let mut set = JoinSet::new();
    for i in 0..key_count {
        let backend = backend.clone();
        set.spawn(async move {
            let key = make_key("ttl-race", i);
            let value = make_value(0, i);
            backend
                .set_with_ttl(key, value, Duration::from_millis(50))
                .await
                .expect("set_with_ttl should succeed");
        });
    }

    // Reader tasks continuously read those keys.
    for _ in 0..CONCURRENCY {
        let backend = backend.clone();
        set.spawn(async move {
            // Read in a tight loop for a short window that spans expiration.
            for iteration in 0..200 {
                let key = make_key("ttl-race", iteration % key_count);
                match backend.get(&key).await {
                    Ok(Some(value)) => {
                        // If present, must be well-formed.
                        let s =
                            String::from_utf8(value.to_vec()).expect("value should be valid utf-8");
                        assert!(s.starts_with("task"), "value should be from writer, got: {s}");
                    },
                    Ok(None) => {
                        // Key expired or not yet written — both valid.
                    },
                    Err(e) => {
                        panic!("unexpected error reading TTL key: {e}");
                    },
                }
                // Small yield to interleave with writers and TTL cleanup.
                tokio::task::yield_now().await;
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }
}

// ---------------------------------------------------------------------------
// Test: Concurrent transactions with CAS on overlapping keys
// ---------------------------------------------------------------------------

/// Multiple transactions use `compare_and_set` on the same key and commit
/// concurrently. Each commit either succeeds or returns `Conflict` due to
/// the CAS precondition failing at commit time.
#[tokio::test]
#[ignore]
async fn concurrent_transactions_cas_on_same_key() {
    let backend = MemoryBackend::new();
    let key = b"txn-cas-key".to_vec();

    for round in 0..CAS_ROUNDS {
        let current = format!("round-{round}").into_bytes();
        backend.set(key.clone(), current.clone()).await.expect("setup should succeed");

        let mut set = JoinSet::new();
        for task_id in 0..10 {
            let backend = backend.clone();
            let key = key.clone();
            let expected = current.clone();
            set.spawn(async move {
                let mut txn = backend.transaction().await.expect("txn should start");
                let new_value = format!("round-{round}-txn-{task_id}").into_bytes();
                txn.compare_and_set(key, Some(expected), new_value)
                    .expect("buffering CAS should succeed");
                txn.commit().await
            });
        }

        let mut successes = 0usize;
        let mut conflicts = 0usize;
        while let Some(result) = set.join_next().await {
            match result.expect("task should not panic") {
                Ok(()) => successes += 1,
                Err(StorageError::Conflict { .. }) => conflicts += 1,
                Err(e) => panic!("unexpected error in txn CAS round {round}: {e}"),
            }
        }

        // MemoryTransaction acquires a single write lock at commit time, so
        // transactions are effectively serialized. The first to acquire the
        // lock succeeds; subsequent ones see the updated value and fail CAS.
        assert_eq!(successes, 1, "round {round}: exactly one transaction CAS should succeed");
        assert_eq!(conflicts, 9);
    }
}

// ---------------------------------------------------------------------------
// Test: Concurrent clear_range during writes
// ---------------------------------------------------------------------------

/// Writers insert keys while another task clears ranges. Verifies no deadlock
/// or panic under this contention pattern.
#[tokio::test]
#[ignore]
async fn concurrent_clear_range_during_writes() {
    let backend = MemoryBackend::new();

    let mut set = JoinSet::new();

    // Writer tasks
    for task_id in 0..CONCURRENCY {
        let backend = backend.clone();
        set.spawn(async move {
            for i in 0..OPS_PER_TASK {
                let key = format!("clear-test:{:06}", task_id * OPS_PER_TASK + i).into_bytes();
                let value = format!("val-{task_id}-{i}").into_bytes();
                let _ = backend.set(key, value).await;
            }
        });
    }

    // Clearer tasks that periodically wipe ranges
    for _ in 0..4 {
        let backend = backend.clone();
        set.spawn(async move {
            for _ in 0..20 {
                let start = b"clear-test:".to_vec();
                let end = b"clear-test:\xff".to_vec();
                let _ = backend.clear_range(start..end).await;
                tokio::task::yield_now().await;
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }

    // Final state: either keys exist or they were cleared. Just verify
    // the backend is in a consistent state by performing a range scan.
    let start = b"clear-test:".to_vec();
    let end = b"clear-test:\xff".to_vec();
    let results = backend.get_range(start..end).await.expect("final range scan should succeed");

    // Results must be sorted if any remain.
    for window in results.windows(2) {
        assert!(window[0].key <= window[1].key, "results should be sorted");
    }
}

// ---------------------------------------------------------------------------
// Test: High-concurrency parallel reads
// ---------------------------------------------------------------------------

/// Many tasks read the same key concurrently. Verifies reads are consistent
/// and never return corrupted data under high read contention.
#[tokio::test]
#[ignore]
async fn high_concurrency_parallel_reads() {
    let backend = MemoryBackend::new();
    let key = b"hot-key".to_vec();
    let value = b"hot-value-data-that-should-not-be-corrupted".to_vec();

    backend.set(key.clone(), value.clone()).await.expect("setup should succeed");

    let expected = Bytes::from(value);
    let tasks = 64;
    let reads_per_task = 500;

    let mut set = JoinSet::new();
    for _ in 0..tasks {
        let backend = backend.clone();
        let key = key.clone();
        let expected = expected.clone();
        set.spawn(async move {
            for _ in 0..reads_per_task {
                let result = backend.get(&key).await.expect("get should succeed");
                let val = result.expect("key should exist");
                assert_eq!(val, expected, "read should return consistent value");
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }
}

// ---------------------------------------------------------------------------
// Test: Delete-while-reading
// ---------------------------------------------------------------------------

/// Writers set keys, deleters remove them, readers check them — all concurrently.
/// Reads must return `Some(valid_value)` or `None`, never an error.
#[tokio::test]
#[ignore]
async fn delete_while_reading() {
    let backend = MemoryBackend::new();
    let key_space = 20;

    let mut set = JoinSet::new();

    // Writer tasks
    for task_id in 0..4 {
        let backend = backend.clone();
        set.spawn(async move {
            for round in 0..OPS_PER_TASK {
                let key = make_key("dwr", round % key_space);
                let value = make_value(task_id, round);
                let _ = backend.set(key, value).await;
                tokio::task::yield_now().await;
            }
        });
    }

    // Deleter tasks
    for _ in 0..4 {
        let backend = backend.clone();
        set.spawn(async move {
            for round in 0..OPS_PER_TASK {
                let key = make_key("dwr", round % key_space);
                let _ = backend.delete(&key).await;
                tokio::task::yield_now().await;
            }
        });
    }

    // Reader tasks
    for _ in 0..8 {
        let backend = backend.clone();
        set.spawn(async move {
            for round in 0..OPS_PER_TASK {
                let key = make_key("dwr", round % key_space);
                match backend.get(&key).await {
                    Ok(Some(value)) => {
                        let s =
                            String::from_utf8(value.to_vec()).expect("value should be valid utf-8");
                        assert!(s.starts_with("task"), "value should be well-formed");
                    },
                    Ok(None) => { /* deleted or not yet written */ },
                    Err(e) => panic!("unexpected error: {e}"),
                }
            }
        });
    }

    while let Some(result) = set.join_next().await {
        result.expect("task should not panic");
    }
}
