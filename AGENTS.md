# AGENTS.md

## Running Benchmarks

The `inferadb-storage` crate includes Criterion benchmarks for measuring storage backend performance. These benchmarks run automatically in CI and compare against the main branch baseline.

## Running Locally

```bash
# Run all storage benchmarks
cargo bench -p inferadb-storage

# Run specific benchmark group
cargo bench -p inferadb-storage -- get_operations

# Save a baseline for comparison
cargo bench -p inferadb-storage -- --save-baseline my-baseline

# Compare against a baseline
cargo bench -p inferadb-storage -- --baseline my-baseline
```

## Benchmark Groups

| Group                    | Description                                                   |
| ------------------------ | ------------------------------------------------------------- |
| `get_operations`         | Single key lookups (existing key, missing key, varying sizes) |
| `set_operations`         | Single key writes (new key, overwrite, varying value sizes)   |
| `delete_operations`      | Key deletion (existing key, missing key)                      |
| `get_range_operations`   | Range scans with varying result sizes and prefix patterns     |
| `clear_range_operations` | Range deletion with varying sizes                             |
| `transaction_operations` | Transaction commit with single/multiple operations            |
| `concurrent_operations`  | Parallel read/write workloads                                 |
| `ttl_operations`         | Time-to-live key operations                                   |
| `health_check`           | Backend health check overhead                                 |

## Interpreting Results

Criterion reports timing statistics with confidence intervals:

```
get_operations/get_existing_key
                        time:   [1.234 µs 1.256 µs 1.278 µs]
                        change: [-2.34% +0.12% +2.56%] (p = 0.89 > 0.05)
                        No change in performance detected.
```

- **time**: [lower bound, estimate, upper bound] at 95% confidence
- **change**: Percentage change from baseline [lower, estimate, upper]
- **p-value**: Statistical significance (p < 0.05 indicates significant change)

## CI Integration

- **PRs**: Benchmarks compare against the main branch baseline
- **Main branch**: Benchmarks save a new baseline for future comparisons
- **Regression alerts**: PRs with >10% performance regression receive a warning comment
- **Artifacts**: Full benchmark results are stored as CI artifacts for 30 days
