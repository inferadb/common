# InferaDB Common — Codebase Manifest

> Auto-generated comprehensive analysis of every crate, file, and method in the `inferadb-common` workspace.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Crate: `inferadb-common-storage`](#crate-inferadb-common-storage)
- [Crate: `inferadb-common-authn`](#crate-inferadb-common-authn)
- [Crate: `inferadb-common-storage-ledger`](#crate-inferadb-common-storage-ledger)
- [Cross-Cutting Observations](#cross-cutting-observations)

---

## Architecture Overview

```
                       ┌─────────────────────────────────────┐
                       │     Application Layer               │
                       │   (Services, Repositories)          │
                       └──────────────┬──────────────────────┘
                                      │
                       ┌──────────────▼──────────────────────┐
                       │   StorageBackend Trait              │
                       │  (inferadb-common-storage)          │
                       │  - CRUD (get, set, delete)          │
                       │  - Range (get_range, clear_range)   │
                       │  - TTL (set_with_ttl)               │
                       │  - Transactions (transaction)       │
                       │  - Health (health_check)            │
                       └──────────────┬──────────────────────┘
                                      │
          ┌───────────────────────────┼───────────────────────────┐
          │                           │                           │
┌─────────▼────────┐       ┌──────────▼─────────┐     ┌──────────▼─────────┐
│  MemoryBackend   │       │  LedgerBackend     │     │  Future backends   │
│  (Testing)       │       │  (Production)      │     │  (RocksDB, etc.)   │
│                  │       │  (storage-ledger)  │     │                    │
│ - BTreeMap       │       │ - Ledger SDK       │     │                    │
│ - TTL cleanup    │       │ - Retry logic      │     │                    │
│ - Size limits    │       │ - Circuit breaker  │     │                    │
└──────────────────┘       └────────────────────┘     └────────────────────┘

                    ┌────────────────────────────────┐
                    │   Cross-Cutting Concerns       │
                    │ - Metrics (latency, counts)    │
                    │ - Rate Limiting (token bucket) │
                    │ - Size Limits (validation)     │
                    │ - Batch Writes (auto-split)    │
                    │ - Tracing (instrumentation)    │
                    └────────────────────────────────┘

                    ┌────────────────────────────────┐
                    │   Authentication (authn)       │
                    │ - JWT verification (EdDSA)     │
                    │ - Signing key cache (3-tier)   │
                    │ - Replay detection (JTI)       │
                    │ - Algorithm validation          │
                    └────────────────────────────────┘
```

### Crate Dependency Graph

```
inferadb-common-storage          (core abstractions, no external DB deps)
    ↑
    ├── inferadb-common-authn    (JWT auth, depends on storage for key store trait)
    │
    └── inferadb-common-storage-ledger  (Ledger implementation of StorageBackend)
            ↑
            └── inferadb-ledger-sdk  (upstream, external)
```

---

## Crate: `inferadb-common-storage`

**Path:** `crates/storage/`
**Purpose:** Defines the core storage abstraction layer — the `StorageBackend` trait, in-memory reference implementation, transaction model, error types, and cross-cutting concerns (metrics, rate limiting, batch writes, size limits, health checks). Also includes the `PublicSigningKeyStore` trait for JWT key management.

### Key Dependencies

| Dependency    | Purpose                                                    |
| ------------- | ---------------------------------------------------------- |
| `async-trait` | Async trait support for `StorageBackend` and `Transaction` |
| `bon`         | Builder pattern generation                                 |
| `bytes`       | Zero-copy byte buffers                                     |
| `chrono`      | DateTime handling for signing keys                         |
| `parking_lot` | High-performance mutex/rwlock                              |
| `thiserror`   | Ergonomic error derivation                                 |
| `tokio`       | Async runtime                                              |
| `tracing`     | Structured logging and instrumentation                     |
| `zeroize`     | Secure memory zeroing for key material                     |

### Features

- **`testutil`** — Exposes `FailingBackend`, assertion macros, helper functions
- **`failpoints`** — Enables `fail` crate injection points

---

### `src/lib.rs` — Crate Root

**Purpose:** Module organization and public API re-exports.

**Key Re-exports:** `StorageBackend`, `StorageError`, `ConfigError`, `StorageResult`, `MemoryBackend`, `Metrics`, `LatencyPercentiles`, `RateLimitConfig`, `RateLimitedBackend`, `TokenBucketLimiter`, `OrganizationExtractor`, `SizeLimits`, `Transaction`, `BatchConfig`, `BatchWriter`, `BatchResult`, `BatchFlushStats`, `BatchOperation`, `BoxError`, `TimeoutContext`, `HealthProbe`, `HealthStatus`, `HealthMetadata`, `MetricsCollector`, `MetricsSnapshot`, `OrganizationOperationSnapshot`, `RateLimitMetricsSnapshot`, `validate_key_size`, `validate_sizes`, `DEFAULT_MAX_KEY_SIZE`, `DEFAULT_MAX_VALUE_SIZE`, `Zeroizing`

**Insights:**

- Excellent API ergonomics — all primary types available at crate root
- Clear public/private module separation
- Architecture ASCII diagram in docs aids onboarding

---

### `src/backend.rs` — StorageBackend Trait

**Purpose:** The core abstraction that all storage implementations must satisfy.

#### Trait: `StorageBackend`

| Method                 | Signature                                                                                                                                | Description                                             |
| ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------- |
| `get`                  | `async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>`                                                                        | Retrieves value by key; returns `None` for missing keys |
| `set`                  | `async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()>`                                                                 | Unconditional write (upsert)                            |
| `compare_and_set`      | `async fn compare_and_set(&self, key: &[u8], expected: Option<&[u8]>, new_value: Vec<u8>) -> StorageResult<()>`                          | Atomic CAS; `expected: None` = insert-if-absent         |
| `delete`               | `async fn delete(&self, key: &[u8]) -> StorageResult<()>`                                                                                | Removes key; no-op if missing                           |
| `get_range`            | `async fn get_range<R: RangeBounds<Vec<u8>> + Send>(&self, range: R) -> StorageResult<Vec<KeyValue>>`                                    | Range scan; results sorted by key                       |
| `clear_range`          | `async fn clear_range<R: RangeBounds<Vec<u8>> + Send>(&self, range: R) -> StorageResult<()>`                                             | Deletes all keys in range                               |
| `set_with_ttl`         | `async fn set_with_ttl(&self, key: Vec<u8>, value: Vec<u8>, ttl: Duration) -> StorageResult<()>`                                         | Sets key with time-to-live                              |
| `transaction`          | `async fn transaction(&self) -> StorageResult<Box<dyn Transaction>>`                                                                     | Creates a new transaction                               |
| `health_check`         | `async fn health_check(&self, probe: HealthProbe) -> StorageResult<HealthStatus>`                                                        | Kubernetes-style health probe                           |
| `compare_and_set_json` | `async fn compare_and_set_json<T: Serialize + Deserialize>(&self, key: &[u8], expected: Option<&T>, new_value: &T) -> StorageResult<()>` | Typed CAS with JSON serialization (default impl)        |

**Insights:**

- Well-designed abstraction covering all essential KV operations plus advanced features
- Each method has detailed documentation covering semantics, edge cases, and errors
- CAS semantics clearly specified: `None` = insert-if-absent, `Some(val)` = update-if-matches
- TTL interaction documented: CAS treats expired keys as absent
- `compare_and_set_json` includes warnings about `serde_json` non-determinism

---

### `src/transaction.rs` — Transaction Trait

**Purpose:** Transaction trait definition with extensive isolation semantics documentation.

#### Trait: `Transaction`

| Method            | Signature                                                                                                         | Description                                |
| ----------------- | ----------------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| `get`             | `async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>>`                                                 | Reads with read-your-writes semantics      |
| `set`             | `fn set(&mut self, key: Vec<u8>, value: Vec<u8>)`                                                                 | Buffers a write                            |
| `delete`          | `fn delete(&mut self, key: Vec<u8>)`                                                                              | Buffers a delete                           |
| `compare_and_set` | `fn compare_and_set(&mut self, key: Vec<u8>, expected: Option<Vec<u8>>, new_value: Vec<u8>) -> StorageResult<()>` | Buffers a CAS operation                    |
| `commit`          | `async fn commit(self: Box<Self>) -> StorageResult<()>`                                                           | Atomically applies all buffered operations |

**Isolation Model:**

| Property             | Guarantee                                  |
| -------------------- | ------------------------------------------ |
| Dirty reads          | Not possible                               |
| Non-repeatable reads | Possible (read-committed)                  |
| Phantom reads        | Possible                                   |
| Write skew           | Possible (only CAS-protected keys checked) |
| Read-your-writes     | Yes                                        |
| Atomic commit        | Yes (all-or-nothing)                       |

**Insights:**

- Exceptional documentation (215 lines) with SQL comparison table
- `Box<Self>` for commit prevents use-after-commit
- Explicitly documents what is NOT provided (snapshot isolation, serializability)

---

### `src/error.rs` — Error Types

**Purpose:** Standardized error types with structured context and tracing integration.

#### Enum: `StorageError` (`#[non_exhaustive]`)

| Variant               | Key Fields                                   | Transient? | Description                                     |
| --------------------- | -------------------------------------------- | ---------- | ----------------------------------------------- |
| `NotFound`            | `key`, `span_id`                             | No         | Key does not exist                              |
| `Conflict`            | `span_id`                                    | No         | CAS condition failed or concurrent modification |
| `Connection`          | `message`, `source`, `span_id`               | **Yes**    | Network/connection error                        |
| `Serialization`       | `message`, `source`, `span_id`               | No         | Serialization/deserialization failure           |
| `Internal`            | `message`, `source`, `span_id`               | No         | Unexpected internal error                       |
| `Timeout`             | `context: Option<TimeoutContext>`, `span_id` | **Yes**    | Operation timed out                             |
| `CasRetriesExhausted` | `attempts`, `span_id`                        | No         | CAS retries exceeded limit                      |
| `CircuitOpen`         | `span_id`                                    | No         | Circuit breaker is open                         |
| `SizeLimitExceeded`   | `kind`, `actual`, `limit`, `span_id`         | No         | Key or value too large                          |
| `RateLimitExceeded`   | `retry_after`, `span_id`                     | **Yes**    | Token bucket exhausted                          |
| `ShuttingDown`        | `span_id`                                    | No         | Backend is shutting down                        |

#### Key Methods

| Method                                                  | Description                                                     |
| ------------------------------------------------------- | --------------------------------------------------------------- |
| `is_transient() -> bool`                                | Returns `true` for `Connection`, `Timeout`, `RateLimitExceeded` |
| `detail() -> String`                                    | Full diagnostic context (server-side only)                      |
| `not_found(key)`, `conflict()`, `connection(msg)`, etc. | Constructor helpers that capture current span ID                |

#### Struct: `TimeoutContext`

| Field                 | Type                       | Description                                            |
| --------------------- | -------------------------- | ------------------------------------------------------ |
| `attempts_completed`  | `u32`                      | Number of retry attempts completed before timeout      |
| `during_backoff`      | `bool`                     | Whether timeout fired during backoff sleep (vs backend call) |
| `last_error`          | `Option<Box<StorageError>>` | Last backend error before timeout; reconstructed from `detail()` on cancellation |

#### Enum: `ConfigError` (`#[non_exhaustive]`)

| Variant        | Fields                                                | Description                         |
| -------------- | ----------------------------------------------------- | ----------------------------------- |
| `BelowMinimum` | `field: &'static str`, `min: String`, `value: String` | Config value below required minimum |

**Insights:**

- Excellent design — `Display` for users, `detail()` for debugging
- `span_id` on every variant enables distributed trace correlation
- `#[non_exhaustive]` allows adding variants without breaking changes
- Constructor helpers are ergonomic and auto-capture span context
- `TimeoutContext.during_backoff` distinguishes "retry config too aggressive" from "backend is slow" — aids operational diagnosis

---

### `src/memory.rs` — In-Memory Backend

**Purpose:** `BTreeMap`-backed `StorageBackend` for testing and local development.

#### Struct: `MemoryBackend` (Clone)

| Field            | Type                                      | Description                  |
| ---------------- | ----------------------------------------- | ---------------------------- |
| `data`           | `Arc<RwLock<BTreeMap<Vec<u8>, Bytes>>>`   | Key-value store              |
| `ttl_data`       | `Arc<RwLock<BTreeMap<Vec<u8>, Instant>>>` | TTL expiration times         |
| `shutdown_guard` | `Arc<ShutdownGuard>`                      | Cancels cleanup task on drop |
| `size_limits`    | `Option<SizeLimits>`                      | Optional size validation     |

| Method                             | Description                                               |
| ---------------------------------- | --------------------------------------------------------- |
| `new() -> Self`                    | Creates backend with background TTL cleanup (1s interval) |
| `with_size_limits(limits) -> Self` | Creates backend with size validation                      |

**Internal: `MemoryTransaction`**

| Field                                  | Description                                      |
| -------------------------------------- | ------------------------------------------------ |
| `pending: HashMap<Vec<u8>, PendingOp>` | Buffered operations (Set, Delete, CompareAndSet) |

**Insights:**

- BTreeMap enables sorted range queries (O(log n) per op)
- Background task cleans expired TTL keys every ~1 second (sleep between iterations)
- `ShutdownGuard` ensures cleanup task cancels on drop — all backend clones must be dropped for cleanup to stop
- `Clone` via `Arc` enables easy sharing across async tasks
- Full feature parity with production backends — ideal for testing

---

### `src/batch.rs` — Batch Write Operations

**Purpose:** Automatic transaction splitting based on size limits.

#### Struct: `BatchConfig`

| Field             | Default  | Description                  |
| ----------------- | -------- | ---------------------------- |
| `max_batch_size`  | 1000 ops | Maximum operations per batch |
| `max_batch_bytes` | 8 MB     | Maximum bytes per batch      |

#### Struct: `BatchWriter<B: StorageBackend>`

| Method                                              | Description                                  |
| --------------------------------------------------- | -------------------------------------------- |
| `new(backend, config) -> Self`                      | Creates writer                               |
| `set(key, value)`                                   | Buffers a set operation                      |
| `delete(key)`                                       | Buffers a delete operation                   |
| `flush() -> BatchResult`                            | Commits current batch; writer remains usable |
| `flush_all(self) -> StorageResult<BatchFlushStats>` | Final flush, consumes writer                 |

#### Struct: `BatchResult`

| Method                                          | Description                   |
| ----------------------------------------------- | ----------------------------- |
| `is_success() -> bool`                          | All operations succeeded      |
| `has_failures() -> bool`                        | At least one operation failed |
| `results() -> &[Result<(), Arc<StorageError>>]` | Per-operation results         |
| `stats() -> &BatchFlushStats`                   | Batch statistics              |

**Constants:** `TRANSACTION_SIZE_LIMIT = 9 MB` (Ledger limit)

**Insights:**

- Auto-splits batches at 9 MB transaction limit (safety margin under FoundationDB's 10 MB hard limit)
- `Arc<StorageError>` allows failed ops in a batch to share one error instance
- Failpoint integration (`batch-before-commit`) for testing
- Separate `flush()` (reusable) vs `flush_all()` (consuming) is good API design

---

### `src/metrics.rs` — Metrics Collection

**Purpose:** Operation counters, latency histograms, error tracking, per-organization breakdowns.

#### Struct: `Metrics`

**Recording Methods:**

| Method                                                                                                       | Description                   |
| ------------------------------------------------------------------------------------------------------------ | ----------------------------- |
| `record_get(latency, organization)`                                                                             | Records get operation         |
| `record_set(latency, organization)`                                                                             | Records set operation         |
| `record_delete(latency, organization)`                                                                          | Records delete operation      |
| `record_error(error)`                                                                                        | Records error by variant name |
| `record_transaction`, `record_get_range`, `record_clear_range`, `record_health_check`, `record_set_with_ttl` | Other operation types         |

**Retrieval Methods:**

| Method                                              | Description                 |
| --------------------------------------------------- | --------------------------- |
| `get_count() -> u64`                                | Total get operations        |
| `get_latency_percentiles() -> LatencyPercentiles`   | p50/p95/p99 in microseconds |
| `error_counts() -> HashMap<String, u64>`            | Error counts by variant     |
| `organization_metrics(ns) -> Option<OrganizationMetrics>` | Per-organization breakdown     |
| (plus matching getters for all operation types)     |                             |

#### Struct: `LatencyPercentiles`

| Field | Type  | Description                    |
| ----- | ----- | ------------------------------ |
| `p50` | `u64` | 50th percentile (microseconds) |
| `p95` | `u64` | 95th percentile                |
| `p99` | `u64` | 99th percentile                |

**Insights:**

- `Ordering::Relaxed` for all counters — justified by approximate nature of metrics
- Circular latency buffers (1024 samples) — bounded memory, trades accuracy
- Max organizations limit (default 100) prevents cardinality explosion; overflow to `_other`

---

### `src/rate_limiter.rs` — Token Bucket Rate Limiting

**Purpose:** Per-organization rate limiting via token bucket algorithm.

#### Struct: `RateLimitConfig`

| Field   | Description             |
| ------- | ----------------------- |
| `rate`  | Tokens per second       |
| `burst` | Maximum bucket capacity |

#### Struct: `TokenBucketLimiter`

| Method                                           | Description                                              |
| ------------------------------------------------ | -------------------------------------------------------- |
| `new(config) -> Self`                            | Creates limiter                                          |
| `check(organization, cost) -> Result<(), Duration>` | Checks if request allowed; returns retry-after on denial |
| `set_enabled(enabled)`                           | Enables/disables globally                                |

#### Struct: `RateLimitedBackend<B>`

Wraps any `StorageBackend` and checks rate limit before each operation. **Transactions and health checks are exempt.**

#### Trait: `OrganizationExtractor`

| Method                                     | Description                                         |
| ------------------------------------------ | --------------------------------------------------- |
| `extract_organization(key) -> Option<String>` | Extracts organization from key for per-tenant limiting |

**Insights:**

- `f64` tokens enable sub-second precision for fractional refills
- `parking_lot::Mutex` for very short critical sections
- Exempting transactions and health checks from rate limiting is correct
- `NoopOrganizationExtractor` default enables simple global limiting

---

### `src/size_limits.rs` — Key/Value Size Validation

**Purpose:** Configurable size limits with validation.

#### Struct: `SizeLimits`

| Method                                                           | Description             |
| ---------------------------------------------------------------- | ----------------------- |
| `new(max_key_size, max_value_size) -> Result<Self, ConfigError>` | Creates with validation |
| `max_key_size() -> usize`                                        | Returns max key size    |
| `max_value_size() -> usize`                                      | Returns max value size  |

**Defaults:** 512 B keys, 512 KiB values

#### Functions

| Function                             | Description                               |
| ------------------------------------ | ----------------------------------------- |
| `validate_sizes(key, value, limits)` | Validates both key and value sizes        |
| `validate_key_size(key, limits)`     | Validates key size only (for delete, get) |

**Insights:**

- Simple, focused module — single responsibility
- `new()` enforces non-zero limits at construction time
- Returns structured `StorageError::SizeLimitExceeded` with `kind`, `actual`, `limit`

---

### `src/health.rs` — Health Check Types

**Purpose:** Kubernetes-style liveness/readiness/startup probes.

#### Enum: `HealthProbe`

`Liveness` | `Readiness` | `Startup`

#### Enum: `HealthStatus`

`Healthy(HealthMetadata)` | `Degraded(HealthMetadata)` | `Unhealthy(HealthMetadata)`

#### Struct: `HealthMetadata`

| Field            | Type                      |
| ---------------- | ------------------------- |
| `check_duration` | `Option<Duration>`        |
| `backend_name`   | `Option<String>`          |
| `details`        | `HashMap<String, String>` |

**Insights:**

- Three-way status (healthy/degraded/unhealthy) enables partial health reporting
- Extensible `details` HashMap for custom fields
- Aligns with Kubernetes health check model

---

### `src/types.rs` — Common Data Types

**Purpose:** Shared types used across the storage layer.

#### Struct: `KeyValue`

| Field   | Type    |
| ------- | ------- |
| `key`   | `Bytes` |
| `value` | `Bytes` |

#### Identifier Newtypes

`OrganizationSlug(u64)` | `VaultSlug(u64)` — re-exported from `inferadb-ledger-types`
`ClientId(i64)` | `CertId(i64)` — defined via `define_id!` macro

All derive: `Debug`, `Clone`, `Copy`, `PartialEq`, `Eq`, `Hash`, `Serialize`, `Deserialize`

**Insights:**

- `OrganizationSlug` and `VaultSlug` are re-exports from the Ledger types crate, aligning with the SDK's public API terminology
- `#[serde(transparent)]` — identifiers serialize as bare integers
- `ClientId`/`CertId` use `define_id!` macro for consistency

---

### `src/conformance.rs` — Conformance Test Suite

**Purpose:** 36 test functions that validate any `StorageBackend` implementation.

#### Test Categories

| Category        | Count | Examples                                                        |
| --------------- | ----- | --------------------------------------------------------------- |
| CRUD            | 8     | `crud_set_then_get_returns_value`, `crud_large_value_roundtrip` |
| Range           | 5     | `range_results_are_ordered`, `range_exclusive_end`              |
| TTL             | 4     | `ttl_key_expires`, `ttl_expired_keys_excluded_from_range`       |
| Transaction     | 6     | `tx_read_your_writes`, `tx_cas_conflict_rejects_commit`         |
| CAS             | 4     | `cas_insert_if_absent`, `cas_update_with_mismatched_value`      |
| Concurrent      | 3     | `concurrent_cas_exactly_one_winner`                             |
| Error Semantics | 4     | `health_check_returns_healthy`, `idempotent_delete`             |

#### Public Entry Point

```rust
pub async fn run_all(backend: Arc<dyn StorageBackend>);
```

**Insights:**

- Enables any new backend implementation to verify correctness with one function call
- Each test independently callable for fine-grained debugging

---

### `src/testutil.rs` — Test Utilities (feature-gated)

**Purpose:** Shared test helpers, assertion macros, and failure injection.

#### Helper Functions

| Function                   | Description                                              |
| -------------------------- | -------------------------------------------------------- |
| `make_key(prefix, i)`        | Generates deterministic test keys                        |
| `make_value(prefix, i)`      | Generates deterministic test values                      |
| `make_tagged_value(prefix)`  | Generates tagged test values                             |
| `populated_backend(count)`   | Creates MemoryBackend with `count` pre-populated entries |
| `is_conflict(err)`           | Checks if error is `Conflict` variant                    |
| `is_not_found(err)`          | Checks if error is `NotFound` variant                    |
| `is_timeout(err)`            | Checks if error is `Timeout` variant                     |

#### Assertion Macros

`assert_conflict!`, `assert_not_found!`, `assert_storage_ok!`, `assert_timeout!`, `assert_storage_error!`, `assert_kv_pair!`, `assert_range_results!`

#### Struct: `FailingBackend<B>`

Wraps any backend and injects errors for a specified operation type. Controlled via `enable_failures()` / `disable_failures()`.

---

### Auth Module: `src/auth/`

#### `src/auth/mod.rs` — Module Root

Re-exports all auth types. Defines `SIGNING_KEY_PREFIX = "signing-keys/"`.

#### `src/auth/signing_key.rs` — PublicSigningKey Type

**Purpose:** Ed25519 public signing key with lifecycle metadata.

#### Struct: `PublicSigningKey`

| Field               | Type                    | Description                          |
| ------------------- | ----------------------- | ------------------------------------ |
| `kid`               | `String`                | Key identifier                       |
| `public_key`        | `Zeroizing<String>`     | Base64url-encoded Ed25519 public key |
| `client_id`         | `ClientId`              | Owning client                        |
| `cert_id`           | `CertId`                | Associated certificate               |
| `created_at`        | `DateTime<Utc>`         | Creation timestamp                   |
| `valid_from`        | `DateTime<Utc>`         | Start of validity window             |
| `valid_until`       | `Option<DateTime<Utc>>` | End of validity window               |
| `active`            | `bool`                  | Whether key is active                |
| `revoked_at`        | `Option<DateTime<Utc>>` | Revocation timestamp                 |
| `revocation_reason` | `Option<String>`        | Reason for revocation                |

**Insights:**

- `Zeroizing<String>` zeroes key material on drop (defense in depth even for public keys)
- Custom `Debug` impl redacts `public_key`
- `#[serde(default)]` on `revoked_at` / `revocation_reason` for backward compatibility

#### `src/auth/store.rs` — PublicSigningKeyStore Trait

**Purpose:** Trait for storing/managing signing keys, plus in-memory implementation.

#### Trait: `PublicSigningKeyStore`

| Method                             | Description                                |
| ---------------------------------- | ------------------------------------------ |
| `create_key(ns, key)`              | Stores new key; `Conflict` if kid exists   |
| `get_key(ns, kid)`                 | Retrieves key by ID                        |
| `list_active_keys(ns)`             | Lists active, non-revoked, valid-time keys |
| `deactivate_key(ns, kid)`          | Soft-disables key (`active = false`)       |
| `revoke_key(ns, kid, reason)`      | Permanently revokes key                    |
| `activate_key(ns, kid)`            | Re-enables key (fails if revoked)          |
| `delete_key(ns, kid)`              | Removes key from storage                   |
| `create_keys(ns, keys)`            | Bulk create (default: sequential)          |
| `revoke_keys(ns, kids)`            | Bulk revoke (default: sequential)          |
| `rotate_key(ns, old_kid, new_key)` | Atomic: deactivate old + create new        |

#### Struct: `MemorySigningKeyStore`

Composite key `(OrganizationSlug, String)` for multi-tenancy. Overrides bulk methods for single-lock atomicity.

#### `src/auth/audit.rs` — Audit Logging

#### Enum: `AuditAction`

`StoreKey`, `RevokeKey`, `RotateKey`, `AccessKey`, `InvalidateCache`, `ClearCache`, `DeactivateKey`, `ActivateKey`, `DeleteKey`, `BulkStoreKeys`, `BulkRevokeKeys`

#### Struct: `AuditEvent`

| Field       | Type                      |
| ----------- | ------------------------- |
| `timestamp` | `DateTime<Utc>`           |
| `actor`     | `String`                  |
| `action`    | `AuditAction`             |
| `resource`  | `String`                  |
| `result`    | `AuditResult`             |
| `metadata`  | `HashMap<String, String>` |

#### Trait: `AuditLogger`

`async fn log(&self, event: &AuditEvent)` — Implementations: `TracingAuditLogger` (tracing INFO), `NoopAuditLogger`

#### `src/auth/audited_store.rs` — Audit Decorator

**Struct: `AuditedKeyStore<S, L>`** — Wraps any `PublicSigningKeyStore` to automatically log all mutations and access operations. `list_active_keys` is not audited (read-only bulk).

#### `src/auth/metrics.rs` — Signing Key Metrics

Tracks per-operation counts, latencies, error categorization, L3 cache metrics, and background refresh metrics. Mirrors the main `Metrics` API design.

---

### Benchmark File

#### `benches/storage_benchmarks.rs`

**Purpose:** Criterion benchmarks for `MemoryBackend` performance.

| Group                    | Benchmarks                                       |
| ------------------------ | ------------------------------------------------ |
| `get_operations`         | existing key (64B, 1KB, 64KB), missing key       |
| `set_operations`         | new key (64B, 1KB, 64KB), overwrite              |
| `delete_operations`      | existing key, missing key                        |
| `get_range_operations`   | 10/100/1000 keys, prefix scan                    |
| `clear_range_operations` | 10/100/1000 keys                                 |
| `transaction_operations` | 1/10/100 ops                                     |
| `concurrent_operations`  | parallel reads (4/16/64), parallel writes, mixed |
| `ttl_operations`         | set with TTL (64B, 1KB, 64KB)                    |
| `health_check`           | Probe overhead                                   |

**Insights:**

- Parameterized by value size to expose scaling behavior
- Concurrent benchmarks use multi-threaded runtime
- Throughput tracking via `Throughput::Bytes` and `Throughput::Elements`

---

### Test Files

#### `tests/conformance.rs`

Thin wrapper running the conformance suite against `MemoryBackend`. One test function per conformance check plus `run_all_conformance_tests()`.

#### `tests/concurrent_stress.rs` (10 tests, `#[ignore]`)

| Test                                      | Description                                       |
| ----------------------------------------- | ------------------------------------------------- |
| `parallel_writers_same_key`               | 16 tasks writing same key — no corruption         |
| `cas_exactly_one_winner_per_round`        | 50 rounds x 16 tasks racing CAS — exactly 1 win   |
| `cas_insert_if_absent_one_winner`         | 50 rounds x 16 tasks — insert-if-absent semantics |
| `mixed_read_write_workload`               | 16 tasks x 100 mixed ops — no panics or deadlocks |
| `concurrent_range_scans_during_writes`    | 8 writers + 8 readers — sorted, no corruption     |
| `ttl_expiration_concurrent_with_reads`    | 50 keys with 50ms TTL + 16 readers                |
| `concurrent_transactions_cas_on_same_key` | 50 rounds x 10 txns with CAS — exactly 1 wins     |
| `concurrent_clear_range_during_writes`    | 16 writers + 4 clearers — no deadlock             |
| `high_concurrency_parallel_reads`         | 64 tasks x 500 reads — consistent                 |
| `delete_while_reading`                    | 4 writers + 4 deleters + 8 readers                |

#### `tests/partial_failure.rs` (8 tests)

Tests transaction atomicity under failure injection. Validates all-or-nothing commit when CAS fails, commit fails, or size limits are exceeded.

#### `tests/range_edge_cases.rs` (22 tests)

Exhaustive range boundary testing: degenerate, single-key, unbounded, inclusive/exclusive combinations, large values, sorting.

#### `tests/tracing_spans.rs` (8 tests)

Validates `#[instrument]` annotations produce expected spans for each `StorageBackend` method.

#### `tests/transaction_edge_cases.rs` (20+ tests)

Transaction conflict detection, isolation, oversized batch splitting, empty transactions, mixed CAS + unconditional ops, abort isolation.

#### `tests/ttl_boundary.rs` (13 tests)

Zero TTL, large TTL (100 years), overflow (`Duration::MAX`), expiration boundaries, TTL clearing/replacement, background cleanup.

#### `tests/failpoint_tests.rs` (4 tests)

Fail-point injection for `batch-before-commit` and `health-check` failpoints.

---

## Crate: `inferadb-common-authn`

**Path:** `crates/authn/`
**Purpose:** JWT authentication library with Ledger-backed key storage, three-tier caching, replay detection, and defense against common JWT attacks (algorithm confusion, "none" bypass, organization isolation).

### Key Dependencies

| Dependency                | Purpose                                                |
| ------------------------- | ------------------------------------------------------ |
| `jsonwebtoken`            | JWT encoding/decoding                                  |
| `ed25519-dalek`           | Ed25519 signature verification                         |
| `moka`                    | Async caching with TTL                                 |
| `zeroize`                 | Secure memory scrubbing                                |
| `inferadb-common-storage` | Storage abstractions and `PublicSigningKeyStore` trait |

### Features

- **`testutil`** — Key generation, JWT crafting helpers
- **`failpoints`** — Cache fault injection

---

### `src/lib.rs` — Crate Root

Re-exports: `AuthError`, `Result`, `JwtClaims`, `DEFAULT_MAX_IAT_AGE`, `ReplayDetector`, `InMemoryReplayDetector`, `SigningKeyCache`, `DEFAULT_CACHE_CAPACITY`, `DEFAULT_CACHE_TTL`, `DEFAULT_FALLBACK_CAPACITY`, `DEFAULT_FALLBACK_TTL`, `DEFAULT_FALLBACK_WARN_THRESHOLD`, `DEFAULT_FALLBACK_CRITICAL_THRESHOLD`, `validate_algorithm`, `validate_kid`, `ACCEPTED_ALGORITHMS`, `FORBIDDEN_ALGORITHMS`, `MAX_KID_LENGTH`.

**Insights:** `#![deny(unsafe_code)]` at crate level. Documentation includes key material zeroing table showing what is protected.

---

### `src/error.rs` — AuthError

**Purpose:** Authentication error types with span tracing and security-aware display.

#### Enum: `AuthError` (`#[non_exhaustive]`)

| Variant                        | Transient?                  | Description                                 |
| ------------------------------ | --------------------------- | ------------------------------------------- |
| `InvalidTokenFormat`           | No                          | Malformed JWT                               |
| `TokenExpired`                 | No                          | Past expiration                             |
| `TokenNotYetValid`             | No                          | `nbf` in future                             |
| `InvalidSignature`             | No                          | Signature verification failed               |
| `InvalidIssuer`                | No                          | Unknown issuer                              |
| `InvalidAudience`              | No                          | Audience mismatch                           |
| `MissingClaim`                 | No                          | Required claim absent                       |
| `InvalidScope`                 | No                          | Scope validation failed                     |
| `UnsupportedAlgorithm`         | No                          | Algorithm not allowed                       |
| `JwksError`                    | No                          | JWKS-related error                          |
| `OidcDiscoveryFailed`          | No                          | OIDC discovery error                        |
| `IntrospectionFailed`          | No                          | Token introspection error                   |
| `InvalidIntrospectionResponse` | No                          | Malformed introspection response            |
| `TokenInactive`                | No                          | Token inactive per introspection            |
| `MissingTenantId`              | No                          | Missing `tenant_id` claim                   |
| `TokenTooOld`                  | No                          | `iat` exceeds max age                       |
| `KeyNotFound`                  | No                          | Signing key not in Ledger                   |
| `KeyInactive`                  | No                          | Key soft-disabled                           |
| `KeyRevoked`                   | No                          | Key permanently revoked                     |
| `KeyNotYetValid`               | No                          | Key `valid_from` in future                  |
| `KeyExpired`                   | No                          | Key `valid_until` in past                   |
| `InvalidPublicKey`             | No                          | Public key format invalid                   |
| `KeyStorageError`              | Delegates to `StorageError` | Storage backend error                       |
| `TokenReplayed`                | No                          | Duplicate JTI detected                      |
| `MissingJti`                   | No                          | Missing `jti` when replay detection enabled |
| `InvalidKid`                   | No                          | JWT `kid` header validation failed          |

**Key Methods:**

| Method           | Description                                                             |
| ---------------- | ----------------------------------------------------------------------- |
| `span_id()`      | Returns captured tracing span ID                                        |
| `detail()`       | Full diagnostic context (server-side only; `Display` sanitizes for API) |
| `is_transient()` | Only `KeyStorageError` delegates to `StorageError::is_transient()`      |

**Insights:**

- Security-first: `Display` never leaks internal error details to API consumers
- `detail()` preserves full context for server-side logging/debugging
- Every variant captures current span ID for distributed tracing
- Only storage errors can be transient — all auth failures are permanent

---

### `src/jwt.rs` — JWT Parsing and Verification

**Purpose:** Core JWT decoding, claims validation, and signature verification with Ledger integration.

#### Struct: `JwtClaims`

| Field      | Type             | Description                             |
| ---------- | ---------------- | --------------------------------------- |
| `iss`      | `String`         | Issuer                                  |
| `sub`      | `String`         | Subject                                 |
| `aud`      | `String`         | Audience                                |
| `exp`      | `u64`            | Expiration (Unix timestamp)             |
| `iat`      | `u64`            | Issued-at                               |
| `nbf`      | `Option<u64>`    | Not-before                              |
| `jti`      | `Option<String>` | JWT ID (for replay detection)           |
| `scope`    | `String`         | Space-delimited scopes                  |
| `vault`    | `Option<String>` | Vault slug                              |
| `org`      | `Option<String>` | Organization slug                       |

| Method               | Description                               |
| -------------------- | ----------------------------------------- |
| `require_org()`      | Returns org or `MissingTenantId` error    |
| `parse_scopes()`     | Splits scope string into `Vec<String>`    |
| `vault()`            | Returns vault if present                  |
| `org()`              | Returns org clone                         |

#### Functions

| Function                                               | Description                                              |
| ------------------------------------------------------ | -------------------------------------------------------- |
| `decode_jwt_header(token)`                             | Extracts header without verification                     |
| `decode_jwt_claims(token)`                             | Extracts claims without verification (for org lookup)    |
| `validate_claims(claims, audience, max_iat_age)`       | Validates exp, nbf, aud, iat age                         |
| `verify_signature(token, key, algorithm)`              | Cryptographic signature verification                     |
| `verify_with_signing_key_cache(token, cache)`          | Full pipeline: header -> claims -> key lookup -> verify  |
| `verify_with_replay_detection(token, cache, detector)` | Full pipeline + JTI replay check                         |

**Verification Flow:**

1. Extract `kid` + `alg` from header; validate kid format + validate algorithm
2. Decode claims (unverified); extract `org` for organization-scoped key lookup
3. Fetch decoding key from cache (`org` + `kid` -> Ledger)
4. Verify signature with `jsonwebtoken`
5. (Optional) Check JTI against replay detector

**Insights:**

- JWT payload bytes wrapped in `Zeroizing<Vec<u8>>` for memory scrubbing
- Algorithm validation happens before key lookup (prevents "none" attack)
- Kid validation before cache access (prevents path traversal)
- Claims decoded before verification — necessary for org lookup, but not trusted until post-verification

---

### `src/validation.rs` — Security Validation

**Purpose:** JWT algorithm and kid validation with security-first design.

#### Constants

| Constant               | Value                                 | Description                                      |
| ---------------------- | ------------------------------------- | ------------------------------------------------ |
| `FORBIDDEN_ALGORITHMS` | `["none", "HS256", "HS384", "HS512"]` | Rejected with "not allowed for security reasons" |
| `ACCEPTED_ALGORITHMS`  | `["EdDSA"]`                           | Only accepted algorithms                         |
| `MAX_KID_LENGTH`       | `256`                                 | Maximum kid string length                        |

#### Functions

| Function                  | Description                                                   |
| ------------------------- | ------------------------------------------------------------- |
| `validate_algorithm(alg)` | Rejects forbidden algorithms first, then checks accepted list |
| `validate_kid(kid)`       | Non-empty, max 256 chars, only `[a-zA-Z0-9._-]`               |

**Insights:**

- Two-phase algorithm check: forbidden then accepted (clear error messages for each)
- Kid validation prevents: path traversal (`../`), null bytes, colon injection (cache key safety)
- RS256 documented as future work in comments

---

### `src/signing_key_cache.rs` — Three-Tier Cache

**Purpose:** Ledger-backed signing key cache with graceful degradation during outages.

#### Architecture

```
L1: TTL cache (moka, default 5 min, 10K capacity)
    | miss
L2: Ledger (PublicSigningKeyStore)
    | transient error
L3: Fallback cache (moka, default 1 hour TTL, 10K capacity)
```

#### Struct: `SigningKeyCache`

| Method                                                          | Description                               |
| --------------------------------------------------------------- | ----------------------------------------- |
| `new(key_store, ttl)`                                           | Creates cache with default capacity       |
| `with_capacity(key_store, ttl, max_capacity)`                   | Custom L1 capacity                        |
| `with_fallback_ttl(key_store, ttl, max_capacity, fallback_ttl)` | Custom L3 TTL                             |
| `with_thresholds(self, warn, critical)`                         | L3 capacity alert thresholds              |
| `with_refresh_interval(self: Arc<Self>, interval)`              | Starts background key refresh             |
| `get_decoding_key(org_slug, kid)`                               | Main API: L1 -> L2 -> L3 fallback            |
| `invalidate(org_slug, kid)`                                     | Removes from L1, bumps generation counter    |
| `clear_all()`                                                   | Clears all caches                            |
| `shutdown()`                                                    | Cancels background tasks                     |
| `entry_count()`                                                 | Returns L1 cache entry count                 |
| `fallback_entry_count()`                                        | Returns L3 fallback cache entry count        |
| `fallback_capacity()`                                           | Returns L3 fallback cache max capacity       |
| `fallback_fill_percentage()`                                    | Returns L3 fill ratio (for alert thresholds) |

**Graceful Degradation:**

1. L1 miss -> fetch from L2 (Ledger)
2. L2 transient error (Connection/Timeout) -> serve from L3 (log age warning)
3. L2 non-transient error -> propagate immediately

**Race Prevention:** Generation counter (`AtomicU64`) prevents TOCTOU: if invalidation occurs during L2 fetch, the fetched result is discarded from L1/L3 but still returned to caller.

**Background Refresh:** Proactively re-fetches "active" keys (accessed since last cycle) to keep L1 warm.

**Insights:**

- Excellent design — production-resilient with bounded staleness
- Generation counter is a novel approach to TOCTOU in async cache population
- L3 capacity alerts with configurable thresholds (warn 80%, critical 95%)
- Fail-point injection for testing L2 failures

---

### `src/replay.rs` — Replay Detection

**Purpose:** JWT replay prevention via JTI tracking.

#### Trait: `ReplayDetector`

| Method                            | Description                                                 |
| --------------------------------- | ----------------------------------------------------------- |
| `check_and_mark(jti, expires_in)` | Atomic check-and-mark; returns `TokenReplayed` on duplicate |

#### Struct: `InMemoryReplayDetector`

Uses `moka::future::Cache` with per-entry TTL matching token expiration. LRU eviction as safety net.

**Insights:**

- Per-entry expiry matches token lifetime — automatic memory cleanup
- Atomic check-and-mark via moka's entry API (concurrent-safe)
- Capacity-bounded with LRU eviction
- Could add Ledger-backed implementation for distributed replay detection

---

### `src/testutil.rs` — Test Utilities (feature-gated)

| Function                                              | Description                                                         |
| ----------------------------------------------------- | ------------------------------------------------------------------- |
| `generate_test_keypair()`                             | Generates Ed25519 keypair; returns `(pkcs8_der, public_key_b64url)` |
| `create_signed_jwt(pkcs8, kid, org)`                  | Creates valid signed JWT                                            |
| `create_signed_jwt_with_jti(pkcs8, kid, org, jti)`    | Signed JWT with JTI                                                 |
| `craft_raw_jwt(header, payload)`                      | Crafts raw JWT for attack testing                                   |
| `create_test_signing_key(kid)`                        | Creates keypair + `PublicSigningKey`                                |
| `create_test_signing_key_with_pubkey(kid, pubkey)`    | Custom public key                                                   |

**Macro:** `assert_auth_error!(result, variant)` — Asserts error variant match.

---

### Test Files

#### `tests/security.rs` (24 tests)

| Category               | Tests                                          |
| ---------------------- | ---------------------------------------------- |
| Algorithm substitution | `none` rejected before key lookup              |
| Algorithm confusion    | HS256/384/512 with EdDSA pubkey as HMAC secret |
| Token expiration       | 1-second boundary precision                    |
| Future `nbf`           | Rejected when in future                        |
| Organization isolation    | Cross-organization key reuse prevented            |
| Key rotation           | Revoked key rejects in-flight tokens           |
| Malformed JWT          | Missing segments, bad base64, not JSON, empty  |
| RS256 boundary         | Rejected as not accepted                       |
| All forbidden algs     | Comprehensive rejection test                   |

#### `tests/failpoint_tests.rs` (2 tests)

Tests `cache-before-l2-fetch` failpoint activation and deactivation.

#### `fuzz/fuzz_targets/fuzz_jwt_claims.rs`

Structured fuzzing with `arbitrary` crate — generates plausible JWTs with varied algorithms, claims, and signatures.

#### `fuzz/fuzz_targets/fuzz_jwt_parsing.rs`

Raw UTF-8 byte fuzzing for JWT parsing. Complements structured fuzzing for edge cases.

---

## Crate: `inferadb-common-storage-ledger`

**Path:** `crates/storage-ledger/`
**Purpose:** Production `StorageBackend` implementation backed by InferaDB Ledger. Provides retry logic, circuit breaker, timeout management, and hex key encoding for byte-order preservation.

### Key Dependencies

| Dependency                | Purpose                                                                |
| ------------------------- | ---------------------------------------------------------------------- |
| `inferadb-ledger-sdk`     | Ledger gRPC client                                                     |
| `inferadb-common-storage` | Core traits (`StorageBackend`, `Transaction`, `PublicSigningKeyStore`) |
| `tokio`                   | Async runtime, timeouts                                                |
| `bon`                     | Builder pattern                                                        |
| `parking_lot`             | High-performance locks                                                 |
| `rand`                    | Jitter for backoff                                                     |
| `thiserror`               | Error derivation                                                       |
| `tracing`                 | Distributed tracing                                                    |

### Features

- **`testutil`** — Mock server helpers
- **`failpoints`** — Retry/timeout fault injection

---

### `src/lib.rs` — Crate Root

Comprehensive crate-level docs with architecture diagram, quick start, key mapping table, and tracing integration guide. Re-exports all primary types plus SDK config types (`ClientConfig`, `ReadConsistency`, `ServerSource`, `TraceConfig`).

---

### `src/backend.rs` — LedgerBackend

**Purpose:** Core `StorageBackend` implementation wrapping the Ledger SDK.

#### Struct: `LedgerBackend`

| Method                                              | Description                          |
| --------------------------------------------------- | ------------------------------------ |
| `new(config) -> Result<Self>`                       | Creates from `LedgerBackendConfig`   |
| `from_client(client, organization, vault, consistency)` | Creates from existing `LedgerClient` |
| `shutdown()`                                        | Signals graceful shutdown            |
| `is_shutting_down() -> bool`                        | Checks shutdown state                |
| `organization()`                                       | Returns the configured organization slug |
| `vault()`                                           | Returns the configured vault slug    |
| `client()`                                          | Returns reference to `LedgerClient`  |
| `client_arc()`                                      | Returns `Arc<LedgerClient>` clone    |
| `page_size()`                                       | Returns pagination page size         |
| `max_range_results()`                               | Returns range result safety limit    |
| `circuit_breaker_metrics()`                         | Returns circuit breaker counters     |
| `circuit_breaker_state()`                           | Returns current circuit state        |
| `storage_metrics()`                                 | Returns storage metrics              |

**Key Implementation Details:**

- **Key encoding:** Hex encoding preserves byte ordering for range queries
- **Range query optimization:** Computes longest common prefix between start/end bounds for server-side filtering
- **Per-operation timeouts:** Read 5s, Write 10s, List 30s (configurable)
- **Circuit breaker:** Optional, records only transient errors
- **Health checks bypass circuit breaker** but record success/failure
- **Size limits:** Optional validation before writes
- **Graceful shutdown:** New ops return `ShuttingDown` after signal

**Insights:**

- Excellent separation of concerns — retry, timeout, circuit breaker are composable layers
- Range query prefix optimization via `common_prefix_len()` reduces network transfer
- `set_with_ttl` computes absolute Unix timestamp (not relative duration) for Ledger compatibility
- Safety limit (`max_range_results`) prevents unbounded memory growth
- Property tests verify `common_prefix_len` correctness
- Every backend operation follows a consistent pattern: start timer → check shutdown → check circuit → execute with retry/timeout → record circuit result → record metrics

---

### `src/transaction.rs` — LedgerTransaction

**Purpose:** Read-committed transaction with in-memory buffering.

#### Struct: `LedgerTransaction`

| Internal State    | Description                                  |
| ----------------- | -------------------------------------------- |
| `pending_sets`    | `HashMap<String, Vec<u8>>` — buffered writes |
| `pending_deletes` | `HashSet<String>` — buffered deletes         |
| `pending_cas`     | `Vec<CasOperation>` — buffered CAS ops       |

**Commit:** Single SDK `write()` call with CAS conditions first, then sets, then deletes.

**Insights:**

- Correct read-your-writes: `get()` checks pending deletes -> pending sets -> Ledger
- Empty transaction commit is a no-op (no SDK call)
- Commit ordering: CAS operations first, then sets, then deletes — ensures preconditions are checked before unconditional writes apply

---

### `src/auth.rs` — LedgerSigningKeyStore

**Purpose:** Ledger-backed `PublicSigningKeyStore` implementation with CAS-based optimistic locking.

#### Struct: `LedgerSigningKeyStore`

| Method                                       | Description                           |
| -------------------------------------------- | ------------------------------------- |
| `new(client)`                                | Creates with linearizable consistency |
| `with_read_consistency(client, consistency)` | Custom consistency                    |
| `with_metrics(metrics)`                      | Enables metrics collection            |
| `with_cas_retry_config(config)`              | CAS retry policy                      |

**CAS Pattern:** All mutations use optimistic locking — read current, modify in-memory, write with `SetCondition::ValueEquals`, retry on conflict.

**Optimized: `create_keys`** — Single SDK `write()` for bulk creates (overrides default sequential impl).

**Insights:**

- Signing keys stored at `signing-keys/{kid}` in Ledger
- `revoke_key` is idempotent (preserves original revocation timestamp)
- `list_active_keys` gracefully handles malformed keys (logs error, continues)
- Hard-coded list limit of 1000 could be made configurable
- Internal helpers: `cas_write()`, `cas_delete()` encapsulate CAS read-modify-write pattern

---

### `src/circuit_breaker.rs` — Circuit Breaker

**Purpose:** Fail-fast pattern for sustained backend outages.

#### State Machine

```
Closed --[threshold failures]--> Open --[recovery timeout]--> HalfOpen
  ^                                                              |
  +--[success threshold]─────────────────────────────────────────+
  +--[any failure]───────────────────────────────────────────────+
```

#### Struct: `CircuitBreakerConfig`

| Field                         | Description                       |
| ----------------------------- | --------------------------------- |
| `failure_threshold`           | Failures before opening circuit   |
| `recovery_timeout`            | Wait time before half-open        |
| `half_open_success_threshold` | Successes needed to close circuit |

#### Struct: `CircuitBreaker`

| Method                               | Description                        |
| ------------------------------------ | ---------------------------------- |
| `allow_request() -> bool`            | Checks if request should proceed   |
| `record_success()`                   | Records success; may close circuit |
| `record_failure()`                   | Records failure; may open circuit  |
| `state() -> CircuitState`            | Returns current state              |
| `metrics() -> CircuitBreakerMetrics` | Returns snapshot                   |

**Insights:**

- `parking_lot::Mutex` for minimal lock contention
- Only transient errors (connection, timeout) recorded
- Health checks bypass breaker but record results
- `CircuitOpen` error is NOT transient — retrying immediately hits the open breaker

---

### `src/config.rs` — Configuration

**Purpose:** Validated configuration structs with builder patterns.

#### Struct: `RetryConfig`

| Field             | Default | Description              |
| ----------------- | ------- | ------------------------ |
| `max_retries`     | 3       | Maximum retry attempts   |
| `initial_backoff` | 100ms   | First backoff duration   |
| `max_backoff`     | 5s      | Maximum backoff duration |

#### Struct: `CasRetryConfig`

| Field         | Default | Description           |
| ------------- | ------- | --------------------- |
| `max_retries` | 5       | CAS retry attempts    |
| `base_delay`  | 50ms    | Base delay for jitter |

#### Struct: `TimeoutConfig`

| Field           | Default | Description       |
| --------------- | ------- | ----------------- |
| `read_timeout`  | 5s      | Per-read timeout  |
| `write_timeout` | 10s     | Per-write timeout |
| `list_timeout`  | 30s     | Per-list timeout  |

#### Struct: `LedgerBackendConfig`

Required: `client: ClientConfig`, `organization: OrganizationSlug`
Optional: `vault`, `read_consistency`, `page_size`, `max_range_results`, `retry_config`, `timeout_config`, `size_limits`, `circuit_breaker_config`, `cancellation_token`

**Insights:**

- Fallible builders validate all constraints at construction time
- Defaults always pass validation
- `#[builder(into)]` enables ergonomic `OrganizationSlug` conversion

---

### `src/error.rs` — Error Mapping

**Purpose:** Maps SDK errors to canonical `StorageError` variants.

#### Enum: `LedgerStorageError` (`#[non_exhaustive]`)

| Variant       | Description                        |
| ------------- | ---------------------------------- |
| `Sdk`         | Wraps `SdkError` with span context |
| `Config`      | Configuration error                |
| `KeyEncoding` | Hex encoding/decoding error        |
| `Transaction` | Transaction-specific error         |

#### SDK to StorageError Mapping

| SDK Error                 | StorageError             |
| ------------------------- | ------------------------ |
| `Connection`              | `Connection`             |
| `Timeout`                 | `Timeout`                |
| `Rpc(NotFound)`           | `NotFound`               |
| `Rpc(AlreadyExists)`      | `Conflict`               |
| `Rpc(FailedPrecondition)` | `Conflict` (CAS)         |
| `Rpc(InvalidArgument)`    | `Serialization`          |
| `Rpc(Unavailable)`        | `Connection`             |
| `RetryExhausted`          | `Connection`             |
| `RateLimited`             | `Connection` (transient) |
| `ProofVerification`       | `Internal`               |
| All other RPC codes       | `Internal`               |

**Insights:**

- Preserves error chains via `source` field
- Separate `Display` (API-safe) vs `detail()` (server-side)
- `RateLimited` mapped to `Connection` — could benefit from dedicated variant in future

---

### `src/keys.rs` — Hex Key Encoding

**Purpose:** Preserves byte ordering through hex encoding for Ledger string keys.

| Function                                   | Description                      |
| ------------------------------------------ | -------------------------------- |
| `encode_key(key: &[u8]) -> String`         | Lowercase hex encoding           |
| `decode_key(key: &str) -> Result<Vec<u8>>` | Hex decoding with error handling |

**Property Tests:** Round-trip, ordering preservation, collision-free, prefix preservation, invalid input rejection.

**Insights:**

- Critical for correctness: byte ordering must be preserved for range queries
- Property tests cover all essential invariants

---

### `src/retry.rs` — Retry Logic

**Purpose:** Exponential backoff with jitter and timeout support.

| Function                                                           | Description                                        |
| ------------------------------------------------------------------ | -------------------------------------------------- |
| `with_retry(config, metrics, op_name, operation)`                  | Retries transient errors with exponential backoff  |
| `with_retry_timeout(config, timeout, metrics, op_name, operation)` | Wraps `with_retry` with overall wall-clock timeout |
| `with_cas_retry(config, operation)`                                | Retries only `Conflict` errors with uniform jitter |

**Implementation Details:**

- `Arc<Mutex<RetryState>>` survives `tokio::time::timeout` future cancellation
- `TimeoutContext` captures attempt count, backoff state, and last error at timeout
- Separate retry logic for CAS vs transient errors (different semantics)
- Failpoints: `retry-before-sleep`, `cas-retry-before-sleep` for deterministic testing
- Internal `compute_backoff()` implements exponential backoff with full jitter

---

### `src/testutil.rs` — Test Utilities (feature-gated)

| Function                                           | Description                           |
| -------------------------------------------------- | ------------------------------------- |
| `test_client_config(server)`                       | Creates config for `MockLedgerServer` |
| `create_test_backend(server)`                      | Default test backend                  |
| `create_paginated_backend(server, page_size, max)` | Custom pagination settings            |

---

### Test Files

#### `tests/integration.rs`

Comprehensive mock-based tests covering all `StorageBackend` methods, signing key store operations, pagination, graceful shutdown, and distributed tracing.

#### `tests/real_ledger_integration.rs`

Real Ledger cluster tests (gated by `RUN_LEDGER_INTEGRATION_TESTS=1`). Tests actual behavior including TTL expiration, CAS conflicts, concurrent writes, reconnection, and stress tests. Uses unique vault IDs per test for isolation.

---

## Cross-Cutting Observations

### Strengths

1. **Well-designed trait abstraction** — `StorageBackend` is comprehensive yet focused; enables testing with `MemoryBackend` and production with `LedgerBackend`
2. **Layered decorator pattern** — `RateLimitedBackend<B>`, `AuditedKeyStore<S, L>` add cross-cutting concerns without modifying core logic
3. **Security-first authentication** — Algorithm validation before key lookup, kid validation before cache access, organization isolation, zeroized key material
4. **Production resilience** — Three-tier cache with bounded staleness, circuit breaker, retry with backoff, per-operation timeouts, graceful shutdown
5. **Exceptional testing** — Conformance suite, stress tests, property tests, fuzz tests, security tests, failpoint injection
6. **Observability** — Tracing span IDs on all errors, structured metrics, audit logging, health probes
7. **Modern Rust** — `async-trait`, `bon` builders, `thiserror`, `parking_lot`, `#[non_exhaustive]`, `Zeroizing`

### Potential Improvements

| Area                         | Observation                                                                             | Severity        |
| ---------------------------- | --------------------------------------------------------------------------------------- | --------------- |
| Async traits                 | Could migrate to native `async fn in trait` when stabilized (removes `async-trait` dep) | Low (future)    |
| Metrics unification          | `Metrics` and `SigningKeyMetrics` share code patterns — could extract shared module     | Low             |
| Rate limiting in SDK mapping | `RateLimited` mapped to `Connection` loses semantics — could add dedicated variant      | Low             |
| Signing key list limit       | Hard-coded 1000 in `list_active_keys` could be configurable                             | Low             |
| Replay detection             | In-memory only — distributed systems need Ledger-backed implementation                  | Medium (future) |
| Time-based tests             | Some use real `sleep` — could use `tokio::time::pause` for faster execution             | Low             |
| `DecodingKey` zeroing        | `jsonwebtoken::DecodingKey` can't be zeroized (external type) — documented gap          | Low (accepted)  |

### Security Assessment

| Threat                              | Mitigation                             | Status    |
| ----------------------------------- | -------------------------------------- | --------- |
| `alg: "none"` bypass                | Algorithm validation before key lookup | Mitigated |
| HS256 algorithm confusion           | Symmetric algorithms always rejected   | Mitigated |
| Token replay                        | JTI tracking with per-token TTL        | Mitigated |
| Cross-organization key reuse           | `org` claim to `OrganizationSlug` scoping | Mitigated |
| Kid path traversal                  | Allowlist validation `[a-zA-Z0-9._-]`  | Mitigated |
| Cache poisoning during invalidation | Generation counter (AtomicU64)         | Mitigated |
| Stale keys during outage            | L3 fallback with bounded TTL           | Bounded   |
| Memory exhaustion                   | Capacity limits on all caches          | Mitigated |
