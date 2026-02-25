# inferadb-common-authn

Shared JWT authentication for InferaDB services.

## Overview

This crate provides JWT validation and signing key management with Ledger-backed key storage. It enables both Engine and Control services to authenticate requests using a unified interface without requiring JWKS endpoints or Control connectivity.

## Features

- **JWT validation**: Claims parsing, timestamp validation, signature verification
- **Ledger-backed keys**: Public signing keys stored in Ledger, no JWKS endpoints needed
- **In-memory caching**: Reduces Ledger round-trips with TTL-based cache
- **Graceful degradation**: Fallback cache ensures operation during Ledger outages
- **Algorithm enforcement**: Only EdDSA and RS256 accepted, symmetric algorithms rejected

## Architecture

```
JWT arrives → decode header (kid, alg)
            → decode claims (org)
            → validate algorithm (EdDSA only for Ledger keys)
            → fetch key from cache
              ├─ L1: local cache hit → use cached key
              └─ L1 miss → L2: fetch from Ledger
                          → validate key state (active, not revoked, within validity)
                          → cache locally
            → verify signature
            → return validated claims
```

## Quick Start

```rust
use std::sync::Arc;
use std::time::Duration;
use inferadb_common_authn::{SigningKeyCache, jwt::verify_with_signing_key_cache};
use inferadb_common_storage::auth::MemorySigningKeyStore;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create signing key cache (use LedgerBackend in production)
    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store, Duration::from_secs(300));

    // Verify a JWT using Ledger-backed keys
    let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6Im9yZy0xMjM0NSJ9...";
    let claims = verify_with_signing_key_cache(token, &cache).await?;

    println!("Verified for org: {}", claims.org.unwrap_or_default());
    println!("Scopes: {:?}", claims.parse_scopes());

    Ok(())
}
```

## JWT Claims Structure

Per the Management API specification, JWTs should have the following structure:

```json
{
  "iss": "https://api.inferadb.com",
  "sub": "client:<client_id>",
  "aud": "https://api.inferadb.com/evaluate",
  "exp": 1234567890,
  "iat": 1234567800,
  "org": "<organization_slug>",
  "vault": "<vault>",
  "scope": "vault:read vault:write"
}
```

| Claim      | Required | Description                        |
| ---------- | -------- | ---------------------------------- |
| `iss`      | Yes      | Issuer URL                         |
| `sub`      | Yes      | Subject (client identifier)        |
| `aud`      | Yes      | Audience (target service)          |
| `exp`      | Yes      | Expiration time (Unix timestamp)   |
| `iat`      | Yes      | Issued-at time (Unix timestamp)    |
| `org`   | Yes      | Organization slug (Snowflake ID)   |
| `vault` | No       | Vault slug for finer-grained scoping |
| `scope`    | Yes      | Space-separated permission scopes  |

## Signing Key Cache

The `SigningKeyCache` wraps `PublicSigningKeyStore` with in-memory caching:

```rust
use std::sync::Arc;
use std::time::Duration;
use inferadb_common_authn::SigningKeyCache;
use inferadb_common_storage::auth::PublicSigningKeyStore;

fn create_cache(store: Arc<dyn PublicSigningKeyStore>) -> SigningKeyCache {
    // Default: 5-minute TTL, 10,000 key capacity
    SigningKeyCache::new(store, Duration::from_secs(300))
}

// Or with custom capacity
fn create_large_cache(store: Arc<dyn PublicSigningKeyStore>) -> SigningKeyCache {
    SigningKeyCache::with_capacity(store, Duration::from_secs(300), 50_000)
}
```

### Key Validation

Keys fetched from Ledger must satisfy all conditions:

| Condition                                       | Error            |
| ----------------------------------------------- | ---------------- |
| `active == true`                                | `KeyInactive`    |
| `revoked_at.is_none()`                          | `KeyRevoked`     |
| `now >= valid_from`                             | `KeyNotYetValid` |
| `valid_until.is_none() \|\| now <= valid_until` | `KeyExpired`     |

### Graceful Degradation

When Ledger is unavailable (connection or timeout errors), the cache falls back to previously fetched keys:

```
┌──────────────┐     ┌──────────────┐     ┌──────────────┐
│  JWT Request │────▶│   L1 Cache   │────▶│    Ledger    │
│              │     │   (TTL 5m)   │     │   (source)   │
└──────────────┘     └──────────────┘     └──────────────┘
                            │                    │
                            │                    ▼
                            │              ┌──────────────┐
                            │              │   Fallback   │
                            └─────────────▶│    Cache     │
                               on error    │  (no TTL)    │
                                           └──────────────┘
```

Transient errors (connection, timeout) trigger fallback. Definitive errors (not found, internal) do not.

## Algorithm Security

Only asymmetric algorithms are accepted:

| Algorithm | Status      | Notes                                 |
| --------- | ----------- | ------------------------------------- |
| `EdDSA`   | ✅ Accepted | Recommended, required for Ledger keys |
| `RS256`   | ✅ Accepted | Legacy support                        |
| `HS256`   | ❌ Rejected | Symmetric algorithm vulnerability     |
| `HS384`   | ❌ Rejected | Symmetric algorithm vulnerability     |
| `HS512`   | ❌ Rejected | Symmetric algorithm vulnerability     |
| `none`    | ❌ Rejected | No signature verification             |

```rust
use inferadb_common_authn::validation::validate_algorithm;

// EdDSA is accepted
assert!(validate_algorithm("EdDSA").is_ok());

// Symmetric algorithms are rejected
assert!(validate_algorithm("HS256").is_err());
```

## Error Handling

All operations return `Result<T, AuthError>`:

| Error                  | Description                           |
| ---------------------- | ------------------------------------- |
| `InvalidTokenFormat`   | Malformed JWT structure               |
| `TokenExpired`         | Token has expired (exp claim)         |
| `TokenNotYetValid`     | Token not yet valid (nbf claim)       |
| `InvalidSignature`     | Signature verification failed         |
| `MissingClaim`         | Required claim missing (org, etc.) |
| `UnsupportedAlgorithm` | Algorithm not in allowed list         |
| `KeyNotFound`          | Signing key not found in Ledger       |
| `KeyInactive`          | Signing key is soft-disabled          |
| `KeyRevoked`           | Signing key has been revoked          |
| `KeyExpired`           | Signing key validity period ended     |
| `KeyStorageError`      | Ledger unavailable, no fallback       |

## Low-Level API

For custom validation flows:

```rust
use inferadb_common_authn::jwt::{
    decode_jwt_header,
    decode_jwt_claims,
    validate_claims,
    verify_signature,
};
use inferadb_common_authn::validation::validate_algorithm;

fn custom_validation(token: &str) -> Result<(), Box<dyn std::error::Error>> {
    // 1. Decode header
    let header = decode_jwt_header(token)?;

    // 2. Validate algorithm
    let alg_str = format!("{:?}", header.alg);
    validate_algorithm(&alg_str)?;

    // 3. Decode claims (without verification)
    let claims = decode_jwt_claims(token)?;

    // 4. Validate claims (timestamps, audience)
    validate_claims(&claims, Some("https://api.inferadb.com/evaluate"))?;

    // 5. Verify signature (requires decoding key)
    // let verified = verify_signature(token, &key, header.alg)?;

    Ok(())
}
```

## Fuzz Testing

This crate includes fuzz targets for security-critical JWT parsing paths using
[cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) (LLVM libFuzzer).

### Prerequisites

```bash
cargo install cargo-fuzz
```

### Fuzz Targets

| Target             | Description                                                                           |
| ------------------ | ------------------------------------------------------------------------------------- |
| `fuzz_jwt_parsing` | Raw byte strings fed to `decode_jwt_header`, `decode_jwt_claims`, `validate_claims`   |
| `fuzz_jwt_claims`  | Structured inputs via `arbitrary` crate — generates valid-ish JWTs with random fields |

### Running Fuzz Tests

```bash
# Run the raw JWT parsing fuzzer (runs indefinitely, Ctrl+C to stop)
cd crates/authn
cargo +nightly fuzz run fuzz_jwt_parsing

# Run with a time limit (60 seconds)
cargo +nightly fuzz run fuzz_jwt_parsing -- -max_total_time=60

# Run the structured claims fuzzer
cargo +nightly fuzz run fuzz_jwt_claims -- -max_total_time=60

# Run with more parallelism
cargo +nightly fuzz run fuzz_jwt_parsing -- -max_total_time=120 -jobs=4 -workers=4
```

### Seed Corpus

Pre-built seed corpus files live in `fuzz/corpus/fuzz_jwt_parsing/` covering known
attack vectors:

- `alg_none` / `alg_hs256` / `alg_hs384` / `alg_hs512` — algorithm confusion attacks
- `path_traversal_kid` / `null_byte_kid` — kid injection attacks
- `oversized_payload` / `oversized_jti` — resource exhaustion
- `invalid_base64` / `invalid_payload_json` — malformed encoding
- `empty` / `single_dot` / `three_dots` — boundary cases

### Extending the Corpus

Add new seed inputs to `fuzz/corpus/<target_name>/`:

```bash
echo -n 'your-test-input' > fuzz/corpus/fuzz_jwt_parsing/my_new_case
```

The fuzzer will use seeds as starting points and mutate from there.

### Reproducing Crashes

If the fuzzer finds a crash, it saves the input in `fuzz/artifacts/<target>/`:

```bash
# Reproduce a specific crash
cargo +nightly fuzz run fuzz_jwt_parsing fuzz/artifacts/fuzz_jwt_parsing/crash-<hash>
```

Fix the bug, add the crash input as a regression test in `jwt.rs::tests::fuzz_regressions`,
and commit the fix.

## License

Dual-licensed under MIT or Apache 2.0.
