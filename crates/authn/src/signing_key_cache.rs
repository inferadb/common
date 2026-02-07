//! Ledger-backed signing key cache for JWT validation.
//!
//! This module provides [`SigningKeyCache`], which wraps
//! [`PublicSigningKeyStore`](inferadb_common_storage::auth::PublicSigningKeyStore) with in-memory
//! caching to avoid Ledger round-trips on every token validation.
//!
//! # Architecture
//!
//! ```text
//! JWT arrives → extract kid, org_id
//!              → check local cache (L1)
//!              → miss? fetch from Ledger via PublicSigningKeyStore (L2)
//!              → validate key state (active, not revoked, within validity window)
//!              → cache decoding key locally
//!              → verify signature
//! ```
//!
//! # Cache Strategy
//!
//! - **TTL**: Default 300 seconds (5 minutes)
//! - **Eviction**: Time-based expiration + capacity limits
//! - **Invalidation**: Keys become invalid on next fetch after Ledger state changes
//!
//! # Example
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::time::Duration;
//! use inferadb_common_authn::SigningKeyCache;
//! use inferadb_common_storage::{NamespaceId, auth::PublicSigningKeyStore};
//!
//! async fn example(key_store: Arc<dyn PublicSigningKeyStore>) {
//!     // Create cache with 5-minute TTL
//!     let cache = SigningKeyCache::new(key_store, Duration::from_secs(300));
//!
//!     // Get decoding key for JWT validation
//!     // org_id from JWT claims, kid from JWT header
//!     let decoding_key = cache.get_decoding_key(NamespaceId::from(42), "key-2024-001").await;
//! }
//! ```

use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::{PUBLIC_KEY_LENGTH, VerifyingKey};
use inferadb_common_storage::{
    NamespaceId, StorageError, Zeroizing,
    auth::{PublicSigningKey, PublicSigningKeyStore},
};
use jsonwebtoken::DecodingKey;
use moka::future::Cache;

use crate::error::AuthError;

/// Default cache TTL (5 minutes).
///
/// This balances security (revoked keys propagate within this window)
/// with performance (reduces Ledger round-trips).
pub const DEFAULT_CACHE_TTL: Duration = Duration::from_secs(300);

/// Default maximum cache capacity.
pub const DEFAULT_CACHE_CAPACITY: u64 = 10_000;

/// Default maximum fallback cache capacity.
///
/// The fallback cache stores keys without TTL for graceful degradation
/// during Ledger outages. This capacity bound prevents unbounded memory
/// growth in long-running services.
pub const DEFAULT_FALLBACK_CAPACITY: u64 = 10_000;

/// Cache for public signing keys fetched from Ledger.
///
/// Wraps [`PublicSigningKeyStore`] with in-memory caching to avoid
/// Ledger round-trips on every token validation.
///
/// # Key Validation
///
/// When a key is fetched from Ledger, it must satisfy all conditions:
/// - `active == true`
/// - `revoked_at.is_none()`
/// - `now >= valid_from`
/// - `valid_until.is_none() || now <= valid_until`
///
/// Keys failing validation are not cached and result in auth errors.
///
/// # Cache Keys
///
/// Keys are cached using `{org_id}:{kid}` format, ensuring namespace isolation.
///
/// # Graceful Degradation
///
/// When Ledger is unavailable (connection or timeout errors), the cache falls back
/// to previously fetched keys stored in the fallback cache. This ensures continued
/// operation during transient Ledger outages. The fallback cache is capacity-bounded
/// with LRU eviction to prevent unbounded memory growth.
pub struct SigningKeyCache {
    /// In-memory cache with TTL-based expiration (L1).
    cache: Cache<String, Arc<DecodingKey>>,
    /// Backend store for fetching keys from Ledger (L2).
    key_store: Arc<dyn PublicSigningKeyStore>,
    /// Fallback cache for graceful degradation during Ledger outages (L3).
    /// Capacity-bounded with LRU eviction, no TTL.
    fallback: Cache<String, Arc<DecodingKey>>,
}

impl SigningKeyCache {
    /// Creates a new signing key cache.
    ///
    /// # Arguments
    ///
    /// * `key_store` - Backend store (typically Ledger-backed)
    /// * `ttl` - Time-to-live for cached keys
    ///
    /// # Example
    ///
    /// ```no_run
    /// use std::sync::Arc;
    /// use std::time::Duration;
    /// use inferadb_common_authn::SigningKeyCache;
    /// use inferadb_common_storage::auth::PublicSigningKeyStore;
    ///
    /// fn example(key_store: Arc<dyn PublicSigningKeyStore>) {
    ///     let cache = SigningKeyCache::new(key_store, Duration::from_secs(300));
    /// }
    /// ```
    #[must_use]
    pub fn new(key_store: Arc<dyn PublicSigningKeyStore>, ttl: Duration) -> Self {
        Self::with_capacity(key_store, ttl, DEFAULT_CACHE_CAPACITY)
    }

    /// Creates a new signing key cache with custom capacity.
    ///
    /// # Arguments
    ///
    /// * `key_store` - Backend store
    /// * `ttl` - Time-to-live for cached keys
    /// * `max_capacity` - Maximum number of keys to cache in L1 and fallback
    #[must_use]
    pub fn with_capacity(
        key_store: Arc<dyn PublicSigningKeyStore>,
        ttl: Duration,
        max_capacity: u64,
    ) -> Self {
        Self {
            cache: Cache::builder().time_to_live(ttl).max_capacity(max_capacity).build(),
            key_store,
            fallback: Cache::builder().max_capacity(max_capacity).build(),
        }
    }

    /// Gets the decoding key for JWT validation.
    ///
    /// Checks local cache first, then fetches from Ledger on miss.
    /// The key is validated for state (active, not revoked, within validity window)
    /// before being returned.
    ///
    /// # Graceful Degradation
    ///
    /// If Ledger is unavailable (connection or timeout errors), the cache will
    /// attempt to return a previously cached key from the fallback store. This
    /// ensures continued operation during transient outages.
    ///
    /// # Arguments
    ///
    /// * `org_id` - Organization ID (maps to Ledger namespace_id)
    /// * `kid` - Key ID from JWT header
    ///
    /// # Errors
    ///
    /// Returns error if:
    /// - Key not found in Ledger ([`AuthError::KeyNotFound`])
    /// - Key is inactive ([`AuthError::KeyInactive`])
    /// - Key has been revoked ([`AuthError::KeyRevoked`])
    /// - Key is not yet valid ([`AuthError::KeyNotYetValid`])
    /// - Key has expired ([`AuthError::KeyExpired`])
    /// - Public key format is invalid ([`AuthError::InvalidPublicKey`])
    /// - Storage backend error with no fallback available ([`AuthError::KeyStorageError`])
    pub async fn get_decoding_key(
        &self,
        org_id: NamespaceId,
        kid: &str,
    ) -> Result<Arc<DecodingKey>, AuthError> {
        let cache_key = format!("{org_id}:{kid}");

        // L1: Check local cache (TTL-based)
        if let Some(key) = self.cache.get(&cache_key).await {
            return Ok(key);
        }

        // L2: Fetch from Ledger (org_id == namespace_id)
        let namespace_id = org_id;
        let ledger_result = self.key_store.get_key(namespace_id, kid).await;

        match ledger_result {
            Ok(Some(public_key)) => {
                // Validate key state
                validate_key_state(&public_key)?;

                // Convert to DecodingKey
                let decoding_key = to_decoding_key(&public_key)?;
                let decoding_key = Arc::new(decoding_key);

                // Cache locally (both TTL cache and fallback)
                self.cache.insert(cache_key.clone(), decoding_key.clone()).await;
                self.fallback.insert(cache_key, decoding_key.clone()).await;

                tracing::debug!(namespace_id = %namespace_id, kid, "Cached signing key from Ledger");

                Ok(decoding_key)
            },
            Ok(None) => Err(AuthError::KeyNotFound { kid: kid.to_string() }),
            Err(storage_error) => {
                // Check if this is a transient error (connection/timeout)
                // where fallback is appropriate
                if is_transient_error(&storage_error)
                    && let Some(key) = self.fallback.get(&cache_key).await
                {
                    tracing::warn!(
                        namespace_id = %namespace_id,
                        kid,
                        error = %storage_error,
                        "Ledger unavailable, using fallback cached key"
                    );
                    return Ok(key);
                }

                // No fallback available or not a transient error
                Err(AuthError::KeyStorageError(storage_error))
            },
        }
    }

    /// Invalidates a specific key from all cache tiers.
    ///
    /// Removes the key from both the L1 TTL cache and the L3 fallback cache.
    /// Call this when a key is known to be revoked or deleted.
    /// The next lookup will fetch fresh state from Ledger.
    pub async fn invalidate(&self, org_id: NamespaceId, kid: &str) {
        let cache_key = format!("{org_id}:{kid}");
        self.cache.invalidate(&cache_key).await;
        self.fallback.invalidate(&cache_key).await;
        tracing::debug!(org_id = %org_id, kid = kid, "Invalidated signing key from all cache tiers");
    }

    /// Clears all keys from all cache tiers.
    ///
    /// Removes all entries from both the L1 TTL cache and the L3 fallback cache.
    /// Use sparingly - this causes a spike in Ledger fetches. Useful during
    /// key rotation events where all cached keys should be refreshed.
    pub async fn clear_all(&self) {
        let l1_count = self.cache.entry_count();
        let fallback_count = self.fallback.entry_count();
        self.cache.invalidate_all();
        self.fallback.invalidate_all();
        tracing::warn!(
            l1_cached_keys = l1_count,
            fallback_cached_keys = fallback_count,
            "Cleared all signing keys from all cache tiers"
        );
    }

    /// Returns current L1 cache entry count.
    ///
    /// Note: This count is eventually consistent. For accurate counts in tests,
    /// call `sync` first.
    #[must_use]
    pub fn entry_count(&self) -> u64 {
        self.cache.entry_count()
    }

    /// Returns current fallback cache entry count.
    ///
    /// Note: This count is eventually consistent. For accurate counts in tests,
    /// call `sync` first.
    #[must_use]
    pub fn fallback_entry_count(&self) -> u64 {
        self.fallback.entry_count()
    }

    /// Synchronizes pending cache operations.
    ///
    /// Call this before checking entry counts in tests to ensure
    /// all inserts and invalidations have been processed.
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    pub async fn sync(&self) {
        self.cache.run_pending_tasks().await;
        self.fallback.run_pending_tasks().await;
    }

    /// Clears only the L1 TTL cache, leaving the fallback cache intact.
    ///
    /// Used in tests to force a cache miss on L1 while preserving fallback
    /// entries for graceful degradation testing.
    #[cfg(test)]
    #[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
    pub async fn clear_l1(&self) {
        self.cache.invalidate_all();
    }
}

/// Determines if a storage error is transient (connection/timeout).
///
/// Transient errors indicate Ledger is temporarily unavailable but may recover.
/// For these errors, we attempt to use the fallback cache.
///
/// Non-transient errors (not found, serialization, internal) indicate a
/// definitive response from Ledger and should not use fallback.
fn is_transient_error(error: &StorageError) -> bool {
    matches!(error, StorageError::Connection { .. } | StorageError::Timeout)
}

/// Validates that a key is in a usable state.
///
/// A key is valid if:
/// - `active == true`
/// - `revoked_at.is_none()`
/// - `now >= valid_from`
/// - `valid_until.is_none() || now <= valid_until`
fn validate_key_state(key: &PublicSigningKey) -> Result<(), AuthError> {
    let now = Utc::now();

    if !key.active {
        return Err(AuthError::KeyInactive { kid: key.kid.clone() });
    }

    if key.revoked_at.is_some() {
        return Err(AuthError::KeyRevoked { kid: key.kid.clone() });
    }

    if now < key.valid_from {
        return Err(AuthError::KeyNotYetValid { kid: key.kid.clone() });
    }

    if let Some(valid_until) = key.valid_until
        && now > valid_until
    {
        return Err(AuthError::KeyExpired { kid: key.kid.clone() });
    }

    Ok(())
}

/// Converts a [`PublicSigningKey`] to a jsonwebtoken [`DecodingKey`].
///
/// The public key is expected to be base64url-encoded (no padding) Ed25519 key.
fn to_decoding_key(key: &PublicSigningKey) -> Result<DecodingKey, AuthError> {
    // Decode base64url public key into a Zeroizing wrapper to ensure
    // the raw key bytes are scrubbed from memory when dropped.
    let public_key_bytes: Zeroizing<Vec<u8>> = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(key.public_key.as_bytes())
            .map_err(|e| AuthError::InvalidPublicKey(format!("base64 decode: {e}")))?,
    );

    // Verify key length (Ed25519 public keys are 32 bytes)
    if public_key_bytes.len() != PUBLIC_KEY_LENGTH {
        return Err(AuthError::InvalidPublicKey(format!(
            "expected {PUBLIC_KEY_LENGTH} bytes, got {}",
            public_key_bytes.len()
        )));
    }

    // Validate it's a valid Ed25519 key by parsing it.
    // The fixed-size array is stack-allocated and zeroed when it goes out of scope
    // via the Zeroizing wrapper on the source Vec.
    let key_bytes: [u8; PUBLIC_KEY_LENGTH] = public_key_bytes[..PUBLIC_KEY_LENGTH]
        .try_into()
        .map_err(|_| AuthError::InvalidPublicKey("failed to convert bytes".to_string()))?;

    let _verifying_key = VerifyingKey::from_bytes(&key_bytes)
        .map_err(|e| AuthError::InvalidPublicKey(format!("invalid Ed25519 key: {e}")))?;

    // Convert to jsonwebtoken DecodingKey
    DecodingKey::from_ed_components(&key.public_key)
        .map_err(|e| AuthError::InvalidPublicKey(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use chrono::Duration as ChronoDuration;
    use ed25519_dalek::SigningKey;
    use inferadb_common_storage::{CertId, ClientId, auth::MemorySigningKeyStore};
    use rand_core::OsRng;

    use super::*;

    /// Generate a valid Ed25519 public key for testing.
    fn generate_test_public_key() -> String {
        let signing_key = SigningKey::generate(&mut OsRng);
        let verifying_key = signing_key.verifying_key();
        URL_SAFE_NO_PAD.encode(verifying_key.as_bytes())
    }

    fn create_test_key(kid: &str, active: bool) -> PublicSigningKey {
        PublicSigningKey {
            kid: kid.to_string(),
            public_key: generate_test_public_key().into(),
            client_id: ClientId::from(1),
            cert_id: CertId::from(1),
            created_at: Utc::now(),
            valid_from: Utc::now() - ChronoDuration::hours(1),
            valid_until: Some(Utc::now() + ChronoDuration::days(365)),
            active,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    fn create_valid_test_key(kid: &str) -> PublicSigningKey {
        create_test_key(kid, true)
    }

    #[tokio::test]
    async fn test_key_not_found() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(60));

        let result = cache.get_decoding_key(NamespaceId::from(1), "nonexistent").await;

        assert!(matches!(result, Err(AuthError::KeyNotFound { kid }) if kid == "nonexistent"));
    }

    #[tokio::test]
    async fn test_key_inactive() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_test_key("inactive-key", false);
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "inactive-key").await;

        assert!(matches!(result, Err(AuthError::KeyInactive { kid }) if kid == "inactive-key"));
    }

    #[tokio::test]
    async fn test_key_revoked() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("revoked-key", true);
        key.revoked_at = Some(Utc::now());
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;

        assert!(matches!(result, Err(AuthError::KeyRevoked { kid }) if kid == "revoked-key"));
    }

    #[tokio::test]
    async fn test_key_not_yet_valid() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("future-key", true);
        key.valid_from = Utc::now() + ChronoDuration::hours(1);
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "future-key").await;

        assert!(matches!(result, Err(AuthError::KeyNotYetValid { kid }) if kid == "future-key"));
    }

    #[tokio::test]
    async fn test_key_expired() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("expired-key", true);
        key.valid_from = Utc::now() - ChronoDuration::days(2);
        key.valid_until = Some(Utc::now() - ChronoDuration::days(1));
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "expired-key").await;

        assert!(matches!(result, Err(AuthError::KeyExpired { kid }) if kid == "expired-key"));
    }

    #[tokio::test]
    async fn test_invalid_public_key_format() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_test_key("bad-key", true);
        key.public_key = "not-valid-base64!!!".to_string().into();
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "bad-key").await;

        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }

    #[tokio::test]
    async fn test_cache_hit() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("cached-key");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call - cache miss
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "cached-key").await;
        assert!(result1.is_ok());

        // Second call - should hit cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "cached-key").await;
        assert!(result2.is_ok());

        // Entry should be in cache (sync to ensure count is accurate)
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);
    }

    #[tokio::test]
    async fn test_namespace_isolation() {
        let store = Arc::new(MemorySigningKeyStore::new());

        // Same kid, different namespaces
        let key1 = create_valid_test_key("shared-kid");
        let key2 = create_valid_test_key("shared-kid");
        store.create_key(NamespaceId::from(1), &key1).await.expect("create_key org1");
        store.create_key(NamespaceId::from(2), &key2).await.expect("create_key org2");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Both should work independently
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "shared-kid").await;
        let result2 = cache.get_decoding_key(NamespaceId::from(2), "shared-kid").await;

        assert!(result1.is_ok());
        assert!(result2.is_ok());

        cache.sync().await;
        assert_eq!(cache.entry_count(), 2);
    }

    #[tokio::test]
    async fn test_invalidate() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let key = create_valid_test_key("to-invalidate");
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate cache
        let _ = cache.get_decoding_key(NamespaceId::from(1), "to-invalidate").await;
        cache.sync().await;
        assert_eq!(cache.entry_count(), 1);

        // Invalidate
        cache.invalidate(NamespaceId::from(1), "to-invalidate").await;

        // Cache should be empty after invalidation
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0);
    }

    #[tokio::test]
    async fn test_clear_all() {
        let store = Arc::new(MemorySigningKeyStore::new());

        for i in 0..5 {
            let key = create_valid_test_key(&format!("key-{i}"));
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
        }

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate cache
        for i in 0..5 {
            let _ = cache.get_decoding_key(NamespaceId::from(1), &format!("key-{i}")).await;
        }
        cache.sync().await;
        assert_eq!(cache.entry_count(), 5);
        assert_eq!(cache.fallback_entry_count(), 5);

        // Clear all tiers
        cache.clear_all().await;

        // Both L1 and fallback should be empty
        cache.sync().await;
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.fallback_entry_count(), 0);
    }

    #[tokio::test]
    async fn test_key_no_expiry() {
        let store = Arc::new(MemorySigningKeyStore::new());
        let mut key = create_valid_test_key("no-expiry");
        key.valid_until = None; // No expiry
        store.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        let result = cache.get_decoding_key(NamespaceId::from(1), "no-expiry").await;

        assert!(result.is_ok());
    }

    #[test]
    fn test_validate_key_state_active() {
        let key = create_test_key("active", true);
        assert!(validate_key_state(&key).is_ok());
    }

    #[test]
    fn test_validate_key_state_inactive() {
        let key = create_test_key("inactive", false);
        let result = validate_key_state(&key);
        assert!(matches!(result, Err(AuthError::KeyInactive { .. })));
    }

    #[test]
    fn test_validate_key_state_revoked() {
        let mut key = create_test_key("revoked", true);
        key.revoked_at = Some(Utc::now());
        let result = validate_key_state(&key);
        assert!(matches!(result, Err(AuthError::KeyRevoked { .. })));
    }

    #[test]
    fn test_validate_key_state_not_yet_valid() {
        let mut key = create_test_key("future", true);
        key.valid_from = Utc::now() + ChronoDuration::hours(1);
        let result = validate_key_state(&key);
        assert!(matches!(result, Err(AuthError::KeyNotYetValid { .. })));
    }

    #[test]
    fn test_validate_key_state_expired() {
        let mut key = create_test_key("expired", true);
        key.valid_from = Utc::now() - ChronoDuration::days(2);
        key.valid_until = Some(Utc::now() - ChronoDuration::days(1));
        let result = validate_key_state(&key);
        assert!(matches!(result, Err(AuthError::KeyExpired { .. })));
    }

    #[test]
    fn test_to_decoding_key_invalid_base64() {
        let mut key = create_test_key("bad", true);
        key.public_key = "not-valid!!!".to_string().into();
        let result = to_decoding_key(&key);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }

    #[test]
    fn test_to_decoding_key_wrong_length() {
        let mut key = create_test_key("short", true);
        key.public_key = "AAAA".to_string().into(); // Too short
        let result = to_decoding_key(&key);
        assert!(matches!(result, Err(AuthError::InvalidPublicKey(_))));
    }

    // ========== Fallback/Graceful Degradation Tests ==========

    /// Mock store that can be configured to fail with specific errors.
    struct FailingStore {
        inner: Arc<MemorySigningKeyStore>,
        fail_with: std::sync::Mutex<Option<StorageError>>,
    }

    impl FailingStore {
        fn new() -> Self {
            Self {
                inner: Arc::new(MemorySigningKeyStore::new()),
                fail_with: std::sync::Mutex::new(None),
            }
        }

        fn set_failure(&self, error: Option<StorageError>) {
            *self.fail_with.lock().expect("lock") = error;
        }
    }

    #[async_trait::async_trait]
    impl PublicSigningKeyStore for FailingStore {
        async fn create_key(
            &self,
            namespace_id: NamespaceId,
            key: &PublicSigningKey,
        ) -> Result<(), StorageError> {
            self.inner.create_key(namespace_id, key).await
        }

        async fn get_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<Option<PublicSigningKey>, StorageError> {
            if let Some(ref error) = *self.fail_with.lock().expect("lock") {
                return Err(match error {
                    StorageError::Connection { message, .. } => StorageError::connection(message),
                    StorageError::Timeout => StorageError::timeout(),
                    StorageError::NotFound { key, .. } => StorageError::not_found(key),
                    StorageError::Internal { message, .. } => StorageError::internal(message),
                    _ => StorageError::internal("unknown"),
                });
            }
            self.inner.get_key(namespace_id, kid).await
        }

        async fn list_active_keys(
            &self,
            namespace_id: NamespaceId,
        ) -> Result<Vec<PublicSigningKey>, StorageError> {
            self.inner.list_active_keys(namespace_id).await
        }

        async fn deactivate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.deactivate_key(namespace_id, kid).await
        }

        async fn revoke_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
            reason: Option<&str>,
        ) -> Result<(), StorageError> {
            self.inner.revoke_key(namespace_id, kid, reason).await
        }

        async fn activate_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.activate_key(namespace_id, kid).await
        }

        async fn delete_key(
            &self,
            namespace_id: NamespaceId,
            kid: &str,
        ) -> Result<(), StorageError> {
            self.inner.delete_key(namespace_id, kid).await
        }
    }

    #[tokio::test]
    async fn test_fallback_on_connection_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("fallback-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "fallback-key").await;
        assert!(result1.is_ok());

        // Simulate Ledger connection failure
        store.set_failure(Some(StorageError::connection("network error")));

        // Clear only L1 cache to force Ledger lookup (fallback remains)
        cache.clear_l1().await;
        cache.sync().await;

        // Should use fallback cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "fallback-key").await;
        assert!(result2.is_ok(), "should use fallback on connection error");
    }

    #[tokio::test]
    async fn test_fallback_on_timeout_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("timeout-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "timeout-key").await;
        assert!(result1.is_ok());

        // Simulate Ledger timeout
        store.set_failure(Some(StorageError::timeout()));

        // Clear only L1 cache (fallback remains)
        cache.clear_l1().await;
        cache.sync().await;

        // Should use fallback cache
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "timeout-key").await;
        assert!(result2.is_ok(), "should use fallback on timeout error");
    }

    #[tokio::test]
    async fn test_no_fallback_on_non_transient_error() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("no-fallback-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // First call succeeds and populates both L1 and fallback
        let result1 = cache.get_decoding_key(NamespaceId::from(1), "no-fallback-key").await;
        assert!(result1.is_ok());

        // Simulate non-transient internal error (should NOT use fallback)
        store.set_failure(Some(StorageError::internal("db corruption")));

        // Clear only L1 cache (fallback remains, but should not be used for non-transient errors)
        cache.clear_l1().await;
        cache.sync().await;

        // Should NOT use fallback - internal errors are definitive responses
        let result2 = cache.get_decoding_key(NamespaceId::from(1), "no-fallback-key").await;
        assert!(
            matches!(result2, Err(AuthError::KeyStorageError(_))),
            "should NOT use fallback on internal error"
        );
    }

    #[tokio::test]
    async fn test_fallback_not_available_returns_error() {
        let store = Arc::new(FailingStore::new());

        // Don't create the key - fallback will be empty
        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Simulate connection failure with no prior cache
        store.set_failure(Some(StorageError::connection("network error")));

        // Should return error since no fallback available
        let result = cache.get_decoding_key(NamespaceId::from(1), "unknown-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError(_))),
            "should return error when no fallback available"
        );
    }

    #[test]
    fn test_is_transient_error_connection() {
        let error = StorageError::connection("network error");
        assert!(is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_timeout() {
        let error = StorageError::timeout();
        assert!(is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_not_found() {
        let error = StorageError::not_found("key");
        assert!(!is_transient_error(&error));
    }

    #[test]
    fn test_is_transient_error_internal() {
        let error = StorageError::internal("oops");
        assert!(!is_transient_error(&error));
    }

    #[tokio::test]
    async fn test_invalidate_removes_from_fallback() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("revoked-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate both L1 and fallback
        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Invalidate the key (simulating revocation)
        cache.invalidate(NamespaceId::from(1), "revoked-key").await;
        cache.sync().await;

        // Verify key is gone from both tiers
        assert_eq!(cache.entry_count(), 0);
        assert_eq!(cache.fallback_entry_count(), 0);

        // Simulate Ledger outage — the revoked key should NOT be served from fallback
        store.set_failure(Some(StorageError::connection("network error")));

        let result = cache.get_decoding_key(NamespaceId::from(1), "revoked-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError(_))),
            "invalidated key must not be returned from fallback"
        );
    }

    #[tokio::test]
    async fn test_clear_all_removes_from_fallback() {
        let store = Arc::new(FailingStore::new());
        let key = create_valid_test_key("rotation-key");
        store.inner.create_key(NamespaceId::from(1), &key).await.expect("create_key");

        let cache = SigningKeyCache::new(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
        );

        // Populate both tiers
        let result = cache.get_decoding_key(NamespaceId::from(1), "rotation-key").await;
        assert!(result.is_ok());
        cache.sync().await;
        assert_eq!(cache.fallback_entry_count(), 1);

        // Clear all tiers (key rotation event)
        cache.clear_all().await;
        cache.sync().await;

        // Verify fallback is also empty
        assert_eq!(cache.fallback_entry_count(), 0);

        // Simulate Ledger outage — no stale keys should be available
        store.set_failure(Some(StorageError::connection("network error")));

        let result = cache.get_decoding_key(NamespaceId::from(1), "rotation-key").await;
        assert!(
            matches!(result, Err(AuthError::KeyStorageError(_))),
            "cleared key must not be returned from fallback"
        );
    }

    #[tokio::test]
    async fn test_fallback_capacity_bounded() {
        let store = Arc::new(MemorySigningKeyStore::new());

        // Create a cache with capacity of 3
        let cache = SigningKeyCache::with_capacity(
            Arc::clone(&store) as Arc<dyn PublicSigningKeyStore>,
            Duration::from_secs(60),
            3,
        );

        // Insert 5 keys
        for i in 0..5 {
            let kid = format!("cap-key-{i}");
            let key = create_valid_test_key(&kid);
            store.create_key(NamespaceId::from(1), &key).await.expect("create_key");
            let _ = cache.get_decoding_key(NamespaceId::from(1), &kid).await;
        }
        cache.sync().await;

        // Fallback should be bounded — at most 3 entries
        assert!(
            cache.fallback_entry_count() <= 3,
            "fallback should not exceed capacity of 3, got {}",
            cache.fallback_entry_count()
        );
    }
}
