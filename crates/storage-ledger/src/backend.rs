//! Ledger-backed storage backend implementation.
//!
//! This module provides [`LedgerBackend`], which implements the
//! [`StorageBackend`](inferadb_common_storage::StorageBackend) trait using
//! the InferaDB Ledger SDK.

use std::{
    ops::{Bound, RangeBounds},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::Bytes;
use inferadb_common_storage::{
    KeyValue, NamespaceId, StorageBackend, StorageError, StorageResult, Transaction, VaultId,
};
use inferadb_ledger_sdk::{
    LedgerClient, ListEntitiesOpts, Operation, ReadConsistency, SetCondition,
};

use crate::{
    config::LedgerBackendConfig,
    error::{LedgerStorageError, Result},
    keys::{decode_key, encode_key},
    transaction::LedgerTransaction,
};

/// Returns the longest common prefix of two strings.
fn common_prefix(a: &str, b: &str) -> String {
    a.chars().zip(b.chars()).take_while(|(ca, cb)| ca == cb).map(|(c, _)| c).collect()
}

/// Ledger-backed implementation of [`StorageBackend`].
///
/// This backend uses the InferaDB Ledger SDK to provide durable, cryptographically
/// verifiable key-value storage. All operations are routed to a Ledger namespace
/// and optionally a vault for data isolation.
///
/// # Key Encoding
///
/// Keys are encoded as lowercase hexadecimal strings to:
/// - Preserve byte ordering for range scans
/// - Ensure compatibility with Ledger's string-based key format
/// - Support arbitrary binary keys
///
/// # Thread Safety
///
/// `LedgerBackend` is `Send + Sync` and can be safely shared across threads.
/// The underlying SDK client manages connection pooling internally.
///
/// # Example
///
/// ```no_run
/// use inferadb_common_storage_ledger::{
///     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
/// };
/// use inferadb_common_storage::StorageBackend;
///
/// #[tokio::main]
/// async fn main() -> Result<(), Box<dyn std::error::Error>> {
///     let client = ClientConfig::builder()
///         .servers(ServerSource::from_static(["http://localhost:50051"]))
///         .client_id("my-service")
///         .build()?;
///
///     let config = LedgerBackendConfig::builder()
///         .client(client)
///         .namespace_id(1)
///         .build();
///
///     let backend = LedgerBackend::new(config).await?;
///
///     // Basic operations
///     backend.set(b"key".to_vec(), b"value".to_vec()).await?;
///     let value = backend.get(b"key").await?;
///     assert_eq!(value, Some(bytes::Bytes::from("value")));
///
///     Ok(())
/// }
/// ```
#[derive(Clone)]
pub struct LedgerBackend {
    /// The underlying SDK client.
    client: Arc<LedgerClient>,

    /// Namespace ID for all operations.
    namespace_id: NamespaceId,

    /// Optional vault ID for scoped operations.
    vault_id: Option<VaultId>,

    /// Read consistency level.
    read_consistency: ReadConsistency,
}

impl std::fmt::Debug for LedgerBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LedgerBackend")
            .field("namespace_id", &self.namespace_id)
            .field("vault_id", &self.vault_id)
            .field("read_consistency", &self.read_consistency)
            .finish_non_exhaustive()
    }
}

impl LedgerBackend {
    /// Creates a new Ledger backend with the given configuration.
    ///
    /// This establishes a connection to the Ledger service and validates
    /// the configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - Configuration is invalid
    /// - Unable to connect to Ledger
    ///
    /// # Example
    ///
    /// ```no_run
    /// use inferadb_common_storage_ledger::{
    ///     ClientConfig, LedgerBackend, LedgerBackendConfig, ServerSource,
    /// };
    ///
    /// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
    /// let client = ClientConfig::builder()
    ///     .servers(ServerSource::from_static(["http://localhost:50051"]))
    ///     .client_id("my-service")
    ///     .build()?;
    ///
    /// let config = LedgerBackendConfig::builder()
    ///     .client(client)
    ///     .namespace_id(1)
    ///     .build();
    ///
    /// let backend = LedgerBackend::new(config).await?;
    /// # Ok(())
    /// # }
    /// ```
    pub async fn new(config: LedgerBackendConfig) -> Result<Self> {
        let namespace_id = config.namespace_id();
        let vault_id = config.vault_id();
        let read_consistency = config.read_consistency();

        let client = LedgerClient::new(config.into_client_config())
            .await
            .map_err(LedgerStorageError::from)?;

        Ok(Self { client: Arc::new(client), namespace_id, vault_id, read_consistency })
    }

    /// Creates a backend from an existing SDK client.
    ///
    /// This is useful when you want to share a client across multiple
    /// backend instances or when you need more control over client lifecycle.
    #[must_use]
    pub fn from_client(
        client: Arc<LedgerClient>,
        namespace_id: NamespaceId,
        vault_id: Option<VaultId>,
        read_consistency: ReadConsistency,
    ) -> Self {
        Self { client, namespace_id, vault_id, read_consistency }
    }

    /// Returns the namespace ID.
    #[must_use]
    pub fn namespace_id(&self) -> NamespaceId {
        self.namespace_id
    }

    /// Returns the vault ID if configured.
    #[must_use]
    pub fn vault_id(&self) -> Option<VaultId> {
        self.vault_id
    }

    /// Returns the underlying SDK client.
    #[must_use]
    pub fn client(&self) -> &LedgerClient {
        &self.client
    }

    /// Returns a cloned reference to the underlying SDK client.
    ///
    /// This is useful when you need to pass the client to other components
    /// that require ownership, such as `LedgerSigningKeyStore`.
    #[must_use]
    pub fn client_arc(&self) -> Arc<LedgerClient> {
        Arc::clone(&self.client)
    }

    /// Returns the namespace ID as a raw `i64` for SDK calls.
    fn ns_raw(&self) -> i64 {
        self.namespace_id.into()
    }

    /// Returns the vault ID as a raw `Option<i64>` for SDK calls.
    fn vault_raw(&self) -> Option<i64> {
        self.vault_id.map(Into::into)
    }

    /// Performs a read with the configured consistency level.
    async fn do_read(&self, key: &str) -> std::result::Result<Option<Vec<u8>>, LedgerStorageError> {
        let result = match self.read_consistency {
            ReadConsistency::Linearizable => {
                self.client.read_consistent(self.ns_raw(), self.vault_raw(), key).await
            },
            ReadConsistency::Eventual => {
                self.client.read(self.ns_raw(), self.vault_raw(), key).await
            },
        };

        result.map_err(LedgerStorageError::from)
    }

    /// Computes an absolute expiration timestamp by adding `ttl_seconds` to the
    /// current system time.
    ///
    /// Returns the number of seconds since the Unix epoch at which the key
    /// should expire.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the system clock is set before
    /// the Unix epoch.
    fn compute_expiration_timestamp(ttl_seconds: u64) -> StorageResult<u64> {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() + ttl_seconds)
            .map_err(|_| {
                StorageError::internal(
                    "system clock is before the Unix epoch; cannot compute expiration timestamp",
                )
            })
    }
}

#[async_trait]
impl StorageBackend for LedgerBackend {
    async fn get(&self, key: &[u8]) -> StorageResult<Option<Bytes>> {
        let encoded_key = encode_key(key);

        match self.do_read(&encoded_key).await {
            Ok(Some(value)) => Ok(Some(Bytes::from(value))),
            Ok(None) => Ok(None),
            Err(e) => Err(StorageError::from(e)),
        }
    }

    async fn set(&self, key: Vec<u8>, value: Vec<u8>) -> StorageResult<()> {
        let encoded_key = encode_key(&key);

        self.client
            .write(self.ns_raw(), self.vault_raw(), vec![Operation::set_entity(encoded_key, value)])
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        Ok(())
    }

    async fn compare_and_set(
        &self,
        key: &[u8],
        expected: Option<&[u8]>,
        new_value: Vec<u8>,
    ) -> StorageResult<()> {
        let encoded_key = encode_key(key);

        let condition = match expected {
            None => SetCondition::NotExists,
            Some(expected_value) => SetCondition::ValueEquals(expected_value.to_vec()),
        };

        use inferadb_ledger_sdk::SdkError;
        use tonic::Code;

        match self
            .client
            .write(
                self.ns_raw(),
                self.vault_raw(),
                vec![Operation::set_entity_if(encoded_key, new_value, condition)],
            )
            .await
        {
            Ok(_) => Ok(()),
            Err(SdkError::Rpc { code: Code::FailedPrecondition, .. }) => {
                Err(StorageError::Conflict)
            },
            Err(e) => Err(StorageError::from(LedgerStorageError::from(e))),
        }
    }

    async fn delete(&self, key: &[u8]) -> StorageResult<()> {
        let encoded_key = encode_key(key);

        self.client
            .write(self.ns_raw(), self.vault_raw(), vec![Operation::delete_entity(encoded_key)])
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        Ok(())
    }

    async fn get_range<R>(&self, range: R) -> StorageResult<Vec<KeyValue>>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        // Convert range bounds to hex-encoded strings
        let (start_key, start_inclusive) = match range.start_bound() {
            Bound::Included(k) => (Some(encode_key(k)), true),
            Bound::Excluded(k) => (Some(encode_key(k)), false),
            Bound::Unbounded => (None, true),
        };

        let (end_key, end_inclusive) = match range.end_bound() {
            Bound::Included(k) => (Some(encode_key(k)), true),
            Bound::Excluded(k) => (Some(encode_key(k)), false),
            Bound::Unbounded => (None, true),
        };

        // Find common prefix between start and end for efficient scanning.
        // For range queries, we use the longest common prefix of start and end
        // to minimize the number of entities returned by the server.
        let prefix = match (&start_key, &end_key) {
            (Some(start), Some(end)) => common_prefix(start, end),
            (Some(start), None) => start.clone(),
            (None, Some(end)) => common_prefix("", end),
            (None, None) => String::new(),
        };

        let opts = ListEntitiesOpts {
            key_prefix: prefix,
            at_height: None,
            include_expired: false,
            limit: 10000, // Reasonable page size
            page_token: None,
            consistency: self.read_consistency,
            vault_id: self.vault_raw(),
        };

        let result = self
            .client
            .list_entities(self.ns_raw(), opts)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        // Filter results to match exact range bounds
        let mut key_values = Vec::new();
        for entity in result.items {
            // Check start bound
            let after_start = match &start_key {
                Some(start) if start_inclusive => &entity.key >= start,
                Some(start) => &entity.key > start,
                None => true,
            };

            // Check end bound
            let before_end = match &end_key {
                Some(end) if end_inclusive => &entity.key <= end,
                Some(end) => &entity.key < end,
                None => true,
            };

            if after_start && before_end {
                match decode_key(&entity.key) {
                    Ok(key) => {
                        key_values.push(KeyValue {
                            key: Bytes::from(key),
                            value: Bytes::from(entity.value),
                        });
                    },
                    Err(e) => {
                        tracing::warn!(key = entity.key, "Failed to decode key: {}", e);
                        // Skip malformed keys
                    },
                }
            }
        }

        // Sort by key to ensure consistent ordering
        key_values.sort_by(|a, b| a.key.cmp(&b.key));

        Ok(key_values)
    }

    async fn clear_range<R>(&self, range: R) -> StorageResult<()>
    where
        R: RangeBounds<Vec<u8>> + Send,
    {
        // First, get all keys in the range
        let keys_to_delete = self.get_range(range).await?;

        if keys_to_delete.is_empty() {
            return Ok(());
        }

        // Build delete operations
        let operations: Vec<_> = keys_to_delete
            .into_iter()
            .map(|kv| Operation::delete_entity(encode_key(&kv.key)))
            .collect();

        // Execute as batch delete
        self.client
            .write(self.ns_raw(), self.vault_raw(), operations)
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        Ok(())
    }

    /// Stores a key-value pair with automatic expiration.
    ///
    /// Computes an absolute Unix timestamp by adding `ttl_seconds` to the
    /// current system time. The Ledger SDK's `set_entity_with_expiry`
    /// interprets this value as an absolute expiration timestamp in seconds
    /// since the Unix epoch.
    ///
    /// # Errors
    ///
    /// Returns [`StorageError::Internal`] if the system clock is set before
    /// the Unix epoch, since a valid absolute timestamp cannot be computed.
    async fn set_with_ttl(
        &self,
        key: Vec<u8>,
        value: Vec<u8>,
        ttl_seconds: u64,
    ) -> StorageResult<()> {
        let encoded_key = encode_key(&key);
        let expires_at = Self::compute_expiration_timestamp(ttl_seconds)?;

        self.client
            .write(
                self.ns_raw(),
                self.vault_raw(),
                vec![Operation::set_entity_with_expiry(encoded_key, value, expires_at)],
            )
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        Ok(())
    }

    async fn transaction(&self) -> StorageResult<Box<dyn Transaction>> {
        let txn = LedgerTransaction::new(
            Arc::clone(&self.client),
            self.namespace_id,
            self.vault_id,
            self.read_consistency,
        );
        Ok(Box::new(txn))
    }

    async fn health_check(&self) -> StorageResult<()> {
        // health_check() returns bool: true = healthy, false = degraded but available
        // It returns Err for unavailable
        self.client
            .health_check()
            .await
            .map_err(|e| StorageError::from(LedgerStorageError::from(e)))?;

        // If we get here, the service is either healthy or degraded (both are OK for this check)
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_key_encoding_roundtrip() {
        let original = b"hello world";
        let encoded = encode_key(original);
        let decoded = decode_key(&encoded).unwrap();

        assert_eq!(original.as_slice(), decoded.as_slice());
    }

    #[test]
    fn test_key_encoding_preserves_order() {
        let k1 = b"aaa";
        let k2 = b"aab";
        let k3 = b"bbb";

        let e1 = encode_key(k1);
        let e2 = encode_key(k2);
        let e3 = encode_key(k3);

        // Lexicographic ordering should be preserved
        assert!(e1 < e2);
        assert!(e2 < e3);
    }

    #[test]
    fn test_key_encoding_binary_keys() {
        // Test with binary data including null bytes
        let key = [0x00, 0x01, 0xFF, 0xFE, 0x00];
        let encoded = encode_key(&key);
        let decoded = decode_key(&encoded).unwrap();

        assert_eq!(&key[..], decoded.as_slice());
    }

    #[test]
    fn test_key_encoding_empty_key() {
        let key: &[u8] = b"";
        let encoded = encode_key(key);
        let decoded = decode_key(&encoded).unwrap();

        assert_eq!(key, decoded.as_slice());
    }

    #[test]
    fn test_decode_invalid_hex() {
        let result = decode_key("invalid-hex-gg");
        assert!(result.is_err());
    }

    #[test]
    fn test_common_prefix() {
        assert_eq!(common_prefix("abc", "abd"), "ab");
        assert_eq!(common_prefix("hello", "help"), "hel");
        assert_eq!(common_prefix("abc", "xyz"), "");
        assert_eq!(common_prefix("same", "same"), "same");
        assert_eq!(common_prefix("", "anything"), "");
        assert_eq!(common_prefix("anything", ""), "");
        assert_eq!(common_prefix("", ""), "");
    }

    #[test]
    fn test_expiration_timestamp_is_in_the_future() {
        let ttl_seconds = 300;
        let before =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        let expires_at = LedgerBackend::compute_expiration_timestamp(ttl_seconds).unwrap();

        let after =
            std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();

        // The expiration timestamp must be at least `before + ttl_seconds`
        // and at most `after + ttl_seconds` (accounting for wall-clock drift
        // between the two SystemTime::now() calls).
        assert!(
            expires_at >= before + ttl_seconds,
            "expiration {expires_at} should be >= {}",
            before + ttl_seconds,
        );
        assert!(
            expires_at <= after + ttl_seconds,
            "expiration {expires_at} should be <= {}",
            after + ttl_seconds,
        );
    }
}
