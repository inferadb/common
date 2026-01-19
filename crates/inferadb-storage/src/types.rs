//! Common types used across storage operations.
//!
//! This module defines shared data structures used by storage backends
//! and their consumers.

use bytes::Bytes;

/// A key-value pair returned from range queries.
///
/// This struct represents a single entry from the storage backend,
/// containing both the key and its associated value as byte sequences.
///
/// # Example
///
/// ```
/// use bytes::Bytes;
/// use inferadb_storage::KeyValue;
///
/// let kv = KeyValue {
///     key: Bytes::from("user:123"),
///     value: Bytes::from(r#"{"name":"Alice"}"#),
/// };
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyValue {
    /// The key identifying this entry.
    pub key: Bytes,

    /// The value stored at this key.
    pub value: Bytes,
}

impl KeyValue {
    /// Creates a new key-value pair.
    ///
    /// # Arguments
    ///
    /// * `key` - The key as a byte sequence
    /// * `value` - The value as a byte sequence
    ///
    /// # Example
    ///
    /// ```
    /// use bytes::Bytes;
    /// use inferadb_storage::KeyValue;
    ///
    /// let kv = KeyValue::new(Bytes::from("key"), Bytes::from("value"));
    /// ```
    pub fn new(key: Bytes, value: Bytes) -> Self {
        Self { key, value }
    }
}
