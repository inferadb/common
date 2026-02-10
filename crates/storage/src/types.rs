//! Common types used across storage operations.
//!
//! This module defines shared data structures used by storage backends
//! and their consumers.

use bytes::Bytes;

/// Key-value pair returned from range queries.
///
/// Contains the key and its associated value as byte sequences.
///
/// # Examples
///
/// ```
/// use bytes::Bytes;
/// use inferadb_common_storage::KeyValue;
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
    /// # Examples
    ///
    /// ```
    /// use bytes::Bytes;
    /// use inferadb_common_storage::KeyValue;
    ///
    /// let kv = KeyValue::new(Bytes::from("key"), Bytes::from("value"));
    /// ```
    pub fn new(key: Bytes, value: Bytes) -> Self {
        Self { key, value }
    }
}

/// Macro to define a newtype wrapper around `i64` with standard trait
/// implementations.
///
/// Each generated type:
/// - Is a transparent wrapper around `i64` (zero runtime cost)
/// - Derives `Copy`, `Clone`, `Debug`, `PartialEq`, `Eq`, `Hash`, `PartialOrd`, `Ord`
/// - Derives `Serialize` and `Deserialize` (transparent)
/// - Implements `From<i64>` and `Into<i64>` for SDK interop
/// - Implements `Display` that outputs the inner value
macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(
            Copy, Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord,
            serde::Serialize, serde::Deserialize,
        )]
        #[serde(transparent)]
        pub struct $name(pub i64);

        impl From<i64> for $name {
            fn from(value: i64) -> Self {
                Self(value)
            }
        }

        impl From<$name> for i64 {
            fn from(id: $name) -> Self {
                id.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "{}", self.0)
            }
        }
    };
}

define_id!(
    /// Namespace ID for data isolation in the Ledger.
    ///
    /// In InferaDB, namespaces map 1:1 to organizations. All storage
    /// operations are scoped to a namespace to ensure data isolation.
    ///
    /// This type wraps a raw `i64` (Snowflake ID) to prevent accidental
    /// misuse — passing a `VaultId` where a `NamespaceId` is expected
    /// is a compile-time error.
    ///
    /// # Examples
    ///
    /// ```
    /// use inferadb_common_storage::NamespaceId;
    ///
    /// let ns = NamespaceId::from(42);
    /// assert_eq!(i64::from(ns), 42);
    /// assert_eq!(ns.to_string(), "42");
    /// ```
    NamespaceId
);

define_id!(
    /// Vault ID for finer-grained data scoping within a namespace.
    ///
    /// Vaults represent blockchain chains within a Ledger namespace.
    /// When present, all key-value operations are scoped to the vault.
    ///
    /// # Examples
    ///
    /// ```
    /// use inferadb_common_storage::VaultId;
    ///
    /// let vault = VaultId::from(100);
    /// assert_eq!(i64::from(vault), 100);
    /// ```
    VaultId
);

define_id!(
    /// Client ID that owns a signing key (Snowflake ID).
    ///
    /// Links a [`PublicSigningKey`](crate::auth::PublicSigningKey) to the
    /// API client that will use it for authentication.
    ///
    /// # Examples
    ///
    /// ```
    /// use inferadb_common_storage::ClientId;
    ///
    /// let client = ClientId::from(12345);
    /// assert_eq!(i64::from(client), 12345);
    /// ```
    ClientId
);

define_id!(
    /// Certificate ID in Control's database (Snowflake ID).
    ///
    /// Provides a back-reference to the certificate record in Control
    /// for auditing and management purposes.
    ///
    /// # Examples
    ///
    /// ```
    /// use inferadb_common_storage::CertId;
    ///
    /// let cert = CertId::from(42);
    /// assert_eq!(i64::from(cert), 42);
    /// ```
    CertId
);
