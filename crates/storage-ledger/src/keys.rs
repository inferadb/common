//! Shared key encoding and decoding utilities for the Ledger storage backend.
//!
//! All Ledger backends use hexadecimal encoding for keys to preserve byte
//! ordering across Ledger's string-based entity key space. This module
//! provides the single canonical implementation used by both
//! [`LedgerBackend`](crate::LedgerBackend) and
//! [`LedgerTransaction`](crate::LedgerTransaction).

use crate::error::LedgerStorageError;

/// Encodes a key as a hexadecimal string.
///
/// This encoding preserves byte ordering, which is essential for
/// correct range scan behavior.
pub(crate) fn encode_key(key: &[u8]) -> String {
    hex::encode(key)
}

/// Decodes a hexadecimal key string back to bytes.
pub(crate) fn decode_key(key: &str) -> std::result::Result<Vec<u8>, LedgerStorageError> {
    hex::decode(key).map_err(|e| LedgerStorageError::KeyEncoding(e.to_string()))
}
