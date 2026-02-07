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

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Encoding then decoding any byte sequence must produce the original bytes.
        #[test]
        fn encode_decode_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let encoded = encode_key(&bytes);
            let decoded = decode_key(&encoded).expect("decode should succeed on valid hex");
            prop_assert_eq!(decoded, bytes);
        }

        /// Hex encoding must preserve byte ordering: if `a < b` lexicographically,
        /// then `encode(a) < encode(b)` as strings.
        #[test]
        fn encoding_preserves_ordering(
            a in proptest::collection::vec(any::<u8>(), 0..128),
            b in proptest::collection::vec(any::<u8>(), 0..128),
        ) {
            let enc_a = encode_key(&a);
            let enc_b = encode_key(&b);
            prop_assert_eq!(a.cmp(&b), enc_a.cmp(&enc_b));
        }

        /// Encoded output must always be valid lowercase hex and exactly 2x the input length.
        #[test]
        fn encode_produces_valid_hex(bytes in proptest::collection::vec(any::<u8>(), 0..256)) {
            let encoded = encode_key(&bytes);
            prop_assert_eq!(encoded.len(), bytes.len() * 2);
            prop_assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }
    }
}
