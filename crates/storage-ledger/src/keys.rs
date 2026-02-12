//! Shared key encoding and decoding utilities for the Ledger storage backend.
//!
//! All Ledger backends use hexadecimal encoding for keys to preserve byte
//! ordering across Ledger's string-based entity key space. This module
//! provides the single canonical implementation used by both
//! [`LedgerBackend`](crate::LedgerBackend) and
//! [`LedgerTransaction`](crate::LedgerTransaction).

use crate::error::LedgerStorageError;

/// Encodes a key as a lowercase hex string.
///
/// This encoding preserves lexicographic byte ordering, which is critical
/// for correct range query behavior over Ledger's string-based key space.
pub(crate) fn encode_key(key: &[u8]) -> String {
    hex::encode(key)
}

/// Decodes a hex-encoded key string (case-insensitive) back to the original bytes.
///
/// # Errors
///
/// Returns [`LedgerStorageError::KeyEncoding`] if the input is not valid
/// hexadecimal.
pub(crate) fn decode_key(key: &str) -> std::result::Result<Vec<u8>, LedgerStorageError> {
    hex::decode(key).map_err(|e| LedgerStorageError::key_encoding(e.to_string()))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    proptest! {
        /// Encoding then decoding any byte sequence must produce the original bytes.
        #[test]
        fn encode_decode_round_trip(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
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
        fn encode_produces_valid_hex(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
            let encoded = encode_key(&bytes);
            prop_assert_eq!(encoded.len(), bytes.len() * 2);
            prop_assert!(encoded.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        }

        /// Different byte sequences must never produce the same encoded output (collision-free).
        #[test]
        fn encoding_is_collision_free(
            a in proptest::collection::vec(any::<u8>(), 0..256),
            b in proptest::collection::vec(any::<u8>(), 0..256),
        ) {
            prop_assume!(a != b);
            let enc_a = encode_key(&a);
            let enc_b = encode_key(&b);
            prop_assert_ne!(enc_a, enc_b, "different inputs must produce different encodings");
        }

        /// If `a` is a byte-prefix of `b`, then `encode(a)` is a string-prefix of `encode(b)`.
        /// This ensures that prefix-based range scans work correctly on encoded keys.
        #[test]
        fn encoding_preserves_prefix_relationship(
            prefix in proptest::collection::vec(any::<u8>(), 0..64),
            suffix in proptest::collection::vec(any::<u8>(), 1..64),
        ) {
            let mut extended = prefix.clone();
            extended.extend_from_slice(&suffix);

            let enc_prefix = encode_key(&prefix);
            let enc_extended = encode_key(&extended);

            prop_assert!(
                enc_extended.starts_with(&enc_prefix),
                "encoded extended key must start with encoded prefix"
            );
            // The extended key must be strictly longer.
            prop_assert!(enc_extended.len() > enc_prefix.len());
        }

        /// Decoding arbitrary (non-hex) strings must not panic — it should return an error.
        #[test]
        fn decode_rejects_invalid_input(s in "[^0-9a-fA-F]+") {
            let result = decode_key(&s);
            prop_assert!(result.is_err(), "non-hex input must produce an error");
        }

        /// Decoding odd-length hex strings must return an error (hex requires even length).
        #[test]
        fn decode_rejects_odd_length_hex(
            bytes in proptest::collection::vec(any::<u8>(), 1..128),
        ) {
            let encoded = encode_key(&bytes);
            // Truncate to odd length
            let truncated = &encoded[..encoded.len() - 1];
            let result = decode_key(truncated);
            prop_assert!(result.is_err(), "odd-length hex string must produce an error");
        }
    }

    // --- Explicit edge case tests ---

    #[test]
    fn empty_key_round_trip() {
        let empty: &[u8] = b"";
        let encoded = encode_key(empty);
        assert_eq!(encoded, "");
        let decoded = decode_key(&encoded).expect("empty hex decodes to empty bytes");
        assert!(decoded.is_empty());
    }

    #[test]
    fn all_zero_bytes_round_trip() {
        let zeros = [0u8; 32];
        let encoded = encode_key(&zeros);
        assert_eq!(encoded, "0".repeat(64));
        let decoded = decode_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded, zeros);
    }

    #[test]
    fn all_ff_bytes_round_trip() {
        let ffs = [0xFFu8; 32];
        let encoded = encode_key(&ffs);
        assert_eq!(encoded, "ff".repeat(32));
        let decoded = decode_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded, ffs);
    }

    #[test]
    fn single_byte_all_values() {
        for byte in 0..=255u8 {
            let encoded = encode_key(&[byte]);
            let decoded = decode_key(&encoded).expect("decode succeeds");
            assert_eq!(decoded, vec![byte]);
        }
    }

    #[test]
    fn maximum_length_key() {
        // Test with a large key (64 KiB — representative upper bound).
        let large_key: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let encoded = encode_key(&large_key);
        assert_eq!(encoded.len(), large_key.len() * 2);
        let decoded = decode_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded, large_key);
    }

    #[test]
    fn separator_like_bytes_in_key() {
        // Keys containing bytes that look like path separators (/, \, :, ., null)
        // should encode and decode without issue.
        let key = b"/path/../to/\x00key\\with:dots.ext";
        let encoded = encode_key(key);
        let decoded = decode_key(&encoded).expect("decode succeeds");
        assert_eq!(decoded, key);
    }
}
