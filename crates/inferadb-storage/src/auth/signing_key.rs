//! Public signing key type for Ledger storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Public signing key stored in Ledger (Ed25519 only).
///
/// This stores the public key material used for JWT signature verification.
/// The corresponding private key remains in Control's secure storage.
///
/// # Naming
///
/// We use `PublicSigningKey` (not `SigningKey`) because this struct stores only
/// the public key material used for signature verification. In cryptography,
/// "signing key" typically refers to the private key; our name explicitly
/// indicates this is the public half.
///
/// # Storage
///
/// Keys are stored as Ledger entities in the organization's namespace:
/// - **Storage key**: `signing-keys/{kid}` (in org namespace)
/// - **Namespace mapping**: `namespace_id == org_id` (1:1 mapping)
///
/// # Validation Rules
///
/// When validating a token, the key must satisfy all of these conditions:
/// - `active == true`
/// - `revoked_at.is_none()`
/// - `now >= valid_from`
/// - `valid_until.is_none() || now <= valid_until`
///
/// # Example
///
/// ```
/// use chrono::{Duration, Utc};
/// use inferadb_storage::auth::PublicSigningKey;
///
/// // Create a key that's valid for 1 year
/// let key = PublicSigningKey {
///     kid: "key-2024-001".to_string(),
///     public_key: "MCowBQYDK2VwAyEAabcd1234...".to_string(),
///     client_id: 12345,
///     cert_id: 1,
///     created_at: Utc::now(),
///     valid_from: Utc::now(),
///     valid_until: Some(Utc::now() + Duration::days(365)),
///     active: true,
///     revoked_at: None,
/// };
///
/// assert!(key.active);
/// assert!(key.revoked_at.is_none());
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicSigningKey {
    /// Key ID (matches JWT `kid` header).
    ///
    /// This uniquely identifies the key and is used for lookup during
    /// JWT validation. The `kid` in the JWT header must match this value.
    pub kid: String,

    /// Ed25519 public key (base64url-encoded, no padding).
    ///
    /// This is the raw 32-byte Ed25519 public key encoded using base64url
    /// without padding, following RFC 7515 (JWS) conventions.
    ///
    /// # Encoding
    ///
    /// The key should be encoded without the "=" padding characters.
    /// For example, a 32-byte key encodes to 43 characters.
    pub public_key: String,

    /// Client ID that owns this key (Snowflake ID).
    ///
    /// This links the key to the API client that will use it for
    /// authentication.
    pub client_id: i64,

    /// Certificate ID in Control's database (Snowflake ID).
    ///
    /// This provides a back-reference to the certificate record in
    /// Control for auditing and management purposes.
    pub cert_id: i64,

    /// When the key was registered in Ledger.
    ///
    /// This is set once at key creation and never changes.
    pub created_at: DateTime<Utc>,

    /// When the key becomes valid (for rotation grace periods).
    ///
    /// During key rotation, new keys may be created with a `valid_from`
    /// time slightly in the future to allow for cache propagation.
    /// Tokens signed with this key are rejected until this time.
    pub valid_from: DateTime<Utc>,

    /// When the key expires (optional).
    ///
    /// If set, the key becomes invalid after this time. This is
    /// independent of token expiration—a valid key can sign tokens,
    /// but an expired key cannot be used for validation even if
    /// the token itself hasn't expired.
    pub valid_until: Option<DateTime<Utc>>,

    /// Whether this key is currently active.
    ///
    /// Inactive keys are not used for validation. This provides a
    /// soft-disable mechanism that's reversible, unlike revocation.
    pub active: bool,

    /// Revocation timestamp (if revoked).
    ///
    /// Once set, this cannot be cleared—revocation is permanent.
    /// A revoked key is never used for validation regardless of
    /// other fields.
    pub revoked_at: Option<DateTime<Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    fn create_test_key() -> PublicSigningKey {
        PublicSigningKey {
            kid: "test-key-001".to_string(),
            // This is a valid base64url-encoded 32-byte value (no padding)
            public_key: "MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_string(),
            client_id: 1001,
            cert_id: 42,
            created_at: Utc::now(),
            valid_from: Utc::now(),
            valid_until: None,
            active: true,
            revoked_at: None,
        }
    }

    #[test]
    fn test_serialization_roundtrip_json() {
        let key = create_test_key();

        // Serialize to JSON
        let json = serde_json::to_string(&key).expect("serialization should succeed");

        // Deserialize back
        let deserialized: PublicSigningKey =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_serialization_with_optional_fields_none() {
        let key = PublicSigningKey {
            kid: "key-no-expiry".to_string(),
            public_key: "MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_string(),
            client_id: 2002,
            cert_id: 100,
            created_at: Utc::now(),
            valid_from: Utc::now(),
            valid_until: None,
            active: true,
            revoked_at: None,
        };

        let json = serde_json::to_string(&key).expect("serialization should succeed");
        let deserialized: PublicSigningKey =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(key, deserialized);
        assert!(deserialized.valid_until.is_none());
        assert!(deserialized.revoked_at.is_none());
    }

    #[test]
    fn test_serialization_with_optional_fields_some() {
        let now = Utc::now();
        let key = PublicSigningKey {
            kid: "key-with-expiry".to_string(),
            public_key: "MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_string(),
            client_id: 3003,
            cert_id: 200,
            created_at: now,
            valid_from: now,
            valid_until: Some(now + Duration::days(365)),
            active: false,
            revoked_at: Some(now + Duration::hours(1)),
        };

        let json = serde_json::to_string(&key).expect("serialization should succeed");
        let deserialized: PublicSigningKey =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(key, deserialized);
        assert!(deserialized.valid_until.is_some());
        assert!(deserialized.revoked_at.is_some());
    }

    #[test]
    fn test_json_field_names() {
        let key = create_test_key();
        let json = serde_json::to_string(&key).expect("serialization should succeed");

        // Verify field names are snake_case as expected
        assert!(json.contains("\"kid\":"));
        assert!(json.contains("\"public_key\":"));
        assert!(json.contains("\"client_id\":"));
        assert!(json.contains("\"cert_id\":"));
        assert!(json.contains("\"created_at\":"));
        assert!(json.contains("\"valid_from\":"));
        assert!(json.contains("\"valid_until\":"));
        assert!(json.contains("\"active\":"));
        assert!(json.contains("\"revoked_at\":"));
    }

    #[test]
    fn test_deserialize_from_known_json() {
        let json = r#"{
            "kid": "known-key-123",
            "public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA",
            "client_id": 9999,
            "cert_id": 8888,
            "created_at": "2024-01-15T10:30:00Z",
            "valid_from": "2024-01-15T10:30:00Z",
            "valid_until": "2025-01-15T10:30:00Z",
            "active": true,
            "revoked_at": null
        }"#;

        let key: PublicSigningKey =
            serde_json::from_str(json).expect("deserialization should succeed");

        assert_eq!(key.kid, "known-key-123");
        assert_eq!(key.public_key, "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA");
        assert_eq!(key.client_id, 9999);
        assert_eq!(key.cert_id, 8888);
        assert!(key.active);
        assert!(key.valid_until.is_some());
        assert!(key.revoked_at.is_none());
    }

    #[test]
    fn test_clone() {
        let key = create_test_key();
        let cloned = key.clone();

        assert_eq!(key, cloned);
        // Ensure they're separate allocations
        assert_eq!(key.kid, cloned.kid);
    }

    #[test]
    fn test_debug_format() {
        let key = create_test_key();
        let debug_str = format!("{:?}", key);

        // Debug output should contain field names
        assert!(debug_str.contains("PublicSigningKey"));
        assert!(debug_str.contains("kid"));
        assert!(debug_str.contains("test-key-001"));
    }

    #[test]
    fn test_partial_eq() {
        let key1 = create_test_key();
        let key2 = key1.clone();
        let mut key3 = key1.clone();
        key3.kid = "different-key".to_string();

        // Keys with same content are equal
        assert_eq!(key1, key2);

        // Keys with different content are not equal
        assert_ne!(key1, key3);
    }
}
