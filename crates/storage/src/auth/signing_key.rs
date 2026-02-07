//! Public signing key type for Ledger storage.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::types::{CertId, ClientId};

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
/// use inferadb_common_storage::auth::PublicSigningKey;
///
/// // Create a key with minimal required fields (defaults: active=true, valid times=now)
/// let key = PublicSigningKey::builder()
///     .kid("key-2024-001".to_owned())
///     .public_key("MCowBQYDK2VwAyEAabcd1234...".to_owned())
///     .client_id(12345)
///     .cert_id(1)
///     .build();
///
/// assert!(key.active);
/// assert!(key.revoked_at.is_none());
///
/// // Create a key with expiry
/// let key_with_expiry = PublicSigningKey::builder()
///     .kid("key-2024-002".to_owned())
///     .public_key("MCowBQYDK2VwAyEAabcd1234...".to_owned())
///     .client_id(12345)
///     .cert_id(2)
///     .valid_until(Utc::now() + Duration::days(365))
///     .build();
///
/// assert!(key_with_expiry.valid_until.is_some());
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize, bon::Builder)]
#[serde(deny_unknown_fields)]
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
    ///
    /// Wrapped in [`Zeroizing`] to ensure the key material is securely
    /// zeroed from memory when this struct is dropped.
    #[builder(into)]
    pub public_key: Zeroizing<String>,

    /// Client ID that owns this key (Snowflake ID).
    ///
    /// This links the key to the API client that will use it for
    /// authentication.
    #[builder(into)]
    pub client_id: ClientId,

    /// Certificate ID in Control's database (Snowflake ID).
    ///
    /// This provides a back-reference to the certificate record in
    /// Control for auditing and management purposes.
    #[builder(into)]
    pub cert_id: CertId,

    /// When the key was registered in Ledger.
    ///
    /// This is set once at key creation and never changes.
    #[builder(default = Utc::now())]
    pub created_at: DateTime<Utc>,

    /// When the key becomes valid (for rotation grace periods).
    ///
    /// During key rotation, new keys may be created with a `valid_from`
    /// time slightly in the future to allow for cache propagation.
    /// Tokens signed with this key are rejected until this time.
    #[builder(default = Utc::now())]
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
    #[builder(default = true)]
    pub active: bool,

    /// Revocation timestamp (if revoked).
    ///
    /// Once set, this cannot be cleared—revocation is permanent.
    /// A revoked key is never used for validation regardless of
    /// other fields.
    pub revoked_at: Option<DateTime<Utc>>,

    /// Reason for revocation (if revoked).
    ///
    /// Stores a human-readable reason for why the key was revoked
    /// (e.g., "compromised", "key rotation", "administrative action").
    /// This field is set alongside `revoked_at` during revocation and
    /// supports enterprise compliance requirements (SOC 2, ISO 27001)
    /// for auditable key lifecycle events.
    ///
    /// Uses `#[serde(default)]` for backward compatibility: existing
    /// stored keys without this field deserialize with `None`.
    #[serde(default)]
    pub revocation_reason: Option<String>,
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use chrono::Duration;

    use super::*;

    // ===== TDD Tests for bon::Builder =====

    #[test]
    fn test_public_signing_key_builder_minimal() {
        let key = PublicSigningKey::builder()
            .kid("test-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1001)
            .cert_id(42)
            .build();

        assert_eq!(key.kid, "test-key");
        assert_eq!(key.client_id, ClientId::from(1001));
        assert_eq!(key.cert_id, CertId::from(42));
        // Defaults
        assert!(key.active); // default true
        assert!(key.valid_until.is_none()); // default None
        assert!(key.revoked_at.is_none()); // default None
    }

    #[test]
    fn test_public_signing_key_builder_with_expiry() {
        let expiry = Utc::now() + Duration::days(365);
        let key = PublicSigningKey::builder()
            .kid("test-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1001)
            .cert_id(42)
            .valid_until(expiry)
            .build();

        assert_eq!(key.valid_until, Some(expiry));
    }

    #[test]
    fn test_public_signing_key_builder_inactive() {
        let key = PublicSigningKey::builder()
            .kid("test-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1001)
            .cert_id(42)
            .active(false)
            .build();

        assert!(!key.active);
    }

    #[test]
    fn test_public_signing_key_builder_with_revocation() {
        let revoked = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("test-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1001)
            .cert_id(42)
            .revoked_at(revoked)
            .revocation_reason("compromised".to_owned())
            .build();

        assert_eq!(key.revoked_at, Some(revoked));
        assert_eq!(key.revocation_reason.as_deref(), Some("compromised"));
    }

    #[test]
    fn test_public_signing_key_builder_all_fields() {
        let now = Utc::now();
        let expiry = now + Duration::days(365);
        let key = PublicSigningKey::builder()
            .kid("full-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAfull".to_owned())
            .client_id(5555)
            .cert_id(999)
            .created_at(now)
            .valid_from(now)
            .valid_until(expiry)
            .active(false)
            .revoked_at(now)
            .revocation_reason("key rotation".to_owned())
            .build();

        assert_eq!(key.kid, "full-key");
        assert_eq!(*key.public_key, "MCowBQYDK2VwAyEAfull");
        assert_eq!(key.client_id, ClientId::from(5555));
        assert_eq!(key.cert_id, CertId::from(999));
        assert_eq!(key.created_at, now);
        assert_eq!(key.valid_from, now);
        assert_eq!(key.valid_until, Some(expiry));
        assert!(!key.active);
        assert_eq!(key.revoked_at, Some(now));
        assert_eq!(key.revocation_reason.as_deref(), Some("key rotation"));
    }

    fn create_test_key() -> PublicSigningKey {
        PublicSigningKey::builder()
            .kid("test-key-001".to_owned())
            // This is a valid base64url-encoded 32-byte value (no padding)
            .public_key("MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_owned())
            .client_id(1001)
            .cert_id(42)
            .build()
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
        let key = PublicSigningKey::builder()
            .kid("key-no-expiry".to_owned())
            .public_key("MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_owned())
            .client_id(2002)
            .cert_id(100)
            .build();

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
        let key = PublicSigningKey::builder()
            .kid("key-with-expiry".to_owned())
            .public_key("MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_owned())
            .client_id(3003)
            .cert_id(200)
            .created_at(now)
            .valid_from(now)
            .valid_until(now + Duration::days(365))
            .active(false)
            .revoked_at(now + Duration::hours(1))
            .revocation_reason("compromised".to_owned())
            .build();

        let json = serde_json::to_string(&key).expect("serialization should succeed");
        let deserialized: PublicSigningKey =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(key, deserialized);
        assert!(deserialized.valid_until.is_some());
        assert!(deserialized.revoked_at.is_some());
        assert_eq!(deserialized.revocation_reason.as_deref(), Some("compromised"));
    }

    #[test]
    fn test_json_field_names() {
        let now = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("test-key-001".to_owned())
            .public_key("MCowBQYDK2VwAyEAabcdefghijklmnopqrstuvwxyz12".to_owned())
            .client_id(1001)
            .cert_id(42)
            .revoked_at(now)
            .revocation_reason("test".to_owned())
            .build();
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
        assert!(json.contains("\"revocation_reason\":"));
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
        assert_eq!(*key.public_key, "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA");
        assert_eq!(key.client_id, ClientId::from(9999));
        assert_eq!(key.cert_id, CertId::from(8888));
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

    #[test]
    fn test_backward_compatible_deserialization_without_revocation_reason() {
        // Simulate JSON from an older version that doesn't have the revocation_reason field
        let json = r#"{
            "kid": "legacy-key-001",
            "public_key": "dGVzdC1wdWJsaWMta2V5LWJhc2U2NA",
            "client_id": 9999,
            "cert_id": 8888,
            "created_at": "2024-01-15T10:30:00Z",
            "valid_from": "2024-01-15T10:30:00Z",
            "valid_until": "2025-01-15T10:30:00Z",
            "active": true,
            "revoked_at": null
        }"#;

        let key: PublicSigningKey = serde_json::from_str(json)
            .expect("old JSON without revocation_reason should deserialize");

        assert_eq!(key.kid, "legacy-key-001");
        assert!(key.revocation_reason.is_none());
    }

    #[test]
    fn test_revocation_reason_serialization_roundtrip() {
        let now = Utc::now();
        let key = PublicSigningKey::builder()
            .kid("revoked-key".to_owned())
            .public_key("MCowBQYDK2VwAyEAtest".to_owned())
            .client_id(1001)
            .cert_id(42)
            .revoked_at(now)
            .revocation_reason("compromised - emergency rotation".to_owned())
            .build();

        let json = serde_json::to_string(&key).expect("serialization should succeed");
        let deserialized: PublicSigningKey =
            serde_json::from_str(&json).expect("deserialization should succeed");

        assert_eq!(
            deserialized.revocation_reason.as_deref(),
            Some("compromised - emergency rotation")
        );
        assert_eq!(key, deserialized);
    }

    #[test]
    fn test_revocation_reason_none_when_not_revoked() {
        let key = create_test_key();

        assert!(key.revoked_at.is_none());
        assert!(key.revocation_reason.is_none());
    }
}
