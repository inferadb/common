//! Shared test utilities for authentication testing.
//!
//! This module provides common helpers for generating Ed25519 key pairs,
//! creating signed JWTs, crafting raw JWT strings (for attack testing),
//! and building [`PublicSigningKey`] instances. It is feature-gated
//! behind `testutil` to prevent leaking into production builds.
//!
//! # Usage
//!
//! In integration tests, enable the feature in `Cargo.toml`:
//!
//! ```toml
//! [dev-dependencies]
//! inferadb-common-authn = { path = "../authn", features = ["testutil"] }
//! ```
//!
//! Then import helpers:
//!
//! ```no_run
//! // Requires the `testutil` feature to be enabled.
//! use inferadb_common_authn::testutil::{generate_test_keypair, create_signed_jwt};
//! ```

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use inferadb_common_storage::{CertId, ClientId, auth::PublicSigningKey};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand_core::OsRng;
use serde_json::json;

/// Generate a test Ed25519 key pair.
///
/// Returns `(pkcs8_der, public_key_base64url)` where:
/// - `pkcs8_der` is the private key in PKCS#8 DER format (suitable for
///   [`EncodingKey::from_ed_der`])
/// - `public_key_base64url` is the 32-byte public key encoded as base64url without padding
///   (suitable for [`PublicSigningKey::public_key`])
///
/// Each call generates a fresh random key pair.
pub fn generate_test_keypair() -> (Vec<u8>, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes);

    let private_bytes = signing_key.to_bytes();
    let mut pkcs8_der = vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ];
    pkcs8_der.extend_from_slice(&private_bytes);

    (pkcs8_der, public_key_b64)
}

/// Create a valid JWT signed with an Ed25519 key in PKCS#8 DER format.
///
/// The JWT contains standard claims (`iss`, `sub`, `aud`, `exp`, `iat`,
/// `scope`) and the given `org_id`. The `kid` header is set to the
/// provided value so the verifier can look up the correct public key.
///
/// The token expires in 1 hour from the current time.
///
/// # Panics
///
/// Panics if JWT encoding fails (should not happen with valid inputs).
pub fn create_signed_jwt(pkcs8_der: &[u8], kid: &str, org_id: &str) -> String {
    let now = Utc::now().timestamp() as u64;
    let claims = json!({
        "iss": "https://api.inferadb.com",
        "sub": "client:test-client",
        "aud": "https://api.inferadb.com/evaluate",
        "exp": now + 3600,
        "iat": now,
        "scope": "vault:read vault:write",
        "org_id": org_id,
    });

    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some(kid.to_string());

    let encoding_key = EncodingKey::from_ed_der(pkcs8_der);
    jsonwebtoken::encode(&header, &claims, &encoding_key).expect("Failed to encode test JWT")
}

/// Create a raw JWT string from arbitrary header and payload JSON.
///
/// The resulting JWT has the structure `{header_b64}.{payload_b64}.`
/// with an empty signature. This is useful for testing rejection of
/// malformed or attack JWTs (e.g., `alg: "none"`, algorithm confusion).
///
/// # Panics
///
/// Panics if JSON serialization fails.
pub fn craft_raw_jwt(header_json: &serde_json::Value, payload_json: &serde_json::Value) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).expect("header json"));
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload_json).expect("payload json"));
    format!("{header_b64}.{payload_b64}.")
}

/// Create a [`PublicSigningKey`] suitable for testing.
///
/// Generates a fresh Ed25519 key pair internally. The key is active,
/// not revoked, and valid from 1 hour ago with no expiry.
///
/// Returns `(pkcs8_der, signing_key)` where `pkcs8_der` can be used
/// with [`create_signed_jwt`] and `signing_key` can be registered in
/// a key store.
pub fn create_test_signing_key(kid: &str) -> (Vec<u8>, PublicSigningKey) {
    let (pkcs8_der, public_key_b64) = generate_test_keypair();
    let key = PublicSigningKey {
        kid: kid.to_string(),
        public_key: public_key_b64.into(),
        client_id: ClientId::from(1),
        cert_id: CertId::from(1),
        created_at: Utc::now(),
        valid_from: Utc::now() - chrono::Duration::hours(1),
        valid_until: None,
        active: true,
        revoked_at: None,
        revocation_reason: None,
    };
    (pkcs8_der, key)
}

/// Create a [`PublicSigningKey`] with a specific public key string.
///
/// This is useful when you already have a key pair and want to create
/// a `PublicSigningKey` that matches it. The key is active, not revoked,
/// and valid from 1 hour ago with no expiry.
pub fn create_test_signing_key_with_pubkey(kid: &str, public_key_b64: &str) -> PublicSigningKey {
    PublicSigningKey {
        kid: kid.to_string(),
        public_key: public_key_b64.to_owned().into(),
        client_id: ClientId::from(1),
        cert_id: CertId::from(1),
        created_at: Utc::now(),
        valid_from: Utc::now() - chrono::Duration::hours(1),
        valid_until: None,
        active: true,
        revoked_at: None,
        revocation_reason: None,
    }
}

#[cfg(test)]
#[allow(clippy::expect_used)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_test_keypair_produces_valid_key() {
        let (pkcs8_der, public_key_b64) = generate_test_keypair();
        // PKCS#8 DER for Ed25519 is 48 bytes (16 header + 32 key)
        assert_eq!(pkcs8_der.len(), 48);
        // Base64url of 32 bytes = 43 characters (no padding)
        assert_eq!(public_key_b64.len(), 43);
    }

    #[test]
    fn test_generate_test_keypair_unique() {
        let (_, pk1) = generate_test_keypair();
        let (_, pk2) = generate_test_keypair();
        assert_ne!(pk1, pk2, "each call should produce a unique key pair");
    }

    #[test]
    fn test_create_signed_jwt_produces_three_part_token() {
        let (pkcs8_der, _) = generate_test_keypair();
        let jwt = create_signed_jwt(&pkcs8_der, "kid-001", "org-test");
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "JWT should have header.payload.signature");
        assert!(!parts[2].is_empty(), "signature should not be empty");
    }

    #[test]
    fn test_craft_raw_jwt_format() {
        let header = json!({"alg": "none", "typ": "JWT"});
        let payload = json!({"sub": "test"});
        let jwt = craft_raw_jwt(&header, &payload);
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3);
        assert!(parts[2].is_empty(), "signature should be empty for raw JWTs");
    }

    #[test]
    fn test_create_test_signing_key_is_active() {
        let (_, key) = create_test_signing_key("test-kid");
        assert_eq!(key.kid, "test-kid");
        assert!(key.active);
        assert!(key.revoked_at.is_none());
        assert!(key.revocation_reason.is_none());
    }

    #[test]
    fn test_create_test_signing_key_with_pubkey() {
        let key = create_test_signing_key_with_pubkey("kid-002", "fake-pubkey-b64");
        assert_eq!(key.kid, "kid-002");
        assert_eq!(*key.public_key, "fake-pubkey-b64");
        assert!(key.active);
    }
}
