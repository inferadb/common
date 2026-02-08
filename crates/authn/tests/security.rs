//! Security-focused authentication tests.
//!
//! These tests verify the authentication pipeline's resistance to common JWT
//! attack vectors: algorithm substitution, algorithm confusion, expired/future
//! tokens, namespace isolation, key rotation during active use, and malformed
//! JWT structures.
#![allow(clippy::expect_used, clippy::panic)]

use std::{sync::Arc, time::Duration};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use ed25519_dalek::SigningKey;
use inferadb_common_authn::{
    error::AuthError,
    jwt::{
        DEFAULT_MAX_IAT_AGE, decode_jwt_claims, decode_jwt_header, validate_claims,
        verify_with_signing_key_cache,
    },
    signing_key_cache::SigningKeyCache,
    validation::validate_algorithm,
};
use inferadb_common_storage::{
    CertId, ClientId, NamespaceId,
    auth::{MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore},
};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rand_core::OsRng;
use serde_json::json;
use zeroize::Zeroizing;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Generate a test Ed25519 key pair and return (pkcs8_der, public_key_base64).
///
/// The private key material is wrapped in [`Zeroizing`] to ensure it is scrubbed
/// from memory on drop.
fn generate_test_keypair() -> (Zeroizing<Vec<u8>>, String) {
    let signing_key = SigningKey::generate(&mut OsRng);
    let public_key_bytes = signing_key.verifying_key().to_bytes();
    let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes);

    let private_bytes: Zeroizing<[u8; 32]> = Zeroizing::new(signing_key.to_bytes());
    let mut pkcs8_der = Zeroizing::new(vec![
        0x30, 0x2e, // SEQUENCE, 46 bytes
        0x02, 0x01, 0x00, // INTEGER version 0
        0x30, 0x05, // SEQUENCE, 5 bytes (algorithm identifier)
        0x06, 0x03, 0x2b, 0x65, 0x70, // OID 1.3.101.112 (Ed25519)
        0x04, 0x22, // OCTET STRING, 34 bytes
        0x04, 0x20, // OCTET STRING, 32 bytes (the actual key)
    ]);
    pkcs8_der.extend_from_slice(&*private_bytes);

    (pkcs8_der, public_key_b64)
}

/// Create a valid JWT signed with the given PKCS#8 DER key.
fn create_signed_jwt(pkcs8_der: &[u8], kid: &str, org_id: &str) -> String {
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

/// Create a raw JWT string from header and payload JSON (with a fake signature).
fn craft_raw_jwt(header_json: &serde_json::Value, payload_json: &serde_json::Value) -> String {
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(header_json).expect("header json"));
    let payload_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(payload_json).expect("payload json"));
    // Empty signature — this is intentional for testing rejection
    format!("{header_b64}.{payload_b64}.")
}

/// Register a valid active EdDSA signing key in the store.
async fn register_key(
    store: &Arc<MemorySigningKeyStore>,
    kid: &str,
    public_key_b64: &str,
    namespace: NamespaceId,
) {
    let key = PublicSigningKey {
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
    };
    store.create_key(namespace, &key).await.expect("Failed to register test key");
}

// ===========================================================================
// 1. Algorithm substitution: JWT with `alg: "none"` must be rejected
// ===========================================================================

#[test]
fn test_algorithm_none_rejected_before_key_lookup() {
    // Security property: the `none` algorithm must be rejected at the
    // algorithm validation layer, before any key lookup occurs.
    let result = validate_algorithm("none");
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
        "Expected 'none' to be rejected with security message, got: {result:?}"
    );
}

#[tokio::test]
async fn test_algorithm_none_jwt_rejected_end_to_end() {
    // Craft a JWT with alg: "none" and verify the full pipeline rejects it.
    let (_pkcs8_der, public_key_b64) = generate_test_keypair();
    let kid = "none-alg-key";
    let ns = NamespaceId::from(99999);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));
    register_key(&store, kid, &public_key_b64, ns).await;

    // Create a validly structured JWT but with alg: none
    let now = Utc::now().timestamp() as u64;
    let header = json!({"typ": "JWT", "alg": "none", "kid": kid});
    let payload = json!({
        "iss": "https://api.inferadb.com",
        "sub": "client:test-client",
        "aud": "https://api.inferadb.com/evaluate",
        "exp": now + 3600,
        "iat": now,
        "scope": "vault:read",
        "org_id": ns.to_string(),
    });
    let token = craft_raw_jwt(&header, &payload);

    let result = verify_with_signing_key_cache(&token, &cache).await;
    // The `jsonwebtoken` crate rejects `"none"` as an unknown algorithm variant
    // during header parsing, so the error surfaces as InvalidTokenFormat rather
    // than UnsupportedAlgorithm. Either rejection path is acceptable — the
    // security property is that the JWT never reaches key lookup or verification.
    assert!(
        matches!(
            &result,
            Err(AuthError::UnsupportedAlgorithm { .. }) | Err(AuthError::InvalidTokenFormat { .. })
        ),
        "Security: JWT with alg:'none' must be rejected, got: {result:?}"
    );
}

// ===========================================================================
// 2. Algorithm confusion: HS256 with EdDSA public key as HMAC secret
// ===========================================================================

#[test]
fn test_algorithm_confusion_hs256_rejected() {
    // Security property: HS256 is a symmetric algorithm and must be rejected
    // as forbidden, preventing the classic algorithm confusion attack where
    // an attacker signs a JWT using HMAC with the server's EdDSA public key
    // as the HMAC secret.
    let result = validate_algorithm("HS256");
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
        "Security: HS256 must be rejected as forbidden, got: {result:?}"
    );
}

#[test]
fn test_algorithm_confusion_hs384_rejected() {
    let result = validate_algorithm("HS384");
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
        "Security: HS384 must be rejected as forbidden, got: {result:?}"
    );
}

#[test]
fn test_algorithm_confusion_hs512_rejected() {
    let result = validate_algorithm("HS512");
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
        "Security: HS512 must be rejected as forbidden, got: {result:?}"
    );
}

#[tokio::test]
async fn test_algorithm_confusion_hs256_end_to_end() {
    // Simulate the algorithm confusion attack: craft a JWT with HS256 header
    // and sign it using the EdDSA public key as the HMAC secret.
    let (_pkcs8_der, public_key_b64) = generate_test_keypair();
    let kid = "confusion-key";
    let ns = NamespaceId::from(88888);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));
    register_key(&store, kid, &public_key_b64, ns).await;

    // Sign with HS256 using the public key bytes as HMAC secret
    let now = Utc::now().timestamp() as u64;
    let claims = json!({
        "iss": "https://api.inferadb.com",
        "sub": "client:test-client",
        "aud": "https://api.inferadb.com/evaluate",
        "exp": now + 3600,
        "iat": now,
        "scope": "vault:read",
        "org_id": ns.to_string(),
    });
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(kid.to_string());

    let public_key_bytes: Zeroizing<Vec<u8>> =
        Zeroizing::new(URL_SAFE_NO_PAD.decode(&public_key_b64).expect("decode public key"));
    let hmac_key = EncodingKey::from_secret(&public_key_bytes);
    let token =
        jsonwebtoken::encode(&header, &claims, &hmac_key).expect("Failed to encode HS256 JWT");

    let result = verify_with_signing_key_cache(&token, &cache).await;
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
        "Security: HS256-signed JWT must be rejected even with valid HMAC, got: {result:?}"
    );
}

// ===========================================================================
// 3. Expired token boundary test with 1-second granularity
// ===========================================================================

#[test]
fn test_token_expired_one_second_ago() {
    // Security property: a token that expired 1 second ago must be rejected.
    let now = Utc::now().timestamp() as u64;
    let claims = inferadb_common_authn::jwt::JwtClaims {
        iss: "https://api.inferadb.com".into(),
        sub: "client:test-client".into(),
        aud: "https://api.inferadb.com/evaluate".into(),
        exp: now - 1, // expired 1 second ago
        iat: now - 3600,
        nbf: None,
        jti: None,
        scope: "vault:read".into(),
        vault_id: None,
        org_id: Some("12345".into()),
    };
    let result = validate_claims(&claims, None, Some(DEFAULT_MAX_IAT_AGE));
    assert!(
        matches!(&result, Err(AuthError::TokenExpired { .. })),
        "Token expired 1 second ago must be rejected, got: {result:?}"
    );
}

#[test]
fn test_token_valid_one_second_from_now() {
    // A token that expires 1 second from now must still be accepted.
    let now = Utc::now().timestamp() as u64;
    let claims = inferadb_common_authn::jwt::JwtClaims {
        iss: "https://api.inferadb.com".into(),
        sub: "client:test-client".into(),
        aud: "https://api.inferadb.com/evaluate".into(),
        exp: now + 1, // expires in 1 second
        iat: now,
        nbf: None,
        jti: None,
        scope: "vault:read".into(),
        vault_id: None,
        org_id: Some("12345".into()),
    };
    let result = validate_claims(&claims, None, Some(DEFAULT_MAX_IAT_AGE));
    assert!(result.is_ok(), "Token expiring in 1 second must be accepted, got: {result:?}");
}

// ===========================================================================
// 4. Future `nbf` test confirms rejection
// ===========================================================================

#[test]
fn test_future_nbf_rejected() {
    // Security property: a token with nbf in the future must be rejected.
    let now = Utc::now().timestamp() as u64;
    let claims = inferadb_common_authn::jwt::JwtClaims {
        iss: "https://api.inferadb.com".into(),
        sub: "client:test-client".into(),
        aud: "https://api.inferadb.com/evaluate".into(),
        exp: now + 7200,
        iat: now,
        nbf: Some(now + 3600), // not valid for another hour
        jti: None,
        scope: "vault:read".into(),
        vault_id: None,
        org_id: Some("12345".into()),
    };
    let result = validate_claims(&claims, None, Some(DEFAULT_MAX_IAT_AGE));
    assert!(
        matches!(&result, Err(AuthError::TokenNotYetValid { .. })),
        "Token with future nbf must be rejected, got: {result:?}"
    );
}

#[test]
fn test_nbf_in_past_accepted() {
    // A token with nbf in the past should be accepted.
    let now = Utc::now().timestamp() as u64;
    let claims = inferadb_common_authn::jwt::JwtClaims {
        iss: "https://api.inferadb.com".into(),
        sub: "client:test-client".into(),
        aud: "https://api.inferadb.com/evaluate".into(),
        exp: now + 3600,
        iat: now,
        nbf: Some(now - 60), // was valid 60 seconds ago
        jti: None,
        scope: "vault:read".into(),
        vault_id: None,
        org_id: Some("12345".into()),
    };
    let result = validate_claims(&claims, None, Some(DEFAULT_MAX_IAT_AGE));
    assert!(result.is_ok(), "Token with past nbf must be accepted, got: {result:?}");
}

// ===========================================================================
// 5. Namespace isolation: key for namespace A must not validate in namespace B
// ===========================================================================

#[tokio::test]
async fn test_namespace_isolation_rejects_cross_namespace_key() {
    // Security property: a JWT signed with a key registered in namespace A
    // must NOT be verifiable when the JWT claims a different namespace (B).
    let (pkcs8_der, public_key_b64) = generate_test_keypair();
    let kid = "ns-isolation-key";
    let ns_a = NamespaceId::from(11111);
    let ns_b = NamespaceId::from(22222);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

    // Register key only in namespace A
    register_key(&store, kid, &public_key_b64, ns_a).await;

    // Create JWT claiming to be from namespace B
    let token = create_signed_jwt(&pkcs8_der, kid, &ns_b.to_string());

    let result = verify_with_signing_key_cache(&token, &cache).await;
    assert!(
        matches!(&result, Err(AuthError::KeyNotFound { .. })),
        "Security: key from namespace A must not validate JWT for namespace B, got: {result:?}"
    );
}

#[tokio::test]
async fn test_namespace_isolation_accepts_same_namespace() {
    // Positive control: JWT verified with a key from the same namespace succeeds.
    let (pkcs8_der, public_key_b64) = generate_test_keypair();
    let kid = "ns-same-key";
    let ns = NamespaceId::from(33333);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));
    register_key(&store, kid, &public_key_b64, ns).await;

    let token = create_signed_jwt(&pkcs8_der, kid, &ns.to_string());
    let result = verify_with_signing_key_cache(&token, &cache).await;
    assert!(result.is_ok(), "JWT with matching namespace must succeed, got: {result:?}");
}

// ===========================================================================
// 6. Key rotation: revoke old key, verify in-flight tokens rejected
// ===========================================================================

#[tokio::test]
async fn test_key_rotation_revoked_key_rejects_inflight_token() {
    // Security property: after a key is revoked, JWTs signed with that key
    // must be rejected, even if the JWT itself is not expired.
    let (pkcs8_der, public_key_b64) = generate_test_keypair();
    let kid = "rotation-old-key";
    let ns = NamespaceId::from(44444);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));
    register_key(&store, kid, &public_key_b64, ns).await;

    // Sign a valid JWT with the old key *before* revocation
    let token = create_signed_jwt(&pkcs8_der, kid, &ns.to_string());

    // Verify it works before revocation
    let before = verify_with_signing_key_cache(&token, &cache).await;
    assert!(before.is_ok(), "JWT must verify before key revocation, got: {before:?}");

    // Invalidate the cache entry so the revoked state is fetched fresh
    cache.invalidate(ns, kid).await;

    // Revoke the old key
    store.revoke_key(ns, kid, Some("key rotation")).await.expect("Failed to revoke key");

    // The in-flight token signed with the revoked key must now be rejected.
    // Note: revoke_key sets active=false AND revoked_at, and validate_key_state
    // checks active first, so KeyInactive fires before KeyRevoked. Both are
    // valid rejections for the security property being tested.
    let after = verify_with_signing_key_cache(&token, &cache).await;
    assert!(
        matches!(&after, Err(AuthError::KeyRevoked { .. }) | Err(AuthError::KeyInactive { .. })),
        "Security: JWT signed with revoked key must be rejected after revocation, got: {after:?}"
    );
}

#[tokio::test]
async fn test_key_rotation_new_key_works_after_old_revoked() {
    // After revoking old key and deploying new key, new JWTs should work.
    let (old_pkcs8, old_pub_b64) = generate_test_keypair();
    let (new_pkcs8, new_pub_b64) = generate_test_keypair();
    let old_kid = "rotate-old";
    let new_kid = "rotate-new";
    let ns = NamespaceId::from(55555);

    let store = Arc::new(MemorySigningKeyStore::new());
    let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

    // Register and then revoke old key
    register_key(&store, old_kid, &old_pub_b64, ns).await;
    store.revoke_key(ns, old_kid, Some("rotation")).await.expect("revoke old key");

    // Register new key
    register_key(&store, new_kid, &new_pub_b64, ns).await;

    // Old key JWT fails (KeyInactive or KeyRevoked — both are valid rejections)
    let old_token = create_signed_jwt(&old_pkcs8, old_kid, &ns.to_string());
    let old_result = verify_with_signing_key_cache(&old_token, &cache).await;
    assert!(
        matches!(
            &old_result,
            Err(AuthError::KeyRevoked { .. }) | Err(AuthError::KeyInactive { .. })
        ),
        "Old key JWT must be rejected, got: {old_result:?}"
    );

    // New key JWT succeeds
    let new_token = create_signed_jwt(&new_pkcs8, new_kid, &ns.to_string());
    let new_result = verify_with_signing_key_cache(&new_token, &cache).await;
    assert!(new_result.is_ok(), "New key JWT must succeed, got: {new_result:?}");
}

// ===========================================================================
// 7. Malformed JWT structure tests
// ===========================================================================

#[test]
fn test_malformed_jwt_missing_segments_one_part() {
    // Security property: a JWT with fewer than 3 parts must be rejected.
    let result = decode_jwt_claims("just-one-part");
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { message: msg, .. }) if msg.contains("3 parts")),
        "JWT with 1 part must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_missing_segments_two_parts() {
    let result = decode_jwt_claims("header.payload");
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { message: msg, .. }) if msg.contains("3 parts")),
        "JWT with 2 parts must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_extra_segments() {
    let result = decode_jwt_claims("a.b.c.d");
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { message: msg, .. }) if msg.contains("3 parts")),
        "JWT with 4 parts must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_invalid_base64url_payload() {
    // Valid header (base64url-encoded JSON), but payload is not valid base64url.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let token = format!("{header_b64}.!!!not-valid-base64!!!.signature");
    let result = decode_jwt_claims(&token);
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { message: msg, .. }) if msg.contains("decode")),
        "JWT with invalid base64url payload must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_payload_not_json() {
    // Valid base64url, but the decoded payload is not valid JSON.
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT"}"#);
    let payload_b64 = URL_SAFE_NO_PAD.encode(b"this is not json");
    let token = format!("{header_b64}.{payload_b64}.signature");
    let result = decode_jwt_claims(&token);
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { message: msg, .. }) if msg.contains("parse")),
        "JWT with non-JSON payload must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_empty_string() {
    let result = decode_jwt_claims("");
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { .. })),
        "Empty string JWT must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_header_decode_fails_garbage() {
    let result = decode_jwt_header("not.a.jwt");
    assert!(
        matches!(&result, Err(AuthError::InvalidTokenFormat { .. })),
        "Garbage JWT header must be rejected, got: {result:?}"
    );
}

#[test]
fn test_malformed_jwt_empty_signature() {
    // JWT with valid header and payload but completely empty signature segment
    let header_b64 = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"JWT","kid":"k1"}"#);
    let now = Utc::now().timestamp() as u64;
    let payload = json!({
        "iss": "https://api.inferadb.com",
        "sub": "client:test",
        "aud": "https://api.inferadb.com/evaluate",
        "exp": now + 3600,
        "iat": now,
        "scope": "vault:read",
        "org_id": "12345",
    });
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("json"));
    let token = format!("{header_b64}.{payload_b64}.");

    // The claims should be decodable (they're structurally valid)
    let claims_result = decode_jwt_claims(&token);
    assert!(
        claims_result.is_ok(),
        "Claims of structurally-valid JWT should decode, got: {claims_result:?}"
    );

    // But the header decode should work too (jsonwebtoken handles empty sig)
    let header_result = decode_jwt_header(&token);
    assert!(
        header_result.is_ok(),
        "Header of structurally-valid JWT should decode, got: {header_result:?}"
    );
}

// ===========================================================================
// Additional: RS256 (accepted-but-unsupported algorithm boundary) test
// ===========================================================================

#[test]
fn test_rs256_rejected_as_not_accepted() {
    // RS256 was removed from ACCEPTED_ALGORITHMS (it was listed but never
    // supported end-to-end). It should be rejected with a "not in accepted
    // list" message, distinct from the "not allowed for security reasons"
    // message used for forbidden algorithms.
    let result = validate_algorithm("RS256");
    assert!(
        matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not in accepted list")),
        "RS256 must be rejected as not-accepted (not forbidden), got: {result:?}"
    );
}

// ===========================================================================
// Additional: all forbidden algorithms each get a dedicated test
// ===========================================================================

#[test]
fn test_all_forbidden_algorithms_rejected_with_security_message() {
    let forbidden = ["none", "HS256", "HS384", "HS512"];
    for alg in &forbidden {
        let result = validate_algorithm(alg);
        assert!(
            matches!(&result, Err(AuthError::UnsupportedAlgorithm { message: msg, .. }) if msg.contains("not allowed for security reasons")),
            "Security: forbidden algorithm '{alg}' must be rejected with security message, got: {result:?}"
        );
    }
}
