//! JWT validation and claims.
//!
//! This module provides types and functions for decoding and validating JWTs.
//!
//! # Example
//!
//! ```no_run
//! use inferadb_common_authn::jwt::{decode_jwt_claims, decode_jwt_header};
//!
//! # fn example(token: &str) -> Result<(), Box<dyn std::error::Error>> {
//! let header = decode_jwt_header(token)?;
//! let claims = decode_jwt_claims(token)?;
//!
//! println!("Algorithm: {:?}", header.alg);
//! println!("Organization: {:?}", claims.org_id);
//! # Ok(())
//! # }
//! ```

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::Utc;
use jsonwebtoken::{Algorithm, DecodingKey, Header, Validation, decode, decode_header};
use serde::{Deserialize, Serialize};

use crate::{error::AuthError, signing_key_cache::SigningKeyCache, validation::validate_algorithm};

/// JWT claims structure.
///
/// Per the Management API specification, JWTs should have the following structure:
///
/// ```json
/// {
///   "iss": "https://api.inferadb.com",
///   "sub": "client:<client_id>",
///   "aud": "https://api.inferadb.com/evaluate",
///   "exp": 1234567890,
///   "iat": 1234567800,
///   "org_id": "<organization_id>",
///   "vault_id": "<vault_id>",
///   "vault_role": "write",
///   "scope": "vault:read vault:write"
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct JwtClaims {
    /// Issuer - Should be the Management API URL (e.g., `https://api.inferadb.com`).
    pub iss: String,
    /// Subject - Client identifier (e.g., "client:<client_id>").
    pub sub: String,
    /// Audience - Target service (e.g., `https://api.inferadb.com/evaluate`).
    pub aud: String,
    /// Expiration time (seconds since epoch).
    pub exp: u64,
    /// Issued at (seconds since epoch).
    pub iat: u64,
    /// Not before (optional, seconds since epoch).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<u64>,
    /// JWT ID (optional).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Space-separated scopes (e.g., "vault:read vault:write").
    pub scope: String,
    /// Vault ID (Snowflake ID as string for multi-tenancy isolation).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vault_id: Option<String>,
    /// Organization ID (Snowflake ID as string - primary identifier per Management API spec).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub org_id: Option<String>,
}

impl JwtClaims {
    /// Require the organization ID from claims, returning an error if absent.
    ///
    /// Use this when the `org_id` claim is mandatory for the operation (e.g., JWT verification
    /// where the org ID is needed to look up the signing key). For optional access, use
    /// [`org_id`](Self::org_id) instead.
    ///
    /// # Returns
    ///
    /// The organization ID as a string.
    ///
    /// # Errors
    ///
    /// Returns `AuthError::MissingClaim` if the `org_id` claim is missing or empty.
    pub fn require_org_id(&self) -> Result<String, AuthError> {
        self.org_id
            .as_ref()
            .filter(|id| !id.is_empty())
            .cloned()
            .ok_or_else(|| AuthError::MissingClaim("org_id".into()))
    }

    /// Parse scopes from space-separated string.
    #[must_use]
    pub fn parse_scopes(&self) -> Vec<String> {
        self.scope.split_whitespace().map(|s| s.to_string()).collect()
    }

    /// Extract vault ID (Snowflake ID) from claims.
    ///
    /// Returns None if not present.
    #[must_use]
    pub fn extract_vault_id(&self) -> Option<String> {
        self.vault_id.clone()
    }

    /// Get the organization ID from claims, if present.
    ///
    /// Returns the raw `org_id` claim value without validation. Use
    /// [`require_org_id`](Self::require_org_id) when the org ID is mandatory and you want an
    /// error on absence.
    #[must_use]
    pub fn org_id(&self) -> Option<String> {
        self.org_id.clone()
    }
}

/// Decode JWT header without verification.
///
/// # Errors
///
/// Returns an error if the JWT header cannot be decoded.
pub fn decode_jwt_header(token: &str) -> Result<Header, AuthError> {
    decode_header(token)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to decode JWT header: {}", e)))
}

/// Decode JWT claims without verification (used to extract issuer for key lookup).
///
/// # Errors
///
/// Returns an error if:
/// - The JWT does not have exactly 3 parts
/// - The payload cannot be base64-decoded
/// - The payload cannot be parsed as JSON
/// - Required claims (iss, sub, aud) are empty
pub fn decode_jwt_claims(token: &str) -> Result<JwtClaims, AuthError> {
    // Split token into parts
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err(AuthError::InvalidTokenFormat(
            "JWT must have 3 parts separated by dots".into(),
        ));
    }

    // Decode payload (part 1) using base64 URL-safe encoding
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).map_err(|e| {
        AuthError::InvalidTokenFormat(format!("Failed to decode JWT payload: {}", e))
    })?;

    // Parse as JSON
    let claims: JwtClaims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| AuthError::InvalidTokenFormat(format!("Failed to parse JWT claims: {}", e)))?;

    // Validate required claims are present
    if claims.iss.is_empty() {
        return Err(AuthError::MissingClaim("iss".into()));
    }
    if claims.sub.is_empty() {
        return Err(AuthError::MissingClaim("sub".into()));
    }
    if claims.aud.is_empty() {
        return Err(AuthError::MissingClaim("aud".into()));
    }

    Ok(claims)
}

/// Validate JWT claims (timestamp and audience checks).
///
/// # Arguments
///
/// * `claims` - The JWT claims to validate
/// * `expected_audience` - Optional expected audience value
///
/// # Errors
///
/// Returns an error if:
/// - Token has expired
/// - Token is not yet valid (nbf in future)
/// - Issued-at is in the future
/// - Issued-at is too old (> 24 hours)
/// - Audience doesn't match expected value (if provided)
pub fn validate_claims(
    claims: &JwtClaims,
    expected_audience: Option<&str>,
) -> Result<(), AuthError> {
    let now = Utc::now().timestamp() as u64;

    // Check expiration
    if claims.exp <= now {
        return Err(AuthError::TokenExpired);
    }

    // Check not-before if present
    if let Some(nbf) = claims.nbf
        && nbf > now
    {
        return Err(AuthError::TokenNotYetValid);
    }

    // Check issued-at is reasonable (not too far in past, max 24 hours)
    if claims.iat > now {
        return Err(AuthError::InvalidTokenFormat("iat claim is in the future".into()));
    }
    if now - claims.iat > 86400 {
        // 24 hours
        return Err(AuthError::InvalidTokenFormat("iat claim is too old (> 24 hours)".into()));
    }

    // Check audience if enforced
    if let Some(expected) = expected_audience
        && claims.aud != expected
    {
        return Err(AuthError::InvalidAudience(format!(
            "expected '{}', got '{}'",
            expected, claims.aud
        )));
    }

    Ok(())
}

/// Verify JWT signature with a public key.
///
/// # Errors
///
/// Returns an error if signature verification fails.
pub fn verify_signature(
    token: &str,
    key: &DecodingKey,
    algorithm: Algorithm,
) -> Result<JwtClaims, AuthError> {
    let mut validation = Validation::new(algorithm);
    validation.validate_exp = true; // Validate token expiration
    validation.validate_nbf = false;
    validation.validate_aud = false;

    let token_data = decode::<JwtClaims>(token, key, &validation)?;

    Ok(token_data.claims)
}

/// Verify JWT signature using Ledger-backed signing key cache.
///
/// This function verifies JWTs using public signing keys fetched from Ledger:
/// 1. Decodes the JWT header to extract the key ID (`kid`) and algorithm
/// 2. Extracts the organization ID from the JWT claims
/// 3. Fetches the corresponding public key from the signing key cache (backed by Ledger)
/// 4. Verifies the JWT signature using the public key
///
/// This approach eliminates the need for JWKS endpoints and Control connectivity,
/// as signing keys are stored directly in Ledger.
///
/// # Arguments
///
/// * `token` - The JWT token to verify (as a string)
/// * `signing_key_cache` - The Ledger-backed signing key cache
///
/// # Returns
///
/// Returns the validated JWT claims if verification succeeds.
///
/// # Errors
///
/// Returns an error if:
/// - The JWT is malformed or missing required fields (`kid`, `org_id`)
/// - The algorithm is not in [`crate::validation::ACCEPTED_ALGORITHMS`] (only EdDSA)
/// - The key cannot be found in Ledger or is inactive/revoked/expired
/// - The signature is invalid
///
/// # Example
///
/// ```no_run
/// use inferadb_common_authn::jwt::verify_with_signing_key_cache;
/// use inferadb_common_authn::signing_key_cache::SigningKeyCache;
/// use inferadb_common_storage::auth::MemorySigningKeyStore;
/// use std::sync::Arc;
/// use std::time::Duration;
///
/// # async fn example() -> Result<(), Box<dyn std::error::Error>> {
/// // Setup signing key cache backed by Ledger
/// let store = Arc::new(MemorySigningKeyStore::new());
/// let cache = SigningKeyCache::new(store, Duration::from_secs(300));
///
/// // Verify a JWT using Ledger keys
/// let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSIsImtpZCI6Im9yZy0uLi4ifQ...";
/// let claims = verify_with_signing_key_cache(token, &cache).await?;
///
/// println!("Verified claims for organization: {}", claims.org_id.unwrap_or_default());
/// # Ok(())
/// # }
/// ```
pub async fn verify_with_signing_key_cache(
    token: &str,
    signing_key_cache: &SigningKeyCache,
) -> Result<JwtClaims, AuthError> {
    // 1. Decode header to get algorithm and key ID
    let header = decode_jwt_header(token)?;

    let kid = header
        .kid
        .ok_or_else(|| AuthError::InvalidTokenFormat("JWT header missing 'kid' field".into()))?;

    // Validate algorithm — only EdDSA is accepted (see ACCEPTED_ALGORITHMS)
    let alg_str = format!("{:?}", header.alg);
    validate_algorithm(&alg_str)?;

    // 2. Decode claims without verification to extract organization ID
    let claims = decode_jwt_claims(token)?;
    let org_id_str = claims.require_org_id()?;
    let org_id =
        inferadb_common_storage::NamespaceId::from(org_id_str.parse::<i64>().map_err(|_| {
            AuthError::InvalidTokenFormat(format!(
                "org_id '{}' is not a valid Snowflake ID",
                org_id_str
            ))
        })?);

    // 3. Get decoding key from signing key cache (fetches from Ledger on cache miss)
    let decoding_key = signing_key_cache.get_decoding_key(org_id, &kid).await.map_err(|e| {
        tracing::warn!(
            org_id = %org_id,
            kid = %kid,
            error = %e,
            "Failed to get signing key from Ledger"
        );
        // Convert signing key cache errors to appropriate auth errors
        e
    })?;

    // 4. Verify signature with the Ledger-backed key
    let verified_claims = verify_signature(token, &decoding_key, header.alg)?;

    tracing::debug!(
        org_id = %org_id,
        kid = %kid,
        "JWT verified using Ledger-backed signing key"
    );

    Ok(verified_claims)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod tests {
    use super::*;

    #[test]
    fn test_require_org_id_present() {
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some("987654321".into()),
        };

        assert_eq!(claims.require_org_id().unwrap(), "987654321");
    }

    #[test]
    fn test_require_org_id_missing() {
        let claims = JwtClaims {
            iss: "https://auth.example.com".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            vault_id: None,
            org_id: None,
        };

        assert!(claims.require_org_id().is_err());
    }

    #[test]
    fn test_require_org_id_empty() {
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some("".into()),
        };

        assert!(claims.require_org_id().is_err());
    }

    #[test]
    fn test_org_id_present() {
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some("987654321".into()),
        };

        assert_eq!(claims.org_id(), Some("987654321".to_owned()));
    }

    #[test]
    fn test_org_id_absent() {
        let claims = JwtClaims {
            iss: "https://auth.example.com".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check".into(),
            vault_id: None,
            org_id: None,
        };

        assert_eq!(claims.org_id(), None);
    }

    #[test]
    fn test_parse_scopes() {
        let claims = JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "inferadb.check inferadb.write inferadb.expand".into(),
            vault_id: None,
            org_id: None,
        };

        let scopes = claims.parse_scopes();
        assert_eq!(scopes.len(), 3);
        assert!(scopes.contains(&"inferadb.check".to_string()));
        assert!(scopes.contains(&"inferadb.write".to_string()));
        assert!(scopes.contains(&"inferadb.expand".to_string()));
    }

    #[test]
    fn test_parse_scopes_empty() {
        let claims = JwtClaims {
            iss: "tenant:acme".into(),
            sub: "test".into(),
            aud: "test".into(),
            exp: 1000000000,
            iat: 1000000000,
            nbf: None,
            jti: None,
            scope: "".into(),
            vault_id: None,
            org_id: None,
        };

        let scopes = claims.parse_scopes();
        assert_eq!(scopes.len(), 0);
    }

    #[test]
    fn test_decode_jwt_header_malformed() {
        let result = decode_jwt_header("not.a.jwt");
        assert!(result.is_err());
    }

    #[test]
    fn test_decode_jwt_claims_malformed_parts() {
        let result = decode_jwt_claims("only.two");
        assert!(result.is_err());

        let result = decode_jwt_claims("too.many.parts.here");
        assert!(result.is_err());
    }

    mod proptests {
        use proptest::prelude::*;

        use super::*;

        /// Strategy for generating valid `JwtClaims` instances with arbitrary field values.
        fn arb_jwt_claims() -> impl Strategy<Value = JwtClaims> {
            (
                "[a-zA-Z0-9:/._-]{1,64}",                                 // iss
                "[a-zA-Z0-9:_-]{1,64}",                                   // sub
                "[a-zA-Z0-9:/._-]{1,64}",                                 // aud
                1_000_000_000u64..2_000_000_000u64,                       // exp
                1_000_000_000u64..2_000_000_000u64,                       // iat
                proptest::option::of(1_000_000_000u64..2_000_000_000u64), // nbf
                proptest::option::of("[a-zA-Z0-9-]{1,64}"),               // jti
                "[a-z:_ ]{1,64}",                                         // scope
                proptest::option::of("[0-9]{1,20}"),                      // vault_id
                proptest::option::of("[0-9]{1,20}"),                      // org_id
            )
                .prop_map(
                    |(iss, sub, aud, exp, iat, nbf, jti, scope, vault_id, org_id)| JwtClaims {
                        iss,
                        sub,
                        aud,
                        exp,
                        iat,
                        nbf,
                        jti,
                        scope,
                        vault_id,
                        org_id,
                    },
                )
        }

        proptest! {
            /// Serializing then deserializing any valid `JwtClaims` must produce
            /// an identical struct.
            #[test]
            fn jwt_claims_serde_round_trip(claims in arb_jwt_claims()) {
                let json = serde_json::to_string(&claims).expect("serialize should succeed");
                let deserialized: JwtClaims =
                    serde_json::from_str(&json).expect("deserialize should succeed");
                prop_assert_eq!(deserialized, claims);
            }

            /// Serialized claims must always be valid JSON.
            #[test]
            fn jwt_claims_serialize_produces_valid_json(claims in arb_jwt_claims()) {
                let json = serde_json::to_string(&claims).expect("serialize should succeed");
                let parsed: serde_json::Value =
                    serde_json::from_str(&json).expect("output must be valid JSON");
                // Required fields must always be present
                prop_assert!(parsed.get("iss").is_some());
                prop_assert!(parsed.get("sub").is_some());
                prop_assert!(parsed.get("aud").is_some());
                prop_assert!(parsed.get("exp").is_some());
                prop_assert!(parsed.get("iat").is_some());
                prop_assert!(parsed.get("scope").is_some());
            }

            /// Optional fields with `skip_serializing_if = "Option::is_none"` must not
            /// appear in the JSON when they are `None`.
            #[test]
            fn jwt_claims_none_fields_omitted(claims in arb_jwt_claims()) {
                let json = serde_json::to_string(&claims).expect("serialize should succeed");
                let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid JSON");
                if claims.nbf.is_none() {
                    prop_assert!(parsed.get("nbf").is_none());
                }
                if claims.jti.is_none() {
                    prop_assert!(parsed.get("jti").is_none());
                }
                if claims.vault_id.is_none() {
                    prop_assert!(parsed.get("vault_id").is_none());
                }
                if claims.org_id.is_none() {
                    prop_assert!(parsed.get("org_id").is_none());
                }
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]
mod ledger_verification_tests {
    use std::{sync::Arc, time::Duration};

    use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
    use chrono::Utc;
    use ed25519_dalek::SigningKey;
    use inferadb_common_storage::{
        CertId, ClientId, NamespaceId,
        auth::{MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore},
    };
    use jsonwebtoken::{Algorithm, EncodingKey, Header};
    use rand_core::OsRng;

    use super::*;
    use crate::signing_key_cache::SigningKeyCache;

    /// Generate a test Ed25519 key pair and return (pkcs8_der, public_key_base64).
    fn generate_test_keypair() -> (Vec<u8>, String) {
        let signing_key = SigningKey::generate(&mut OsRng);
        let public_key_bytes = signing_key.verifying_key().to_bytes();
        let public_key_b64 = URL_SAFE_NO_PAD.encode(public_key_bytes);

        // Create PKCS#8 DER encoding for Ed25519 private key
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

    /// Create a JWT signed with the given PKCS#8 DER key.
    fn create_test_jwt(pkcs8_der: &[u8], kid: &str, org_id: &str) -> String {
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: Some("test-jti-12345".into()),
            scope: "vault:read vault:write".into(),
            vault_id: Some("123456789".into()),
            org_id: Some(org_id.into()),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());

        let encoding_key = EncodingKey::from_ed_der(pkcs8_der);
        jsonwebtoken::encode(&header, &claims, &encoding_key).expect("Failed to encode test JWT")
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_success() {
        // Generate key pair
        let (pkcs8_der, public_key_b64) = generate_test_keypair();
        let kid = "test-key-001";
        let org_id = NamespaceId::from(12345);

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

        // Register the public key
        let public_key = PublicSigningKey {
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
        store.create_key(org_id, &public_key).await.unwrap();

        // Create and verify JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let claims = verify_with_signing_key_cache(&token, &cache).await.unwrap();

        assert_eq!(claims.org_id, Some(org_id.to_string()));
        assert_eq!(claims.sub, "client:test-client");
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_key_not_found() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();
        let kid = "nonexistent-key";
        let org_id = NamespaceId::from(12345);

        // Create store and cache (without registering the key)
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::KeyNotFound { .. })));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_key_revoked() {
        // Generate key pair
        let (pkcs8_der, public_key_b64) = generate_test_keypair();
        let kid = "revoked-key";
        let org_id = NamespaceId::from(12345);

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store.clone(), Duration::from_secs(300));

        // Register a revoked key
        let public_key = PublicSigningKey {
            kid: kid.to_string(),
            public_key: public_key_b64.into(),
            client_id: ClientId::from(1),
            cert_id: CertId::from(1),
            created_at: Utc::now(),
            valid_from: Utc::now() - chrono::Duration::hours(1),
            valid_until: None,
            active: true,
            revoked_at: Some(Utc::now()),
            revocation_reason: None,
        };
        store.create_key(org_id, &public_key).await.unwrap();

        // Create JWT
        let token = create_test_jwt(&pkcs8_der, kid, &org_id.to_string());
        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::KeyRevoked { .. })));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_invalid_org_id() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();
        let kid = "test-key";

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT with non-numeric org_id
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: None,
            scope: "vault:read".into(),
            vault_id: None,
            org_id: Some("not-a-number".into()),
        };

        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(kid.to_string());

        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::InvalidTokenFormat(_))));
    }

    #[tokio::test]
    async fn test_verify_with_signing_key_cache_missing_kid() {
        // Generate key pair
        let (pkcs8_der, _) = generate_test_keypair();

        // Create store and cache
        let store = Arc::new(MemorySigningKeyStore::new());
        let cache = SigningKeyCache::new(store, Duration::from_secs(300));

        // Create JWT without kid
        let now = Utc::now().timestamp() as u64;
        let claims = JwtClaims {
            iss: "https://api.inferadb.com".into(),
            sub: "client:test-client".into(),
            aud: "https://api.inferadb.com/evaluate".into(),
            exp: now + 3600,
            iat: now,
            nbf: None,
            jti: None,
            scope: "vault:read".into(),
            vault_id: None,
            org_id: Some("12345".into()),
        };

        let header = Header::new(Algorithm::EdDSA); // No kid set
        let encoding_key = EncodingKey::from_ed_der(&pkcs8_der);
        let token = jsonwebtoken::encode(&header, &claims, &encoding_key).unwrap();

        let result = verify_with_signing_key_cache(&token, &cache).await;

        assert!(matches!(result, Err(AuthError::InvalidTokenFormat(_))));
    }
}
