//! Structured fuzz target for JWT claim parsing and validation.
//!
//! Uses the `arbitrary` crate to generate structured JWT-like inputs,
//! constructs base64-encoded JWT strings from them, and feeds them through
//! the parsing pipeline. This reaches deeper code paths than raw byte
//! fuzzing because the inputs are valid-ish JWTs with plausible structure.

#![no_main]

use arbitrary::Arbitrary;
use libfuzzer_sys::fuzz_target;

use inferadb_common_authn::jwt::{decode_jwt_claims, decode_jwt_header, validate_claims};

/// Structured input representing a fuzzed JWT.
///
/// The fuzzer generates arbitrary values for each field, which are then
/// assembled into a three-part JWT string (header.payload.signature).
#[derive(Debug, Arbitrary)]
struct FuzzedJwt {
    /// Algorithm string for the header
    alg: FuzzedAlg,
    /// Optional key ID in the header
    kid: Option<String>,
    /// Issuer claim
    iss: String,
    /// Subject claim
    sub: String,
    /// Audience claim
    aud: String,
    /// Expiration timestamp
    exp: u64,
    /// Issued-at timestamp
    iat: u64,
    /// Not-before timestamp (optional)
    nbf: Option<u64>,
    /// JWT ID (optional)
    jti: Option<String>,
    /// Scope string
    scope: String,
    /// Organization slug (optional)
    org: Option<String>,
    /// Vault slug (optional)
    vault: Option<String>,
    /// Extra arbitrary bytes appended to the signature segment
    signature_bytes: Vec<u8>,
    /// Whether to include a type field in the header
    include_typ: bool,
}

/// Fuzzed algorithm values covering known attack vectors and edge cases.
#[derive(Debug, Arbitrary)]
enum FuzzedAlg {
    /// Standard EdDSA
    EdDSA,
    /// Algorithm confusion attack: "none"
    None,
    /// Symmetric algorithm attack: HS256
    HS256,
    /// Symmetric algorithm attack: HS384
    HS384,
    /// Symmetric algorithm attack: HS512
    HS512,
    /// RSA algorithms
    RS256,
    RS384,
    RS512,
    /// ECDSA algorithms
    ES256,
    ES384,
    /// Arbitrary string
    Other(String),
}

impl FuzzedAlg {
    fn as_str(&self) -> &str {
        match self {
            Self::EdDSA => "EdDSA",
            Self::None => "none",
            Self::HS256 => "HS256",
            Self::HS384 => "HS384",
            Self::HS512 => "HS512",
            Self::RS256 => "RS256",
            Self::RS384 => "RS384",
            Self::RS512 => "RS512",
            Self::ES256 => "ES256",
            Self::ES384 => "ES384",
            Self::Other(s) => s,
        }
    }
}

/// Build a JWT string from the fuzzed input.
fn build_jwt(input: &FuzzedJwt) -> String {
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use base64::Engine;

    // Build header JSON
    let mut header = serde_json::Map::new();
    header.insert("alg".to_string(), serde_json::Value::String(input.alg.as_str().to_string()));
    if input.include_typ {
        header.insert("typ".to_string(), serde_json::Value::String("JWT".to_string()));
    }
    if let Some(ref kid) = input.kid {
        header.insert("kid".to_string(), serde_json::Value::String(kid.clone()));
    }

    // Build payload JSON
    let mut payload = serde_json::Map::new();
    payload.insert("iss".to_string(), serde_json::Value::String(input.iss.clone()));
    payload.insert("sub".to_string(), serde_json::Value::String(input.sub.clone()));
    payload.insert("aud".to_string(), serde_json::Value::String(input.aud.clone()));
    payload.insert(
        "exp".to_string(),
        serde_json::Value::Number(serde_json::Number::from(input.exp)),
    );
    payload.insert(
        "iat".to_string(),
        serde_json::Value::Number(serde_json::Number::from(input.iat)),
    );
    if let Some(nbf) = input.nbf {
        payload.insert("nbf".to_string(), serde_json::Value::Number(serde_json::Number::from(nbf)));
    }
    if let Some(ref jti) = input.jti {
        payload.insert("jti".to_string(), serde_json::Value::String(jti.clone()));
    }
    payload.insert("scope".to_string(), serde_json::Value::String(input.scope.clone()));
    if let Some(ref org) = input.org {
        payload.insert("org".to_string(), serde_json::Value::String(org.clone()));
    }
    if let Some(ref vault) = input.vault {
        payload.insert("vault".to_string(), serde_json::Value::String(vault.clone()));
    }

    let header_json = serde_json::Value::Object(header);
    let payload_json = serde_json::Value::Object(payload);

    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header_json).unwrap_or_default());
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload_json).unwrap_or_default());
    let sig_b64 = URL_SAFE_NO_PAD.encode(&input.signature_bytes);

    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

fuzz_target!(|input: FuzzedJwt| {
    let token = build_jwt(&input);

    // Fuzz decode_jwt_header: must not panic
    let header_result = decode_jwt_header(&token);

    // Fuzz decode_jwt_claims: must not panic
    let claims_result = decode_jwt_claims(&token);

    // If claims decoded, fuzz validate_claims
    if let Ok(ref claims) = claims_result {
        let _ = validate_claims(claims, None);
        let _ = validate_claims(claims, Some("https://api.inferadb.com/evaluate"));
        let _ = validate_claims(claims, Some(&claims.aud));
    }

    // Validate algorithm and kid if header decoded
    if let Ok(ref header) = header_result {
        let alg_str = format!("{:?}", header.alg);
        let _ = inferadb_common_authn::validate_algorithm(&alg_str);

        if let Some(ref kid) = header.kid {
            let _ = inferadb_common_authn::validate_kid(kid);
        }
    }
});
