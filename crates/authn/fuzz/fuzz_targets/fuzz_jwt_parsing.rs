//! Fuzz target for JWT parsing and validation.
//!
//! Feeds arbitrary byte strings as JWT tokens to the parsing and validation
//! functions. The goal is to find inputs that cause panics, hangs, or
//! unexpected behavior — every result must be either `Ok(...)` or
//! `Err(AuthError)`.

#![no_main]

use libfuzzer_sys::fuzz_target;

use inferadb_common_authn::jwt::{decode_jwt_claims, decode_jwt_header, validate_claims};

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8 — JWT tokens are always UTF-8 strings
    let Ok(token) = std::str::from_utf8(data) else {
        return;
    };

    // Fuzz decode_jwt_header: must not panic on any input
    let header_result = decode_jwt_header(token);

    // Fuzz decode_jwt_claims: must not panic on any input
    let claims_result = decode_jwt_claims(token);

    // If claims decoded successfully, fuzz validate_claims with them
    if let Ok(ref claims) = claims_result {
        // Validate without audience enforcement
        let _ = validate_claims(claims, None);

        // Validate with a fixed audience
        let _ = validate_claims(claims, Some("https://api.inferadb.com/evaluate"));

        // Validate with an audience matching the token's audience
        let _ = validate_claims(claims, Some(&claims.aud));
    }

    // If header decoded, verify the algorithm string round-trips safely
    if let Ok(ref header) = header_result {
        let alg_str = format!("{:?}", header.alg);
        let _ = inferadb_common_authn::validate_algorithm(&alg_str);

        // If there's a kid, validate it
        if let Some(ref kid) = header.kid {
            let _ = inferadb_common_authn::validate_kid(kid);
        }
    }
});
