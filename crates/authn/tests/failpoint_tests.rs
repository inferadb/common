#![allow(clippy::expect_used, clippy::panic)]
//! Integration tests for fail-point injection in the authn crate.
//!
//! These tests require both `failpoints` and `testutil` features:
//! ```bash
//! cargo test -p inferadb-common-authn --features failpoints,testutil --test failpoint_tests
//! ```

use std::sync::Arc;

use inferadb_common_authn::{SigningKeyCache, testutil::generate_test_keypair};
use inferadb_common_storage::{
    CertId, ClientId, OrganizationSlug,
    auth::{MemorySigningKeyStore, PublicSigningKey, PublicSigningKeyStore},
};

async fn setup_cache_with_key() -> (Arc<SigningKeyCache>, OrganizationSlug, String) {
    let store = Arc::new(MemorySigningKeyStore::new());
    let (_, public_key_b64) = generate_test_keypair();
    let org = OrganizationSlug::from(1);
    let kid = "fp-test-key";

    let key = PublicSigningKey::builder()
        .kid(kid)
        .public_key(public_key_b64.to_owned())
        .client_id(ClientId::from(1))
        .cert_id(CertId::from(1))
        .active(true)
        .valid_from(chrono::Utc::now())
        .build();

    store.create_key(org, &key).await.expect("failed to create key");

    let cache = SigningKeyCache::with_fallback_ttl(
        store,
        std::time::Duration::from_secs(300),
        1000,
        std::time::Duration::from_secs(600),
    );

    (Arc::new(cache), org, kid.to_owned())
}

#[tokio::test]
async fn cache_l2_fetch_failpoint_returns_error() {
    let scenario = fail::FailScenario::setup();
    let (cache, org, kid) = setup_cache_with_key().await;

    // Enable fail point — L2 fetch should fail
    fail::cfg("cache-before-l2-fetch", "return").expect("failed to configure fail point");

    let result = cache.get_decoding_key(org, &kid).await;
    assert!(result.is_err(), "L2 fetch should fail when fail point is active");

    scenario.teardown();
}

#[tokio::test]
async fn cache_l2_fetch_without_failpoint_succeeds() {
    let scenario = fail::FailScenario::setup();
    let (cache, org, kid) = setup_cache_with_key().await;

    // No fail point configured — L2 fetch should succeed
    let result = cache.get_decoding_key(org, &kid).await;
    assert!(result.is_ok(), "L2 fetch should succeed without fail point");

    scenario.teardown();
}
