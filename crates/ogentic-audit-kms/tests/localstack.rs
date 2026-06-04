//! Hermetic AWS KMS integration tests against localstack.
//!
//! Activated by setting `OGENTIC_KMS_TEST_ENDPOINT=http://localhost:4566`.
//!
//! The CI workflow (`kms-integration.yml`) seeds two HMAC keys before these
//! tests run and injects `OGENTIC_KMS_TEST_KEY_A` + `OGENTIC_KMS_TEST_KEY_B`
//! as environment variables.
//!
//! All tests are `#[ignore]` so they never run in the standard `cargo test`
//! pass.  Run them explicitly with:
//!
//! ```text
//! OGENTIC_KMS_TEST_ENDPOINT=http://localhost:4566 \
//! OGENTIC_KMS_TEST_KEY_A=<arn> \
//! cargo test -p ogentic-audit-kms --features aws --tests -- --ignored localstack
//! ```

#![cfg(feature = "aws")]

use ogentic_audit_core::KeyHandle;
use ogentic_audit_kms::{AwsKmsProvider, KmsKey};

fn endpoint() -> Option<String> {
    std::env::var("OGENTIC_KMS_TEST_ENDPOINT").ok()
}

async fn make_client(ep: &str) -> aws_sdk_kms::Client {
    // aws-config 1.x API: defaults() builder with endpoint_url override and
    // static test credentials for localstack (no real IAM validation).
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(ep)
        .test_credentials()
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    aws_sdk_kms::Client::new(&cfg)
}

/// End-to-end MAC round-trip: signing the same message twice with the same
/// KMS key must produce identical MACs.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn localstack_generate_mac_roundtrip() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let arn = std::env::var("OGENTIC_KMS_TEST_KEY_A")
        .expect("OGENTIC_KMS_TEST_KEY_A must be set (seeded by CI)");

    let client = make_client(&ep).await;
    let provider = AwsKmsProvider::from_client(client, &arn);
    let key = KmsKey::new(provider).unwrap();

    let m1 = KeyHandle::sign(&key, b"audit-record-1");
    let m2 = KeyHandle::sign(&key, b"audit-record-1");
    assert_eq!(
        m1.as_bytes(),
        m2.as_bytes(),
        "signing the same message twice must produce the same MAC"
    );
}

/// `key_id` is deterministic across separate client instances pointed at
/// the same ARN — it derives from the descriptor, not from any SDK state.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn localstack_key_id_deterministic_across_clients() {
    let Some(ep) = endpoint() else {
        return;
    };
    let arn = std::env::var("OGENTIC_KMS_TEST_KEY_A").expect("seeded");

    let p1 = AwsKmsProvider::from_client(make_client(&ep).await, &arn);
    let p2 = AwsKmsProvider::from_client(make_client(&ep).await, &arn);
    let k1 = KmsKey::new(p1).unwrap();
    let k2 = KmsKey::new(p2).unwrap();
    assert_eq!(
        k1.key_id().as_bytes(),
        k2.key_id().as_bytes(),
        "key_id must be identical across two providers pointing at the same ARN"
    );
}

/// Per-org isolation: two distinct KMS keys (org A + org B) produce
/// DIFFERENT MACs for the SAME plaintext, and DIFFERENT `key_id`s. This is
/// the property that makes the "one tenant cannot forge another's audit
/// record" claim cryptographic, not just IAM-policy-shaped.
///
/// Uses both `OGENTIC_KMS_TEST_KEY_A` and `OGENTIC_KMS_TEST_KEY_B` seeded
/// by `kms-integration.yml`. Without this test, KEY_B would be unused
/// CI seeding overhead.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT + KEY_A + KEY_B; run in kms-integration CI job"]
async fn localstack_cross_key_mac_isolation() {
    let Some(ep) = endpoint() else {
        return;
    };
    let arn_a = std::env::var("OGENTIC_KMS_TEST_KEY_A").expect("KEY_A seeded by CI");
    let arn_b = std::env::var("OGENTIC_KMS_TEST_KEY_B").expect("KEY_B seeded by CI");

    let key_a = KmsKey::new(AwsKmsProvider::from_client(make_client(&ep).await, &arn_a)).unwrap();
    let key_b = KmsKey::new(AwsKmsProvider::from_client(make_client(&ep).await, &arn_b)).unwrap();

    // Distinct ARNs → distinct `key_id`s (BLAKE3 projection of the descriptor).
    assert_ne!(
        key_a.key_id().as_bytes(),
        key_b.key_id().as_bytes(),
        "two distinct KMS keys must project to distinct key_ids"
    );

    // Same plaintext, different keys → distinct MACs. This is the HMAC-SHA256
    // tenant-isolation property; the test proves the keys are genuinely
    // distinct in the HSM (not just distinct ARNs pointing at the same key).
    let mac_a = KeyHandle::sign(&key_a, b"the same plaintext payload");
    let mac_b = KeyHandle::sign(&key_b, b"the same plaintext payload");
    assert_ne!(
        mac_a.as_bytes(),
        mac_b.as_bytes(),
        "MAC of the same plaintext under two distinct KMS keys must differ"
    );
}

/// Real AWS smoke test — runs against actual AWS KMS using OIDC credentials
/// injected by the `kms-smoke.yml` workflow.
///
/// Only activated via `--ignored` + the filter `aws_smoke` in the smoke workflow.
#[tokio::test]
#[ignore = "requires real AWS credentials and OGENTIC_KMS_TEST_KEY_A; run via kms-smoke.yml"]
async fn aws_smoke_generate_mac() {
    let arn = std::env::var("OGENTIC_KMS_TEST_KEY_A").expect("OGENTIC_KMS_TEST_KEY_A must be set");
    let provider = AwsKmsProvider::from_arn(&arn)
        .await
        .expect("from_arn should succeed with valid credentials");
    let key = KmsKey::new(provider).unwrap();
    let mac = KeyHandle::sign(&key, b"aws-smoke-test-payload");
    assert_eq!(mac.as_bytes().len(), 32, "MAC must be 32 bytes");
}
