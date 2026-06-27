//! Adversarial per-org isolation tests.
//!
//! These tests verify that using the wrong ARN (wrong key, wrong region,
//! wrong account, missing credentials) always surfaces as a structured
//! `KmsError`, never as a successful signing operation or a panic.
//!
//! All tests are `#[ignore]`-gated and require a running localstack instance.
//! Run via the `kms-integration.yml` CI job, which seeds two distinct HMAC
//! keys (`OGENTIC_KMS_TEST_KEY_A`, `OGENTIC_KMS_TEST_KEY_B`) and sets
//! `OGENTIC_KMS_TEST_ENDPOINT`.

#![cfg(feature = "aws")]

use ogentic_audit_kms::{AwsKmsProvider, KmsError, KmsProvider};

fn endpoint() -> Option<String> {
    std::env::var("OGENTIC_KMS_TEST_ENDPOINT").ok()
}

async fn make_client_with_ep(ep: &str) -> aws_sdk_kms::Client {
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(ep)
        .test_credentials()
        .region(aws_config::Region::new("us-east-1"))
        .load()
        .await;
    aws_sdk_kms::Client::new(&cfg)
}

/// Calling `sign` with a non-existent ARN in the same region must produce
/// `KmsError::KeyNotFound` or `KmsError::AccessDenied` (both are structured
/// errors, not an `Ok` with a wrong MAC, and not a panic).
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn org_isolation_wrong_arn_same_region() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let wrong_arn = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, wrong_arn);
    let result = provider.sign(b"isolation-test").await;
    assert!(
        result.is_err(),
        "signing with a non-existent ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound | KmsError::AccessDenied => {},
        other => panic!("expected KeyNotFound or AccessDenied for wrong ARN; got {other:?}"),
    }
}

/// Cross-region ARN — pointing at a key in a region the client is not
/// configured for must fail; the library must NOT silently route the request
/// to the wrong region.
///
/// LOCALSTACK LIMITATION: localstack KMS runs as a single endpoint and does
/// not validate region routing. With localstack as the test backend, this
/// test exercises the same code path as `org_isolation_wrong_arn_same_region`
/// — the request fails because no key with that ARN exists, not because of
/// region-mismatch routing. Real cross-region routing failure is exercised
/// by the `aws_smoke_*` tests in `localstack.rs`, which run against actual
/// AWS via `kms-smoke.yml`. The accepted-error set below is therefore a
/// superset that includes both the localstack KeyNotFound case and the
/// real-AWS region-routing failure modes.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn org_isolation_wrong_region() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    // Simulate a cross-region access by pointing at a non-existent key in a
    // different region prefix (localstack may surface this as KeyNotFound or
    // AccessDenied depending on its routing config).
    let cross_region_arn =
        "arn:aws:kms:eu-west-1:000000000000:key/00000000-0000-0000-0000-000000000001";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, cross_region_arn);
    let result = provider.sign(b"cross-region-test").await;
    assert!(
        result.is_err(),
        "signing with a cross-region ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound
        | KmsError::AccessDenied
        | KmsError::ServiceUnavailable
        | KmsError::Internal(_) => {},
        other => panic!("expected structured KmsError for cross-region ARN; got {other:?}"),
    }
}

/// Wrong account — access to another account's key is denied.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn org_isolation_wrong_account() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let wrong_account_arn =
        "arn:aws:kms:us-east-1:999999999999:key/00000000-0000-0000-0000-000000000002";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, wrong_account_arn);
    let result = provider.sign(b"wrong-account-test").await;
    assert!(
        result.is_err(),
        "signing with a wrong-account ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound | KmsError::AccessDenied | KmsError::Internal(_) => {},
        other => panic!("expected KeyNotFound or AccessDenied for wrong account; got {other:?}"),
    }
}

/// Missing / expired credentials — the call must fail with a structured error.
///
/// This test injects deliberately invalid static credentials to simulate a
/// missing/expired-credentials scenario without requiring any external
/// credential chain or env var.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn org_isolation_missing_creds() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let arn = std::env::var("OGENTIC_KMS_TEST_KEY_A")
        .unwrap_or_else(|_| "arn:aws:kms:us-east-1:000000000000:key/missing".into());

    // Build a client with deliberately invalid static credentials.
    // aws_config re-exports Credentials from aws-credential-types.
    use aws_config::SdkConfig;
    use aws_sdk_kms::config::Builder as KmsConfigBuilder;
    let creds = aws_sdk_kms::config::Credentials::new(
        "INVALID_ACCESS_KEY",
        "INVALID_SECRET_KEY",
        None,
        None,
        "adversarial-test",
    );
    let kms_cfg = KmsConfigBuilder::new()
        .credentials_provider(creds)
        .endpoint_url(&ep)
        .region(aws_sdk_kms::config::Region::new("us-east-1"))
        .behavior_version_latest()
        .build();
    let _ = SdkConfig::builder().build(); // silence unused-import warning
    let client = aws_sdk_kms::Client::from_conf(kms_cfg);
    let provider = AwsKmsProvider::from_client(client, &arn);
    let result = provider.sign(b"missing-creds-test").await;
    assert!(
        result.is_err(),
        "signing with invalid credentials must fail; got Ok"
    );
    // Localstack typically returns 403/AccessDenied for invalid credentials.
    match result.unwrap_err() {
        KmsError::AccessDenied
        | KmsError::ServiceUnavailable
        | KmsError::Config(_)
        | KmsError::Internal(_) => {},
        other => panic!("expected a structured KmsError for missing creds; got {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Envelope-mode adversarial variants (OGE-603 / v0.2)
//
// These mirror the four GenerateMac tests above but exercise
// `KmsProvider::envelope_unwrap` (backed by KMS `GenerateDataKey`).
// Org isolation is enforced through the IAM scope of `GenerateDataKey`:
// the KMS Decrypt/GenerateDataKey call is what is IAM-gated, not the
// subsequent local HMAC.
// ---------------------------------------------------------------------------

/// Envelope mode: wrong ARN → `envelope_unwrap` must return a structured error.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn envelope_org_isolation_wrong_arn_same_region() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let wrong_arn = "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000000";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, wrong_arn);
    let result = provider.envelope_unwrap().await;
    assert!(
        result.is_err(),
        "envelope_unwrap with a non-existent ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound | KmsError::AccessDenied => {},
        other => {
            panic!("expected KeyNotFound or AccessDenied for wrong ARN (envelope); got {other:?}")
        },
    }
}

/// Envelope mode: cross-region ARN → `envelope_unwrap` must return a structured error.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn envelope_org_isolation_wrong_region() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let cross_region_arn =
        "arn:aws:kms:eu-west-1:000000000000:key/00000000-0000-0000-0000-000000000001";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, cross_region_arn);
    let result = provider.envelope_unwrap().await;
    assert!(
        result.is_err(),
        "envelope_unwrap with a cross-region ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound
        | KmsError::AccessDenied
        | KmsError::ServiceUnavailable
        | KmsError::Internal(_) => {},
        other => {
            panic!("expected structured KmsError for cross-region ARN (envelope); got {other:?}")
        },
    }
}

/// Envelope mode: wrong account ARN → `envelope_unwrap` must return a structured error.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn envelope_org_isolation_wrong_account() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let wrong_account_arn =
        "arn:aws:kms:us-east-1:999999999999:key/00000000-0000-0000-0000-000000000002";
    let client = make_client_with_ep(&ep).await;
    let provider = AwsKmsProvider::from_client(client, wrong_account_arn);
    let result = provider.envelope_unwrap().await;
    assert!(
        result.is_err(),
        "envelope_unwrap with a wrong-account ARN must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::KeyNotFound | KmsError::AccessDenied | KmsError::Internal(_) => {},
        other => panic!(
            "expected KeyNotFound or AccessDenied for wrong account (envelope); got {other:?}"
        ),
    }
}

/// Envelope mode: invalid credentials → `envelope_unwrap` must return a structured error.
#[tokio::test]
#[ignore = "requires OGENTIC_KMS_TEST_ENDPOINT; run in kms-integration CI job"]
async fn envelope_org_isolation_missing_creds() {
    let Some(ep) = endpoint() else {
        eprintln!("skipping: OGENTIC_KMS_TEST_ENDPOINT not set");
        return;
    };
    let arn = std::env::var("OGENTIC_KMS_TEST_KEY_A")
        .unwrap_or_else(|_| "arn:aws:kms:us-east-1:000000000000:key/missing".into());

    use aws_config::SdkConfig;
    use aws_sdk_kms::config::Builder as KmsConfigBuilder;
    let creds = aws_sdk_kms::config::Credentials::new(
        "INVALID_ACCESS_KEY",
        "INVALID_SECRET_KEY",
        None,
        None,
        "adversarial-envelope-test",
    );
    let kms_cfg = KmsConfigBuilder::new()
        .credentials_provider(creds)
        .endpoint_url(&ep)
        .region(aws_sdk_kms::config::Region::new("us-east-1"))
        .behavior_version_latest()
        .build();
    let _ = SdkConfig::builder().build();
    let client = aws_sdk_kms::Client::from_conf(kms_cfg);
    let provider = AwsKmsProvider::from_client(client, &arn);
    let result = provider.envelope_unwrap().await;
    assert!(
        result.is_err(),
        "envelope_unwrap with invalid credentials must fail; got Ok"
    );
    match result.unwrap_err() {
        KmsError::AccessDenied
        | KmsError::ServiceUnavailable
        | KmsError::Config(_)
        | KmsError::Internal(_) => {},
        other => {
            panic!("expected a structured KmsError for missing creds (envelope); got {other:?}")
        },
    }
}
