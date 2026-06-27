//! AWS KMS provider — the only file in this crate that imports
//! `aws_sdk_kms`.
//!
//! All other modules are provider-agnostic.
//!
//! This module is only compiled when the `aws` feature is enabled.  The
//! feature gate is applied in `lib.rs`; the `#![cfg]` inner attribute that
//! would duplicate it is intentionally omitted here.

use ogentic_audit_core::{HmacBytes, HMAC_LEN};
use zeroize::Zeroizing;

use crate::error::KmsError;
use crate::provider::KmsProvider;

/// A [`KmsProvider`] backed by AWS KMS `GenerateMac` (HMAC_SHA_256).
///
/// The HMAC key bytes remain inside the AWS HSM at all times; only the 32-byte
/// MAC output crosses the TLS boundary back to this process.
///
/// ## Construction
///
/// ```no_run
/// # async fn example() -> Result<(), ogentic_audit_kms::KmsError> {
/// use ogentic_audit_kms::AwsKmsProvider;
///
/// let arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcdef01234567890";
/// let provider = AwsKmsProvider::from_arn(arn).await?;
/// # Ok(())
/// # }
/// ```
///
/// ## Security
///
/// `Debug` is redacted — the ARN is never included in formatted output.
pub struct AwsKmsProvider {
    client: aws_sdk_kms::Client,
    key_id: String,
    descriptor: Vec<u8>,
}

impl AwsKmsProvider {
    /// Load credentials and region from the environment (env vars,
    /// `~/.aws/credentials`, IMDS, etc.) and build a provider from the
    /// given ARN.
    pub async fn from_arn(arn: impl Into<String>) -> Result<Self, KmsError> {
        let cfg = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        let client = aws_sdk_kms::Client::new(&cfg);
        let arn = arn.into();
        let descriptor = canonical_descriptor(&arn);
        Ok(Self {
            client,
            key_id: arn,
            descriptor,
        })
    }

    /// Construct from an already-configured `Client`.  Useful in tests
    /// (localstack, mock transports) and in environments where the config
    /// is loaded separately.
    pub fn from_client(client: aws_sdk_kms::Client, arn: impl Into<String>) -> Self {
        let arn = arn.into();
        let descriptor = canonical_descriptor(&arn);
        Self {
            client,
            key_id: arn,
            descriptor,
        }
    }
}

impl std::fmt::Debug for AwsKmsProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // ARN is not exposed — it identifies the key but also encodes the
        // account ID and region, both of which are considered sensitive in
        // log output.
        write!(f, "AwsKmsProvider(arn=<redacted>)")
    }
}

#[async_trait::async_trait]
impl KmsProvider for AwsKmsProvider {
    fn key_descriptor(&self) -> &[u8] {
        &self.descriptor
    }

    async fn sign(&self, msg: &[u8]) -> Result<HmacBytes, KmsError> {
        use aws_sdk_kms::primitives::Blob;
        use aws_sdk_kms::types::MacAlgorithmSpec;

        let out = self
            .client
            .generate_mac()
            .key_id(&self.key_id)
            .message(Blob::new(msg.to_vec()))
            .mac_algorithm(MacAlgorithmSpec::HmacSha256)
            .send()
            .await
            .map_err(KmsError::from_aws_sdk)?;

        let mac_blob = out
            .mac
            .ok_or(KmsError::Internal("aws-sdk: GenerateMac returned no MAC"))?;
        let bytes = mac_blob.as_ref();

        if bytes.len() != HMAC_LEN {
            return Err(KmsError::Internal(
                "aws-sdk: GenerateMac returned wrong length",
            ));
        }

        let mut arr = [0u8; HMAC_LEN];
        arr.copy_from_slice(bytes);
        Ok(HmacBytes::from(arr))
    }

    /// Obtain a fresh HMAC DEK via `GenerateDataKey` (envelope mode).
    ///
    /// Calls KMS `GenerateDataKey` with `NumberOfBytes = 32` to obtain a
    /// fresh 256-bit DEK encrypted under this key.  Only the **plaintext**
    /// bytes are returned; the ciphertext blob is discarded (v0.2 fresh-key
    /// flow — the DEK is scoped to this `KmsKey` instance lifetime).
    ///
    /// ## IAM requirement
    ///
    /// The IAM principal must have `kms:GenerateDataKey` on the key ARN.
    /// A symmetric CMK (AES-256) is required; HMAC KMS keys do NOT support
    /// `GenerateDataKey`.
    async fn envelope_unwrap(&self) -> Result<[u8; HMAC_LEN], KmsError> {
        let out = self
            .client
            .generate_data_key()
            .key_id(&self.key_id)
            .number_of_bytes(HMAC_LEN as i32)
            .send()
            .await
            .map_err(KmsError::from_aws_sdk)?;

        // `plaintext` is a `SensitiveBlob` — the AWS SDK zeroes it on drop.
        // We copy out the bytes before that happens and wrap them in our own
        // Zeroizing buffer immediately after.
        let plaintext = out.plaintext.ok_or(KmsError::Internal(
            "aws-sdk: GenerateDataKey returned no plaintext",
        ))?;
        let bytes = plaintext.as_ref();

        if bytes.len() != HMAC_LEN {
            return Err(KmsError::Internal(
                "aws-sdk: GenerateDataKey returned wrong key length",
            ));
        }

        // Wrap in Zeroizing to ensure the stack copy is zeroed before we
        // return (best-effort; the compiler is not obligated to honour this
        // for every optimisation level, but the volatile barrier in zeroize
        // maximises the chance).
        let mut zk = Zeroizing::new([0u8; HMAC_LEN]);
        zk.copy_from_slice(bytes);
        Ok(*zk)
    }
}

/// Canonicalise an ARN for use as a provider descriptor.
///
/// Trims whitespace and normalises to lowercase so that two ARN strings
/// that differ only in case or surrounding whitespace produce the same
/// `key_id`.
fn canonical_descriptor(arn: &str) -> Vec<u8> {
    arn.trim().to_ascii_lowercase().into_bytes()
}
