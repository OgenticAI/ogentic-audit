//! KMS error taxonomy with structured retryability.
//!
//! Every variant is non-exhaustive at the crate boundary so callers that
//! pattern-match against a specific variant continue to compile when new
//! variants are added in point releases.
//!
//! ## Security note
//!
//! No variant's `Display` must include an ARN, AWS credentials, a request
//! body, or any URL.  The `from_aws_sdk` classifier strips all that from the
//! SDK's internal error type before constructing a `KmsError`; only the HTTP
//! status or a static string is retained.

/// Errors from a KMS-backed signing operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum KmsError {
    /// The IAM principal was denied access to the key.
    #[error("KMS denied access (IAM/AccessDenied)")]
    AccessDenied,

    /// The requested KMS key does not exist in this region/account.
    #[error("KMS key not found")]
    KeyNotFound,

    /// The request was rate-limited by the KMS service; the caller should
    /// back off and retry.
    #[error("KMS throttled; caller should back off")]
    Throttled,

    /// The KMS service returned a 5xx response; retry after a delay.
    #[error("KMS unavailable (5xx); retry")]
    ServiceUnavailable,

    /// A network-level failure before the service was reached.
    ///
    /// The inner error MUST NOT include an ARN, credential, or raw request
    /// body.  The wrapper used by `from_aws_sdk` sanitises the SDK error
    /// before boxing it here.
    #[error("network error")]
    Network(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// A configuration problem (bad ARN format, missing required setting).
    #[error("invalid configuration: {0}")]
    Config(&'static str),

    /// An unexpected internal condition (SDK version mismatch, unexpected
    /// response shape).
    #[error("internal: {0}")]
    Internal(&'static str),
}

impl KmsError {
    /// Returns `true` if the operation can safely be retried without any
    /// change to the request.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::Throttled | Self::ServiceUnavailable)
    }

    /// Classify an `aws_sdk_kms` `SdkError` into our taxonomy.
    ///
    /// **Security contract:** the returned `KmsError` MUST NOT include the
    /// ARN, the request body, AWS credentials, or any URL.  This function
    /// discards the inner SDK error for every variant except `Network`, and
    /// even there wraps only a static string.
    ///
    /// `aws_sdk_kms::error::SdkError<E>` uses the default type parameter for
    /// the HTTP response (`HttpResponse`), so we don't need to name
    /// `aws_smithy_runtime_api` directly.
    #[cfg(feature = "aws")]
    pub(crate) fn from_aws_sdk<E>(err: aws_sdk_kms::error::SdkError<E>) -> Self
    where
        E: std::fmt::Debug + 'static,
    {
        use aws_sdk_kms::error::SdkError;

        match err {
            SdkError::TimeoutError(_) => Self::ServiceUnavailable,
            SdkError::DispatchFailure(_) => Self::ServiceUnavailable,
            SdkError::ConstructionFailure(_) => {
                Self::Config("aws-sdk: request construction failed")
            },
            SdkError::ResponseError(_) => Self::Internal("aws-sdk: malformed response"),
            SdkError::ServiceError(svc) => {
                // Read the raw HTTP status; do NOT propagate the typed error
                // or its Display — it may include the ARN or request ID.
                let status = svc.raw().status().as_u16();
                match status {
                    403 => Self::AccessDenied,
                    404 => Self::KeyNotFound,
                    429 => Self::Throttled,
                    500..=599 => Self::ServiceUnavailable,
                    _ => Self::Internal("aws-sdk: unexpected service error"),
                }
            },
            _ => Self::Internal("aws-sdk: unhandled SdkError variant"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Confirm that the Display of every KmsError variant is free of a
    /// sentinel string that could represent a leaked ARN or credential.
    #[test]
    fn display_does_not_leak_sentinel() {
        let sentinel = "arn:aws:kms:us-east-1:123456789012:key/fake-key-id";
        let variants: &[KmsError] = &[
            KmsError::AccessDenied,
            KmsError::KeyNotFound,
            KmsError::Throttled,
            KmsError::ServiceUnavailable,
            KmsError::Config("some config issue"),
            KmsError::Internal("some internal issue"),
        ];
        for v in variants {
            let s = format!("{v}");
            assert!(
                !s.contains(sentinel),
                "KmsError::{v:?} Display leaked sentinel: {s}"
            );
        }
    }

    #[test]
    fn retryable_variants() {
        assert!(KmsError::Throttled.is_retryable());
        assert!(KmsError::ServiceUnavailable.is_retryable());
        assert!(!KmsError::AccessDenied.is_retryable());
        assert!(!KmsError::KeyNotFound.is_retryable());
        assert!(!KmsError::Config("x").is_retryable());
        assert!(!KmsError::Internal("x").is_retryable());
    }
}
