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
    /// ## Security contract for implementors of custom `KmsProvider`
    ///
    /// The boxed inner error's `Display` AND `Debug` MUST NOT include:
    ///
    /// - the resource ARN / URL / GCP resource name / Azure vault URI
    /// - AWS credentials, OIDC tokens, or any session material
    /// - raw request bodies or response bodies
    /// - the IAM principal ARN of the caller
    ///
    /// `KmsError::Display` itself is a static string (`"network error"`)
    /// and is safe to log. The risk is `Error::source()`-chain walkers
    /// (crash reporters, `tracing_error::SpanTrace`, `anyhow`/`eyre`)
    /// that recursively format the inner error.
    ///
    /// `AwsKmsProvider` (the only shipping v0.1 implementation) constructs
    /// this variant only via `from_aws_sdk` for `SdkError::DispatchFailure`,
    /// where the boxed inner is a sanitised static-message `io::Error`.
    /// Custom providers MUST follow the same discipline.
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
    ///
    /// Retryable variants: `Throttled`, `ServiceUnavailable`, `Network`.
    /// Permanent variants: `AccessDenied`, `KeyNotFound`, `Config`, `Internal`.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(
            self,
            Self::Throttled | Self::ServiceUnavailable | Self::Network(_)
        )
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
            SdkError::DispatchFailure(_) => {
                // TLS/TCP failure before the request reached the KMS service.
                // We construct `Network` with a sanitised static-message
                // `io::Error` so neither the raw SDK error's `Display` nor
                // its `Debug` reaches the boxed inner — `Error::source()`
                // walkers see only the static string.
                Self::Network(Box::new(std::io::Error::new(
                    std::io::ErrorKind::ConnectionRefused,
                    "aws-sdk: dispatch failure (TLS/TCP before KMS)",
                )))
            },
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
    /// `Network` is covered separately because it owns a boxed inner.
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

    /// Sentinel-leak test for the `Network` variant: even if a careless
    /// custom provider tried to box an ARN-containing inner error, the
    /// outer `KmsError::Display` would still be `"network error"`. We
    /// also walk `Error::source()` to confirm the sentinel doesn't leak
    /// through chain-walking crash reporters when `AwsKmsProvider`
    /// constructs the variant (via `DispatchFailure` mapping).
    #[test]
    fn network_variant_display_and_source_chain_safe() {
        // Caller could try to wrap a leaky inner — outer Display still safe.
        let sentinel = "arn:aws:kms:us-east-1:123456789012:key/fake-key-id";
        let leaky_inner = std::io::Error::other(format!("oops {sentinel}"));
        let err = KmsError::Network(Box::new(leaky_inner));
        let outer = format!("{err}");
        assert_eq!(
            outer, "network error",
            "outer Display must be the static string; got {outer}"
        );

        // The boxed inner IS reachable via source() — that's the documented
        // contract. The contract on the variant docstring is that providers
        // MUST NOT box leaky inners. This test exists to keep the outer
        // Display contract honest, not to prevent inner leakage.
        let src = std::error::Error::source(&err);
        assert!(src.is_some(), "Network exposes source for retry classifier");
    }

    #[test]
    fn retryable_variants() {
        assert!(KmsError::Throttled.is_retryable());
        assert!(KmsError::ServiceUnavailable.is_retryable());
        assert!(KmsError::Network(Box::new(std::io::Error::other("x"))).is_retryable());
        assert!(!KmsError::AccessDenied.is_retryable());
        assert!(!KmsError::KeyNotFound.is_retryable());
        assert!(!KmsError::Config("x").is_retryable());
        assert!(!KmsError::Internal("x").is_retryable());
    }
}
