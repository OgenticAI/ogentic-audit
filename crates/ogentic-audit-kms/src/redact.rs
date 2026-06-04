//! Redaction policy for `Display` / `Debug` impls across this crate.
//!
//! ## Rules
//!
//! - ARNs are **never** included in any formatted output.  ARNs encode the
//!   AWS account ID and region, both of which are considered sensitive in
//!   logs, traces, and crash reports.
//! - MAC bytes are **never** included; they are equivalent to a signature.
//! - `key_id` (the BLAKE3-256 projection of the provider descriptor) **is**
//!   safe to include — it is a one-way hash that does not reveal the key
//!   material or the ARN.  The first 8 bytes (16 hex chars) are shown in
//!   the short form used by [`crate::KmsKey`] and [`crate::aws::AwsKmsProvider`].
//!
//! The `Display` / `Debug` impls for [`crate::KmsKey`] live in
//! [`crate::key`]; the impl for [`crate::aws::AwsKmsProvider`] lives in
//! [`crate::aws`].
