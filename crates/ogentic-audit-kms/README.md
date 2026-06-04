# ogentic-audit-kms

[![CI](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](../../LICENSE)

Optional KMS-backed [`KeyHandle`] for [`ogentic-audit`](https://crates.io/crates/ogentic-audit-core).

v0.1 ships with **AWS KMS** (`GenerateMac`, HMAC_SHA_256). GCP Cloud KMS and Azure Key
Vault are reserved for v0.2 (OGE-603).

## MSRV

Rust **1.85** (edition 2021).

## Feature flags

| Feature | Default | What it adds |
|---------|---------|-------------|
| `aws`   | **on**  | `AwsKmsProvider` + `aws-sdk-kms` dependency |

Turn off the default features with `default-features = false` if you want only the
`KmsProvider` trait and `KmsKey` type surface (e.g. to implement a custom provider
without pulling in the AWS SDK).

## Quickstart

```toml
[dependencies]
ogentic-audit-kms = "0.2.0-pre"
ogentic-audit-core = "0.1.0-alpha.0"
tokio = { version = "1", features = ["rt-multi-thread", "macros"] }
```

```rust,no_run
use ogentic_audit_kms::{AwsKmsProvider, KmsKey};
use ogentic_audit_core::{KeyHandle, Writer};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arn = "arn:aws:kms:us-east-1:123456789012:key/mrk-abcdef0123456789";
    let provider = AwsKmsProvider::from_arn(arn).await?;
    let key = KmsKey::new(provider)?;

    // Use exactly like any other KeyHandle.
    let session_id = [0u8; 16]; // UUIDv4 in real use
    let mut writer = Writer::open("./audit-logs", Box::new(key), session_id)?;
    // ... append records ...
    Ok(())
}
```

## Integration guide

For full setup instructions — CloudFormation snippet, minimum IAM policy, Node.js
quickstart, error taxonomy, per-org isolation pattern — see
[`docs/integrations/server-side-kms.md`](../../docs/integrations/server-side-kms.md).

## Security

- HMAC key material never enters process memory.  All signing is delegated to the
  AWS HSM; only the 32-byte MAC output crosses the TLS boundary.
- `Display` and `Debug` impls redact the ARN and never expose MAC bytes.
- `key_id` is derived from the provider descriptor (not key material) via BLAKE3-256.
  Documented in [`docs/adr/0002-server-side-kms-key-sourcing.md`](../../docs/adr/0002-server-side-kms-key-sourcing.md).

## License

Apache License 2.0.  See [`LICENSE`](../../LICENSE).
