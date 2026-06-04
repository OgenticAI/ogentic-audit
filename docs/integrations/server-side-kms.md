# Server-side KMS integration guide — `ogentic-audit-kms` v0.1

**Status:** Normative for v0.1.
**Tracks:** [OGE-460 (R4-ext)](https://linear.app/ogenticai/issue/OGE-460)
**Last updated:** 2026-06-04

This guide covers everything an operator needs to use `ogentic-audit-kms`
in a server-side deployment where the HMAC signing key must stay inside a
hardware security module (HSM) and never touch process memory.

For the security boundary and threat-model context, read
[`docs/security/threat-model.md`](../security/threat-model.md) — in
particular the new `## Server-side / KMS` section which documents the
axiom changes that come with this deployment shape.

## Why server-side KMS

The v0.1 keychain crate (`ogentic-audit-keychain`) is built for
single-user desktop deployments: the key lives in the OS keychain and is
loaded into process memory for the duration of a vault-unlock session.

Server-side deployments — a Node.js Zashboard backend, a multi-tenant
audit service, a containerised compliance pipeline — cannot use an OS
keychain.  Their HMAC signing key must be:

- Durable beyond any single process lifetime.
- Inaccessible to process dumps and debug-level introspection.
- Auditable: every use of the key is logged with a timestamp, an IAM
  principal, and a request ID.

AWS KMS `GenerateMac` satisfies all three requirements.  The key bytes
stay inside the AWS HSM; your process receives only the 32-byte MAC output
over TLS.  Every call is logged in CloudTrail.

## Setup

### 1. Create the HMAC KMS key (CloudFormation)

```yaml
# cloudformation/audit-kms-key.yaml
AWSTemplateFormatVersion: "2010-09-09"
Description: HMAC-SHA256 KMS key for ogentic-audit signing

Resources:
  AuditHmacKey:
    Type: AWS::KMS::Key
    Properties:
      Description: "ogentic-audit HMAC-SHA256 signing key"
      KeySpec: HMAC_256
      KeyUsage: GENERATE_VERIFY_MAC
      EnableKeyRotation: false  # HMAC keys do not support automatic rotation
      PendingWindowInDays: 7
      Tags:
        - Key: "ogentic-audit/purpose"
          Value: "audit-signing"
        - Key: "ogentic-audit/version"
          Value: "v0.1"

  AuditHmacKeyAlias:
    Type: AWS::KMS::Alias
    Properties:
      AliasName: alias/ogentic-audit-signing
      TargetKeyId: !Ref AuditHmacKey

Outputs:
  KeyArn:
    Value: !GetAtt AuditHmacKey.Arn
    Export:
      Name: !Sub "${AWS::StackName}-KeyArn"
```

**Important:** HMAC KMS keys do not support AWS KMS automatic key rotation.
Rotation means provisioning a new key (new ARN) and updating your
configuration.  See [Key rotation](#key-rotation) below.

### 2. Minimum IAM policy

Scope the policy to a single key and a single action.  Never use wildcards
on either the resource or the action.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "OgenticAuditSign",
      "Effect": "Allow",
      "Action": "kms:GenerateMac",
      "Resource": "arn:aws:kms:us-east-1:123456789012:key/<KEY-ID>",
      "Condition": {
        "StringEquals": {
          "kms:MacAlgorithm": "HMAC_SHA_256"
        }
      }
    }
  ]
}
```

The `kms:MacAlgorithm` condition prevents the policy from being used for any
other MAC algorithm, even if AWS KMS introduces new ones later.

## Rust quickstart

```rust,no_run
use ogentic_audit_kms::{AwsKmsProvider, KmsKey};
use ogentic_audit_core::{Writer, PayloadValue};
use std::collections::BTreeMap;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arn = std::env::var("AUDIT_KEY_ARN")?;
    let provider = AwsKmsProvider::from_arn(&arn).await?;
    let key = KmsKey::new(provider)?;

    let session_id = uuid::Uuid::new_v4().into_bytes();
    let mut writer = Writer::open("./audit-logs", Box::new(key), session_id)?;
    let mut payload = BTreeMap::new();
    payload.insert("user_id".into(), PayloadValue::Text("u-001".into()));
    writer.append(ogentic_audit_core::RecordInput {
        ts_wall: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        ts_mono_delta: 0,
        actor: "server:zashboard".into(),
        event: "vault.unlocked".into(),
        payload,
        schema_version: 1,
    })?;
    writer.flush()?;
    Ok(())
}
```

## Node.js quickstart

For v0.1, Node.js consumers either:

1. **Use the Rust library directly** via the `ogentic-audit-py`-style FFI
   bindings (planned for v0.2 via napi-rs — OGE-603).
2. **Shell out to the CLI binary** (pre-built via `cargo install ogentic-audit-cli`)
   using `child_process.execFile`:

```javascript
// v0.1 interim approach: shell-out to the CLI static binary.
// NOTE: This uses OGENTIC_AUDIT_KEY_HEX (in-memory key) not KMS.
// For KMS, use the Rust library directly or wait for the --key-arn
// CLI flag in v0.2 (OGE-603).
const { execFile } = require("child_process");
const { promisify } = require("util");
const execFileAsync = promisify(execFile);

const KEY_HEX = process.env.OGENTIC_AUDIT_KEY_HEX; // 64 hex chars

async function verifyLog(logDir) {
  const { stdout } = await execFileAsync("ogentic-audit", [
    "verify", logDir,
    "--format", "json",
  ], { env: { ...process.env, OGENTIC_AUDIT_KEY_HEX: KEY_HEX } });
  return JSON.parse(stdout);
}
```

When the v0.2 CLI gains `--key-arn`, replace `OGENTIC_AUDIT_KEY_HEX` with
`--key-arn $ARN` and remove the in-memory key entirely.  Document this
choice openly: v0.1 Node.js deployments using the CLI shim do not get
HSM-residency for their signing key.

## GenerateMac vs envelope-encrypted mode

| Mode | v0.1 status | Key residency | Per-call latency | Offline writes |
|------|-------------|---------------|------------------|----------------|
| `GenerateMac` (default) | Stable | HSM | ~1–5 ms (TLS RTT) | No |
| Envelope-encrypted | Reserved (OGE-603, v0.2) | Local (KEK in HSM) | ~0 ms after first call | Yes (cached DEK) |

Use `GenerateMac` for v0.1.  Envelope mode is reserved via
`KmsKey::with_envelope_mode` but returns an error until v0.2 ships.

## Error taxonomy

| `KmsError` variant | Retryable | Cause | Action |
|--------------------|-----------|-------|--------|
| `AccessDenied` | No | IAM policy missing or wrong principal | Fix policy; check role assumption |
| `KeyNotFound` | No | Wrong ARN or key deleted | Verify ARN; check key state |
| `Throttled` | Yes | Rate limit exceeded | Exponential back-off; request limit increase |
| `ServiceUnavailable` | Yes | AWS KMS 5xx | Retry with back-off; check AWS Service Health |
| `Network` | Yes | TLS/TCP failure before KMS | Retry; check VPC routing, security groups |
| `Config` | No | Invalid configuration | Fix at startup; cannot recover at runtime |
| `Internal` | No | SDK version mismatch or unexpected response | Update SDK; file a bug |

`KmsError::is_retryable()` returns `true` for `Throttled` and `ServiceUnavailable`.

## Per-org isolation pattern

Each tenant (org) gets its own KMS key.  A single compromised IAM credential
can sign for at most one org's key.

The four adversarial cases the test suite covers:

1. **Wrong ARN, same region** — `kms:GenerateMac` on a key the IAM principal has
   no access to → `AccessDenied` or `KeyNotFound`.
2. **Cross-region ARN** — the request is routed to a different region endpoint →
   `KeyNotFound` or `AccessDenied` (cross-region calls fail without an MRK).
3. **Wrong account** — the ARN belongs to a different AWS account → `AccessDenied`.
4. **Missing or invalid credentials** — the IAM credential chain fails →
   `AccessDenied` or `Config` error.

In all four cases the library returns a structured `KmsError`; no `Ok` response
with a wrong or empty MAC is ever produced.

## Observability hooks

**Safe to log:**

- `KmsError` variant names (e.g. `AccessDenied`, `Throttled`).
- `KmsKey::key_id()` as hex — this is the BLAKE3-256 projection of the
  descriptor, not the key material.
- Retry counts, latency histograms.

**Never log:**

- The ARN — it encodes the account ID and region, both considered sensitive.
- MAC bytes — equivalent to a partial key reveal.
- AWS credentials or session tokens.
- The raw canonical descriptor (it's a normalised ARN; see above).

## Key rotation

Rotating a KMS-backed key means **pointing at a new ARN**, not re-keying in
place (AWS KMS does not support in-place rotation for HMAC keys).

1. Create a new HMAC KMS key.
2. Update your deployment to use the new ARN.
3. Open a new log directory with the new `KmsKey`; the new key produces a
   new `key_id` which roots a fresh segment chain.
4. Record the rotation event: timestamp, old `key_id` hex, new `key_id` hex.
5. The old key must remain accessible (and its IAM grant intact) for
   the retention period of the pre-rotation log.

See [`docs/security/key-rotation.md`](../security/key-rotation.md) §"Rotation in
multi-tenant / server-side deployments" for KMS-specific details, including
AWS KMS scheduled-deletion semantics (7–30 day minimum pending window).

## CloudTrail as chain-of-custody artefact

Every `GenerateMac` call is logged in AWS CloudTrail with:

- Timestamp (UTC, millisecond precision).
- IAM principal that made the request.
- Key ARN (the managed key resource, not the HMAC output).
- AWS Request ID.

This gives you a parallel chain-of-custody record: alongside the audit log
itself, the CloudTrail log attests "this MAC was produced by this IAM principal
at this time under this key."

For the court-defensibility implications, see
[`docs/legal/court-defensibility.md`](../legal/court-defensibility.md)
§"Server-side / KMS-backed deployments".
