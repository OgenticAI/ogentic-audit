# ADR-0002: Server-side KMS key sourcing for `ogentic-audit`

**Status:** Accepted (2026-06-04)
**Deciders:** David Oladeji (CTO)
**Tracks:** [OGE-460 (R4-ext)](https://linear.app/ogenticai/issue/OGE-460)
**Supersedes:** Nothing in ADR-0001 (on-disk format unchanged); fills the
multi-tenant deployment gap ADR-0001 explicitly deferred to v0.2.

## Context

ADR-0001 chose HMAC-SHA256 over a linear hash chain for the v0.1 on-disk
format.  That decision was correct for the single-user, single-device
threat model (vault on a laptop; key in OS keychain; no network I/O).

Two consumers named at v0.1 need a different key storage shape:

- **Zashboard (Node.js server-side)** — a long-running API server where the
  signing key cannot live in a per-process OS keychain.
- **Multi-tenant audit pipelines** — where multiple organisations write to
  independent logs but share a deployment.

ADR-0001 explicitly deferred multi-tenant and server-side key management
to a follow-on ticket.  This ADR is that follow-on.

## Decision

### i. `kms` as an optional feature, parallel to `keychain`, default-off in the workspace

`ogentic-audit-kms` ships as a separate optional crate (not inside core)
with feature `aws` on by default within that crate.  The workspace adds it
as a non-default member, preserving the "no network I/O" property of a
plain `ogentic-audit-core` dependency.

Consumers who want KMS explicitly add `ogentic-audit-kms` to their
`Cargo.toml`.  They opt into the expanded threat surface consciously.

### ii. `KmsProvider` trait — caller-owned ARN mapping, library is provider-pluggable

The library exposes a `KmsProvider` trait with two methods:

```rust
fn key_descriptor(&self) -> &[u8];
async fn sign(&self, msg: &[u8]) -> Result<HmacBytes, KmsError>;
```

`key_descriptor()` returns a stable byte slice (typically a normalised ARN)
that the library uses to derive `key_id`.  It is never sent to the KMS
service.

The caller owns the ARN-to-key mapping.  The library never hard-codes a
region, account, or key alias.  This keeps the library provider-pluggable:
a GCP Cloud KMS or Azure Key Vault implementation only needs to satisfy the
same `KmsProvider` trait (v0.2, OGE-603).

### iii. AWS KMS `GenerateMac` as the v0.1 default primitive; envelope-encrypted local-HMAC deferred to OGE-603 (v0.2)

`GenerateMac(HMAC_SHA_256)` keeps key bytes inside the AWS HSM at all times.
The process receives only the 32-byte HMAC output over TLS.  This is the
strongest possible key-residency guarantee at v0.1.

Envelope-encrypted local-HMAC (Data Encryption Key wrapped by a KMS CMK,
local HMAC computed in-process) would reduce per-record latency and support
offline writes.  It introduces an additional attack surface (the DEK in
process memory).  It is reserved via `KmsKey::with_envelope_mode` but
returns a `Config` error until v0.2.

### iv. `key_id` projection

For in-memory and keychain keys, `key_id = BLAKE3-256(key_material)`.
For KMS-backed keys, the key material never enters the process; the
derivation therefore uses the provider descriptor instead:

```
descriptor   = canonical bytes from provider.key_descriptor()
              (= ARN normalised to lowercase, whitespace-trimmed)
key_id_bytes = BLAKE3-256("ogentic-audit-kms/v1\n" || provider_name || "\n" || descriptor)
KeyId        = key_id_bytes  (same 32-byte type as all other KeyIds)
```

`provider_name` is the literal string `"aws-kms"` for `AwsKmsProvider`
and `"fake"` for the test fixture.

The output domain is unchanged (32 bytes, KeyId type); only the input
domain differs.  Cross-language verifiers compare `key_id` bytes and
never inspect the input, so the change is transparent to the OGE-441
golden vectors.

### v. Explicit acknowledgement of axiom changes

**"No network I/O" invariant:**  The v0.1 main doc states this invariant
for the `ogentic-audit-core` and `ogentic-audit-keychain` features.  The
`kms` feature deliberately breaks this invariant.  Consumers who add
`ogentic-audit-kms` to their dependency tree opt into network I/O.
The invariant is preserved for consumers who do not.

**"Signing party = verifying party = vault owner" axiom:**  In the desktop
deployment, the HMAC key is derived from the vault passphrase, which both
the writer (at vault unlock) and the verifier (at audit time) must present.
In server-side deployments, the verifier holds `kms:GenerateMac` capability
on the same key to re-compute MACs — the signing and verifying party may be
different IAM principals.  Asymmetric signing (one party signs, another
verifies without signing capability) remains a v0.2+ path.

### vi. Failure mode: KMS unavailable → audit gap; caller's responsibility

If the KMS is unreachable during a `sign` call, the `KeyHandle::sign`
trait method panics (the trait is infallible).  This surfaces as a process
crash or a `std::panic::catch_unwind`-catchable panic in the caller.

The alternative — silently writing a zero-byte or sentinel MAC — would be
worse: the audit log would appear valid but would fail verification, with
no indication of when the failure occurred.  A loud failure (panic) is
preferable to a silent one.

Operators are responsible for:

- Ensuring KMS reachability from the deployment environment.
- Deciding the application-level response to a failed write (retry,
  queue, alert, halt).
- Monitoring `KmsError::Throttled` and `KmsError::ServiceUnavailable`
  (both `is_retryable()` = true) and implementing back-off.

### vii. What is NOT in this ADR

- GCP Cloud KMS provider (v0.2, OGE-603).
- Azure Key Vault provider (v0.2, OGE-603).
- FFI/RPC sidecar for calling Rust signing from non-Rust runtimes (v0.2).
- Envelope-encrypted local-HMAC (v0.2, OGE-603).
- Multi-region key replication semantics.
- Automatic key rotation scheduling.

## Consequences

### Benefits

- Server-side deployments get HSM-grade key residency without pulling in a
  KMS dependency for desktop consumers.
- The `KmsProvider` trait is extensible to GCP/Azure without changing core
  or the on-disk format.
- CloudTrail provides a parallel chain-of-custody artefact for every
  signing operation.
- The `kms` optional feature preserves the "no AWS SDK" compilation path
  for existing consumers.

### Costs

- Network I/O per signing call (~1–5 ms per record vs. sub-microsecond
  for in-memory keys).
- New dependency surface: `aws-sdk-kms`, `aws-config`, `tokio`.
- IAM misconfiguration is a new operational failure mode (see §vi above).
- The blocking shim (`block_in_place` / `std::thread::scope`) adds
  complexity to `KeyHandle::sign`.

## Future work

- **OGE-644** — Add fallible `KeyHandle::try_sign(&self, &[u8]) ->
  Result<HmacBytes, SignError>` to `ogentic-audit-core` so KMS errors
  surface as ordinary `Writer::append` errors instead of process
  panics. **Breaking change** — `ogentic-audit-core` major-version
  bump. Removes the panic shim documented in §vi above and in
  `docs/integrations/server-side-kms.md` §"v0.1 panic posture".
- OGE-603: envelope-encrypted local-HMAC, GCP/Azure providers, napi-rs
  FFI for Node.js consumers, `--key-arn` CLI flag.
- Asymmetric signing (Ed25519/ML-DSA) for third-party verification without
  signing capability — opens the "external witness" path from ADR-0001
  § Future direction.
