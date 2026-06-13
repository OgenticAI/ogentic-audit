# Key rotation policy — `ogentic-audit` v0.1

**Status:** Normative for v0.1.
**Tracks:** [OGE-431 (R4)](https://linear.app/ogenticai/issue/OGE-431) — paired with [`docs/spec/v0.1.md`](../spec/v0.1.md) and [`docs/security/threat-model.md`](threat-model.md).
**Last updated:** 2026-05-13

## When to rotate

The HMAC signing key MUST be rotated in any of these situations:

1. **Suspected compromise.** Anything that could have exposed the key bytes — host compromise, lost device, OS keychain exfiltration, a contractor offboarding with access, accidental disclosure in a screenshot. Rotate immediately and treat the existing log as evidence of pre-rotation activity only.
2. **Scheduled hygiene.** A calendar trigger you set as part of your compliance posture (annual, biennial, etc.). v0.1 does not enforce a rotation cadence; that's a customer policy decision.
3. **Format-version migration.** If a future major spec version requires a key-format change (e.g. v0.2 introduces forward-secure key evolution, or asymmetric signing), rotating happens alongside the format upgrade.
4. **Personnel handoff.** The custodian-of-records associated with the log changes. Rotate so the new custodian can attest under FRE 902-style language to the post-rotation portion only.

Rotation is **not** required for:

- Routine reboots, app updates, or OS upgrades.
- Adding records to an existing log — the key signs every record continuously.
- A failed signing operation due to a transient OS keychain error.

## What rotation looks like

`ogentic-audit` v0.1 is an **append-only library**. Rotation does **not** rewrite existing log files. The recipe is:

1. **Stop writing** to the current log. Flush the writer if it's still open.
2. **Generate or provision a new key.** New 32 random bytes. The recommended source is the host OS CSPRNG; `KeychainKey::load_or_generate` handles this for desktop deployments.
3. **Store the new key** somewhere durable (OS keychain, KMS, etc.). The old key MUST remain accessible for verification of the pre-rotation log — do not delete it until you've decided the pre-rotation log no longer needs to be re-verifiable.
4. **Open a new log directory** with the new key. This produces a fresh segment 0 with a new `key_id` field in the header and a chain root of `HMAC(new_key, header_bytes[0..72])`. The two logs are now independent chains.
5. **Record the rotation event** in your compliance system: timestamp, old `key_id` (BLAKE3-256 hex), new `key_id`, custodian, reason.

## What rotation explicitly does NOT do

The library will not, and at v0.1 cannot:

- **Re-sign existing records under the new key.** Doing so would destroy the integrity claim — every record's HMAC is bound to the key in effect at the time of signing. Re-signing under a new key would make a tamper attempt by an authorized party visually indistinguishable from a legitimate rotation.
- **Migrate records into the new log.** Records stay in their original segment files, signed by the key they were signed with. The verifier doesn't merge chains across keys; it reports the verdict per log.
- **Hide the rotation from a verifier.** The two logs have different `key_id` values and different segment headers. An auditor inspecting both sees two chains; the rotation event is intentionally visible.

## Verifying across a rotation boundary

Auditors holding both the old key and the new key verify each log independently:

```
ogentic-audit verify old-log-dir/ --key-id <old-key-id-hex>
ogentic-audit verify new-log-dir/ --key-id <new-key-id-hex>
```

(`ogentic-audit` CLI is being added under [C2 / OGE-436](https://linear.app/ogenticai/issue/OGE-436); use the library's `verify()` API in the meantime.)

A single auditor with only the new key cannot verify the old log — the HMAC chain in the old log requires the old key to recompute. This is by design: it limits the blast radius if a key is compromised post-rotation.

## Key destruction

When the pre-rotation log no longer needs to be re-verified (typically: after retention period expiry, after the underlying data has been deleted, or after a final independent attestation), destroy the old key:

```rust
ogentic_audit_keychain::KeychainKey::delete(service, account)?;
```

After destruction, the old log file is still parseable (the on-disk format is independent of key knowledge), but its HMAC chain is no longer verifiable. **This is irreversible** — destroyed keys cannot be recovered. Customer policy should document the destruction event with the same rigor as the rotation event.

## Rotation in multi-tenant / server-side deployments

Server-side deployments that use `ogentic-audit-kms` with an AWS KMS HMAC key
have a different operational recipe from the OS-keychain path above.

### KMS rotation means pointing at a new ARN

AWS KMS does not support automatic rotation for HMAC keys (unlike RSA/ECC
asymmetric keys).  Rotating a KMS-backed audit key means provisioning a new KMS
HMAC key, obtaining its ARN, and updating the deployment.  There is no
"rotate in place" operation.

The chain segment boundary is the same as in the OS-keychain case: a new key
produces a new `key_id`, which roots a fresh segment chain.  The two log
directories (pre-rotation, post-rotation) are independent chains verified
independently.

### Rotation recipe for KMS deployments

1. **Create a new HMAC KMS key** — CloudFormation or CLI; obtain the new ARN.
2. **Update the IAM policy** on your server role to include `kms:GenerateMac`
   on the new ARN.  Keep the old ARN in the policy until the pre-rotation log
   is either destroyed or its verification window expires.
3. **Stop writing** to the current log directory.  Flush the open writer.
4. **Swap the ARN** in your deployment configuration (`AUDIT_KEY_ARN` env var,
   SSM parameter, etc.).  Deploy.
5. **Open a new log directory** with the new `KmsKey`.
6. **Record the rotation event** in your compliance system: timestamp, old
   `key_id` hex, new `key_id` hex, old ARN (for your records only — do not
   log it in the audit log payload; see observability guidance in
   `docs/integrations/server-side-kms.md`), reason for rotation.
7. **Retain the old IAM grant** until the pre-rotation log's retention period
   expires or you make a final verified archive of the old log.

### AWS KMS scheduled-deletion semantics

When you eventually retire the old KMS key, AWS KMS requires a minimum pending
window of **7 days** (default 30 days) before the key is deleted.  During this
window the key is disabled but can be re-enabled.  After deletion, it is
unrecoverable.

Implications for log verification:

- The pre-rotation log remains verifiable as long as the old key is not in
  `PendingDeletion` or `Deleted` state.
- Do not schedule deletion until you have made a final independent verification
  of the pre-rotation log and archived the result (e.g. `export --pdf` to a
  write-once store).
- A key in `Disabled` state cannot be used for `GenerateMac`.  If you need to
  verify an old log after rotating, re-enable the key for the duration of the
  verification, then disable it again.

### Verification across a rotation boundary

The same principle as OS-keychain rotation applies: each log segment carries its
`key_id` in the header.  Auditors must present the correct key for each segment.
With KMS, "present the key" means "hold IAM `kms:GenerateMac` capability on the
ARN that produced that segment."

```bash
# Verify pre-rotation log (old KMS key must be enabled and reachable)
AUDIT_KEY_ARN=<old-arn> ogentic-audit verify old-log-dir/

# Verify post-rotation log
AUDIT_KEY_ARN=<new-arn> ogentic-audit verify new-log-dir/
```

(The `--key-arn` CLI flag lands in v0.2 / OGE-603; for v0.1 use the Rust
API directly.)

## Threat-model alignment

The rotation policy above maps onto the threat model at [`threat-model.md`](threat-model.md) as follows:

- **Insider tampering with the cold log file** — rotation doesn't help directly (the old log is signed by the old key whether the insider tampered with it or not), but rotation limits the window during which the old key could have signed forged records.
- **Compromised process holding the HMAC key** — rotation is the primary remediation. The library cannot detect this class of attack while the compromise is active (documented residual risk); the post-compromise response is to rotate and treat the pre-rotation log as suspect from the moment of compromise forward.
- **Time-anchor manipulation** — independent of rotation. The dual-time-anchor reasoning ([`v0.1.md` § Time anchoring](../spec/v0.1.md#time-anchoring)) applies to each log independently.

## Failure modes to plan for

Operators should think through:

- **Lost new-key during rotation step 2/3.** Mitigation: don't destroy the old key until the new key is provably stored. The recommended sequence is "store new → verify new can sign + key_id matches expected → open new log → archive old key" with the old key untouched until the new chain has a few records in it.
- **Old key destroyed before pre-rotation log is finished being verified.** This is irreversible (see above). Mitigation: documented hold period; destruction only by explicit operator action via the CLI or programmatic API.
- **Custodian disagreement on rotation timing.** Treat as a process question, not a technical one. The library records what it's asked to record; the rotation event is whatever the custodian declares it to be.
