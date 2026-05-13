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

This document covers the v0.1 single-user-vault threat model: the key lives in the OS keychain on the user's device. Server-side deployments using a KMS-backed key (tracked under [OGE-460 / R4-ext](https://linear.app/ogenticai/issue/OGE-460)) will have a different operational recipe — KMS-rotate semantics, IAM-policy considerations, etc. — covered in that ticket's documentation.

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
