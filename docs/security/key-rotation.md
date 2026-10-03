# Key rotation policy — `ogentic-audit` v0.1

**Status:** Normative for v0.1 (HMAC, format `0x0001`). Signed mode (format `0x0002`): [§ Signed mode](#signed-mode-format-0x0002), draft.
**Tracks:** [OGE-431 (R4)](https://linear.app/ogenticai/issue/OGE-431) — paired with [`docs/spec/v0.1.md`](../spec/v0.1.md) and [`docs/security/threat-model.md`](threat-model.md).
**Last updated:** 2026-10-03

## When to rotate

The HMAC signing key MUST be rotated in any of these situations:

1. **Suspected compromise.** Anything that could have exposed the key bytes — host compromise, lost device, OS keychain exfiltration, a contractor offboarding with access, accidental disclosure in a screenshot. Rotate immediately and treat the existing log as evidence of pre-rotation activity only.
2. **Scheduled hygiene.** A calendar trigger you set as part of your compliance posture (annual, biennial, etc.). v0.1 does not enforce a rotation cadence; that's a customer policy decision.
3. **Format-version migration.** If a future major spec version requires a key-format change (e.g. v0.2 introduces forward-secure key evolution, or asymmetric signing), rotating happens alongside the format upgrade. Moving from HMAC (`0x0001`) to signed mode (`0x0002`) means generating an Ed25519 signing key and opening **new** logs in signed mode. Existing HMAC logs are never converted, and they keep needing their HMAC key to verify.
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

## Signed mode (format `0x0002`)

**Status:** Draft, with [ADR-0004](../adr/0004-signed-chain-and-offline-verification.md) and [`v0.2.md`](../spec/v0.2.md) §9. Everything above applies to HMAC logs (format `0x0001`) and is unchanged.

### What is different

| | HMAC (`0x0001`) | Signed (`0x0002`) |
|---|---|---|
| Needed to verify | the secret key | the public key, pinned out of band |
| Can a verifier forge? | yes | no |
| Old key after rotation | must be **kept** to verify old logs | private key can be **destroyed**; old logs stay verifiable with the public key, and the old key is retired so a leaked copy signs nothing new that verifies |
| One pin across rotations | no: each log needs its own key | yes: a pinned root key reaches later keys through signed, accepted transitions |

### Generating a signing key

- `ogentic-audit key generate --keychain <service> <account>`, or `KeychainSigner::load_or_generate(service, account)` from the library. Use an account distinct from any HMAC key (for example `<app>:ed25519`). The seed comes from the OS CSPRNG and is stored tagged `ed25519-seed:v1:` together with its public key, so an HMAC loader can never read a signing seed as an HMAC key, and a wrong or corrupted item is detected on load.
- Generation is create-only, under a lock. It never overwrites an existing key, whose fingerprint may already be published.
- The public key is also written to a non-secret `<account>.pub` file, so printing the fingerprint does not unlock the keychain.
- **Know what your platform's store guarantees** ([spec §13.2](../spec/v0.2.md#132-rust-ogentic-audit-keychain)). On macOS the login keychain is not synced to iCloud Keychain, but it does move to a new Mac with Migration Assistant and with Time Machine restores; treat those as copies of the key. On Windows the item is stored with local persistence and does not roam. On Linux the Secret Service has no notion of a device, and headless machines have none.
- Use one key per signing installation or custodian, and do not copy it between machines. Several installations under one organization each get their own key, linked by transitions from a root key, or pinned individually.
- **Never** add the key to `ssh-agent` (an agent signs in any namespace, for any host it is forwarded to), and never export it in OpenSSH private-key format. `key export` exports public keys only.

### Publishing the public key

1. Export it: `ogentic-audit key export --format openssh` (also `pem`, `hex`). Print the fingerprint with `ogentic-audit key fingerprint`, which shows grouped hex (`6db5 e9b8 …`, 16 groups of 4), the dashed form for command lines, and the `SHA256:` form `ssh-keygen -l` prints.
2. Publish the fingerprint through **at least two channels the recipients of your logs and releases can reach independently**: for example an HTTPS page you control, and the cover letter or filing that accompanies a release. Be prepared to read it aloud over the phone, and tell recipients to compare it by machine (`--key-fingerprint`, or the comparison in spec §11.7), never by eye.
3. Publish the **trust line** too, with its scope, for people who use `allowed_signers` files: `release-signer namespaces="ogentic-audit/v0.2/release" ssh-ed25519 AAAA…` for checking releases with stock tools, or with no options for full use. Publish a separate line for each witness, scoped to `ogentic-audit/v0.2/witness`.
4. Consider an **offline revocation key**: a second key, kept offline, pinned under the same principal with only `namespaces="ogentic-audit/v0.2/key-revocation"`. It can revoke your signing key if that key is stolen, and can do nothing else.
5. Never make a copy inside a release bundle the only source. The bundle's `ogentic-audit-signer.pub` is for convenience; a verifier must not pin it.
6. Point recipients at the verifier's public release page, which carries `SHA256SUMS` and sigstore bundles ([spec §11.8](../spec/v0.2.md#118-obtaining-the-verifier)).
7. Record the publication in your compliance system: fingerprint, date, channels, custodian.

### Rotating (scheduled, custodian change, or format migration)

1. **Seal** the current logs (`log.sealed`), and issue a signed checkpoint of each final head. Give the checkpoints to a party outside your control (an auditor, a requester, your records system).
2. **Generate** the new key (new keychain account).
3. **Sign the transition** with the old key, listing every final head and the SHA-256 of every release attestation the old key signed: `ogentic-audit key transition --old <old> --new <new.pub> --final-heads <checkpoints>… --final-releases <attestations>… --out ogentic-audit-keys/<date>`. This writes `<date>.json` and `<date>.json.sig`.
4. **Accept it with the new key**: `ogentic-audit key accept --key <new> ogentic-audit-keys/<date>.json`, which writes `<date>.json.accept.sig`. A transition without the acceptance is ignored.
5. **Open new logs** with the new key. A log never changes key midway. The first record of a successor log MAY name the old head (`log.continued`).
6. **Ship the transition** in `ogentic-audit-keys/` with every later release, and publish it next to the root fingerprint.
7. **Publish the new fingerprint** as well. Verifiers who pin the newest key get the strongest guarantee.
8. **Destroy the old private key.** After a transition, a verifier accepts the old key only for the heads and releases listed in it, so the key is no longer useful for anything but further statements. Verification of old logs and releases needs only public keys. This is the opposite of the HMAC advice above.

Sign **one** transition per key. Two different transitions from the same key are reported as `TransitionEquivocation`, and verifiers then follow neither.

### Revoking (suspected compromise)

Revocation is for compromise. Retiring a key you still control is a transition, not a revocation.

1. **Stop signing** with the suspected key.
2. **Generate a new key and publish its fingerprint out of band as a new pin.** Do not rely on a transition from the suspect key alone: whoever holds that key can mint transitions too.
3. **Issue an authority revocation**, signed by a key that verifiers pinned **directly** under the same principal, with `key-revocation` in its scope (the root key, or the offline revocation key above): `ogentic-audit key revoke --key <suspect fp> --trusted-head <checkpoint>… --trusted-release <attestation>… --trusted-successor <fp>… --sign <authority key>`.
   - `trusted_heads`: signed checkpoints of logs you still vouch for, as of **before** the possible compromise. Records after those heads, and every other log signed by the key, are rejected (`RevokedKey`).
   - `trusted_releases`: release attestations you still stand behind. Others signed by the key are rejected.
   - `trusted_successors`: legitimate keys the suspect key transitioned to before the compromise. Any other transition from it is ignored.
4. **What a self-revocation does.** The suspect key can revoke itself, and verifiers honour that, but only as "revoked": its cut-point lists are ignored, because a thief could set them. Until an authority revocation provides cut points, nothing the key signed verifies. A key reached only through transitions cannot revoke another key.
5. **Several revocations combine** as follows: any one revokes the key; the cut points are the intersection of the authority revocations' lists. Their order and dates do not matter.
6. **Publish the revocation next to the pins**, together with an OpenSSH revocation list (`ogentic-audit key krl` or `ssh-keygen -k`) for people checking releases with stock tools. A verifier cannot apply a revocation it is not given (`--revocations <file>`). Leaving one out of a release bundle is exactly what an attacker would do, so the bundle cannot be the only copy. Stock tools apply the list all-or-nothing: they reject even the releases in `trusted_releases`, which is safe but stricter.
7. **Re-issue release attestations** under the new key for releases you still stand behind and did not list in `trusted_releases`. The released files do not change; only the attestation is re-signed.

### Verifying across rotations

```sh
# Pin the root key's fingerprint; transition statements come from the bundle or a directory.
ogentic-audit verify new-log/ \
  --key-fingerprint 6db5-e9b8-a1ba-ce1c-dd9a-7c6a-db9e-9396-acc5-0734-65d9-fe8e-3a0e-f6d9-c60d-6d4f \
  --statements ogentic-audit-keys/ --revocations revocations/2027-03-01.json

ogentic-audit verify-release ./release --trust allowed_signers --revocations revocations/2027-03-01.json
```

The report's `signer.trust_path` lists every key from the pin to the signer, with the principal, so an auditor can see which transitions were relied on.

### Failure modes to plan for (signed mode)

- **Private key lost before a transition was signed.** No transition is possible. Publish the new key as a new pin. Existing logs remain verifiable, because only the public key is needed.
- **Transition signed, new key lost before it accepted.** The transition is incomplete and ignored. Sign a fresh transition to another new key. Once a transition is accepted, a second one from the same key is equivocation, so treat a lost *accepted* successor as a compromise: revoke it with the authority key and publish a new pin.
- **Fingerprint published only inside bundles.** This defeats the model: anyone who can alter a bundle can alter the fingerprint in it. Treat it as a process failure and republish independently.
- **Revocation issued but not distributed.** Verifiers will keep accepting the compromised key. Distribution is part of revocation, not a follow-up.
- **Authority key stolen.** The thief can revoke your keys with empty cut points, which makes their history fail to verify (it fails closed; nothing can be forged this way). Publish a new pin and new cut points through your out-of-band channels.
