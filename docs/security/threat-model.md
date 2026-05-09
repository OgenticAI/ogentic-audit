# ogentic-audit — Threat model, v0.1

**Status:** Draft (paired with [ADR-0001](../adr/0001-on-disk-format.md))
**Tracks:** [OGE-427 (F4)](https://linear.app/ogenticai/issue/OGE-427)
**Last updated:** 2026-05-09

This document defines the security boundary of the `ogentic-audit` library at v0.1, names the adversaries we defend against, states the cryptographic invariants we maintain, explains why we made specific design choices given the threat model, and is paired with the court-defensibility brief at [`court-brief.md`](court-brief.md) (TBD).

## Trust model

`ogentic-audit` v0.1 assumes:

- **Single-user, single-device deployment.** The audit log lives inside the user's encrypted vault on their own machine. The same passphrase derives both the vault's data-encryption key and the audit log's HMAC key.
- **The OS is trusted while the user is logged in.** Process-level adversaries who can read live memory are out of scope; if they have memory, they have the key.
- **The on-disk file is the threat surface.** Adversaries we defend against operate on the cold log file: rewriting bytes, swapping records, replacing the file, deleting segments, manipulating the filesystem clock.

Out of scope at v0.1:

- Multi-tenant servers (deferred to Sotto Server / Zashboard server-side roadmap; see [OGE-460](https://linear.app/ogenticai/issue/OGE-460))
- Adversaries with live access to the running process (memory, signing key in RAM)
- Network-level adversaries (the v0.1 library does no network I/O)
- Side-channel attacks against HMAC-SHA256

## Adversaries

| Adversary | Capability | Defense |
|-----------|-----------|---------|
| **Insider with write access (offline)** | Can read and modify any byte of any segment file while the vault is locked | HMAC chain detection on next verify; chain-break or hmac-mismatch violation |
| **External attacker with disk image** | Same as insider; obtained a forensic image of the laptop | Same defense; additionally cannot recover plaintext records without vault passphrase (audit log lives inside encrypted vault) |
| **Clock manipulator** | Can advance or rewind the system wall-clock | Dual-time-anchor (wall + monotonic + session_id); divergence > 60 s within a session triggers `TimestampInconsistency` |
| **Compromised process with HMAC key** | Has live access to the signing key (post key-derivation) | **Cannot defend at v0.1.** Documented as accepted residual risk; mitigated by key only existing in memory while vault is unlocked. v0.2 may add forward-secure signing (FSPRG) — see Future Direction. |
| **Partial-write / power-loss** | SIGKILL or power-loss between record bytes hitting disk | Crash recovery via `len_trailer == len_prefix` check + atomic truncate to last valid record; chain remains intact at resume |
| **File-replacement (whole-segment swap)** | Replaces a segment file with one signed by a different key | Header `key_id` mismatch with prior segment + `prev_final` chain break across segments |
| **File-deletion** | Removes a middle segment from the directory | `SegmentDiscontinuity` violation: segment N+1's `prev_final` does not match what we computed from segment N-1 |
| **Replay** | Inserts a previously-valid record at a later position | `record_id` is monotonic per segment + signed; insertion produces an `HmacMismatch` because the inserted record's `prev_hash` won't match its claimed predecessor's HMAC |

## Invariants

The library guarantees, at all times when the library's API is the only writer:

1. **Append-only at the API level.** No code path mutates an existing record. Truncation only occurs during crash recovery and only of the last (incomplete) record.
2. **Append-only at the filesystem level.** All writes use `O_APPEND` semantics with explicit `fsync` after the trailer; no `pwrite` or `seek + write` to existing offsets.
3. **Every record is HMAC-chained.** No record can be added, removed, or modified without breaking the chain.
4. **Time is doubly anchored.** Every record carries wall-clock and monotonic timestamps; their divergence is checked at verify time.
5. **The signing key never lives outside controlled scope.** During use, the key is in process memory only while the vault is unlocked; on disk, only the public-portion `key_id` (BLAKE3 hash) is recorded.
6. **The format is self-describing.** A standalone verifier with no prior state can verify any log given the key and the spec.
7. **Verification is deterministic and total.** A log either verifies cleanly or produces a single, structured violation pointing to the specific record where the chain breaks.

## Why hash chain, not Merkle tree

The closest OSS court-relevant peers — Sigstore Rekor, Certificate Transparency, AWS QLDB — all use Merkle trees rather than linear hash chains. We deliberately chose differently for v0.1.

**What Merkle buys in their context:**

- **Subrange proofs**: an auditor verifies records 5,000–5,100 without scanning the rest of the log
- **Pre-published witnesses**: log operator publishes signed tree heads; consumers gossip and detect split-view attacks
- **External-witness friendly**: third parties can prove they observed a specific tree head at time T

**Why none of these matter at v0.1:**

- **No subrange use case**: an auditor verifying a Sotto Desktop user's vault is verifying the whole log, not a slice
- **No split-view**: there's exactly one consumer (the vault owner) and exactly one log; no peer set to gossip with
- **No external witness**: v0.1 has no external party with ground truth about chain heads

**Where Merkle would actually matter:**

The asymmetric advantage of public-key-signed Merkle tree heads — that compromise of the signing key cannot rewrite history — collapses in our threat model because **HMAC key compromise is equivalent to vault passphrase compromise**. Both derive from the same Argon2id-stretched root. An adversary with the HMAC key has, by construction, the ability to read every record in plaintext anyway. The "rewrite history" capability is a strict subset of the harm already done.

In a multi-tenant Sotto Server deployment where many users share a single audit infrastructure but no user has the signing key, Merkle tree + log-operator-signed heads becomes the right model. That's a v0.2+ deployment shape, not v0.1.

**Decision documented in [ADR-0001](../adr/0001-on-disk-format.md), Option E rejection.**

## Why HMAC-SHA256 over Ed25519

We use a symmetric MAC (HMAC-SHA256) rather than an asymmetric signature (Ed25519, RSA). This is consistent with the threat model — the key already protects the data — but worth naming explicitly.

Symmetric MAC:
- Single key derived from passphrase via Argon2id
- Tiny dependency surface (`sha2` and `hmac` crates only)
- 32-byte signatures vs Ed25519's 64
- Verifier needs the key (acceptable: only the user verifies their own vault)

Asymmetric signature would matter if:
- Verification needed to be possible without the signing capability (third-party attestation)
- The signing party and verifying party were different principals

For v0.1, the signing party = verifying party = vault owner. HMAC is the right primitive. Future v0.2 work on external witnesses will introduce Ed25519 signatures over chain-head attestations layered on top of (not in place of) the HMAC chain.

## Time anchoring rationale

A bare-wall-clock timestamp is forge-able by anyone who can advance the system clock. Sotto Desktop users have administrative control over their own machines — they can `date -s` if they want to. The court-relevant threat is not the user attacking their own log; it's **a third party (an opposing counsel, a regulator) arguing that the user could have**.

Three anchors in every record:

- `ts_wall` — RFC 3339 UTC. Auditor-readable. Forge-able.
- `ts_mono_delta` — milliseconds since session start on a monotonic clock. Resets on reboot or vault re-unlock. Forge-able only by reboot-and-replay (which leaves other traces).
- `session_id` — UUIDv4 generated at vault unlock. Constant for the session. Forge-able only by re-running the entire session deterministically (effectively rewriting history, caught by HMAC chain).

A coordinated forgery requires forging all three to remain mutually consistent across a record range — provably harder than forging any one alone. The expert-witness argument in court is: "If the wall-clock had been moved, the monotonic delta and session UUID would not have aligned in this self-consistent way."

We intentionally do not use external timestamping (RFC 3161) at v0.1 — it requires a TSA procurement decision, network reachability, and a fallback path for offline use. Reserved for v0.2 as an optional `attestation` field.

## Future direction (v0.2+)

These are explicitly out of scope at v0.1, named here so the v0.1 architecture does not foreclose them.

### Forward-secure signing (FSPRG)

`systemd-journald` evolves its signing key over time using a forward-secure pseudo-random generator. Even if the current key is compromised, an attacker cannot forge records prior to the compromise without also having historical evolution states.

For our threat model — where HMAC key compromise = vault passphrase compromise — FSPRG would change the calculus: a passphrase exposed today no longer permits unbounded retroactive forgery. Periodic key-evolution events would be persisted and verified separately.

**Path forward:** introduce a `key.evolved` event type with payload `{ epoch: u64, witness: bstr }` where the witness is the next-epoch key-derivation evidence. Out of v0.1 because it requires a key-evolution policy decision (every N records? every wall-clock interval? on every vault unlock?) and the addition of epoch tracking to the verifier.

### External witnesses

Rekor uses Sigstore's TSA; CT uses log-operator-signed tree heads; some compliance products anchor periodically to public blockchains. The pattern: a third party signs an attestation that "I observed chain head X at time T."

**Path forward:** the `attestation` field reserved at v0.2 will accommodate witness signatures. Witness identity and signature scheme are pluggable. Likely first witness types: a customer's compliance team (offline witness, asymmetric signature), Sotto's hosted attestation service (online witness), and an RFC-3161 TSA token (procurement-driven).

### Public anchoring

Periodic commitment of chain heads to a public log (Bitcoin OP_RETURN, a Sigstore TSA, an internal append-only log run by Sotto). Strongest possible "no one can rewrite history without the world noticing" argument, at the cost of operational complexity, network dependency, and (in the Bitcoin case) cost-per-anchor.

**Path forward:** v0.2+, layered on top of external witness infrastructure.

### Subrange / Merkle proofs

If multi-tenant Sotto Server emerges, the threat model and the use cases shift toward the Rekor/CT shape. At that point, a major version bump (v0.2 or v1.0) introduces a Merkle-tree variant of the format. Careful: we do not want to sacrifice the v0.1 hash-chain format in the meantime — v0.1 should remain a valid mode under any future spec.

### Encryption-at-rest

The audit log is plaintext on disk inside the encrypted vault. We rely on the vault for confidentiality. If a v0.2+ deployment shape exposes the audit file outside the vault (server-side, shared filesystem), the audit log itself must be encrypted. Likely approach: AEAD (XChaCha20-Poly1305) of each record's payload bytes under a key derived alongside the HMAC key.

## Court-defensibility positioning

(Detailed in [`court-brief.md`](court-brief.md) — TBD; outline below.)

The court argument relies on:

1. **Format precedent**: binary, framed, length-prefixed audit records map onto well-understood prior art (Certificate Transparency logs, git objects, Sigstore Rekor entries). All have been examined in technical proceedings.
2. **Cryptographic invariants**: HMAC-SHA256 is FIPS 140-3 approved (NIST SP 800-107). Chain construction is straightforward to explain to a judge with the right expert witness.
3. **Tamper-evidence**: any modification to the log breaks the chain. The verifier produces a structured report pointing to the exact record where tamper-evidence was triggered.
4. **Self-authentication path**: per FRE 902(13)/(14), an audit log produced by a system with documented integrity controls can be self-authenticating with a certification of process. The CLI's `export --pdf` ([OGE-438](https://linear.app/ogenticai/issue/OGE-438)) is intended to produce such a certification.
5. **Independence**: a separate `ogentic-audit` binary, not the application that wrote the log, performs verification. The verifier is open-source — opposing counsel can run it themselves.

## Residual risks (accepted at v0.1)

| Risk | Why we accept it |
|------|------------------|
| HMAC key compromise → unbounded retroactive forgery | Equivalent to vault passphrase compromise; user already has bigger problems. Mitigated by FSPRG at v0.2. |
| No external witness | Single-user threat model doesn't require it. v0.2 will add. |
| Clock manipulation by sufficiently coordinated adversary | Dual-anchor catches naive cases; sophisticated forgery requires session-replay equivalent to HMAC compromise. |
| Process-memory adversary | Out of v0.1 scope. Vault unlock window is the exposure. |
| Side-channel timing attacks against HMAC | Not relevant to file-format integrity; the key isn't network-exposed. |

## Open questions

These resolve before v0.1 is tagged Accepted:

1. **Crash-recovery semantics under network-mounted filesystems** (NFS, SMB) — `fsync` semantics are weaker. Likely answer: refuse to open log files on non-local filesystems at v0.1, with a config opt-out.
2. **Key-derivation parameters** — Argon2id memory/time/parallelism for the HMAC-key derivation. Inherits Sotto Desktop's vault parameters; documented in `docs/spec/key-derivation.md` (TBD).
3. **`segment_index` width** — u16 caps at 65,536 segments. At 64 MiB / segment, that's 4 TiB per key. v0.2 may widen to u32 if needed; v0.1 documents the limit.
4. **Witness signature scheme** for v0.2 — Ed25519 vs ML-DSA (post-quantum). Decision deferred until v0.2 design.
