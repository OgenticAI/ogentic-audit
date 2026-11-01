# ogentic-audit — Threat model, v0.1 and v0.2 signed mode

**Status:** Draft (paired with [ADR-0001](../adr/0001-on-disk-format.md))
**Tracks:** [OGE-427 (F4)](https://linear.app/ogenticai/issue/OGE-427)
**Last updated:** 2026-10-03 (added [§ Signed mode](#signed-mode-format-0x0002-v02) for format `0x0002`, revised after review; everything else describes format `0x0001`)

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

For v0.1, the signing party = verifying party = vault owner. HMAC is the right primitive.

Both conditions above now hold for logs and releases checked by a third party, so v0.2 adds a signed format (`0x0002`, [§ Signed mode](#signed-mode-format-0x0002-v02)). It **replaces** HMAC in that mode rather than layering Ed25519 head attestations over the HMAC chain, as this section previously planned. Layered heads would still leave the records themselves checkable only by someone holding the HMAC key ([ADR-0004](../adr/0004-signed-chain-and-offline-verification.md) D1). Format `0x0001` remains the right choice when the writer is the only verifier.

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

### Checkpoint anchoring (shipped — the local half)

The gap the mechanisms in this section address is concrete, so it is worth stating in attack form. An adversary holding the HMAC key and write access to the log truncates it at any record, then re-chains fabricated history forward: each forged record gets a valid HMAC and a valid `prev_hash`. Every internal check in the verifier passes, because the chain is being validated **against itself**. This is not a hypothetical — `crates/ogentic-audit-core/tests/checkpoint_anchor.rs::verifies_rewritten_chain_without_checkpoint` asserts that a rewritten log passes plain verification, so the limitation stays visible in CI rather than drifting into folklore. Run `cargo run -p ogentic-audit-core --example rewrite_attack` to watch it happen.

**Shipped:** `ogentic-audit checkpoint` emits a `(segment, record_id, hmac)` triple — the chain head as observed at a moment in time — and `ogentic-audit verify --checkpoint <file>` asserts the log still contains that record. A rewrite reports `CheckpointMismatch`; a truncation reports `CheckpointTruncated`. The checkpoint lives outside the log, so this is not an on-disk format change.

**What it does not do.** The mechanism supplies comparison, not trust. A checkpoint stored beside the log by the same party that controls the log buys **nothing** — whoever rewrites the log rewrites the checkpoint next to it. The security property lives entirely in *where the checkpoint goes*: a party with different interests from the log's operator (a customer, a regulator, a counterpart agent, an append-only public log). Everything below this line is about making that "somewhere else" systematic rather than manual.

### External witnesses

Rekor uses Sigstore's TSA; CT uses log-operator-signed tree heads; some compliance products anchor periodically to public blockchains. The pattern: a third party signs an attestation that "I observed chain head X at time T."

**Path forward:** the `attestation` field reserved at v0.2 will accommodate witness signatures. Witness identity and signature scheme are pluggable. Likely first witness types: a customer's compliance team (offline witness, asymmetric signature), a hosted attestation service (online witness), and an RFC-3161 TSA token (procurement-driven). *(2026-10-03: in signed mode a witness signs a co-signature over a checkpoint with its own key, in its own namespace, [v0.2 §10.2](../spec/v0.2.md#102-witness-co-signatures), so the `attestation` record field stays unassigned.)*

### Public anchoring

Periodic commitment of chain heads to a public log (Bitcoin OP_RETURN, a Sigstore TSA, an internal append-only log run by Sotto). Strongest possible "no one can rewrite history without the world noticing" argument, at the cost of operational complexity, network dependency, and (in the Bitcoin case) cost-per-anchor.

**Path forward:** v0.2+, layered on top of external witness infrastructure.

### Subrange / Merkle proofs

If multi-tenant Sotto Server emerges, the threat model and the use cases shift toward the Rekor/CT shape. At that point, a major version bump (v0.2 or v1.0) introduces a Merkle-tree variant of the format. Careful: we do not want to sacrifice the v0.1 hash-chain format in the meantime — v0.1 should remain a valid mode under any future spec.

### Encryption-at-rest

The audit log is plaintext on disk inside the encrypted vault. We rely on the vault for confidentiality. If a v0.2+ deployment shape exposes the audit file outside the vault (server-side, shared filesystem), the audit log itself must be encrypted. Likely approach: AEAD (XChaCha20-Poly1305) of each record's payload bytes under a key derived alongside the HMAC key.

## Policy attestation binds only a retained policy

The `payload["policy"]` convention ([ADR-0003](../adr/0003-policy-attestation-payload-convention.md), shipped) records *what rule permitted an action* — a `permit`/`deny` decision plus a SHA-256 `digest` of the governing policy — inside the HMAC'd record bytes. Because it is signed and chain-linked, an attacker cannot alter a stored decision or digest without breaking the chain, and (with a checkpoint) cannot rewrite it undetected.

What the digest does **not** do on its own: it binds the decision to a *specific policy document* only if that document is **retained and retrievable**. The library never sees, canonicalizes, or hashes the policy — the digest is caller-computed and opaque (analogous to `key_id`). So a `digest` whose source policy was discarded proves only that *some* policy with that hash was claimed, not what it said. Operators relying on policy attestation for compliance evidence MUST retain the versioned policy artifacts their digests are taken over, under the same retention regime as the audit log itself. This is a process control, not something the format can enforce — stated here so it is not assumed away.

## Signed mode (format `0x0002`, v0.2)

Specified in [`v0.2.md`](../spec/v0.2.md); decisions in [ADR-0004](../adr/0004-signed-chain-and-offline-verification.md). Everything above still describes format `0x0001`, which is unchanged.

### Trust model change

v0.1 assumes the signer and the verifier are the same principal. Signed mode exists for the case where they are not. A log or a release written by one party is checked by another (a requester, an auditor, or a court) who must not need to trust the writer and must not be able to forge.

- **Signer:** holds an Ed25519 private key in the OS keychain, behind a `Signer` handle that never exposes it ([spec §13.2](../spec/v0.2.md#132-rust-ogentic-audit-keychain) states what each platform's store guarantees).
- **Verifier:** holds the signer's **public** key or fingerprint, obtained **outside** the artefact, with a scope saying what that key may sign. No secret. The verifier program itself is obtained independently, or checked before it is run ([spec §11.8](../spec/v0.2.md#118-obtaining-the-verifier)).
- **Witnesses:** other parties who co-sign checkpoints with their own keys, pinned for that purpose only.
- **The artefact travels through untrusted hands:** the requester, intermediaries, storage providers, an opposing party. All of them are now adversaries, alongside the cold-file adversaries above.

The verifier's inputs are part of the threat surface too. The pin, the revocations and transitions, and the verifier program must arrive by a channel the artefact's holder does not control.

### Adversaries in scope for signed mode

| Adversary | Capability | Defense | Report |
|-----------|-----------|---------|--------|
| **Holder of the log or release, without the signing key** | Edit, insert, delete, reorder, or splice records; alter or replace released files or the attestation | Strict per-record Ed25519 signatures over every envelope; body bound by `body_hash`; public SHA-256 chain; signed attestation with per-file and per-part hashes | `SignatureInvalid` naming the record; `ChainBreak` for moved or missing records; `FileAltered` naming the file and part; `FileMissing` |
| **The same holder, truncating** | Drop the tail of a log or whole trailing segments; append a header-only segment | Anchoring: `log.sealed`, a checkpoint or witness naming the head, or the attested head in a release. Rollover records are checked against the chain. Without an anchor the report says "tail not anchored" | `CheckpointTruncated`; warnings `UnsignedLastSegment`, `RolledOverWithoutSuccessor` |
| **The same holder, planting files** | Add a file to a bundle and claim it was released | Unattested files fail by default, apart from a fixed list of operating-system litter | `UnattestedFile` |
| **The same holder, swapping the verifier** | Replace a verifier binary in the bundle with one that always prints "Verified" | Verifier files are attested and checked with stock tools first; releases publish `SHA256SUMS` and sigstore bundles checkable offline; instructions say to obtain the verifier independently | `FileAltered` on the verifier file |
| **Key substitution** | Re-sign altered content with their own key; replace `ogentic-audit-signer.pub` and any printed instructions | The verifier's key comes from outside the artefact; keys inside it are informational; with no pin the best verdict is `SelfConsistent` (exit 4); instructions never present an in-bundle fingerprint as the one to use; fingerprints are compared by machine, in full | `UntrustedSigner` (expected vs actual fingerprint) |
| **A trusted party acting outside its role** | A witness, or an unrelated signer pinned in the same trust file, signs a log or release, mints a transition, or revokes someone else's key | Scopes on every pin (`namespaces=`); revocation authority confined to directly pinned keys of the same principal | `UntrustedSigner` (`out_of_scope`); statement not honoured |
| **Forged key statements** | Sign a transition or revocation with their own key while naming a pinned key as its author | The signer of a statement must be the key it names, verified under the trusted copy of that key | statement rejected |
| **Thief of a current key** | Sign new history; mint transitions to keys they control; revoke the key with cut points of their choosing | Revocation by the authority, with cut points; a self-revocation only marks the key revoked and its lists are ignored; several authority revocations intersect, independent of order and of signer-chosen times; one transition per key | `RevokedKey`, `TransitionEquivocation` |
| **Thief of a retired key** | Use a copy of an old key, taken before it was destroyed, to sign new logs or releases | A transition retires the old key: it is accepted only up to its listed final heads and releases | `RetiredKey` |
| **Successor hijack** | Name someone else's key as one's successor, so their genuine releases verify under one's own pin | The new key must accept the transition with its own signature | transition rejected |
| **Log substitution** | Pass off another log by the same key as "the" log, or rewrite a log from its first record | Random `log_id` fixed at creation, signed in every header; `--expect-log-id`; checkpoints compare `log_id` | `CheckpointMismatch`, `CheckpointForDifferentLog`, `LogIdMismatch` |
| **Downgrade** | Swap a signed log for an HMAC log made under a key of their choosing, and supply that key through the environment; splice a v0.1 segment into a v0.2 log; present a v1 checkpoint | Format read before any key; no implicit HMAC key; shared-key results labelled; an HMAC log under any signed-mode input is never `Verified`; one format per log; checkpoint versions not interchangeable | error `HmacLog` (exit 3); `FormatDowngrade` inside a signed log or release |
| **Algorithm or protocol confusion** | Replay a signature from one context in another; claim a different algorithm | SSHSIG namespaces per object type; `sig_alg` inside every signed envelope, every hashed header, and the key blob behind `key_id`; every JSON `alg` checked; strict SSHSIG parsing | `SignatureInvalid` (`namespace`), `AlgorithmMismatch` |
| **Malleability, weak keys, verifier disagreement** | Re-encode a signature; publish a small-order or mixed-order key and later disown signatures; craft signatures that one library accepts and another rejects | Strict verification defined rule by rule (canonical encodings, all small-order points, torsion-free keys, `S < L`, cofactorless); weak keys refused at pin time and in headers; Appendix A for the stock-tools path; the edge cases of "Taming the many EdDSAs" as vectors | `SignatureInvalid` (`reencoded`, `weak_key`) |
| **Parser differential and resource exhaustion** | Craft an attestation two JSON parsers read differently (duplicate keys, alternative escapes, `1.0`); send huge lengths, deep nesting, or many statements | Canonical JSON with re-serialize-and-compare and integer type checks; size, count, and depth limits applied before parsing | `AttestationMalformed`, `RecordCorrupt` (`TooLarge`) |
| **Display and path tricks** | Names with escape sequences, carriage returns, bidirectional overrides, or newlines (which inject lines into `shasum -c`); `..` or absolute paths; symlinks, reparse points, Unicode or case collisions | Those characters are banned in attested strings and escaped on output; path rules; links never followed; NFC lookup; ambiguous names fail closed | `AttestationMalformed`, `FileAltered` |
| **Disclosure through a release** | Read withheld content from a released log, or confirm a guess about a withheld page from its hash | Withheld records are elided; values about withheld content are salted commitments; release builders may include only releasable data | none: prevention |
| **The signer, rewriting their own history** | Produce an alternate history and deny the earlier one | Not preventable by any format. Signed checkpoints and witness co-signatures held by others make it **provable**: two signed checkpoints for one position with different hashes are an equivocation proof | `CheckpointMismatch` |

### Invariants in signed mode

1. Verification needs no secret, and nothing a verifier holds lets it sign.
2. `Verified` means no violation **and** at least one signature checked under a key that is pinned, or reachable from a pin through accepted transitions, within that key's scope, and neither retired nor revoked for that object.
3. Every envelope byte of every record is covered by that record's signature, and every body byte by `body_hash`. Every header field is covered through `chain_start` once its segment holds a record. A header-only segment is unsigned, carries nothing to attest, and is reported as such.
4. Every signature names its purpose (namespace) and its algorithm, and is accepted only within its key's scope.
5. Revocation and retirement only ever reduce trust, and their result does not depend on the order in which statements arrive or on any time a signer chose.
6. Destroying the private key after rotation does not affect verifiability. Only public keys are needed, which reverses the v0.1 key-destruction trade-off.
7. Every report says whether the end of each log is anchored.

### What signed mode does not change

- **Signatures prove origin, not truth.** The signer can still record false events from the start. Same as v0.1.
- **Time is the signer's clock.** `ts_wall`, `observed_at`, and `created_at` are each asserted by whoever signed them. Trusted time (RFC 3161 over a checkpoint) remains future work, and is required for any checkpoint relied on for the long-term post-quantum claim.
- **A compromised process holding the unlocked key can sign anything.** Same as v0.1, except that signed mode now has remediations third parties can apply: revocation with cut points, and retirement through rotation.

### Residual risks (signed mode)

| Risk | Why accepted / mitigation |
|------|---------------------------|
| The pin arrives through a compromised channel | Outside the format. Publish the fingerprint in at least two independent places; compare it by machine |
| A revocation or transition is never delivered to the verifier | An offline verifier cannot know. Publish both next to the pins; pinning the newest key limits what a compromised older key can do; anyone verifying a newer key's artefacts necessarily holds the transition that retires the older one |
| The thief of a directly pinned key issues an authority revocation with empty cut points | Fails closed: the key's history stops verifying until the signer republishes a pin and cut points. Denial of service by a key thief is inherent; forging is not possible |
| A self-revoked key's history is unverifiable until the authority issues cut points | Deliberate: only the authority decides what survives a compromise |
| Tail truncation when no anchor exists | Inherent to any log. The report states it. Seal logs, hand out signed checkpoints, and attest heads in releases |
| A rewrite under a new `log_id` | Cannot be linked to the old log by the format. An earlier signed checkpoint of the old `log_id` remains signed evidence that the old log existed, which the signer must account for |
| Ed25519 forgeable by a future quantum computer | ML-DSA-65 is reserved (`sig_alg 0x0002`). Evidence made before then is defended by checkpoints and attestations held by others and timestamped before that point. Transitions into a post-quantum key are only as strong as Ed25519 |
| `ssh-keygen` accepts `S + L` and, like OpenSSL, signatures under small-order keys | Stated in the spec. The `ogentic-audit` verifiers are strict and report re-encoding by name; the stock-tools recipe checks the pin against the list of small-order keys first |
| The stock-tools path follows no transitions and applies revocations all-or-nothing | It fails closed. Cut points and transitions need an `ogentic-audit` verifier or an independent implementation |
| The OS store moves the signing key off the device | macOS login keychain items move with Migration Assistant and backups; Linux Secret Service has no device binding; Windows items are stored with local persistence. Documented per platform; an application with the needed entitlements can provide a device-bound `Signer` |
| Release content is only as private as the builder makes it | The verifier cannot know what was withheld. Elision and commitments are builder obligations, with a vector showing an elided release verifying |

## Court-defensibility positioning

(Detailed in [`court-brief.md`](court-brief.md) — TBD; outline below.)

The court argument relies on:

1. **Format precedent**: binary, framed, length-prefixed audit records map onto well-understood prior art (Certificate Transparency logs, git objects, Sigstore Rekor entries). All have been examined in technical proceedings.
2. **Cryptographic invariants**: HMAC-SHA256 is FIPS 140-3 approved (NIST SP 800-107). Chain construction is straightforward to explain to a judge with the right expert witness.
3. **Tamper-evidence**: any modification to the log breaks the chain. The verifier produces a structured report pointing to the exact record where tamper-evidence was triggered.
4. **Self-authentication path**: per FRE 902(13)/(14), an audit log produced by a system with documented integrity controls can be self-authenticating with a certification of process. The CLI's `export --pdf` ([OGE-438](https://linear.app/ogenticai/issue/OGE-438)) is intended to produce such a certification.
5. **Independence**: a separate `ogentic-audit` binary, not the application that wrote the log, performs verification. The verifier is open-source — opposing counsel can run it themselves. For a `0x0001` log they need the HMAC key to do so, and that key also lets them forge. Verification that confers no power to forge requires a `0x0002` signed log, a public key pinned independently, and a verifier obtained or checked independently of the party offering the log ([§ Signed mode](#signed-mode-format-0x0002-v02)); the release signature and files can also be checked with stock OpenSSH tools alone.

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
4. ~~**Witness signature scheme** for v0.2 — Ed25519 vs ML-DSA (post-quantum). Decision deferred until v0.2 design.~~ Resolved 2026-10-03 ([ADR-0004](../adr/0004-signed-chain-and-offline-verification.md) D5): Ed25519 now; ML-DSA-65 reserved as `sig_alg 0x0002`.

## Server-side / KMS

This section documents the threat surface of `ogentic-audit-kms` — the optional
KMS-backed `KeyHandle` introduced in v0.1 for server-side deployments.  All
analysis above applies to the `ogentic-audit-core` and
`ogentic-audit-keychain` features; this section covers **axiom changes** that
apply when the `kms` feature is in use.

See `docs/adr/0002-server-side-kms-key-sourcing.md` for the design rationale.

### Axiom change 1: "No network I/O" invariant

The v0.1 main document states that the library performs no network I/O.  That
invariant is preserved for consumers of `ogentic-audit-core` and
`ogentic-audit-keychain` — neither makes any network call.

**The `kms` feature deliberately breaks this invariant.**  Every signing
operation dispatches a TLS-authenticated `GenerateMac` request to AWS KMS.
Consumers who add `ogentic-audit-kms` to their dependency tree opt into this
expanded threat surface consciously.

Implications:

- A network outage between the deployment and AWS KMS = audit gap.  The
  `KeyHandle::sign` method panics if the KMS call fails; the caller is
  responsible for the application-level handling (retry, queue, alert).
- KMS availability is now part of the audit log's availability SLA.
- TLS failure, DNS failure, VPC routing misconfiguration, or AWS region outage
  are new failure modes.  None of them silently produce a forged MAC; they all
  surface as a loud failure (panic from `KeyHandle::sign`).

### Axiom change 2: "Signing party = verifying party = vault owner"

In desktop deployments, signing and verification both require presenting the
same HMAC key (derived from the vault passphrase).  The signing party and the
verifying party are the same principal — the vault owner.

In server-side KMS deployments, the verifier holds
`kms:GenerateMac`-capable IAM credentials on the same key.  The signing IAM
principal (a server role) and the verifying IAM principal (an auditor role)
may be different.  This is the v0.1 workaround for the absence of asymmetric
signing.  The distinction matters:

- Two different IAM principals with `kms:GenerateMac` on the same key can
  both produce valid MACs.  A court expert should verify that access logs
  (CloudTrail) confirm only the expected principal signed the records under audit.
- Asymmetric signing — where the verifier holds only a public key and cannot
  forge records — is specified as format `0x0002`
  ([ADR-0004](../adr/0004-signed-chain-and-offline-verification.md)); a KMS-backed
  `Signer` is a follow-up.

### New failure mode: KMS unavailable

`KmsError::ServiceUnavailable` and `KmsError::Throttled` (unit variants — see
`KmsError::is_retryable()` for the retryability classifier method) surface
when the KMS service is reachable but temporarily unable to serve requests.
`KmsError::Network` surfaces on TLS/TCP failure before the request reaches
the service; all three return `true` from `is_retryable()`. `KeyHandle::sign`
panics with the error in every case in v0.1 — see OGE-644 for the v0.2
`try_sign` fix.

The library does not implicitly retry.  Operators must implement their own
retry logic (exponential back-off is standard) by wrapping the `Writer::append`
call in a retry loop that inspects the panic message, or — better — by ensuring
the calling code path is itself retried at the application level.

This is an accepted trade-off: the trait `KeyHandle::sign` is infallible by
design (it must be compatible with both in-memory and KMS backends), so errors
must surface as panics.  A v0.2 redesign may introduce a fallible
`KeyHandle::try_sign` for async-native contexts.

### What AWS KMS adds

| Property | AWS KMS `GenerateMac` |
|----------|----------------------|
| Key residency | HSM — key material never leaves AWS hardware |
| IAM scoping | Per-key, per-action, condition on `MacAlgorithm` |
| Audit of every use | CloudTrail: timestamp, principal, key ID, request ID |
| Key state management | Disabled, scheduled-deletion, pending-import states |

### What AWS KMS does NOT add

**Protection from an attacker who has gained MAC-capable IAM credentials.**
An adversary with valid `kms:GenerateMac` credentials for the audit key can
forge records that will verify successfully — identical to the desktop
scenario where the attacker has the HMAC key bytes.

The recommended IAM scoping pattern (from `docs/integrations/server-side-kms.md`):

```json
"Action": "kms:GenerateMac",
"Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY-ID",
"Condition": { "StringEquals": { "kms:MacAlgorithm": "HMAC_SHA_256" } }
```

One key, one action, one algorithm, no wildcards.

### Side-channel timing

The timing side-channel claim from the v0.1 main doc still holds for
KMS deployments: `GenerateMac` executes the HMAC inside the HSM, the output
travels over TLS.  No timing information about the key material leaks at
the network boundary.  The file-format integrity framing (HMAC chain,
canonical CBOR) is unchanged and unaffected by the key source.
