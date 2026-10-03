# ADR-0004: Signed chain (format 0x0002) and offline third-party verification

**Status:** Proposed (2026-10-03). Becomes Accepted when the v0.2 golden vectors are committed and pass in Rust, Python, and `tools/gen_vectors.py`.
**Date:** 2026-10-03
**Deciders:** David Oladeji (CTO)
**Specification:** [`docs/spec/v0.2.md`](../spec/v0.2.md)
**Supersedes:** the threat model's earlier plan to add "Ed25519 signatures over chain-head attestations layered on top of (not in place of) the HMAC chain" (see D1). Leaves ADR-0001 (format `0x0001`) in force.

## Context

The v0.1 chain is HMAC-SHA256. Verifying it requires the HMAC key, and anyone holding that key can forge a log that verifies. That was the right primitive for a single principal who writes and verifies their own vault ([threat model](../security/threat-model.md), "Why HMAC-SHA256 over Ed25519").

It is the wrong primitive for the case that now matters: a log or a release produced by one party and checked by another, such as a requester, an auditor, or a court, who must be able to verify **without trusting the producer**. Under HMAC, handing a verifier the key hands them the power to forge, and withholding it means they cannot verify. So "a third party can verify without trusting us" was not true of `0x0001`, and the court-defensibility brief said otherwise. That sentence is corrected in this change.

The threat model already named the conditions under which an asymmetric signature becomes necessary: "verification needed to be possible without the signing capability" and "the signing party and verifying party were different principals". Both now hold.

Requirements:

1. A machine with no secret and without the writing application installed verifies a log, and a release, end to end.
2. Changing one byte of a released file, of the release index, or of the log fails verification and names the item.
3. A forgery signed with a different key fails.
4. The "verify without trusting the producer" claim is accurate as written.
5. `0x0001` keeps working unchanged in every API.

## Decision

**Add format `0x0002`: every record carries a strict-verified Ed25519 signature (as an SSHSIG over the record bytes), and records are linked by a public, domain-separated SHA-256 hash. The verifier requires a public key pinned from outside the artefact, and without one it never reports "Verified". Add signed checkpoints, signed key statements (transition, revocation), and a release attestation: a canonical-JSON index of every released file and the audit-log head, with a detached SSHSIG that `ssh-keygen` can verify.**

The decisions below are numbered as the spec refers to them.

### D1. A new format, not signatures layered on the HMAC chain

*Considered:* (a) keep `0x0001` and add Ed25519-signed chain-head attestations on top (the earlier plan); (b) a new format with per-record signatures.

The two options differ in what a third party can check. Under (a), they can check the attested **heads** but not the **records**: recomputing the chain up to a head still needs the HMAC key. They would be trusting that the heads describe the records, which is the very trust we are removing. Under (b), every record is checkable with the public key. (b) needs a format version, and v0.1's own spec reserves `0x0002` for exactly this.

### D2. HMAC is dropped in signed mode, not kept alongside

A dual HMAC + Ed25519 record would add a second key to generate, store, and rotate, and a check that third parties still cannot run. Its one theoretical benefit is that HMAC-SHA256 resists a quantum forger. That benefit goes only to the key holder, so it restores exactly the single-principal property we are leaving. The post-quantum answer is an algorithm identifier (D5), not a hidden second MAC. `0x0001` remains available for deployments where the writer is the only verifier.

### D3. Per-record signatures, not periodic signed heads

Periodic signed heads leave an **unsigned window**. Records after the last head are only hash-linked, so anyone holding the file can rewrite them freely. A crash also always leaves such a window at the tail. Per-record signatures close both: every durable record is authenticated, and since each signature covers `prev_hash`, the head record's signature already *is* a signed head of the whole history. The cost is 64 bytes and one Ed25519 signature (microseconds) per record, which is immaterial at audit-log rates. Default kept; nothing showed it wrong.

### D4. The chain link is a public, domain-separated SHA-256 over the payload

`record_hash = SHA-256("ogentic-audit/v0.2/record" ‖ 0x00 ‖ payload_bytes)`, and `prev_hash` embeds the predecessor's. The payload includes position, key, algorithm, and session, so the hash commits to all of them. The hash covers the payload, **not** the signature. Record identity then does not depend on signature encoding, and a checkpoint pins content, not a signature. Every segment header (not only segment 0's) is hashed into that segment's `chain_start`, so header fields are signed via record 0.

### D5. Ed25519 now; ML-DSA reserved

Ed25519 has deterministic signatures, so there is no nonce to get wrong and golden vectors are byte-reproducible. It also has small keys and signatures, and is available everywhere a third party might look: OpenSSH, OpenSSL, Go, Node, and Python. *Considered:* ECDSA P-256. Its one real advantage is that Apple's Secure Enclave can hold a non-exportable P-256 key. It is non-deterministic unless RFC 6979 is used, and malleable. The `sig_alg` field leaves room to add it later as a hardware-backed option. ML-DSA-65 (FIPS 204) is reserved as `0x0002` and not implemented. Every layout is parameterized by `sig_alg`, so adding it is additive.

### D6. One signature construction everywhere: SSHSIG with namespaces

Every signature — record, checkpoint, attestation, transition, revocation — is Ed25519 over OpenSSH's SSHSIG signed-data, with a namespace naming the object type.

- *Versus our own prefix strings:* SSHSIG is published, deployed domain separation. Inventing our own construction gains nothing and costs reviewers an unfamiliar one.
- *Versus COSE_Sign1:* ADR-0001 anticipated COSE for signed attestations. We depart from that because of independence. Detached SSHSIG signatures verify with `ssh-keygen -Y verify`, which ships with macOS and most Linux distributions (and is available for Windows), and is maintained by people with no stake in our verdict. COSE has no such ubiquitous verifier. The on-disk records stay CBOR; only the signature construction changes.
- Writers emit only `sha512` SSHSIGs and verifiers reject `sha256`, leaving one encoding per signature.

This was prototyped before it was written down. A hand-built SSHSIG over an attestation, made with the RFC 8032 test key, verifies under OpenSSH 10.3. A wrong key or a wrong namespace is rejected.

### D7. `key_id` is the OpenSSH fingerprint; humans read grouped hex

`key_id = SHA-256(OpenSSH key blob)`. It is exactly what `ssh-keygen -l` prints, so a third party can cross-check our fingerprint with a stock tool, and no BLAKE3 is needed (v0.1's `key_id` hash). The key blob names the algorithm, so `key_id` binds it. The primary human form is 64 hex characters in 16 groups of 4: case-insensitive, 16 symbols, unambiguous over a phone line, printable on a letter. There is no short form, so nobody pins a truncation. The `SHA256:base64` form is shown alongside for `ssh-keygen` users.

### D8. One key per log; rotation is a signed transition statement; revocation has cut points

*Considered:* an in-log `key.transition` record that switches keys mid-log. *Chosen:* a log is signed by exactly one key, and rotation starts a new log. Each change of key is a detached **transition statement** signed by the old key, and it travels with releases. A verifier pinned to the root key reaches later keys through the chain of statements. Reasons:

- The common deployment opens a log per session, so the key changes between logs anyway. Cross-log continuity needs the detached statement regardless, and adding an in-log variant would mean two mechanisms.
- One key per log keeps v0.1's simplest invariant: every record's `key_id` equals its header's.
- A long-lived log rotates by closing with a signed checkpoint and opening a successor, which may name the old head in a `log.continued` record.

**Revocation** is for compromise only; retirement is a transition. A revocation names the revoked key, the log heads still vouched for (`trusted_heads`), and the transitions still honoured (`trusted_successors`). Everything else that key signed is rejected. It must be signed by a pinned key or by the revoked key itself (self-revocation only reduces trust). We do **not** let a merely transition-reachable key revoke others: that creates circular trust (a compromised key mints a successor that revokes the legitimate one), which a verifier cannot resolve offline.

The new key does not co-sign the transition. Proof of possession would stop the old key from endorsing a key it does not hold, but that endorsement cannot forge anything the new key's holder did not sign.

### D9. No pin, no "Verified"

The verifier takes the expected key from outside the artefact: `--public-key`, `--key-fingerprint`, or a trust file in OpenSSH `allowed_signers` format (so the same file also drives `ssh-keygen`). Keys inside a header, an SSHSIG blob, `ogentic-audit-signer.pub`, or a release's instructions are informational. With no pin, or with nothing signed, the best verdict is **`SelfConsistent`**, printed as "Self-consistent, signer not pinned" with the signer's fingerprint, and it exits **4**. Exit 0 would let scripts treat an unpinned check as success. Exit 1 would accuse a log of tampering that showed none. 4 is new and reachable only with v0.2 inputs, so v0.1 exit codes are unchanged.

### D10. The public key lives in every segment header

The verifier needs the key bytes before the first record so it can check the signature **before** decoding (D13). Pinning by fingerprint alone must also work, and each segment should be checkable on its own. *Considered:* the key in record 0's payload. That forces a decode before the first signature check, so a flipped byte in record 0 reports as a decode error, not as the altered record. The header grows from 80 to `80 + P` bytes (112 for Ed25519), and its length follows from `sig_alg`. v0.1 readers reject it at the version field, before the CRC, as `UnknownVersion`.

### D11. Signed checkpoints, and witnesses for free

Checkpoint v2 pins `(log_id, segment, record_id, record_count, record_hash)` plus the signer's clock fields. Signed by the log's key, it is the signer's own non-repudiable statement of its head. Two such checkpoints for one position with different hashes prove equivocation. Signed by anyone else, it is a witness attestation: the "external witness" of ADR-0001 with no new format and no reserved record field. Unsigned, it is the verifier's own observation. `record_count` makes truncation reportable even for a holder who never saw the head record.

### D12. The release attestation is canonical JSON with a detached SSHSIG

*Considered:* CBOR or COSE. *Chosen:* the JCS subset (integers, strings, arrays, objects; ASCII keys; no floats or nulls). It is human-readable, `jq`-able, and reproducible with one line of Python's standard library. The verifier re-serializes and requires byte equality, so duplicate keys or alternative escapes cannot make two parsers see different file lists. The attestation lists every released file (`path`, `size`, `sha256`, optional `role`, optional `parts` byte ranges naming items such as pages or index rows) and every audit log with its head. Then:

- `ssh-keygen` plus `shasum -c` verify the signature and every file with stock tools, naming any altered file. This was exercised end to end with non-ASCII names.
- The `ogentic-audit` verifiers add part-level naming, the log chain, and the checkpoint.

Paths are NFC and are looked up by NFC equality, so a decomposing filesystem cannot produce a false "missing file". Symlinks are never followed. Files present but not attested are listed by name as "not covered" rather than failing, because operating systems add `.DS_Store` and similar files when a folder is browsed. `--strict` fails on them. Everything in the attestation is published, so names must not leak withheld content.

### D13. Signature first, strictly

Per record: framing, then **signature**, then decode, then chain. A byte change anywhere in a record therefore reports `SignatureInvalid` **at that record**. A validly signed record in the wrong place reports `ChainBreak`, which separates "altered" from "moved or missing". Verification is strict: canonical `S`, no small-order `A` or `R`, cofactorless. Weak keys are refused at pin time. `ssh-keygen` is laxer about `S`; we confirmed it accepts `S + L` while OpenSSL rejects it. That only admits re-encodings of an existing signature, so the stock-tools path stays sound.

### D14. Downgrade fails loudly

A signed-mode verification of a `0x0001` log or segment is a `FormatDowngrade` **violation**, because someone holding (or inventing) an HMAC key can forge such a log. An HMAC-mode verification of a signed log is an argument error. Formats, algorithms, and keys never mix within a log. v1 and v2 checkpoints are not interchangeable.

### D15. Compatibility and versioning

`0x0001` is frozen and unchanged in every API, the CLI, the Python package, the reports (`format_version: 1`), and the exit codes. There is no in-place conversion: re-signing an HMAC log would make the new key vouch for history it never witnessed. The implementing release is **0.4.0** across crates and the Python package, because `ViolationKind` and `Verdict` gain variants and are not `#[non_exhaustive]` today. They become so in 0.4.0, and later additions are minor. `FORMAT_VERSION` keeps meaning `0x0001`; `FORMAT_VERSION_SIGNED` is added.

### D16. The offline verifiers

The CLI binary and the Python package are the offline verifiers. A bundle may carry them for air-gapped machines, together with their sigstore provenance signatures, so their origin is checked against the public build pipeline and not against the release's signer. For the release-level checks (signature, files), stock tools are a second, fully independent path (D12). *Deferred:* a single-file, standard-library-only reference verifier. It would be valuable as a third implementation a reader can audit in one sitting, but it is not required by the acceptance criteria.

### D17. Golden vectors use the RFC 8032 test keys

The v0.2 vectors use RFC 8032 §7.1 TEST 1 (K1) and TEST 2 (K2), so any Ed25519 implementation can confirm the keys without this repository. Ed25519 is deterministic, so outputs are byte-fixed. The generator uses Python `cryptography` (OpenSSL), an implementation independent of the Rust core's `ed25519-dalek`. Detached signatures in the vectors must also verify under `ssh-keygen`. The suite covers clean, unpinned, payload- and signature-byte tamper, non-canonical `S`, removal, reordering, other-key forgery, mixed-format downgrade, HMAC-under-signed-mode, checkpoint truncation and rewrite, transition, revocation, and release file, part, attestation, forged-key, missing-file, and truncated-log cases (spec §16).

## Consequences

**Becomes possible.** A requester, auditor, or court verifies a log or a release with a public key and no secret. The claim "verification does not require trusting the producer" is true for `0x0002` artefacts **given a key pinned out of band**, and is stated with that condition. A signer's private key can be destroyed after rotation without making old logs unverifiable (under HMAC, destroying the key destroyed verifiability).

**Still true, now stated plainly.** A signer can still write a false history from the start, or rewrite their own log. Signatures prove *who*, not *truth*. The defenses are checkpoints held by others (D11) and equivocation proofs, as before. Timestamps are the signer's clock. A verifier that is not given a revocation cannot apply it.

**New dependencies (implementation).** `ed25519-dalek` 2.x (strict verification), `base64`, `unicode-normalization`, and `serde`/`serde_json` in core behind a default `release` feature (core stays serde-free without it).

**New surface.** `Signer` trait, `InMemorySigner`, `KeychainSigner` (tagged, device-only seed), `PublicKey` and `Fingerprint`, `TrustContext`, `SignedVerifier`, checkpoint v2, release attestation build/sign/verify, key statements; CLI `verify` (auto-detect), `verify-release`, `checkpoint --sign`, `key …`; Python equivalents (spec §13).

**Embedding applications** need a follow-up in their own repositories: sign through `KeychainSigner`, write the attestation with each release, export and publish the public key fingerprint through a channel requesters can check independently, and change any user-facing text that says "Verified" without a pin.

## Action items

1. [ ] Core: signed segment/record format, `Signer`, `SignedVerifier`, strict verification, downgrade rules.
2. [ ] Checkpoint v2 (make, sign, verify) and key statements (transition, revocation, trust evaluation).
3. [ ] Release attestation (build, sign, `verify_release`) and the CLI `verify-release`.
4. [ ] `KeychainSigner` in `ogentic-audit-keychain` (tagged seed, device-only item).
5. [ ] CLI flags, exit code 4, `key` subcommands; Python bindings.
6. [ ] `tests/vectors/v0.2/` from `tools/gen_vectors.py`; Rust + Python conformance; `ssh-keygen` check in CI.
7. [ ] README and court-defensibility brief: describe `0x0002` once shipped; keep the `0x0001` limitation stated.
8. [ ] Mark this ADR Accepted when item 6 passes.
