# ADR-0004: Signed chain (format 0x0002) and offline third-party verification

**Status:** Proposed (2026-10-03; revised the same day after a cryptographic review and a compatibility review). Becomes Accepted when the v0.2 golden vectors are committed and pass in Rust, Python, and the independent oracle in `tools/gen_vectors.py`.
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
5. `0x0001` keeps working in every API.

## Decision

**Add format `0x0002`: every record carries a strictly verified Ed25519 signature (an SSHSIG over the record's envelope), records are linked by a public, domain-separated SHA-256 hash, and each record's body is bound by a salted hash so it can be withheld from a release without breaking the chain. The verifier requires a public key pinned from outside the artefact, scoped to what that key may sign; without one it never reports "Verified". Add signed checkpoints and witness co-signatures, signed key statements (transition with retirement, revocation with cut points), and a release attestation: a canonical-JSON index of every released file and every audit-log head, with a detached SSHSIG that `ssh-keygen` can verify.**

The decisions below are numbered as the spec refers to them.

### D1. A new format, not signatures layered on the HMAC chain

*Considered:* (a) keep `0x0001` and add Ed25519-signed chain-head attestations on top (the earlier plan); (b) a new format with per-record signatures.

The two options differ in what a third party can check. Under (a), they can check the attested **heads** but not the **records**: recomputing the chain up to a head still needs the HMAC key. They would be trusting that the heads describe the records, which is the very trust we are removing. Under (b), every record is checkable with the public key. (b) needs a format version, and v0.1's own spec reserves `0x0002` for exactly this.

### D2. HMAC is dropped in signed mode, not kept alongside

A dual HMAC + Ed25519 record would add a second key to generate, store, and rotate, and a check that third parties still cannot run. Its one theoretical benefit is that HMAC-SHA256 resists a quantum forger. That benefit goes only to the key holder, so it restores exactly the single-principal property we are leaving. The post-quantum answer is an algorithm identifier (D5), not a hidden second MAC. `0x0001` remains available for deployments where the writer is the only verifier.

### D3. Per-record signatures, not periodic signed heads

Periodic signed heads leave an **unsigned window**. Records after the last head are only hash-linked, so anyone holding the file can rewrite them freely. A crash also always leaves such a window at the tail. Per-record signatures close both: every durable record is authenticated, and since each signature covers `prev_hash`, the head record's signature already *is* a signed head of the whole history. The cost is 64 bytes and one Ed25519 signature (microseconds) per record, immaterial at audit-log rates.

A signed head is not an *anchored* head: every prefix of a log also ends in one. D19 covers how a verifier learns that nothing was cut.

### D4. The chain link is a public, domain-separated SHA-256 over the envelope

`record_hash = TH("ogentic-audit/v0.2/record", envelope_bytes)`, and `prev_hash` embeds the predecessor's. The envelope carries position, `log_id` (through `chain_start`), key, algorithm, session, event name, timestamps, and `body_hash`, so the hash commits to all of them and, through `body_hash`, to the body. The hash covers the envelope, **not** the signature, so record identity does not depend on signature encoding and a checkpoint pins content. Every segment header (not only segment 0's) is hashed into that segment's `chain_start`, so header fields are signed via record 0.

### D5. Ed25519 now; ML-DSA reserved

Ed25519 has deterministic signatures, so there is no nonce to get wrong and golden vectors are byte-reproducible. It also has small keys and signatures, and is available everywhere a third party might look: OpenSSH, OpenSSL, Go, Node, and Python. *Considered:* ECDSA P-256. Its one real advantage is that Apple's Secure Enclave can hold a non-exportable P-256 key. It is non-deterministic unless RFC 6979 is used, and malleable. The `sig_alg` field leaves room to add it later as a hardware-backed option, and `Signer::sign` returns a `Result` so such a key fits without an API break. ML-DSA-65 (FIPS 204) is reserved as `0x0002` and not implemented. The log layout is parameterized by `sig_alg`. The stock-tools path and transitions do not carry over automatically; spec §15 states what changes.

### D6. One signature construction everywhere: SSHSIG with namespaces

Every signature (record, checkpoint, witness co-signature, attestation, transition, transition acceptance, revocation) is Ed25519 over OpenSSH's SSHSIG signed-data, with a namespace naming the object type.

- *Versus our own prefix strings:* SSHSIG is published, deployed domain separation. Inventing our own construction gains nothing and costs reviewers an unfamiliar one.
- *Versus COSE_Sign1:* ADR-0001 anticipated COSE for signed attestations. We depart from that because of independence. Detached SSHSIG signatures verify with `ssh-keygen -Y verify`, which ships with macOS and most Linux distributions (and is available for Windows), and is maintained by people with no stake in our verdict. COSE has no such ubiquitous verifier. The on-disk records stay CBOR; only the signature construction changes.
- Writers emit only `sha512` SSHSIGs and verifiers reject `sha256`, leaving one encoding per signature. Blobs are parsed strictly, with exact lengths at every level and no trailing bytes.
- **The signer of a detached object is the key the object names**, never the key that happens to be in its SSHSIG blob. The verifier looks the key up by the object's signer field, requires it to be authorised for that namespace, verifies under it, and requires the blob's key to be the same key. Without this rule, anyone could sign a statement claiming to come from a pinned key.

This was prototyped before it was written down. A hand-built SSHSIG over an attestation, made with the RFC 8032 test key, verifies under OpenSSH 10.3. A wrong key or a wrong namespace is rejected, and `allowed_signers` lines restricted with `namespaces=` and `-r` revocation lists behave as the spec uses them.

### D7. `key_id` is the OpenSSH fingerprint; humans read grouped hex; machines compare

`key_id = SHA-256(OpenSSH key blob)`. It is exactly what `ssh-keygen -l` prints, so a third party can cross-check our fingerprint with a stock tool, and no BLAKE3 is needed (v0.1's `key_id` hash). The key blob names the algorithm, so `key_id` binds it. The primary human form is 64 hex characters in 16 groups of 4: case-insensitive, 16 symbols, unambiguous over a phone line, printable on a letter. A dash-separated form is one shell argument. There is no short form, a parser accepts exactly 32 bytes and never matches a prefix, and every instruction says to compare by machine: a key grinder can match the first and last groups people check by eye.

### D8. One key per log; rotation is an accepted transition that retires the old key; revocation has authority rules and cut points

*Considered:* an in-log `key.transition` record that switches keys mid-log. *Chosen:* a log is signed by exactly one key, and rotation starts a new log. Each change of key is a detached **transition statement** that travels with releases and is published next to the pins. A verifier pinned to the root key reaches later keys through the chain of statements. Reasons:

- The common deployment opens a log per session, so the key changes between logs anyway. Cross-log continuity needs the detached statement regardless, and adding an in-log variant would mean two mechanisms.
- One key per log keeps v0.1's simplest invariant: every record's `key_id` equals its header's.
- A long-lived log rotates by sealing and opening a successor, which may name the old head in a `log.continued` record.

**A transition retires the old key.** It lists the old key's `final_heads` (every log it signed) and `final_releases` (every attestation it signed). After it, the old key's signatures are accepted only on those, on the transition itself, and on revocations; anything else is `RetiredKey`. Without retirement the old key would stay fully trusted forever, so a copy stolen before it was destroyed could sign new artefacts that verify. Retirement needs no revocation to reach the verifier: anyone verifying the new key's artefacts under the old pin must hold the transition.

**The new key accepts.** The new key signs the same transition bytes in a separate namespace. Without that proof of possession, nothing could be forged, but one key could name another's key as its successor and make that key's genuine releases verify under its own pin as if they were its own.

**One transition per key.** Two verified transitions from one key are `TransitionEquivocation`, signed evidence of a split succession, and the verifier follows neither.

**Revocation** is for compromise; retirement is a transition. A revocation names the revoked key, its signer (`revoker_key_id`), and the cut points: the log heads, releases, and successors still vouched for. Rules, all chosen so that a thief of a key cannot decide what survives:

- **Authority.** The revoked key itself may revoke (self-revocation), but its cut points are ignored. Otherwise, only a **directly pinned** key of the same principal with `key-revocation` in its scope has authority. A key reached through transitions never revokes another, which avoids the circular trust of a compromised key minting a successor that revokes the legitimate one. A co-pinned key of another principal, and a witness, never revoke.
- **Combination.** Revoked is the union of honoured revocations. Cut points come only from authority revocations, intersected when there are several. The result is a function of the set, so neither order of arrival nor a signer-chosen `issued_at` changes it. A self-revoked key's history is unverifiable until the authority issues cut points: fail closed.
- **Releases survive** through `trusted_releases`, so a revocation need not break every past release.

### D9. No pin, no "Verified"; every pin has a scope

The verifier takes the expected key from outside the artefact: `--public-key`, `--key-fingerprint`, or a trust file in OpenSSH `allowed_signers` format (so the same file also drives `ssh-keygen`). Keys inside a header, an SSHSIG blob, `ogentic-audit-signer.pub`, or a release's instructions are informational. With no pin, or with nothing signed, the best verdict is **`SelfConsistent`**, which exits **4** and prints one of two plain messages (no key supplied; no records to check). Exit 0 would let scripts treat an unpinned check as success. Exit 1 would accuse a log of tampering that showed none.

**Scopes.** A pin is not only "which key" but "for what". Each trust-file line may carry `namespaces="…"`, which `ssh-keygen` already honours, and every signature is accepted only in its key's scope. A witness is pinned for the witness namespace only, so adding a witness never lets it sign logs or releases, mint transitions, or revoke. Each line also names a principal, and revocation authority is confined to one principal, so one trust file can pin unrelated signers safely.

*The default scope* (a line with no options, and the two pin forms that carry no options at all, `--public-key` and `--key-fingerprint`) covers record, checkpoint, release, key-transition, and key-revocation. A fingerprint is the form people actually publish and read aloud, and rotation must work with it; a narrower default would make every fingerprint pin unable to follow a rotation. The risks a default could carry are handled elsewhere: a transition only ever passes on the old key's own scope and principal, retires the old key, needs the new key's acceptance, and can happen once.

### D10. The public key and a random `log_id` live in every segment header

The verifier needs the key bytes before the first record so it can check the signature **before** decoding (D13). Pinning by fingerprint alone must also work, and each segment should be checkable on its own. *Considered:* the key in record 0's payload. That forces a decode before the first signature check, so a flipped byte in record 0 reports as a decode error, not as the altered record.

`log_id` is 16 random bytes fixed at creation, in every header and hashed into every `chain_start`. *Considered:* the hash of the first record. That changes whenever the history is rewritten from the start, so a full rewrite looked like "a checkpoint for a different log", an operator mistake, and escaped the equivocation check; and two logs with the same first record shared an id. A random id stays the same under a rewrite (now `CheckpointMismatch`), never collides, and lets a caller say which log they mean (`--expect-log-id`). The header is `96 + P` bytes (128 for Ed25519). v0.1 readers reject it at the version field, before the CRC.

### D11. Signed checkpoints by the signer; witnesses co-sign with their own envelope

Checkpoint v2 pins `(log_id, segment, record_id, record_count, record_hash)` plus clock fields, and is signed only by the log's own key. It is the signer's non-repudiable statement of its head, and two of them for one position with different hashes prove equivocation. A **witness** does not sign the checkpoint itself: it signs a small co-signature naming the checkpoint's SHA-256, its own `observed_at`, and its own key, in its own namespace. The witness's time is then its own, and a witness can never be mistaken for the signer. This is the "external witness" of ADR-0001 with no reserved record field. A checkpoint by the log's signer that names a different log is reported as a finding, because substituting one of the signer's logs for another is an attack; a checkpoint by a different signer is an operator error.

### D12. The release attestation is canonical JSON with a detached SSHSIG; names are the unit of naming

*Considered:* CBOR or COSE. *Chosen:* the JCS subset (integers, strings, arrays, objects; ASCII keys; no floats, booleans, or nulls). It is human-readable, `jq`-able, and reproducible with one line of Python's standard library. The verifier re-serializes and requires byte equality, and type-checks integers (a `1.0` survives the round trip in common parsers), so duplicate keys, alternative escapes, or floats cannot make two parsers see different file lists.

The attestation lists every released file (`path`, `size`, `sha256`, optional `role`, optional `parts` byte ranges naming contiguous items such as index rows) and every audit log with its head. It is itself the signed index of page hashes. **A page is named by being its own file**: PDF pages are not contiguous byte ranges, so a part can never name one, and a multi-page file is named only as a whole. The decision index is a released file with one part per row.

- `ssh-keygen` plus `shasum -c` verify the signature and every file with stock tools, naming any altered file.
- The `ogentic-audit` verifiers add part-level naming, the log chain, checkpoints, and key statements.

Names in the attestation may not contain control, line-separator, or bidirectional-formatting characters, and the verifier escapes such characters wherever it prints a name. Otherwise a name could overwrite the verdict line on a terminal, disguise itself, or inject a forged `OK` line into `shasum -c`. Paths are NFC and looked up by NFC equality; symlinks and reparse points are never followed; names equal after case folding are ambiguous and fail closed. **Unattested files fail** (`UnattestedFile`) except for a fixed list of operating-system litter (`.DS_Store` and similar); `--allow-unattested` relaxes this. A planted file must not pass a script that reads only the exit code.

### D13. Signature first; strict verification defined completely

Per record: framing, then **signature**, then body hash, then decode, then chain. A byte change anywhere in a record therefore reports `SignatureInvalid` **at that record**. A validly signed record in the wrong place reports `ChainBreak`, which separates "altered" from "moved or missing".

Strictness is spelled out rule by rule, not by naming a library: canonical encodings of `A` and `R` checked by byte comparison, all small-order points rejected in every encoding (listed in spec Appendix A), torsion-free keys, `S < L`, and the cofactorless equation with `R` compared as bytes. Cofactored verifiers are non-conforming. Without this, a signer wanting deniability could craft a signature that one conforming implementation accepts and another rejects.

Where stock tools differ, that is stated exactly. `ssh-keygen` accepts `S + L`; we report that as `reencoded` ("a valid signature, re-encoded after signing"), not as altered content, so the two paths disagree for a named reason. Both OpenSSH and OpenSSL accept an all-zero signature under the identity key for any message, so the stock-tools recipe checks the pinned fingerprint against Appendix A first, and any verifier built on those libraries applies the point rules itself.

### D14. Downgrade fails closed and never accuses

A signed log replaced by an HMAC log could otherwise verify under an HMAC key the attacker chose, given in an environment variable. So: the verifier reads the format before loading any key; it never uses an implicit HMAC key source; an HMAC `Verified` is labelled "shared key: anyone holding this key could have written it". A whole HMAC log checked with any signed-mode input is the error `HmacLog` (exit 3), not a violation: a log legitimately written before signed mode must not read as tampered. A v0.1 segment inside a signed log, or an HMAC log inside a signed release, is the violation `FormatDowngrade`, because there a signed statement says otherwise. Formats, algorithms, `log_id`s, and keys never mix within a log, and v1 and v2 checkpoints are not interchangeable.

### D15. Compatibility and versioning

`0x0001` is frozen in format, report shape (plus one additive member), and library API. Two CLI behaviours change in 0.4.0, both toward failing closed: no implicit HMAC key from the environment, and `--segment` never reports `Verified` for a segment it did not check (an existing bug). 0.3.x verifiers report a v0.2 log as an `UnknownVersion` violation, so instructions name 0.4.0 as the minimum, and from 0.4.0 a newer format is an "upgrade the verifier" error rather than a violation. There is no in-place conversion: re-signing an HMAC log would make the new key vouch for history it never witnessed.

The implementing release is **0.4.0** for every published crate and the Python package. Every public enum and struct that will grow becomes `#[non_exhaustive]` in that release (the full list is in spec §13.1), release results get their own `ReleaseReport` with release item locations, `Record` gains an `auth` member, and the CHANGELOG tells consumers that wildcard arms must fail closed. `FORMAT_VERSION` keeps meaning `0x0001`; `FORMAT_VERSION_SIGNED` is added.

### D16. The offline verifiers, and how a reader trusts them

The CLI binary and the Python package (`python -m ogentic_audit`) are the offline verifiers; both print the same output and exit with the same codes. A verifier is only as trustworthy as its provenance, and a binary taken unchecked from a bundle vouches for itself. Therefore:

- each GitHub release publishes `SHA256SUMS` and a sigstore bundle per artifact (including the transparency-log proof), checkable offline with `cosign verify-blob --offline` against an identity and trusted root obtained independently;
- a verifier shipped inside a bundle is an **attested** file, so the stock-tools check, which instructions put first, verifies it against the signer's key before anyone runs it;
- instructions tell the reader to obtain the verifier independently where they can, and the stock-tools path is always available as a fallback that needs no verifier at all.

*Deferred:* a single-file, standard-library-only reference verifier. `tools/gen_vectors.py --verify` is an independent second implementation used as a test oracle, which covers most of that value for conformance.

### D17. Golden vectors use the RFC 8032 test keys, one per rule

The v0.2 vectors use RFC 8032 §7.1 TEST 1–3 keys, so any Ed25519 implementation can confirm the keys without this repository. Ed25519 is deterministic and vectors fix `log_id` and body nonces, so outputs are byte-fixed. The generator uses Python `cryptography` (OpenSSL), independent of the Rust core's `ed25519-dalek`, and its `--verify` oracle applies the point rules itself. Every MUST-reject rule has a vector, the 12 cases of "Taming the many EdDSAs" are included, and cases git cannot carry (NFD names, symlinks, case collisions) are generated at test time (spec §16).

### D18. Releases withhold content without breaking the chain

A release that ships a log ships every record in it, and a plain SHA-256 of a short or templated withheld page confirms a guess. Because the on-disk format is frozen once implemented, this is decided now:

- **Elidable bodies.** A record is an envelope (signed and chained) plus a body (`actor`, `payload`, and a fresh 32-byte nonce) bound by `body_hash`. A release copies a log with the bodies of withheld records removed; the chain and every signature still verify, and the report counts and lists elided records. Structural records are never elided. The nonce makes `body_hash` hiding.
- **Commitments.** A value derived from content that may be withheld is `TH("ogentic-audit/v0.2/commit", nonce ‖ content)` with a fresh nonce per item, disclosed only to someone entitled to the content (for example a court reviewing it in camera).
- **Normative release content.** A bundled log contains only releasable data; event names carry no content. The builder enforces it, because a verifier cannot know what was withheld.

*Considered:* only a normative rule with no format support. That would force a choice between releasing withheld information and not releasing the log, which defeats offline verification of the log.

### D19. Anchoring and sealing

Any prefix of a signed log verifies, so the report states whether the end is the real end. The tail is **anchored** by a signed `log.sealed` record, by a trusted checkpoint or witness co-signature naming the last record, or by the attested head in a release. Otherwise the report says "tail not anchored" and `head_anchored: false`. A header-only last segment (forgeable from public data) is a warning and not counted; a `segment.finalized` record is checked against the chain and must have a successor; nothing may follow `log.sealed`. *Considered:* making an unanchored log a failure. A log that is still being written is always unanchored, so that would make every live log fail.

### D20. Defensive limits and signer hygiene

Every input can come from an untrusted holder, so sizes, counts, and nesting are capped before parsing, and `len_prefix` is bounded by the bytes remaining in the file. On the signing side: the public key is derived from the seed for every signature (signing with a separately stored public key leaks the private key), every signature is verified before it is written (fault attacks on deterministic signing), the key is never placed in `ssh-agent` or exported in OpenSSH private format, and keychain items are created create-only under a lock and checked against a stored public key on load.

## Consequences

**Becomes possible.** A requester, auditor, or court verifies a log or a release with a public key and no secret. The claim "verification does not require trusting the producer" is true for `0x0002` artefacts **given a key pinned out of band and a verifier obtained or checked independently** (or the stock-tools path alone, for the signature and the files), and is stated with those conditions. A signer's private key can be destroyed after rotation without making old logs unverifiable (under HMAC, destroying the key destroyed verifiability), and rotation retires it so a leaked copy cannot sign anything new that verifies. Released logs can omit withheld content and still verify.

**Still true, now stated plainly.** A signer can still write a false history from the start, or rewrite their own log. Signatures prove *who*, not *truth*. The defenses are checkpoints held by others, witness co-signatures, and equivocation proofs. Timestamps are each signer's own clock. A verifier that is not given a revocation cannot apply it, and the stock-tools path applies revocations all-or-nothing. The OS keychains used today are not device-bound on every platform; spec §13.2 states what each one guarantees.

**New dependencies (implementation).** `ed25519-dalek` 2.x (with the explicit encoding and torsion checks of spec §3.5), `base64`, `unicode-normalization`, and `serde`/`serde_json` in core behind a default `release` feature (core stays serde-free without it).

**New surface.** `Signer` trait (fallible), `InMemorySigner`, `KeychainSigner`, `PublicKey` and `Fingerprint`, `TrustContext` with scopes and principals, `SignedVerifier`, `log_format`, checkpoint v2, witness co-signatures, release attestation build and `verify_release` with `ReleaseReport`, key statements and KRL export; CLI `verify` (format detection), `verify-release`, `checkpoint`, `witness`, `key …`; Python equivalents and `python -m ogentic_audit` (spec §13).

**Embedding applications** need a follow-up in their own repositories: sign through a `Signer` backed by the OS keychain under an account separate from any HMAC key, seal logs and write the attestation with each release (eliding withheld records), export and publish the public key fingerprint through a channel requesters can check independently, and change any user-facing text that says "Verified" without a pin.

## Action items

Status as of the implementing change (2026-10-03):

1. [x] Core: signed segment and record format (envelope, body, `log_id`), `Signer`, `SignedVerifier`, strict verification per §3.5, downgrade rules, limits, anchoring.
2. [x] Checkpoint v2, witness co-signatures, key statements (transition with acceptance and retirement, revocation with authority and cut points), scoped trust evaluation, KRL export.
3. [x] Release attestation (builder with elision, `verify_release`, `ReleaseReport`) and the CLI `verify-release`.
4. [x] `KeychainSigner` (tagged seed with stored public key, create-only, Windows local persistence, `.pub` file). The Windows path is compiled and run only in CI.
5. [x] CLI: format detection before key loading, explicit HMAC key, `--segment` fix, stdout reports, exit 4 and parser usage errors to 64, `export` wording per format, `key` subcommands; Python bindings and `python -m ogentic_audit`.
6. [ ] `#[non_exhaustive]` sweep and CHANGELOG migration note are done; the 0.4.0 version bump and the crates.io and PyPI publication belong to the release-preparation change.
7. [x] Release workflow: sigstore bundles and `SHA256SUMS` per artifact (not yet exercised by a tagged release).
8. [ ] `tests/vectors/v0.2/` from `tools/gen_vectors_v02.py` (also `tools/gen_vectors.py --v02`), its `--verify` oracle, Rust and Python conformance, and `ssh-keygen` checks (release signature, namespace restriction, KRL) in the CLI tests are done. Remaining: the PowerShell recipe of §11.7, run on Windows in CI.
9. [x] Docs: `violation-report.md` format version 2 and its JSON Schema (`violation-report-v2.schema.json`), `release-report.md`, README.
10. [ ] Mark this ADR Accepted when item 8 passes.
