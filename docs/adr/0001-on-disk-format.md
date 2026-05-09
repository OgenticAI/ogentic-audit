# ADR-0001: On-disk format for ogentic-audit

**Status:** Proposed
**Date:** 2026-05-09
**Deciders:** David Oladeji (CTO)
**Tracks:** [OGE-425 (F2)](https://linear.app/ogenticai/issue/OGE-425) — unblocks [OGE-426 (F3 spec)](https://linear.app/ogenticai/issue/OGE-426), [OGE-429 (R1 Writer)](https://linear.app/ogenticai/issue/OGE-429), [OGE-430 (R2 Reader)](https://linear.app/ogenticai/issue/OGE-430), [OGE-437 (R3 Verifier)](https://linear.app/ogenticai/issue/OGE-437), [OGE-441 (Q2 cross-language vectors)](https://linear.app/ogenticai/issue/OGE-441)

## Context

`ogentic-audit` is the Wave 1 OSS audit-chain library — court-defensible, tamper-evident, language-agnostic. v0.1 targets 2026-06-30. Two known consumers at v0.1: Sotto Desktop (Rust, in-process via Tauri) and Zashboard (Node.js server-side, KMS-backed keys per [OGE-460](https://linear.app/ogenticai/issue/OGE-460)). The OSS pitch — "regulators and customers can run their own verifier" — depends on Python parity at v0.1 ([OGE-433 (P1)](https://linear.app/ogenticai/issue/OGE-433), [OGE-441 (Q2)](https://linear.app/ogenticai/issue/OGE-441)).

This decision blocks every R-ticket and Q-ticket on the v0.1 milestone. Five sub-questions:

1. Container format
2. What the HMAC covers
3. Time anchoring
4. Segment rollover
5. Cross-language scope at v0.1

A peer survey of comparable systems (`systemd-journald`, Sigstore Rekor / Trillian, Certificate Transparency, HashiCorp Vault audit log, AWS CloudTrail, AWS QLDB) informs each sub-decision; deviations from prior art are called out explicitly below.

## Decision

**Binary CBOR-canonical, length-prefixed records, fixed-size segmented files. HMAC covers the full canonical record bytes (prev_hash embedded in the record). Wall-clock + monotonic delta + session_id in every record; RFC-3161 timestamping deferred to v0.2. Cross-language Python parity is in scope for v0.1.**

### File layout

```
audit-0000.cbor            ← segment 0 (genesis)
audit-0001.cbor            ← segment 1 (rollover at 64 MiB)
audit-0002.cbor
...
```

Per-segment structure:

```
┌─ HEADER (fixed, 80 bytes) ──────────────────────────┐
│ magic         "OGAU"                  4 B           │
│ version       u16 = 1                 2 B           │
│ segment_index u16                     2 B           │
│ key_id        32 B (BLAKE3 of pubkey portion)       │
│ prev_final    32 B (genesis hash for seg 0;         │
│                     prior segment's final hmac)     │
│ header_crc    u32 (CRC32 of preceding bytes)        │
│ reserved      4 B (zero, for alignment)             │
├─ RECORD 0 ──────────────────────────────────────────┤
│ len_prefix    u32 (length of CBOR payload)          │
│ payload       CBOR bytes (canonical, deterministic) │
│ hmac          32 B (HMAC-SHA256 over payload)       │
│ len_trailer   u32 (== len_prefix; reverse seek)     │
├─ RECORD 1 ──────────────────────────────────────────┤
│ ...                                                  │
├─ ...                                                 │
└─ FINAL RECORD (segment.finalized event) ────────────┘
```

`len_trailer` mirrors `len_prefix` so a reader can walk backward from EOF for crash recovery ([OGE-432 (R5)](https://linear.app/ogenticai/issue/OGE-432)) without re-parsing the whole file.

### Record schema (CBOR map, canonical encoding)

Fields are keyed by small integers (not strings) to keep canonical-form sort order trivial and on-disk size tight:

| Key | Field | Type | Notes |
|-----|-------|------|-------|
| 1 | `record_id` | `u64` | Monotonic per-segment, 0-indexed |
| 2 | `prev_hash` | `bstr (32 B)` | Zero on segment 0 record 0; otherwise prior record's HMAC |
| 3 | `ts_wall` | `tstr` | RFC 3339 UTC, fixed-precision millis (`2026-05-09T19:48:23.456Z`) |
| 4 | `ts_mono_delta` | `u64` | Milliseconds since session start on monotonic clock |
| 5 | `session_id` | `bstr (16 B)` | UUIDv4 generated at vault unlock; constant for the session |
| 6 | `actor` | `tstr` | `"user:david"`, `"system:shield"`, `"agent:router"`, etc. |
| 7 | `event` | `tstr` | Short tag — `"shield.classified"`, `"vault.unlocked"`, etc. |
| 8 | `payload` | `map` | Event-specific structured data; CBOR map |
| 9 | `key_id` | `bstr (32 B)` | Same as header — supports key rotation across segments |
| 10 | `schema_version` | `u8` | Major version of the `payload` schema for `event` |

CBOR canonical form per RFC 8949 §4.2: fixed integer encoding, deterministic map-key sorting (length-then-lex), no indefinite-length items, definite-length strings, no unused tags.

### HMAC chain

```
hmac_0  = HMAC-SHA256(key, header_bytes)               ← genesis (segment 0 only)
hmac_n  = HMAC-SHA256(key, canonical_cbor(record_n))   ← record_n.prev_hash = hmac_{n-1}
final_n = hmac of last record in the segment
```

On segment rollover, the new segment's header `prev_final` field equals `final_n` of the prior segment, and record 0 of segment N+1 has `prev_hash = final_n`. The chain is continuous across files.

### What the HMAC covers — and why

`prev_hash` is **embedded in the record** and signed as part of the canonical CBOR bytes. Verifier loop:

```
for record in segment:
    expected_prev = previous_record.hmac
    assert record.prev_hash == expected_prev
    expected_hmac = HMAC(key, canonical_cbor(record))
    assert record.hmac == expected_hmac
```

Single invariant ("HMAC the record bytes"); self-contained record; familiar pattern.

### Time anchoring

Three time-related fields per record: `ts_wall`, `ts_mono_delta`, `session_id`.

- `ts_wall` — RFC 3339 UTC, millisecond precision. Auditor-readable.
- `ts_mono_delta` — milliseconds since session start on a monotonic clock (`Instant::elapsed` in Rust, `clock_gettime(CLOCK_MONOTONIC)`).
- `session_id` — UUIDv4 generated at vault unlock; stable for the session, regenerated on next unlock.

Verifier reports a `TimestampInconsistency` violation if `|wall_delta_n − mono_delta_n| > 60_000ms` within the same session (1 minute slack for NTP corrections). Across sessions (`session_id` changes), only `ts_wall` continuity is checked because the monotonic clock resets.

This is the courtroom answer to clock-tampering questions: "An attacker would need to forge two clocks that already disagreed, in correlated fashion, plus mint a self-consistent session UUID and re-sign every subsequent record with the HMAC key."

RFC-3161 external timestamping is **out of scope for v0.1**. It requires a TSA procurement decision, network reachability, and a fallback path for offline use. Reserved as an optional `attestation` field at v0.2.

### Segments

64 MiB default segment size, configurable. At ~500 B average record, ~130k records per segment — comfortable for months of normal use, small enough that re-verification of the current segment fits in memory.

Final record of every segment is a `segment.finalized` event with payload `{ "records": u64, "final_hash": bstr }`.

### Cross-language v0.1: yes

Python parity is in v0.1 scope. The OSS narrative collapses without it — "verify your own log" is the trust pitch. Cost: ~1 extra week of wheel-build infrastructure ([OGE-434 (P2)](https://linear.app/ogenticai/issue/OGE-434) is already scoped). The format is Rust-canonical-CBOR but the **spec is the source of truth**, not the Rust impl. Python (PyO3) and any future Go / Node bindings verify against shared golden vectors in `tests/vectors/`.

## Options considered

### Option A: CBOR length-prefixed, segmented (chosen)

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — CBOR canonical lib + length-framing + segment header logic |
| Cost | $0 marginal; no new infra |
| Compactness | ~30% smaller than JSONL for typical records |
| Cross-language | Strong — every major language has a CBOR lib |
| Auditor-friendly | Medium — needs the CLI to read; `--format json` export bridges this |
| Court-defensibility | Strong — same family as Certificate Transparency, git objects |

**Pros:** deterministic encoding (RFC 8949 §4.2) with no canonicalization tax in user code; matches the `audit.log.cbor` reference already baked into Sotto Desktop's UI; binary framing makes "this is special signed data" argument credible; reverse-seekable for fast tail reads; COSE-family alignment for future signed-attestation work (RFC 8152) without changing the underlying encoding.

**Cons:** not human-readable without a tool; CBOR canonical-form support varies in CBOR libraries — must validate the chosen Rust crate's deterministic mode actually conforms to RFC 8949 §4.2 (one-day spike before R1 starts).

### Option B: Protobuf length-prefixed, segmented

This is the format Sigstore Rekor / Trillian chose — the closest court-relevant OSS peer. Rejected, but the rejection deserves explicit justification.

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium — `protoc` toolchain, generated code |
| Cost | $0 marginal |
| Compactness | Comparable to CBOR |
| Cross-language | Strongest — Google-supported libs everywhere |
| Auditor-friendly | Medium — needs the CLI to read |
| Court-defensibility | Strong — Rekor precedent in software-supply-chain litigation |
| Schema enforcement | Compiled `.proto` schemas |

**Why rejected for v0.1:**

1. **Codegen surface**: Protobuf adds `protoc`, `.proto` files, and generated stubs in every consuming language. Third parties writing a from-scratch verifier must run codegen or hand-decode. CBOR is decoded with two-line library calls in any major language.

2. **Schema enforcement is not the right kind**: Protobuf enforces field types and field numbers, but it does *not* enforce the semantic invariants that matter to us (HMAC chain validity, monotonic record IDs, canonical encoding). Those live in code regardless. We get the "schema rigor" intuition without the actual enforcement value.

3. **COSE-family alignment**: when v0.2 adds signed attestations (TSA tokens, witness signatures), COSE_Sign (RFC 8152) is the natural choice — and COSE is CBOR. With Protobuf as the base, we'd have a mixed-format encoding (Protobuf records + COSE attestations), which complicates the spec.

4. **Rekor's threat model is different**. Rekor is a public log with adversarial gossip; its choice of Protobuf plus the Trillian Merkle tree is fitted to that environment. We're a single-user vault. The Protobuf precedent's strength comes mostly from Trillian's machinery, not from Protobuf itself.

5. **Sotto Desktop UI commitment**: `audit.log.cbor` is already baked into Settings copy. Switching to `.pb` or `.audit` is a small thing, but it indicates the team thought through CBOR. Don't undo that without a real reason.

This is a real fork in the road. If a v0.2 review concludes Protobuf would have been better (stronger schema versioning ergonomics, Trillian-style integration), the migration path is one major version bump and a converter binary. Acceptable risk.

### Option C: JSONL + sidecar HMAC chain

| Dimension | Assessment |
|-----------|------------|
| Complexity | Medium-high — JSON Canonicalization Scheme (RFC 8785) |
| Cost | $0 |
| Compactness | Worst (~30% larger; whitespace + key repetition) |
| Cross-language | Strong — JSON is universal |
| Auditor-friendly | Strong — `cat`, `grep`, `jq` work |
| Court-defensibility | Weaker — "the file is text, anyone could edit it" intuition undermines tamper-evidence claim, even if technically incorrect |

**Why rejected:** JSON Canonicalization Scheme (RFC 8785) is its own complexity tax — every implementation must agree on number formatting, Unicode escapes, key ordering, whitespace, surrogate pair handling. CBOR canonical form is more rigorously specified and easier to comply with. A sidecar HMAC file means two sources of truth that must agree; tampering with both is one extra step for an attacker. The grep-ability win is fully recovered by `ogentic-audit show --format json`.

### Option D: SQLite WAL

| Dimension | Assessment |
|-----------|------------|
| Complexity | Low (SQLite handles framing, recovery, indexing) |
| Cost | New runtime dependency |
| Append-only claim | Weakens — SQLite rewrites pages during checkpointing |
| Cross-language | Medium — every language has SQLite, but "the format" is now SQLite's, not ours |
| Court-defensibility | Awkward — "the file changed at rest" requires explaining SQLite internals |

**Why rejected:** the append-only filesystem-level claim is a load-bearing part of the court argument. SQLite's normal operation includes page rewrites, WAL checkpoints, and vacuums. Defending tamper-evidence becomes "trust SQLite's internals," which is harder than "trust an HMAC chain over flat bytes." Also: ties our spec to SQLite's format, which we don't control.

### Option E: Merkle tree (à la Rekor / CT / QLDB)

This is what every other OSS court-relevant peer chose. Rejected for v0.1, but the rejection deserves explicit justification — see threat-model treatment in [F4 (OGE-427)](https://linear.app/ogenticai/issue/OGE-427).

**Why rejected for v0.1:** Merkle trees buy subrange proofs, pre-published witnesses, and split-view detection — capabilities that matter when the log lives outside the protected scope of its data (Rekor: public log, private signing key) or has many simultaneous consumers (CT: every TLS client). Our v0.1 threat model is **single-user vault on single device**; HMAC key compromise ≡ vault passphrase compromise (both derive from the same Argon2id root), so the asymmetric advantage of public-key-signed Merkle heads collapses. Hash chain is simpler, smaller, and equivalent for this threat model. Reconsider for v0.2 if Sotto Server / multi-tenant changes the boundary.

### Option F: FlatBuffers length-prefixed

**Why rejected:** zero-copy reads aren't a real benefit at our throughput (1–100 records/sec). More complex toolchain than CBOR. Less well-known to auditors.

## Trade-off analysis

The decision optimizes for **cryptographic adversary** and **cross-language verifiability** over **shell-tool ergonomics**. Reasoning:

1. The grep-ability win of JSONL is recovered through the CLI's `show --format json` path; the CBOR canonicalization win is irrecoverable.
2. Court-defensibility is Sotto's commercial moat. The court argument is cleanest with a binary, framed, self-describing format that maps onto well-understood prior art (CT logs, git, signed binaries).
3. Python parity at v0.1 forces a rigorously specified canonical encoding. CBOR §4.2 is more rigorously specified than RFC 8785 JCS in the wild — fewer footguns when a third party writes their own verifier.
4. Segments add ~200 lines of code total (segment-header read/write + iterator across files) and prevent a backward-incompatible "we should have done segments" change at v0.2 when someone hits 10 GiB.
5. CBOR over Protobuf is the one place we silently differ from the closest peer (Rekor/Trillian). Justified above; revisit at v0.2 if Trillian-style integration becomes desirable.
6. Hash chain over Merkle is the second place we differ from peers (Rekor / CT / QLDB). Justified by threat model; revisit at v0.2 if multi-tenant deployment changes the boundary.

## Future direction (out of v0.1 scope)

These are explicitly deferred but worth noting so v0.1 isn't accidentally architected against them.

- **Forward-secure signing (FSPRG)** — `systemd-journald` evolves the signing key over time using a forward-secure pseudo-random generator, so even if the current key is compromised, an attacker cannot forge records before the compromise. Genuinely interesting prior art for our threat model. Out of v0.1 because it requires periodic key-evolution events to be persisted and verified separately. Reserved as a `key_evolution` event type for v0.2+.

- **External witnesses** — Rekor uses Sigstore TSA; CT uses log-operator-signed tree heads. A v0.2+ direction: a customer's compliance team or Sotto's hosted service can act as a witness, signing chain heads at known intervals. The `attestation` field reserved at v0.2 will accommodate witness signatures alongside RFC-3161 timestamp tokens.

- **Public anchoring** — periodic commitment of the chain head to a public log (Bitcoin OP_RETURN, Sigstore TSA, internal blockchain) for "even if Sotto and the customer are both compromised, the chain head was witnessed externally at time T" arguments. Pure v0.2+; not in v0.1.

- **RFC-3161 timestamping** — covered above. Reserved as `attestation`.

- **Subrange proofs / Merkle tree** — only matters if multi-tenant Sotto Server emerges. Pre-emptively documenting why it's not in v0.1 (see Option E rejection).

## Consequences

**What becomes easier:**
- R1 Writer / R2 Reader / R3 Verifier are nearly mechanical translations of this spec
- Q2 cross-language goldens are well-defined: "given key K and these inputs, the canonical CBOR bytes equal these hex strings, and the HMAC equals X"
- C3 `export --pdf` can render any segment's records; the binary format doesn't constrain the export format
- Sotto Desktop's `audit.log.cbor` reference is correct as-is

**What becomes harder:**
- Ad-hoc field-level inspection without `ogentic-audit show`. Mitigated by shipping the CLI as a static binary in [C4 / OGE-439](https://linear.app/ogenticai/issue/OGE-439).
- CBOR libraries that don't support deterministic encoding mode are excluded. Recommend `ciborium` (Rust) and `cbor2` (Python); a third-party impl in a language without a deterministic CBOR lib has to write canonical-form code manually. The spec doc must be unambiguous enough to make this tractable.
- Spec document becomes a real asset that must be maintained. Lives at `docs/spec/v0.1.md`.

**What we'll need to revisit:**
- RFC-3161 timestamping (`attestation` field) — when (not if) a customer asks "what stops you from forging timestamps?"
- Subrange / Merkle proofs — if multi-tenant Sotto Server emerges
- Encryption-at-rest is **not** in this spec — the audit log is plaintext on disk inside the encrypted vault. If we ever ship a server-side variant where the log is on a shared filesystem, this assumption changes.
- Segment size of 64 MiB. Revisit at v0.2 with real data.
- CBOR-vs-Protobuf decision — revisit if Trillian-style integration becomes desirable.

## Action items

1. [ ] Open PR to `ogentic-audit/` repo: commit existing scaffold (LICENSE, README, CONTRIBUTING) + add this ADR + initial `Cargo.toml` workspace stub. Closes [F1 / OGE-424](https://linear.app/ogenticai/issue/OGE-424).
2. [ ] Write `docs/spec/v0.1.md` from this ADR as the source-of-truth: header layout, record schema, canonical-form rules, HMAC algorithm, golden-vector format. Closes [F3 / OGE-426](https://linear.app/ogenticai/issue/OGE-426).
3. [ ] Write `docs/security/threat-model.md` covering: single-user-vault threat model, HMAC-key-compromise ≡ passphrase-compromise, why-not-Merkle, FSPRG-as-v0.2-direction, external-witness-as-v0.2-direction, time-anchor reasoning. Closes [F4 / OGE-427](https://linear.app/ogenticai/issue/OGE-427).
4. [ ] One-day spike: prove `ciborium` (Rust) and `cbor2` (Python) produce byte-identical canonical encoding for our test schema. If they don't, change crate before R1 starts.
5. [ ] Generate first 6 golden vectors as part of F3. Each vector is `{key_hex, records_json, expected_segment_bytes_hex, expected_chain_hashes}`.
6. [ ] Mark this ADR Accepted after the spike (item 4) confirms canonical-form parity.
