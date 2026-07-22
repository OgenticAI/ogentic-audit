# ADR-0003: Policy attestation as a `payload` convention

**Status:** Accepted (2026-07-22)
**Deciders:** David Oladeji (CTO)
**Tracks:** [OGE-1674](https://linear.app/ogenticai/issue/OGE-1674)
**Supersedes:** Nothing. On-disk format unchanged (`FORMAT_VERSION` stays `0x0001`); this ADR adds a documented convention over the existing free-form `payload` field. Distinct from the `attestation` field reserved for v0.2 external witnesses (ADR-0001) — see §"Why not the reserved `attestation` field".

## Context

An `ogentic-audit` record answers *"this happened"*: actor, event, timestamp, and a free-form `payload` map, all inside the HMAC'd record bytes and therefore tamper-evident and chain-linked. It does not answer *"…and it was permitted under policy P, decision D"*.

That second half is what turns a tamper-evident log into a **compliance artifact**. The distinction was named directly in the [NousResearch/hermes-agent#487](https://github.com/NousResearch/hermes-agent/issues/487) thread, where several independent agent-audit implementations converged on a `policy_attestation` shape (now drafted for [LangChain RFC #35691](https://github.com/langchain-ai/langchain/issues/35691)):

> an auditor doesn't just see "action X happened" — they see "action X was authorized under policy Y, and the result was Z". that's the difference between a tamper-evident log and a compliance artifact.

Their two normative requirements:

1. The policy **decision** and a **digest of the policy** must be inside the *signed* payload, not attached as metadata — otherwise a rewritten chain can swap policies without breaking any signature.
2. The digest must be over a **canonicalized** policy artifact so independent implementations reproduce the same value. Their canonicalization is RFC 8785 (JCS) for JSON policies.

We need to decide how `ogentic-audit` records this, and how it reconciles with our own canonicalization (RFC 8949 deterministic CBOR).

### Constraints established by research (file:line-cited in the ticket)

- **`payload` (record key 8) is free-form and already signed.** It is a caller-defined `BTreeMap<String, PayloadValue>` (`writer.rs`), encoded as part of the whole record map that gets HMAC'd (`writer.rs::encode_record_payload` → `sign_bytes`), and decoded generically by the reader with no fixed key set (`reader.rs::expect_payload_map`). Requirement (1) is therefore satisfiable *inside* `payload` with no format change.
- **New top-level schema keys are expensive.** The reader rejects any record-map key outside `1..=10` today (`reader.rs`), so a first-class `policy` *record key* needs a `FORMAT_VERSION` bump to `0x0002`: a parallel `tests/vectors/v0.2/` tree, a new spec doc, cross-language parity re-proven, Python bindings re-verified, and every fielded v0.1 reader broken until upgraded.
- **The library never hashes caller data.** It only computes `HMAC-SHA256(key, record_bytes)` over its own canonical CBOR. There is no code path that hashes a sub-structure. So the policy digest is necessarily **caller-computed**; we can only make it tamper-evident, not derive it.
- **No JCS anywhere.** The crate has no RFC 8785 machinery; it is CBOR-only.

## Decision

**Record policy attestation as a documented convention inside the existing `payload` map, under a reserved `policy` key, carrying a caller-computed opaque digest. No format-version bump.** The convention is `ogentic-audit-policy/v1` and a typed builder/parser ships in `ogentic-audit-core::policy`.

### i. The digest is caller-computed and opaque — which dissolves the CBOR-vs-JCS question

The policy digest is a SHA-256 the **caller** computes over *their* policy document, using whatever canonicalization their policy engine's interop contract demands — RFC 8785 (JCS) for a JSON policy (matching the LangChain RFC), RFC 8949 canonical CBOR for a CBOR one. `ogentic-audit` stores it as an opaque value and makes it tamper-evident via the HMAC chain. We do **not** implement JCS, and we do not need to: canonicalization is a contract between the policy author and whoever re-derives the digest, not something the audit log participates in. This mirrors how `key_id` is a caller-supplied BLAKE3 projection the writer never recomputes.

The one-line interop guidance we publish: *for a JSON policy, canonicalize with RFC 8785 before hashing; for a CBOR policy, RFC 8949 §4.2. Record the result as `"sha256:<hex>"`.*

### ii. The reserved shape (`ogentic-audit-policy/v1`)

A record whose outcome was determined by a policy MAY carry `payload["policy"]` = a CBOR map:

| key | type | required | notes |
|-----|------|----------|-------|
| `format` | text | yes | `"ogentic-audit-policy/v1"` |
| `decision` | text | yes | `"permit"` or `"deny"` — binary core, matching the RFC core profile |
| `digest` | text | yes | `"sha256:<64 hex>"` — SHA-256 over the caller's canonicalized policy artifact |
| `policy_id` | text | no | stable id an auditor uses to locate the retained policy |
| `deciding_rules` | array of text | no | stable rule ids sufficient to determine the decision |

`digest` is a `"<alg>:<hex>"` **text string**, not a raw byte string: it matches the RFC's JSON representation exactly, is auditor-readable, and needs no changes to the JSON-driven golden-vector generator. The typed API still exposes `[u8; 32]`.

### iii. `decision` is binary in v1

`permit` / `deny` only. Systems with richer verdicts (`require_approval`, `indeterminate`) record the *effective* binary outcome here and carry nuance in their own payload fields. Widening the vocabulary is a future profile decision, deliberately out of v1 — consistent with the RFC thread's own "keep core binary, extend via profile" conclusion.

### iv. Tamper-evidence, not validation

The verifier remains unaware of the convention: a record carrying a `policy` sub-map is an ordinary v0.1 record, and the chain verifies clean because the policy data is *inside* the HMAC'd bytes. Editing a stored `decision` or `digest` breaks the HMAC (proven by a test that flips `permit`→`deny` in the raw bytes). We deliberately do **not** make the verifier enforce presence/shape of policy fields — that would require first-class schema keys (§"Options"). Applications that need "every record MUST carry a policy decision" enforce it at their own layer today, and can be given a future `--require-policy` verify mode without a format change.

## Decision matrix

| | Payload convention (chosen) | First-class schema keys (v0.2) | Defer / ADR-only |
|---|---|---|---|
| On-disk format change | none (`0x0001`) | bump to `0x0002` | none |
| Ships | one additive PR now | multi-PR (new vector tree, new spec doc, parity re-proof) | no code |
| Satisfies RFC req (1) "digest in signed payload" | yes | yes | — |
| Verifier can *enforce* policy fields | no (app-layer) | yes | — |
| Breaks fielded v0.1 readers | no | yes | no |
| Forecloses upgrading later | no — can promote to keys in v0.2 | n/a | no |

The only thing the convention gives up is verifier-*enforced* policy fields. For a first cut of an interop-driven feature whose exact shape is still settling in the LangChain RFC, keeping it additive and non-breaking is worth more than enforcement, and nothing about it prevents a future v0.2 from promoting the fields to first-class if enforcement becomes necessary.

## Why not the reserved `attestation` field

ADR-0001 reserves an `attestation` field for **v0.2 external witnesses** — a third party (TSA, compliance officer, hosted service) signing *"I observed chain head X at time T"*, strengthening the existence/timing claim against a keyholder rewrite. That is a different axis from **policy attestation** (the semantic justification of an already-recorded event). To avoid confusion we do **not** reuse the name `attestation`: the payload key is `policy`, and the two features never share a namespace (top-level record key vs. payload sub-key).

## Consequences

- `ogentic-audit-core::policy` gains `PolicyAttestation`, `PolicyDecision`, `PolicyError`, and the `POLICY_KEY` / `POLICY_FORMAT` / `DIGEST_ALG` constants. No change to `Writer`, `Reader`, `Verifier`, `cbor`, or the record schema.
- Two golden vectors (`policy-permit`, `policy-deny`) exercise the convention and are held byte-identical across Rust, Python, and `gen_vectors.py`.
- Python callers build the same shape as a plain `payload["policy"]` dict; the field names and `"sha256:<hex>"` digest form are identical. A typed Python helper is a possible follow-up but not required — the shape is trivial in a dict.
- The threat model gains a note: a digest binds the decision to a policy **only if the policy artifact is retained and retrievable**. A digest of a document nobody kept proves nothing.

## Future direction (out of scope here)

- A `--require-policy` verify mode / a first-class v0.2 record key, if verifier-enforced policy provenance is ever needed.
- Aligning field names/extensions with the final LangChain RFC #35691 `policy_attestation` shape once it stabilises.
- A `deciding_rules` semantics profile (which rule-set counts as "deciding") — the RFC leaves this to profiles; so do we.

## Action items

- [x] `policy` module + typed API in `ogentic-audit-core`.
- [x] Convention documented in `docs/spec/v0.1.md`.
- [x] `policy-permit` / `policy-deny` golden vectors, wired into Rust + Python conformance.
- [x] Threat-model note on digest-binds-only-if-policy-retained.
