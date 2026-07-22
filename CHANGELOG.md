# Changelog

All notable changes to `ogentic-audit` are recorded here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
On-disk format versions follow the spec in [`docs/spec/`](docs/spec/);
library APIs follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **MCP tool-call audit middleware (OGE-1721).** A reference integration
  that turns MCP server tool-call events into chained, tamper-evident
  records — the "drop-in HMAC hash-chain audit trail for MCP tool-call
  logs" promised to compliance customers. No new record format, no new
  crate: a tool-call is an ordinary record with a conventional `payload`
  shape.
  - `ogentic_audit.mcp`: `audit_tool_call(writer, tool=, arguments=,
    result=/error=, policy=, redact=)` appends one chained record;
    `MCPAuditMiddleware.instrument(...)` decorates a tool function so every
    call is recorded (result on success, exception on failure, then
    re-raised). Arguments/results are JSON-summarised, redactable, and
    size-capped — the log protects integrity, not confidentiality.
  - Composes with policy attestation (OGE-1674): pass an
    `ogentic-audit-policy/v1` dict as `policy=` to record *why* a call was
    permitted (or denied — a denied call is still audited).
  - `docs/integrations/mcp.md` (quick-start, redaction, policy, verify,
    EU AI Act Art. 12 / SOC 2 CC7 / ISO 42001 mapping) and a runnable
    `examples/mcp-audit/` demo, covered end-to-end by `test_mcp.py`.

- **Policy attestation (OGE-1674).** Records can now carry *what rule
  permitted an action*, not just that it happened — the difference between
  a tamper-evident log and a compliance artifact, per the
  [NousResearch/hermes-agent#487](https://github.com/NousResearch/hermes-agent/issues/487)
  / [LangChain RFC #35691](https://github.com/langchain-ai/langchain/issues/35691)
  discussion.
  - A documented `payload["policy"]` convention (`ogentic-audit-policy/v1`)
    holding `decision` (`permit`/`deny`), a caller-computed `digest`
    (`"sha256:<hex>"`), and optional `policy_id` / `deciding_rules`. Because
    it rides inside the already-signed `payload`, it is tamper-evident and
    chain-linked — **no on-disk format change**, `FORMAT_VERSION` stays
    `0x0001`, all existing golden vectors unchanged.
  - `ogentic_audit_core::policy`: `PolicyAttestation`, `PolicyDecision`,
    `PolicyError`, with a typed builder (`.with_policy_id`,
    `.with_deciding_rules`), `.attach(&mut payload)`, and `from_payload`.
  - The digest is **caller-computed and opaque** — the library never
    parses, canonicalizes, or hashes the policy. This dissolves the
    CBOR-vs-JCS canonicalization question: canonicalize a JSON policy with
    RFC 8785, a CBOR one with RFC 8949, record the result. Documented in
    [ADR-0003](docs/adr/0003-policy-attestation-payload-convention.md).
  - Golden vectors `policy-permit` / `policy-deny`, held byte-identical
    across Rust, Python, and `gen_vectors.py`.
  - Threat-model note: a digest binds the decision to a policy only if that
    policy artifact is retained and retrievable.
  - Distinct from the `attestation` field reserved for v0.2 external
    witnesses (ADR-0001) — the payload key is `policy`, no namespace clash.

- **Checkpoint anchoring in the Python binding (OGE-1673).** Brings the
  PyO3 bindings to parity with the Rust core's checkpoint support, so a
  Python compliance job can ask the one question internal verification
  cannot — did the log I'm looking at extend the head I saw before?
  - `verify(log_dir, key, checkpoint=...)` accepts a checkpoint dict or a
    path to a `ogentic-audit-checkpoint/v1` JSON file. A rewrite surfaces
    as `CheckpointMismatchError` (or `report.verdict_kind ==
    "CheckpointMismatch"`); a truncation as `CheckpointTruncatedError`.
  - `checkpoint(log_dir, key, *, observed_at=None, out=None)` emits a
    chain-head pin (verifies first; refuses a broken chain), defaulting
    `observed_at` to the current UTC time and optionally writing `out`.
  - `CheckpointMismatchError` / `CheckpointTruncatedError` (under
    `VerificationFailed`) and `CheckpointKeyMismatchError` (under
    `ArgumentError` — a wrong-file mistake is not tamper evidence). `.pyi`
    stubs updated.
  - A cross-language parity test derives the *same* checkpoint from the
    committed `single-record` golden vector's `chain.json` on both sides
    and asserts the Rust core and the Python binding reach the same
    verdict (`python_parity_*` in `checkpoint_anchor.rs`;
    `test_parity_*` in `test_checkpoint.py`).

- **Keychain integration tests on real OS stores (OGE-478, closes
  OGE-431 AC 7).** `store` / `load` / `load_or_generate` / `delete` now run
  end-to-end against the macOS Keychain, Linux Secret Service, and Windows
  Credential Manager in CI on every PR — previously only compiled on those
  platforms, with the macOS suite `#[ignore]`-gated. The tests skip unless
  `OGENTIC_KEYCHAIN_CI=1` so a developer's `cargo test` never touches their
  login keychain; each CI job provisions an ephemeral, unlocked store and
  runs `--test-threads=1`. A `Drop`-based `CleanupGuard` removes entries
  even when a test panics.

- **Checkpoint anchoring (OGE-1671).** Chain verification is
  self-referential: it proves a log is consistent with itself, which is
  also true of a log that someone holding the HMAC key truncated and
  re-chained. A checkpoint is a `(segment, record_id, hmac)` triple
  observed earlier and held outside the log, which makes that rewrite
  visible. Motivated by the critique in
  [NousResearch/hermes-agent#487](https://github.com/NousResearch/hermes-agent/issues/487).
  - `ogentic-audit checkpoint <log_dir> [--out FILE]` — emit the current
    head as `ogentic-audit-checkpoint/v1` JSON. Refuses to emit for a log
    that does not verify, so a break cannot be laundered into an anchor.
  - `ogentic-audit verify --checkpoint <FILE>` — additionally prove the
    log still extends that head.
  - Two new violation kinds: `CheckpointMismatch` (history rewritten) and
    `CheckpointTruncated` (history cut), both specified in
    [`docs/spec/violation-report.md`](docs/spec/violation-report.md).
  - `VerifyOptions::checkpoint` in the core crate; `VerifyError::CheckpointKeyMismatch`
    for a checkpoint presented against a different log (exit 3 — an
    operator mistake, deliberately not reported as tamper evidence).
  - `cargo run -p ogentic-audit-core --example rewrite_attack` — runnable
    demonstration of the attack and its detection.
  - **No on-disk format change.** The checkpoint lives outside the log;
    `FORMAT_VERSION` stays `0x0001` and all golden vectors are unchanged.

### Changed

- **`keyring` 3 → 4 (OGE-478).** Real macOS keychain integration testing
  was impossible on 3.x: from an unsigned `cargo test` binary `set_secret`
  returned `Ok` but the immediate `get_secret` returned `NoEntry` (the OS
  itself was fine — the `security` CLI round-tripped against the same
  keychain). keyring 4's redesigned Apple backend fixes the round-trip.
  The `v1` default feature keeps the `Entry` API source-compatible, so the
  `KeychainKey` backend is unchanged; on Linux the `v1` Secret-Service
  store is the pure-Rust `zbus` client, so no `libdbus`/`libsecret` system
  package is required.

- README no longer claims properties the code does not have (OGE-1672):
  the tamper-evidence claim is qualified inline (chained HMACs detect
  edits by a non-keyholder; a keyholder rewrite needs a checkpoint), the
  status line reflects 0.2.0, and PyPI / crates.io / Homebrew install
  paths are marked as pending rather than advertised as working —
  neither package is published yet (OGE-1407).

### Note for downstream verifiers

`ViolationKind` gained two variants. Exhaustive `match` statements over it
will need a new arm. Independent implementations that do not support
checkpoints remain conformant: the new kinds are only emitted when a
checkpoint is supplied.

## [0.2.0] - 2026-06-25

### Breaking

- `--format json` output shape changed: `"verdict"` and `"compact"` keys removed; replaced by `"status": "ok"|"tampered"` and `"segments_verified"`. Scripts that parse the old shape must update their field references. (OGE-1063, #48)

### Added

- `ogentic-audit verify --segment <id>`: verify a single segment by zero-based index, returning only that segment's result in both text and JSON output formats. (OGE-1063, #48)
- 17 new integration tests covering `--segment`, JSON shape, stderr routing, and multi-segment edge cases. (#48)

### Fixed

- Tamper violation detail now correctly routes to stderr in text format (was incorrectly mixed with stdout). (OGE-1063, #48)
- RUSTSEC-2026-0186: `memmap2` bumped to 0.9.11 to address security advisory. (#48)

### Added

- **`ogentic-audit-kms` 0.2.0-pre (OGE-460):** optional KMS-backed
  `KeyHandle`.  AWS KMS `GenerateMac` (HMAC_SHA_256) is the v0.1 default;
  key material stays HSM-resident.  Envelope-encrypted local-HMAC mode
  is reserved via `KmsKey::with_envelope_mode` (returns `Config` error
  until OGE-603, v0.2).
  Crate surface: `KmsKey<P>`, `KmsProvider` trait, `AwsKmsProvider`,
  `KmsError` (with `is_retryable()`).  `Display`/`Debug` redact the ARN.
  `key_id` is derived from the provider descriptor via BLAKE3-256 (not
  key material — transparent to OGE-441 golden vectors).
  CI: `kms-integration.yml` localstack job (HMAC_256 key seeding +
  adversarial isolation suite); dormant `kms-smoke.yml` for real-AWS
  smoke tests (activates when `AWS_KMS_SMOKE_ROLE_ARN` repo var is set).

### Documentation

- `docs/adr/0002-server-side-kms-key-sourcing.md` — new ADR accepted
  2026-06-04; documents `kms` as optional feature, `KmsProvider` trait,
  `GenerateMac` as v0.1 primitive, `key_id` projection, explicit axiom
  changes (no-network-IO broken for kms consumers; signing!=verifying
  principal), failure mode, and what is deferred to v0.2.
- `docs/integrations/server-side-kms.md` — full integration guide:
  CloudFormation snippet, minimum IAM policy, Rust quickstart, Node.js
  interim approach, GenerateMac-vs-envelope decision matrix, error
  taxonomy, per-org isolation pattern, observability guidance, key
  rotation recipe, CloudTrail as chain-of-custody artefact.
- `docs/security/threat-model.md` — new `## Server-side / KMS` section
  with explicit axiom-change notes: no-network-IO invariant broken for
  kms feature consumers; signing!=verifying axiom workaround; new failure
  mode (KMS unavailable → panic); what KMS adds/doesn't add; timing
  side-channel claim retained.
- `docs/legal/court-defensibility.md` — new `## Server-side / KMS-backed
  deployments` section: CloudTrail as parallel chain-of-custody artefact;
  FRE 902(13)/(14) certification scope expansion to two systems; concrete
  caveat on CloudTrail retention; what KMS adds/doesn't add.
- `docs/security/key-rotation.md` — `## Rotation in multi-tenant /
  server-side deployments` section continued: new ARN = rotation,
  AWS KMS scheduled-deletion semantics (7–30 day window), verification
  recipe for pre/post rotation logs.
- `docs/spec/v0.1.md` — `key_id` terminology table extended with KMS
  descriptor-based projection note (transparent to OGE-441 vectors;
  links to ADR-0002).
- `crates/ogentic-audit-kms/README.md` — crate README with quickstart,
  feature-flag table, MSRV note, security summary, link to integration
  guide.

## [0.1.0] — 2026-06-13

First public release. On-disk format frozen at `0x0001`.

### Breaking changes

- **Package renamed:** the crates.io publish name moved from
  `ogentic-audit-cli` to `ogentic-audit`. Anyone with `cargo install
  ogentic-audit-cli` in a script, Dockerfile, or shell history must
  switch to `cargo install ogentic-audit`; the old name will not
  resolve to a v0.1.0 (or later) crate. The installed **binary** name
  is unchanged (`ogentic-audit` on `$PATH` either way), and the
  workspace member directory (`crates/ogentic-audit-cli/`) is also
  unchanged.

### Changed (publication-readiness)

- **Renamed crates.io package** `ogentic-audit-cli` → `ogentic-audit` so
  `cargo install ogentic-audit` resolves to the CLI binary. The binary
  itself was already named `ogentic-audit`; only the crates.io publish
  name changes. The workspace member directory (`crates/ogentic-audit-cli/`)
  is unchanged.
- **`verify --summary` flag** — single-line verdict suitable for the
  homepage demo (`✓ Verified · N events · chain head <prefix>`) or for
  embedding in CI status output. Failure form is
  `✗ Verification failed · <Kind> at segment N record N`. Mutually
  exclusive with `--format json`.
- **Sample fixtures under `samples/`** — homepage-grade synthetic logs:
  - `samples/matter-2024-CV-3047/matter-2024-CV-3047.log/` — four-event
    civil-litigation flow (vault.unlocked → file.opened →
    llm.cloud-approved → audit.exported); verifies clean.
  - `samples/matter-2024-CV-3047-tampered/matter-2024-CV-3047.log/` —
    same four events with one byte flipped inside record 2's HMAC field;
    verifier rejects with `HmacMismatch`.
  Both fixtures are produced deterministically by `tools/gen_vectors.py
  --samples`. They are NOT conformance vectors; those remain under
  `tests/vectors/v0.1/`.
- **DCO enforcement** — `.github/workflows/dco.yml` blocks PRs to `main`
  whose commits lack a `Signed-off-by:` trailer.
- **README rewrite** of the CLI quickstart so the install + verify block
  is copy-paste-true verbatim with the sottotrust.ai homepage demo.
- **macOS codesigning posture (v0.1.0):** binaries ship
  sigstore-keyless-signed via cosign + GitHub OIDC, but **not** Apple
  Developer ID signed. First launch may surface a Gatekeeper dialog.
  Apple Developer ID + notarization lands in v0.1.1.

### Added

- **Rust core** (`ogentic-audit-core`):
  - HMAC-SHA256 chained, append-only Writer with atomic flush
    (`F_FULLFSYNC` on macOS), segment rollover, and crash recovery.
  - Reader (sequential iterator + indexed seek; cooperative
    tail-watching with a live writer).
  - Verifier (HMAC + chain integrity; structured violation evidence).
  - Crash-recovery scan: on reopen, repair torn tails or refuse to
    extend a tampered log. `RecoveryReport` surfaced to callers.
  - Canonical CBOR encoder + decoder (RFC 8949 §4.2).
  - `KeyHandle` trait + in-memory implementation with constant-time
    HMAC + key_id comparison via `subtle`.
- **OS keychain backend** (`ogentic-audit-keychain`): macOS Keychain,
  Linux Secret Service, Windows Credential Manager via `keyring 3`.
- **Python bindings** (`ogentic-audit` on PyPI): PyO3 wrapper exposing
  `KeyHandle` / `Writer` / `Reader` / `verify` with Pythonic context
  managers, iterators, typed exception hierarchy, and `.pyi` stubs.
  abi3-py39 wheels for Linux (x86_64 + aarch64 manylinux_2_28),
  macOS (arm64 + x86_64), and Windows (x86_64).
- **CLI** (`ogentic-audit`): `verify` / `show` / `head` / `export
  --pdf` / `version`. Disciplined exit codes (0/1/2/3/64). Bit-
  reproducible PDF export for court submissions.
- **Court-defensibility narrative**: paired threat model + legal brief
  + bit-reproducible PDF export. Verifier ships a normative JSON
  schema for violation reports.
- **Conformance gates**: 6 v0.1 golden vectors with Rust + Python
  verifier parity; `gen_vectors.py --check` blocks merge on drift;
  property-based round-trip suite (1024+ cases per CI run);
  exhaustive single-byte tamper matrix; 100-iteration randomized
  crash-recovery stress tests.

### Documentation

- On-disk format spec (`docs/spec/v0.1.md`)
- Violation-report schema (`docs/spec/violation-report.md`)
- Threat model (`docs/security/threat-model.md`)
- Key-rotation policy (`docs/security/key-rotation.md`)
- Court-defensibility brief (`docs/legal/court-defensibility.md`)
- On-disk format ADR (`docs/adr/0001-on-disk-format.md`)
- Sotto Desktop integration guide (`docs/integrations/sotto-desktop.md`)
- Homebrew formula stub (`docs/integrations/homebrew-formula.md`)
- API reference: rustdoc on docs.rs + Sphinx on Read the Docs

### Format / spec promises

- The v0.1 on-disk format is **frozen** at `0x0001`. Subsequent
  changes that affect bytes on disk increment to `0x0002` and land
  under `tests/vectors/v0.2/`. v0.1 readers continue to compile and
  pass against v0.1 vectors indefinitely.
- The library APIs (Rust + Python) are alpha until v0.1.0 is tagged;
  after the tag they follow semver (breaking changes increment
  major version).

[Unreleased]: https://github.com/OgenticAI/ogentic-audit/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/OgenticAI/ogentic-audit/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/OgenticAI/ogentic-audit/releases/tag/v0.1.0
