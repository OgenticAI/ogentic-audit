# ogentic-audit

[![CI](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)
[![Format v0.1](https://img.shields.io/badge/on--disk%20format-v0.1-informational)](docs/spec/v0.1.md)

HMAC-SHA256 chained, append-only audit log library. Court-defensible, tamper-evident, language-agnostic on-disk format.

> **Status:** v0.1.0 released. The on-disk format is specified in [`docs/spec/v0.1.md`](docs/spec/v0.1.md) and the wire bytes are pinned by [committed golden vectors](tests/vectors/v0.1). The format is the stable surface; the Rust / Python APIs follow semantic versioning from this tag forward. See [Status & versioning](#status--versioning).

## Why

Regulated industries and audit-grade AI tooling need an audit log that:

- **Cannot be silently rewritten** — every record is HMAC-chained to the previous, so any tamper is detectable. The verifier reports the exact `(segment, record_id)` of the first violation, with a structured evidence payload an auditor can act on.
- **Survives crashes** — append-only with atomic flush + `F_FULLFSYNC` on macOS; partial writes never produce a half-record. On reopen, the writer detects any torn tail (`len_trailer != len_prefix`) and truncates to the last fully-written record, surfacing a structured `RecoveryReport` to the caller.
- **Travels across languages** — the on-disk format is documented byte-by-byte, with [golden vectors](tests/vectors/v0.1) that conforming implementations MUST round-trip. v0.1 ships Rust + Python; the format is intentionally implementable in any language that has HMAC-SHA256.
- **Is court-defensible** — paired [threat model](docs/security/threat-model.md) and [court-defensibility brief](docs/legal/court-defensibility.md); the CLI ships a bit-reproducible `export --pdf` command for self-contained evidence packages.

## Components

- [`crates/ogentic-audit-core`](crates/ogentic-audit-core) — Rust core library (writer, reader, verifier, key handle, crash recovery)
- [`crates/ogentic-audit-cli`](crates/ogentic-audit-cli) — `ogentic-audit` CLI binary (`verify` / `show` / `head` / `export`)
- [`crates/ogentic-audit-keychain`](crates/ogentic-audit-keychain) — optional OS-keychain key source (macOS / Linux / Windows)
- [`crates/ogentic-audit-kms`](crates/ogentic-audit-kms) — optional KMS-backed key source (AWS KMS in v0.1; GCP / Azure in v0.2)
- [`python/ogentic_audit`](python/ogentic_audit) — PyO3-based Python bindings (`pip install ogentic-audit`)

## Quickstart

### Rust

Add to `Cargo.toml`:

```toml
[dependencies]
ogentic-audit-core = "0.1"
```

```rust
use ogentic_audit_core::{InMemoryKey, RecordInput, Writer, Verifier, PayloadValue};
use std::collections::BTreeMap;

fn main() -> anyhow::Result<()> {
    // 32 raw bytes; in real use load via ogentic-audit-keychain or a vault.
    let key = InMemoryKey::from_bytes([0u8; 32]);
    let session_id = [0u8; 16]; // UUIDv4 in real use

    let mut writer = Writer::open("./audit-logs", Box::new(key), session_id)?;
    let mut payload = BTreeMap::new();
    payload.insert("vault_id".into(), PayloadValue::Text("v-001".into()));
    writer.append(RecordInput {
        ts_wall: "2026-05-21T05:00:00.000Z".into(),
        ts_mono_delta: 0,
        actor: "user:alice".into(),
        event: "vault.unlocked".into(),
        payload,
        schema_version: 1,
    })?;
    writer.flush()?;
    drop(writer);

    // Verify the log end-to-end.
    let key = InMemoryKey::from_bytes([0u8; 32]);
    let verifier = Verifier::new(Box::new(key));
    let report = verifier.verify("./audit-logs")?;
    assert_eq!(report.compact_verdict(), "Verified");
    Ok(())
}
```

### Python

```sh
pip install ogentic-audit
```

```python
from ogentic_audit import Writer, Reader, KeyHandle, verify

key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")  # 64 hex chars

with Writer.open("./audit-logs", key=key) as w:
    w.append({"actor": "user:alice", "event": "vault.unlocked",
              "payload": {"vault_id": "v-001"}})

for record in Reader.open("./audit-logs"):
    print(record["record_id"], record["actor"], record["event"])

report = verify("./audit-logs", key=key)
assert report.ok
```

### CLI — quick start

#### macOS (Homebrew)

```sh
brew install ogenticai/tap/ogentic-audit
```

#### Linux / cross-platform (Cargo)

```sh
cargo install ogentic-audit
```

#### Codesigning status (v0.1.0)

macOS binaries are **sigstore-keyless-signed** (cosign + GitHub OIDC)
but **not** Apple Developer ID signed in v0.1.0. First launch on macOS
may show a Gatekeeper dialog — right-click → Open to bypass. Apple
Developer ID + notarization lands in v0.1.1.

#### Verify the sample log shipped with the project

The sample uses the public all-zeros fixture key; the CLI reads it
from `OGENTIC_AUDIT_KEY_HEX` under the default `--key-source=env`. Set
it first, then run the verify:

```sh
export OGENTIC_AUDIT_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000
ogentic-audit verify ./samples/matter-2024-CV-3047/matter-2024-CV-3047.log/ --summary
# ✓ Verified · 4 events · chain head 5c643f56
```

A tampered companion is also shipped — same four events with one byte
flipped inside record 2's HMAC field — so you can see a failing
verification end-to-end:

```sh
ogentic-audit verify ./samples/matter-2024-CV-3047-tampered/matter-2024-CV-3047.log/ --summary
# ✗ Verification failed · HmacMismatch at segment 0 record 2
echo $?
# 1
```

Exit codes (CI-friendly): `0` success, `1` verification failed, `2` I/O
error, `3` argument error, `64` clap usage error.

> The `samples/` directory ships inside the release tarball
> (`ogentic-audit-<target>.tar.gz`) and inside the source repo.
> `brew install` and `cargo install` users get the binary only; either
> download the tarball, or `git clone` the repo, to follow the demo
> block above against the shipped sample.

#### Verify cosign signatures on the released binaries

Every release artifact is sigstore-keyless-signed (cosign + GitHub
OIDC). The workflow uploads a split `.sig` + `.pem` pair alongside
each tarball/zip; the certificate anchors the signature back to the
GitHub Actions workflow that built it.

For the macOS arm64 build of v0.1.0:

```sh
cosign verify-blob \
  --certificate-identity "https://github.com/OgenticAI/ogentic-audit/.github/workflows/release-cli.yml@refs/tags/v0.1.0" \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --signature ogentic-audit-macos-arm64.tar.gz.sig \
  --certificate ogentic-audit-macos-arm64.tar.gz.pem \
  ogentic-audit-macos-arm64.tar.gz
```

Swap the artifact filename for the target you downloaded:
`ogentic-audit-macos-arm64.tar.gz`, `ogentic-audit-macos-x86_64.tar.gz`,
`ogentic-audit-linux-x86_64.tar.gz`, `ogentic-audit-linux-aarch64.tar.gz`,
or `ogentic-audit-windows-x86_64.zip`. Each ships with a sibling
`.sig` + `.pem`.

#### Daily-driver subcommands

```sh
# verify a vault's log (64 hex chars = 32 raw bytes)
export OGENTIC_AUDIT_KEY_HEX=$(openssl rand -hex 32)
ogentic-audit verify ./audit-logs            # exit 0 verified, 1 violation

# verify only segment 0 (useful for spot-checking a specific segment)
ogentic-audit verify ./audit-logs --segment 0

# machine-readable output (see "verify JSON output" below)
ogentic-audit verify ./audit-logs --format json

# pretty-print the last 100 records
ogentic-audit show ./audit-logs --from 0 --to 100

# spot-check the chain head
ogentic-audit head ./audit-logs --format json
```

#### verify JSON output (v0.2 shape — OGE-1063)

The `--format json` output uses `status` (not `verdict`) and `segments_verified`
(not `compact`). If you have automation that reads the old keys, update it:

| Old key | New key | Notes |
|---------|---------|-------|
| `verdict` | `status` | Values: `"ok"` or `"tampered"` |
| `compact` | removed | Use `status` instead |
| — | `segments_verified` | Count of segments walked |

Clean example:

```json
{
  "status": "ok",
  "format_version": 1,
  "segments_verified": 1,
  "log": { "segments_inspected": 1, "records_inspected": 1, ... }
}
```

Tampered example:

```json
{
  "status": "tampered",
  "format_version": 1,
  "segments_verified": 1,
  "violation": { "kind": "HmacMismatch", "segment_index": 0, "record_id": 2, ... },
  "additional_violations": [],
  "log": { ... }
}
```

Violation detail text (kind, message, coordinates) is written to **stderr**;
the JSON summary on **stdout** is clean for `jq`-based pipelines.

#### `--segment <id>` flag

Verify a single named segment. Useful for forensic spot-checks on large logs:

```sh
ogentic-audit verify ./audit-logs --segment 0          # verify segment 0 only
ogentic-audit verify ./audit-logs --segment 42         # verify segment 42 only
```

Exit codes for `--segment`:
- `0` — segment verified clean
- `1` — segment has a chain violation
- `2` — segment index `> 65535`, or the segment file does not exist in the log directory

## Design

The format is HMAC-SHA256 chained records framed inside per-segment files. Every record carries its `prev_hash` (the previous record's HMAC) inside the canonical-CBOR-encoded payload, and the segment header binds the genesis HMAC to the header bytes themselves. The verifier walks records, recomputes HMACs against the running chain, and short-circuits at the first deviation with structured evidence.

- **Hash:** HMAC-SHA256 (FIPS 198-1)
- **Encoding:** Canonical CBOR per RFC 8949 §4.2 (deterministic)
- **Segment header CRC:** CRC32 (IEEE 802.3)
- **Key fingerprint:** BLAKE3-256
- **Constant-time comparison:** [`subtle`](https://docs.rs/subtle) on HMAC and key_id

Full spec: [`docs/spec/v0.1.md`](docs/spec/v0.1.md). Architecture rationale: [`docs/adr/0001-on-disk-format.md`](docs/adr/0001-on-disk-format.md).

## Comparative positioning

| | ogentic-audit | Database audit logs (PostgreSQL, MySQL audit plugin) | syslog / journald | Blockchain (Hyperledger, Ethereum) |
|---|---|---|---|---|
| **Tamper evidence** | HMAC chained; every record links to previous | None — DB admin can rewrite | None — root can rewrite | Distributed consensus |
| **Crash safety** | Atomic per-record framing, F_FULLFSYNC, structured recovery report | Depends on the underlying storage engine | Best-effort; rotation can drop records | Block-level atomicity |
| **Cross-language** | Spec'd byte format + golden vectors | Vendor-specific | Vendor-specific (rsyslog vs systemd-journald) | EVM / chaincode-specific |
| **Independent verifier** | `verify` is a 10-line function; CLI ships a JSON report | Trust the DB | Trust the OS | Trust the chain |
| **Latency / cost** | Microseconds per record, no network | Microseconds; coupled to DB load | Microseconds | Seconds to minutes per record, gas fees |
| **Court-defensibility narrative** | First-class: paired threat model + brief + PDF export | Requires expert testimony per vendor | Requires expert testimony | Requires expert testimony + chain explanation |

**Use ogentic-audit when** you need a portable, tamper-evident audit log for a single product (a vault, an AI agent, a compliance event stream) and you want the option to swap implementations later without rewriting the wire format. **Skip ogentic-audit when** you need distributed consensus across multiple writers (use a blockchain) or you're fine extending the DB you already operate (just turn on its audit plugin).

## Court-defensibility

The legal narrative is documented in [`docs/legal/court-defensibility.md`](docs/legal/court-defensibility.md) and pairs with the [`threat model`](docs/security/threat-model.md). Three pieces in combination:

1. **Cryptographic invariants** — HMAC chain, constant-time compare, `subtle` crate; refuses to resume from in-place-tampered logs.
2. **Operational invariants** — append-only, F_FULLFSYNC on macOS, structured `RecoveryReport` for crash recovery, golden-vector conformance asserted in CI.
3. **Independent verification** — verifier is a thin function (Rust + Python today, format-spec'd for any language); not a black box.

> ⚖️ *The court-defensibility brief is currently engineering's read; the legal-team sign-off lands before v0.1.0 GA.*

## Status & versioning

- **Library API (Rust + Python):** alpha until v0.1.0. Pre-`v0.1.0`, the surface MAY change between alpha tags; we'll call out breaking moves in CHANGELOG.
- **On-disk format:** the segment-header layout, record schema, and HMAC chain are pinned by the [committed golden vectors](tests/vectors/v0.1). Once v0.1.0 ships, the format is frozen until v0.2 (which lands under `tests/vectors/v0.2/` so v0.1 readers continue to compile and pass).
- **MSRV:** Rust 1.85 (edition 2024).
- **Python:** 3.9 + (abi3 wheels per `pyo3`'s abi3-py39 feature).

## Choose your key source

Three options, all implementing the same `KeyHandle` trait:

| Source | Crate | Best for |
|--------|-------|----------|
| **In-memory** | `ogentic-audit-core` | Tests, CI, transient workloads |
| **OS keychain** | `ogentic-audit-keychain` | Desktop apps (macOS / Linux / Windows) |
| **KMS (server-side)** | `ogentic-audit-kms` | Server-side, containerised, multi-tenant deployments |

```rust,no_run
// KMS (server-side):
// let key = KmsKey::new(AwsKmsProvider::from_arn(arn).await?)?;
```

Full integration guide for the KMS option:
[`docs/integrations/server-side-kms.md`](docs/integrations/server-side-kms.md).

## Documentation

- [`docs/spec/v0.1.md`](docs/spec/v0.1.md) — language-agnostic on-disk format spec
- [`docs/spec/violation-report.md`](docs/spec/violation-report.md) — normative JSON schema for verifier output
- [`docs/security/threat-model.md`](docs/security/threat-model.md) — adversaries, invariants, accepted residual risk
- [`docs/security/key-rotation.md`](docs/security/key-rotation.md) — customer-facing rotation policy
- [`docs/legal/court-defensibility.md`](docs/legal/court-defensibility.md) — court-defensibility brief (draft)
- [`docs/adr/0001-on-disk-format.md`](docs/adr/0001-on-disk-format.md) — on-disk format rationale (ADR)
- [`docs/adr/0002-server-side-kms-key-sourcing.md`](docs/adr/0002-server-side-kms-key-sourcing.md) — KMS key sourcing rationale (ADR)
- [`tests/vectors/v0.1/README.md`](tests/vectors/v0.1/README.md) — golden-vector layout + procedure for adding new vectors
- [`docs/integrations/sotto-desktop.md`](docs/integrations/sotto-desktop.md) — embedding `ogentic-audit-core` inside the Sotto Desktop Tauri shell
- [`docs/integrations/server-side-kms.md`](docs/integrations/server-side-kms.md) — KMS integration guide (AWS KMS `GenerateMac`)
- [`examples/sotto-desktop-tauri/`](examples/sotto-desktop-tauri/) — minimal Tauri sample code

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Security

- [`SECURITY.md`](SECURITY.md) — responsible-disclosure address for vulnerability reports. **Do not** open public issues for tamper-evidence, HMAC, or cryptographic findings; email the listed address.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md). The project plan and open tickets live on [Linear](https://linear.app/ogenticai/project/ogentic-audit-oss-30ea638d6f03/overview).
