# ogentic-audit

[![CI](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/OgenticAI/ogentic-audit/actions/workflows/ci.yml)
[![License: Apache-2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](LICENSE)

HMAC-SHA256 chained, append-only audit log library. Court-defensible, tamper-evident, language-agnostic on-disk format.

> **Status:** v0.1 in development. The on-disk format is not yet stabilized — see [`docs/spec/`](docs/spec/) once published. Do not depend on this library for production data until v0.1.0 is tagged.

## Why

Regulated industries and audit-grade AI tooling need an audit log that:

- **Cannot be silently rewritten** — every record is HMAC-chained to the previous, so any tamper is detectable.
- **Survives crashes** — append-only with atomic flush + fsync; partial writes never produce a half-record.
- **Travels across languages** — the on-disk format is documented and language-agnostic. Rust core, Python bindings, more to follow.
- **Is court-defensible** — paired [threat model](docs/security/threat-model.md) and [court-defensibility brief](docs/legal/court-defensibility.md); CLI exports a self-contained PDF for attorneys.

## Components

- `crates/ogentic-audit-core` — Rust core library (writer, reader, verifier, key handle)
- `crates/ogentic-audit-cli` — `ogentic-audit` CLI binary
- `crates/ogentic-audit-keychain` — optional OS-keychain key source (macOS / Linux / Windows)
- `python/ogentic_audit` — PyO3-based Python bindings

## Quickstart

Code, examples, and prebuilt binaries arrive with v0.1.0. See the [project plan](https://linear.app/ogenticai/project/ogentic-audit-oss-30ea638d6f03/overview) for what's landing first.

## License

Apache License 2.0 — see [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).

## Security & legal

- [`docs/security/threat-model.md`](docs/security/threat-model.md) — adversaries, invariants, accepted residual risk, and the security boundary of the v0.1 design.
- [`docs/legal/court-defensibility.md`](docs/legal/court-defensibility.md) — engineering's brief on how the v0.1 design supports the "court-defensible" positioning. *Draft, awaiting legal review.*
- [`SECURITY.md`](SECURITY.md) — responsible-disclosure address for vulnerability reports. **Do not** open public issues for tamper-evidence, HMAC, or cryptographic findings.

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md) and [`CODE_OF_CONDUCT.md`](CODE_OF_CONDUCT.md).
