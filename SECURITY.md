# Security Policy

`ogentic-audit` is sold on tamper-evidence. We take findings against the HMAC chain, the on-disk format, the verifier, or any cryptographic invariant **very seriously** and will treat them as priority-zero work.

## Reporting a vulnerability

**Do not open a public issue or pull request for security findings.**

Email **security@ogenticai.com** with:

- A description of the issue and the affected component (core, CLI, keychain, Python bindings, on-disk format spec).
- The version (commit SHA or release tag) you tested against.
- Reproduction steps, ideally including a minimal test vector or PoC.
- Your assessment of impact (data exposure, chain forgery, denial of verification, etc.).
- Whether you would like public credit when the fix ships.

We will acknowledge receipt within **3 business days** and aim to provide an initial triage within **7 business days**. Coordinated-disclosure timelines are typically **90 days** from the date of acknowledgement, shorter if the issue is being actively exploited and longer by mutual agreement when a fix requires a format change.

## Scope

In scope:

- The Rust crates under `crates/`.
- The Python bindings under `python/`.
- The on-disk format specification under `docs/spec/`.
- Cross-language golden vectors under `tests/vectors/`.

Out of scope at v0.1 (documented in [`docs/security/threat-model.md`](docs/security/threat-model.md)):

- Adversaries with live access to the running process or HMAC key in memory.
- Network-level adversaries — the v0.1 library performs no network I/O.
- Side-channel attacks against HMAC-SHA256 itself.
- Multi-tenant server deployments (deferred to a server-side roadmap).

A finding outside the v0.1 threat model is still welcome — we may not classify it as a vulnerability, but we will document it and credit you if you'd like.

## Supported versions

`ogentic-audit` is pre-1.0. Until v0.1.0 is tagged, only the `main` branch is supported. After v0.1.0:

| Version | Supported |
|---------|-----------|
| `0.1.x` | Yes — security fixes backported until v0.2.0 + 6 months |
| `< 0.1` | No |

## PGP

A PGP key for `security@ogenticai.com` will be published alongside the v0.1.0 release. Until then, plain email is acceptable; if you require encrypted communication before then, mention it in your initial mail and we will coordinate a key out of band.
