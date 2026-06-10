# Sample — `matter-2024-CV-3047`

A homepage-grade synthetic audit log demonstrating the canonical four-event
flow for a civil-litigation matter under Sotto Desktop. **All of it is
fabricated** — the case number is invented, the deposition filename is
invented, the actors are placeholders, and the HMAC key is the public
all-zeros fixture key (`OGENTIC_AUDIT_KEY_HEX=` + 64 zeros).

This sample is what the [sottotrust.ai](https://sottotrust.ai/) homepage
demo points at. It is **not** a conformance test vector — those live under
[`tests/vectors/v0.1/`](../../tests/vectors/v0.1/) and are gated on
byte-stability by `tools/gen_vectors.py --check` in CI.

## The four events

| # | event | actor | payload |
|---|---|---|---|
| 1 | `vault.unlocked` | `user:counsel-of-record` | `{"matter_id": "2024-CV-3047"}` |
| 2 | `file.opened` | `user:counsel-of-record` | `{"filename": "plaintiff-deposition-2024-08-15.pdf"}` |
| 3 | `llm.cloud-approved` | `user:counsel-of-record` | `{"model": "gpt-4o", "approval_reason": "summarize witness statement"}` |
| 4 | `audit.exported` | `user:counsel-of-record` | `{"export_format": "pdf"}` |

All four records carry the same `session_id` (zero UUID) and `key_id`
(BLAKE3-256 of the all-zeros key). Timestamps are spread across 30 seconds
of `2026-06-10T14:00:00Z`.

## Verify it yourself

```sh
export OGENTIC_AUDIT_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000
ogentic-audit verify ./matter-2024-CV-3047.log/ --summary
# ✓ Verified · 4 events · chain head 5c643f56
```

Drop `--summary` for the full multi-line text report.

## Tampered companion

See [`../matter-2024-CV-3047-tampered/`](../matter-2024-CV-3047-tampered/)
for an identical log with one byte flipped — the verifier rejects it with
`HmacMismatch` at `(segment 0, record 2)`. That's the tamper-evidence
demo.

## Regenerate

The bytes are produced deterministically by the canonical generator:

```sh
python3 tools/gen_vectors.py --samples matter-2024-CV-3047/matter-2024-CV-3047.log
```

Re-running the generator with the same `inputs.json` MUST produce
byte-identical `audit-0000.cbor` and `chain.json` files. Drift is a bug
in either the generator or the writer.
