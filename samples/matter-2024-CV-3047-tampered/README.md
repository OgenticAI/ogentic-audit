# Sample — `matter-2024-CV-3047-tampered`

The tamper-evidence companion to
[`../matter-2024-CV-3047/`](../matter-2024-CV-3047/README.md). Same four
synthetic civil-litigation events, same public all-zeros key, same
session — then a **single byte is flipped inside record 2's HMAC field**.

The verifier MUST reject the chain.

## What was flipped

- **Segment:** 0
- **Record id:** 2 (`llm.cloud-approved`)
- **Region:** HMAC (the 32-byte HMAC-SHA256 trailing the canonical-CBOR
  payload, before the `len_trailer`)
- **Byte offset within region:** 0 (the first byte of the HMAC)
- **Operation:** `byte_xor` with `0xff`

That works out to file byte 788 of `audit-0000.cbor` changing from `0x18`
to `0xe7`. The rest of the file is byte-identical to the clean sample.

## Expected output

```sh
export OGENTIC_AUDIT_KEY_HEX=0000000000000000000000000000000000000000000000000000000000000000
ogentic-audit verify ./matter-2024-CV-3047.log/ --summary
# ✗ Verification failed · HmacMismatch at segment 0 record 2
echo $?
# 1
```

Drop `--summary` to see the full structured violation report (`kind:
HmacMismatch`, `segment: 0`, `record_id: 2`, byte offset, and message).

## Regenerate

```sh
python3 tools/gen_vectors.py --samples matter-2024-CV-3047-tampered/matter-2024-CV-3047.log
```

The tamper is encoded in `inputs.json` under `post_process` —
deterministic, reproducible, no randomness.
