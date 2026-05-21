# Your first audit log

Five-minute walkthrough: open a writer, append a record, read it back, verify it.

## 1. Install

```sh
pip install ogentic-audit
```

## 2. Generate a key

The library never generates keys for you — you bring the 32 bytes. Two common patterns:

### Env var (development)

```sh
export OGENTIC_AUDIT_KEY_HEX=$(openssl rand -hex 32)
```

### OS Keychain (production / Sotto Desktop)

```python
from ogentic_audit import KeyHandle
key = KeyHandle.from_keychain("my-app", "default")
```

The keychain backend stores the bytes under your app's name; the next call returns the same key.

## 3. Open a writer + append

```python
import uuid
from ogentic_audit import KeyHandle, Writer

key = KeyHandle.from_env("OGENTIC_AUDIT_KEY_HEX")
session_id = uuid.uuid4().hex  # 32 hex chars

with Writer.open("./audit-logs", key=key, session_id_hex=session_id) as w:
    w.append({
        "actor": "user:alice",
        "event": "vault.unlocked",
        "payload": {"vault_id": "v-001"},
    })
```

The `with` block flushes any buffered writes to disk (with `F_FULLFSYNC` on macOS) on exit, so the record is durable even if your process crashes immediately after.

## 4. Read records back

```python
from ogentic_audit import Reader

for record in Reader.open("./audit-logs"):
    print(record["record_id"], record["actor"], record["event"])
```

Records are dicts with the shape documented in [`Record`](api.md#record).

## 5. Verify the chain

```python
from ogentic_audit import verify

report = verify("./audit-logs", key=key)
assert report.ok
print(report.compact)  # "Verified"
```

If anyone tampered with the on-disk bytes between step 3 and now, `report.ok` will be `False` and `report.violation` will tell you exactly which record + byte offset failed.

## 6. Handle violations precisely

```python
from ogentic_audit import HmacMismatchError, verify

try:
    verify("./audit-logs", key=key, raise_on_violation=True)
except HmacMismatchError as e:
    # The specific failure mode. Other variants exist for ChainBreak,
    # MissingRecord, RecordCorrupt, HeaderCorrupt, KeyIdMismatch,
    # SegmentDiscontinuity, TimestampError, SchemaError.
    log_incident(str(e))
```

## What's next

- The [API reference](api.md) catalogs every exported name.
- The [GitHub README](https://github.com/OgenticAI/ogentic-audit) has the same flow in Rust + the CLI.
- The [on-disk format spec](https://github.com/OgenticAI/ogentic-audit/blob/main/docs/spec/v0.1.md) is the authoritative description of the bytes on disk — independently implementable in any language that has HMAC-SHA256.
