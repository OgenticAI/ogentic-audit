# API reference

```{eval-rst}
.. automodule:: ogentic_audit
   :members:
   :undoc-members:
   :show-inheritance:
```

## Module-level functions

```{eval-rst}
.. autofunction:: ogentic_audit.format_version
.. autofunction:: ogentic_audit.core_version
.. autofunction:: ogentic_audit.verify
```

## Classes

### `KeyHandle`

```{eval-rst}
.. autoclass:: ogentic_audit.KeyHandle
   :members:
```

### `Writer`

```{eval-rst}
.. autoclass:: ogentic_audit.Writer
   :members:
   :special-members: __enter__, __exit__
```

### `Reader`

```{eval-rst}
.. autoclass:: ogentic_audit.Reader
   :members:
   :special-members: __iter__
```

### `Record`

The `dict[str, Any]` shape every iterator and seek call returns. Documented as a `TypedDict` in `python/ogentic_audit/__init__.pyi`.

| Key | Type | Notes |
|-----|------|-------|
| `segment_index` | `int` | Which `audit-NNNN.cbor` segment the record lives in |
| `record_id` | `int` | Monotonic per segment, starts at 0 |
| `ts_wall` | `str` | RFC 3339 UTC, millisecond precision |
| `ts_mono_delta` | `int` | Milliseconds since session start (monotonic clock) |
| `session_id_hex` | `str` | 32-char hex of the UUIDv4 session id |
| `actor` | `str` | Implementation-defined (`user:alice`, `system:audit`, …) |
| `event` | `str` | `category.action` tag (`vault.unlocked`, `shield.classified`) |
| `payload` | `dict[str, Any]` | Event-specific; only int/str/bool/bytes/None/dict/list values |
| `key_id_hex` | `str` | BLAKE3-256 fingerprint of the signing key |
| `schema_version` | `int` | Payload schema version |
| `prev_hash` / `prev_hash_hex` | `bytes` / `str` | HMAC of the preceding record |
| `hmac` / `hmac_hex` | `bytes` / `str` | HMAC of this record's payload |

### `VerifyReport`

```{eval-rst}
.. autoclass:: ogentic_audit.VerifyReport
   :members:
```

## Exception hierarchy

```
OgenticAuditError(Exception)
├── IoFailure
├── ArgumentError
├── RecoveryError
└── VerificationFailed
    ├── ChainBreakError
    ├── HmacMismatchError
    ├── MissingRecordError
    ├── RecordCorruptError
    ├── HeaderCorruptError
    ├── KeyIdMismatchError
    ├── SegmentDiscontinuityError
    ├── TimestampError
    └── SchemaError
```

Catch `OgenticAuditError` for any binding-emitted error; subclass for precise handling.
