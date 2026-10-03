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
.. autofunction:: ogentic_audit.checkpoint
.. autofunction:: ogentic_audit.attest_release
.. autofunction:: ogentic_audit.verify_release
.. autofunction:: ogentic_audit.log_format
```

`verify` reads the log's format before it uses any key. A signed log
(format `0x0002`) takes the signer's public key, obtained from the signer:
`public_key=`, `key_fingerprint=` or `trust=` (an OpenSSH `allowed_signers`
file), plus `statements=` and `revocations=`, and returns a
`SignedVerifyReport`. Without a key its verdict is `"SelfConsistent"` and
`.ok` is `False`. An HMAC log (format `0x0001`) takes `key=` and returns a
`VerifyReport`; passing it a public key raises `HmacLogError`.

From a shell, `python -m ogentic_audit verify …` and
`python -m ogentic_audit verify-release …` print the same report and exit
with the same codes as the `ogentic-audit` command-line tool.

## Classes

### `SigningKey`

An Ed25519 signing key for signed logs and releases. `generate()`,
`from_seed(bytes)`, `from_keychain(service, account, create=False)`,
`create_in_keychain(service, account)`; `public_key_openssh()`,
`public_key_pem()`, `public_key_hex()`, `fingerprint()` (16 groups of 4 hex
digits: publish this), `fingerprint_openssh()`. The private key never leaves
the object.

### `SignedVerifyReport` and `ReleaseReport`

```{eval-rst}
.. autoclass:: ogentic_audit.SignedVerifyReport
   :members:
.. autoclass:: ogentic_audit.ReleaseReport
   :members:
```

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
├── SignerNotPinnedError        (a signed log checked without a key: not verified, not tampered)
└── VerificationFailed
    ├── SignatureInvalidError, UntrustedSignerError, RevokedKeyError, RetiredKeyError,
    │   TransitionEquivocationError, AlgorithmMismatchError, UnsupportedAlgorithmError,
    │   LogIdMismatchError, SealedLogExtendedError, CheckpointForDifferentLogError,
    │   FormatDowngradeError, AttestationMissingError, AttestationMalformedError,
    │   ReleaseIdMismatchError, FileMissingError, FileAlteredError, UnattestedFileError
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

`HmacLogError` subclasses `ArgumentError`. An unknown violation kind raises
`VerificationFailed` itself, so a handler written today fails closed on a
kind added later.

Catch `OgenticAuditError` for any binding-emitted error; subclass for precise handling.
