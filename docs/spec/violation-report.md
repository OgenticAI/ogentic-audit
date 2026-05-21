# ogentic-audit — Violation report shape, v0.1

**Status:** Normative (companion to [`v0.1.md`](v0.1.md))
**Tracks:** [OGE-461 (F3 closeout)](https://linear.app/ogenticai/issue/OGE-461) — consumed by [OGE-437 (R3 Verifier)](https://linear.app/ogenticai/issue/OGE-437) and [OGE-441 (Q2 cross-language vectors)](https://linear.app/ogenticai/issue/OGE-441)
**Last updated:** 2026-05-10

This document defines the JSON shape a verifier emits when reading an `ogentic-audit` log. Conforming implementations — Rust core, Python bindings, third-party verifiers — MUST emit reports byte-identical to this shape so that auditors, attorneys, and downstream tooling can rely on a stable interchange format without coupling to a specific implementation.

For human-language semantics, see [`v0.1.md` § Violation taxonomy](v0.1.md#violation-taxonomy). For the on-disk format, see [`v0.1.md`](v0.1.md). For the threat model behind each violation, see [`../security/threat-model.md`](../security/threat-model.md).

## Top-level shape

A verifier emits exactly one report per log it inspects:

```json
{
  "format_version": 1,
  "verdict": "Verified",
  "log": {
    "log_dir": "<path>",
    "key_id_hex": "<64-hex>",
    "segments_inspected": 3,
    "records_inspected": 9,
    "first_segment_index": 0,
    "last_segment_index": 2,
    "final_hmac_hex": "<64-hex>"
  },
  "violation": null
}
```

When the chain is intact, `verdict` is `"Verified"` and `violation` is `null`.

When the chain fails, `verdict` is `"Violation"` and `violation` is non-null:

```json
{
  "format_version": 1,
  "verdict": "Violation",
  "log": {
    "log_dir": "<path>",
    "key_id_hex": "<64-hex>",
    "segments_inspected": 1,
    "records_inspected": 2,
    "first_segment_index": 0,
    "last_segment_index": 0,
    "final_hmac_hex": null
  },
  "violation": {
    "kind": "HmacMismatch",
    "location": { ... },
    "evidence": { ... },
    "message": "<human-readable, ≤200 chars>"
  }
}
```

`final_hmac_hex` is the chain head as known *up to* the violation point — null if the violation occurred at or before the first record. `records_inspected` counts every record the verifier walked, including the one that failed. `segments_inspected` counts every segment the verifier opened.

## Required fields

### Top level

| Field | Type | Notes |
|-------|------|-------|
| `format_version` | u16 | The on-disk format version this report was produced against. v0.1 = `1`. |
| `verdict` | string | `"Verified"` or `"Violation"`. No other values at v0.1. |
| `log` | object | Always present, even on violation. See below. |
| `violation` | object \| null | Null iff `verdict == "Verified"`. |

### `log` object

| Field | Type | Notes |
|-------|------|-------|
| `log_dir` | string | Filesystem path of the directory containing the segment files. Implementation-relative; auditors use it to navigate to the file. |
| `key_id_hex` | string | 64-character lowercase hex of the segment header's `key_id`. Lets a verifier confirm "I checked the log signed with this key." |
| `segments_inspected` | u32 | Number of segment files the verifier opened and parsed (header + zero or more records). |
| `records_inspected` | u64 | Total number of records walked across all segments (including the failing record on violation). |
| `first_segment_index` | u16 | The smallest `segment_index` the verifier saw. Usually 0; non-zero if a verifier was asked to inspect a segment range. |
| `last_segment_index` | u16 | The largest `segment_index` the verifier reached before stopping (success or violation). |
| `final_hmac_hex` | string \| null | Chain head as known up to the stopping point. Null if no record verified successfully (e.g. `HeaderCorrupt` on segment 0). |

### `violation` object

Always present on `verdict == "Violation"`:

| Field | Type | Notes |
|-------|------|-------|
| `kind` | string | Exactly one of the nine kinds listed below. |
| `location` | object | Where the violation was detected. Shape depends on `kind`; required fields below. |
| `evidence` | object | Concrete bytes, indices, or values needed to reproduce. Shape depends on `kind`; required fields below. |
| `message` | string | Human-readable summary, ≤200 characters, ASCII only. Intended for log lines and audit reports — not parsed by tooling. |

Implementations MUST emit exactly the fields documented for each `kind` — no more, no fewer. Forward-compat additions ride a format-version bump.

## Per-kind shapes

All hex strings are lowercase. All byte offsets are absolute within the named segment file unless explicitly noted.

### `HmacMismatch`

The HMAC stored in a record's `hmac` field does not equal `HMAC-SHA256(key, payload_bytes)`.

```json
{
  "kind": "HmacMismatch",
  "location": {
    "segment_index": 0,
    "record_id": 2,
    "byte_offset": 401
  },
  "evidence": {
    "expected_hmac_hex": "<64-hex>",
    "actual_hmac_hex": "<64-hex>",
    "payload_len": 180,
    "payload_byte_offset": 405
  },
  "message": "HMAC mismatch at s0r2: expected 470d51..., got a8b2c4..."
}
```

- `byte_offset` points at the start of the record's `len_prefix` field.
- `payload_byte_offset` points at the start of the `payload` bytes (i.e. `byte_offset + 4`). Lets an auditor `xxd -s <offset> -l <payload_len>` directly.

### `ChainBreak`

A record's `prev_hash` field does not equal the preceding record's HMAC (or for record 0 of segment 0, does not equal `chain_start_0`).

```json
{
  "kind": "ChainBreak",
  "location": {
    "segment_index": 0,
    "record_id": 3,
    "byte_offset": 583
  },
  "evidence": {
    "expected_prev_hash_hex": "<64-hex>",
    "actual_prev_hash_hex": "<64-hex>",
    "preceding_record_id": 1,
    "is_genesis": false
  },
  "message": "Chain break at s0r3: prev_hash links to record 2 but verifier reached record 1"
}
```

- `expected_prev_hash_hex` is the HMAC the verifier computed for the preceding record (or `chain_start_segment` for record 0).
- `actual_prev_hash_hex` is the value read from the failing record's `prev_hash` field.
- `preceding_record_id` is the `record_id` of whatever record the verifier inspected immediately before this one. On `is_genesis: true`, `preceding_record_id` is `null`.

### `RecordCorrupt`

A record framing or canonical-form invariant is violated. Used for any of: `len_trailer != len_prefix`, payload not canonical CBOR, schema validation failure (unknown integer key 11–99, missing required key, wrong major type for a known key), or definite-length-encoding rule violations.

```json
{
  "kind": "RecordCorrupt",
  "location": {
    "segment_index": 0,
    "record_id": 2,
    "byte_offset": 401
  },
  "evidence": {
    "subkind": "LenMismatch",
    "len_prefix": 180,
    "len_trailer": 179
  },
  "message": "Record at s0r2 has len_prefix=180 but len_trailer=179 (torn-tail or tampering)"
}
```

`evidence.subkind` is one of:

- `"LenMismatch"` — `len_trailer != len_prefix`. Evidence: `len_prefix`, `len_trailer`.
- `"NotCanonicalCbor"` — payload bytes do not round-trip through canonical encoding. Evidence: `byte_offset_in_payload`, `rule` (one of `"shortest-int-encoding"`, `"map-key-order"`, `"definite-length"`, `"utf8-shortest"`, `"unused-tag"`, `"float-disallowed"`).
- `"UnknownKey"` — record map contains an integer key in `[11, 99]` (forbidden at v0.1). Evidence: `key`.
- `"MissingKey"` — record map is missing one of the required keys 1–10. Evidence: `key`.
- `"WrongType"` — a known key's value has the wrong major type. Evidence: `key`, `expected_type` (`"uint" | "bstr" | "tstr" | "map"`), `actual_major_type` (0–7).

`location.record_id` is `null` when the corruption prevents reading the `record_id` field (e.g. `LenMismatch`).

### `TimestampRegression`

A record's `ts_wall` regresses from the preceding record by more than 60,000 ms (1 minute slack for NTP corrections), within a session or across sessions.

```json
{
  "kind": "TimestampRegression",
  "location": {
    "segment_index": 1,
    "record_id": 4,
    "byte_offset": 902
  },
  "evidence": {
    "current_ts_wall": "2026-05-10T11:55:00.000Z",
    "preceding_ts_wall": "2026-05-10T12:00:00.000Z",
    "delta_ms": -300000,
    "across_sessions": false
  },
  "message": "ts_wall regressed 300000 ms at s1r4 within session"
}
```

`delta_ms` is `current - preceding` and is always negative for this violation kind.

### `TimestampInconsistency`

Within a single session, `|wall_delta - mono_delta|` exceeds 60,000 ms for two consecutive records.

```json
{
  "kind": "TimestampInconsistency",
  "location": {
    "segment_index": 0,
    "record_id": 5,
    "byte_offset": 1024
  },
  "evidence": {
    "session_id_hex": "<32-hex>",
    "current_ts_wall": "2026-05-10T12:05:00.000Z",
    "preceding_ts_wall": "2026-05-10T12:00:00.000Z",
    "current_ts_mono_delta": 0,
    "preceding_ts_mono_delta": 0,
    "wall_delta_ms": 300000,
    "mono_delta_ms": 0,
    "divergence_ms": 300000
  },
  "message": "Within session, wall advanced 300000 ms while monotonic stayed at 0 (s0r5)"
}
```

`divergence_ms` is `|wall_delta_ms - mono_delta_ms|`, always positive.

### `SegmentDiscontinuity`

Segment N+1's header `prev_final` does not equal the HMAC of segment N's last record.

```json
{
  "kind": "SegmentDiscontinuity",
  "location": {
    "segment_index": 1,
    "record_id": null,
    "byte_offset": 40
  },
  "evidence": {
    "expected_prev_final_hex": "<64-hex>",
    "actual_prev_final_hex": "<64-hex>",
    "preceding_segment_index": 0,
    "preceding_segment_final_hex": "<64-hex>"
  },
  "message": "Segment 1 prev_final does not match segment 0 final"
}
```

- `byte_offset` is `40` (the offset of the `prev_final` field in the header).
- `record_id` is `null` because the violation is at the segment-header boundary, before any record is read.

### `KeyIdMismatch`

A record's `key_id` field does not equal its segment header's `key_id`.

```json
{
  "kind": "KeyIdMismatch",
  "location": {
    "segment_index": 0,
    "record_id": 1,
    "byte_offset": 250
  },
  "evidence": {
    "header_key_id_hex": "<64-hex>",
    "record_key_id_hex": "<64-hex>"
  },
  "message": "Record s0r1 key_id does not match segment header key_id"
}
```

### `HeaderCorrupt`

Segment header CRC32 fails, or the magic bytes are not `OGAU`.

```json
{
  "kind": "HeaderCorrupt",
  "location": {
    "segment_index": 0,
    "record_id": null,
    "byte_offset": 0
  },
  "evidence": {
    "subkind": "CrcMismatch",
    "expected_crc32": 3349348137,
    "actual_crc32": 12345678,
    "header_bytes_hex": "<144-hex>"
  },
  "message": "Segment 0 header CRC mismatch: expected 0xc7e78129, got 0x00bc614e"
}
```

`evidence.subkind` is:

- `"CrcMismatch"` — CRC32 over header bytes `[0, 72)` does not match the value at offset 72. Evidence: `expected_crc32`, `actual_crc32`, `header_bytes_hex` (full 80 bytes for context).
- `"BadMagic"` — bytes 0–3 are not ASCII `"OGAU"`. Evidence: `actual_magic_hex` (8 hex chars), `header_bytes_hex`.
- `"Truncated"` — header file ended before byte 80. Evidence: `message` (diagnostic from the reader).
- `"ReservedBytesNonZero"` — reserved bytes `[76, 80)` contain a non-zero value. These bytes are not covered by the header CRC; verifiers MUST reject non-zero values to close a 4-byte mutation gap. Evidence: `actual_hex` (8 hex chars).

### `UnknownVersion`

Segment header `version` field is not `0x0001`.

```json
{
  "kind": "UnknownVersion",
  "location": {
    "segment_index": 0,
    "record_id": null,
    "byte_offset": 4
  },
  "evidence": {
    "actual_version": 2,
    "supported_versions": [1]
  },
  "message": "Segment 0 declares version 2; this verifier supports [1]"
}
```

## Determinism and stability

- **Field order in JSON output is irrelevant** for conformance. The on-disk-vector cross-check ([Q2 / OGE-441](https://linear.app/ogenticai/issue/OGE-441)) compares parsed JSON, not text.
- **Integer fields** are JSON numbers (no quoting). Hex byte fields are lowercase strings without `0x` prefix.
- **No optional fields at v0.1.** A field documented above MUST appear; a verifier MUST NOT emit fields not documented above. Forward-compat additions ride a `format_version` bump.
- **`message`** is the only field with implementation latitude (wording, language, length within the cap). Tooling MUST NOT parse it.

## Security caveats

- A violation report contains hex-encoded HMAC values, payload byte offsets, and timestamps. None of these are sensitive on their own. **Implementations MUST NOT include payload contents** in the report — payloads may contain secrets (PII, vault data). The `payload_byte_offset` + `payload_len` give an auditor a way to extract the raw bytes from the file themselves under whatever authorization regime applies.
- Implementations MUST emit at most one violation per report. The verifier walks until the first failure and stops; a tampered log may have many subsequent failures, but reporting them all leaks more about the chain state than is necessary and may aid adversaries reconstructing what survived.

## Example: clean log

Hypothetical verifier output for a single-segment log signed with the v0.1 vector key:

```json
{
  "format_version": 1,
  "verdict": "Verified",
  "log": {
    "log_dir": "/Users/auditor/inspect/audit-2026-05-10",
    "key_id_hex": "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
    "segments_inspected": 1,
    "records_inspected": 1000,
    "first_segment_index": 0,
    "last_segment_index": 0,
    "final_hmac_hex": "<final HMAC of the last record in the segment>"
  },
  "violation": null
}
```

## Example: tampered byte

Verifier output for the `tampered-byte` golden vector at [`tests/vectors/v0.1/tampered-byte/`](../../tests/vectors/v0.1/tampered-byte/). Record 2's payload has had byte 50 XOR'd with `0xff`; the stored HMAC was computed pre-tamper, so the verifier computes a different HMAC over the on-disk bytes and reports the mismatch.

Concrete values are pulled from the vector's `chain.json` (expected) and from byte offsets walked over the on-disk segment file:

```json
{
  "format_version": 1,
  "verdict": "Violation",
  "log": {
    "log_dir": "tests/vectors/v0.1/tampered-byte",
    "key_id_hex": "e528e95798037df410543d9f31e396ecdd458d71b157d6014398bae32fb56c65",
    "segments_inspected": 1,
    "records_inspected": 3,
    "first_segment_index": 0,
    "last_segment_index": 0,
    "final_hmac_hex": "adc192201e3bd519cc9c3e1ab9247fba098850f817de539098c015427eb5ca8f"
  },
  "violation": {
    "kind": "HmacMismatch",
    "location": {
      "segment_index": 0,
      "record_id": 2,
      "byte_offset": 509
    },
    "evidence": {
      "expected_hmac_hex": "3bf942484631bd02c19d74ebf131e668b6eaf0e1d3e6ab98eaf93d73f80a4fdd",
      "actual_hmac_hex": "<HMAC the verifier computes over the tampered payload bytes>",
      "payload_len": 180,
      "payload_byte_offset": 513
    },
    "message": "HMAC mismatch at s0r2: stored hmac does not match HMAC over payload bytes"
  }
}
```

Notes:
- `byte_offset = 509` is record 2's `len_prefix` start; `payload_byte_offset = 513` is the first payload byte. An auditor can `xxd -s 513 -l 180 audit-0000.cbor` to dump the tampered payload directly.
- `expected_hmac_hex` is `chain.json`'s `records[2].hmac_hex` from the vector — the value the writer recorded at the time of signing.
- `actual_hmac_hex` is the value `HMAC-SHA256(key, on_disk_payload_bytes)` produces *after* tampering. The two differ because the tampered payload bytes differ from the bytes the writer signed. The exact value is implementation-deterministic but not statically known here (it depends on the byte that was XOR'd).
- `final_hmac_hex` is the HMAC of the last record that successfully verified — record 1 — exactly as it appears in `chain.json`'s `records[1].hmac_hex`. The chain head moves forward by exactly one HMAC per verified record.
