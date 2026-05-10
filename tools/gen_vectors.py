#!/usr/bin/env python3
"""Reference generator for ogentic-audit v0.1 golden vectors.

Reads each vector's `inputs.json`, produces byte-identical `audit-NNNN.cbor`
segment files plus a `chain.json` describing the expected HMAC chain and
verifier verdict. The on-disk format is defined in `docs/spec/v0.1.md`.

This generator is the authoritative source for the v0.1 vector suite. The Rust
core (R1/R2/R3) and Python bindings (P1) verify against the bytes this script
produces; OGE-441 (Q2) is the cross-language conformance suite that consumes
the same vectors.

Dependencies:
    blake3   (PyPI: blake3) — for key_id derivation
    Python 3.9+

Usage:
    python3 tools/gen_vectors.py                      # regenerate every vector
    python3 tools/gen_vectors.py --check              # error if any output drifted
    python3 tools/gen_vectors.py <vector-dir> [...]   # regenerate just these
"""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import os
import re
import struct
import sys
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

try:
    import blake3 as _blake3
except ImportError as exc:  # pragma: no cover
    sys.stderr.write(
        "error: this script requires the `blake3` package.\n"
        "       install with: pip install blake3\n"
    )
    raise SystemExit(1) from exc


REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "tests" / "vectors" / "v0.1"

FORMAT_VERSION = 0x0001
HEADER_BODY_LEN = 72
HEADER_TOTAL_LEN = 80
HMAC_LEN = 32
KEY_ID_LEN = 32
SESSION_ID_LEN = 16
DEFAULT_SEGMENT_SIZE_BYTES = 64 * 1024 * 1024


# ---------------------------------------------------------------------------
# Canonical CBOR encoder (RFC 8949 §4.2 — covering the subset we need)
# ---------------------------------------------------------------------------


def _cbor_head(major: int, value: int) -> bytes:
    base = major << 5
    if value < 24:
        return bytes([base | value])
    if value < 1 << 8:
        return bytes([base | 24, value])
    if value < 1 << 16:
        return bytes([base | 25]) + struct.pack(">H", value)
    if value < 1 << 32:
        return bytes([base | 26]) + struct.pack(">I", value)
    if value < 1 << 64:
        return bytes([base | 27]) + struct.pack(">Q", value)
    raise ValueError(f"value {value} exceeds u64")


def cbor_uint(v: int) -> bytes:
    if v < 0:
        raise ValueError("cbor_uint requires non-negative")
    return _cbor_head(0, v)


def cbor_nint(v: int) -> bytes:
    if v >= 0:
        raise ValueError("cbor_nint requires negative")
    return _cbor_head(1, -1 - v)


def cbor_bstr(v: bytes) -> bytes:
    return _cbor_head(2, len(v)) + v


def cbor_tstr(v: str) -> bytes:
    enc = v.encode("utf-8")
    return _cbor_head(3, len(enc)) + enc


def cbor_bool(v: bool) -> bytes:
    return b"\xf5" if v else b"\xf4"


def cbor_value(v: Any) -> bytes:
    """Encode a generic value, used for payload sub-trees."""
    if isinstance(v, bool):
        return cbor_bool(v)
    if isinstance(v, int):
        return cbor_uint(v) if v >= 0 else cbor_nint(v)
    if isinstance(v, str):
        return cbor_tstr(v)
    if isinstance(v, bytes):
        return cbor_bstr(v)
    if isinstance(v, dict):
        return cbor_map_textkeys(v)
    if isinstance(v, list):
        # major type 4 (array). Definite-length, canonical.
        return _cbor_head(4, len(v)) + b"".join(cbor_value(item) for item in v)
    raise TypeError(f"unsupported value type {type(v).__name__}")


def cbor_map_intkeys(items: list[tuple[int, bytes]]) -> bytes:
    """Encode a map with unsigned-integer keys. Items are (key, encoded_value)
    pairs. Sort by canonical key encoding (length, then byte order)."""
    encoded = [(cbor_uint(k), v) for k, v in items]
    encoded.sort(key=lambda kv: (len(kv[0]), kv[0]))
    body = b"".join(k + v for k, v in encoded)
    return _cbor_head(5, len(encoded)) + body


def cbor_map_textkeys(d: dict[str, Any]) -> bytes:
    """Encode a map with text-string keys (used inside payload). Sort canonical:
    by encoded-key length, then byte order."""
    encoded = [(cbor_tstr(k), cbor_value(v)) for k, v in d.items()]
    encoded.sort(key=lambda kv: (len(kv[0]), kv[0]))
    body = b"".join(k + v for k, v in encoded)
    return _cbor_head(5, len(encoded)) + body


# ---------------------------------------------------------------------------
# Schema-aware encoders
# ---------------------------------------------------------------------------


@dataclass
class Record:
    record_id: int
    prev_hash: bytes
    ts_wall: str
    ts_mono_delta: int
    session_id: bytes
    actor: str
    event: str
    payload: dict[str, Any]
    key_id: bytes
    schema_version: int

    def to_cbor_payload(self) -> bytes:
        if len(self.prev_hash) != HMAC_LEN:
            raise ValueError("prev_hash must be 32 bytes")
        if len(self.session_id) != SESSION_ID_LEN:
            raise ValueError("session_id must be 16 bytes")
        if len(self.key_id) != KEY_ID_LEN:
            raise ValueError("key_id must be 32 bytes")
        if not self.ts_wall.endswith("Z"):
            raise ValueError("ts_wall must end with Z")
        items: list[tuple[int, bytes]] = [
            (1, cbor_uint(self.record_id)),
            (2, cbor_bstr(self.prev_hash)),
            (3, cbor_tstr(self.ts_wall)),
            (4, cbor_uint(self.ts_mono_delta)),
            (5, cbor_bstr(self.session_id)),
            (6, cbor_tstr(self.actor)),
            (7, cbor_tstr(self.event)),
            (8, cbor_map_textkeys(self.payload)),
            (9, cbor_bstr(self.key_id)),
            (10, cbor_uint(self.schema_version)),
        ]
        return cbor_map_intkeys(items)


def build_segment_header(
    segment_index: int,
    key_id: bytes,
    prev_final: bytes,
) -> bytes:
    if len(key_id) != KEY_ID_LEN:
        raise ValueError("key_id must be 32 bytes")
    if len(prev_final) != HMAC_LEN:
        raise ValueError("prev_final must be 32 bytes")
    body = (
        b"OGAU"
        + struct.pack("<H", FORMAT_VERSION)
        + struct.pack("<H", segment_index)
        + key_id
        + prev_final
    )
    if len(body) != HEADER_BODY_LEN:
        raise AssertionError(f"header body length {len(body)} != {HEADER_BODY_LEN}")
    crc = zlib.crc32(body) & 0xFFFFFFFF
    header = body + struct.pack("<I", crc) + (b"\x00" * 4)
    if len(header) != HEADER_TOTAL_LEN:
        raise AssertionError(f"header total {len(header)} != {HEADER_TOTAL_LEN}")
    return header


def frame_record(payload: bytes, key: bytes) -> tuple[bytes, bytes]:
    h = hmac.new(key, payload, hashlib.sha256).digest()
    framed = struct.pack("<I", len(payload)) + payload + h + struct.pack("<I", len(payload))
    return framed, h


def derive_key_id(key: bytes) -> bytes:
    return _blake3.blake3(key).digest(length=KEY_ID_LEN)


def chain_start_for_segment(
    segment_index: int, header: bytes, prev_final: bytes, key: bytes
) -> bytes:
    if segment_index == 0:
        return hmac.new(key, header[:HEADER_BODY_LEN], hashlib.sha256).digest()
    return prev_final


# ---------------------------------------------------------------------------
# Vector model
# ---------------------------------------------------------------------------


@dataclass
class WriterConfig:
    segment_size_bytes: int = DEFAULT_SEGMENT_SIZE_BYTES
    finalize_on_rollover: bool = True


@dataclass
class WrittenRecord:
    segment: int
    record_id: int
    prev_hash: bytes
    payload_bytes: bytes
    hmac: bytes
    file_offset: int
    framed_len: int
    ts_wall: str
    ts_mono_delta: int


@dataclass
class WrittenSegment:
    segment_index: int
    header: bytes
    body: bytes  # bytes after the header
    chain_start: bytes
    records: list[WrittenRecord]

    @property
    def file_bytes(self) -> bytes:
        return self.header + self.body

    @property
    def final_hmac(self) -> bytes:
        if self.records:
            return self.records[-1].hmac
        return self.chain_start


def parse_hex(s: str, expected_bytes: int | None = None) -> bytes:
    s = s.strip().lower().replace(" ", "")
    if s.startswith("0x"):
        s = s[2:]
    out = bytes.fromhex(s)
    if expected_bytes is not None and len(out) != expected_bytes:
        raise ValueError(
            f"expected {expected_bytes}-byte hex string, got {len(out)} bytes"
        )
    return out


# ---------------------------------------------------------------------------
# Generation
# ---------------------------------------------------------------------------


class VectorBuildError(Exception):
    pass


def expand_record_inputs(spec: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve the `records` section into a flat list of record specs.

    Supports:
      - explicit list: `"records": [ {...}, {...} ]`
      - generated: `"records": {"mode": "generated", "count": N, "template": {...}}`
    """
    src = spec.get("records")
    if src is None:
        return []
    if isinstance(src, list):
        return src
    if not isinstance(src, dict):
        raise VectorBuildError("`records` must be a list or generator object")
    mode = src.get("mode")
    if mode != "generated":
        raise VectorBuildError(f"unknown records mode {mode!r}")
    count = int(src["count"])
    template = src["template"]
    base_ts = template["ts_wall_base"]
    step_ms = int(template.get("ts_wall_step_ms", 1000))
    mono_step_ms = int(template.get("ts_mono_step_ms", step_ms))
    actor = template.get("actor", "user:david")
    event = template.get("event", "noise.tick")
    schema_version = int(template.get("schema_version", 1))
    payload_template = template.get("payload", {"i": "$i"})

    base_dt_ms = _iso_to_ms(base_ts)
    out: list[dict[str, Any]] = []
    for i in range(count):
        wall_ms = base_dt_ms + i * step_ms
        rec = {
            "ts_wall": _ms_to_iso(wall_ms),
            "ts_mono_delta": i * mono_step_ms,
            "actor": actor,
            "event": event,
            "schema_version": schema_version,
            "payload": _resolve_payload(payload_template, i),
        }
        out.append(rec)
    return out


def _resolve_payload(template: Any, i: int) -> Any:
    if isinstance(template, dict):
        return {k: _resolve_payload(v, i) for k, v in template.items()}
    if isinstance(template, list):
        return [_resolve_payload(v, i) for v in template]
    if template == "$i":
        return i
    return template


_ISO_RE = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})\.(\d{3})Z$"
)


def _iso_to_ms(s: str) -> int:
    m = _ISO_RE.match(s)
    if not m:
        raise ValueError(f"timestamp {s!r} not in expected RFC 3339 ms-precision form")
    y, mo, d, h, mi, se, ms = (int(g) for g in m.groups())
    import datetime as _dt

    dt = _dt.datetime(y, mo, d, h, mi, se, tzinfo=_dt.timezone.utc)
    epoch = _dt.datetime(1970, 1, 1, tzinfo=_dt.timezone.utc)
    return int((dt - epoch).total_seconds() * 1000) + ms


def _ms_to_iso(ms: int) -> str:
    import datetime as _dt

    dt = _dt.datetime.fromtimestamp(ms / 1000.0, tz=_dt.timezone.utc)
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def write_vector(spec: dict[str, Any]) -> tuple[list[WrittenSegment], dict[str, Any]]:
    key = parse_hex(spec["key_hex"], 32)
    session_id = parse_hex(spec["session_id_hex"], SESSION_ID_LEN)
    config_in = spec.get("writer_config") or {}
    cfg = WriterConfig(
        segment_size_bytes=int(
            config_in.get("segment_size_bytes", DEFAULT_SEGMENT_SIZE_BYTES)
        ),
        finalize_on_rollover=bool(config_in.get("finalize_on_rollover", True)),
    )
    key_id = derive_key_id(key)
    record_inputs = expand_record_inputs(spec)

    # First, build segments.
    segments: list[WrittenSegment] = []
    seg_index = 0
    seg_records_in: list[dict[str, Any]] = []  # records targeted at the current segment
    record_id_in_segment = 0
    prev_hmac: bytes | None = None  # tracks chain across records within current segment

    def open_segment(idx: int, prev_final: bytes) -> WrittenSegment:
        header = build_segment_header(idx, key_id, prev_final)
        return WrittenSegment(
            segment_index=idx,
            header=header,
            body=b"",
            chain_start=chain_start_for_segment(idx, header, prev_final, key),
            records=[],
        )

    def append_record(seg: WrittenSegment, rec_input: dict[str, Any]) -> tuple[bytes, int]:
        nonlocal record_id_in_segment
        prev_hash_for_record = (
            seg.chain_start if not seg.records else seg.records[-1].hmac
        )
        rec = Record(
            record_id=record_id_in_segment,
            prev_hash=prev_hash_for_record,
            ts_wall=rec_input["ts_wall"],
            ts_mono_delta=int(rec_input["ts_mono_delta"]),
            session_id=session_id,
            actor=rec_input["actor"],
            event=rec_input["event"],
            payload=rec_input.get("payload", {}),
            key_id=key_id,
            schema_version=int(rec_input["schema_version"]),
        )
        payload_bytes = rec.to_cbor_payload()
        framed, h = frame_record(payload_bytes, key)
        offset = HEADER_TOTAL_LEN + len(seg.body)
        seg.body += framed
        seg.records.append(
            WrittenRecord(
                segment=seg.segment_index,
                record_id=record_id_in_segment,
                prev_hash=prev_hash_for_record,
                payload_bytes=payload_bytes,
                hmac=h,
                file_offset=offset,
                framed_len=len(framed),
                ts_wall=rec.ts_wall,
                ts_mono_delta=rec.ts_mono_delta,
            )
        )
        record_id_in_segment += 1
        return h, len(framed)

    seg = open_segment(0, b"\x00" * HMAC_LEN)
    segments.append(seg)

    for rec_input in record_inputs:
        # Predict whether appending this record exceeds segment_size_bytes;
        # if so, finalize the current segment and roll over.
        next_payload_len = _estimate_record_size(rec_input, key_id, session_id)
        framed_size = 4 + next_payload_len + HMAC_LEN + 4
        projected = HEADER_TOTAL_LEN + len(seg.body) + framed_size
        # Reserve room for a potential segment.finalized record.
        finalize_size = _estimate_finalize_size(key_id, session_id)
        if (
            cfg.finalize_on_rollover
            and seg.records  # don't roll over an empty segment
            and projected + finalize_size > cfg.segment_size_bytes
        ):
            _append_segment_finalized(seg, append_record)
            seg_index += 1
            record_id_in_segment = 0
            seg = open_segment(seg_index, seg.final_hmac)
            segments.append(seg)
        append_record(seg, rec_input)

    # Apply post-processing (tampering, removal) if specified.
    files = _materialize_files(segments)
    pp = spec.get("post_process")
    if pp is not None:
        files = _apply_post_process(files, segments, pp)

    expected_verdict = spec.get("expected_verdict", "Verified")
    chain = _build_chain_json(
        key=key,
        key_id=key_id,
        session_id=session_id,
        segments=segments,
        expected_verdict=expected_verdict,
        post_process=pp,
    )
    return segments, {"files": files, "chain": chain}


def _estimate_record_size(
    rec_input: dict[str, Any], key_id: bytes, session_id: bytes
) -> int:
    """Encode a candidate record with placeholder prev_hash + record_id 0 to
    estimate its payload length. The actual encoded length is independent of
    those two fields' values (they are fixed-length: u64 record_id ≤ 9 bytes,
    bstr(32) prev_hash) for any record_id < 2^64."""
    rec = Record(
        record_id=0xFFFF_FFFF_FFFF_FFFF,  # max u64 → 9 bytes encoded
        prev_hash=b"\x00" * HMAC_LEN,
        ts_wall=rec_input["ts_wall"],
        ts_mono_delta=int(rec_input["ts_mono_delta"]),
        session_id=session_id,
        actor=rec_input["actor"],
        event=rec_input["event"],
        payload=rec_input.get("payload", {}),
        key_id=key_id,
        schema_version=int(rec_input["schema_version"]),
    )
    return len(rec.to_cbor_payload())


def _estimate_finalize_size(key_id: bytes, session_id: bytes) -> int:
    placeholder = {
        "ts_wall": "2026-01-01T00:00:00.000Z",
        "ts_mono_delta": 0,
        "actor": "system:audit",
        "event": "segment.finalized",
        "schema_version": 1,
        "payload": {
            "records": 0xFFFF_FFFF_FFFF_FFFF,
            "final_hash": b"\x00" * HMAC_LEN,
        },
    }
    return 4 + _estimate_record_size(placeholder, key_id, session_id) + HMAC_LEN + 4


def _append_segment_finalized(
    seg: WrittenSegment,
    append_record_fn,
) -> None:
    last = seg.records[-1]
    finalize_input = {
        "ts_wall": _ms_to_iso(_iso_to_ms(last.ts_wall) + 1),
        "ts_mono_delta": last.ts_mono_delta + 1,
        "actor": "system:audit",
        "event": "segment.finalized",
        "schema_version": 1,
        "payload": {
            "records": len(seg.records),
            "final_hash": last.hmac,
        },
    }
    append_record_fn(seg, finalize_input)


def _materialize_files(segments: list[WrittenSegment]) -> dict[str, bytes]:
    return {
        f"audit-{seg.segment_index:04d}.cbor": seg.file_bytes for seg in segments
    }


def _apply_post_process(
    files: dict[str, bytes],
    segments: list[WrittenSegment],
    pp: dict[str, Any],
) -> dict[str, bytes]:
    kind = pp.get("kind")
    if kind == "byte_xor":
        seg_idx = int(pp["segment"])
        offset = int(pp["offset"])
        xor = int(pp.get("xor", "0xff"), 16) if isinstance(pp.get("xor"), str) else int(pp["xor"])
        name = f"audit-{seg_idx:04d}.cbor"
        data = bytearray(files[name])
        data[offset] ^= xor & 0xFF
        files[name] = bytes(data)
        return files
    if kind == "byte_xor_in_record":
        seg_idx = int(pp["segment"])
        rec_id = int(pp["record_id"])
        seg = segments[seg_idx]
        rec = next(r for r in seg.records if r.record_id == rec_id)
        region = pp.get("region", "payload")
        byte_offset = int(pp["byte_in_region"])
        xor = (
            int(pp.get("xor", "0xff"), 16)
            if isinstance(pp.get("xor"), str)
            else int(pp["xor"])
        )
        if region == "payload":
            absolute = rec.file_offset + 4 + byte_offset
            limit = rec.file_offset + 4 + len(rec.payload_bytes)
        elif region == "hmac":
            absolute = rec.file_offset + 4 + len(rec.payload_bytes) + byte_offset
            limit = absolute + HMAC_LEN
        elif region == "len_prefix":
            absolute = rec.file_offset + byte_offset
            limit = rec.file_offset + 4
        elif region == "len_trailer":
            absolute = rec.file_offset + 4 + len(rec.payload_bytes) + HMAC_LEN + byte_offset
            limit = absolute + 4
        else:
            raise VectorBuildError(f"unknown region {region!r}")
        if absolute >= limit:
            raise VectorBuildError(
                f"byte_in_region {byte_offset} out of range for region {region}"
            )
        name = f"audit-{seg_idx:04d}.cbor"
        data = bytearray(files[name])
        data[absolute] ^= xor & 0xFF
        files[name] = bytes(data)
        return files
    if kind == "remove_record":
        seg_idx = int(pp["segment"])
        rec_id = int(pp["record_id"])
        seg = segments[seg_idx]
        target = next(r for r in seg.records if r.record_id == rec_id)
        name = f"audit-{seg_idx:04d}.cbor"
        data = files[name]
        cut_start = target.file_offset
        cut_end = target.file_offset + target.framed_len
        files[name] = data[:cut_start] + data[cut_end:]
        return files
    raise VectorBuildError(f"unknown post_process kind {kind!r}")


def _build_chain_json(
    *,
    key: bytes,
    key_id: bytes,
    session_id: bytes,
    segments: list[WrittenSegment],
    expected_verdict: str,
    post_process: dict[str, Any] | None,
) -> dict[str, Any]:
    chain_records: list[dict[str, Any]] = []
    seg_finals: list[dict[str, Any]] = []
    for seg in segments:
        seg_finals.append(
            {
                "segment": seg.segment_index,
                "chain_start_hex": seg.chain_start.hex(),
                "final_hex": seg.final_hmac.hex(),
                "record_count": len(seg.records),
            }
        )
        for rec in seg.records:
            chain_records.append(
                {
                    "segment": seg.segment_index,
                    "record_id": rec.record_id,
                    "prev_hash_hex": rec.prev_hash.hex(),
                    "hmac_hex": rec.hmac.hex(),
                    "payload_len": len(rec.payload_bytes),
                }
            )
    out: dict[str, Any] = {
        "format_version": FORMAT_VERSION,
        "key_id_hex": key_id.hex(),
        "session_id_hex": session_id.hex(),
        "segments": seg_finals,
        "records": chain_records,
        "expected_verdict": expected_verdict,
    }
    if post_process is not None:
        out["post_process"] = post_process
    return out


# ---------------------------------------------------------------------------
# I/O
# ---------------------------------------------------------------------------


def write_vector_dir(vec_dir: Path, *, check: bool = False) -> bool:
    """Generate all output files for the vector directory. Returns True if
    something was written (or would be written, in --check mode)."""
    inputs_path = vec_dir / "inputs.json"
    if not inputs_path.exists():
        raise VectorBuildError(f"{inputs_path} does not exist")
    spec = json.loads(inputs_path.read_text())
    _, out = write_vector(spec)
    files = out["files"]
    chain = out["chain"]

    expected_outputs: dict[str, bytes] = dict(files)
    expected_outputs["chain.json"] = (
        json.dumps(chain, sort_keys=True, indent=2).encode("utf-8") + b"\n"
    )

    drift = False
    for name, body in expected_outputs.items():
        path = vec_dir / name
        if path.exists() and path.read_bytes() == body:
            continue
        drift = True
        if check:
            sys.stderr.write(
                f"DRIFT: {path.relative_to(REPO_ROOT)} would change ({len(body)} bytes)\n"
            )
        else:
            path.write_bytes(body)
    # Clean up stale audit-NNNN.cbor files that our generation no longer produces.
    for stale in vec_dir.glob("audit-*.cbor"):
        if stale.name not in expected_outputs:
            drift = True
            if check:
                sys.stderr.write(f"DRIFT: stale {stale.relative_to(REPO_ROOT)}\n")
            else:
                stale.unlink()
    return drift


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="exit non-zero if any vector output would change",
    )
    parser.add_argument(
        "vectors",
        nargs="*",
        help="optional vector directory names; defaults to all under tests/vectors/v0.1",
    )
    args = parser.parse_args()

    if args.vectors:
        targets = [VECTORS_DIR / name for name in args.vectors]
    else:
        targets = sorted(p for p in VECTORS_DIR.iterdir() if p.is_dir())

    overall_drift = False
    for vec_dir in targets:
        try:
            drift = write_vector_dir(vec_dir, check=args.check)
        except VectorBuildError as exc:
            sys.stderr.write(f"FAIL [{vec_dir.name}]: {exc}\n")
            return 2
        overall_drift = overall_drift or drift
        action = "would update" if (drift and args.check) else ("updated" if drift else "ok")
        print(f"  {vec_dir.name:<24}  {action}")

    if args.check and overall_drift:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
