#!/usr/bin/env python3
"""Cross-check the hand-rolled canonical CBOR encoder in `gen_vectors.py`
against the reference `cbor2` library.

This is the F2 spike (ADR-0001 Action item 4) that proves canonical-form
parity between independent implementations on the v0.1 schema. We re-decode
every payload in every committed vector with `cbor2`, re-encode it with
`cbor2.dumps(..., canonical=True)`, and assert byte-identical output.

Run:
    pip install cbor2  # in a venv
    python3 tools/check_cbor_parity.py

Exit 0 on success, non-zero on any divergence.
"""

from __future__ import annotations

import json
import struct
import sys
from pathlib import Path

try:
    import cbor2
except ImportError as exc:  # pragma: no cover
    sys.stderr.write("error: install cbor2 in a venv first: pip install cbor2\n")
    raise SystemExit(1) from exc

REPO_ROOT = Path(__file__).resolve().parent.parent
VECTORS_DIR = REPO_ROOT / "tests" / "vectors" / "v0.1"
HEADER_LEN = 80
HMAC_LEN = 32


def split_records(segment_bytes: bytes) -> list[bytes]:
    """Split a segment file into raw payload byte strings."""
    payloads: list[bytes] = []
    pos = HEADER_LEN
    while pos < len(segment_bytes):
        if pos + 4 > len(segment_bytes):
            break
        (lp,) = struct.unpack("<I", segment_bytes[pos : pos + 4])
        pl_start = pos + 4
        pl_end = pl_start + lp
        if pl_end + HMAC_LEN + 4 > len(segment_bytes):
            break
        payload = segment_bytes[pl_start:pl_end]
        (lt,) = struct.unpack("<I", segment_bytes[pl_end + HMAC_LEN : pl_end + HMAC_LEN + 4])
        if lt != lp:
            # torn-tail or surgically removed record. Skip the rest.
            break
        payloads.append(payload)
        pos = pl_end + HMAC_LEN + 4
    return payloads


def _vector_has_byte_tamper(vec_dir: Path) -> bool:
    inputs = json.loads((vec_dir / "inputs.json").read_text())
    pp = inputs.get("post_process") or {}
    return pp.get("kind") in {"byte_xor", "byte_xor_in_record"}


def main() -> int:
    fails = 0
    checked = 0
    skipped_vectors: list[str] = []
    for vec_dir in sorted(p for p in VECTORS_DIR.iterdir() if p.is_dir()):
        if _vector_has_byte_tamper(vec_dir):
            skipped_vectors.append(vec_dir.name)
            continue
        for seg_path in sorted(vec_dir.glob("audit-*.cbor")):
            data = seg_path.read_bytes()
            for i, payload in enumerate(split_records(data)):
                # Decode with cbor2.
                try:
                    decoded = cbor2.loads(payload)
                except Exception as exc:  # pragma: no cover
                    sys.stderr.write(
                        f"FAIL {seg_path.relative_to(REPO_ROOT)} record {i}: "
                        f"cbor2 decode error: {exc}\n"
                    )
                    fails += 1
                    continue
                # Re-encode with cbor2 canonical mode.
                roundtrip = cbor2.dumps(decoded, canonical=True)
                if roundtrip != payload:
                    fails += 1
                    sys.stderr.write(
                        f"FAIL {seg_path.relative_to(REPO_ROOT)} record {i}: "
                        f"cbor2 canonical encoding diverges from gen_vectors\n"
                        f"  hand-rolled ({len(payload)}B): {payload.hex()[:160]}...\n"
                        f"  cbor2       ({len(roundtrip)}B): {roundtrip.hex()[:160]}...\n"
                    )
                else:
                    checked += 1
    skip_note = (
        f"  skipped (byte-tamper vectors): {', '.join(skipped_vectors)}\n"
        if skipped_vectors
        else ""
    )
    print(f"{skip_note}  checked {checked} record payloads across all clean vectors  fails={fails}")
    return 0 if fails == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
