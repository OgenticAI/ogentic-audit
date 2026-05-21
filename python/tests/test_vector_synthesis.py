"""Cross-language synthesize-and-compare test (Q2 / OGE-441).

Drive the Python bindings' Writer with the same inputs as the
``single-record`` and ``segment-rollover`` golden vectors; assert the
on-disk bytes are byte-identical to the committed `audit-NNNN.cbor`
files. This is the load-bearing cross-language correctness gate — if
this passes, the Python bindings produce wire-compatible output with
the reference generator (and, transitively, with the Rust Writer).

Tamper vectors (``tampered-byte``, ``missing-record``) are NOT
synthesized — the Writer should never produce mutated bytes — and the
``1k-records`` vector uses a deterministic generator block we don't
parse here for brevity. Those are covered by the verifier-side tests.
"""

from __future__ import annotations

import json
import tempfile
from pathlib import Path

import pytest

ogentic_audit = pytest.importorskip("ogentic_audit", reason="native extension not built yet")
from ogentic_audit import KeyHandle, Writer  # noqa: E402

VECTORS_DIR = Path(__file__).resolve().parent.parent.parent / "tests" / "vectors" / "v0.1"


def _segments_bytes(log_dir: Path) -> dict[str, bytes]:
    """Return a {filename: bytes} dict for every audit-NNNN.cbor in dir."""
    return {p.name: p.read_bytes() for p in sorted(log_dir.glob("audit-*.cbor"))}


def _synthesize(vector_name: str, tmp: Path) -> None:
    """Write `tmp/audit-NNNN.cbor` files driven by `inputs.json`."""
    spec = json.loads((VECTORS_DIR / vector_name / "inputs.json").read_text())
    key = KeyHandle.from_hex(spec["key_hex"])
    cfg = spec.get("writer_config", {})
    segment_size_bytes = cfg.get("segment_size_bytes")

    with Writer.open(
        str(tmp),
        key=key,
        session_id_hex=spec["session_id_hex"],
        segment_size_bytes=segment_size_bytes,
    ) as w:
        for rec in spec["records"]:
            w.append(
                {
                    "actor": rec["actor"],
                    "event": rec["event"],
                    "ts_wall": rec["ts_wall"],
                    "ts_mono_delta": rec["ts_mono_delta"],
                    "schema_version": rec["schema_version"],
                    "payload": rec.get("payload", {}),
                }
            )


@pytest.mark.parametrize("vector_name", ["single-record", "segment-rollover"])
def test_python_writer_synthesizes_byte_identical_output(vector_name: str) -> None:
    with tempfile.TemporaryDirectory() as tmp_str:
        tmp = Path(tmp_str)
        _synthesize(vector_name, tmp)

        produced = _segments_bytes(tmp)
        expected = _segments_bytes(VECTORS_DIR / vector_name)

        assert produced.keys() == expected.keys(), (
            f"file set mismatch for {vector_name}: "
            f"produced={sorted(produced)}, expected={sorted(expected)}"
        )
        for name in expected:
            assert produced[name] == expected[name], (
                f"{vector_name}/{name} bytes diverge: "
                f"len(produced)={len(produced[name])}, len(expected)={len(expected[name])}"
            )
