"""Every run of tests/vectors/v0.2 through the Python package (spec v0.2 §16).

Runs whose key statements are found inside a bundle are library-only (the
Python API, like the command line, treats statements you pass as your own)
and are covered by the Rust conformance suite.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

import ogentic_audit as oa

VECTORS = Path(__file__).resolve().parents[2] / "tests" / "vectors" / "v0.2"


def _runs():
    for d in sorted(p for p in VECTORS.iterdir() if p.is_dir()):
        inputs = json.loads((d / "inputs.json").read_text())
        for i, r in enumerate(inputs["runs"]):
            if r["command"] not in ("verify", "verify-release"):
                continue
            if r.get("statements_source") == "bundle":
                continue
            yield pytest.param(d, r, id=f"{d.name}/{r.get('name', i)}")


def _outcome(d: Path, r: dict):
    """(exit code, compact verdict, reason, report or None)."""
    target = d / r["target"]
    common = dict(
        public_key=r.get("public_key"),
        key_fingerprint=r.get("key_fingerprint"),
        trust=(d / r["trust"]) if "trust" in r else None,
        statements=[d / s for s in r.get("statements", [])],
        revocations=[d / s for s in r.get("revocations", [])],
        witnesses=[d / s for s in r.get("witnesses", [])],
    )
    try:
        if r["command"] == "verify-release":
            rep = oa.verify_release(
                target,
                expect_release_id=r.get("expect_release_id"),
                allow_unattested=r.get("allow_unattested", False),
                **common,
            )
            first = rep.violations[0] if rep.violations else {}
            return (
                {"Verified": 0, "SelfConsistent": 4}.get(rep.verdict, 1),
                rep.compact,
                first.get("reason"),
                rep,
            )
        key = None
        if r.get("hmac_key_source"):
            key = oa.KeyHandle.from_hex(r["env"]["OGENTIC_AUDIT_KEY_HEX"])
        rep = oa.verify(
            target,
            key,
            "segment" in r,
            False,
            [d / c for c in r.get("checkpoints", [])] or None,
            expect_log_id=r.get("expect_log_id"),
            segment=r.get("segment"),
            **common,
        )
    except oa.IoFailure:
        return 2, None, None, None
    except oa.ArgumentError:
        return 3, None, None, None
    if not hasattr(rep, "reason"):
        return (0 if rep.ok else 1), rep.compact, None, rep
    reason = rep.violation["reason"] if rep.violation else rep.reason
    return {"Verified": 0, "SelfConsistent": 4}.get(rep.verdict, 1), rep.compact, reason, rep


@pytest.mark.parametrize("d,r", list(_runs()))
def test_vector_run(d: Path, r: dict) -> None:
    if r.get("env") and not r.get("hmac_key_source"):
        # The Python API never reads a key from the environment by itself.
        os.environ.update(r["env"])
    code, compact, reason, rep = _outcome(d, r)
    e = r["expect"]
    assert code == e["exit"], (compact, reason)
    if "verdict" in e:
        assert compact == e["verdict"]
    if "reason" in e:
        assert reason == e["reason"]
    if "head_anchored" in e:
        assert rep.head_anchored is e["head_anchored"]
    if "elided" in e and r["command"] == "verify":
        assert rep.elided_records == e["elided"]


def test_vector_count() -> None:
    assert len(list(_runs())) >= 100
