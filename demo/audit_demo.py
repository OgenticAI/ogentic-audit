"""Logic layer for the ogentic-audit verify-chain demo (OGE-1668).

Every verdict here comes from the **real, published** verifier
(`pip install ogentic-audit`) — the demo never re-implements the check, so
what you see is exactly what the library does. The three stories:

1. `build_and_verify` — a clean HMAC-chained audit log verifies end to end.
2. `tamper_byte` — flip one byte inside a record; the chain breaks at that
   exact `(segment, record_id)`.
3. `rewrite_vs_checkpoint` — the NousResearch/hermes-agent#487 attack: a log
   rewritten by someone holding the key passes *plain* verification, but is
   caught the moment it is checked against a checkpoint observed earlier.

Logs are generated at runtime in a temp dir with the public all-zeros fixture
key — no secrets, no KMS, nothing to configure.
"""

from __future__ import annotations

import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from ogentic_audit import KeyHandle, Reader, Writer, checkpoint, verify

# Public, non-secret fixture key (the one the repo's samples + golden vectors
# use). A demo has nothing to hide — the point is the chain, not the key.
FIXTURE_KEY_HEX = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

# A realistic four-event matter, mirroring the repo's homepage sample.
CLEAN_EVENTS: list[tuple[str, str, dict]] = [
    ("user:counsel", "vault.unlocked", {"matter_id": "2024-CV-3047"}),
    ("user:counsel", "file.opened", {"filename": "plaintiff-deposition.pdf"}),
    (
        "user:counsel",
        "llm.cloud-approved",
        {"model": "gpt-4o", "reason": "summarize witness statement"},
    ),
    ("user:counsel", "vault.locked", {"matter_id": "2024-CV-3047"}),
]


def _key() -> KeyHandle:
    return KeyHandle.from_hex(FIXTURE_KEY_HEX)


@dataclass
class RecordView:
    """One record, flattened for display."""

    record_id: int
    actor: str
    event: str
    payload: dict
    hmac_hex: str
    prev_hash_hex: str


@dataclass
class VerifyView:
    """A verify outcome, flattened for display."""

    ok: bool
    verdict: str  # "Verified" or "<Kind>@s<seg>r<rec>"
    kind: str  # "Verified" | "HmacMismatch" | "CheckpointMismatch" | …
    records_inspected: int
    chain_head: str | None
    # Present on a violation:
    broken_segment: int | None = None
    broken_record: int | None = None
    message: str | None = None


@dataclass
class DemoLog:
    """A generated log directory plus its records and verify outcome."""

    path: str
    records: list[RecordView] = field(default_factory=list)
    report: VerifyView | None = None


def _events_to_log(path: str, events: list[tuple[str, str, dict]]) -> None:
    key = _key()
    with Writer.open(path, key=key, session_id_hex="00112233445566778899aabbccddeeff") as w:
        for actor, event, payload in events:
            w.append({"actor": actor, "event": event, "payload": payload})


def _read_records(path: str) -> list[RecordView]:
    out: list[RecordView] = []
    for r in Reader.open(path):
        out.append(
            RecordView(
                record_id=r["record_id"],
                actor=r["actor"],
                event=r["event"],
                payload=r.get("payload", {}),
                hmac_hex=r["hmac_hex"],
                prev_hash_hex=r["prev_hash_hex"],
            )
        )
    return out


def _verify_view(path: str, checkpoint_arg: dict | None = None) -> VerifyView:
    report = verify(path, key=_key(), checkpoint=checkpoint_arg)
    v = report.violation
    return VerifyView(
        ok=report.ok,
        verdict=report.compact,
        kind=report.verdict_kind,
        records_inspected=report.records_inspected,
        chain_head=report.final_hmac_hex,
        broken_segment=(v or {}).get("segment_index"),
        broken_record=(v or {}).get("record_id"),
        message=(v or {}).get("message"),
    )


def build_and_verify(path: str | None = None) -> DemoLog:
    """Write the clean four-event log and verify it."""
    path = path or tempfile.mkdtemp(prefix="oga-demo-")
    _events_to_log(path, CLEAN_EVENTS)
    return DemoLog(path=path, records=_read_records(path), report=_verify_view(path))


def tamper_byte(path: str, marker: bytes = b"gpt-4o", replacement: bytes = b"gpt-5o") -> VerifyView:
    """Flip a byte inside a record's payload, then re-verify.

    `marker` is a known payload substring (default: the model name in record 2);
    replacing it changes the record's bytes, so the recomputed HMAC no longer
    matches — the verifier reports `HmacMismatch` at that exact record. Same
    length in/out keeps the record framing intact, so the HMAC (not a framing
    error) is what catches it.
    """
    seg = next(Path(path).glob("audit-*.cbor"))
    data = bytearray(seg.read_bytes())
    pos = data.find(marker)
    if pos == -1:
        raise ValueError(f"marker {marker!r} not found in the log")
    data[pos : pos + len(marker)] = replacement[: len(marker)].ljust(len(marker), b" ")
    seg.write_bytes(bytes(data))
    return _verify_view(path)


@dataclass
class RewriteDemo:
    """The three verdicts that make the checkpoint point."""

    honest: VerifyView  # the original log, verified
    checkpoint: dict  # the head observed while honest
    rewritten_plain: VerifyView  # rewritten log, verified WITHOUT the checkpoint
    rewritten_checked: VerifyView  # rewritten log, verified AGAINST the checkpoint


def rewrite_vs_checkpoint(path: str | None = None) -> RewriteDemo:
    """Reproduce the hermes-agent#487 rewrite attack and its detection.

    An adversary who holds the key truncates the log and re-chains a
    fabricated history. Plain verification — which only checks the chain
    against itself — still says Verified. A checkpoint observed *before* the
    rewrite, and held somewhere the writer can't reach, catches it.
    """
    path = path or tempfile.mkdtemp(prefix="oga-rewrite-")

    # Honest history, then observe + hand out a checkpoint.
    _events_to_log(path, CLEAN_EVENTS)
    honest = _verify_view(path)
    cp = checkpoint(path, _key(), observed_at="2026-07-23T00:00:00Z")

    # The rewrite: same key, the third event scrubbed and history re-chained.
    for f in Path(path).glob("*.cbor"):
        f.unlink()
    rewritten_events = [
        ("user:counsel", "vault.unlocked", {"matter_id": "2024-CV-3047"}),
        ("user:counsel", "file.opened", {"filename": "plaintiff-deposition.pdf"}),
        ("user:counsel", "file.closed", {"note": "no cloud model was ever used"}),
        ("user:counsel", "vault.locked", {"matter_id": "2024-CV-3047"}),
    ]
    _events_to_log(path, rewritten_events)

    return RewriteDemo(
        honest=honest,
        checkpoint=cp,
        rewritten_plain=_verify_view(path),
        rewritten_checked=_verify_view(path, checkpoint_arg=cp),
    )


def cleanup(*paths: str) -> None:
    for p in paths:
        shutil.rmtree(p, ignore_errors=True)
