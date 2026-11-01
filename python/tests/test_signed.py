"""Signed mode (format 0x0002) through the Python package."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

import ogentic_audit as oa

K1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
K2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
K1_FP = "6db5 e9b8 a1ba ce1c dd9a 7c6a db9e 9396 acc5 0734 65d9 fe8e 3a0e f6d9 c60d 6d4f"
REPO = Path(__file__).resolve().parents[2]


def _log(path: Path, seed: bytes = K1, n: int = 3, seal: bool = False) -> None:
    with oa.Writer.open(str(path), signing_key=oa.SigningKey.from_seed(seed)) as w:
        for i in range(n):
            w.append(
                {
                    "actor": "user:clerk",
                    "event": "page.released",
                    "ts_wall": f"2026-10-03T12:00:{i:02d}.000Z",
                    "ts_mono_delta": i * 1000,
                    "payload": {"page": i},
                }
            )
        if seal:
            w.seal()


def test_signing_key_forms() -> None:
    k = oa.SigningKey.from_seed(K1)
    assert k.fingerprint() == K1_FP
    assert k.fingerprint_openssh() == "SHA256:bbXpuKG6zhzdmnxq256TlqzFBzRl2f6OOg722cYNbU8"
    assert k.public_key_openssh("c").startswith("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5")
    assert "BEGIN PUBLIC KEY" in k.public_key_pem()
    assert k.public_key_hex() == "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a"
    assert oa.SigningKey.generate().fingerprint() != K1_FP
    with pytest.raises(oa.ArgumentError):
        oa.SigningKey.from_seed(b"short")


def test_verify_pinned_and_unpinned(tmp_path: Path) -> None:
    _log(tmp_path / "log")
    rep = oa.verify(tmp_path / "log", key_fingerprint=K1_FP)
    assert rep.ok and rep.verdict == "Verified"
    assert rep.head_anchored is False
    assert rep.signer["fingerprint_grouped"] == K1_FP
    assert rep.signer["reason"] == "pinned"
    assert json.loads(rep.to_json())["format_version"] == 2

    rep = oa.verify(tmp_path / "log")
    assert not rep.ok
    assert rep.verdict == "SelfConsistent" and rep.reason == "not_pinned"
    with pytest.raises(oa.SignerNotPinnedError):
        oa.verify(tmp_path / "log", raise_on_violation=True)
    # SignerNotPinnedError is not a tamper finding.
    assert not issubclass(oa.SignerNotPinnedError, oa.VerificationFailed)

    other = oa.SigningKey.from_seed(K2).public_key_openssh()
    with pytest.raises(oa.UntrustedSignerError):
        oa.verify(tmp_path / "log", public_key=other, raise_on_violation=True)
    with pytest.raises(oa.ArgumentError):
        oa.verify(tmp_path / "log", key=oa.KeyHandle.from_bytes(b"\x00" * 32))


def test_tamper_is_named(tmp_path: Path) -> None:
    _log(tmp_path / "log", n=5)
    seg = tmp_path / "log" / "audit-0000.cbor"
    b = bytearray(seg.read_bytes())
    b[-40] ^= 1  # inside the last record's body
    seg.write_bytes(bytes(b))
    rep = oa.verify(tmp_path / "log", key_fingerprint=K1_FP)
    assert rep.verdict == "Violation"
    assert rep.compact == "SignatureInvalid@s0r4"
    assert rep.violation["reason"] == "body_mismatch"
    with pytest.raises(oa.SignatureInvalidError):
        oa.verify(tmp_path / "log", key_fingerprint=K1_FP, raise_on_violation=True)


def test_hmac_log_with_public_key_is_refused(tmp_path: Path) -> None:
    key = oa.KeyHandle.from_bytes(b"\x07" * 32)
    with oa.Writer.open(str(tmp_path / "log"), key) as w:
        w.append({"actor": "a", "event": "x.y", "ts_wall": "2026-10-03T12:00:00.000Z"})
    with pytest.raises(oa.HmacLogError):
        oa.verify(tmp_path / "log", key_fingerprint=K1_FP)
    with pytest.raises(oa.ArgumentError):
        oa.verify(tmp_path / "log")
    assert oa.verify(tmp_path / "log", key).ok


def test_signed_checkpoint(tmp_path: Path) -> None:
    _log(tmp_path / "log")
    k = oa.SigningKey.from_seed(K1)
    cp = oa.checkpoint(
        tmp_path / "log",
        signing_key=k,
        out=tmp_path / "cp.json",
        observed_at="2026-10-03T13:00:00.000Z",
    )
    assert cp["format"] == "ogentic-audit-checkpoint/v2"
    assert (tmp_path / "cp.json.sig").exists()
    rep = oa.verify(tmp_path / "log", key_fingerprint=K1_FP, checkpoint=[tmp_path / "cp.json"])
    assert rep.ok and rep.head_anchored


def _release(tmp: Path) -> Path:
    _log(tmp / "live", seal=True)
    rel = tmp / "release"
    (rel / "pages").mkdir(parents=True)
    (rel / "pages" / "0001.pdf").write_bytes(b"%PDF one")
    (rel / "Decisions.csv").write_bytes(b"page,decision\n1,release\n")
    digest = oa.attest_release(
        rel,
        files=[
            oa.FileSpec("pages/0001.pdf", "page"),
            oa.FileSpec("Decisions.csv", "index", [("header", 0, 14), ("row 1", 14, 10)]),
        ],
        logs=[oa.LogSpec(str(tmp / "live"), elide=[(0, 1)])],
        signing_key=oa.SigningKey.from_seed(K1),
        release_id="2026-0147",
    )
    assert len(digest) == 64
    return rel


def test_release_round_trip(tmp_path: Path) -> None:
    rel = _release(tmp_path)
    rep = oa.verify_release(rel, key_fingerprint=K1_FP)
    assert rep.ok, rep.render()
    assert rep.files["attested"] == 3
    assert oa.verify_release(rel).verdict == "SelfConsistent"
    (rel / "Decisions.csv").write_bytes(b"page,decision\n1,RELEASE\n")
    (rel / "extra.pdf").write_bytes(b"x")
    rep = oa.verify_release(rel, key_fingerprint=K1_FP)
    items = [v["item"] for v in rep.violations]
    assert items == ["file:Decisions.csv#row 1", "file:extra.pdf"]


def _cli() -> list[str] | None:
    exe = REPO / "target" / "debug" / "ogentic-audit"
    if exe.exists():
        return [str(exe)]
    found = shutil.which("ogentic-audit")
    return [found] if found else None


def test_python_m_matches_the_cli(tmp_path: Path) -> None:
    rel = _release(tmp_path)
    py = [sys.executable, "-m", "ogentic_audit"]
    ok = subprocess.run(
        [*py, "verify-release", str(rel), "--key-fingerprint", K1_FP],
        capture_output=True,
        text=True,
    )
    assert ok.returncode == 0, ok.stderr
    assert 'Verified: release "2026-0147"' in ok.stdout
    assert subprocess.run([*py, "verify-release", str(rel)], capture_output=True).returncode == 4
    assert (
        subprocess.run(
            [*py, "verify-release", str(rel), "--key-fingerprint", "abc"], capture_output=True
        ).returncode
        == 3
    )
    assert subprocess.run([*py, "verify-release"], capture_output=True).returncode == 64
    (rel / "pages" / "0001.pdf").write_bytes(b"%PDF ONE")
    bad = subprocess.run(
        [*py, "verify-release", str(rel), "--key-fingerprint", K1_FP, "--ascii"],
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 1
    cli = _cli()
    if cli is None:
        pytest.skip("ogentic-audit binary not built")
    rust = subprocess.run(
        [*cli, "--ascii", "verify-release", str(rel), "--key-fingerprint", K1_FP],
        capture_output=True,
        text=True,
    )
    assert rust.returncode == bad.returncode
    assert rust.stdout == bad.stdout
