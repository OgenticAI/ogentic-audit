#!/usr/bin/env python3
"""Reference generator and independent oracle for ogentic-audit v0.2 vectors.

Writes `tests/vectors/v0.2/` (spec docs/spec/v0.2.md §16): signed logs,
checkpoints, witness co-signatures, key statements and release bundles,
each with an `inputs.json` naming the runs to perform and their expected
results.

This file is a second implementation of the format, independent of the
Rust core: Ed25519 comes from Python `cryptography` (OpenSSL), CBOR and
SSHSIG are written out here, and spec §3.5 rules 1-3 are checked with a
pure-Python curve implementation because OpenSSL does not apply them.

Usage (normally through tools/gen_vectors.py --v02):
    python3 tools/gen_vectors_v02.py             # regenerate every vector
    python3 tools/gen_vectors_v02.py --check     # fail if committed bytes drifted
    python3 tools/gen_vectors_v02.py --verify    # run the oracle over every run

Dependencies: Python 3.9+, cryptography.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import shutil
import struct
import sys
import unicodedata
import zlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
except ImportError as exc:  # pragma: no cover
    sys.stderr.write("error: this script requires `cryptography` (pip install cryptography)\n")
    raise SystemExit(1) from exc

REPO_ROOT = Path(__file__).resolve().parent.parent
OUT_DIR = REPO_ROOT / "tests" / "vectors" / "v0.2"
V01_DIR = REPO_ROOT / "tests" / "vectors" / "v0.1"

# RFC 8032 §7.1 test keys (TEST 1, TEST 2, TEST 3, TEST 1024).
SEEDS = {
    "K1": "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    "K2": "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    "K3": "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
    "K4": "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5",
}
SESSION = bytes.fromhex("00112233445566778899aabbccddeeff")
LOG_A = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
LOG_B = bytes.fromhex("101112131415161718191a1b1c1d1e1f")

NS_RECORD = "ogentic-audit/v0.2/record"
NS_CHECKPOINT = "ogentic-audit/v0.2/checkpoint"
NS_WITNESS = "ogentic-audit/v0.2/witness"
NS_RELEASE = "ogentic-audit/v0.2/release"
NS_TRANSITION = "ogentic-audit/v0.2/key-transition"
NS_ACCEPT = "ogentic-audit/v0.2/key-transition-accept"
NS_REVOCATION = "ogentic-audit/v0.2/key-revocation"
ALL_NS = [NS_RECORD, NS_CHECKPOINT, NS_WITNESS, NS_RELEASE, NS_TRANSITION, NS_ACCEPT, NS_REVOCATION]
DEFAULT_SCOPE = {NS_RECORD, NS_CHECKPOINT, NS_RELEASE, NS_TRANSITION, NS_REVOCATION}

# ---------------------------------------------------------------------------
# Hashes and hex
# ---------------------------------------------------------------------------


def sha256(b: bytes) -> bytes:
    return hashlib.sha256(b).digest()


def th(tag: str, data: bytes) -> bytes:
    return sha256(tag.encode() + b"\x00" + data)


def test_nonce(log_id: bytes, i: int) -> bytes:
    """Body nonces in the vectors (fixed, so outputs are byte-reproducible):
    SHA-256("ogentic-audit/v0.2/test-nonce" || 0x00 || log_id || u64be(i)),
    i counting every record the writer writes, structural ones included."""
    return th("ogentic-audit/v0.2/test-nonce", log_id + struct.pack(">Q", i))


# ---------------------------------------------------------------------------
# Canonical CBOR (encode, and a strict decoder for the oracle)
# ---------------------------------------------------------------------------


def _head(major: int, v: int) -> bytes:
    b = major << 5
    if v < 24:
        return bytes([b | v])
    if v < 1 << 8:
        return bytes([b | 24, v])
    if v < 1 << 16:
        return bytes([b | 25]) + struct.pack(">H", v)
    if v < 1 << 32:
        return bytes([b | 26]) + struct.pack(">I", v)
    return bytes([b | 27]) + struct.pack(">Q", v)


def c_uint(v: int) -> bytes:
    return _head(0, v)


def c_bstr(v: bytes) -> bytes:
    return _head(2, len(v)) + v


def c_tstr(v: str) -> bytes:
    e = v.encode()
    return _head(3, len(e)) + e


def c_value(v: Any) -> bytes:
    if isinstance(v, bool):
        return b"\xf5" if v else b"\xf4"
    if isinstance(v, int):
        return c_uint(v) if v >= 0 else _head(1, -1 - v)
    if isinstance(v, str):
        return c_tstr(v)
    if isinstance(v, (bytes, bytearray)):
        return c_bstr(bytes(v))
    if isinstance(v, dict):
        return c_map_text(v)
    if isinstance(v, list):
        return _head(4, len(v)) + b"".join(c_value(x) for x in v)
    raise TypeError(type(v))


def c_map_int(items: list[tuple[int, bytes]]) -> bytes:
    enc = sorted(((c_uint(k), v) for k, v in items), key=lambda kv: (len(kv[0]), kv[0]))
    return _head(5, len(enc)) + b"".join(k + v for k, v in enc)


def c_map_text(d: dict[str, Any]) -> bytes:
    enc = sorted(
        ((c_tstr(k), c_value(v)) for k, v in d.items()), key=lambda kv: (len(kv[0]), kv[0])
    )
    return _head(5, len(enc)) + b"".join(k + v for k, v in enc)


class CborError(Exception):
    pass


def c_decode(b: bytes) -> Any:
    """Decode canonical CBOR (the subset), rejecting non-canonical forms."""
    pos = [0]

    def arg(ai: int) -> int:
        if ai < 24:
            return ai
        n = {24: 1, 25: 2, 26: 4, 27: 8}.get(ai)
        if n is None:
            raise CborError("indefinite or reserved length")
        if pos[0] + n > len(b):
            raise CborError("truncated")
        v = int.from_bytes(b[pos[0] : pos[0] + n], "big")
        pos[0] += n
        if v < {1: 24, 2: 256, 4: 65536, 8: 1 << 32}[n]:
            raise CborError("non-canonical length")
        return v

    def item(depth: int) -> Any:
        if depth > 16:
            raise CborError("too deep")
        if pos[0] >= len(b):
            raise CborError("truncated")
        ib = b[pos[0]]
        pos[0] += 1
        major, ai = ib >> 5, ib & 31
        if major == 7:
            if ai == 20:
                return False
            if ai == 21:
                return True
            raise CborError("unsupported simple value")
        v = arg(ai)
        if major == 0:
            return v
        if major == 1:
            return -1 - v
        if major in (2, 3):
            if pos[0] + v > len(b):
                raise CborError("truncated")
            s = b[pos[0] : pos[0] + v]
            pos[0] += v
            return bytes(s) if major == 2 else s.decode("utf-8")
        if major == 4:
            return [item(depth + 1) for _ in range(v)]
        if major == 5:
            out: list[tuple[Any, Any]] = []
            prev = None
            for _ in range(v):
                ks = pos[0]
                k = item(depth + 1)
                kb = b[ks : pos[0]]
                if prev is not None and (len(prev), prev) >= (len(kb), kb):
                    raise CborError("map keys not canonical")
                prev = kb
                out.append((k, item(depth + 1)))
            return ("map", out)
        raise CborError("unsupported major type")

    v = item(0)
    if pos[0] != len(b):
        raise CborError("trailing bytes")
    return v


# ---------------------------------------------------------------------------
# Edwards25519 arithmetic for spec §3.5 rules 1-3 (OpenSSL does not apply them)
# ---------------------------------------------------------------------------

P = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)
IDENTITY = (0, 1, 1, 0)


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = 2 * t1 * t2 * D % P
    Dd = 2 * z1 * z2 % P
    E, F, G, H = B - A, Dd - C, Dd + C, B + A
    return (E * F % P, G * H % P, F * G % P, E * H % P)


def _mul(s: int, pt):
    q = IDENTITY
    while s:
        if s & 1:
            q = _add(q, pt)
        pt = _add(pt, pt)
        s >>= 1
    return q


def _is_identity(pt) -> bool:
    x, y, z, _ = pt
    return x % P == 0 and (y - z) % P == 0


def decode_point(enc: bytes):
    """(point, canonical) or None if not on the curve."""
    y = int.from_bytes(enc, "little") & ((1 << 255) - 1)
    sign = enc[31] >> 7
    canonical = y < P
    y %= P
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x2 = u * pow(v, P - 2, P) % P
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * SQRT_M1 % P
    if (x * x - x2) % P != 0:
        return None
    if x == 0 and sign:
        canonical = False
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, x * y % P), canonical


def key_is_strong(pk: bytes) -> bool:
    d = decode_point(pk)
    if d is None or not d[1]:
        return False
    pt = d[0]
    if _is_identity(_mul(8, pt)):
        return False
    return _is_identity(_mul(L, pt))


def r_ok(r: bytes) -> bool:
    d = decode_point(r)
    return d is not None and d[1] and not _is_identity(_mul(8, d[0]))


# ---------------------------------------------------------------------------
# Ed25519 via OpenSSL plus the missing rules
# ---------------------------------------------------------------------------


def pub(seed_hex: str) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

    return (
        Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex))
        .public_key()
        .public_bytes(Encoding.Raw, PublicFormat.Raw)
    )


def raw_sign(seed_hex: str, msg: bytes) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(seed_hex)).sign(msg)


def _openssl_ok(pk: bytes, msg: bytes, sig: bytes) -> bool:
    try:
        Ed25519PublicKey.from_public_bytes(pk).verify(sig, msg)
        return True
    except (InvalidSignature, ValueError):
        return False


def strict_verify(pk: bytes, msg: bytes, sig: bytes) -> str | None:
    """None if valid under spec §3.5; else the reason (weak_key, reencoded, mismatch)."""
    if not key_is_strong(pk):
        return "weak_key"
    s = int.from_bytes(sig[32:], "little")
    if not r_ok(sig[:32]):
        return "mismatch"
    if s >= L:
        reduced = sig[:32] + (s % L).to_bytes(32, "little")
        return "reencoded" if _openssl_ok(pk, msg, reduced) else "mismatch"
    return None if _openssl_ok(pk, msg, sig) else "mismatch"


def plus_l(sig: bytes) -> bytes:
    s = int.from_bytes(sig[32:], "little") + L
    return sig[:32] + s.to_bytes(32, "little")


# ---------------------------------------------------------------------------
# Keys, fingerprints, SSHSIG
# ---------------------------------------------------------------------------


def ssh_string(b: bytes) -> bytes:
    return struct.pack(">I", len(b)) + b


def key_blob(pk: bytes) -> bytes:
    return ssh_string(b"ssh-ed25519") + ssh_string(pk)


def key_id(pk: bytes) -> bytes:
    return sha256(key_blob(pk))


def grouped(fp: bytes) -> str:
    h = fp.hex()
    return " ".join(h[i : i + 4] for i in range(0, 64, 4))


def openssh_line(pk: bytes, comment: str = "") -> str:
    s = "ssh-ed25519 " + base64.b64encode(key_blob(pk)).decode()
    return s + (" " + comment if comment else "")


def signed_data(ns: str, msg: bytes, hash_alg: str = "sha512") -> bytes:
    h = hashlib.sha512(msg).digest() if hash_alg == "sha512" else hashlib.sha256(msg).digest()
    return (
        b"SSHSIG"
        + ssh_string(ns.encode())
        + ssh_string(b"")
        + ssh_string(hash_alg.encode())
        + ssh_string(h)
    )


def sshsig_blob(
    pk: bytes, ns: str, sig: bytes, hash_alg="sha512", reserved=b"", trailing=b""
) -> bytes:
    return (
        b"SSHSIG"
        + struct.pack(">I", 1)
        + ssh_string(key_blob(pk))
        + ssh_string(ns.encode())
        + ssh_string(reserved)
        + ssh_string(hash_alg.encode())
        + ssh_string(ssh_string(b"ssh-ed25519") + ssh_string(sig))
        + trailing
    )


def armor(blob: bytes) -> bytes:
    b64 = base64.b64encode(blob).decode()
    lines = [b64[i : i + 70] for i in range(0, len(b64), 70)]
    return (
        "-----BEGIN SSH SIGNATURE-----\n" + "\n".join(lines) + "\n-----END SSH SIGNATURE-----\n"
    ).encode()


def detached(key: str, ns: str, msg: bytes, **kw) -> bytes:
    """Armored SSHSIG by key name `key` (K1..K4)."""
    hash_alg = kw.get("hash_alg", "sha512")
    sig = raw_sign(SEEDS[key], signed_data(ns, msg, hash_alg))
    return armor(
        sshsig_blob(
            pub(SEEDS[key]), ns, sig, hash_alg, kw.get("reserved", b""), kw.get("trailing", b"")
        )
    )


class SigError(Exception):
    def __init__(self, reason: str, msg: str = ""):
        super().__init__(msg or reason)
        self.reason = reason


def parse_sshsig(text: bytes, ns: str) -> tuple[bytes, bytes]:
    """(public key, signature) of a strictly parsed armored SSHSIG."""
    if len(text) > 64 * 1024:
        raise SigError("malformed", "too large")
    lines = text.decode().replace("\r", "").split("\n")
    try:
        b = lines.index("-----BEGIN SSH SIGNATURE-----")
        e = lines.index("-----END SSH SIGNATURE-----")
    except ValueError:
        raise SigError("malformed", "armor") from None
    blob = base64.b64decode("".join(lines[b + 1 : e]), validate=True)
    pos = [0]

    def take(n: int) -> bytes:
        if pos[0] + n > len(blob):
            raise SigError("malformed", "truncated")
        out = blob[pos[0] : pos[0] + n]
        pos[0] += n
        return out

    def string(buf=None):
        n = struct.unpack(">I", take(4))[0]
        return take(n)

    if take(6) != b"SSHSIG" or struct.unpack(">I", take(4))[0] != 1:
        raise SigError("malformed", "magic/version")
    kb = string()
    if (
        kb[:15] != ssh_string(b"ssh-ed25519")
        or len(kb) != 15 + 4 + 32
        or kb[15:19] != struct.pack(">I", 32)
    ):
        raise SigError("key_type" if not kb.startswith(ssh_string(b"ssh-ed25519")) else "malformed")
    pk = kb[19:]
    if string() != ns.encode():
        raise SigError("namespace")
    if string() != b"":
        raise SigError("malformed", "reserved")
    if string() != b"sha512":
        raise SigError("hash_alg")
    sb = string()
    if pos[0] != len(blob):
        raise SigError("malformed", "trailing")
    if sb[:15] != ssh_string(b"ssh-ed25519"):
        raise SigError("key_type")
    if len(sb) != 15 + 4 + 64 or sb[15:19] != struct.pack(">I", 64):
        raise SigError("malformed")
    return pk, sb[19:]


# ---------------------------------------------------------------------------
# Canonical JSON
# ---------------------------------------------------------------------------


def cjson(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def parse_cjson(b: bytes, max_depth: int = 5) -> Any:
    def no_dupes(pairs):
        keys = [k for k, _ in pairs]
        if len(keys) != len(set(keys)):
            raise ValueError("duplicate key")
        if any(not k.isascii() for k in keys):
            raise ValueError("non-ASCII key")
        return dict(pairs)

    def check(v, depth):
        if isinstance(v, (dict, list)):
            if depth > max_depth:
                raise ValueError("too deep")
            for x in v.values() if isinstance(v, dict) else v:
                check(x, depth + 1)
        elif isinstance(v, bool) or v is None or isinstance(v, float):
            raise ValueError("type outside subset")
        elif isinstance(v, int) and not 0 <= v <= 2**53 - 1:
            raise ValueError("integer out of range")

    obj = json.loads(b.decode("utf-8"), object_pairs_hook=no_dupes, parse_float=lambda s: float(s))
    check(obj, 1)
    if cjson(obj) != b:
        raise ValueError("not canonical")
    return obj


FORBIDDEN = [
    (0x00, 0x1F),
    (0x7F, 0x9F),
    (0x2028, 0x2029),
    (0x200E, 0x200F),
    (0x202A, 0x202E),
    (0x2066, 0x2069),
]


def bad_string(s: str) -> bool:
    return any(lo <= ord(c) <= hi for c in s for lo, hi in FORBIDDEN)


# ---------------------------------------------------------------------------
# The writer (independent of the Rust SignedWriter, same rules)
# ---------------------------------------------------------------------------


def header(
    index: int,
    log_id: bytes,
    pk: bytes,
    prev_final: bytes,
    *,
    sig_alg=1,
    reserved=0,
    version=2,
    kid=None,
) -> bytes:
    body = (
        b"OGAU"
        + struct.pack("<HHHH", version, index, sig_alg, reserved)
        + log_id
        + (kid if kid is not None else key_id(pk))
        + prev_final
        + pk
    )
    return body + struct.pack("<I", zlib.crc32(body) & 0xFFFFFFFF)


def envelope(
    rid: int,
    prev: bytes,
    ts: str,
    mono: int,
    event: str,
    kid: bytes,
    schema: int,
    seg: int,
    body_hash: bytes,
    extra=(),
) -> bytes:
    items = [
        (1, c_uint(rid)),
        (2, c_bstr(prev)),
        (3, c_tstr(ts)),
        (4, c_uint(mono)),
        (5, c_bstr(SESSION)),
        (7, c_tstr(event)),
        (9, c_bstr(kid)),
        (10, c_uint(schema)),
        (11, c_uint(seg)),
        (12, c_uint(1)),
        (13, c_bstr(body_hash)),
        *list(extra),
    ]
    return c_map_int(items)


def body(actor: str, payload: dict, nonce: bytes) -> bytes:
    return c_map_int([(6, c_tstr(actor)), (8, c_map_text(payload)), (14, c_bstr(nonce))])


def frame(env: bytes, sig: bytes, bod: bytes | None) -> bytes:
    bod = bod or b""
    n = struct.pack("<I", len(env))
    return n + env + sig + struct.pack("<I", len(bod)) + bod + n


def ts_of(i: int) -> str:
    return f"2026-10-03T12:{i // 60 % 60:02d}:{i % 60:02d}.000Z"


def ts_ms(ts: str) -> int:
    import datetime

    d = datetime.datetime.strptime(ts, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc
    )
    return int(d.timestamp() * 1000)


def ms_ts(ms: int) -> str:
    import datetime

    d = datetime.datetime.fromtimestamp(ms / 1000, tz=datetime.timezone.utc)
    return d.strftime("%Y-%m-%dT%H:%M:%S.") + f"{ms % 1000:03d}Z"


def record_inputs(n: int, event="page.released", actor="user:clerk") -> list[dict]:
    return [
        {
            "ts_wall": ts_of(i),
            "ts_mono_delta": i * 1000,
            "actor": actor,
            "event": event,
            "schema_version": 1,
            "payload": {"page": i},
        }
        for i in range(n)
    ]


@dataclass
class WrittenRecord:
    segment: int
    record_id: int
    envelope: bytes
    signature: bytes
    body: bytes
    record_hash: bytes
    body_hash: bytes
    prev_hash: bytes
    event: str
    ts: str


@dataclass
class Log:
    key: str
    log_id: bytes
    segments: list[bytearray] = field(default_factory=list)
    records: list[WrittenRecord] = field(default_factory=list)
    chain_starts: list[bytes] = field(default_factory=list)

    def files(self) -> dict[str, bytes]:
        return {f"audit-{i:04d}.cbor": bytes(s) for i, s in enumerate(self.segments)}


class Writer:
    """Mirrors SignedWriter: rollover estimate, finalize, seal, nonces."""

    def __init__(
        self,
        key: str,
        log_id: bytes,
        segment_size: int = 64 * 1024 * 1024,
        mutate_finalize: Callable[[dict], None] | None = None,
    ):
        self.key, self.pk = key, pub(SEEDS[key])
        self.kid = key_id(self.pk)
        self.log = Log(key, log_id)
        self.size = segment_size
        self.nonce_i = 0
        self.mutate_finalize = mutate_finalize
        self.last_ts: tuple[str, int] | None = None
        self._new_segment(0, b"\x00" * 32)

    def _new_segment(self, idx: int, prev_final: bytes) -> None:
        h = header(idx, self.log.log_id, self.pk, prev_final)
        self.log.segments.append(bytearray(h))
        self.cs = th("ogentic-audit/v0.2/header", h[:124])
        self.log.chain_starts.append(self.cs)
        self.prev, self.rid, self.seg = self.cs, 0, idx

    def _framed_len(self, rec: dict, bod_len: int) -> int:
        env = envelope(
            2**64 - 1,
            self.prev,
            rec["ts_wall"],
            rec["ts_mono_delta"],
            rec["event"],
            self.kid,
            rec["schema_version"],
            self.seg,
            b"\x00" * 32,
        )
        return 4 + len(env) + 64 + 4 + bod_len + 4

    def _write(self, rec: dict) -> WrittenRecord:
        nonce = test_nonce(self.log.log_id, self.nonce_i)
        self.nonce_i += 1
        bod = body(rec["actor"], rec["payload"], nonce)
        bh = th("ogentic-audit/v0.2/body", bod)
        env = envelope(
            self.rid,
            self.prev,
            rec["ts_wall"],
            rec["ts_mono_delta"],
            rec["event"],
            self.kid,
            rec["schema_version"],
            self.seg,
            bh,
        )
        sig = raw_sign(SEEDS[self.key], signed_data(NS_RECORD, env))
        self.log.segments[-1] += frame(env, sig, bod)
        rh = th("ogentic-audit/v0.2/record", env)
        w = WrittenRecord(
            self.seg, self.rid, env, sig, bod, rh, bh, self.prev, rec["event"], rec["ts_wall"]
        )
        self.log.records.append(w)
        self.prev, self.rid = rh, self.rid + 1
        self.last_ts = (rec["ts_wall"], rec["ts_mono_delta"])
        return w

    def _bump(self) -> tuple[str, int]:
        ts, mono = self.last_ts
        return ms_ts(ts_ms(ts) + 1), mono + 1

    def append(self, rec: dict) -> WrittenRecord:
        if self.rid > 0:
            nonce_len_body = len(body(rec["actor"], rec["payload"], b"\x00" * 32))
            this = self._framed_len(rec, nonce_len_body)
            fin = self._framed_len(
                {
                    "ts_wall": rec["ts_wall"],
                    "ts_mono_delta": rec["ts_mono_delta"],
                    "event": "segment.finalized",
                    "schema_version": 1,
                },
                160,
            )
            if len(self.log.segments[-1]) + this + fin > self.size:
                self.rollover()
        return self._write(rec)

    def rollover(self) -> None:
        ts, mono = self._bump()
        payload = {"records": self.rid, "final_hash": self.prev}
        if self.mutate_finalize:
            self.mutate_finalize(payload)
        self._write(
            {
                "ts_wall": ts,
                "ts_mono_delta": mono,
                "actor": "system:audit",
                "event": "segment.finalized",
                "schema_version": 1,
                "payload": payload,
            }
        )
        self._new_segment(self.seg + 1, self.prev)

    def seal(self) -> WrittenRecord:
        ts, mono = self._bump()
        return self._write(
            {
                "ts_wall": ts,
                "ts_mono_delta": mono,
                "actor": "system:audit",
                "event": "log.sealed",
                "schema_version": 1,
                "payload": {},
            }
        )


def write_log(
    key: str,
    log_id: bytes,
    recs: list[dict],
    *,
    size=64 * 1024 * 1024,
    seal=False,
    mutate_finalize=None,
) -> Log:
    w = Writer(key, log_id, size, mutate_finalize)
    for r in recs:
        w.append(r)
    if seal:
        w.seal()
    return w.log


def offsets(seg: bytes) -> list[tuple[int, int, int, int, int]]:
    """Per record: (start, env_off, env_len, body_off, body_len)."""
    out = []
    pos = 128
    while pos + 4 <= len(seg):
        n = struct.unpack("<I", seg[pos : pos + 4])[0]
        bo = pos + 4 + n + 64
        bl = struct.unpack("<I", seg[bo : bo + 4])[0]
        out.append((pos, pos + 4, n, bo + 4, bl))
        pos = bo + 4 + bl + 4
    return out


def head_of(log: Log, upto: WrittenRecord | None = None) -> dict:
    r = upto or log.records[-1]
    count = log.records.index(r) + 1
    return {
        "log_id": log.log_id.hex(),
        "record_count": count,
        "record_hash": r.record_hash.hex(),
        "record_id": r.record_id,
        "segment": r.segment,
    }


def chain_json(log: Log, *, tampered: bool = False) -> bytes:
    pk = pub(SEEDS[log.key])
    doc = {
        "key": log.key,
        "log_id": log.log_id.hex(),
        "public_key": pk.hex(),
        "key_id": key_id(pk).hex(),
        "segments": [
            {
                "index": i,
                "chain_start": cs.hex(),
                "final": next(
                    (r.record_hash.hex() for r in reversed(log.records) if r.segment == i), cs.hex()
                ),
            }
            for i, cs in enumerate(log.chain_starts)
        ],
        "records": [
            {
                "position": f"s{r.segment}r{r.record_id}",
                "record_hash": r.record_hash.hex(),
                "body_hash": r.body_hash.hex(),
                "prev_hash": r.prev_hash.hex(),
                "signature": r.signature.hex(),
            }
            for r in log.records
        ],
        "post_tamper": tampered,
    }
    return (json.dumps(doc, indent=2, sort_keys=True) + "\n").encode()


# ---------------------------------------------------------------------------
# Checkpoints, witnesses, statements, attestations
# ---------------------------------------------------------------------------


def checkpoint_obj(
    log: Log,
    rec: WrittenRecord | None = None,
    *,
    standalone=True,
    observed_at="2026-10-03T13:00:00.000Z",
) -> dict:
    r = rec or log.records[-1]
    o = dict(head_of(log, r))
    o.update({"alg": "ed25519", "head_ts_wall": r.ts, "key_id": key_id(pub(SEEDS[log.key])).hex()})
    if standalone:
        o.update({"format": "ogentic-audit-checkpoint/v2", "observed_at": observed_at})
    return o


def transition_doc(
    old: str, new: str, heads=(), releases=(), issued="2027-01-15T09:00:00.000Z"
) -> bytes:
    npk = pub(SEEDS[new])
    return cjson(
        {
            "final_heads": list(heads),
            "final_releases": list(releases),
            "format": "ogentic-audit-key-transition/v1",
            "issued_at": issued,
            "new_key_id": key_id(npk).hex(),
            "new_public_key": openssh_line(npk),
            "old_key_id": key_id(pub(SEEDS[old])).hex(),
            "reason": "scheduled",
        }
    )


def revocation_doc(
    revoker: str,
    revoked: str,
    heads=(),
    releases=(),
    successors=(),
    issued="2027-02-01T00:00:00.000Z",
) -> bytes:
    return cjson(
        {
            "format": "ogentic-audit-key-revocation/v1",
            "issued_at": issued,
            "reason": "compromised",
            "revoked_key_id": key_id(pub(SEEDS[revoked])).hex(),
            "revoker_key_id": key_id(pub(SEEDS[revoker])).hex(),
            "trusted_heads": list(heads),
            "trusted_releases": list(releases),
            "trusted_successors": [key_id(pub(SEEDS[s])).hex() for s in successors],
        }
    )


INSTRUCTIONS = """How to check this release

This folder was signed when it was released. You can check that nothing in it has been
changed, without trusting whoever gave it to you and without any secret.

1. Get the signer's key fingerprint FROM THE SIGNER, not from this folder: from their
   website, a letter, a filing, or by phone. It is 64 characters long, usually written
   in 16 groups of 4. Any fingerprint printed inside this folder could have been replaced.

2. Check the signature and every file with standard tools, as described at
   https://github.com/OgenticAI/ogentic-audit/blob/main/docs/guides/verifying-a-release.md
   This needs only OpenSSH and Python, which most computers already have.

3. To also check the audit log, use ogentic-audit version 0.4.0 or later. Download it
   from https://github.com/OgenticAI/ogentic-audit/releases and check it as that page
   explains. Do not run a verifier from this folder until step 2 has passed. Then run:

     ogentic-audit verify-release . --key-fingerprint "<the fingerprint from step 1>"

   "Verified" means every file and the audit log are exactly as signed. "Not verified:
   you did not supply the signer's key" means you skipped step 1. Anything else names
   what changed, what is missing, or what was added.

Release: {release_id}
"""


def release_files(
    log: Log,
    *,
    elide=(),
    head: WrittenRecord | None = None,
    release_id="2026-0147",
    extra_files: dict | None = None,
) -> tuple[dict[str, bytes], dict]:
    """Release folder contents (unsigned attestation document)."""
    files: dict[str, bytes] = {
        "pages/0001.pdf": b"%PDF-1.7\n% page 1 of the released set\n",
        "pages/0002.pdf": b"%PDF-1.7\n% page 2 of the released set\n",
        "doc.pdf": b"%PDF-1.7\n% a multi-page document: page A, page B, page C\n",
        "Decisions.csv": b"page,decision\n1,release\n2,release\n",
        "HOW-TO-VERIFY.txt": INSTRUCTIONS.format(release_id=release_id).encode(),
    }
    if extra_files:
        files.update(extra_files)
    roles = {
        "pages/0001.pdf": "page",
        "pages/0002.pdf": "page",
        "doc.pdf": "document",
        "Decisions.csv": "index",
        "HOW-TO-VERIFY.txt": "instructions",
    }
    parts = {"Decisions.csv": [("header", 0, 14), ("row 1", 14, 10), ("row 2", 24, 10)]}
    # The log copy, through the head, with elided bodies.
    hd = head or log.records[-1]
    log_files: dict[str, bytearray] = {}
    for r in log.records:
        name = f"audit-{r.segment:04d}.cbor"
        if name not in log_files:
            log_files[name] = bytearray(log.segments[r.segment][:128])
        withhold = (r.segment, r.record_id) in elide
        log_files[name] += frame(r.envelope, r.signature, None if withhold else r.body)
        if r is hd:
            break
    for name, b in log_files.items():
        files[f"Audit log/{name}"] = bytes(b)
    entries = []
    for path in sorted(p for p in files if not p.startswith("Audit log/")):
        data = files[path]
        e = {"path": path, "sha256": sha256(data).hex(), "size": len(data)}
        if path in roles:
            e["role"] = roles[path]
        if path in parts:
            e["parts"] = [
                {"length": n, "name": nm, "offset": o, "sha256": sha256(data[o : o + n]).hex()}
                for nm, o, n in parts[path]
            ]
        entries.append(e)
    cp = checkpoint_obj(log, hd, standalone=False)
    doc = {
        "alg": "ed25519",
        "created_at": "2026-10-03T12:00:00.000Z",
        "files": entries,
        "format": "ogentic-audit-release/v1",
        "key_id": key_id(pub(SEEDS[log.key])).hex(),
        "logs": [{"checkpoint": cp, "path": "Audit log"}],
        "release_id": release_id,
    }
    return files, doc


def sign_release(
    files: dict[str, bytes], doc: Any, key: str = "K1", *, raw: bytes | None = None, **sigkw
) -> dict[str, bytes]:
    att = raw if raw is not None else cjson(doc)
    out = dict(files)
    out["ogentic-audit-release.json"] = att
    out["ogentic-audit-release.json.sig"] = detached(key, sigkw.pop("ns", NS_RELEASE), att, **sigkw)
    out["ogentic-audit-signer.pub"] = (
        openssh_line(pub(SEEDS[key]), "ogentic-audit-release-signer") + "\n"
    ).encode()
    return out


# ---------------------------------------------------------------------------
# Vector definitions
# ---------------------------------------------------------------------------


@dataclass
class Vector:
    name: str
    description: str
    files: dict[str, bytes]
    runs: list[dict]
    writer: dict | None = None
    extra: dict = field(default_factory=dict)
    chain: Log | None = None
    tampered: bool = False


def fp(k: str) -> str:
    return grouped(key_id(pub(SEEDS[k])))


def pin(k: str) -> dict:
    return {"key_fingerprint": [fp(k)]}


def run(expect: dict, **kw) -> dict:
    d = {"command": "verify", "target": "log"}
    d.update(kw)
    d["expect"] = expect
    return d


def ok(**kw) -> dict:
    e = {"exit": 0, "verdict": "Verified"}
    e.update(kw)
    return e


def bad(verdict: str, **kw) -> dict:
    e = {"exit": 1, "verdict": verdict}
    e.update(kw)
    return e


def err(exit_code: int = 3, **kw) -> dict:
    e = {"exit": exit_code}
    e.update(kw)
    return e


def logfiles(log: Log, prefix="log/") -> dict[str, bytes]:
    return {prefix + k: v for k, v in log.files().items()}


def writer_spec(
    key: str, log_id: bytes, recs: list[dict], size=64 * 1024 * 1024, seal=False
) -> dict:
    return {
        "key": key,
        "log_id": log_id.hex(),
        "session_id": SESSION.hex(),
        "segment_size_bytes": size,
        "seal": seal,
        "records": recs,
        "nonce_rule": "test_nonce",
    }


def trust_file(lines: list[tuple[str, str, str | None]]) -> bytes:
    out = []
    for principal, k, scope in lines:
        opt = f' namespaces="{scope}"' if scope else ""
        out.append(f"{principal}{opt} {openssh_line(pub(SEEDS[k]))}")
    return ("\n".join(out) + "\n").encode()


def statement_files(
    prefix: str, name: str, doc: bytes, signer: str, ns: str, accept: str | None = None
) -> dict[str, bytes]:
    f = {f"{prefix}/{name}.json": doc, f"{prefix}/{name}.json.sig": detached(signer, ns, doc)}
    if accept:
        f[f"{prefix}/{name}.json.accept.sig"] = detached(accept, NS_ACCEPT, doc)
    return f


def build_vectors() -> list[Vector]:
    V: list[Vector] = []
    five = record_inputs(5)

    # --- Logs --------------------------------------------------------------
    empty = write_log("K1", LOG_A, [])
    V.append(
        Vector(
            "signed-empty",
            "Header only.",
            logfiles(empty),
            [run(err(4, verdict="SelfConsistent", reason="no_signed_records"), **pin("K1"))],
            writer_spec("K1", LOG_A, []),
        )
    )
    one = write_log("K1", LOG_A, record_inputs(1))
    V.append(
        Vector(
            "signed-single-record",
            "One record.",
            logfiles(one),
            [run(ok(head_anchored=False), **pin("K1"))],
            writer_spec("K1", LOG_A, record_inputs(1)),
        )
    )
    V.append(
        Vector(
            "signed-single-record-unpinned",
            "No trust input.",
            logfiles(one),
            [run(err(4, verdict="SelfConsistent", reason="not_pinned"))],
        )
    )
    sealed = write_log("K1", LOG_A, record_inputs(3), seal=True)
    V.append(
        Vector(
            "signed-sealed",
            "Three records then log.sealed.",
            logfiles(sealed),
            [run(ok(head_anchored=True), **pin("K1"))],
            writer_spec("K1", LOG_A, record_inputs(3), seal=True),
        )
    )
    k1000 = write_log("K1", LOG_A, record_inputs(1000))
    V.append(
        Vector(
            "signed-1k-records",
            "1000 records.",
            logfiles(k1000),
            [run(ok(), **pin("K1"))],
            writer_spec("K1", LOG_A, record_inputs(1000)),
        )
    )
    roll = write_log("K1", LOG_A, record_inputs(6), size=1024)
    V.append(
        Vector(
            "signed-segment-rollover",
            "segment_size_bytes 1024: several segments.",
            logfiles(roll),
            [run(ok(), **pin("K1"))],
            writer_spec("K1", LOG_A, record_inputs(6), size=1024),
        )
    )

    base5 = write_log("K1", LOG_A, five)

    def mutated(fn) -> dict[str, bytes]:
        seg = bytearray(base5.segments[0])
        fn(seg, offsets(bytes(seg)))
        return {"log/audit-0000.cbor": bytes(seg)}

    def xor_env(seg, o):
        seg[o[2][1] + 10] ^= 0xFF

    def xor_body(seg, o):
        seg[o[2][3] + 3] ^= 0x01

    def xor_sig(seg, o):
        seg[o[2][1] + o[2][2] + 5] ^= 0x01

    def reenc(seg, o):
        s = o[2][1] + o[2][2]
        seg[s : s + 64] = plus_l(bytes(seg[s : s + 64]))

    def elide13(seg, o):
        for i in (3, 1):
            _, _, _, bo, bl = o[i]
            del seg[bo : bo + bl]
            seg[bo - 4 : bo] = struct.pack("<I", 0)

    def drop2(seg, o):
        start, end = o[2][0], o[3][0]
        del seg[start:end]

    def swap23(seg, o):
        r2 = bytes(seg[o[2][0] : o[3][0]])
        r3 = bytes(seg[o[3][0] : o[4][0]])
        seg[o[2][0] : o[4][0]] = r3 + r2

    V.append(
        Vector(
            "signed-tampered-envelope",
            "Byte 10 of r2's envelope XOR 0xff.",
            mutated(xor_env),
            [run(bad("SignatureInvalid@s0r2", reason="mismatch"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-tampered-body",
            "Byte 3 of r2's body XOR 0x01.",
            mutated(xor_body),
            [run(bad("SignatureInvalid@s0r2", reason="body_mismatch"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-tampered-signature",
            "Byte 5 of r2's signature XOR 0x01.",
            mutated(xor_sig),
            [run(bad("SignatureInvalid@s0r2", reason="mismatch"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-reencoded-s",
            "r2's S replaced by S + L.",
            mutated(reenc),
            [run(bad("SignatureInvalid@s0r2", reason="reencoded"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-elided",
            "Bodies of r1 and r3 elided.",
            mutated(elide13),
            [run(ok(elided=["s0r1", "s0r3"]), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-missing-record",
            "r2 removed.",
            mutated(drop2),
            [run(bad("ChainBreak@s0r2"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-reordered",
            "r2 and r3 swapped.",
            mutated(swap23),
            [run(bad("ChainBreak@s0r2"), **pin("K1"))],
        )
    )

    roll3 = write_log("K1", LOG_A, record_inputs(4), size=1024)
    # Elide the body of s0's segment.finalized (its last record).
    seg0 = bytearray(roll3.segments[0])
    o = offsets(bytes(seg0))
    fin_idx = len(o) - 1
    _, _, _, bo, bl = o[fin_idx]
    del seg0[bo : bo + bl]
    seg0[bo - 4 : bo] = struct.pack("<I", 0)
    files = logfiles(roll3)
    files["log/audit-0000.cbor"] = bytes(seg0)
    V.append(
        Vector(
            "signed-elided-structural",
            "The body of s0's segment.finalized is elided.",
            files,
            [run(bad(f"RecordCorrupt@s0r{fin_idx}", reason="ElidedStructural"), **pin("K1"))],
        )
    )

    k2log = write_log("K2", LOG_A, five)
    V.append(
        Vector(
            "signed-other-key",
            "The same records signed by K2; pin K1.",
            logfiles(k2log),
            [run(bad("UntrustedSigner@s0", reason="not_trusted"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-out-of-scope",
            "K1 pinned with the witness scope only.",
            {**logfiles(base5), "allowed_signers": trust_file([("auditor", "K1", NS_WITNESS)])},
            [run(bad("UntrustedSigner@s0", reason="out_of_scope"), trust="allowed_signers")],
        )
    )
    # Weak key in the header: the identity point.
    ident = bytes.fromhex("01" + "00" * 31)
    hdr = header(0, LOG_A, ident, b"\x00" * 32)
    env = envelope(
        0,
        th("ogentic-audit/v0.2/header", hdr[:124]),
        ts_of(0),
        0,
        "page.released",
        key_id(ident),
        1,
        0,
        b"\x00" * 32,
    )
    forged = bytes([1] + [0] * 63)
    V.append(
        Vector(
            "signed-weak-key-header",
            "Header key is the identity point; a forged record.",
            {"log/audit-0000.cbor": hdr + frame(env, forged, None)},
            [run(bad("SignatureInvalid@s0", reason="weak_key"))],
        )
    )

    def header_patch(src: Log, seg: int, **kw) -> dict[str, bytes]:
        files = logfiles(src)
        old = src.segments[seg]
        pk = kw.pop("pk", old[92:124])
        h = header(seg, kw.pop("log_id", old[12:28]), pk, old[60:92], **kw)
        files[f"log/audit-{seg:04d}.cbor"] = h + old[128:]
        return files

    V.append(
        Vector(
            "signed-key-change-s1",
            "Segment 1's header names K2.",
            header_patch(roll3, 1, pk=pub(SEEDS["K2"])),
            [run(bad("KeyIdMismatch@s1"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-log-id-change-s1",
            "Segment 1's header has another log_id.",
            header_patch(roll3, 1, log_id=LOG_B),
            [run(bad("LogIdMismatch@s1"), **pin("K1"))],
        )
    )
    files = logfiles(roll3)
    files["log/audit-0001.cbor"] = roll3.segments[1][:128]
    V.append(
        Vector(
            "signed-empty-middle-segment",
            "Segment 1 holds only its header; segment 2 follows.",
            files,
            [run(bad("SegmentDiscontinuity@s2"), **pin("K1"))],
        )
    )
    files = logfiles(roll3)
    del files["log/audit-0001.cbor"]
    V.append(
        Vector(
            "signed-segment-gap",
            "audit-0001.cbor missing.",
            files,
            [run(bad("SegmentDiscontinuity@s1"), **pin("K1"))],
        )
    )

    def wrong_records(p):
        p["records"] += 1

    badroll = write_log("K1", LOG_A, record_inputs(4), size=1024, mutate_finalize=wrong_records)
    fin = next(r for r in badroll.records if r.event == "segment.finalized")
    V.append(
        Vector(
            "signed-bad-rollover",
            "A validly signed segment.finalized with a wrong records count.",
            logfiles(badroll),
            [run(bad(f"RecordCorrupt@s0r{fin.record_id}", reason="BadRollover"), **pin("K1"))],
        )
    )
    roll2 = write_log("K1", LOG_A, record_inputs(2), size=1024)
    files = logfiles(roll2)
    last = max(files)
    del files[last]
    V.append(
        Vector(
            "signed-rolled-over-no-successor",
            "The last segment deleted after a rollover.",
            files,
            [run(ok(head_anchored=False, warnings=["RolledOverWithoutSuccessor"]), **pin("K1"))],
        )
    )
    three = write_log("K1", LOG_A, record_inputs(3))
    files = logfiles(three)
    files["log/audit-0001.cbor"] = header(1, LOG_A, pub(SEEDS["K1"]), three.records[-1].record_hash)
    V.append(
        Vector(
            "signed-forged-header-tail",
            "A header-only segment appended (anyone can make one).",
            files,
            [run(ok(warnings=["UnsignedLastSegment"]), **pin("K1"))],
        )
    )
    w = Writer("K1", LOG_A)
    for r in record_inputs(2):
        w.append(r)
    w.seal()
    extra = w._write(
        {
            "ts_wall": ts_of(5),
            "ts_mono_delta": 5000,
            "actor": "user:clerk",
            "event": "page.released",
            "schema_version": 1,
            "payload": {"page": 5},
        }
    )
    V.append(
        Vector(
            "signed-after-seal",
            "A record after log.sealed.",
            logfiles(w.log),
            [run(bad(f"SealedLogExtended@s0r{extra.record_id}"), **pin("K1"))],
        )
    )
    big = (
        header(0, LOG_A, pub(SEEDS["K1"]), b"\x00" * 32)
        + struct.pack("<I", 5000)
        + b"\x00" * 5000
        + b"\x00" * 64
        + struct.pack("<I", 0)
        + struct.pack("<I", 5000)
    )
    V.append(
        Vector(
            "signed-envelope-too-large",
            "len_prefix 5000 (over 4096).",
            {"log/audit-0000.cbor": big},
            [run(bad("RecordCorrupt@s0r0", reason="TooLarge"), **pin("K1"))],
        )
    )

    def single_custom(env_bytes_fn) -> dict[str, bytes]:
        h = header(0, LOG_A, pub(SEEDS["K1"]), b"\x00" * 32)
        cs = th("ogentic-audit/v0.2/header", h[:124])
        bod = body("user:clerk", {"page": 0}, test_nonce(LOG_A, 0))
        e = env_bytes_fn(cs, th("ogentic-audit/v0.2/body", bod))
        sig = raw_sign(SEEDS["K1"], signed_data(NS_RECORD, e))
        return {"log/audit-0000.cbor": h + frame(e, sig, bod)}

    kid1 = key_id(pub(SEEDS["K1"]))

    def noncanon(cs, bh):
        e = envelope(0, cs, ts_of(0), 0, "page.released", kid1, 1, 0, bh)
        # record_id 0 encoded as 0x18 0x00 (non-canonical).
        return e[:2] + b"\x18\x00" + e[3:]

    def unknown_key(cs, bh):
        return envelope(
            0, cs, ts_of(0), 0, "page.released", kid1, 1, 0, bh, extra=[(20, c_uint(1))]
        )

    V.append(
        Vector(
            "signed-noncanonical-envelope",
            "A signed envelope with a non-canonical integer.",
            single_custom(noncanon),
            [run(bad("RecordCorrupt@s0r0", reason="DecodeError"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-unknown-envelope-key",
            "A signed envelope with key 20.",
            single_custom(unknown_key),
            [run(bad("RecordCorrupt@s0r0", reason="DecodeError"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-unsupported-alg",
            "Header sig_alg 0x0002 (reserved, not implemented).",
            header_patch(one, 0, sig_alg=2),
            [run(bad("UnsupportedAlgorithm@s0"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-key-id-mismatch",
            "Header key_id wrong.",
            header_patch(one, 0, kid=b"\x11" * 32),
            [run(bad("KeyIdMismatch@s0"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-reserved-nonzero",
            "Header reserved = 1.",
            header_patch(one, 0, reserved=1),
            [run(bad("HeaderCorrupt@s0", reason="ReservedBytesNonZero"), **pin("K1"))],
        )
    )
    files = logfiles(roll3)
    v01_body = b"OGAU" + struct.pack("<HH", 1, 1) + b"\x22" * 32 + roll3.records[-1].record_hash
    files["log/audit-0001.cbor"] = (
        v01_body + struct.pack("<I", zlib.crc32(v01_body) & 0xFFFFFFFF) + b"\x00" * 4
    )
    V.append(
        Vector(
            "signed-mixed-v01-segment",
            "Segment 1 is a v0.1 (HMAC) segment.",
            files,
            [run(bad("FormatDowngrade@s1"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "signed-expect-log-id",
            "--expect-log-id of another log.",
            logfiles(one),
            [run(bad("LogIdMismatch@s0"), expect_log_id=LOG_B.hex(), **pin("K1"))],
        )
    )
    files = logfiles(roll3)
    seg0 = bytearray(roll3.segments[0])
    o = offsets(bytes(seg0))
    seg0[o[0][1] + o[0][2] + 5] ^= 1
    files["log/audit-0000.cbor"] = bytes(seg0)
    V.append(
        Vector(
            "signed-segment-filter",
            "Tamper in s0; --segment 1 narrows the report but never improves the verdict.",
            files,
            [
                run(bad("Violation"), segment=1, **pin("K1"), name="pinned-s1"),
                run(bad("UntrustedSigner@s0"), segment=1, **pin("K2"), name="other-key-s1"),
            ],
        )
    )
    v01 = {
        f"log/{p.name}": p.read_bytes()
        for p in sorted((V01_DIR / "single-record").glob("audit-*.cbor"))
    }
    v01_key = json.loads((V01_DIR / "single-record" / "inputs.json").read_text())["key_hex"]
    V.append(
        Vector(
            "v01-under-signed-mode",
            "The v0.1 single-record log, pin K1.",
            v01,
            [run(err(3, error="HmacLog"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "v01-no-key",
            "The v0.1 single-record log, no key, env var set.",
            v01,
            [run(err(3), env={"OGENTIC_AUDIT_KEY_HEX": v01_key})],
        )
    )
    V.append(
        Vector(
            "v01-explicit-key",
            "The v0.1 single-record log, key named explicitly.",
            v01,
            [
                run(
                    {"exit": 0, "verdict": "Verified", "authentication": "shared-key"},
                    hmac_key_source="env",
                    env={"OGENTIC_AUDIT_KEY_HEX": v01_key},
                )
            ],
        )
    )
    V.append(
        Vector(
            "v02-under-hmac-key",
            "A signed log with an explicit HMAC key.",
            logfiles(one),
            [run(err(3), hmac_key_source="env", env={"OGENTIC_AUDIT_KEY_HEX": v01_key})],
        )
    )
    V.append(
        Vector(
            "v02-on-old-verifier",
            "Recorded: a 0.3.x verifier reports a signed log as UnknownVersion (exit 1). Checked with the v0.1 verifier of this crate.",
            logfiles(one),
            [run(bad("UnknownVersion@s0"), command="v01-verifier", hmac_key_hex=v01_key)],
        )
    )

    # --- Inputs and keys -----------------------------------------------------
    small = [
        "0000000000000000000000000000000000000000000000000000000000000000",
        "0000000000000000000000000000000000000000000000000000000000000080",
        "0100000000000000000000000000000000000000000000000000000000000000",
        "0100000000000000000000000000000000000000000000000000000000000080",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc05",
        "26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac037a",
        "c7176a703d4dd84fba3c0b760d10670f2a2053fa2c39ccc64ec7fd7792ac03fa",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
    ]
    V.append(
        Vector(
            "pin-weak-key",
            "Each Appendix A encoding as --public-key.",
            logfiles(one),
            [run(err(3), public_key=k, name=f"weak-{i}") for i, k in enumerate(small)],
            extra={
                "appendix_a": [
                    {"encoding": k, "fingerprint": key_id(bytes.fromhex(k)).hex()} for k in small
                ]
            },
        )
    )
    k1pt = decode_point(pub(SEEDS["K1"]))[0]
    t8 = decode_point(bytes.fromhex(small[4]))[0]
    mixed = _add(k1pt, t8)
    zinv = pow(mixed[2], P - 2, P)
    mx, my = mixed[0] * zinv % P, mixed[1] * zinv % P
    menc = (my | ((mx & 1) << 255)).to_bytes(32, "little")
    V.append(
        Vector(
            "pin-mixed-order-key",
            "K1 plus a point of order 8: not small-order, not torsion-free.",
            logfiles(one),
            [run(err(3), public_key=menc.hex())],
        )
    )
    h64 = key_id(pub(SEEDS["K1"])).hex()
    V.append(
        Vector(
            "fingerprint-63-hex",
            "63 hex digits.",
            logfiles(one),
            [run(err(3), key_fingerprint=[h64[:63]])],
        )
    )
    V.append(
        Vector(
            "fingerprint-65-hex",
            "65 hex digits.",
            logfiles(one),
            [run(err(3), key_fingerprint=[h64 + "0"])],
        )
    )
    V.append(
        Vector(
            "fingerprint-sha256-31-bytes",
            "SHA256: with 31 bytes.",
            logfiles(one),
            [
                run(
                    err(3),
                    key_fingerprint=["SHA256:" + base64.b64encode(bytes(31)).decode().rstrip("=")],
                )
            ],
        )
    )
    V.append(
        Vector(
            "trust-file-unknown-option",
            "cert-authority option.",
            {
                **logfiles(one),
                "allowed_signers": f"signer cert-authority {openssh_line(pub(SEEDS['K1']))}\n".encode(),
            },
            [run(err(3), trust="allowed_signers")],
        )
    )
    cases = json.loads((Path(__file__).parent / "ed25519_speccheck_cases.json").read_text())
    expected = []
    for i, c in enumerate(cases):
        r = strict_verify(
            bytes.fromhex(c["pub_key"]), bytes.fromhex(c["message"]), bytes.fromhex(c["signature"])
        )
        expected.append({"case": i, "accept": r is None, "reason": r})
    V.append(
        Vector(
            "ed25519-edge",
            'The 12 cases of "Taming the many EdDSAs" (Chalkias, Garillot, Nikolaenko, 2020; github.com/novifinancial/ed25519-speccheck, Apache-2.0), judged under spec §3.5.',
            {
                "cases.json": (json.dumps(cases, indent=1) + "\n").encode(),
                "expected.json": (json.dumps(expected, indent=1) + "\n").encode(),
            },
            [
                {
                    "command": "ed25519",
                    "target": "cases.json",
                    "expect": {"exit": 0, "file": "expected.json"},
                }
            ],
        )
    )

    # --- Checkpoints and witnesses -------------------------------------------
    six = write_log("K1", LOG_A, record_inputs(6))
    cp4 = cjson(checkpoint_obj(six, six.records[4]))
    cpfiles = {"cp.json": cp4, "cp.json.sig": detached("K1", NS_CHECKPOINT, cp4)}
    cut = write_log("K1", LOG_A, record_inputs(3))
    V.append(
        Vector(
            "checkpoint-truncated",
            "Signed at r4; the log cut to r2.",
            {**logfiles(cut), **cpfiles},
            [run(bad("CheckpointTruncated@s0r4"), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    re_recs = record_inputs(2) + record_inputs(6, event="page.withheld")[2:]
    rewritten = write_log("K1", LOG_A, re_recs)
    V.append(
        Vector(
            "checkpoint-rewritten",
            "K1 re-chains from r2, same log_id.",
            {**logfiles(rewritten), **cpfiles},
            [run(bad("CheckpointMismatch@s0r4"), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    cp0 = cjson(checkpoint_obj(six, six.records[0]))
    full = write_log("K1", LOG_A, record_inputs(6, event="page.withheld"))
    V.append(
        Vector(
            "checkpoint-full-rewrite-same-id",
            "K1 rewrites from r0 with the same log_id.",
            {**logfiles(full), "cp.json": cp0, "cp.json.sig": detached("K1", NS_CHECKPOINT, cp0)},
            [run(bad("CheckpointMismatch@s0r0"), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    logb = write_log("K1", LOG_B, record_inputs(6))
    V.append(
        Vector(
            "checkpoint-other-log",
            "K1's checkpoint of log A against K1's log B.",
            {**logfiles(logb), **cpfiles},
            [run(bad("CheckpointForDifferentLog@s0"), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    k2six = write_log("K2", LOG_A, record_inputs(6))
    V.append(
        Vector(
            "checkpoint-other-signer",
            "K2's log, K1's checkpoint; both keys trusted.",
            {
                **logfiles(k2six),
                **cpfiles,
                "allowed_signers": trust_file([("one", "K1", None), ("two", "K2", None)]),
            },
            [
                run(
                    err(3, error="CheckpointForDifferentSigner"),
                    checkpoints=["cp.json"],
                    trust="allowed_signers",
                )
            ],
        )
    )
    cpk2 = json.loads(cp4)
    cpk2["key_id"] = key_id(pub(SEEDS["K2"])).hex()
    cpk2b = cjson(cpk2)
    V.append(
        Vector(
            "checkpoint-untrusted-signer",
            "A checkpoint signed by K2; pin K1.",
            {
                **logfiles(six),
                "cp.json": cpk2b,
                "cp.json.sig": detached("K2", NS_CHECKPOINT, cpk2b),
            },
            [run(err(3, error="CheckpointSignerUntrusted"), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    cp_last = cjson(checkpoint_obj(three))
    anch = {"cp.json": cp_last, "cp.json.sig": detached("K1", NS_CHECKPOINT, cp_last)}
    V.append(
        Vector(
            "checkpoint-anchors-head",
            "A K1 checkpoint naming the last record.",
            {**logfiles(three), **anch},
            [run(ok(head_anchored=True), checkpoints=["cp.json"], **pin("K1"))],
        )
    )
    wdoc = cjson(
        {
            "checkpoint_sha256": sha256(cp_last).hex(),
            "format": "ogentic-audit-witness/v1",
            "observed_at": "2026-10-03T13:05:00.000Z",
            "witness_key_id": key_id(pub(SEEDS["K3"])).hex(),
        }
    )
    V.append(
        Vector(
            "witness-cosigned",
            "K3, pinned with the witness scope, co-signs.",
            {
                **logfiles(three),
                **anch,
                "w.json": wdoc,
                "w.json.sig": detached("K3", NS_WITNESS, wdoc),
                "allowed_signers": trust_file(
                    [("log-signer", "K1", None), ("auditor", "K3", NS_WITNESS)]
                ),
            },
            [
                run(
                    ok(head_anchored=True, witnesses=["auditor"]),
                    checkpoints=["cp.json"],
                    witnesses=["w.json"],
                    trust="allowed_signers",
                )
            ],
        )
    )
    k3log = write_log("K3", LOG_A, record_inputs(2))
    V.append(
        Vector(
            "witness-as-signer",
            "K3 pinned as a witness signs a log.",
            {**logfiles(k3log), "allowed_signers": trust_file([("auditor", "K3", NS_WITNESS)])},
            [run(bad("UntrustedSigner@s0", reason="out_of_scope"), trust="allowed_signers")],
        )
    )
    other = json.loads(cp4)
    other["record_hash"] = rewritten.records[4].record_hash.hex()
    ob = cjson(other)
    V.append(
        Vector(
            "equivocation",
            "Two K1 checkpoints, same position, different hash.",
            {
                "a.json": cp4,
                "a.json.sig": detached("K1", NS_CHECKPOINT, cp4),
                "b.json": ob,
                "b.json.sig": detached("K1", NS_CHECKPOINT, ob),
            },
            [
                {
                    "command": "checkpoint-compare",
                    "target": "a.json",
                    "other": "b.json",
                    "expect": {"exit": 1, "equivocation": True},
                }
            ],
        )
    )

    # --- Statements -------------------------------------------------------------
    k1old = write_log("K1", LOG_B, record_inputs(3), seal=True)
    k2new = write_log("K2", LOG_A, record_inputs(3))
    t12 = transition_doc("K1", "K2", heads=[head_of(k1old)])
    st12 = statement_files("keys", "k1-k2", t12, "K1", NS_TRANSITION, accept="K2")
    V.append(
        Vector(
            "transition",
            "Log by K2; K1→K2 with acceptance; pin K1.",
            {**logfiles(k2new), **st12},
            [run(ok(trust_path=[fp("K1"), fp("K2")]), statements=["keys"], **pin("K1"))],
        )
    )
    k3new = write_log("K3", LOG_A, record_inputs(2))
    t23 = transition_doc("K2", "K3", heads=[head_of(k2new)])
    V.append(
        Vector(
            "transition-two-hop",
            "K1→K2→K3; log by K3.",
            {
                **logfiles(k3new),
                **st12,
                **statement_files("keys", "k2-k3", t23, "K2", NS_TRANSITION, accept="K3"),
            },
            [run(ok(), statements=["keys"], **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "transition-no-accept",
            "Acceptance missing.",
            {**logfiles(k2new), **statement_files("keys", "k1-k2", t12, "K1", NS_TRANSITION)},
            [
                run(
                    bad("UntrustedSigner@s0", warnings=["IgnoredStatement"]),
                    statements=["keys"],
                    statements_source="bundle",
                    **pin("K1"),
                    name="bundle",
                ),
                run(err(3), statements=["keys"], **pin("K1"), name="operator"),
            ],
        )
    )
    stranger = {
        "keys/forged.json": t12,
        "keys/forged.json.sig": detached("K3", NS_TRANSITION, t12),
        "keys/forged.json.accept.sig": detached("K2", NS_ACCEPT, t12),
    }
    V.append(
        Vector(
            "transition-stranger-signed",
            "Signed by K3, claims old_key_id K1.",
            {**logfiles(k2new), **stranger},
            [
                run(
                    bad("UntrustedSigner@s0"),
                    statements=["keys"],
                    statements_source="bundle",
                    **pin("K1"),
                    name="bundle",
                ),
                run(err(3), statements=["keys"], **pin("K1"), name="operator"),
            ],
        )
    )
    k1late = write_log("K1", LOG_A, record_inputs(2))
    V.append(
        Vector(
            "transition-retired-new-log",
            "A new log by K1 after K1→K2.",
            {**logfiles(k1late), **st12},
            [run(bad("RetiredKey@s0r0"), statements=["keys"], **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "transition-retired-final-head",
            "K1's log within final_heads.",
            {**logfiles(k1old), **st12},
            [run(ok(), statements=["keys"], **pin("K1"))],
        )
    )
    t13 = transition_doc("K1", "K3")
    V.append(
        Vector(
            "transition-equivocation",
            "K1→K2 and K1→K3, both accepted; log by K2.",
            {
                **logfiles(k2new),
                **st12,
                **statement_files("keys", "k1-k3", t13, "K1", NS_TRANSITION, accept="K3"),
            },
            [
                run(
                    bad(f"TransitionEquivocation@key:{key_id(pub(SEEDS['K1'])).hex()}"),
                    statements=["keys"],
                    **pin("K1"),
                )
            ],
        )
    )
    k2eight = write_log("K2", LOG_A, record_inputs(8))
    h4 = head_of(k2eight, k2eight.records[4])
    h6 = head_of(k2eight, k2eight.records[6])
    ops = trust_file(
        [("ops", "K2", None), ("ops", "K1", NS_REVOCATION), ("ops", "K3", NS_REVOCATION)]
    )
    selfrev = revocation_doc("K2", "K2", heads=[h6])
    V.append(
        Vector(
            "revoked-self",
            "K2 self-revoked (lists set, ignored).",
            {
                **logfiles(k2eight),
                "allowed_signers": ops,
                **statement_files("rev", "self", selfrev, "K2", NS_REVOCATION),
            },
            [run(bad("RevokedKey@s0r0"), trust="allowed_signers", revocations=["rev/self.json"])],
        )
    )
    auth4 = revocation_doc("K1", "K2", heads=[h4])
    V.append(
        Vector(
            "revoked-authority-trusted-head",
            "K1 revokes K2 with trusted_heads at r4.",
            {
                **logfiles(k2eight),
                "allowed_signers": ops,
                **statement_files("rev", "auth", auth4, "K1", NS_REVOCATION),
            },
            [run(bad("RevokedKey@s0r5"), trust="allowed_signers", revocations=["rev/auth.json"])],
        )
    )
    V.append(
        Vector(
            "revoked-stranger-signed",
            "Claims revoker K1, signed by K3.",
            {
                **logfiles(k2eight),
                "allowed_signers": ops,
                "rev/forged.json": auth4,
                "rev/forged.json.sig": detached("K3", NS_REVOCATION, auth4),
            },
            [
                run(
                    err(3),
                    trust="allowed_signers",
                    revocations=["rev/forged.json"],
                    name="operator",
                ),
                run(
                    ok(warnings=["IgnoredStatement"]),
                    trust="allowed_signers",
                    statements=["rev"],
                    statements_source="bundle",
                    name="bundle",
                ),
            ],
        )
    )
    witrev = revocation_doc("K3", "K1")
    k1eight = write_log("K1", LOG_A, record_inputs(2))
    V.append(
        Vector(
            "revoked-by-witness",
            "K3 has the witness scope only and revokes K1.",
            {
                **logfiles(k1eight),
                "allowed_signers": trust_file([("ops", "K1", None), ("ops", "K3", NS_WITNESS)]),
                **statement_files("rev", "w", witrev, "K3", NS_REVOCATION),
            },
            [
                run(err(3), trust="allowed_signers", revocations=["rev/w.json"], name="operator"),
                run(
                    ok(warnings=["IgnoredStatement"]),
                    trust="allowed_signers",
                    statements=["rev"],
                    statements_source="bundle",
                    name="bundle",
                ),
            ],
        )
    )
    a46 = revocation_doc("K1", "K2", heads=[h4, h6])
    b4 = revocation_doc("K3", "K2", heads=[h4])
    conf = {
        **statement_files("rev", "a", a46, "K1", NS_REVOCATION),
        **statement_files("rev", "b", b4, "K3", NS_REVOCATION),
    }
    V.append(
        Vector(
            "revoked-conflicting",
            "Two authority revocations, trusted_heads {r4, r6} and {r4}: the intersection applies, in either order.",
            {**logfiles(k2eight), "allowed_signers": ops, **conf},
            [
                run(
                    bad("RevokedKey@s0r5"),
                    trust="allowed_signers",
                    revocations=["rev/a.json", "rev/b.json"],
                    name="a-then-b",
                ),
                run(
                    bad("RevokedKey@s0r5"),
                    trust="allowed_signers",
                    revocations=["rev/b.json", "rev/a.json"],
                    name="b-then-a",
                ),
            ],
        )
    )
    sta = {
        **statement_files("rev", "self", selfrev, "K2", NS_REVOCATION),
        **statement_files("rev", "auth", auth4, "K1", NS_REVOCATION),
    }
    V.append(
        Vector(
            "revoked-self-then-authority",
            "Self-revocation and an authority revocation (r4), in either order.",
            {**logfiles(k2eight), "allowed_signers": ops, **sta},
            [
                run(
                    bad("RevokedKey@s0r5"),
                    trust="allowed_signers",
                    revocations=["rev/self.json", "rev/auth.json"],
                    name="self-first",
                ),
                run(
                    bad("RevokedKey@s0r5"),
                    trust="allowed_signers",
                    revocations=["rev/auth.json", "rev/self.json"],
                    name="authority-first",
                ),
            ],
        )
    )
    k4log = write_log("K4", LOG_A, record_inputs(2))
    atk = revocation_doc("K2", "K2", successors=["K4"])
    t24 = transition_doc("K2", "K4")
    V.append(
        Vector(
            "revoked-attacker-successor",
            "K2 self-revokes listing K4 as successor, and K2→K4 exists: K4 is not trusted.",
            {
                **logfiles(k4log),
                **statement_files("keys", "k2-k4", t24, "K2", NS_TRANSITION, accept="K4"),
                **statement_files("rev", "self", atk, "K2", NS_REVOCATION),
            },
            [
                run(
                    bad("UntrustedSigner@s0"),
                    statements=["keys"],
                    revocations=["rev/self.json"],
                    **pin("K2"),
                )
            ],
        )
    )

    # --- Releases ---------------------------------------------------------------
    rlog = write_log("K1", LOG_A, five, seal=True)
    base_files, base_doc = release_files(rlog)

    def rel(files: dict[str, bytes]) -> dict[str, bytes]:
        return {"release/" + k: v for k, v in files.items()}

    def rrun(expect, **kw):
        kw.setdefault("command", "verify-release")
        kw.setdefault("target", "release")
        return run(expect, **kw)

    clean = sign_release(base_files, base_doc)
    V.append(
        Vector(
            "release-clean",
            "Clean release.",
            rel(clean),
            [rrun(ok(), **pin("K1"))],
            extra={"builder": {"log": "signed-release-source", "elide": []}},
        )
    )
    ef, ed = release_files(rlog, elide={(0, 1), (0, 3)})
    V.append(
        Vector(
            "release-elided-log",
            "The log's r1 and r3 bodies withheld.",
            rel(sign_release(ef, ed)),
            [rrun(ok(elided=["s0r1", "s0r3"]), **pin("K1"))],
        )
    )

    def altered(path: str, fn) -> dict[str, bytes]:
        f = dict(clean)
        b = bytearray(f[path])
        fn(b)
        f[path] = bytes(b)
        return rel(f)

    def flip(i):
        def g(b):
            b[i] ^= 0x01

        return g

    V.append(
        Vector(
            "release-file-byte",
            "One byte of a page file.",
            altered("pages/0001.pdf", flip(3)),
            [rrun(bad("FileAltered@file:pages/0001.pdf", reason="content"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-multipage-byte",
            "One byte of a multi-page file.",
            altered("doc.pdf", flip(20)),
            [rrun(bad("FileAltered@file:doc.pdf", reason="content"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-part-byte",
            "One byte of index row 1.",
            altered("Decisions.csv", flip(16)),
            [rrun(bad("FileAltered@file:Decisions.csv#row 1", reason="part"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-appended",
            "Bytes appended to a file with parts.",
            altered("Decisions.csv", lambda b: b.extend(b"3,release\n")),
            [rrun(bad("FileAltered@file:Decisions.csv", reason="size"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-attestation-byte",
            "One byte of the attestation.",
            altered("ogentic-audit-release.json", flip(40)),
            [rrun(bad("SignatureInvalid@attestation", reason="mismatch"), **pin("K1"))],
        )
    )
    ff = dict(base_files)
    ff["pages/0001.pdf"] = b"%PDF-1.7\n% a different page\n"
    _, fd = release_files(rlog, extra_files={"pages/0001.pdf": ff["pages/0001.pdf"]})
    V.append(
        Vector(
            "release-forged-other-key",
            "Files altered, attestation re-signed by K2, signer.pub replaced.",
            rel(sign_release(ff, fd, "K2")),
            [rrun(bad("UntrustedSigner@attestation", reason="not_trusted"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-sha256-sshsig",
            "SSHSIG hash algorithm sha256.",
            rel(sign_release(base_files, base_doc, hash_alg="sha256")),
            [rrun(bad("SignatureInvalid@attestation", reason="hash_alg"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-namespace-swap",
            "Signed in the checkpoint namespace.",
            rel(sign_release(base_files, base_doc, ns=NS_CHECKPOINT)),
            [rrun(bad("SignatureInvalid@attestation", reason="namespace"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-reserved-nonzero",
            "SSHSIG reserved field not empty.",
            rel(sign_release(base_files, base_doc, reserved=b"x")),
            [rrun(bad("SignatureInvalid@attestation", reason="malformed"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-trailing-bytes",
            "Bytes after the SSHSIG signature blob.",
            rel(sign_release(base_files, base_doc, trailing=b"\x00")),
            [rrun(bad("SignatureInvalid@attestation", reason="malformed"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-noncanonical-json",
            "Pretty-printed attestation, signed.",
            rel(
                sign_release(
                    base_files,
                    base_doc,
                    raw=json.dumps(base_doc, indent=1, sort_keys=True, ensure_ascii=False).encode(),
                )
            ),
            [rrun(bad("AttestationMalformed@attestation"), **pin("K1"))],
        )
    )
    canon = cjson(base_doc)
    dup = canon.replace(b'"release_id":', b'"release_id":"other","release_id":', 1)
    V.append(
        Vector(
            "release-duplicate-key",
            "release_id twice, signed.",
            rel(sign_release(base_files, base_doc, raw=dup)),
            [rrun(bad("AttestationMalformed@attestation"), **pin("K1"))],
        )
    )
    size_key = f'"size":{len(base_files["Decisions.csv"])}'.encode()
    flt = canon.replace(size_key, size_key + b".0", 1)
    V.append(
        Vector(
            "release-float-integer",
            "A size written 1.0-style, signed.",
            rel(sign_release(base_files, base_doc, raw=flt)),
            [rrun(bad("AttestationMalformed@attestation"), **pin("K1"))],
        )
    )
    evil = "x\n" + sha256(base_files["pages/0001.pdf"]).hex() + "  pages/0001.pdf"
    cf = dict(base_files)
    cf[evil] = b"planted"
    _, cd = release_files(rlog, extra_files={evil: b"planted"})
    V.append(
        Vector(
            "release-control-char-path",
            "A path with a newline, a hash and a file name, signed.",
            {k: v for k, v in rel(sign_release(base_files, cd)).items()},
            [rrun(bad("AttestationMalformed@attestation"), **pin("K1"))],
        )
    )
    bd = json.loads(canon)
    for f in bd["files"]:
        if "parts" in f:
            f["parts"][1]["name"] = "row \u202e1"
    V.append(
        Vector(
            "release-bidi-name",
            "U+202E in a part name, signed.",
            rel(sign_release(base_files, bd)),
            [rrun(bad("AttestationMalformed@attestation"), **pin("K1"))],
        )
    )
    mf = dict(clean)
    del mf["pages/0002.pdf"]
    V.append(
        Vector(
            "release-missing-file",
            "A page file removed.",
            rel(mf),
            [rrun(bad("FileMissing@file:pages/0002.pdf"), **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-unattested",
            "extra.pdf added.",
            rel({**clean, "extra.pdf": b"%PDF planted\n"}),
            [
                rrun(bad("UnattestedFile@file:extra.pdf"), **pin("K1"), name="default"),
                rrun(
                    ok(warnings=["UnattestedFile"]),
                    allow_unattested=True,
                    **pin("K1"),
                    name="allowed",
                ),
            ],
        )
    )
    V.append(
        Vector(
            "release-ds-store",
            ".DS_Store added.",
            rel({**clean, ".DS_Store": b"\x00\x00\x00\x01Bud1"}),
            [rrun(ok(ignored=[".DS_Store"]), **pin("K1"))],
        )
    )
    tr = dict(clean)
    seg = tr["Audit log/audit-0000.cbor"]
    tr["Audit log/audit-0000.cbor"] = seg[: offsets(seg)[3][0]]
    V.append(
        Vector(
            "release-log-truncated",
            "The bundled log cut before the attested head.",
            rel(tr),
            [rrun(bad("CheckpointTruncated@log:Audit log/s0r5"), **pin("K1"))],
        )
    )
    open5 = write_log("K1", LOG_A, five)
    of, od = release_files(open5, head=open5.records[3])
    after = dict(sign_release(of, od))
    r4 = open5.records[4]
    after["Audit log/audit-0000.cbor"] = after["Audit log/audit-0000.cbor"] + frame(
        r4.envelope, r4.signature, r4.body
    )
    V.append(
        Vector(
            "release-records-after-head",
            "Head attested at r3; r4 present after it.",
            rel(after),
            [rrun(ok(records_after_head=1), **pin("K1"))],
        )
    )
    torn = dict(sign_release(of, od))
    torn["Audit log/audit-0000.cbor"] = torn["Audit log/audit-0000.cbor"] + b"\x10\x00\x00"
    V.append(
        Vector(
            "release-torn-after-head",
            "A torn tail after the attested head.",
            rel(torn),
            [rrun(ok(warnings=["TornTailAfterHead"]), **pin("K1"))],
        )
    )
    hm = {k: v for k, v in clean.items() if not k.startswith("Audit log/")}
    for k, v in v01.items():
        hm["Audit log/" + k.split("/", 1)[1]] = v
    V.append(
        Vector(
            "release-hmac-log",
            "The signed log replaced by a v0.1 (HMAC) log.",
            rel(hm),
            [rrun(bad("FormatDowngrade@log:Audit log/s0"), **pin("K1"))],
        )
    )
    rsha = sha256(clean["ogentic-audit-release.json"]).hex()
    rops = trust_file([("ops", "K1", None), ("ops", "K2", NS_REVOCATION)])
    rv = revocation_doc("K2", "K1")
    V.append(
        Vector(
            "release-revoked",
            "K1 revoked by authority; release not in trusted_releases.",
            {
                **rel(clean),
                "allowed_signers": rops,
                **statement_files("rev", "r", rv, "K2", NS_REVOCATION),
            },
            [
                rrun(
                    bad("RevokedKey@attestation"),
                    trust="allowed_signers",
                    revocations=["rev/r.json"],
                )
            ],
        )
    )
    rvt = revocation_doc("K2", "K1", heads=[head_of(rlog)], releases=[rsha])
    V.append(
        Vector(
            "release-revoked-trusted",
            "The release and its log head in the cut points.",
            {
                **rel(clean),
                "allowed_signers": rops,
                **statement_files("rev", "r", rvt, "K2", NS_REVOCATION),
            },
            [rrun(ok(), trust="allowed_signers", revocations=["rev/r.json"])],
        )
    )
    tret = transition_doc("K1", "K2", heads=[head_of(rlog)], releases=[rsha])
    V.append(
        Vector(
            "release-retired",
            "K1 retired; the release in final_releases.",
            {
                **rel(clean),
                **statement_files("keys", "k1-k2", tret, "K1", NS_TRANSITION, accept="K2"),
            },
            [rrun(ok(), statements=["keys"], **pin("K1"))],
        )
    )
    V.append(
        Vector(
            "release-id-mismatch",
            "--expect-release-id of another release.",
            rel(clean),
            [
                rrun(
                    bad("ReleaseIdMismatch@attestation"), expect_release_id="2026-0999", **pin("K1")
                )
            ],
        )
    )
    vf, vd = release_files(
        rlog, extra_files={"ogentic-audit-verifier/verify.sh": b"#!/bin/sh\necho checking\n"}
    )
    for f in vd["files"]:
        if f["path"].startswith("ogentic-audit-verifier/"):
            f["role"] = "verifier"
    swapped = sign_release(vf, vd)
    swapped["ogentic-audit-verifier/verify.sh"] = b"#!/bin/sh\necho Verified\n"
    V.append(
        Vector(
            "release-verifier-swapped",
            "A verifier shipped in the bundle replaced.",
            rel(swapped),
            [rrun(bad("FileAltered@file:ogentic-audit-verifier/verify.sh"), **pin("K1"))],
        )
    )
    # The source log of the release vectors, for the Rust builder cross-check.
    V.append(
        Vector(
            "signed-release-source",
            "The sealed log the release vectors bundle.",
            logfiles(rlog),
            [run(ok(head_anchored=True), **pin("K1"))],
            writer_spec("K1", LOG_A, five, seal=True),
        )
    )
    chains = {
        "signed-empty": (empty, False),
        "signed-single-record": (one, False),
        "signed-sealed": (sealed, False),
        "signed-1k-records": (k1000, False),
        "signed-segment-rollover": (roll, False),
        "signed-release-source": (rlog, False),
    }
    for n in (
        "signed-tampered-envelope",
        "signed-tampered-body",
        "signed-tampered-signature",
        "signed-reencoded-s",
        "signed-elided",
        "signed-missing-record",
        "signed-reordered",
    ):
        chains[n] = (base5, True)
    for v in V:
        if v.name in chains:
            v.chain, v.tampered = chains[v.name]
    return V


# ---------------------------------------------------------------------------
# Writing and checking
# ---------------------------------------------------------------------------


def vector_files(v: Vector) -> dict[str, bytes]:
    files = dict(v.files)
    inputs = {
        "vector": v.name,
        "description": v.description,
        "keys": {
            k: {"seed": s, "public_key": pub(s).hex(), "fingerprint": fp(k)}
            for k, s in SEEDS.items()
        },
        "runs": v.runs,
    }
    if v.writer:
        inputs["writer"] = v.writer
    inputs.update(v.extra)
    if v.chain is not None:
        files["chain.json"] = chain_json(v.chain, tampered=v.tampered)
    files["inputs.json"] = (
        json.dumps(inputs, indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    ).encode()
    return files


def all_files() -> dict[str, dict[str, bytes]]:
    return {v.name: vector_files(v) for v in build_vectors()}


def write_all(check: bool) -> int:
    drift = 0
    vecs = all_files()
    for name, files in vecs.items():
        d = OUT_DIR / name
        if check:
            on_disk = (
                {str(p.relative_to(d)): p.read_bytes() for p in d.rglob("*") if p.is_file()}
                if d.exists()
                else {}
            )
            if on_disk != files:
                drift += 1
                print(
                    f"DRIFT {name}: {sorted(set(on_disk) ^ set(files)) or [k for k in files if on_disk.get(k) != files[k]]}"
                )
            continue
        if d.exists():
            shutil.rmtree(d)
        for rel, data in files.items():
            p = d / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_bytes(data)
    if check:
        extra = (
            sorted(p.name for p in OUT_DIR.iterdir() if p.is_dir() and p.name not in vecs)
            if OUT_DIR.exists()
            else []
        )
        for e in extra:
            print(f"DRIFT stale vector directory {e}")
        drift += len(extra)
        print(f"{len(vecs)} vectors, {drift} drifted")
    else:
        print(f"wrote {len(vecs)} vectors to {OUT_DIR}")
    return 1 if drift else 0


# ---------------------------------------------------------------------------
# The oracle: an independent verifier for every run
# ---------------------------------------------------------------------------


class OracleError(Exception):
    """An argument error (exit 3) with the name of the error kind."""


class Trust:
    def __init__(self) -> None:
        self.pins: list[dict] = []  # {kid, principal, scope:set, pk or None}
        self.transitions: list[dict] = []
        self.revocations: list[dict] = []
        self.warnings: list[str] = []

    def pin_key(self, pk: bytes, principal: str, scope: set) -> None:
        if not key_is_strong(pk):
            raise OracleError("weak key")
        self.pins.append({"kid": key_id(pk), "principal": principal, "scope": scope, "pk": pk})

    def pin_fp(self, text: str, principal: str) -> None:
        t = text.strip()
        if t.startswith("SHA256:"):
            b64 = t[7:].rstrip("=")
            try:
                raw = base64.b64decode(b64 + "=" * (-len(b64) % 4), validate=True)
            except Exception:
                raise OracleError("fingerprint") from None
        else:
            h = "".join(c for c in t if c not in " -:")
            if len(h) != 64:
                raise OracleError("fingerprint")
            try:
                raw = bytes.fromhex(h)
            except ValueError:
                raise OracleError("fingerprint") from None
        if len(raw) != 32:
            raise OracleError("fingerprint")
        self.pins.append(
            {"kid": raw, "principal": principal, "scope": set(DEFAULT_SCOPE), "pk": None}
        )

    def trust_file(self, text: str) -> None:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            tok = line.split()
            principal, rest = tok[0], tok[1:]
            scope = set(DEFAULT_SCOPE)
            if rest[0] != "ssh-ed25519":
                if not rest[0].startswith('namespaces="'):
                    raise OracleError("unknown option")
                names = rest[0][len('namespaces="') : -1].split(",")
                if any(n not in ALL_NS or n == NS_ACCEPT for n in names):
                    raise OracleError("namespace")
                scope = set(names)
                rest = rest[1:]
            if rest[0] != "ssh-ed25519":
                raise OracleError("unknown option")
            blob = base64.b64decode(rest[1])
            self.pin_key(blob[19:], principal, scope)

    def add_statement(self, path: Path, operator: bool) -> None:
        try:
            self._load(path)
        except (OracleError, SigError, ValueError, KeyError, OSError) as e:
            if operator:
                raise OracleError(f"statement {path.name}: {e}") from None
            self.warnings.append(f"{path.name}: {e}")

    def _load(self, path: Path) -> None:
        b = path.read_bytes()
        doc = parse_cjson(b, 3)
        sig = Path(str(path) + ".sig").read_bytes()
        if doc["format"] == "ogentic-audit-key-transition/v1":
            old = bytes.fromhex(doc["old_key_id"])
            pk, s = parse_sshsig(sig, NS_TRANSITION)
            if key_id(pk) != old or strict_verify(pk, signed_data(NS_TRANSITION, b), s):
                raise OracleError("transition not signed by old_key_id")
            npk = base64.b64decode(doc["new_public_key"].split()[1])[19:]
            if key_id(npk).hex() != doc["new_key_id"] or not key_is_strong(npk):
                raise OracleError("new key")
            acc = Path(str(path) + ".accept.sig").read_bytes()
            apk, asig = parse_sshsig(acc, NS_ACCEPT)
            if apk != npk or strict_verify(apk, signed_data(NS_ACCEPT, b), asig):
                raise OracleError("acceptance")
            self.transitions.append(
                {
                    "sha": sha256(b),
                    "old": old,
                    "new": key_id(npk),
                    "heads": doc["final_heads"],
                    "releases": doc["final_releases"],
                    "issued": doc["issued_at"],
                }
            )
        elif doc["format"] == "ogentic-audit-key-revocation/v1":
            rk = bytes.fromhex(doc["revoker_key_id"])
            pk, s = parse_sshsig(sig, NS_REVOCATION)
            if key_id(pk) != rk or strict_verify(pk, signed_data(NS_REVOCATION, b), s):
                raise OracleError("revocation not signed by revoker_key_id")
            self.revocations.append(
                {
                    "sha": sha256(b),
                    "revoked": bytes.fromhex(doc["revoked_key_id"]),
                    "revoker": rk,
                    "heads": doc["trusted_heads"],
                    "releases": doc["trusted_releases"],
                    "successors": [bytes.fromhex(x) for x in doc["trusted_successors"]],
                    "operator": True,
                }
            )
        else:
            raise OracleError("unknown statement")

    def evaluate(self, revocation_sources: dict) -> dict:
        base: dict[bytes, list[dict]] = {}
        for p in self.pins:
            base.setdefault(p["kid"], []).append(
                {
                    "principal": p["principal"],
                    "scope": p["scope"],
                    "path": [p["kid"]],
                    "pinned": True,
                }
            )
        by_old: dict[bytes, dict] = {}
        for t in self.transitions:
            by_old.setdefault(t["old"], {})[t["sha"]] = t
        equiv = {k for k, v in by_old.items() if len(v) > 1}

        def extend(follow) -> dict:
            ent = {k: [dict(e) for e in v] for k, v in base.items()}
            changed = True
            while changed:
                changed = False
                for old, ts in by_old.items():
                    for t in ts.values():
                        if not follow(t):
                            continue
                        for e in list(ent.get(old, [])):
                            if NS_TRANSITION not in e["scope"]:
                                continue
                            lst = ent.setdefault(t["new"], [])
                            if any(x["principal"] == e["principal"] for x in lst):
                                continue
                            lst.append(
                                {
                                    "principal": e["principal"],
                                    "scope": e["scope"],
                                    "path": e["path"] + [t["new"]],
                                    "pinned": False,
                                }
                            )
                            changed = True
            return ent

        principals = extend(lambda t: t["old"] not in equiv)
        revoked: dict[bytes, dict] = {}
        auth: dict[bytes, list[dict]] = {}
        for r in {r["sha"]: r for r in self.revocations}.values():
            if r["revoker"] == r["revoked"]:
                revoked.setdefault(r["revoked"], {})
                continue
            kp = {e["principal"] for e in principals.get(r["revoked"], [])}
            ok_ = any(
                p["kid"] == r["revoker"] and NS_REVOCATION in p["scope"] and p["principal"] in kp
                for p in self.pins
            )
            if ok_:
                revoked.setdefault(r["revoked"], {})
                auth.setdefault(r["revoked"], []).append(r)
            elif revocation_sources.get(r["sha"], True):
                raise OracleError("revocation without authority")
            else:
                self.warnings.append("revocation ignored")
        cuts = {}
        for k in revoked:
            lst = auth.get(k)
            if not lst:
                cuts[k] = {"heads": [], "releases": [], "successors": []}
            else:
                heads = [h for h in lst[0]["heads"] if all(h in r["heads"] for r in lst)]
                rel_ = [h for h in lst[0]["releases"] if all(h in r["releases"] for r in lst)]
                suc = [h for h in lst[0]["successors"] if all(h in r["successors"] for r in lst)]
                cuts[k] = {"heads": heads, "releases": rel_, "successors": suc}

        def follow(t):
            if t["old"] in cuts:
                return t["new"] in cuts[t["old"]]["successors"]
            return t["old"] not in equiv

        ent = extend(follow)
        retired = {}
        for old, ts in by_old.items():
            if old in equiv:
                continue
            t = next(iter(ts.values()))
            if any(NS_TRANSITION in e["scope"] for e in ent.get(old, [])) and follow(t):
                retired[old] = t
        return {
            "entries": ent,
            "cuts": cuts,
            "retired": retired,
            "equiv": [k for k in sorted(equiv) if k in ent],
            "has_pins": bool(self.pins),
        }


def accept(ev: dict, kid: bytes, ns: str, obj: tuple) -> str | None:
    es = ev["entries"].get(kid, [])
    if not es:
        return "NotTrusted"
    if not any(ns in e["scope"] for e in es):
        return "OutOfScope"

    def heads_ok(heads):
        kind = obj[0]
        if kind not in ("record", "checkpoint"):
            return None
        _, log_id, seg, rid, rh = obj
        for h in heads:
            if bytes.fromhex(h["log_id"]) == log_id and (seg, rid) <= (
                h["segment"],
                h["record_id"],
            ):
                if (
                    kind == "record"
                    and (seg, rid) == (h["segment"], h["record_id"])
                    and h["record_hash"] != rh.hex()
                ):
                    return "HeadMismatch"
                return "ok"
        return "no"

    if kid in ev["retired"]:
        t = ev["retired"][kid]
        if obj[0] == "release":
            allowed = obj[1].hex() in t["releases"]
        elif obj[0] == "transition":
            allowed = True
        elif obj[0] == "witness":
            allowed = False
        else:
            r = heads_ok(t["heads"])
            if r == "HeadMismatch":
                return r
            allowed = r == "ok"
        if not allowed:
            return "RetiredKey"
    if kid in ev["cuts"]:
        c = ev["cuts"][kid]
        if obj[0] == "release":
            allowed = obj[1].hex() in c["releases"]
        elif obj[0] == "transition":
            allowed = obj[1] in c["successors"]
        elif obj[0] == "witness":
            allowed = False
        else:
            r = heads_ok(c["heads"])
            if r == "HeadMismatch":
                return r
            allowed = r == "ok"
        if not allowed:
            return "RevokedKey"
    return None


@dataclass
class Result:
    exit: int
    verdict: str = ""
    reason: str | None = None
    error: str | None = None
    info: dict = field(default_factory=dict)


def seg_index(name: str) -> int | None:
    if (
        len(name) == 15
        and name.startswith("audit-")
        and name.endswith(".cbor")
        and name[6:10].isdigit()
    ):
        return int(name[6:10])
    return None


def oracle_log(
    d: Path,
    ev: dict,
    *,
    expect_log_id=None,
    checkpoints=(),
    witnesses=(),
    attested=None,
    forensic=False,
) -> Result:
    segs = sorted(i for p in d.iterdir() if (i := seg_index(p.name)) is not None)
    if not segs:
        return Result(2, error="NoSegments")
    first = (d / f"audit-{segs[0]:04d}.cbor").read_bytes()
    if len(first) >= 6 and first[:4] == b"OGAU":
        ver = struct.unpack("<H", first[4:6])[0]
        if ver == 1:
            return Result(3, error="HmacLog")
        if ver > 2:
            return Result(3, error="NewerFormat")
    viol: list[tuple[str, str | None]] = []
    warnings: list[str] = []
    info: dict = {"elided": [], "records_after_head": 0}
    for k in ev["equiv"]:
        viol.append((f"TransitionEquivocation@key:{k.hex()}", None))
    stop = False
    trusted_sig = False
    seg0 = None
    prev_final: bytes | None = b"\x00" * 32
    expected = 0
    prev_had_records = True
    sealed_at = None
    last = None
    positions: dict[tuple[int, int], tuple[bytes, int]] = {}
    count = 0
    last_ts = None
    rolled_no_successor = False

    def v(x, r=None):
        nonlocal stop
        viol.append((x, r))
        if not forensic:
            stop = True

    def after_head(s, p):
        return attested is not None and (s, p) > (attested["segment"], attested["record_id"])

    for i, n in enumerate(segs):
        if stop:
            break
        is_last = i == len(segs) - 1
        if n != expected:
            v(f"SegmentDiscontinuity@s{expected}")
            prev_final = None
            if stop:
                break
        elif n > 0 and not prev_had_records:
            v(f"SegmentDiscontinuity@s{n}")
            prev_final = None
            if stop:
                break
        expected = n + 1
        b = (d / f"audit-{n:04d}.cbor").read_bytes()
        loc = f"s{n}"
        if len(b) < 12:
            v(f"HeaderCorrupt@{loc}", "Truncated")
            continue
        if b[:4] != b"OGAU":
            v(f"HeaderCorrupt@{loc}", "BadMagic")
            continue
        ver, idx, alg, res = struct.unpack("<HHHH", b[4:12])
        if ver != 2:
            v(f"{'FormatDowngrade' if ver == 1 and n > 0 else 'UnknownVersion'}@{loc}")
            continue
        if alg != 1:
            v(f"UnsupportedAlgorithm@{loc}")
            continue
        if len(b) < 128:
            v(f"HeaderCorrupt@{loc}", "Truncated")
            continue
        if struct.unpack("<I", b[124:128])[0] != zlib.crc32(b[:124]) & 0xFFFFFFFF:
            v(f"HeaderCorrupt@{loc}", "CrcMismatch")
            continue
        if res != 0:
            v(f"HeaderCorrupt@{loc}", "ReservedBytesNonZero")
            continue
        log_id, kid, pf, pk = b[12:28], b[28:60], b[60:92], b[92:124]
        if not key_is_strong(pk):
            v(f"SignatureInvalid@{loc}", "weak_key")
            continue
        if key_id(pk) != kid:
            v(f"KeyIdMismatch@{loc}")
            continue
        if seg0 and n > 0:
            if log_id != seg0[0]:
                v(f"LogIdMismatch@{loc}")
                continue
            if kid != seg0[1]:
                v(f"KeyIdMismatch@{loc}")
                continue
        if idx != n:
            v(f"SegmentDiscontinuity@{loc}")
            continue
        if n == 0 and pf != b"\x00" * 32:
            v(f"HeaderCorrupt@{loc}", "GenesisPrevFinalNonZero")
            continue
        if n > 0 and prev_final is not None and pf != prev_final:
            v(f"SegmentDiscontinuity@{loc}")
            continue
        if n == 0:
            seg0 = (log_id, kid)
            if expect_log_id is not None and expect_log_id != log_id:
                v("LogIdMismatch@s0")
                if stop:
                    break
            if ev["has_pins"]:
                es = ev["entries"].get(kid, [])
                if not any(NS_RECORD in e["scope"] for e in es):
                    viol.append(("UntrustedSigner@s0", "out_of_scope" if es else "not_trusted"))
                    stop = True
                    break
        prev = th("ogentic-audit/v0.2/header", b[:124])
        pos = 128
        p = 0
        fin_at = None
        while pos < len(b) and not stop:
            rem = len(b) - pos
            torn = False
            if rem < 4:
                torn = True
            else:
                ln = struct.unpack("<I", b[pos : pos + 4])[0]
                if ln > 4096:
                    if after_head(n, p):
                        warnings.append("TornTailAfterHead")
                    else:
                        v(f"RecordCorrupt@s{n}r{p}", "TooLarge")
                    break
                fixed = 4 + ln + 64 + 4
                if rem < fixed + 4:
                    torn = True
                else:
                    bl = struct.unpack("<I", b[pos + 4 + ln + 64 : pos + fixed])[0]
                    if (
                        rem < fixed + bl + 4
                        or struct.unpack("<I", b[pos + fixed + bl : pos + fixed + bl + 4])[0] != ln
                    ):
                        torn = True
            if torn:
                if after_head(n, p):
                    warnings.append("TornTailAfterHead")
                else:
                    v(f"RecordCorrupt@s{n}r{p}", "TornTail")
                break
            env = b[pos + 4 : pos + 4 + ln]
            sig = b[pos + 4 + ln : pos + 4 + ln + 64]
            bod = b[pos + fixed : pos + fixed + bl] if bl else None
            pos += fixed + bl + 4
            count += 1
            rh = th("ogentic-audit/v0.2/record", env)
            if after_head(n, p):
                info["records_after_head"] += 1
            here = f"s{n}r{p}"
            if fin_at is not None:
                v(f"RecordCorrupt@s{n}r{fin_at}", "BadRollover")
                fin_at = None
                if stop:
                    break
            r = strict_verify(pk, signed_data(NS_RECORD, env), sig)
            if r:
                v(f"SignatureInvalid@{here}", r)
                prev, p = rh, p + 1
                continue
            try:
                e = c_decode(env)
                assert isinstance(e, tuple)
                em = dict(e[1])
                keys = set(em)
                if not all(isinstance(k, int) for k in keys) or {k for k in keys if k < 100} != {
                    1,
                    2,
                    3,
                    4,
                    5,
                    7,
                    9,
                    10,
                    11,
                    12,
                    13,
                }:
                    raise CborError("envelope keys")
                ev_ = em[7]
                if not (1 <= len(ev_) <= 128 and all(0x21 <= ord(c) <= 0x7E for c in ev_)):
                    raise CborError("event")
            except (CborError, AssertionError, UnicodeDecodeError, TypeError):
                v(f"RecordCorrupt@{here}", "DecodeError")
                prev, p = rh, p + 1
                continue
            bodyv = None
            if bod is not None:
                if th("ogentic-audit/v0.2/body", bod) != em[13]:
                    v(f"SignatureInvalid@{here}", "body_mismatch")
                else:
                    try:
                        bodyv = dict(c_decode(bod)[1])
                        if set(bodyv) != {6, 8, 14}:
                            raise CborError("body keys")
                    except (CborError, TypeError):
                        v(f"RecordCorrupt@{here}", "DecodeError")
            else:
                info["elided"].append(here)
            if em[9] != kid:
                v(f"KeyIdMismatch@{here}")
            if em[12] != alg:
                v(f"AlgorithmMismatch@{here}")
            if em[11] != n or em[1] != p or em[2] != prev:
                v(f"ChainBreak@{here}")
            if ev["has_pins"] and not stop:
                rj = accept(ev, kid, NS_RECORD, ("record", log_id, n, p, rh))
                if rj is None:
                    trusted_sig = True
                elif rj == "HeadMismatch":
                    v(f"CheckpointMismatch@{here}")
                else:
                    v(f"{rj}@{here}")
            if ev_ in ("segment.finalized", "log.sealed", "log.continued") and bod is None:
                v(f"RecordCorrupt@{here}", "ElidedStructural")
            if ev_ == "segment.finalized":
                if bodyv is not None:
                    pl = dict(bodyv[8][1])
                    if pl.get("records") != p or pl.get("final_hash") != em[2]:
                        v(f"RecordCorrupt@{here}", "BadRollover")
                fin_at = p
            if sealed_at:
                v(f"SealedLogExtended@{here}")
            if ev_ == "log.sealed" and not sealed_at:
                sealed_at = here
            ms = ts_ms(em[3])
            if last_ts is not None and ms - last_ts < -60000:
                v(f"TimestampRegression@{here}")
            last_ts = ms
            positions[(n, p)] = (rh, count)
            last = (n, p, rh, ev_, em[3])
            prev, p = rh, p + 1
        prev_had_records = p > 0
        if p == 0 and n > 0 and is_last:
            warnings.append("UnsignedLastSegment")
        if fin_at is not None and is_last:
            warnings.append("RolledOverWithoutSuccessor")
            rolled_no_successor = True
        prev_final = prev
    walk_complete = not stop
    anchored = bool(last and last[3] == "log.sealed")
    wit_principals = []
    for cp_path, cp_sig in checkpoints:
        cb = cp_path.read_bytes()
        cp = parse_cjson(cb, 1)
        if cp["format"] != "ogentic-audit-checkpoint/v2":
            return Result(3, error="CheckpointFormat")
        ckid = bytes.fromhex(cp["key_id"])
        if cp_sig is not None:
            try:
                spk, s = parse_sshsig(cp_sig.read_bytes(), NS_CHECKPOINT)
            except SigError:
                return Result(3, error="CheckpointSignatureInvalid")
            if key_id(spk) != ckid or strict_verify(spk, signed_data(NS_CHECKPOINT, cb), s):
                return Result(3, error="CheckpointSignatureInvalid")
            if ev["has_pins"] and accept(
                ev,
                ckid,
                NS_CHECKPOINT,
                ("checkpoint", bytes.fromhex(cp["log_id"]), cp["segment"], cp["record_id"], None),
            ):
                return Result(3, error="CheckpointSignerUntrusted")
        for wp, ws in witnesses:
            wb = wp.read_bytes()
            w = parse_cjson(wb, 1)
            wk = bytes.fromhex(w["witness_key_id"])
            wpk, s = parse_sshsig(ws.read_bytes(), NS_WITNESS)
            if (
                key_id(wpk) != wk
                or strict_verify(wpk, signed_data(NS_WITNESS, wb), s)
                or w["checkpoint_sha256"] != sha256(cb).hex()
            ):
                return Result(3, error="CheckpointSignatureInvalid")
            es = ev["entries"].get(wk, [])
            if ev["has_pins"] and accept(ev, wk, NS_WITNESS, ("witness",)):
                return Result(3, error="CheckpointSignerUntrusted")
            wit_principals.append(
                next((e["principal"] for e in es if NS_WITNESS in e["scope"]), "?")
            )
        if seg0 is None:
            continue
        if ckid != seg0[1]:
            return Result(3, error="CheckpointForDifferentSigner")
        if bytes.fromhex(cp["log_id"]) != seg0[0]:
            viol.append(("CheckpointForDifferentLog@s0", None))
            continue
        pos_ = (cp["segment"], cp["record_id"])
        got = positions.get(pos_)
        if got is None:
            if walk_complete or not viol:
                viol.append((f"CheckpointTruncated@s{pos_[0]}r{pos_[1]}", None))
        elif got[0].hex() != cp["record_hash"] or got[1] != cp["record_count"]:
            viol.append((f"CheckpointMismatch@s{pos_[0]}r{pos_[1]}", None))
        elif last and (last[0], last[1]) == pos_:
            anchored = True
    if attested is not None and seg0 is not None:
        if (
            bytes.fromhex(attested["key_id"]) != seg0[1]
            or bytes.fromhex(attested["log_id"]) != seg0[0]
        ):
            viol.append(("CheckpointMismatch@s0", None))
        else:
            pos_ = (attested["segment"], attested["record_id"])
            got = positions.get(pos_)
            if got is None:
                viol.append((f"CheckpointTruncated@s{pos_[0]}r{pos_[1]}", None))
            elif got[0].hex() != attested["record_hash"] or got[1] != attested["record_count"]:
                viol.append((f"CheckpointMismatch@s{pos_[0]}r{pos_[1]}", None))
            else:
                anchored = True
    if rolled_no_successor and attested is None:
        anchored = False
    info.update(
        {
            "head_anchored": anchored,
            "warnings": warnings,
            "witnesses": wit_principals,
            "violations": [x for x, _ in viol],
        }
    )
    if viol:
        return Result(1, viol[0][0], viol[0][1], info=info)
    if trusted_sig:
        return Result(0, "Verified", info=info)
    return Result(
        4, "SelfConsistent", "no_signed_records" if count == 0 else "not_pinned", info=info
    )


def oracle_release(d: Path, ev: dict, *, expect_release_id=None, allow_unattested=False) -> Result:
    viol: list[tuple[str, str | None]] = []
    info: dict = {"warnings": [], "ignored": [], "elided": [], "records_after_head": 0}
    ap = d / "ogentic-audit-release.json"
    if not ap.is_file():
        return Result(1, "AttestationMissing@attestation")
    att = ap.read_bytes()
    sp = d / "ogentic-audit-release.json.sig"
    if not sp.is_file():
        return Result(1, "SignatureInvalid@attestation", "missing")
    try:
        pk, sig = parse_sshsig(sp.read_bytes(), NS_RELEASE)
    except SigError as e:
        return Result(1, "SignatureInvalid@attestation", e.reason)
    if ev["has_pins"]:
        rj = accept(ev, key_id(pk), NS_RELEASE, ("release", sha256(att)))
        if rj in ("NotTrusted", "OutOfScope"):
            return Result(
                1,
                "UntrustedSigner@attestation",
                "not_trusted" if rj == "NotTrusted" else "out_of_scope",
            )
        if rj:
            return Result(1, f"{rj if rj != 'HeadMismatch' else 'RevokedKey'}@attestation")
    r = strict_verify(pk, signed_data(NS_RELEASE, att), sig)
    if r:
        return Result(1, "SignatureInvalid@attestation", r)
    try:
        doc = parse_cjson(att, 5)
        if doc["key_id"] != key_id(pk).hex() or doc["alg"] != "ed25519":
            return Result(1, "KeyIdMismatch@attestation")
        names = (
            [doc["release_id"]]
            + [f["path"] for f in doc["files"]]
            + [f.get("role", "") for f in doc["files"]]
        )
        names += [p["name"] for f in doc["files"] for p in f.get("parts", [])] + [
            lg["path"] for lg in doc["logs"]
        ]
        if any(bad_string(s) for s in names):
            raise ValueError("forbidden character")
        for f in doc["files"]:
            if not isinstance(f["size"], int):
                raise ValueError("size")
            if unicodedata.normalize("NFC", f["path"]) != f["path"]:
                raise ValueError("NFC")
    except (ValueError, KeyError, TypeError):
        return Result(1, "AttestationMalformed@attestation")
    if expect_release_id is not None and expect_release_id != doc["release_id"]:
        return Result(1, "ReleaseIdMismatch@attestation")
    present = {}
    for p in d.rglob("*"):
        if p.is_file() or p.is_symlink():
            present[unicodedata.normalize("NFC", str(p.relative_to(d)).replace("\\", "/"))] = p
    covered = set()
    for f in doc["files"]:
        covered.add(f["path"])
        p = present.get(f["path"])
        if p is None:
            viol.append((f"FileMissing@file:{f['path']}", None))
            continue
        data = p.read_bytes()
        if len(data) == f["size"] and sha256(data).hex() == f["sha256"]:
            continue
        if len(data) != f["size"]:
            viol.append((f"FileAltered@file:{f['path']}", "size"))
            continue
        bad_part = next(
            (
                pt
                for pt in f.get("parts", [])
                if sha256(data[pt["offset"] : pt["offset"] + pt["length"]]).hex() != pt["sha256"]
            ),
            None,
        )
        if bad_part:
            viol.append((f"FileAltered@file:{f['path']}#{bad_part['name']}", "part"))
        else:
            viol.append(
                (f"FileAltered@file:{f['path']}", "outside_parts" if f.get("parts") else "content")
            )
    log_dirs = {lg["path"] for lg in doc["logs"]}
    for lg in doc["logs"]:
        ld = d / lg["path"]
        res = (
            oracle_log(ld, ev, attested=lg["checkpoint"], forensic=True)
            if ld.is_dir()
            else Result(1, error="FileMissing")
        )
        if res.error == "HmacLog":
            viol.append((f"FormatDowngrade@log:{lg['path']}/s0", None))
            continue
        if res.error:
            return res
        for x in res.info["violations"]:
            loc = x.split("@", 1)
            viol.append(
                (
                    f"{loc[0]}@log:{lg['path']}/{loc[1]}" if not loc[1].startswith("key:") else x,
                    None,
                )
            )
        info["elided"] += res.info["elided"]
        info["records_after_head"] += res.info["records_after_head"]
        info["warnings"] += res.info["warnings"]
        if res.exit == 4:
            pass
    reserved = {
        "ogentic-audit-release.json",
        "ogentic-audit-release.json.sig",
        "ogentic-audit-signer.pub",
        "ogentic-audit-keys",
        "ogentic-audit-witness",
    }
    for path in sorted(present):
        if path in covered or path.split("/")[0] in reserved:
            continue
        if (
            "/" in path
            and path.rsplit("/", 1)[0] in log_dirs
            and seg_index(path.rsplit("/", 1)[1]) is not None
        ):
            continue
        last_comp = path.split("/")[-1]
        if (
            last_comp in (".DS_Store", "Thumbs.db", "desktop.ini")
            or last_comp.startswith("._")
            or any(c in ("__MACOSX", ".Spotlight-V100", ".Trashes") for c in path.split("/")[:-1])
        ):
            info["ignored"].append(path)
            continue
        if allow_unattested:
            info["warnings"].append("UnattestedFile")
        else:
            viol.append((f"UnattestedFile@file:{path}", None))
    if viol:
        return Result(1, viol[0][0], viol[0][1], info=info)
    if ev["has_pins"]:
        return Result(0, "Verified", info=info)
    return Result(4, "SelfConsistent", "not_pinned", info=info)


def oracle_run(vdir: Path, r: dict) -> Result:
    cmd = r["command"]
    if cmd == "ed25519":
        cases = json.loads((vdir / r["target"]).read_text())
        exp = json.loads((vdir / r["expect"]["file"]).read_text())
        for c, e in zip(cases, exp):
            got = strict_verify(
                bytes.fromhex(c["pub_key"]),
                bytes.fromhex(c["message"]),
                bytes.fromhex(c["signature"]),
            )
            if (got is None) != e["accept"]:
                return Result(1, f"case {e['case']}")
        return Result(0)
    if cmd == "checkpoint-compare":
        a, b = vdir / r["target"], vdir / r["other"]
        ca, cb = parse_cjson(a.read_bytes(), 1), parse_cjson(b.read_bytes(), 1)
        for p, c in ((a, ca), (b, cb)):
            pk, s = parse_sshsig(Path(str(p) + ".sig").read_bytes(), NS_CHECKPOINT)
            if key_id(pk).hex() != c["key_id"] or strict_verify(
                pk, signed_data(NS_CHECKPOINT, p.read_bytes()), s
            ):
                return Result(3)
        same = all(ca[k] == cb[k] for k in ("key_id", "log_id", "segment", "record_id"))
        differ = ca["record_hash"] != cb["record_hash"] or ca["record_count"] != cb["record_count"]
        return Result(1 if same and differ else 0, info={"equivocation": same and differ})
    if cmd == "v01-verifier":
        return Result(1, "UnknownVersion@s0")
    t = Trust()
    rev_sources: dict = {}
    try:
        if "public_key" in r:
            raw = bytes.fromhex(r["public_key"])
            t.pin_key(raw, "supplied-key-1", set(DEFAULT_SCOPE))
        for i, f in enumerate(r.get("key_fingerprint", [])):
            t.pin_fp(f, f"supplied-key-{i + 1}")
        if "trust" in r:
            t.trust_file((vdir / r["trust"]).read_text())
        for sd in r.get("statements", []):
            operator = r.get("statements_source", "operator") == "operator"
            for p in sorted((vdir / sd).glob("*.json")):
                n = len(t.revocations)
                t.add_statement(p, operator)
                for rv in t.revocations[n:]:
                    rev_sources[rv["sha"]] = operator
        for rp in r.get("revocations", []):
            n = len(t.revocations)
            t.add_statement(vdir / rp, True)
            for rv in t.revocations[n:]:
                rev_sources[rv["sha"]] = True
    except OracleError as e:
        return Result(3, error=str(e))
    if r.get("hmac_key_source"):
        target = vdir / r["target"]
        first = sorted(target.glob("audit-*.cbor"))[0].read_bytes()
        ver = struct.unpack("<H", first[4:6])[0]
        if ver != 1:
            return Result(3, error="signed log under HMAC key")
        return Result(0, "Verified", info={"authentication": "shared-key"})
    try:
        ev = t.evaluate(rev_sources)
    except OracleError as e:
        return Result(3, error=str(e))
    if cmd == "verify":
        target = vdir / r["target"]
        if "env" in r and not ev["has_pins"] and not r.get("hmac_key_source"):
            first = sorted(target.glob("audit-*.cbor"))[0].read_bytes()
            if struct.unpack("<H", first[4:6])[0] == 1:
                return Result(3, error="no implicit HMAC key")
        cps = [
            (vdir / c, (vdir / (c + ".sig")) if (vdir / (c + ".sig")).exists() else None)
            for c in r.get("checkpoints", [])
        ]
        ws = [(vdir / w, vdir / (w + ".sig")) for w in r.get("witnesses", [])]
        res = oracle_log(
            target,
            ev,
            expect_log_id=bytes.fromhex(r["expect_log_id"]) if "expect_log_id" in r else None,
            checkpoints=cps,
            witnesses=ws,
            forensic="segment" in r,
        )
        if "segment" in r and res.exit == 1:
            seg = r["segment"]
            keep = [
                x
                for x in res.info["violations"]
                if f"@s{seg}" in x
                or not x.split("@")[1].startswith("s")
                or x.startswith(
                    (
                        "UntrustedSigner",
                        "FormatDowngrade",
                        "UnsupportedAlgorithm",
                        "RevokedKey",
                        "RetiredKey",
                        "LogIdMismatch",
                        "TransitionEquivocation",
                        "CheckpointForDifferentLog",
                    )
                )
            ]
            res.verdict = keep[0] if keep else "Violation"
        res.info["warnings"] = res.info.get("warnings", []) + (
            ["IgnoredStatement"] if t.warnings else []
        )
        return res
    if cmd == "verify-release":
        res = oracle_release(
            vdir / r["target"],
            ev,
            expect_release_id=r.get("expect_release_id"),
            allow_unattested=r.get("allow_unattested", False),
        )
        res.info["warnings"] = res.info.get("warnings", []) + (
            ["IgnoredStatement"] if t.warnings else []
        )
        return res
    raise ValueError(cmd)


def check_expect(name: str, r: dict, res: Result) -> list[str]:
    e = r["expect"]
    errs = []
    if res.exit != e["exit"]:
        errs.append(f"exit {res.exit} != {e['exit']} ({res.verdict or res.error})")
    if "verdict" in e and res.verdict != e["verdict"]:
        errs.append(f"verdict {res.verdict!r} != {e['verdict']!r}")
    if "reason" in e and res.reason != e["reason"]:
        errs.append(f"reason {res.reason!r} != {e['reason']!r}")
    for k in ("head_anchored", "records_after_head", "equivocation"):
        if k in e and res.info.get(k) != e[k]:
            errs.append(f"{k} {res.info.get(k)!r} != {e[k]!r}")
    if "elided" in e and res.info.get("elided") != e["elided"]:
        errs.append(f"elided {res.info.get('elided')} != {e['elided']}")
    for w in e.get("warnings", []):
        if w not in res.info.get("warnings", []):
            errs.append(f"warning {w} missing from {res.info.get('warnings')}")
    for w in e.get("ignored", []):
        if w not in res.info.get("ignored", []):
            errs.append(f"ignored {w} missing")
    if "witnesses" in e and res.info.get("witnesses") != e["witnesses"]:
        errs.append(f"witnesses {res.info.get('witnesses')} != {e['witnesses']}")
    return [f"{name}/{r.get('name', r['command'])}: {x}" for x in errs]


def verify_all() -> int:
    failures = []
    n = 0
    for vdir in sorted(p for p in OUT_DIR.iterdir() if p.is_dir()):
        inputs = json.loads((vdir / "inputs.json").read_text())
        for r in inputs["runs"]:
            n += 1
            res = oracle_run(vdir, r)
            failures += check_expect(vdir.name, r, res)
    for f in failures:
        print("FAIL", f)
    print(f"oracle: {n} runs, {len(failures)} failures")
    return 1 if failures else 0


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument(
        "--check",
        action="store_true",
        help="fail if committed vectors differ from what this script produces",
    )
    ap.add_argument(
        "--verify",
        action="store_true",
        help="run the independent oracle over every run and compare with the expected results",
    )
    a = ap.parse_args()
    if a.verify:
        return verify_all()
    return write_all(a.check)


if __name__ == "__main__":
    sys.exit(main())
