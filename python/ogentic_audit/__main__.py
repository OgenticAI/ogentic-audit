"""``python -m ogentic_audit``: the offline verifier for people who do not program.

Prints the same report and exits with the same codes as the ``ogentic-audit``
command-line tool:

    0  verified
    1  verification failed: something was altered, removed, added, or is not
       signed by a trusted key
    2  I/O error (missing folder, no segment files)
    3  argument or input error (a malformed key, fingerprint or trust file; a
       key of the wrong kind for this log)
    4  not verified: no key was supplied, or nothing was signed
   64  usage error

Examples::

    python -m ogentic_audit verify-release ./release --key-fingerprint "6db5 e9b8 ..."
    python -m ogentic_audit verify ./logs --public-key signer.pub
    python -m ogentic_audit verify ./logs --key-env OGENTIC_AUDIT_KEY_HEX   # HMAC log
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from typing import NoReturn

from ogentic_audit import (
    ArgumentError,
    IoFailure,
    KeyHandle,
    OgenticAuditError,
    verify,
    verify_release,
)

PROGRAM = "python -m ogentic_audit"


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        self.print_usage(sys.stderr)
        sys.stderr.write(f"{self.prog}: error: {message}\n")
        raise SystemExit(64)


def _ascii(flag: bool) -> bool:
    if flag or os.environ.get("OGENTIC_AUDIT_ASCII"):
        return True
    enc = (getattr(sys.stdout, "encoding", None) or "").lower().replace("-", "")
    return enc not in ("utf8", "utf_8")


def _trust_args(p: argparse.ArgumentParser) -> None:
    p.add_argument(
        "--public-key", metavar="FILE|KEY", help="the signer's public key (from the signer)"
    )
    p.add_argument(
        "--key-fingerprint",
        metavar="FINGERPRINT",
        action="append",
        default=[],
        help="the signer's key fingerprint, 64 hex digits in any grouping (repeatable)",
    )
    p.add_argument("--trust", metavar="FILE", help="an OpenSSH allowed_signers trust file")
    p.add_argument(
        "--statements",
        metavar="DIR",
        action="append",
        default=[],
        help="a directory of key transitions and revocations (repeatable)",
    )
    p.add_argument(
        "--revocations",
        metavar="FILE",
        action="append",
        default=[],
        help="a revocation statement (repeatable)",
    )
    p.add_argument("--format", choices=["text", "json"], default="text")
    p.add_argument("--ascii", action="store_true", help="print [OK] [FAILED] [!] marks")


def _exit_for(verdict: str) -> int:
    return {"Verified": 0, "SelfConsistent": 4}.get(verdict, 1)


def main(argv: Sequence[str] | None = None) -> int:
    parser = _Parser(
        prog=PROGRAM, description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    sub = parser.add_subparsers(dest="command", required=True, parser_class=_Parser)

    v = sub.add_parser("verify", help="verify an audit log")
    v.add_argument("log_dir")
    _trust_args(v)
    v.add_argument(
        "--checkpoint", action="append", default=[], help="a checkpoint file (repeatable)"
    )
    v.add_argument(
        "--witness", action="append", default=[], help="a witness co-signature (repeatable)"
    )
    v.add_argument("--expect-log-id", metavar="LOG_ID")
    v.add_argument("--segment", type=int)
    v.add_argument("--forensic", action="store_true")
    v.add_argument("--key-env", metavar="VAR", help="HMAC logs only: env var holding the hex key")
    v.add_argument("--key-file", metavar="FILE", help="HMAC logs only: file holding the hex key")

    r = sub.add_parser("verify-release", help="verify a signed release folder")
    r.add_argument("release_dir")
    _trust_args(r)
    r.add_argument("--witness", action="append", default=[])
    r.add_argument("--expect-release-id", metavar="ID")
    r.add_argument("--allow-unattested", action="store_true")

    a = parser.parse_args(argv)
    ascii_ = _ascii(a.ascii)
    try:
        if a.command == "verify-release":
            rep = verify_release(
                a.release_dir,
                public_key=a.public_key,
                key_fingerprint=a.key_fingerprint,
                trust=a.trust,
                statements=a.statements,
                revocations=a.revocations,
                witnesses=a.witness,
                expect_release_id=a.expect_release_id,
                allow_unattested=a.allow_unattested,
            )
            print(
                rep.to_json() if a.format == "json" else rep.render(ascii_, PROGRAM),
                end="" if a.format == "text" else "\n",
            )
            return _exit_for(rep.verdict)
        key = None
        if a.key_env:
            key = KeyHandle.from_env(a.key_env)
        elif a.key_file:
            with open(a.key_file, encoding="utf-8") as fh:
                key = KeyHandle.from_hex(fh.read().strip())
        rep = verify(
            a.log_dir,
            key,
            a.forensic,
            False,
            a.checkpoint or None,
            public_key=a.public_key,
            key_fingerprint=a.key_fingerprint,
            trust=a.trust,
            statements=a.statements,
            revocations=a.revocations,
            witnesses=a.witness,
            expect_log_id=a.expect_log_id,
            segment=a.segment,
        )
        if hasattr(rep, "render"):
            print(
                rep.to_json() if a.format == "json" else rep.render(ascii_, PROGRAM),
                end="" if a.format == "text" else "\n",
            )
            return _exit_for(rep.verdict)
        # HMAC (format 0x0001) report.
        if a.format == "json":
            import json

            print(
                json.dumps(
                    {
                        "verdict": "Verified" if rep.ok else "Violation",
                        "compact": rep.compact,
                        "authentication": "shared-key",
                    },
                    indent=2,
                )
            )
        elif rep.ok:
            print(
                "Verified with a shared key: anyone holding this key could have written this log."
            )
        else:
            print(f"Verification failed: {rep.compact}")
        return 0 if rep.ok else 1
    except IoFailure as e:
        sys.stderr.write(f"error: {e}\n")
        return 2
    except (ArgumentError, ValueError) as e:
        sys.stderr.write(f"error: {e}\n")
        return 3
    except OgenticAuditError as e:
        sys.stderr.write(f"error: {e}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
