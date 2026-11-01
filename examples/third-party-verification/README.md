# Third-party verification walk-through

A producer answers a records request and signs what it releases. A third party (a requester, an auditor, a court) checks the release **without any secret and without the producer's software**, using only a key fingerprint the producer published separately. This walk-through plays both sides.

It uses signed mode (format `0x0002`, [spec v0.2](../../docs/spec/v0.2.md)). The guide for people receiving a release is [`docs/guides/verifying-a-release.md`](../../docs/guides/verifying-a-release.md).

## 1. The producer signs a release

```sh
cargo run -p ogentic-audit-core --example third_party_verification -- /tmp/walkthrough
```

The [example program](../../crates/ogentic-audit-core/examples/third_party_verification.rs):

1. generates an Ed25519 signing key (in production it lives in the OS keychain: `ogentic-audit key generate --signer keychain:<service>:<account>`, or `KeychainSigner` from the library);
2. writes `published-fingerprint.txt`: the fingerprint the producer publishes **out of band** (a website, a letter, a filing);
3. keeps a signed audit log while three pages are reviewed. Each review records a salted *commitment* to the page, not a plain hash, so a withheld page cannot be confirmed by guessing. The log is sealed when the work is done;
4. builds `release/`: two released pages, a decision index with one named part per row, the audit log with the withheld page's record carried **without its body** (the chain and every signature still verify), `HOW-TO-VERIFY.txt`, and the signed attestation `ogentic-audit-release.json` + `.sig`;
5. checks the release as the third party would, then shows a changed row and a forgery re-signed with another key.

```text
Third party, untouched release:
✓ Verified: release "R-0001", 4 files, 1 audit log (1 segment, 6 records, 1 with withheld content)
  Signed by producer, the key you supplied:
    e4e4 9429 6660 65e8 2198 8976 62a9 55c3 cc11 f1b1 0110 6323 0551 6bdd f799 4b7e

Third party, one row changed:
✗ Verification failed: 1 problem
  Altered
    "Decisions.csv", item "row 3" (bytes 47–74)

Third party, re-signed by someone else:
✗ Verification failed: 1 problem
  Signature and index
    the release index: signed by a key other than the one you supplied (UntrustedSigner)
```

(The fingerprint differs on every run: the key is fresh.)

## 2. The third party checks it with stock tools only

No `ogentic-audit` software at all: OpenSSH, `shasum` and Python 3 ([spec §11.7](../../docs/spec/v0.2.md#117-checking-a-release-with-stock-tools-only)). Run this first; it also checks any verifier shipped inside a release before anyone runs it.

```sh
cd /tmp/walkthrough/release
FP="$(cat ../published-fingerprint.txt)"      # really: the fingerprint you got from the producer

# The key in the folder is the key you were given. Compare by machine, not by eye.
HAVE=$(awk '{print $2}' ogentic-audit-signer.pub | base64 -d | shasum -a 256 | cut -c1-64)
WANT=$(printf '%s' "$FP" | tr -d ' :-' | tr 'A-F' 'a-f')
[ "$HAVE" = "$WANT" ] && echo "key matches" || echo "KEY DOES NOT MATCH: stop"

# The attestation is signed by that key, for releases and nothing else.
echo "release-signer namespaces=\"ogentic-audit/v0.2/release\" $(cut -d' ' -f1,2 ogentic-audit-signer.pub)" > ../allowed_signers
ssh-keygen -Y verify -f ../allowed_signers -I release-signer -n ogentic-audit/v0.2/release \
  -s ogentic-audit-release.json.sig < ogentic-audit-release.json

# Every released file matches; a changed file prints FAILED with its name.
python3 -c '
import json
def no_dupes(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)): raise SystemExit("duplicate key: stop")
    return dict(pairs)
a = json.load(open("ogentic-audit-release.json", encoding="utf-8"), object_pairs_hook=no_dupes)
for f in a["files"]: print(f["sha256"] + "  " + f["path"])' | shasum -a 256 -c
```

```text
key matches
Good "ogentic-audit/v0.2/release" signature for release-signer with ED25519 key SHA256:…
Decisions.csv: OK
HOW-TO-VERIFY.txt: OK
pages/0001.pdf: OK
pages/0002.pdf: OK
```

In `/tmp/walkthrough/altered` the same check prints `Decisions.csv: FAILED`. The stock path names files; it does not name rows, check the audit log, or follow key rotations. The verifier does.

## 3. The third party checks everything with a verifier

```sh
cargo install ogentic-audit --locked            # or a release binary, or: pip install ogentic-audit
ogentic-audit verify-release /tmp/walkthrough/release --key-fingerprint "$(cat /tmp/walkthrough/published-fingerprint.txt)"
python -m ogentic_audit verify-release /tmp/walkthrough/release --key-fingerprint "…"   # same report, same exit codes
```

| Exit | Meaning |
|------|---------|
| 0 | Verified: every file, every index row and the audit log are exactly as signed by the key you supplied |
| 1 | Something changed, is missing, was added, or is not signed by that key; every problem is listed |
| 4 | Not verified: you did not supply the signer's key (or nothing was signed) |
| 2, 3 | The check could not run (unreadable folder; a wrong input such as a mistyped fingerprint) |

Without `--key-fingerprint` the verifier says **"Not verified: you did not supply the signer's key"** and exits 4, even though the signature is intact: anyone could have made that signature with a key of their own, which is exactly what the forged folder in step 1 does.

## What this shows, and what it does not

- Nobody who can verify can forge: verification needs only the public key.
- One changed byte in a page, an index row, the attestation, or the log fails, and the report names the item.
- A release re-signed with another key fails, provided the fingerprint was obtained from the producer and not from the folder.
- A signature proves who signed and that nothing changed since. It does not prove that what was recorded is true, and times are the producer's own clock.
