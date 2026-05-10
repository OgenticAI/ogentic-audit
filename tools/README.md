# tools/

Small utilities that support the spec, vectors, and build, but are not part of the published library or CLI.

| Script | Purpose |
|--------|---------|
| [`gen_vectors.py`](gen_vectors.py) | Reference generator for v0.1 golden vectors. Reads `tests/vectors/v0.1/<name>/inputs.json`; writes `audit-NNNN.cbor` + `chain.json`. The hand-rolled canonical CBOR encoder is the authoritative source for the wire format at v0.1. |
| [`check_cbor_parity.py`](check_cbor_parity.py) | Cross-check the hand-rolled encoder's output against the [`cbor2`](https://pypi.org/project/cbor2/) library's `canonical=True` mode. Exits non-zero on any divergence. This is the F2 / ADR-0001 "canonical-form parity" spike, runnable on demand. |

## Setup

The scripts target Python 3.9+ and need a couple of PyPI packages:

```sh
python3 -m venv .venv
source .venv/bin/activate
pip install blake3 cbor2
```

`blake3` is used for `key_id` derivation (`BLAKE3-256(key)`); `cbor2` is used by the parity check only.

## Common commands

```sh
# Regenerate all golden vectors
python3 tools/gen_vectors.py

# CI-mode: fail if any committed vector would change
python3 tools/gen_vectors.py --check

# Regenerate just one vector
python3 tools/gen_vectors.py 1k-records

# Confirm the hand-rolled encoder matches cbor2's canonical mode
python3 tools/check_cbor_parity.py
```
