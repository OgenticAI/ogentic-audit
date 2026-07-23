# ogentic-audit — live verify-chain demo

A tiny [Streamlit](https://streamlit.io) app that shows the audit log doing its
one job: proving a record of AI-agent actions wasn't altered. Every verdict on
screen comes from the **real, published** verifier — `pip install ogentic-audit`
— so what you see is exactly what the library does, not a mock-up.

Three things, in order:

1. **A verified chain.** Four events from a legal matter, each record
   HMAC-SHA256-chained to the one before it. `verify` → `✓ Verified`.
2. **Tamper one byte.** Flip a single byte inside a record's payload. The chain
   breaks at that exact `(segment, record_id)` — `HmacMismatch@s0r2`.
3. **The rewrite attack.** The hard case from
   [NousResearch/hermes-agent#487](https://github.com/NousResearch/hermes-agent/issues/487):
   an attacker who *holds the key* can re-chain a fabricated history, and plain
   verification — which only checks the chain against itself — is fooled. A
   **checkpoint** observed while the log was honest, and stored out of the
   writer's reach, catches it (`CheckpointMismatch`).

Logs are generated in-session in a temp dir with a public, non-secret fixture
key. Nothing to configure; no secrets involved.

## Run locally

```bash
pip install -r demo/requirements.txt
streamlit run demo/app.py          # http://localhost:8501
```

Or with Docker (mirrors the deployed image exactly):

```bash
docker build -f demo/Dockerfile -t ogentic-audit-demo .
docker run -p 8501:8501 ogentic-audit-demo
```

The logic layer ([`audit_demo.py`](audit_demo.py)) is plain, importable
functions — you can exercise the three stories headlessly without Streamlit:

```python
import audit_demo as d
print(d.build_and_verify().report.verdict)       # Verified
print(d.rewrite_vs_checkpoint().rewritten_checked.verdict)  # CheckpointMismatch@s0r3
```

## Deploy (Railway)

[`railway.json`](railway.json) + [`Dockerfile`](Dockerfile) are wired for a
one-click Railway deploy from the repo root:

- **Builder:** Dockerfile at `demo/Dockerfile`
- **Health check:** `/_stcore/health`
- **Start:** `streamlit run demo/app.py --server.port=$PORT …`

Railway injects `$PORT`; the container binds it. No environment variables are
required — the demo needs no key of its own.

## What it is *not*

Not a KMS integration, not a production logging setup, and not a place to put a
real signing key. It's a faithful, self-contained illustration of the on-disk
format and the verifier. For the real API, see the
[repo README](../README.md).
