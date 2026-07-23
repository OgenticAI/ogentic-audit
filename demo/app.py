"""ogentic-audit — live verify-chain demo (OGE-1668).

A small Streamlit app that shows the audit log doing its one job: proving a
record of agent actions wasn't altered. Every verdict comes from the real,
published verifier (`pip install ogentic-audit`) — nothing here re-implements
the check.

Run locally:
    pip install ogentic-audit streamlit
    streamlit run demo/app.py            # http://localhost:8501

Deploy: see demo/README.md (Railway).
"""

from __future__ import annotations

import os
import sys

import pandas as pd
import streamlit as st

# Make the sibling logic module importable regardless of launcher (`streamlit
# run demo/app.py`, Streamlit AppTest, or the Docker image all resolve it).
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import audit_demo as d  # noqa: E402

st.set_page_config(page_title="ogentic-audit demo", page_icon="🔗", layout="centered")


def verdict_banner(v: d.VerifyView) -> None:
    if v.ok:
        st.success(f"✓ **Verified** · {v.records_inspected} events · chain head `{(v.chain_head or '')[:16]}…`")
    else:
        st.error(f"✗ **{v.kind}** at segment {v.broken_segment}, record {v.broken_record} — {v.message}")


def records_table(records: list[d.RecordView], broken: int | None = None) -> None:
    rows = []
    for r in records:
        rows.append(
            {
                "#": r.record_id,
                "actor": r.actor,
                "event": r.event,
                "payload": ", ".join(f"{k}={v}" for k, v in r.payload.items()),
                "prev_hash": r.prev_hash_hex[:10] + "…",
                "hmac": r.hmac_hex[:10] + "…",
                "": "⛔" if r.record_id == broken else "🔗",
            }
        )
    st.dataframe(pd.DataFrame(rows), hide_index=True, use_container_width=True)


st.title("🔗 ogentic-audit")
st.markdown(
    "**A tamper-evident record of what an AI agent did.** Every action is an "
    "append-only record, HMAC-SHA256-chained to the one before it. Change one "
    "byte and the chain breaks at that exact record — and if someone with the "
    "key rewrites the whole thing, a **checkpoint** catches even that.\n\n"
    "Live on [PyPI](https://pypi.org/project/ogentic-audit/) + "
    "[crates.io](https://crates.io/crates/ogentic-audit) · "
    "[source](https://github.com/OgenticAI/ogentic-audit). "
    "Everything below runs the real verifier on logs generated in-session with a "
    "public fixture key — no secrets, no KMS."
)

# --- State: one clean log for the verify + tamper sections ------------------
if "log" not in st.session_state:
    st.session_state.log = d.build_and_verify()
    st.session_state.tampered = False

log: d.DemoLog = st.session_state.log

# ---------------------------------------------------------------------------
st.header("① A verified chain")
st.caption(
    "Four events from a legal matter. Each `hmac` is HMAC-SHA256 over the record; "
    "each `prev_hash` links back to the previous record's `hmac` — that's the chain."
)
current = d.VerifyView(**vars(log.report)) if not st.session_state.tampered else d._verify_view(log.path)
verdict_banner(current)
records_table(d._read_records(log.path), broken=current.broken_record)

# ---------------------------------------------------------------------------
st.header("② Tamper one byte")
st.caption(
    "Flip a single byte inside record 2's payload (the model name `gpt-4o`). "
    "No key, no re-chaining — just an edit, the way an attacker with file access "
    "would try it."
)
c1, c2 = st.columns(2)
with c1:
    if st.button("💥 Flip a byte in record 2", use_container_width=True, disabled=st.session_state.tampered):
        d.tamper_byte(log.path)
        st.session_state.tampered = True
        st.rerun()
with c2:
    if st.button("↺ Reset to a clean log", use_container_width=True):
        d.cleanup(log.path)
        st.session_state.log = d.build_and_verify()
        st.session_state.tampered = False
        st.rerun()
if st.session_state.tampered:
    st.markdown(
        "The verdict above flipped to **HmacMismatch at s0r2** — the verifier "
        "names the exact record whose bytes no longer match their HMAC. It "
        "can't tell you *what* changed (that would leak the payload), only "
        "*where* — which is all a court needs."
    )
else:
    st.info("The chain is intact. Flip a byte to watch it break.")

# ---------------------------------------------------------------------------
st.header("③ The rewrite attack — and the checkpoint that catches it")
st.markdown(
    "A single-byte edit is easy to catch. The hard case (raised on "
    "[NousResearch/hermes-agent#487](https://github.com/NousResearch/hermes-agent/issues/487)): "
    "what if the attacker **holds the key**? They can truncate the log and "
    "re-chain a fabricated history — every HMAC recomputes, every link is valid. "
    "Plain verification checks the chain *against itself*, so it's fooled.\n\n"
    "The fix is a **checkpoint**: a `(segment, record_id, hmac)` triple observed "
    "while the log was honest and handed to someone the writer can't reach — a "
    "customer, a regulator, a counterpart agent. Re-verifying against it proves "
    "the log still extends the head you saw before."
)
if st.button("🔓 Run the rewrite, then check both ways", use_container_width=True):
    st.session_state.rewrite = d.rewrite_vs_checkpoint()

if "rewrite" in st.session_state:
    r: d.RewriteDemo = st.session_state.rewrite
    st.caption(
        f"Observed while honest: checkpoint at s{r.checkpoint['segment']}r{r.checkpoint['record_id']}, "
        f"hmac `{r.checkpoint['hmac'][:16]}…`. Then the log was rewritten (record 3 scrubbed)."
    )
    col_plain, col_checked = st.columns(2)
    with col_plain:
        st.markdown("**Plain verification**")
        if r.rewritten_plain.ok:
            st.warning(f"✓ Verified — **fooled**\n\n`{r.rewritten_plain.verdict}`")
        else:
            st.error(f"✗ {r.rewritten_plain.kind}")
        st.caption("Self-referential: the rewritten chain is consistent with itself.")
    with col_checked:
        st.markdown("**Against the checkpoint**")
        if r.rewritten_checked.ok:
            st.success("✓ Verified")
        else:
            st.error(f"✗ {r.rewritten_checked.kind} — **caught**\n\n`{r.rewritten_checked.verdict}`")
        st.caption("The pinned head no longer matches: history was rewritten.")
    st.info(
        "A checkpoint held **beside** the log buys nothing — whoever rewrites one "
        "rewrites the other. The security comes from where you store it."
    )

st.divider()
st.caption(
    "`pip install ogentic-audit` · `cargo add ogentic-audit-core` · "
    "Rust core + Python bindings + CLI, one on-disk format, court-defensible."
)
