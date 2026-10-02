"""PQC-Swarm - agentic post-quantum code migration dashboard (Streamlit + CrewAI)."""
import html
import io
import json
import os
import queue
import threading
import zipfile
from pathlib import Path

import pandas as pd
import streamlit as st

from pqc_swarm.swarm import run_swarm

ROOT = Path(__file__).parent
AGENTS = {"Auditor": ("🔍", "Auditor Agent", "Detects weak / quantum-breakable crypto"),
          "Refactoring": ("🛠️", "Refactoring Agent", "Rewrites to NIST quantum-safe algorithms"),
          "Verifier": ("✅", "Verifier Agent", "Proves the new code is valid & safe")}
KIND_ICON = {"start": "▶️", "finding": "⚠️", "change": "✏️", "check": "🧪", "done": "✔️", "error": "❌", "info": "💬"}

st.set_page_config(page_title="PQC-Swarm", page_icon="🛡️", layout="wide")
st.markdown("""
<style>
.hero{padding:1.2rem 1.4rem;border-radius:14px;background:linear-gradient(120deg,#0f172a,#1e3a8a 60%,#0e7490);color:#fff;margin-bottom:1rem}
.hero h1{margin:0;font-size:2rem}.hero p{margin:.3rem 0 0;opacity:.9}
.card{border:1px solid rgba(128,128,128,.35);border-radius:12px;padding:.8rem 1rem;min-height:210px}
.card h4{margin:0 0 .2rem}.badge{font-size:.75rem;padding:2px 9px;border-radius:99px;color:#fff}
.idle{background:#64748b}.working{background:#f59e0b}.done{background:#16a34a}.error{background:#dc2626}
.card .line{font-size:.8rem;margin:.15rem 0;opacity:.92;word-break:break-word}
</style>""", unsafe_allow_html=True)
st.markdown('<div class="hero"><h1>🛡️ PQC-Swarm</h1><p>Autonomous agents that scan code for '
            'quantum-breakable encryption and migrate it to NIST post-quantum standards '
            '(FIPS 203 ML-KEM · FIPS 204 ML-DSA).</p></div>', unsafe_allow_html=True)


def secret(name):
    try:
        return st.secrets.get(name, "")
    except Exception:
        return os.environ.get(name, "")


# ---------------------------------------------------------------- sidebar
with st.sidebar:
    st.header("⚙️ Swarm settings")
    mode_label = st.radio("Engine", ["Offline engine (no API key)", "CrewAI + LLM agents"],
                          help="Offline is deterministic and instant. CrewAI lets an LLM reason, "
                               "using the same engine as tools.")
    mode = "crewai" if mode_label.startswith("CrewAI") else "offline"
    cfg = {}
    if mode == "crewai":
        prov = st.selectbox("Provider", ["OpenAI", "Anthropic", "Google Gemini"])
        default = {"OpenAI": "openai/gpt-4o-mini", "Anthropic": "anthropic/claude-sonnet-5-5",
                   "Google Gemini": "gemini/gemini-2.0-flash"}[prov]
        keyname = {"OpenAI": "OPENAI_API_KEY", "Anthropic": "ANTHROPIC_API_KEY",
                   "Google Gemini": "GEMINI_API_KEY"}[prov]
        model = st.text_input("Model (LiteLLM id)", default)
        key = st.text_input("API key", type="password", value=secret(keyname),
                            help=f"Or set {keyname} in Streamlit secrets.")
        cfg = {"model": model, "api_key": key}
        if key:
            os.environ[keyname] = key
    run_exec = st.checkbox("Run refactored code in sandboxed subprocess", value=False,
                           help="Executes the refactored file (120s timeout). Only enable for trusted demo code.")
    st.divider()
    st.caption("**Standards targeted**\n\n- FIPS 203 · ML-KEM (key exchange)\n- FIPS 204 · ML-DSA (signatures)\n"
               "- FIPS 205 · SLH-DSA (hash-based sigs)\n- FIPS 202 · SHA-3")

# ---------------------------------------------------------------- input
samples = {p.name: p for p in sorted((ROOT / "samples").glob("*.py"))}
c1, c2 = st.columns([1, 1])
with c1:
    up = st.file_uploader("Upload vulnerable Python code", type=["py"])
with c2:
    pick = st.selectbox("…or use a built-in sample", ["—"] + list(samples))

source, filename = None, None
if up is not None:
    source, filename = up.getvalue().decode("utf-8", errors="replace"), up.name
elif pick != "—":
    source, filename = samples[pick].read_text(encoding="utf-8"), pick

if source:
    with st.expander(f"📄 Input: {filename} ({len(source.splitlines())} lines)", expanded=False):
        st.code(source, language="python", line_numbers=True)

launch = st.button("🚀 Launch PQC-Swarm", type="primary", disabled=not source, width="stretch")


def render_cards(slots, status, lines):
    for name, slot in slots.items():
        icon, title, sub = AGENTS[name]
        body = "".join(f'<div class="line">{html.escape(l)}</div>' for l in lines[name][-6:]) or \
            '<div class="line">Waiting…</div>'
        slot.markdown(f'<div class="card"><h4>{icon} {title} <span class="badge {status[name]}">'
                      f'{status[name].upper()}</span></h4><small>{sub}</small><hr style="margin:.4rem 0">{body}</div>',
                      unsafe_allow_html=True)


# ---------------------------------------------------------------- run
if launch and source:
    for k in ("result", "log"):
        st.session_state.pop(k, None)
    st.subheader("🐝 Live swarm activity")
    cols = st.columns(3)
    slots = {n: c.empty() for n, c in zip(AGENTS, cols)}
    feed = st.empty()
    status = {n: "idle" for n in AGENTS}
    lines = {n: [] for n in AGENTS}
    log = []
    render_cards(slots, status, lines)

    q = queue.Queue()

    def emit(agent, kind, text):
        q.put(("event", agent, kind, text))

    def worker():
        try:
            q.put(("done", run_swarm(source, filename, mode, cfg, run_exec, emit)))
        except Exception as exc:  # surfaced in UI
            q.put(("error", f"{type(exc).__name__}: {exc}"))

    t = threading.Thread(target=worker, daemon=True)
    t.start()
    result, err = None, None
    while True:
        try:
            item = q.get(timeout=0.25)
        except queue.Empty:
            if not t.is_alive():
                break
            continue
        if item[0] == "event":
            _, agent, kind, text = item
            if agent in AGENTS:
                status[agent] = {"start": "working", "done": "done", "error": "error"}.get(kind, status[agent]) \
                    if status[agent] != "done" or kind == "start" else status[agent]
                lines[agent].append(f"{KIND_ICON.get(kind, '')} {text}".replace("`", ""))
                log.append(f"{AGENTS[agent][0]} **{agent}** {KIND_ICON.get(kind, '')} {text}")
                render_cards(slots, status, lines)
                feed.markdown("\n\n".join(log[-12:]))
        elif item[0] == "done":
            result = item[1]
            break
        else:
            err = item[1]
            break
    if err:
        st.error(f"Swarm failed: {err}")
    else:
        st.session_state["result"], st.session_state["log"] = result, log
        st.success("Swarm finished.")

# ---------------------------------------------------------------- results
res = st.session_state.get("result")
if res:
    rep = res["report"]
    st.divider()
    st.subheader("📊 Results")
    m = st.columns(4)
    m[0].metric("Vulnerabilities found", len(res["findings"]))
    m[1].metric("Quantum risk score", res["risk_after"], delta=res["risk_after"] - res["risk_before"],
                delta_color="inverse", help=f"Before: {res['risk_before']}")
    m[2].metric("Transformations", len(res["changes"]))
    m[3].metric("Verifier", rep["verdict"])

    t1, t2, t3, t4, t5 = st.tabs(["🔍 Findings", "🔀 Before / After", "🧬 Quantum-safe code",
                                  "✅ Verification", "🧾 Agent log"])
    with t1:
        if res["findings"]:
            st.dataframe(pd.DataFrame(res["findings"])[["line", "severity", "algorithm", "snippet", "issue", "fix",
                                                        "auto_fixable"]], width="stretch", hide_index=True)
        else:
            st.info("No quantum-vulnerable patterns detected.")
    with t2:
        st.code(res["diff"] or "# no changes", language="diff")
    with t3:
        st.code(res["refactored"], language="python", line_numbers=True)
    with t4:
        icon = {"pass": "🟢", "warn": "🟡", "fail": "🔴"}
        for c in rep["checks"]:
            st.markdown(f"{icon[c['status']]} **{c['check']}** — {c['detail']}")
        if rep["stdout"]:
            st.code(rep["stdout"])
    with t5:
        st.markdown("\n\n".join(st.session_state.get("log", [])) or "_empty_")

    stem = Path(res["filename"]).stem
    md = [f"# PQC-Swarm report: {res['filename']}", f"Engine: {res['mode']}  \nVerdict: **{rep['verdict']}**",
          f"Risk score: {res['risk_before']} -> {res['risk_after']}", "", "## Findings"]
    md += [f"- L{f['line']} **{f['severity']}** {f['algorithm']}: `{f['snippet']}` -> {f['fix']}" for f in res["findings"]]
    md += ["", "## Verification"] + [f"- {c['status'].upper()}: {c['check']} - {c['detail']}" for c in rep["checks"]]
    report_md = "\n".join(md)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(f"{stem}_quantum_safe.py", res["refactored"])
        z.writestr(f"{stem}_report.md", report_md)
        z.writestr(f"{stem}_findings.json", json.dumps(res["findings"], indent=2))
        z.writestr(f"{stem}.diff", res["diff"])
    d = st.columns(3)
    d[0].download_button("⬇️ Quantum-safe code (.py)", res["refactored"], f"{stem}_quantum_safe.py", width="stretch")
    d[1].download_button("⬇️ Audit report (.md)", report_md, f"{stem}_report.md", width="stretch")
    d[2].download_button("⬇️ Everything (.zip)", buf.getvalue(), f"{stem}_pqc_swarm_output.zip",
                         width="stretch")
