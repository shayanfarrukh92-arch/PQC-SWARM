"""Orchestration of the three agents.

Two interchangeable modes:
  * offline : deterministic engine (no API key) - always works, ideal for live judging
  * crewai  : real CrewAI crew (Auditor / Refactoring / Verifier agents) driven by an LLM,
              using the same engine as tools so every answer is grounded in real analysis
"""
from __future__ import annotations

import json
import os
import time
from typing import Callable

from .engine import (rewrite, risk_score, scan, to_dicts, unified_diff, verify)

Emit = Callable[[str, str, str], None]  # (agent, kind, text)


def _finalize(source, filename, findings, refactored, changes, run_exec, mode) -> dict:
    report = verify(source, refactored, run_exec=run_exec)
    after = scan(refactored)
    return {
        "mode": mode, "filename": filename,
        "findings": to_dicts(findings), "changes": changes,
        "refactored": refactored, "diff": unified_diff(source, refactored, filename),
        "report": report,
        "risk_before": risk_score(findings), "risk_after": risk_score(after),
    }


# ------------------------------------------------------------------ offline mode
def _offline(source, filename, run_exec, emit: Emit, pace=0.12) -> dict:
    nap = lambda: time.sleep(pace)  # noqa: E731
    emit("Auditor", "start", f"Reading {len(source.splitlines())} lines of {filename} ...")
    nap()
    findings = scan(source)
    for f in findings:
        emit("Auditor", "finding", f"L{f.line} [{f.severity}] {f.algorithm}: `{f.snippet}`")
        nap()
    emit("Auditor", "done", f"{len(findings)} quantum-vulnerable pattern(s) found; risk score {risk_score(findings)}.")

    emit("Refactoring", "start", "Planning migration to NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA) ...")
    nap()
    new, changes, err = rewrite(source)
    if err:
        emit("Refactoring", "error", err)
        new = source
    for c in changes:
        emit("Refactoring", "change", f"L{c['line'] or '-'} {c['kind']}: `{c['before']}` -> `{c['after']}`".replace("`` ->", "->"))
        nap()
    emit("Refactoring", "done", f"{len(changes)} transformation(s) applied.")

    emit("Verifier", "start", "Compiling refactored code and re-scanning for residual risk ...")
    nap()
    res = _finalize(source, filename, findings, new, changes, run_exec, "offline")
    for c in res["report"]["checks"]:
        emit("Verifier", "check", f"{c['status'].upper()} - {c['check']}: {c['detail']}")
        nap()
    emit("Verifier", "done", f"Verdict: {res['report']['verdict']}")
    return res


# ------------------------------------------------------------------ CrewAI mode
def _crewai(source, filename, run_exec, cfg, emit: Emit) -> dict:
    os.environ.setdefault("CREWAI_DISABLE_TELEMETRY", "true")
    os.environ.setdefault("OTEL_SDK_DISABLED", "true")
    from crewai import LLM, Agent, Crew, Process, Task
    from crewai.tools import tool

    state = {"findings": [], "candidate": None, "changes": []}

    @tool("scan_code")
    def scan_code(scope: str = "all") -> str:
        """Scan the uploaded file for quantum-vulnerable cryptography. Returns JSON findings. scope: 'all'."""
        state["findings"] = scan(source)
        for f in state["findings"]:
            emit("Auditor", "finding", f"L{f.line} [{f.severity}] {f.algorithm}: `{f.snippet}`")
        return json.dumps(to_dicts(state["findings"]))

    @tool("get_source")
    def get_source(scope: str = "all") -> str:
        """Return the original source code with line numbers. scope: 'all'."""
        return "\n".join(f"{i:4d} | {l}" for i, l in enumerate(source.splitlines(), 1))

    @tool("apply_rule_engine")
    def apply_rule_engine(scope: str = "all") -> str:
        """Run the deterministic PQC migration engine; returns the migrated full file as baseline."""
        new, changes, err = rewrite(source)
        if err:
            return f"ERROR: {err}"
        state["candidate"], state["changes"] = new, changes
        for c in changes:
            emit("Refactoring", "change", f"L{c['line'] or '-'} {c['kind']}: `{c['before']}` -> `{c['after']}`")
        return new

    @tool("submit_refactored_code")
    def submit_refactored_code(code: str) -> str:
        """Submit the FINAL complete refactored Python file. It is syntax-checked before acceptance."""
        import ast
        code = code.strip("\n")
        if code.startswith("```"):
            code = "\n".join(code.split("\n")[1:]).rsplit("```", 1)[0]
        try:
            ast.parse(code)
        except SyntaxError as exc:
            return f"REJECTED: syntax error line {exc.lineno}: {exc.msg}. Fix and resubmit."
        state["candidate"] = code + "\n"
        emit("Refactoring", "info", f"Final candidate submitted ({len(code.splitlines())} lines).")
        return "ACCEPTED"

    @tool("verify_code")
    def verify_code(scope: str = "all") -> str:
        """Verify the submitted refactored code: syntax, imports, residual-risk scan. Returns JSON report."""
        if not state["candidate"]:
            return "No candidate code has been submitted yet."
        rep = verify(source, state["candidate"], run_exec=run_exec)
        for c in rep["checks"]:
            emit("Verifier", "check", f"{c['status'].upper()} - {c['check']}: {c['detail']}")
        return json.dumps(rep)

    llm = LLM(model=cfg["model"], api_key=cfg.get("api_key") or None, temperature=0.1)

    def cb(agent):
        def _cb(step):
            try:
                tool_name = getattr(step, "tool", None)
                thought = (getattr(step, "thought", "") or "").strip()
                out = getattr(step, "output", None) or getattr(step, "text", None) or ""
                if tool_name:
                    emit(agent, "info", f"Using tool `{tool_name}`")
                elif thought or out:
                    emit(agent, "info", (thought or str(out)).replace("\n", " ")[:300])
            except Exception:
                pass
        return _cb

    common = dict(llm=llm, allow_delegation=False, verbose=False, max_iter=8)
    auditor = Agent(
        role="Quantum-Vulnerability Auditor",
        goal="Find every use of cryptography that a future quantum computer could break.",
        backstory="A cryptographic-audit specialist who knows Shor's and Grover's algorithms and NIST PQC standards.",
        tools=[scan_code], step_callback=cb("Auditor"), **common)
    refactorer = Agent(
        role="Post-Quantum Refactoring Engineer",
        goal="Rewrite the vulnerable file so it uses NIST-approved quantum-safe algorithms (ML-KEM FIPS 203, "
             "ML-DSA FIPS 204, SLH-DSA FIPS 205) without changing business logic.",
        backstory="A senior security engineer who migrates production code to post-quantum cryptography.",
        tools=[get_source, apply_rule_engine, submit_refactored_code], step_callback=cb("Refactoring"), **common)
    verifier = Agent(
        role="Code Verification Engineer",
        goal="Prove the refactored code is valid, runnable Python with no remaining quantum-vulnerable crypto.",
        backstory="A meticulous QA engineer who never trusts code until the checks pass.",
        tools=[verify_code], step_callback=cb("Verifier"), **common)

    t1 = Task(description=f"Audit the uploaded file '{filename}'. Call scan_code, then summarise each finding, "
                          "its severity and the NIST-approved replacement.",
              expected_output="A prioritised audit report listing each vulnerable line and its recommended fix.",
              agent=auditor,
              callback=lambda _o: (emit("Auditor", "done", "Audit complete."),
                                   emit("Refactoring", "start", "Received audit - starting migration ...")))
    t2 = Task(description="Using the audit, produce the fully migrated file: call apply_rule_engine for a baseline, "
                          "review it, manually fix anything the engine flagged as not auto-fixable, then call "
                          "submit_refactored_code with the COMPLETE final file. Preserve all business logic.",
              expected_output="Confirmation that the final refactored file was accepted.",
              agent=refactorer, context=[t1],
              callback=lambda _o: (emit("Refactoring", "done", "Refactoring complete."),
                                   emit("Verifier", "start", "Verifying refactored code ...")))
    t3 = Task(description="Call verify_code and report whether the refactored code passes every check. "
                          "If it fails, state exactly what is wrong.",
              expected_output="A pass/fail verification summary.",
              agent=verifier, context=[t2],
              callback=lambda _o: emit("Verifier", "done", "Verification complete."))

    emit("Auditor", "start", "CrewAI crew launched - Auditor is reading the code ...")
    Crew(agents=[auditor, refactorer, verifier], tasks=[t1, t2, t3],
         process=Process.sequential, verbose=False).kickoff()

    # Safety net: never leave the UI empty if an agent skipped a tool call.
    findings = state["findings"] or scan(source)
    candidate = state["candidate"]
    changes = state["changes"]
    if not candidate:
        emit("Refactoring", "info", "Agent did not submit code - falling back to the rule engine.")
        candidate, changes, _ = rewrite(source)
    res = _finalize(source, filename, findings, candidate, changes, run_exec, "crewai")
    emit("Verifier", "done", f"Final independent check: {res['report']['verdict']}")
    return res


def run_swarm(source: str, filename: str, mode: str, cfg: dict, run_exec: bool, emit: Emit) -> dict:
    if mode == "crewai":
        return _crewai(source, filename, run_exec, cfg, emit)
    return _offline(source, filename, run_exec, emit)
