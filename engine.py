"""PQC-Swarm core engine.

Auditor   -> scan()     : finds quantum-vulnerable cryptography
Refactor  -> rewrite()  : AST-aware migration to NIST FIPS 203 (ML-KEM) / FIPS 204 (ML-DSA)
Verifier  -> verify()   : syntax, imports, residual-risk re-scan, optional sandboxed run
"""
from __future__ import annotations

import ast
import difflib
import importlib.util
import re
import subprocess
import sys
import tempfile
from dataclasses import dataclass, asdict
from pathlib import Path

SHIM_BEGIN = "# >>> PQC-Swarm shim"
SHIM_END = "# <<< PQC-Swarm shim <<<"

SHIM = '''# >>> PQC-Swarm shim: NIST FIPS 203 (ML-KEM-768) + FIPS 204 (ML-DSA-65) via liboqs >>>
import hashlib as _hl
import os as _os
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM as _AESGCM

try:
    import oqs as _oqs
except Exception:  # liboqs-python not installed
    _oqs = None

_KEM_ALG, _SIG_ALG = "ML-KEM-768", "ML-DSA-65"


class PQKeyPair:
    """Quantum-safe replacement for RSA/ECC key objects (hybrid ML-KEM + AES-256-GCM, ML-DSA)."""

    def __init__(self, kem_pub, sig_pub, kem=None, sig=None):
        self._kem_pub, self._sig_pub, self._kem, self._sig = kem_pub, sig_pub, kem, sig

    @classmethod
    def generate(cls, *_a, **_k):
        if _oqs is None:
            raise RuntimeError("liboqs-python is required: pip install liboqs-python")
        kem, sig = _oqs.KeyEncapsulation(_KEM_ALG), _oqs.Signature(_SIG_ALG)
        return cls(kem.generate_keypair(), sig.generate_keypair(), kem, sig)

    def public_key(self):
        return PQKeyPair(self._kem_pub, self._sig_pub)

    publickey = public_key

    def public_bytes(self, *_a, **_k):
        return self._kem_pub + self._sig_pub

    def encrypt(self, data, *_a, **_k):
        with _oqs.KeyEncapsulation(_KEM_ALG) as enc:
            ct, secret = enc.encap_secret(self._kem_pub)
        nonce = _os.urandom(12)
        return ct + nonce + _AESGCM(_hl.sha3_256(secret).digest()).encrypt(nonce, data, None)

    def decrypt(self, blob, *_a, **_k):
        n = self._kem.details["length_ciphertext"]
        ct, nonce, body = blob[:n], blob[n:n + 12], blob[n + 12:]
        key = _hl.sha3_256(self._kem.decap_secret(ct)).digest()
        return _AESGCM(key).decrypt(nonce, body, None)

    def sign(self, data, *_a, **_k):
        return self._sig.sign(data)

    def verify(self, signature, data, *_a, **_k):
        with _oqs.Signature(_SIG_ALG) as v:
            if not v.verify(data, signature, self._sig_pub):
                raise InvalidSignature("ML-DSA signature invalid")
# <<< PQC-Swarm shim <<<
'''

# --------------------------------------------------------------------------- Auditor
SEV_WEIGHT = {"CRITICAL": 10, "HIGH": 5, "MEDIUM": 2, "LOW": 1}


@dataclass
class Finding:
    rule: str
    line: int
    severity: str
    algorithm: str
    snippet: str
    issue: str
    fix: str
    auto_fixable: bool


# (rule id, regex, severity, algorithm, issue, recommended fix, auto-fixable)
RULES = [
    ("RSA-KEYGEN", r"\b(rsa\.generate_private_key|RSA\.generate|rsa\.newkeys)\b", "CRITICAL", "RSA",
     "RSA is broken by Shor's algorithm at any key size (harvest-now-decrypt-later risk).",
     "ML-KEM-768 (FIPS 203) for key exchange/encryption, ML-DSA-65 (FIPS 204) for signatures", True),
    ("RSA-PADDING", r"\bpadding\.(OAEP|PSS|PKCS1v15)\b|PKCS1_OAEP|pkcs1_15", "HIGH", "RSA",
     "RSA padding schemes only wrap a quantum-breakable primitive.",
     "Hybrid ML-KEM + AES-256-GCM / ML-DSA", True),
    ("DSA-KEYGEN", r"\bdsa\.generate_private_key\b", "CRITICAL", "DSA",
     "Finite-field DSA is broken by Shor's algorithm.", "ML-DSA-65 (FIPS 204)", True),
    ("ECC-KEYGEN", r"\bec\.(generate_private_key|ECDSA)\b", "CRITICAL", "ECC/ECDSA",
     "Elliptic-curve discrete log is broken by Shor's algorithm.", "ML-DSA-65 (FIPS 204)", True),
    ("ECC-KEX", r"\bec\.ECDH\b|\b(x25519|x448)\b|\.exchange\(", "CRITICAL", "ECDH/X25519",
     "Elliptic-curve key agreement is quantum-breakable.", "ML-KEM-768 (FIPS 203) - needs manual protocol change", False),
    ("ECC-EDDSA", r"\b(ed25519|ed448|Ed25519|Ed448)\b", "CRITICAL", "EdDSA",
     "EdDSA relies on elliptic-curve discrete log.", "ML-DSA-65 or SLH-DSA (FIPS 204/205) - manual", False),
    ("DH", r"\bdh\.generate_parameters\b|DiffieHellman", "HIGH", "Diffie-Hellman",
     "Finite-field DH is broken by Shor's algorithm.", "ML-KEM-768 (FIPS 203) - manual", False),
    ("WEAK-HASH", r"\bhashlib\.(md5|sha1)\b", "MEDIUM", "MD5/SHA-1",
     "Collision-broken classically; weak against Grover too.", "SHA3-256 (FIPS 202)", True),
    ("LEGACY-CIPHER", r"\b(DES3?|ARC4|RC4|Blowfish)\b|MODE_ECB|modes\.ECB", "HIGH", "Legacy symmetric",
     "Weak or insecure symmetric cipher/mode.", "AES-256-GCM - manual", False),
    ("AES-128", r"os\.urandom\(16\)|token_bytes\(16\)", "LOW", "128-bit symmetric key",
     "Grover's algorithm halves effective key strength to ~64 bits.", "Use 256-bit keys (32 bytes)", True),
]


def scan(source: str) -> list[Finding]:
    findings: list[Finding] = []
    in_shim = False
    for no, line in enumerate(source.splitlines(), 1):
        s = line.strip()
        if s.startswith(SHIM_BEGIN):
            in_shim = True
        if in_shim:
            if s.startswith(SHIM_END):
                in_shim = False
            continue
        if not s or s.startswith("#"):
            continue
        for rid, pat, sev, algo, issue, fix, auto in RULES:
            if re.search(pat, line):
                findings.append(Finding(rid, no, sev, algo, s[:110], issue, fix, auto))
    return findings


def risk_score(findings) -> int:
    return sum(SEV_WEIGHT[f.severity if hasattr(f, "severity") else f["severity"]] for f in findings)


# --------------------------------------------------------------------------- Refactoring
_KEYGEN = {"rsa.generate_private_key", "RSA.generate", "dsa.generate_private_key", "ec.generate_private_key"}
_STRONG = re.compile(r"padding\.|OAEP|PSS|PKCS1v15|ECDSA")
_HASHARG = re.compile(r"^hashes\.[A-Za-z0-9_]+\(\)$")
_REMOVABLE = {
    "cryptography.hazmat.primitives.asymmetric": {"rsa", "padding", "ec", "dsa"},
    "Crypto.PublicKey": {"RSA"},
    "Crypto.Cipher": {"PKCS1_OAEP"},
}


def _dotted(n):
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return None


class _Offsets:
    def __init__(self, src: str):
        self.b = src.encode("utf-8")
        self.starts = [0]
        for ln in self.b.split(b"\n")[:-1]:
            self.starts.append(self.starts[-1] + len(ln) + 1)

    def span(self, n):
        return (self.starts[n.lineno - 1] + n.col_offset,
                self.starts[n.end_lineno - 1] + n.end_col_offset)

    def text(self, s, e):
        return self.b[s:e].decode("utf-8")

    def tnode(self, n):
        return self.text(*self.span(n))


def _apply(src: str, edits, changes):
    """Apply non-overlapping edits (outermost first), return new source."""
    off = _Offsets(src)
    edits = sorted(edits, key=lambda e: (e[0], -e[1]))
    chosen, last_end = [], -1
    for e in edits:
        if e[0] >= last_end:
            chosen.append(e)
            last_end = e[1]
    b = off.b
    for s, e, new, kind, line in reversed(chosen):
        before = " ".join(off.text(s, e).split())
        changes.append({"line": line, "kind": kind, "before": before[:110], "after": new[:110]})
        b = b[:s] + new.encode("utf-8") + b[e:]
    return b.decode("utf-8")


def _call_edits(tree, off):
    edits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Attribute) and _dotted(node) in ("hashlib.md5", "hashlib.sha1"):
            s, e = off.span(node)
            edits.append((s, e, "hashlib.sha3_256", "weak hash -> SHA3-256", node.lineno))
        if not isinstance(node, ast.Call):
            continue
        name = _dotted(node.func)
        s, e = off.span(node)
        if name in _KEYGEN:
            edits.append((s, e, "PQKeyPair.generate()", "keygen -> ML-KEM-768 + ML-DSA-65", node.lineno))
        elif name == "PKCS1_OAEP.new" and node.args:
            edits.append((s, e, off.tnode(node.args[0]), "PKCS1_OAEP wrapper removed", node.lineno))
        elif isinstance(node.func, ast.Attribute) and node.func.attr in ("encrypt", "decrypt", "sign", "verify"):
            parts = [off.tnode(a) for a in node.args]
            parts += [(f"{k.arg}=" if k.arg else "**") + off.tnode(k.value) for k in node.keywords]
            if not any(_STRONG.search(p) for p in parts):
                continue
            kept = [p for p in parts if not (_STRONG.search(p) or _HASHARG.match(p))]
            new = f"{off.tnode(node.func)}({', '.join(kept)})"
            edits.append((s, e, new, f"classical {node.func.attr}() args dropped", node.lineno))
    return edits


def _clean_imports(src, changes):
    tree = ast.parse(src)
    off = _Offsets(src)
    used = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    edits = []
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.level == 0 and node.module in _REMOVABLE:
            rem = _REMOVABLE[node.module]
            keep = [a for a in node.names if not (a.name in rem and (a.asname or a.name) not in used)]
            if len(keep) == len(node.names):
                continue
            s, e = off.span(node)
            orig = " ".join(off.text(s, e).split())
            if keep:
                new = f"from {node.module} import " + ", ".join(
                    a.name + (f" as {a.asname}" if a.asname else "") for a in keep)
            elif node.col_offset == 0:
                new = f"# [PQC-Swarm] removed legacy import: {orig}"
            else:
                new = f"pass  # [PQC-Swarm] removed legacy import: {orig}"
            edits.append((s, e, new, "legacy import removed", node.lineno))
    return _apply(src, edits, changes) if edits else src


def _inject_shim(src):
    if SHIM_BEGIN in src or "PQKeyPair" not in src:
        return src
    tree = ast.parse(src)
    after = 0
    for i, st in enumerate(tree.body):
        is_doc = i == 0 and isinstance(st, ast.Expr) and isinstance(getattr(st, "value", None), ast.Constant) \
            and isinstance(st.value.value, str)
        is_future = isinstance(st, ast.ImportFrom) and st.module == "__future__"
        if is_doc or is_future:
            after = st.end_lineno
        else:
            break
    lines = src.split("\n")
    block = ["", *SHIM.rstrip("\n").split("\n"), ""]
    return "\n".join(lines[:after] + block + lines[after:])


def rewrite(source: str):
    """Return (new_source, changes, error)."""
    changes: list[dict] = []
    src = source
    try:
        for _ in range(6):
            tree = ast.parse(src)
            edits = _call_edits(tree, _Offsets(src))
            if not edits:
                break
            src = _apply(src, edits, changes)
        src = _clean_imports(src, changes)
        before = src
        src = re.sub(r"(urandom|token_bytes)\(16\)", r"\1(32)", src)
        if src != before:
            changes.append({"line": 0, "kind": "128-bit key -> 256-bit", "before": "urandom(16)", "after": "urandom(32)"})
        src = _inject_shim(src)
        if SHIM_BEGIN in src:
            changes.insert(0, {"line": 0, "kind": "PQC shim injected", "before": "",
                               "after": "PQKeyPair (ML-KEM-768 + ML-DSA-65 + AES-256-GCM)"})
        return src, changes, None
    except SyntaxError as exc:
        return source, [], f"Cannot parse input (line {exc.lineno}): {exc.msg}"


def unified_diff(a: str, b: str, name="file.py") -> str:
    return "".join(difflib.unified_diff(a.splitlines(True), b.splitlines(True),
                                        f"a/{name}", f"b/{name}", n=2))


# --------------------------------------------------------------------------- Verifier
def verify(original: str, refactored: str, run_exec: bool = False, timeout: int = 120) -> dict:
    checks = []

    def add(name, status, detail):
        checks.append({"check": name, "status": status, "detail": detail})

    # 1. syntax
    syntax_ok = True
    try:
        tree = ast.parse(refactored)
        compile(refactored, "<refactored>", "exec")
        add("Syntax / compile", "pass", "ast.parse and compile() succeeded - no syntax errors.")
    except SyntaxError as exc:
        syntax_ok = False
        tree = None
        add("Syntax / compile", "fail", f"SyntaxError line {exc.lineno}: {exc.msg}")

    # 2. imports resolvable
    if tree is not None:
        mods = set()
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                mods |= {a.name.split(".")[0] for a in n.names}
            elif isinstance(n, ast.ImportFrom) and n.level == 0 and n.module:
                mods.add(n.module.split(".")[0])
        missing = []
        for m in sorted(mods):
            try:
                if importlib.util.find_spec(m) is None:
                    missing.append(m)
            except (ImportError, ValueError):
                missing.append(m)
        if missing:
            add("Imports resolvable", "warn", "Not installed in this environment: " + ", ".join(missing))
        else:
            add("Imports resolvable", "pass", f"All {len(mods)} imported modules are available.")

    # 3. residual quantum-vulnerable crypto
    before, after = scan(original), scan(refactored)
    hard = [f for f in after if f.severity in ("CRITICAL", "HIGH")]
    if not after:
        add("Residual-risk re-scan", "pass", f"0 findings remain (was {len(before)}).")
    elif not hard:
        add("Residual-risk re-scan", "warn", f"{len(after)} low/medium finding(s) remain (was {len(before)}).")
    else:
        add("Residual-risk re-scan", "warn",
            f"{len(hard)} CRITICAL/HIGH finding(s) need manual review (lines "
            + ", ".join(str(f.line) for f in hard[:8]) + ").")

    # 4. PQC primitives present
    had_asym = any(f.rule.startswith(("RSA", "ECC", "DSA", "DH")) for f in before)
    has_pqc = "ML-KEM" in refactored or "ML-DSA" in refactored or "SLH-DSA" in refactored
    if had_asym:
        add("NIST PQC primitives present", "pass" if has_pqc else "fail",
            "ML-KEM-768 (FIPS 203) / ML-DSA-65 (FIPS 204) found." if has_pqc
            else "Asymmetric crypto was flagged but no PQC algorithm is present.")

    # 5. optional sandboxed run
    stdout = ""
    if run_exec and syntax_ok:
        oqs_missing = "PQKeyPair" in refactored and importlib.util.find_spec("oqs") is None
        if oqs_missing:
            add("Sandboxed execution", "warn", "Skipped: liboqs-python (oqs) is not installed here.")
        else:
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / "refactored.py"
                path.write_text(refactored, encoding="utf-8")
                try:
                    p = subprocess.run([sys.executable, "-I", str(path)], cwd=tmp, capture_output=True,
                                       text=True, timeout=timeout)
                    stdout = (p.stdout + p.stderr).strip()[-1500:]
                    add("Sandboxed execution", "pass" if p.returncode == 0 else "fail",
                        "Exited with code 0." if p.returncode == 0 else f"Exit code {p.returncode}: {stdout[-300:]}")
                except subprocess.TimeoutExpired:
                    add("Sandboxed execution", "fail", f"Timed out after {timeout}s.")
    elif not run_exec:
        add("Sandboxed execution", "warn", "Disabled (enable in sidebar).")

    failed = any(c["status"] == "fail" for c in checks)
    warned = any(c["status"] == "warn" for c in checks)
    verdict = "FAILED" if failed else ("PASSED WITH WARNINGS" if warned else "PASSED")
    return {"verdict": verdict, "ok": not failed, "checks": checks, "stdout": stdout,
            "findings_before": len(before), "findings_after": len(after)}


def to_dicts(findings):
    return [asdict(f) for f in findings]
