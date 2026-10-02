# 🛡️ PQC-Swarm
Agentic AI that scans code for quantum-breakable encryption and migrates it to NIST post-quantum standards.

| Agent | Job | Implementation |
|---|---|---|
| 🔍 Auditor | Flags RSA / ECC / DH / DSA / weak hashes / legacy ciphers | regex rule base (`engine.scan`) |
| 🛠️ Refactoring | Rewrites to ML-KEM-768 (FIPS 203) + ML-DSA-65 (FIPS 204) + AES-256-GCM | AST rewriter (`engine.rewrite`) |
| ✅ Verifier | Compile check, import check, residual-risk re-scan, optional sandboxed run | `engine.verify` |

Two engines (sidebar): **Offline** (deterministic, no key, instant) and **CrewAI + LLM** (real CrewAI crew; agents call the
same engine as tools, so LLM output is grounded and always falls back safely).

## Run locally
```bash
pip install -r requirements.txt     # liboqs-python builds liboqs on first import (needs cmake, git, C compiler)
streamlit run app.py
```
Demo: pick `vulnerable_bank.py` in the app -> **Launch PQC-Swarm**. Upload any `.py` file for judges.

## Deploy on Streamlit Community Cloud (free)
1. Push this folder to a **public GitHub repo**.
2. Go to https://share.streamlit.io -> **Create app** -> pick the repo, branch `main`, main file `app.py`.
3. (Optional) *Advanced settings -> Secrets*: `OPENAI_API_KEY = "..."` (or `ANTHROPIC_API_KEY`, `GEMINI_API_KEY`).
4. Deploy. `packages.txt` installs cmake/git/compiler so liboqs can build. Open the app once before judging to warm up.

Docker alternative: `docker build -t pqc-swarm . && docker run -p 8501:8501 pqc-swarm`.

## Notes / limitations
- Auto-rewrite targets Python using `cryptography` and PyCryptodome RSA/ECC/DSA. Patterns the engine cannot safely
  rewrite (ECDH, X25519, Ed25519, DH, DES/RC4/ECB) are flagged "manual"; in CrewAI mode the LLM handles them.
- Migrated code uses a small injected shim over `liboqs-python` (`import oqs`). Without liboqs the code compiles but
  key generation raises a clear error; the Verifier reports this as a warning.
- Sandboxed execution is **off by default**; never enable it on a public deployment for untrusted uploads.
