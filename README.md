# كشف × حصانة — Kashf × AcadShield AI

Arabic-first, evidence-based cybersecurity & academic integrity platform powered by a **pure Python backend** (`backend/*.py`, FastAPI + SQLite) with a lightweight React + TypeScript structural UI.

## Python Backend Architecture

All core logic, security engines, forensics, and persistence live strictly in **Python**:

- **Phishing & Scam Engine (`backend/analyzer.py`, `backend/brands.py`)**: Context-aware Arabic/Iraqi/English rule engine + Levenshtein lookalike detection, open-redirect analysis, OAuth consent phishing, and SHA-256 fingerprint trending (`backend/db.py`).
- **URL Forensics & Safe Sandbox (`backend/url_inspector.py`, `backend/url_sandbox.py`, `backend/threat_intel.py`)**: Punycode/IDN mixed-script homograph analysis, SSRF guards, live DNS/RDAP/TLS probing, Threat Intelligence aggregation, and non-executing static HTML/DOM detonation.
- **Academic Integrity & DLP (`backend/academic_analyzer.py`, `backend/blockchain.py`)**: Stylometric AI text classifier (`AiTextDetection`), 4-shingle plagiarism checks, DLP secret masking, and SHA-256 hash-chained certificates.
- **20-Scenario Phishing IQ Lab (`backend/quiz.py`)**: 20 curated bilingual phishing/safe challenges verified dynamically against the Python analyzer.
- **Developer Console & RBAC (`backend/dev_console.py`)**: PBKDF2-HMAC-SHA256 (`210,000` rounds) authentication, HMAC-SHA256 Bearer tokens, single-use signed invite links (`editor` / `viewer`), live runtime threshold & feature toggles, custom domain blocklist/allowlist rules, and immutable audit logs.
- **FastAPI Server (`backend/main.py`) & Bridge (`backend/bridge.py`)**: Standalone Python HTTP API on port `8000`, also bridged cleanly behind the unified Node/Vite preview wrapper (`server.ts` on port `3000`).

## GitHub Security Checklist

- Zero hardcoded passwords, API keys, or session secrets in source files.
- `.env` files and local SQLite databases (`backend/*.db`) are ignored via `.gitignore`.
- Developer Console signing secrets default to OS CSPRNG if `KASHF_DEV_SESSION_SECRET` is not set.
- API keys (`GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `GOOGLE_SAFE_BROWSING_API_KEY`, `URLHAUS_AUTH_KEY`, `PHISHTANK_APP_KEY`) are read **only** on the Python server and never exposed to client code (only boolean readiness flags appear in the Developer Console).

## Run Instructions (FastAPI + Vite)

1. Start the Python FastAPI backend:
   ```bash
   cd backend
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```
2. In a second terminal, install frontend dependencies and start Vite (proxies `/api` to `http://localhost:8000`):
   ```bash
   npm install
   npx vite --port 5173
   ```
3. Open `http://localhost:5173`

## Integrated Dev Server (Single Command)

Run the integrated Express + Vite + Python bridge server on port `3000`:

```bash
npm install
npm run dev
```

## Running Tests

- **Python backend & security test suite**:
  ```bash
  python3 backend/test_analyzer.py
  python3 backend/test_stage6_dev_console.py
  ```
- **Frontend utility tests**:
  ```bash
  npx tsx --test src/utils/*.test.ts
  ```

