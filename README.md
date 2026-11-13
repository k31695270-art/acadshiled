# كشف — Kashf

Arabic-first, privacy-preserving scam and phishing message analyzer. Runs completely offline with zero external API keys or tracking.

## Features

- **Instant Risk Analysis**: Paste SMS, WhatsApp messages, or suspicious URLs to receive a 0–100 risk score, clear Arabic/English verdict (`آمنة غالباً` / `مشبوهة` / `خطيرة`), highlighted phrases, and concrete next steps.
- **Offline Rule Engine (`backend/analyzer.py`)**: Detects URL shorteners, risky TLDs, raw IPs, excessive subdomains/`@`, Punycode/homographs, lookalike brand impersonation via Levenshtein distance (`backend/brands.py`), Arabic/English urgency, prize lures, OTP/credential theft, fake delivery fees, and guaranteed-profit/job scams.
- **Privacy-First Trending (`backend/db.py`)**: Never stores message text—only a 16-character SHA-256 fingerprint of normalized text, category, score, and timestamp in SQLite (`reports`), deduplicated within 24 hours.
- **Bilingual RTL/LTR & Accessible**: Arabic default (`dir="rtl"`) with live `AR / EN` toggle, 1080×1080 PNG share card export, keyboard focus rings, and `prefers-reduced-motion` support.

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

- **Python analyzer tests (10 cases)**:
  ```bash
  python3 backend/test_analyzer.py
  # or with pytest:
  cd backend && pytest
  ```
- **Frontend utility tests**:
  ```bash
  npx tsx --test src/utils/urlDetect.test.ts
  ```
