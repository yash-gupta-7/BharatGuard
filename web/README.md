# BharatGuard web UI

React (Vite) frontend for the BharatGuard demo. Talks to the FastAPI
backend in `../server/` — the Sarvam API key stays server-side and never
reaches this app.

## Run

From the repo root:

```bash
# terminal 1 — backend
pip install -e ".[server]"
uvicorn server.main:app --reload --port 8000

# terminal 2 — frontend
cd web
npm install
npm run dev
```

Open http://localhost:5173. In dev, Vite proxies `/api/*` to the backend
(see `vite.config.js`) — no `VITE_API_BASE_URL` needed locally.

## Environment variables

Copy `.env.example` to `.env` only if deploying the frontend and backend
on different origins:

```
VITE_API_BASE_URL=http://localhost:8000
```

## Pages

- **Overview** — what BharatGuard does, live headline metrics
- **Protect** — the real detect → mask → Sarvam → restore workflow
- **Detectors** — supported PII types and default policy, from `/api/detectors`
- **Evaluation** — real precision/recall/F1/leakage from the evaluation harness, via `/api/evaluation`
- **Activity** — session-local log of Protect calls (entity type counts only, never raw text)

## Build

```bash
npm run build
```
