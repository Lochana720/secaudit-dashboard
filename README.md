# SecAudit — Website Security Audit Dashboard

A full-stack tool that audits the **basic security configuration** of websites you are authorised to test, scores them, and produces PDF reports.

**Stack:** React 18 (Vite, Recharts) · Python FastAPI · PostgreSQL (SQLAlchemy 2) · httpx · cryptography · dnspython · ReportLab

> ⚠️ Only scan websites you own or have **written permission** to test. The app enforces this with domain ownership verification.

## Features

| Area | What it does |
|------|--------------|
| **HTTP security headers** | HSTS (max-age, includeSubDomains, preload), CSP (presence, `unsafe-inline`, `unsafe-eval`, wildcards, `object-src`), X-Frame-Options / frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy, COOP, deprecated X-XSS-Protection, Cache-Control on cookie responses |
| **HTTPS & TLS** | TLS availability, certificate trust & hostname match, expiry countdown, key strength, signature algorithm, negotiated protocol & cipher, TLS 1.0/1.1 legacy support probe |
| **Transport** | HTTP → HTTPS redirect (301/308 vs temporary), TRACE method |
| **Cookies** | Secure, HttpOnly, SameSite flags (stricter for session-like cookies) |
| **CORS** | Origin reflection, wildcard + credentials misconfigurations |
| **Info disclosure** | Server version, X-Powered-By and similar headers |
| **Page content** | Mixed content, third-party scripts without Subresource Integrity |
| **DNS / Email** | SPF, DMARC, CAA records |
| **Policy** | security.txt (RFC 9116) |
| **Scoring** | Weighted pass ratio → 0–100 score and A+…F grade (any critical caps the grade at D) |
| **Severity view** | Findings grouped/filterable by severity and category, with fix guidance, evidence and references |
| **PDF export** | Branded report: grade, severity summary, TLS overview, findings with fixes, passed checks |
| **History & dashboard** | Scan history with filters/pagination, severity chart, score trend, risk ranking, most common issues |
| **Scan comparison** | Each scan shows score delta, resolved and new issues vs the previous scan |

### Safety built in
- **Ownership verification** — before scanning, prove control via a DNS TXT record (`_secaudit.<host>`) or a file at `/.well-known/secaudit-verification.txt`.
- **SSRF protection** — targets (and every redirect) that resolve to private, loopback or link-local IPs are blocked.
- **Rate limiting** — one active scan per target and a cooldown between scans.
- **Passive checks only** — no exploitation, brute forcing or fuzzing.

## Quick start (Docker)

```bash
cp .env.example .env        # set a real POSTGRES_PASSWORD
docker compose up --build
```
Open http://localhost:8080. (Interactive API docs: run the backend locally and open http://localhost:8000/docs.)

## Local development

**Backend**
```bash
cd backend
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
# Uses SQLite by default; for Postgres:
# export DATABASE_URL=postgresql+psycopg://user:pass@localhost:5432/secaudit
uvicorn app.main:app --reload
pytest -q
```

**Frontend**
```bash
cd frontend
npm install
npm run dev        # http://localhost:5173 (proxies /api → :8000)
```

### Environment variables
| Variable | Default | Purpose |
|----------|---------|---------|
| `DATABASE_URL` | `sqlite:///./secaudit.db` | SQLAlchemy URL (`postgresql+psycopg://…`) |
| `SKIP_VERIFICATION` | `false` | Dev only: auto-verify targets |
| `ALLOW_PRIVATE_TARGETS` | `false` | Dev only: allow localhost / private IPs |
| `SCAN_COOLDOWN_SECONDS` | `30` | Minimum gap between scans of one target |
| `REQUEST_TIMEOUT` | `10` | Network timeout per check (seconds) |
| `CORS_ORIGINS` | `http://localhost:5173,http://localhost:8080` | Allowed frontend origins |

To test against a local site: `SKIP_VERIFICATION=true ALLOW_PRIVATE_TARGETS=true uvicorn app.main:app --reload`

## API

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET/POST | `/api/targets` | List / add targets |
| POST | `/api/targets/{id}/verify` | Check DNS TXT or file token |
| DELETE | `/api/targets/{id}` | Delete target and its scans |
| POST | `/api/scans` | Start a scan `{ "target_id": 1 }` (runs in background) |
| GET | `/api/scans?target_id=&status=&page=` | Paginated history |
| GET | `/api/scans/{id}` | Scan with findings and metadata |
| GET | `/api/scans/{id}/diff` | Compare with previous scan |
| GET | `/api/scans/{id}/report.pdf` | Download PDF report |
| GET | `/api/dashboard` | Aggregated dashboard data |

## Project structure
```
backend/app/
  main.py, config.py, database.py, models.py, schemas.py
  verification.py        ownership proof (DNS / file)
  report.py              PDF generation
  routers/               targets, scans, dashboard
  scanner/               engine + tls, headers, cookies, web, dns_checks
frontend/src/
  pages/                 Dashboard, Targets, ScanDetail, History
  components/ui.jsx      badges, score ring, stat cards
```

## Ideas for next steps
- Scheduled re-scans with email alerts when the grade drops
- User accounts (JWT) and multi-tenant targets
- Celery/RQ worker queue for large numbers of scans
- Alembic migrations for schema changes
